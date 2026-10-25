"""Resilient multi-chain EVM WebSocket subscriber optimized for Alchemy using server-side filtered eth_subscribe('logs')."""

import asyncio
from collections import deque
import json
import logging
import time
from typing import Optional, Deque, Dict, Any, List, Tuple
import websockets

from app.chains import ChainConfig, is_sequencer_feed_url
from app.config import Settings
from app.pipeline import (
    AlertPipeline,
    TRANSFER_TOPIC,
    TRANSFER_SINGLE_TOPIC,
    TRANSFER_BATCH_TOPIC,
    ZERO_ADDRESS_32BYTES,
    is_zero_address,
)
from app.rpc import EvmRpcClient, redact_rpc_url

logger = logging.getLogger(__name__)


class ChainIdMismatchError(RuntimeError):
    """Raised when the RPC endpoint's eth_chainId does not match the configured chain_id."""

    def __init__(self, expected_chain_id: int, actual_chain_id: int):
        self.expected_chain_id = expected_chain_id
        self.actual_chain_id = actual_chain_id
        super().__init__(
            f"chain ID mismatch: expected {expected_chain_id}, got {actual_chain_id}"
        )


def classify_reconnect_reason(exc: Exception, ws_url: Optional[str] = None) -> Tuple[str, str]:
    """
    Classify a WebSocket or RPC failure into one of the standard reconnect categories:
      - 'chain ID mismatch'
      - '429'
      - 'timeout'
      - 'handshake error'
      - 'connection error'
    and return (category, redacted_detail) with all RPC URLs and API keys stripped.
    """
    raw_detail = redact_rpc_url(f"{type(exc).__name__}: {exc}", ws_url)
    low = raw_detail.lower()
    exc_type_low = type(exc).__name__.lower()

    if isinstance(exc, ChainIdMismatchError) or "chain id mismatch" in low:
        category = "chain ID mismatch"
    elif (
        "429" in low
        or "rate limit" in low
        or "too many requests" in low
        or "compute units" in low
        or "-32005" in low
    ):
        category = "429"
    elif (
        isinstance(exc, (asyncio.TimeoutError, TimeoutError))
        or "timeout" in low
        or "timed out" in low
        or "timeout" in exc_type_low
    ):
        category = "timeout"
    elif (
        "invalidstatus" in exc_type_low
        or "invalidhandshake" in exc_type_low
        or "invaliduri" in exc_type_low
        or "handshake" in low
        or "rejected websocket connection" in low
        or "http 400" in low
        or "http 401" in low
        or "http 403" in low
        or "http 404" in low
        or "http 502" in low
        or "http 503" in low
        or "sequencer feed" in low
        or "eth_subscribe" in low
        or "method not found" in low
        or "not supported" in low
    ):
        category = "handshake error"
    else:
        category = "connection error"

    return category, raw_detail


def build_erc721_mint_subscription_request(req_id: int = 1) -> Dict[str, Any]:
    """
    Build eth_subscribe('logs') request filtering server-side on:
      - topics[0]: ERC-721 Transfer(address,address,uint256)
      - topics[1]: ZERO_ADDRESS_32BYTES (from == 0x000...000)
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "eth_subscribe",
        "params": [
            "logs",
            {
                "topics": [
                    TRANSFER_TOPIC,
                    ZERO_ADDRESS_32BYTES,
                ]
            },
        ],
    }


def build_erc1155_mint_subscription_request(req_id: int = 2) -> Dict[str, Any]:
    """
    Build separate eth_subscribe('logs') request for ERC-1155 mints filtering server-side on:
      - topics[0]: [TransferSingle, TransferBatch]
      - topics[1]: None (any operator)
      - topics[2]: ZERO_ADDRESS_32BYTES (from == 0x000...000)
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "eth_subscribe",
        "params": [
            "logs",
            {
                "topics": [
                    [
                        TRANSFER_SINGLE_TOPIC,
                        TRANSFER_BATCH_TOPIC,
                    ],
                    None,
                    ZERO_ADDRESS_32BYTES,
                ]
            },
        ],
    }


def is_mint_log_from_zero_address(log: Dict[str, Any]) -> bool:
    """
    Client-side filter for eth_subscribe('logs') events:
    - Returns True only if the Transfer / TransferSingle / TransferBatch log has `from == 0x000...000`
      and `to != 0x000...000`.
    - Explicitly discards events that lack an indexed tokenId topic (`len(topics) < 4` on `TRANSFER_TOPIC`),
      filtering out all ERC-20 mints before any RPC call is made.
    """
    if log.get("removed") is True:
        return False
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) < 4:
        # Both ERC-721 Transfer (4 topics: sig, from, to, tokenId) and
        # ERC-1155 TransferSingle/Batch (4 topics: sig, operator, from, to) have 4 topics.
        # ERC-20 Transfer has only 3 topics (lacks tokenId topic) and is discarded here.
        return False

    topic0 = str(topics[0]).lower()
    if topic0 == TRANSFER_TOPIC.lower():
        if not topics[3]:
            return False
        return is_zero_address(str(topics[1])) and not is_zero_address(str(topics[2]))
    elif topic0 in (TRANSFER_SINGLE_TOPIC.lower(), TRANSFER_BATCH_TOPIC.lower()):
        return is_zero_address(str(topics[2])) and not is_zero_address(str(topics[3]))

    return False


class WebSocketSubscriber:
    """
    Per-chain async listener supporting both WebSocket (`eth_subscribe('logs')`) and HTTP
    polling (`eth_blockNumber` + `eth_getLogs`) modes, with `eth_chainId` verification on
    connect, sequencer feed protection, reconnect reason classification, 429 exponential
    backoff, and automatic fallback from websocket to polling after 5 failed reconnects.
    Never logs RPC URLs or API keys.
    """

    def __init__(
        self,
        config: Settings,
        pipeline: AlertPipeline,
        rpc: EvmRpcClient,
        chain_config: Optional[ChainConfig] = None,
    ):
        self.config = config
        self.pipeline = pipeline
        self.rpc = rpc
        self.chain_config = chain_config

        self.chain_key = chain_config.key if chain_config else getattr(pipeline, "chain_key", "ethereum")
        self.chain_name = chain_config.name if chain_config else getattr(pipeline, "chain_name", "Ethereum")
        self.chain_id = chain_config.chain_id if chain_config else getattr(pipeline, "chain_id", 1)
        self.ws_rpc_url = (
            chain_config.effective_ws_rpc_url if chain_config else config.ws_rpc_url
        )
        self.fallback_ws_url: Optional[str] = None
        if chain_config and chain_config.ws_rpc_default:
            default_ws = ChainConfig._to_ws_scheme(chain_config.ws_rpc_default)
            if not is_sequencer_feed_url(default_ws) and default_ws != self.ws_rpc_url:
                self.fallback_ws_url = default_ws

        self.confirmation_depth = chain_config.confirmation_depth if chain_config else 1
        self.mode = chain_config.normalized_mode if chain_config else "websocket"
        self.active_mode = self.mode
        self.poll_interval_seconds = float(
            getattr(chain_config, "poll_interval_seconds", 1.5) if chain_config else 1.5
        )
        self.log_batch_size = max(
            1, int(getattr(chain_config, "log_batch_size", 10) if chain_config else 10)
        )
        self.max_ws_reconnects = max(
            1, int(getattr(chain_config, "max_ws_reconnects", 5) if chain_config else 5)
        )

        self._running = False
        self._ws = None
        self._sem = asyncio.Semaphore(8)

        # Live telemetry for /status reporting
        self.ws_connected: bool = False
        self.polling_connected: bool = False
        self.last_ws_error: Optional[str] = None
        self.last_reconnect_reason: Optional[str] = None
        self.last_block_number: Optional[int] = None
        self.last_block_received_at: Optional[float] = None
        self._last_processed_block: Optional[int] = None
        self.reconnect_count: int = 0
        self.failed_reconnects: int = 0
        self._event_timestamps: Deque[float] = deque()
        self.total_subscription_events: int = 0

    def record_subscription_event(self, now: Optional[float] = None) -> None:
        """Record a received WebSocket/polling log event in the rolling 1-hour window."""
        ts = now if now is not None else time.time()
        self.total_subscription_events += 1
        self._event_timestamps.append(ts)
        cutoff = ts - 3600.0
        while self._event_timestamps and self._event_timestamps[0] < cutoff:
            self._event_timestamps.popleft()

    def get_subscription_events_last_hour(self, now: Optional[float] = None) -> int:
        """Return the number of subscription events received in the last 3600 seconds."""
        ts = now if now is not None else time.time()
        cutoff = ts - 3600.0
        while self._event_timestamps and self._event_timestamps[0] < cutoff:
            self._event_timestamps.popleft()
        return len(self._event_timestamps)

    @property
    def subscription_events_per_hour(self) -> int:
        """Current rolling 1-hour subscription event count."""
        return self.get_subscription_events_last_hour()

    @property
    def rpc_calls_per_hour(self) -> int:
        """Current rolling 1-hour RPC call count for this chain."""
        if self.rpc is not None and hasattr(self.rpc, "get_rpc_calls_last_hour"):
            return self.rpc.get_rpc_calls_last_hour()
        return 0

    async def _verify_chain_id(self, ws: Optional[Any] = None) -> int:
        """
        Call eth_chainId on connect and verify it matches `self.chain_id` (e.g. 4663 for Robinhood Chain).
        Logs a clear error and raises ChainIdMismatchError if it does not match.
        """
        actual_chain_id: Optional[int] = None

        if ws is not None and hasattr(ws, "recv"):
            req = {"jsonrpc": "2.0", "id": 999, "method": "eth_chainId", "params": []}
            if hasattr(self.rpc, "record_call"):
                self.rpc.record_call()
            await ws.send(json.dumps(req))
            raw_resp = await asyncio.wait_for(ws.recv(), timeout=10.0)
            resp_data = json.loads(raw_resp)
            if "error" in resp_data and resp_data["error"]:
                err_obj = resp_data["error"]
                err_msg = (
                    err_obj.get("message", str(err_obj))
                    if isinstance(err_obj, dict)
                    else str(err_obj)
                )
                err_code = err_obj.get("code") if isinstance(err_obj, dict) else None
                safe_msg = redact_rpc_url(err_msg, self.ws_rpc_url)
                raise RuntimeError(f"handshake error: eth_chainId rejected: {safe_msg} (code={err_code})")
            res_val = resp_data.get("result")
            if res_val is not None:
                actual_chain_id = int(res_val) if isinstance(res_val, int) else int(str(res_val), 16)

        if actual_chain_id is None and self.rpc is not None and hasattr(self.rpc, "eth_chain_id"):
            actual_chain_id = await self.rpc.eth_chain_id()

        if actual_chain_id is None:
            raise RuntimeError("handshake error: eth_chainId returned empty result")

        if actual_chain_id != self.chain_id:
            logger.error(
                "[%s] Chain ID mismatch on connect: expected %d, got %d",
                self.chain_name,
                self.chain_id,
                actual_chain_id,
            )
            raise ChainIdMismatchError(self.chain_id, actual_chain_id)

        logger.info("[%s] Verified eth_chainId == %d", self.chain_name, actual_chain_id)
        return actual_chain_id

    async def start(self):
        """
        Start the per-chain listener in configured mode ('websocket' or 'polling').
        In 'websocket' mode, automatically falls back to 'polling' after `self.max_ws_reconnects` (5)
        failed reconnect attempts and sends a Telegram notification.
        """
        self._running = True
        self.active_mode = self.mode
        backoff = 1.0
        max_backoff = 60.0
        has_connected_before = False
        failed_attempts = 0
        self.failed_reconnects = 0

        try:
            await self.pipeline.initialize()
        except Exception as e:
            logger.error("[%s] Database initialization error: %s", self.chain_name, redact_rpc_url(e, self.ws_rpc_url))

        db = getattr(self.pipeline, "db", None)
        if db is not None and hasattr(db, "get_last_processed_block"):
            try:
                stored_blk = await db.get_last_processed_block(self.chain_key)
                if isinstance(stored_blk, int):
                    self._last_processed_block = stored_blk
                    self.last_block_number = stored_blk
            except Exception as e:
                logger.debug("[%s] Could not read last_processed_block on startup: %s", self.chain_name, redact_rpc_url(e, self.ws_rpc_url))

        # Seed initial block number via HTTP RPC once on startup so /status has block info immediately
        if self.last_block_number is None:
            try:
                blk = await self.rpc.eth_block_number()
                if isinstance(blk, int):
                    self.last_block_number = blk
                    self.last_block_received_at = time.time()
            except Exception as e:
                logger.debug("[%s] Initial block number seed failed: %s", self.chain_name, redact_rpc_url(e, self.ws_rpc_url))

        if self.mode == "polling":
            logger.info(
                "[%s] Starting in configured HTTP polling mode (interval=%.1fs, batch_size=%d)...",
                self.chain_name,
                self.poll_interval_seconds,
                self.log_batch_size,
            )
            await self._run_polling_loop()
            return

        logger.info("[%s] Connecting to WebSocket RPC...", self.chain_name)

        while self._running:
            try:
                if is_sequencer_feed_url(self.ws_rpc_url):
                    if self.fallback_ws_url and not is_sequencer_feed_url(self.fallback_ws_url):
                        logger.warning(
                            "[%s] Rejecting sequencer feed WebSocket URL (does not support eth_subscribe); switching to JSON-RPC WebSocket endpoint.",
                            self.chain_name,
                        )
                        self.ws_rpc_url = self.fallback_ws_url
                    else:
                        raise ValueError(
                            "handshake error: configured WebSocket URL is a sequencer feed (feed.mainnet.chain.robinhood.com) and does not support eth_subscribe"
                        )

                async with websockets.connect(
                    self.ws_rpc_url,
                    ping_interval=20,
                    ping_timeout=30,
                    close_timeout=10,
                    max_size=16 * 1024 * 1024,
                ) as ws:
                    self._ws = ws

                    # (1) Verify eth_chainId on connect before marking connected or subscribing
                    await self._verify_chain_id(ws=ws)

                    # Load last_processed_block from SQLite on connect/reconnect so we resume cleanly
                    # and ignore events from blocks already processed
                    resume_floor_block: Optional[int] = self._last_processed_block
                    if db is not None and hasattr(db, "get_last_processed_block"):
                        try:
                            persisted = await db.get_last_processed_block(self.chain_key)
                            if isinstance(persisted, int):
                                resume_floor_block = persisted
                                self._last_processed_block = persisted
                        except Exception:
                            pass

                    # 1. Subscribe over WebSocket to ERC-721 Transfer logs filtered server-side on from=0x0
                    erc721_req = build_erc721_mint_subscription_request(req_id=1)
                    if hasattr(self.rpc, "record_call"):
                        self.rpc.record_call()
                    await ws.send(json.dumps(erc721_req))

                    # 2. Subscribe separately to ERC-1155 TransferSingle and TransferBatch mints (from=0x0)
                    erc1155_req = build_erc1155_mint_subscription_request(req_id=2)
                    if hasattr(self.rpc, "record_call"):
                        self.rpc.record_call()
                    await ws.send(json.dumps(erc1155_req))

                    # 3. Subscribe separately to newHeads for real-time block and watchdog tracking
                    new_heads_req = {"jsonrpc": "2.0", "id": 3, "method": "eth_subscribe", "params": ["newHeads"]}
                    if hasattr(self.rpc, "record_call"):
                        self.rpc.record_call()
                    await ws.send(json.dumps(new_heads_req))

                    self.ws_connected = True
                    self.last_ws_error = None
                    self.last_reconnect_reason = None
                    backoff = 1.0  # Reset backoff on successful connection

                    if has_connected_before or failed_attempts > 0:
                        self.reconnect_count += 1
                        logger.info(
                            "🔄 [%s] WebSocket reconnected automatically (reconnect #%d, resume_block=%s)",
                            self.chain_name,
                            self.reconnect_count,
                            f"#{resume_floor_block}" if resume_floor_block is not None else "latest",
                        )
                    else:
                        logger.info(
                            "⚡ [%s] WebSocket connected (resume_block=%s)",
                            self.chain_name,
                            f"#{resume_floor_block}" if resume_floor_block is not None else "latest",
                        )

                    # If resuming from a stored block in SQLite and missed blocks exist on-chain, backfill them
                    if resume_floor_block is not None and self.rpc is not None:
                        try:
                            head_blk = await self.rpc.eth_block_number()
                            if (
                                isinstance(head_blk, int)
                                and head_blk > resume_floor_block
                                and (head_blk - resume_floor_block) <= max(self.log_batch_size * 5, 50)
                            ):
                                b_start = resume_floor_block + 1
                                while b_start <= head_blk and self._running:
                                    b_end = min(b_start + self.log_batch_size - 1, head_blk)
                                    await self._poll_block_range(b_start, b_end)
                                    if db is not None and hasattr(db, "set_last_processed_block"):
                                        await db.set_last_processed_block(self.chain_key, b_end)
                                    self._last_processed_block = b_end
                                    resume_floor_block = b_end
                                    self.last_block_number = b_end
                                    self.last_block_received_at = time.time()
                                    b_start = b_end + 1
                            elif isinstance(head_blk, int) and (head_blk - resume_floor_block) > max(self.log_batch_size * 5, 50):
                                logger.warning(
                                    "[%s] Stored checkpoint #%d is %d blocks behind head #%d (>%d max catchup); fast-forwarding to avoid stale burst.",
                                    self.chain_name,
                                    resume_floor_block,
                                    head_blk - resume_floor_block,
                                    head_blk,
                                    max(self.log_batch_size * 5, 50),
                                )
                                self._last_processed_block = head_blk
                                resume_floor_block = head_blk
                                self.last_block_number = head_blk
                                self.last_block_received_at = time.time()
                                if db is not None and hasattr(db, "set_last_processed_block"):
                                    await db.set_last_processed_block(self.chain_key, head_blk)
                        except Exception as catchup_exc:
                            logger.debug(
                                "[%s] Reconnect block catchup skipped: %s",
                                self.chain_name,
                                redact_rpc_url(catchup_exc, self.ws_rpc_url),
                            )

                    has_connected_before = True
                    failed_attempts = 0
                    self.failed_reconnects = 0

                    sub_721_id: Optional[str] = None
                    sub_1155_id: Optional[str] = None
                    sub_heads_id: Optional[str] = None

                    async for message in ws:
                        if not self._running:
                            break
                        try:
                            data = json.loads(message)
                        except json.JSONDecodeError:
                            continue

                        if "error" in data and isinstance(data["error"], dict):
                            err_obj = data["error"]
                            err_code = err_obj.get("code")
                            err_msg = redact_rpc_url(err_obj.get("message", "Unknown WS RPC error"), self.ws_rpc_url)
                            if (
                                err_code in (429, -32005)
                                or "429" in err_msg.lower()
                                or "rate limit" in err_msg.lower()
                                or "compute units" in err_msg.lower()
                            ):
                                raise RuntimeError(f"WebSocket 429 rate limit: {err_msg} (code={err_code})")
                            if data.get("id") in (1, 2) or "eth_subscribe" in err_msg.lower() or err_code == -32601:
                                raise RuntimeError(
                                    f"handshake error: eth_subscribe rejected by WebSocket endpoint: {err_msg} (code={err_code})"
                                )
                            logger.warning("[%s] WebSocket RPC error: %s (code=%s)", self.chain_name, err_msg, err_code)
                            continue

                        if data.get("id") == 1 and "result" in data:
                            sub_721_id = data["result"]
                            logger.info(
                                "[%s] Subscribed to ERC-721 mint logs (server-side Transfer + from=0x0, sub_id=%s)",
                                self.chain_name,
                                sub_721_id,
                            )
                            continue
                        elif data.get("id") == 2 and "result" in data:
                            sub_1155_id = data["result"]
                            logger.info(
                                "[%s] Subscribed to ERC-1155 TransferSingle/Batch mint logs (server-side from=0x0, sub_id=%s)",
                                self.chain_name,
                                sub_1155_id,
                            )
                            continue
                        elif data.get("id") == 3 and "result" in data:
                            sub_heads_id = data["result"]
                            logger.debug(
                                "[%s] Subscribed to newHeads (sub_id=%s)",
                                self.chain_name,
                                sub_heads_id,
                            )
                            continue

                        if data.get("method") == "eth_subscription":
                            self.record_subscription_event()
                            params = data.get("params", {})
                            sub_id = params.get("subscription")
                            result = params.get("result", {})
                            if not isinstance(result, dict):
                                continue

                            # Handle newHeads block notifications
                            if (sub_heads_id and sub_id == sub_heads_id) or ("number" in result and "topics" not in result):
                                head_hex = result.get("number")
                                if head_hex is not None:
                                    try:
                                        head_blk = int(head_hex, 16) if isinstance(head_hex, str) else int(head_hex)
                                        self.last_block_number = head_blk
                                        self.last_block_received_at = time.time()
                                        if self._last_processed_block is None or head_blk > self._last_processed_block:
                                            self._last_processed_block = head_blk
                                            if db is not None and hasattr(db, "set_last_processed_block"):
                                                await db.set_last_processed_block(self.chain_key, head_blk)
                                    except Exception:
                                        pass
                                continue

                            block_hex = result.get("blockNumber")
                            blk_num: Optional[int] = None
                            if block_hex is not None:
                                try:
                                    blk_num = int(block_hex, 16) if isinstance(block_hex, str) else int(block_hex)
                                except ValueError:
                                    blk_num = None

                            # Ignore events from blocks already processed prior to reconnect/restart or older than current processed block
                            if blk_num is not None:
                                if (resume_floor_block is not None and blk_num <= resume_floor_block) or (
                                    self._last_processed_block is not None and blk_num < self._last_processed_block
                                ):
                                    if db is not None and hasattr(db, "record_suppressed_duplicate"):
                                        await db.record_suppressed_duplicate(
                                            chain_id=self.chain_id,
                                            chain=self.chain_key,
                                            contract_address=result.get("address"),
                                            tx_hash=result.get("transactionHash"),
                                            duplicate_type="already_processed_block",
                                            reason=f"Ignored event from already-processed block #{blk_num} (last_processed=#{self._last_processed_block or resume_floor_block})",
                                        )
                                    continue

                                if self.last_block_number is None or blk_num >= self.last_block_number:
                                    self.last_block_number = blk_num
                                    self.last_block_received_at = time.time()
                                if self._last_processed_block is None or blk_num > self._last_processed_block:
                                    self._last_processed_block = blk_num
                                    if db is not None and hasattr(db, "set_last_processed_block"):
                                        await db.set_last_processed_block(self.chain_key, blk_num)

                            # Client-side filter: discard events lacking tokenId topic (ERC-20 mints)
                            # and verify `from == zero address`
                            if is_mint_log_from_zero_address(result):
                                asyncio.create_task(self._handle_log(result))

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.ws_connected = False
                failed_attempts += 1
                self.failed_reconnects = failed_attempts
                reason_category, safe_err = classify_reconnect_reason(e, self.ws_rpc_url)
                self.last_reconnect_reason = reason_category
                self.last_ws_error = f"{reason_category}: {safe_err}"
                if not self._running:
                    break

                # If primary WS endpoint failed with handshake error or 429 and a fallback JSON-RPC WS endpoint is configured, switch to it
                if (
                    reason_category in ("handshake error", "429")
                    and self.fallback_ws_url
                    and self.ws_rpc_url != self.fallback_ws_url
                ):
                    logger.warning(
                        "[%s] Primary WebSocket endpoint failed with %s; switching to fallback JSON-RPC WebSocket endpoint on next attempt.",
                        self.chain_name,
                        reason_category,
                    )
                    self.ws_rpc_url = self.fallback_ws_url

                if failed_attempts >= self.max_ws_reconnects:
                    logger.warning(
                        "⚠️ [%s] WebSocket failed %d consecutive reconnects (reason: %s — %s). Falling back automatically from websocket to HTTP polling mode.",
                        self.chain_name,
                        failed_attempts,
                        reason_category,
                        safe_err,
                    )
                    await self._notify_polling_fallback(failed_attempts, reason_category, safe_err)
                    await self._run_polling_loop()
                    if self.mode == "websocket" and self._running:
                        logger.info("[%s] Returning to WebSocket attempt loop...", self.chain_name)
                        failed_attempts = 0
                        continue
                    return

                if reason_category == "429":
                    try:
                        from app.watchdog import get_warning_dispatcher
                        asyncio.create_task(
                            get_warning_dispatcher().notify_rate_limit(
                                service="WebSocket RPC",
                                chain_name=self.chain_name,
                                detail=safe_err,
                            )
                        )
                    except Exception:
                        pass
                    backoff = max(backoff, 2.0)
                    logger.warning(
                        "[%s] WebSocket reconnect reason: 429 rate-limit (attempt %d/%d) — %s. Backing off %.1fs before reconnect...",
                        self.chain_name,
                        failed_attempts,
                        self.max_ws_reconnects,
                        safe_err,
                        backoff,
                    )
                else:
                    logger.warning(
                        "[%s] WebSocket reconnect reason: %s (attempt %d/%d) — %s. Reconnecting in %.1fs...",
                        self.chain_name,
                        reason_category,
                        failed_attempts,
                        self.max_ws_reconnects,
                        safe_err,
                        backoff,
                    )

                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)

    async def _notify_polling_fallback(
        self,
        failed_attempts: int,
        reason_category: str,
        safe_err: str,
    ) -> None:
        """Send a Telegram notification when automatic fallback from websocket to polling occurs."""
        tg = getattr(self.pipeline, "telegram", None)
        if tg is None or not hasattr(tg, "send_alert"):
            return
        try:
            import html as _html
            msg = (
                f"⚠️ <b>WebSocket to Polling Fallback — {_html.escape(self.chain_name)} (Chain ID: <code>{self.chain_id}</code>)</b>\n"
                f"• <b>Failed Reconnects:</b> <code>{failed_attempts}</code>\n"
                f"• <b>Reason:</b> <code>{_html.escape(reason_category)}</code> (<code>{_html.escape(safe_err[:120])}</code>)\n"
                f"• <b>Action:</b> Automatically switched from <code>websocket</code> to <code>polling</code> mode "
                f"(<code>eth_blockNumber</code> + <code>eth_getLogs</code> every <code>{self.poll_interval_seconds:.1f}s</code>)."
            )
            await tg.send_alert(msg)
        except Exception as exc:
            logger.warning(
                "[%s] Failed to send Telegram fallback notification: %s",
                self.chain_name,
                redact_rpc_url(exc, self.ws_rpc_url),
            )

    async def force_reconnect(self, reason: str = "watchdog") -> None:
        """
        Force an immediate reconnect of the WebSocket subscriber.
        If consecutive failed reconnects reach max_ws_reconnects (5),
        automatically switches to polling mode and notifies the user on Telegram.
        """
        logger.warning("[%s] Forcing reconnect: %s", self.chain_name, reason)
        self.failed_reconnects += 1
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
        if self.failed_reconnects >= self.max_ws_reconnects and self.mode == "websocket" and self.active_mode != "polling":
            logger.warning(
                "⚠️ [%s] Reached %d consecutive failed reconnects (reason: %s). Switching to polling mode.",
                self.chain_name,
                self.failed_reconnects,
                reason,
            )
            await self._notify_polling_fallback(self.failed_reconnects, "watchdog timeout", reason)
            self.active_mode = "polling"

    async def _run_polling_loop(self) -> None:
        """
        HTTP JSON-RPC polling mode:
        - Verifies `eth_chainId` on connect against `self.chain_id`.
        - Polls `eth_blockNumber` every `self.poll_interval_seconds` (1-2s).
        - Queries `eth_getLogs` over new block ranges with the exact ERC-721 and ERC-1155 mint topic filters,
          batching ranges to stay within provider limits.
        - Persists `last_processed_block` in SQLite (`chain_sync_state`) so no blocks are missed or repeated across restarts.
        - Respects 429 rate-limit responses with exponential backoff.
        """
        self.active_mode = "polling"
        poll_backoff = 1.0
        max_poll_backoff = 60.0
        chain_verified = False
        failed_polls = 0
        current_batch_size = max(1, self.log_batch_size)
        db = getattr(self.pipeline, "db", None)

        while self._running:
            try:
                if not chain_verified:
                    await self._verify_chain_id(ws=None)
                    chain_verified = True
                    self.polling_connected = True
                    self.ws_connected = True
                    self.last_ws_error = None
                    logger.info(
                        "🟢 [%s] Polling mode active (chain_id=%d, interval=%.1fs, batch_size=%d)",
                        self.chain_name,
                        self.chain_id,
                        self.poll_interval_seconds,
                        current_batch_size,
                    )

                latest_block = await self.rpc.eth_block_number()
                self.polling_connected = True
                self.ws_connected = True
                self.last_ws_error = None
                poll_backoff = 1.0
                failed_polls = 0

                last_processed: Optional[int] = None
                if db is not None and hasattr(db, "get_last_processed_block"):
                    last_processed = await db.get_last_processed_block(self.chain_key)

                if last_processed is None:
                    # First run with no prior checkpoint in SQLite: initialize at latest_block
                    last_processed = latest_block
                    if db is not None and hasattr(db, "set_last_processed_block"):
                        await db.set_last_processed_block(self.chain_key, last_processed)
                    self.last_block_number = latest_block
                    self.last_block_received_at = time.time()
                elif latest_block > last_processed:
                    max_catchup_blocks = max(current_batch_size * 20, 500)
                    if (latest_block - last_processed) > max_catchup_blocks:
                        logger.warning(
                            "[%s] Stored checkpoint #%d is %d blocks behind head #%d (exceeds max catchup %d); fast-forwarding.",
                            self.chain_name,
                            last_processed,
                            latest_block - last_processed,
                            latest_block,
                            max_catchup_blocks,
                        )
                        last_processed = latest_block - current_batch_size
                        if db is not None and hasattr(db, "set_last_processed_block"):
                            await db.set_last_processed_block(self.chain_key, last_processed)

                    batch_start = last_processed + 1
                    while batch_start <= latest_block and self._running:
                        batch_end = min(batch_start + current_batch_size - 1, latest_block)
                        try:
                            await self._poll_block_range(batch_start, batch_end)
                        except Exception as range_exc:
                            _, range_err_str = classify_reconnect_reason(range_exc, self.ws_rpc_url)
                            low_err = range_err_str.lower()
                            if (
                                current_batch_size > 1
                                and (
                                    "range" in low_err
                                    or "limit" in low_err
                                    or "10000" in low_err
                                    or "too many" in low_err
                                    or "-32602" in low_err
                                    or "-32005" in low_err
                                )
                            ):
                                current_batch_size = max(1, current_batch_size // 2)
                                logger.warning(
                                    "[%s] Provider rejected eth_getLogs block range [%d..%d]; reducing batch_size to %d.",
                                    self.chain_name,
                                    batch_start,
                                    batch_end,
                                    current_batch_size,
                                )
                                continue
                            raise

                        if db is not None and hasattr(db, "set_last_processed_block"):
                            await db.set_last_processed_block(self.chain_key, batch_end)
                        self.last_block_number = batch_end
                        self.last_block_received_at = time.time()
                        last_processed = batch_end
                        batch_start = batch_end + 1
                else:
                    self.last_block_number = latest_block
                    self.last_block_received_at = time.time()

                await asyncio.sleep(self.poll_interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.polling_connected = False
                self.ws_connected = False
                failed_polls += 1
                reason_category, safe_err = classify_reconnect_reason(e, self.ws_rpc_url)
                self.last_reconnect_reason = reason_category
                self.last_ws_error = f"{reason_category}: {safe_err}"
                if not self._running:
                    break
                if reason_category == "chain ID mismatch":
                    chain_verified = False
                # If configured for WebSocket mode and polling encounters repeated errors (e.g. 403 on getLogs),
                # attempt to return to WebSocket mode after 3 failed polls
                if self.mode == "websocket" and failed_polls >= 3:
                    logger.info(
                        "[%s] Polling encountering errors (%s); returning to attempt WebSocket reconnection.",
                        self.chain_name,
                        safe_err,
                    )
                    return
                if reason_category == "429":
                    poll_backoff = max(poll_backoff, 2.0)
                    logger.warning(
                        "[%s] Polling 429 rate-limited (%s). Backing off %.1fs...",
                        self.chain_name,
                        safe_err,
                        poll_backoff,
                    )
                else:
                    logger.warning(
                        "[%s] Polling error (%s — %s). Retrying in %.1fs...",
                        self.chain_name,
                        reason_category,
                        safe_err,
                        poll_backoff,
                    )
                await asyncio.sleep(poll_backoff)
                poll_backoff = min(poll_backoff * 2, max_poll_backoff)

    async def _poll_block_range(self, from_block: int, to_block: int) -> int:
        """
        Fetch ERC-721 and ERC-1155 mint logs over [from_block, to_block] via eth_getLogs
        with server-side zero-address topic filters, apply client-side ERC-20 discard,
        and process all matching NFT mints. Returns number of matching mint logs processed.
        """
        from_hex = hex(from_block)
        to_hex = hex(to_block)

        filter_721 = {
            "fromBlock": from_hex,
            "toBlock": to_hex,
            "topics": [
                TRANSFER_TOPIC,
                ZERO_ADDRESS_32BYTES,
            ],
        }
        filter_1155 = {
            "fromBlock": from_hex,
            "toBlock": to_hex,
            "topics": [
                [
                    TRANSFER_SINGLE_TOPIC,
                    TRANSFER_BATCH_TOPIC,
                ],
                None,
                ZERO_ADDRESS_32BYTES,
            ],
        }

        logs_721, logs_1155 = await asyncio.gather(
            self.rpc.eth_get_logs(filter_721),
            self.rpc.eth_get_logs(filter_1155),
        )

        combined: List[Dict[str, Any]] = []
        if isinstance(logs_721, list):
            combined.extend(logs_721)
        if isinstance(logs_1155, list):
            combined.extend(logs_1155)

        matched = 0
        for log in combined:
            if not isinstance(log, dict):
                continue
            self.record_subscription_event()
            if is_mint_log_from_zero_address(log):
                matched += 1
                await self._handle_log(log)

        return matched

    async def _handle_log(self, log: Dict[str, Any]):
        """Handle a client-side filtered mint log event."""
        async with self._sem:
            try:
                now_ts = int(time.time())
                mint = await self.pipeline.parse_log_as_mint(log, block_timestamp=now_ts)
                if mint:
                    await self.pipeline.process_mint(mint)
            except Exception as e:
                logger.debug("[%s] Error processing live mint log: %s", self.chain_name, redact_rpc_url(e, self.ws_rpc_url))

    async def stop(self):
        """Stop the subscriber gracefully."""
        self._running = False
        self.ws_connected = False
        self.polling_connected = False
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        logger.info("[%s] Subscriber stopped.", self.chain_name)


class MultiChainSubscriberManager:
    """
    Runs one isolated async WebSocketSubscriber per configured chain concurrently.
    If one chain experiences an RPC outage, all other chains continue uninterrupted.
    """

    def __init__(
        self,
        subscribers: Dict[str, WebSocketSubscriber],
        pipelines: Dict[str, AlertPipeline],
        rpcs: Dict[str, EvmRpcClient],
        warning_dispatcher: Optional[Any] = None,
    ):
        self.subscribers = subscribers
        self.pipelines = pipelines
        self.rpcs = rpcs
        self._tasks: Dict[str, asyncio.Task] = {}
        try:
            from app.watchdog import get_warning_dispatcher, ChainWatchdog
            self.dispatcher = warning_dispatcher or get_warning_dispatcher()
            self.watchdog = ChainWatchdog(self.subscribers, self.rpcs, self.dispatcher)
        except Exception:
            self.watchdog = None

    async def start_all(self):
        """Launch all per-chain listeners concurrently as isolated tasks."""
        if self.watchdog is not None:
            self.watchdog.start()
        for chain_key, sub in self.subscribers.items():
            self._tasks[chain_key] = asyncio.create_task(
                self._run_isolated(chain_key, sub),
                name=f"listener-{chain_key}",
            )
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    async def _run_isolated(self, chain_key: str, sub: WebSocketSubscriber):
        """Ensure an unexpected crash in one listener never propagates to other chains."""
        while sub._running or chain_key in self._tasks:
            try:
                await sub.start()
                break
            except asyncio.CancelledError:
                break
            except Exception as e:
                sub.ws_connected = False
                safe_err = redact_rpc_url(f"{type(e).__name__}: {e}", sub.ws_rpc_url)
                sub.last_ws_error = safe_err
                logger.error("[%s] Isolated listener crash: %s. Restarting in 5s...", sub.chain_name, safe_err)
                await asyncio.sleep(5.0)

    async def stop_all(self):
        """Stop all chain listeners and close their pipelines and RPC clients."""
        if getattr(self, "watchdog", None) is not None:
            try:
                await self.watchdog.stop()
            except Exception:
                pass
        for sub in self.subscribers.values():
            await sub.stop()
        for task in self._tasks.values():
            if not task.done():
                task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()
        for pipeline in self.pipelines.values():
            await pipeline.close()
        for rpc in self.rpcs.values():
            await rpc.close()

    async def start_chain(
        self,
        chain_key: str,
        cfg: Any,
        config: Any,
        db: Any,
        telegram: Any,
    ) -> bool:
        """Dynamically launch an isolated listener for a newly enabled chain."""
        ck = chain_key.lower().strip()
        if ck in self._tasks and not self._tasks[ck].done():
            logger.info("[%s] Chain listener is already running.", getattr(cfg, "name", ck))
            return True

        from app.rpc import EvmRpcClient
        from app.pipeline import AlertPipeline

        rpc_client = self.rpcs.get(ck)
        if rpc_client is None:
            rpc_client = EvmRpcClient(
                cfg.effective_http_rpc_url,
                chain_name=cfg.name,
                fallback_rpc_url=cfg.http_rpc_url,
            )
            self.rpcs[ck] = rpc_client

        pipe = self.pipelines.get(ck)
        if pipe is None:
            pipe = AlertPipeline(
                config=config,
                db=db,
                rpc=rpc_client,
                telegram=telegram,
                chain_config=cfg,
            )
            self.pipelines[ck] = pipe

        sub = self.subscribers.get(ck)
        if sub is None:
            sub = WebSocketSubscriber(
                config=config,
                pipeline=pipe,
                rpc=rpc_client,
                chain_config=cfg,
            )
            self.subscribers[ck] = sub

        sub._running = True
        self._tasks[ck] = asyncio.create_task(
            self._run_isolated(ck, sub),
            name=f"listener-{ck}",
        )
        logger.info("🟢 [%s] Dynamically launched chain listener.", getattr(cfg, "name", ck))
        return True

    async def stop_chain(self, chain_key: str) -> bool:
        """Dynamically stop the listener task and close resources for a disabled chain."""
        ck = chain_key.lower().strip()
        sub = self.subscribers.get(ck)
        if sub:
            await sub.stop()
        task = self._tasks.pop(ck, None)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        pipe = self.pipelines.pop(ck, None)
        if pipe:
            await pipe.close()
        rpc = self.rpcs.pop(ck, None)
        if rpc:
            await rpc.close()
        self.subscribers.pop(ck, None)
        logger.info("🛑 [%s] Dynamically stopped chain listener.", ck)
        return True


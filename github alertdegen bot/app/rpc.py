"""Async EVM JSON-RPC client for executing calls, queries, logs, and storage reads."""

import asyncio
from collections import deque
import json
import logging
import re
import time
from typing import Any, Deque, Dict, List, Optional, Union
import httpx

logger = logging.getLogger(__name__)

_URL_PATTERN = re.compile(r"(?:https?|wss?)://[^\s'\"<>]+", re.IGNORECASE)


def redact_rpc_url(text: Any, rpc_url: Optional[str] = None) -> str:
    """
    Redact any RPC URLs (which may contain Alchemy/provider API keys in the path or query)
    from log messages and exception strings. Never log RPC URLs.
    """
    msg = str(text or "")
    if not msg:
        return ""
    if rpc_url:
        clean_url = rpc_url.strip()
        if clean_url:
            msg = msg.replace(clean_url, "[REDACTED_RPC_URL]")
            # Also redact the path segment (API key) if it appears separately
            parts = clean_url.rstrip("/").split("/")
            if len(parts) >= 4:
                key_seg = parts[-1]
                if len(key_seg) >= 8 and key_seg not in ("v1", "v2", "v3", "rpc", "ws", "mainnet"):
                    msg = msg.replace(key_seg, "[REDACTED_KEY]")
    msg = _URL_PATTERN.sub("[REDACTED_RPC_URL]", msg)
    return msg


class RPCError(Exception):
    """EVM JSON-RPC error."""

    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data


class EvmRpcClient:
    """Read-only Async EVM JSON-RPC Client with 1-hour call telemetry and 429 exponential backoff."""

    def __init__(
        self,
        rpc_url: str,
        timeout: float = 15.0,
        chain_name: str = "",
        fallback_rpc_url: Optional[str] = None,
    ):
        self.rpc_url = rpc_url
        self.fallback_rpc_url = (
            fallback_rpc_url
            if fallback_rpc_url and fallback_rpc_url.strip() and fallback_rpc_url.strip() != rpc_url.strip()
            else None
        )
        self.timeout = timeout
        self.chain_name = chain_name
        self._request_id = 0
        self._client: Optional[httpx.AsyncClient] = None
        self._call_timestamps: Deque[float] = deque()
        self.total_rpc_calls: int = 0
        self.rate_limit_429_count: int = 0

    def record_call(self, now: Optional[float] = None) -> None:
        """Record an RPC call in the rolling 1-hour window."""
        ts = now if now is not None else time.time()
        self.total_rpc_calls += 1
        self._call_timestamps.append(ts)
        cutoff = ts - 3600.0
        while self._call_timestamps and self._call_timestamps[0] < cutoff:
            self._call_timestamps.popleft()

    def get_rpc_calls_last_hour(self, now: Optional[float] = None) -> int:
        """Return the number of RPC calls made in the last 3600 seconds."""
        ts = now if now is not None else time.time()
        cutoff = ts - 3600.0
        while self._call_timestamps and self._call_timestamps[0] < cutoff:
            self._call_timestamps.popleft()
        return len(self._call_timestamps)

    @property
    def rpc_calls_per_hour(self) -> int:
        """Current rolling 1-hour RPC call count."""
        return self.get_rpc_calls_last_hour()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)",
                },
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def call(self, method: str, params: List[Any], retries: int = 3, backoff: float = 1.0) -> Any:
        """
        Execute a JSON-RPC request with retries and exponential backoff (including explicit
        429 rate-limit handling). Never logs the RPC URL.
        """
        client = await self._get_client()
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._request_id,
        }

        last_error: Optional[str] = None
        max_attempts = max(1, retries)
        attempt = 0

        while attempt < max_attempts:
            self.record_call()
            try:
                resp = await client.post(self.rpc_url, json=payload)

                if resp.status_code == 429:
                    self.rate_limit_429_count += 1
                    try:
                        from app.watchdog import get_warning_dispatcher
                        asyncio.create_task(
                            get_warning_dispatcher().notify_rate_limit(
                                service="HTTP RPC",
                                chain_name=self.chain_name or "EVM",
                                detail=f"HTTP 429 Too Many Requests (method={method})",
                            )
                        )
                    except Exception:
                        pass
                    resp_body_text = ""
                    try:
                        resp_body_text = resp.text.lower()
                    except Exception:
                        pass
                    if (
                        self.fallback_rpc_url
                        and self.rpc_url != self.fallback_rpc_url
                        and ("capacity limit" in resp_body_text or "monthly" in resp_body_text or "exceeded" in resp_body_text)
                    ):
                        logger.warning(
                            "[%s] Primary HTTP RPC returned HTTP 429 quota exceeded; switching to configured fallback HTTP RPC endpoint.",
                            self.chain_name or "RPC",
                        )
                        self.rpc_url = self.fallback_rpc_url
                        continue

                    # Expand retry budget for 429 rate limits up to at least 5 attempts
                    if max_attempts < 5 and retries >= 2:
                        max_attempts = 5
                    retry_after_hdr = resp.headers.get("Retry-After")
                    retry_after_sec = 0.0
                    if retry_after_hdr:
                        try:
                            retry_after_sec = float(retry_after_hdr)
                        except ValueError:
                            retry_after_sec = 0.0
                    sleep_time = max(backoff * (2 ** attempt), retry_after_sec)
                    last_error = f"HTTP 429 Too Many Requests ({method})"
                    if attempt < max_attempts - 1:
                        logger.warning(
                            "RPC %s received HTTP 429 rate limit (attempt %d/%d). Backing off %.1fs...",
                            method,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                        await asyncio.sleep(sleep_time)
                        attempt += 1
                        continue

                    if self.fallback_rpc_url and self.rpc_url != self.fallback_rpc_url:
                        logger.warning(
                            "[%s] Primary HTTP RPC rate-limited after %d attempts; switching to configured fallback HTTP RPC endpoint.",
                            self.chain_name or "RPC",
                            max_attempts,
                        )
                        self.rpc_url = self.fallback_rpc_url
                        continue

                    raise RPCError(f"RPC {method} rate limited (HTTP 429) after {max_attempts} attempts")

                if resp.status_code == 401:
                    try:
                        from app.watchdog import get_warning_dispatcher
                        asyncio.create_task(
                            get_warning_dispatcher().notify_api_key_error(
                                service="HTTP RPC",
                                chain_name=self.chain_name or "EVM",
                                status_code=401,
                                detail=f"HTTP 401 Unauthorized ({method})",
                            )
                        )
                    except Exception:
                        pass

                is_optional_trace = method.startswith(("trace_", "debug_"))
                if (
                    not is_optional_trace
                    and resp.status_code in (400, 401, 403, 404, 502, 503)
                    and self.fallback_rpc_url
                    and self.rpc_url != self.fallback_rpc_url
                ):
                    logger.warning(
                        "[%s] Primary HTTP RPC endpoint returned HTTP %d on %s; switching to configured fallback HTTP RPC endpoint.",
                        self.chain_name or "RPC",
                        resp.status_code,
                        method,
                    )
                    self.rpc_url = self.fallback_rpc_url
                    continue

                resp.raise_for_status()
                data = resp.json()

                if "error" in data:
                    err = data["error"] if isinstance(data["error"], dict) else {"message": str(data["error"])}
                    err_msg = redact_rpc_url(err.get("message", "Unknown error"), self.rpc_url)
                    err_code = err.get("code")
                    is_rate_limit_err = (
                        err_code in (429, -32005)
                        or "rate limit" in err_msg.lower()
                        or "compute units" in err_msg.lower()
                        or "429" in err_msg.lower()
                        or "too many requests" in err_msg.lower()
                    )
                    if is_rate_limit_err:
                        self.rate_limit_429_count += 1
                        try:
                            from app.watchdog import get_warning_dispatcher
                            asyncio.create_task(
                                get_warning_dispatcher().notify_rate_limit(
                                    service="JSON-RPC",
                                    chain_name=self.chain_name or "EVM",
                                    detail=f"{err_msg} (code={err_code})",
                                )
                            )
                        except Exception:
                            pass
                        if (
                            self.fallback_rpc_url
                            and self.rpc_url != self.fallback_rpc_url
                            and ("capacity limit" in err_msg.lower() or "monthly" in err_msg.lower() or "exceeded" in err_msg.lower())
                        ):
                            logger.warning(
                                "[%s] Primary HTTP RPC returned quota exceeded (%s); switching to configured fallback HTTP RPC endpoint.",
                                self.chain_name or "RPC",
                                err_msg,
                            )
                            self.rpc_url = self.fallback_rpc_url
                            continue

                        if max_attempts < 5 and retries >= 2:
                            max_attempts = 5
                        sleep_time = backoff * (2 ** attempt)
                        last_error = f"RPC 429/rate-limit ({method}): {err_msg} (code={err_code})"
                        if attempt < max_attempts - 1:
                            logger.warning(
                                "RPC %s rate-limited by provider (attempt %d/%d, code=%s). Backing off %.1fs...",
                                method,
                                attempt + 1,
                                max_attempts,
                                err_code,
                                sleep_time,
                            )
                            await asyncio.sleep(sleep_time)
                            attempt += 1
                            continue

                        if self.fallback_rpc_url and self.rpc_url != self.fallback_rpc_url:
                            logger.warning(
                                "[%s] Primary HTTP RPC rate-limited after %d attempts; switching to configured fallback HTTP RPC endpoint.",
                                self.chain_name or "RPC",
                                max_attempts,
                            )
                            self.rpc_url = self.fallback_rpc_url
                            continue
                    # Non-rate-limit revert or execution error: raise immediately
                    err_data = err.get("data")
                    raise RPCError(f"RPC Error ({method}): {err_msg} (code={err_code})", code=err_code, data=err_data)

                return data.get("result")

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                safe_err = redact_rpc_url(e, self.rpc_url)
                last_error = safe_err
                is_429 = isinstance(e, httpx.HTTPStatusError) and e.response is not None and e.response.status_code == 429
                if resp.status_code == 401:
                    try:
                        from app.watchdog import get_warning_dispatcher
                        asyncio.create_task(
                            get_warning_dispatcher().notify_api_key_error(
                                service="HTTP RPC",
                                chain_name=self.chain_name or "EVM",
                                status_code=401,
                                detail=f"HTTP 401 Unauthorized ({method})",
                            )
                        )
                    except Exception:
                        pass

                is_optional_trace = method.startswith(("trace_", "debug_"))
                if not is_429 and not is_optional_trace and self.fallback_rpc_url and self.rpc_url != self.fallback_rpc_url:
                    logger.warning(
                        "[%s] Primary HTTP RPC endpoint failed (%s); switching to configured fallback HTTP RPC endpoint.",
                        self.chain_name or "RPC",
                        safe_err,
                    )
                    self.rpc_url = self.fallback_rpc_url
                    continue
                if is_429:
                    self.rate_limit_429_count += 1
                    if max_attempts < 5 and retries >= 2:
                        max_attempts = 5
                if attempt < max_attempts - 1:
                    sleep_time = backoff * (2 ** attempt)
                    if is_429:
                        logger.warning(
                            "RPC %s hit 429 rate limit (attempt %d/%d). Backing off %.1fs...",
                            method,
                            attempt + 1,
                            max_attempts,
                            sleep_time,
                        )
                    else:
                        logger.debug(
                            "RPC %s failed (attempt %d/%d): %s. Retrying in %.1fs...",
                            method,
                            attempt + 1,
                            max_attempts,
                            safe_err,
                            sleep_time,
                        )
                    await asyncio.sleep(sleep_time)
                else:
                    logger.warning("RPC %s failed after %d attempts: %s", method, max_attempts, safe_err)
            except RPCError:
                raise

            attempt += 1

        raise RPCError(f"RPC {method} failed after {max_attempts} retries: {last_error}")

    async def eth_chain_id(self) -> int:
        """Get the current chain ID via eth_chainId."""
        result = await self.call("eth_chainId", [])
        if isinstance(result, int):
            return result
        return int(str(result), 16)

    async def eth_block_number(self) -> int:
        """Get the current latest block number."""
        result = await self.call("eth_blockNumber", [])
        return int(result, 16)

    async def eth_get_block_by_number(self, block_num: Union[int, str], full_txs: bool = False) -> Optional[Dict[str, Any]]:
        """Fetch block header by number (or 'latest'). Defaults to full_txs=False to avoid fetching full blocks."""
        num_hex = hex(block_num) if isinstance(block_num, int) else block_num
        return await self.call("eth_getBlockByNumber", [num_hex, full_txs])

    async def eth_call(
        self,
        to: str,
        data: str,
        block: str = "latest",
        from_addr: Optional[str] = None,
        value: Optional[Union[int, str]] = None,
    ) -> str:
        """Execute an eth_call (read-only smart contract call), optionally simulating from a specific sender and value."""
        tx_obj: Dict[str, Any] = {"to": to, "data": data}
        if from_addr:
            tx_obj["from"] = from_addr
        if value is not None:
            if isinstance(value, int):
                tx_obj["value"] = hex(value)
            elif isinstance(value, str):
                tx_obj["value"] = value if value.startswith("0x") else hex(int(value))
        return await self.call("eth_call", [tx_obj, block])

    async def eth_get_storage_at(self, address: str, position: str, block: str = "latest") -> str:
        """Read a 32-byte storage slot."""
        pos = position if position.startswith("0x") else hex(int(position, 16))
        return await self.call("eth_getStorageAt", [address, pos, block])

    async def eth_get_code(self, address: str, block: str = "latest") -> str:
        """Fetch contract bytecode."""
        return await self.call("eth_getCode", [address, block])

    async def eth_get_block_receipts(self, block_num: Union[int, str]) -> Optional[List[Dict[str, Any]]]:
        """Fetch all transaction receipts for a block in one call (EIP-supported)."""
        num_hex = hex(block_num) if isinstance(block_num, int) else block_num
        return await self.call("eth_getBlockReceipts", [num_hex])

    async def eth_get_transaction_receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch transaction receipt."""
        return await self.call("eth_getTransactionReceipt", [tx_hash])

    async def eth_get_transaction_by_hash(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch transaction details."""
        return await self.call("eth_getTransactionByHash", [tx_hash])

    async def eth_get_transaction_count(self, address: str, block: str = "latest") -> int:
        """Fetch total transactions sent by an address."""
        result = await self.call("eth_getTransactionCount", [address, block])
        return int(result, 16)

    async def eth_get_logs(self, filter_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query historical logs matching filter parameters."""
        return await self.call("eth_getLogs", [filter_params])


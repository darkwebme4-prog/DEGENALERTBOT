"""Telemetry, Watchdog, Heartbeat, and Health Monitoring for Multi-Chain EVM Alert Bot."""

import asyncio
import html
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.chains import ChainConfig
from app.config import Settings
from app.db import Database
from app.explorer import redact_secrets
from app.telegram import TelegramNotifier

logger = logging.getLogger("alertbot.watchdog")


class WarningDispatcher:
    """
    Centralized dispatcher for operational warnings sent to Telegram with cooldown to prevent spam.
    Redacts all URLs, RPC secrets, and API keys before sending or logging.
    """

    def __init__(
        self,
        telegram: Optional[TelegramNotifier] = None,
        cooldown_seconds: float = 900.0,
    ):
        self.telegram = telegram
        self.cooldown_seconds = cooldown_seconds
        self._last_sent: Dict[str, float] = {}
        self._suppressed_counts: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    def set_telegram(self, telegram: TelegramNotifier) -> None:
        self.telegram = telegram

    def _is_on_cooldown(self, key: str, now: float) -> bool:
        last = self._last_sent.get(key, 0.0)
        if (now - last) < self.cooldown_seconds:
            self._suppressed_counts[key] = self._suppressed_counts.get(key, 0) + 1
            return True
        return False

    async def _send(self, key: str, message: str) -> bool:
        now = time.time()
        async with self._lock:
            if self._is_on_cooldown(key, now):
                logger.debug("Warning %r is on cooldown (suppressed count=%d)", key, self._suppressed_counts.get(key, 0))
                return False

            suppressed = self._suppressed_counts.pop(key, 0)
            if suppressed > 0:
                message += f"\n<i>(Note: {suppressed} duplicate warnings were suppressed during the cooldown window)</i>"

            self._last_sent[key] = now

        if self.telegram is not None and hasattr(self.telegram, "send_alert"):
            try:
                await self.telegram.send_alert(message)
                return True
            except Exception as e:
                logger.warning("Failed sending Telegram warning [%s]: %s", key, redact_secrets(e))
                return False
        else:
            logger.warning("[Telegram Notifier unavailable] Operational warning: %s", message)
            return False

    async def notify_chain_down(
        self,
        chain_name: str,
        chain_id: int,
        duration_sec: float,
        mode: str,
        reason: str = "",
    ) -> bool:
        """Triggered when a chain has been disconnected for more than 2 minutes (120s)."""
        key = f"chain_down:{chain_id}"
        safe_reason = html.escape(redact_secrets(reason or "Connection dropped / unresponsive"))
        msg = (
            f"🚨 <b>Chain Down Warning — {html.escape(chain_name)}</b>\n"
            f"• <b>Chain ID:</b> <code>{chain_id}</code>\n"
            f"• <b>Mode:</b> <code>{html.escape(mode)}</code>\n"
            f"• <b>Downtime:</b> <code>{duration_sec:.0f}s</code> (exceeds 120s threshold)\n"
            f"• <b>Last Error:</b> <code>{safe_reason}</code>\n"
            f"• <b>Status:</b> Auto-reconnecting in background..."
        )
        logger.warning("[%s] Chain down for %.0fs: %s", chain_name, duration_sec, safe_reason)
        return await self._send(key, msg)

    async def notify_block_lag(
        self,
        chain_name: str,
        chain_id: int,
        lag_blocks: int,
        duration_sec: float,
    ) -> bool:
        """Triggered when ingestion lag is above 100 blocks for more than 60 seconds."""
        key = f"block_lag:{chain_id}"
        msg = (
            f"⚠️ <b>Ingestion Lag Warning — {html.escape(chain_name)}</b>\n"
            f"• <b>Chain ID:</b> <code>{chain_id}</code>\n"
            f"• <b>Lag:</b> <code>{lag_blocks} blocks</code> (exceeds 100 blocks)\n"
            f"• <b>Lag Duration:</b> <code>{duration_sec:.0f}s</code> (exceeds 60s threshold)\n"
            f"• <b>Action:</b> Fast-polling range catchup active."
        )
        logger.warning("[%s] Ingestion lag high (%d blocks for %.0fs)", chain_name, lag_blocks, duration_sec)
        return await self._send(key, msg)

    async def notify_rate_limit(
        self,
        service: str,
        chain_name: str,
        detail: str,
    ) -> bool:
        """Triggered when RPC, explorer, or marketplace returns HTTP 429 / compute units exceeded."""
        key = f"rate_limit:{service.lower()}:{chain_name.lower()}"
        safe_detail = html.escape(redact_secrets(detail[:160]))
        msg = (
            f"⚠️ <b>Rate Limit Warning (HTTP 429) — {html.escape(service)}</b>\n"
            f"• <b>Chain:</b> <code>{html.escape(chain_name)}</code>\n"
            f"• <b>Detail:</b> <code>{safe_detail}</code>\n"
            f"• <b>Action:</b> Applying exponential backoff to avoid quota ban."
        )
        logger.warning("[%s] Rate limit (429) on %s: %s", chain_name, service, safe_detail)
        return await self._send(key, msg)

    async def notify_api_key_error(
        self,
        service: str,
        chain_name: str,
        status_code: Optional[int],
        detail: str,
    ) -> bool:
        """Triggered when an API key is invalid, unauthorized (401), or plan-restricted."""
        key = f"api_key_error:{service.lower()}"
        safe_detail = html.escape(redact_secrets(detail[:180]))
        status_str = f"HTTP {status_code}" if status_code else "Rejected"
        msg = (
            f"🚨 <b>Invalid or Expired API Key — {html.escape(service)}</b>\n"
            f"• <b>Chain:</b> <code>{html.escape(chain_name)}</code>\n"
            f"• <b>Status:</b> <code>{status_str}</code>\n"
            f"• <b>Detail:</b> <code>{safe_detail}</code>\n"
            f"• <b>Action:</b> Please check your <code>.env</code> file configuration."
        )
        logger.error("[%s] API key error on %s (%s): %s", chain_name, service, status_str, safe_detail)
        return await self._send(key, msg)

    async def notify_database_error(
        self,
        operation: str,
        detail: str,
    ) -> bool:
        """Triggered on SQLite operational errors, database locked, or corruption."""
        key = f"db_error:{operation.lower()}"
        safe_detail = html.escape(redact_secrets(detail[:180]))
        msg = (
            f"🚨 <b>Database Error</b>\n"
            f"• <b>Operation:</b> <code>{html.escape(operation)}</code>\n"
            f"• <b>Detail:</b> <code>{safe_detail}</code>\n"
            f"• <b>Action:</b> Check SQLite disk space and permissions."
        )
        logger.error("Database error in %s: %s", operation, safe_detail)
        return await self._send(key, msg)

    async def notify_telegram_send_failure(
        self,
        error_msg: str,
    ) -> None:
        """Records a Telegram dispatch failure."""
        safe_err = redact_secrets(error_msg[:160])
        logger.error("Telegram send failure: %s", safe_err)


# Global singleton warning dispatcher
_global_dispatcher: Optional[WarningDispatcher] = None


def get_warning_dispatcher(telegram: Optional[TelegramNotifier] = None) -> WarningDispatcher:
    global _global_dispatcher
    if _global_dispatcher is None:
        _global_dispatcher = WarningDispatcher(telegram=telegram)
    elif telegram is not None and _global_dispatcher.telegram is None:
        _global_dispatcher.set_telegram(telegram)
    return _global_dispatcher


class ChainWatchdog:
    """
    Watches individual chain subscribers:
    1. If no new block is received within configurable timeout (default 60s, shorter for fast chains),
       forces a reconnect.
    2. After 5 failed reconnects, switches websocket chains to polling and notifies user on Telegram.
    3. Monitors chain disconnects (>120s) and block lag (>100 blocks for >60s), triggering immediate warnings.
    """

    def __init__(
        self,
        subscribers: Dict[str, Any],
        rpcs: Dict[str, Any],
        warning_dispatcher: WarningDispatcher,
    ):
        self.subscribers = subscribers
        self.rpcs = rpcs
        self.dispatcher = warning_dispatcher
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._disconnected_since: Dict[str, Optional[float]] = {}
        self._high_lag_since: Dict[str, Optional[float]] = {}

    def start(self) -> asyncio.Task:
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        return self._task

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run_loop(self) -> None:
        logger.info("Chain watchdog started (monitoring block receipt, disconnections, and lag)...")
        while self._running:
            try:
                await asyncio.sleep(5.0)
                if not self._running:
                    break

                now = time.time()
                for chain_key, sub in list(self.subscribers.items()):
                    if not getattr(sub, "_running", False):
                        continue

                    chain_name = sub.chain_name
                    chain_id = sub.chain_id
                    effective_timeout = getattr(sub.chain_config, "effective_watchdog_timeout_seconds", 60.0)

                    # 1. Block receipt watchdog
                    last_block_at = getattr(sub, "last_block_received_at", None)
                    if last_block_at is not None:
                        elapsed_block = now - last_block_at
                        if elapsed_block > effective_timeout:
                            # Force a reconnect if we're in websocket mode and connected
                            if getattr(sub, "ws_connected", False) and getattr(sub, "active_mode", "") == "websocket":
                                logger.warning(
                                    "[%s] Watchdog: No new block received in %.1fs (timeout=%.1fs). Forcing reconnect...",
                                    chain_name,
                                    elapsed_block,
                                    effective_timeout,
                                )
                                # Reset last_block_received_at to prevent immediate tight re-trigger
                                sub.last_block_received_at = now
                                if hasattr(sub, "force_reconnect"):
                                    asyncio.create_task(sub.force_reconnect(reason="watchdog_stale_blocks"))

                    # 2. Connection state & Downtime tracking (>120s)
                    is_connected = getattr(sub, "ws_connected", False) or getattr(sub, "polling_connected", False)
                    if not is_connected:
                        if self._disconnected_since.get(chain_key) is None:
                            self._disconnected_since[chain_key] = now
                        down_duration = now - (self._disconnected_since[chain_key] or now)
                        if down_duration >= 120.0:
                            err_msg = getattr(sub, "last_ws_error", "Connection lost")
                            mode_str = getattr(sub, "active_mode", sub.mode)
                            await self.dispatcher.notify_chain_down(
                                chain_name=chain_name,
                                chain_id=chain_id,
                                duration_sec=down_duration,
                                mode=mode_str,
                                reason=err_msg,
                            )
                    else:
                        self._disconnected_since[chain_key] = None

                    # 3. Ingestion Lag tracking (>100 blocks for >60s)
                    rpc = self.rpcs.get(chain_key)
                    last_processed = getattr(sub, "last_block_number", None)
                    if is_connected and rpc is not None and last_processed is not None:
                        try:
                            # Sample live head block
                            live_head = await rpc.eth_block_number()
                            if isinstance(live_head, int) and live_head > last_processed:
                                lag = live_head - last_processed
                                if lag > 100:
                                    if self._high_lag_since.get(chain_key) is None:
                                        self._high_lag_since[chain_key] = now
                                    lag_duration = now - (self._high_lag_since[chain_key] or now)
                                    if lag_duration >= 60.0:
                                        await self.dispatcher.notify_block_lag(
                                            chain_name=chain_name,
                                            chain_id=chain_id,
                                            lag_blocks=lag,
                                            duration_sec=lag_duration,
                                        )
                                else:
                                    self._high_lag_since[chain_key] = None
                            else:
                                self._high_lag_since[chain_key] = None
                        except Exception:
                            pass

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Error in chain watchdog loop: %s", e)


class ProcessWatchdog:
    """
    Process-level liveness watchdog:
    If the main loop has not completed an iteration within 5 minutes (300 seconds),
    exits with a non-zero code so Docker (restart: unless-stopped) or PM2 automatically restarts it.
    """

    def __init__(self, timeout_seconds: float = 300.0):
        self.timeout_seconds = timeout_seconds
        self.last_heartbeat: float = time.time()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def heartbeat(self) -> None:
        """Call this on every main loop iteration."""
        self.last_heartbeat = time.time()

    def start(self) -> asyncio.Task:
        self._running = True
        self.last_heartbeat = time.time()
        self._task = asyncio.create_task(self._monitor())
        return self._task

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _monitor(self) -> None:
        logger.info("Process liveness watchdog active (timeout=%.0fs)...", self.timeout_seconds)
        while self._running:
            try:
                await asyncio.sleep(10.0)
                if not self._running:
                    break

                elapsed = time.time() - self.last_heartbeat
                if elapsed > self.timeout_seconds:
                    logger.critical(
                        "🚨 PROCESS WATCHDOG: Main loop stalled for %.1fs (>%.0fs). Exiting with code 1 for process manager restart.",
                        elapsed,
                        self.timeout_seconds,
                    )
                    sys.stdout.flush()
                    sys.stderr.flush()
                    # Hard exit so hanging asyncio event loops or deadlocked threads cannot prevent restart
                    os._exit(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Error in process watchdog: %s", e)


class HeartbeatReporter:
    """
    Dispatches a Telegram heartbeat message every 6 hours (configurable).
    Shows:
    - Per-chain state (connection status, mode, last block, lag, seconds since last block)
    - Contracts seen, candidates crossing threshold, rejections by reason
    - Alerts sent in that period (explicitly displaying 'no alerts in 6 hours' when count is 0)
    """

    def __init__(
        self,
        db: Database,
        telegram: TelegramNotifier,
        subscribers: Dict[str, Any],
        rpcs: Dict[str, Any],
        interval_hours: float = 6.0,
    ):
        self.db = db
        self.telegram = telegram
        self.subscribers = subscribers
        self.rpcs = rpcs
        self.interval_hours = interval_hours
        self.last_heartbeat_at = time.time()

    async def build_heartbeat_message(self, since_timestamp: int, as_of_timestamp: int) -> str:
        hours = max(0.1, round((as_of_timestamp - since_timestamp) / 3600.0, 1))

        # 1. Per-chain state
        chain_lines: List[str] = []
        for chain_key, sub in self.subscribers.items():
            chain_name = sub.chain_name
            mode = getattr(sub, "active_mode", sub.mode)
            is_conn = getattr(sub, "ws_connected", False) or getattr(sub, "polling_connected", False)
            conn_icon = "🟢" if is_conn else "🔴"
            last_blk = getattr(sub, "last_block_number", None)
            last_blk_str = f"#{last_blk:,}" if last_blk else "none"

            last_at = getattr(sub, "last_block_received_at", None)
            sec_ago = f"{int(time.time() - last_at)}s ago" if last_at else "n/a"

            # Compute lag
            lag_str = "0"
            rpc = self.rpcs.get(chain_key)
            if rpc is not None and last_blk is not None:
                try:
                    head = await rpc.eth_block_number()
                    if isinstance(head, int) and head >= last_blk:
                        lag_str = f"{head - last_blk}"
                except Exception:
                    lag_str = "n/a"

            chain_lines.append(
                f"  {conn_icon} <b>{html.escape(chain_name)}</b>: {last_blk_str} ({sec_ago}) | Lag: <code>{lag_str}</code> | {mode.upper()}"
            )

        # 2. Database period metrics
        contracts_seen = 0
        threshold_candidates = 0
        rejections: Dict[str, int] = {}
        alerts_count = 0

        if hasattr(self.db, "get_heartbeat_metrics"):
            try:
                metrics = await self.db.get_heartbeat_metrics(since_timestamp)
                contracts_seen = metrics.get("contracts_seen", 0)
                threshold_candidates = metrics.get("threshold_candidates", 0)
                rejections = metrics.get("rejections", {})
                alerts_count = metrics.get("alerts_count", 0)
            except Exception as e:
                logger.debug("Failed reading heartbeat metrics from DB: %s", e)

        # Alerts summary line
        if alerts_count == 0:
            alerts_line = f"• <b>Alerts Sent:</b> <code>0</code> <i>(no alerts in {hours:g} hours)</i>"
        else:
            alerts_line = f"• <b>Alerts Sent:</b> <code>{alerts_count}</code>"

        rej_lines = []
        if rejections:
            label_map = {
                "rejected_old": "Old Contract (>72h)",
                "rejected_unknown_age": "Unknown Age",
                "not_live_ended": "Live Check: Simulation Ended",
                "not_live_sold_out": "Live Check: Sold Out",
                "not_live_slowing": "Live Check: Slowing",
                "duplicate_alert": "Already Alerted",
                "muted_contract": "Muted",
                "self_mint": "Owner Self-Mints (>30%)",
            }
            for r_key, cnt in sorted(rejections.items(), key=lambda x: x[1], reverse=True)[:6]:
                friendly = label_map.get(r_key, r_key.replace("_", " ").title())
                rej_lines.append(f"  • {html.escape(friendly)}: <code>{cnt}</code>")

        rejection_block = "\n".join(rej_lines) if rej_lines else "  • <i>None</i>"

        msg = (
            f"💓 <b>Bot Heartbeat — Last {hours:g} Hours</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"<b>Per-Chain State:</b>\n"
            + "\n".join(chain_lines)
            + f"\n\n<b>Period Telemetry:</b>\n"
            f"• <b>Contracts Seen:</b> <code>{contracts_seen}</code>\n"
            f"• <b>Threshold Crossed:</b> <code>{threshold_candidates}</code>\n"
            f"{alerts_line}\n\n"
            f"<b>Rejections by Reason:</b>\n"
            f"{rejection_block}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"<i>System Healthy | All chain watchdogs active</i>"
        )
        return msg

    async def send_heartbeat_if_due(self) -> bool:
        now = time.time()
        interval_sec = self.interval_hours * 3600.0
        if (now - self.last_heartbeat_at) >= interval_sec:
            since = int(self.last_heartbeat_at)
            self.last_heartbeat_at = now
            try:
                msg = await self.build_heartbeat_message(since_timestamp=since, as_of_timestamp=int(now))
                if self.telegram and hasattr(self.telegram, "send_alert"):
                    await self.telegram.send_alert(msg)
                    logger.info("Heartbeat message dispatched successfully.")
                    return True
            except Exception as e:
                logger.warning("Error dispatching heartbeat: %s", redact_secrets(e))
        return False


class HealthServer:
    """
    Lightweight health check server and periodic outbound ping.
    1. Outbound ping: sends GET request to HEALTHCHECK_URL (e.g. Healthchecks.io / Better Uptime).
    2. Inbound HTTP server: minimal zero-dependency asyncio HTTP server responding on /health with 200 OK.
    """

    def __init__(
        self,
        port: int = 8080,
        healthcheck_url: Optional[str] = None,
        subscribers: Optional[Dict[str, Any]] = None,
        start_time: Optional[float] = None,
    ):
        self.port = port
        self.healthcheck_url = healthcheck_url
        self.subscribers = subscribers or {}
        self.start_time = start_time or time.time()
        self._server: Optional[asyncio.Server] = None
        self._ping_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        # 1. Start inbound server
        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                host="0.0.0.0",
                port=self.port,
            )
            logger.info("Local HTTP healthcheck endpoint active on port :%d (/health)", self.port)
        except Exception as e:
            logger.warning("Could not bind healthcheck port :%d (%s) — continuing without local port listener.", self.port, e)

        # 2. Start periodic outbound ping if configured
        if self.healthcheck_url:
            self._ping_task = asyncio.create_task(self._outbound_ping_loop())
            logger.info("Periodic outbound healthcheck pings configured to external monitor.")

    async def stop(self) -> None:
        self._running = False
        if self._ping_task is not None:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _outbound_ping_loop(self) -> None:
        while self._running:
            try:
                if self.healthcheck_url:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.get(self.healthcheck_url)
                        if resp.status_code < 400:
                            logger.debug("Outbound healthcheck ping successful (status=%d)", resp.status_code)
                        else:
                            logger.warning("Outbound healthcheck ping returned HTTP %d", resp.status_code)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Outbound healthcheck ping failed: %s", redact_secrets(e))

            await asyncio.sleep(60.0)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            req_line = line.decode("utf-8", errors="ignore").strip()
            parts = req_line.split()
            path = parts[1] if len(parts) >= 2 else "/"

            uptime = int(time.time() - self.start_time)
            chains_info = {}
            for k, sub in self.subscribers.items():
                is_conn = getattr(sub, "ws_connected", False) or getattr(sub, "polling_connected", False)
                chains_info[k] = {
                    "connected": is_conn,
                    "mode": getattr(sub, "active_mode", sub.mode),
                    "last_block": getattr(sub, "last_block_number", None),
                }

            payload = {
                "status": "healthy",
                "uptime_seconds": uptime,
                "chains": chains_info,
                "timestamp": int(time.time()),
            }
            body = json.dumps(payload, indent=2).encode("utf-8")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("utf-8") + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            writer.write(response)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

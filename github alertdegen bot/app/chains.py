"""Multi-chain configuration loader and schema for chains.yaml."""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

SEQUENCER_FEED_PATTERNS = (
    "feed.mainnet.chain.robinhood.com",
    "://feed.",
)


def is_sequencer_feed_url(url: Optional[str]) -> bool:
    """
    Return True if the URL points to an Arbitrum Nitro sequencer feed
    (e.g. feed.mainnet.chain.robinhood.com) rather than a JSON-RPC endpoint.
    """
    if not url or not isinstance(url, str):
        return False
    low = url.strip().lower()
    return any(pat in low for pat in SEQUENCER_FEED_PATTERNS)


class ChainConfig(BaseModel):
    """Per-chain configuration loaded from chains.yaml."""

    key: str
    name: str
    chain_id: int
    mode: str = "websocket"  # "websocket" or "polling"
    ws_rpc_env: str
    ws_rpc_default: Optional[str] = None
    http_rpc_url: str
    native_token_symbol: str = "ETH"
    native_token_decimals: int = 18
    explorer_name: Optional[str] = None
    explorer_base_url: Optional[str] = None
    explorer_api_type: Optional[str] = None  # "etherscan_v2", "blockscout", or "none"
    explorer_family: str = "etherscan"  # "etherscan" or "blockscout"
    explorer_type: str = "etherscan"  # "etherscan", "etherscan_v2", "blockscout", or "none"
    explorer_url: str = "https://etherscan.io"
    explorer_api_base_url: str = "https://api.etherscan.io/v2/api"
    explorer_api_key_env: Optional[str] = None
    blockscout_fallback_url: Optional[str] = None
    opensea_chain_slug: Optional[str] = None
    confirmation_depth: int = 1
    mint_threshold: int = 15
    min_mints: int = 15
    window: int = 300
    cooldown: int = 1800
    max_contract_age_hours: float = 72.0
    alert_on_old_contracts: Optional[bool] = None
    realert_after_hours: Optional[float] = None
    poll_interval_seconds: float = 1.5
    log_batch_size: int = 10
    max_ws_reconnects: int = 5
    enabled: bool = True
    live_mint_max_minutes: float = 10.0
    slowing_mint_max_minutes: float = 30.0
    watchdog_timeout_seconds: Optional[float] = None

    http_rpc_env: Optional[str] = None

    @property
    def effective_watchdog_timeout_seconds(self) -> float:
        """
        Watchdog timeout per chain:
        Configurable time (default 60s, shorter 30s for fast chains).
        If no new block is received within this time, reconnect is forced.
        """
        if self.watchdog_timeout_seconds is not None and self.watchdog_timeout_seconds > 0:
            return float(self.watchdog_timeout_seconds)
        # Fast chains: Robinhood (4663), Arbitrum (42161), Base (8453), Optimism (10), Polygon (137)
        if self.chain_id in (4663, 42161, 8453, 10, 137, 999, 1329, 80094, 33139, 57073, 2741, 143, 4326, 5042):
            return 30.0
        return 60.0

    @property
    def effective_explorer_base_url(self) -> str:
        return (self.explorer_base_url or self.explorer_url or "https://etherscan.io").rstrip("/")

    @property
    def effective_explorer_name(self) -> str:
        if self.explorer_name:
            return self.explorer_name
        return "Blockscout Explorer" if self.effective_explorer_family == "blockscout" else "Etherscan"

    @property
    def effective_explorer_api_type(self) -> str:
        if self.explorer_api_type:
            return self.explorer_api_type.lower()
        return (self.explorer_type or "etherscan_v2").lower()

    @property
    def effective_explorer_family(self) -> str:
        if self.explorer_family:
            return self.explorer_family.lower()
        if "blockscout" in (self.explorer_type or "").lower():
            return "blockscout"
        return "etherscan"

    def get_explorer_links(
        self,
        address: Optional[str] = None,
        tx_hash: Optional[str] = None,
        block_number: Optional[int] = None,
        is_proxy: bool = False,
    ) -> Dict[str, Optional[str]]:
        from app.explorer import build_explorer_links
        return build_explorer_links(
            family=self.effective_explorer_family,
            base_url=self.effective_explorer_base_url,
            address=address,
            tx_hash=tx_hash,
            block_number=block_number,
            is_proxy=is_proxy,
        )

    @property
    def normalized_mode(self) -> str:
        m = (self.mode or "websocket").strip().lower()
        return "polling" if m == "polling" else "websocket"

    @staticmethod
    def _to_ws_scheme(url: str) -> str:
        u = url.strip()
        if u.startswith("https://"):
            return "wss://" + u[8:]
        if u.startswith("http://"):
            return "ws://" + u[7:]
        return u

    @staticmethod
    def _to_http_scheme(url: str) -> str:
        u = url.strip()
        if u.startswith("wss://"):
            return "https://" + u[6:]
        if u.startswith("ws://"):
            return "http://" + u[5:]
        return u

    def _sanitize_ws_candidate(self, candidate: Optional[str], source_label: str) -> Optional[str]:
        if not candidate or not candidate.strip():
            return None
        if is_sequencer_feed_url(candidate):
            logger.warning(
                "[%s] Rejecting %s because it points to the sequencer feed (feed.mainnet.chain.robinhood.com) "
                "which does not support JSON-RPC eth_subscribe.",
                self.name,
                source_label,
            )
            return None
        return self._to_ws_scheme(candidate)

    def _sanitize_http_candidate(self, candidate: Optional[str], source_label: str) -> Optional[str]:
        if not candidate or not candidate.strip():
            return None
        if is_sequencer_feed_url(candidate):
            logger.warning(
                "[%s] Rejecting %s because it points to the sequencer feed (feed.mainnet.chain.robinhood.com) "
                "rather than a JSON-RPC endpoint.",
                self.name,
                source_label,
            )
            return None
        return self._to_http_scheme(candidate)

    @property
    def effective_ws_rpc_url(self) -> str:
        """Resolve WebSocket RPC URL from environment variable or default (converting https->wss and rejecting sequencer feeds)."""
        env_val = self._sanitize_ws_candidate(os.getenv(self.ws_rpc_env), self.ws_rpc_env)
        if env_val:
            return env_val
        http_env_name = self.http_rpc_env or self.ws_rpc_env.replace("_WS_", "_HTTP_")
        http_env_val = self._sanitize_ws_candidate(os.getenv(http_env_name), http_env_name)
        if http_env_val:
            return http_env_val
        if self.key == "ethereum":
            legacy_ws = self._sanitize_ws_candidate(os.getenv("WS_RPC_URL"), "WS_RPC_URL")
            if legacy_ws:
                return legacy_ws
        default_ws = self._sanitize_ws_candidate(self.ws_rpc_default, "ws_rpc_default")
        if default_ws:
            return default_ws
        default_http = self._sanitize_ws_candidate(self.http_rpc_url, "http_rpc_url")
        if default_http:
            return default_http
        return "wss://rpc.mainnet.chain.robinhood.com" if self.chain_id == 4663 else ""

    @property
    def effective_http_rpc_url(self) -> str:
        """Resolve HTTP RPC URL from environment variable or default (converting wss->https and rejecting sequencer feeds)."""
        http_env_name = self.http_rpc_env or self.ws_rpc_env.replace("_WS_", "_HTTP_")
        http_env_val = self._sanitize_http_candidate(os.getenv(http_env_name), http_env_name)
        if http_env_val:
            return http_env_val
        ws_env_val = self._sanitize_http_candidate(os.getenv(self.ws_rpc_env), self.ws_rpc_env)
        if ws_env_val:
            return ws_env_val
        if self.key == "ethereum":
            legacy_http = self._sanitize_http_candidate(os.getenv("HTTP_RPC_URL"), "HTTP_RPC_URL")
            if legacy_http:
                return legacy_http
            legacy_ws = self._sanitize_http_candidate(os.getenv("WS_RPC_URL"), "WS_RPC_URL")
            if legacy_ws:
                return legacy_ws
        default_http = self._sanitize_http_candidate(self.http_rpc_url, "http_rpc_url")
        if default_http:
            return default_http
        return self._to_http_scheme(self.effective_ws_rpc_url)

    def resolve_explorer_api_key(self, fallback_etherscan_key: Optional[str] = None) -> Optional[str]:
        """Resolve explorer API key from env var or Etherscan V2 unified key."""
        if self.explorer_api_key_env:
            val = os.getenv(self.explorer_api_key_env)
            if val and val.strip() and val.strip() != "YourEtherscanApiKeyHere":
                return val.strip()
        if self.explorer_type in ("etherscan", "etherscan_v2"):
            env_eth = os.getenv("ETHERSCAN_API_KEY") or fallback_etherscan_key
            if env_eth and env_eth.strip() and env_eth.strip() != "YourEtherscanApiKeyHere":
                return env_eth.strip()
        return None


def _parse_scalar(val_str: str) -> Any:
    """Parse a scalar YAML value (string, int, float, bool, null)."""
    v = val_str.strip()
    if not v or v.lower() in ("null", "~", "none"):
        return None
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _fallback_yaml_parse(text: str) -> Dict[str, Any]:
    """
    Lightweight YAML parser for chains.yaml structure when PyYAML is not installed.
    Supports nested mappings (`chains:` -> `<chain_key>:` -> `<field>: <value>`).
    """
    root: Dict[str, Any] = {}
    current_section: Optional[str] = None
    current_item: Optional[str] = None

    for raw_line in text.splitlines():
        # Strip comments outside quotes
        line_no_comment = raw_line
        in_quote = False
        quote_char = ""
        for idx, ch in enumerate(raw_line):
            if ch in ('"', "'"):
                if not in_quote:
                    in_quote = True
                    quote_char = ch
                elif quote_char == ch:
                    in_quote = False
            elif ch == "#" and not in_quote:
                line_no_comment = raw_line[:idx]
                break

        if not line_no_comment.strip():
            continue

        indent = len(line_no_comment) - len(line_no_comment.lstrip(" "))
        stripped = line_no_comment.strip()
        if ":" not in stripped:
            continue

        k, _, rest = stripped.partition(":")
        key = k.strip()
        val_part = rest.strip()

        if indent == 0:
            if not val_part:
                current_section = key
                root[current_section] = {}
                current_item = None
            else:
                root[key] = _parse_scalar(val_part)
        elif indent == 2 and current_section is not None:
            if not val_part:
                current_item = key
                root[current_section][current_item] = {}
            else:
                root[current_section][key] = _parse_scalar(val_part)
        elif indent >= 4 and current_section is not None and current_item is not None:
            root[current_section][current_item][key] = _parse_scalar(val_part)

    return root


def _load_dotenv_defaults(dotenv_path: Optional[Path] = None) -> None:
    """Populate os.environ with variables from .env (using setdefault so existing env vars take precedence)."""
    candidates = []
    if dotenv_path is not None:
        candidates.append(dotenv_path)
    candidates.append(Path(".env"))
    candidates.append(Path(__file__).resolve().parent.parent / ".env")
    for env_file in candidates:
        if env_file.exists() and env_file.is_file():
            try:
                for raw_line in env_file.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    key = k.strip()
                    val = v.strip()
                    if (val.startswith('"') and val.endswith('"')) or (
                        val.startswith("'") and val.endswith("'")
                    ):
                        val = val[1:-1]
                    if key:
                        os.environ.setdefault(key, val)
            except Exception:
                pass
            break


def load_chains_yaml(
    path: str | Path = "chains.yaml", only_enabled: bool = True
) -> Dict[str, ChainConfig]:
    """Load and validate all chains from chains.yaml."""
    _load_dotenv_defaults()
    file_path = Path(path)
    if not file_path.exists():
        # Try relative to project root
        alt_path = Path(__file__).resolve().parent.parent / "chains.yaml"
        if alt_path.exists():
            file_path = alt_path
        else:
            raise FileNotFoundError(f"Chains configuration file not found at {path}")

    raw_text = file_path.read_text(encoding="utf-8")
    data: Dict[str, Any] = {}
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(raw_text) or {}
    except ImportError:
        data = _fallback_yaml_parse(raw_text)

    chains_raw = data.get("chains", data)
    result: Dict[str, ChainConfig] = {}

    for chain_key, cfg_dict in chains_raw.items():
        if not isinstance(cfg_dict, dict):
            continue
        merged = {"key": chain_key.lower(), **cfg_dict}
        chain_cfg = ChainConfig(**merged)
        if not only_enabled or chain_cfg.enabled:
            result[chain_key.lower()] = chain_cfg

    return result


async def run_chain_preflight_check(
    cfg: ChainConfig,
    timeout: float = 8.0,
    ws_listen_seconds: float = 30.0,
    min_ws_heads: int = 3,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Run pre-flight check before enabling an EVM chain:
    1. eth_chainId matches cfg.chain_id
    2. Latest block can be fetched
    3. 20-block eth_getLogs call works
    4. For websocket chains: eth_subscribe to new heads delivers at least 3 events in 30 seconds.
       If WebSocket test fails, switch cfg.mode to 'polling' and continue.
    Returns:
        (passed: bool, message: str, details: dict)
    All URLs and keys are guaranteed redacted.
    """
    import asyncio
    import time
    from app.rpc import EvmRpcClient, redact_rpc_url

    details: Dict[str, Any] = {
        "key": cfg.key,
        "name": cfg.name,
        "chain_id_expected": cfg.chain_id,
        "chain_id_actual": None,
        "latest_block": None,
        "getlogs_ok": False,
        "ws_ok": False,
        "ws_heads_count": 0,
        "mode": cfg.mode,
        "switched_to_polling": False,
        "failure_reason": None,
    }

    http_url = cfg.effective_http_rpc_url
    if not http_url:
        reason = f"Missing HTTP RPC URL for {cfg.name}"
        details["failure_reason"] = reason
        return False, reason, details

    rpc = EvmRpcClient(http_url, chain_name=cfg.name, timeout=timeout)
    try:
        # 1. eth_chainId check
        try:
            actual_chain_id = await asyncio.wait_for(rpc.eth_chain_id(), timeout=timeout)
            details["chain_id_actual"] = actual_chain_id
            if actual_chain_id != cfg.chain_id:
                reason = f"Chain ID mismatch: expected {cfg.chain_id}, got {actual_chain_id}"
                details["failure_reason"] = reason
                return False, reason, details
        except Exception as e:
            reason = f"eth_chainId failed: {redact_rpc_url(str(e))}"
            details["failure_reason"] = reason
            return False, reason, details

        # 2. Latest block fetch
        try:
            latest_blk = await asyncio.wait_for(rpc.eth_block_number(), timeout=timeout)
            details["latest_block"] = latest_blk
            if not isinstance(latest_blk, int):
                reason = f"Invalid block number returned: {latest_blk}"
                details["failure_reason"] = reason
                return False, reason, details
        except Exception as e:
            reason = f"eth_blockNumber failed: {redact_rpc_url(str(e))}"
            details["failure_reason"] = reason
            return False, reason, details

        # 3. 20-block eth_getLogs check
        try:
            from_blk = max(0, latest_blk - 20)
            logs = await asyncio.wait_for(
                rpc.eth_get_logs({"fromBlock": hex(from_blk), "toBlock": hex(latest_blk)}),
                timeout=timeout,
            )
            details["getlogs_ok"] = True
            details["logs_count"] = len(logs) if isinstance(logs, list) else 0
        except Exception as e:
            reason = f"eth_getLogs (20 blocks) failed: {redact_rpc_url(str(e))}"
            details["failure_reason"] = reason
            return False, reason, details

        # 4. For websocket chains: eth_subscribe to new heads delivers >= min_ws_heads in ws_listen_seconds
        ws_url = cfg.effective_ws_rpc_url
        if cfg.normalized_mode == "websocket" and ws_url:
            heads_count = 0
            ws_err_msg = ""
            try:
                import websockets
                import json
                async with websockets.connect(ws_url, open_timeout=7.0, close_timeout=3.0) as ws:
                    sub_req = {"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe", "params": ["newHeads"]}
                    await ws.send(json.dumps(sub_req))
                    sub_ack = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    ack_data = json.loads(sub_ack)
                    if "error" in ack_data:
                        raise Exception(f"eth_subscribe rejected: {ack_data['error']}")

                    start_t = time.time()
                    while time.time() - start_t < ws_listen_seconds and heads_count < min_ws_heads:
                        rem = ws_listen_seconds - (time.time() - start_t)
                        msg = await asyncio.wait_for(ws.recv(), timeout=min(rem, 15.0))
                        msg_data = json.loads(msg)
                        if msg_data.get("method") == "eth_subscription":
                            heads_count += 1
                details["ws_heads_count"] = heads_count
                if heads_count >= min_ws_heads:
                    details["ws_ok"] = True
                else:
                    ws_err_msg = f"Delivered only {heads_count}/{min_ws_heads} heads in {ws_listen_seconds}s"
            except Exception as w_exc:
                ws_err_msg = redact_rpc_url(str(w_exc))

            if not details["ws_ok"]:
                # Switch chain to polling mode
                cfg.mode = "polling"
                details["mode"] = "polling"
                details["switched_to_polling"] = True
                logger.warning(
                    "[%s] Pre-flight WebSocket eth_subscribe failed (%s) — automatically switched to polling mode.",
                    cfg.name,
                    ws_err_msg,
                )

        return True, "Pre-flight check passed", details
    finally:
        await rpc.close()

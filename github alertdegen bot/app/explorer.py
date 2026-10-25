"""Explorer abstraction layer with Etherscan and Blockscout implementations."""

from abc import ABC, abstractmethod
import asyncio
import json
import logging
import os
import re
import time
from typing import Optional, Tuple, List, Dict, Any
import httpx
from eth_utils import keccak, to_checksum_address

logger = logging.getLogger(__name__)

_SECRET_PARAM_RE = re.compile(
    r"((?:apikey|api_key|x-api-key|token|secret|authorization)\s*[:=]\s*[\"']?)([^\"'&\s,}]+)",
    re.IGNORECASE,
)
_URL_SECRET_PATH_RE = re.compile(
    r"((?:https?|wss?)://[^\s'\"<>]+/(?:v[0-9]+|api|rpc)/)([a-zA-Z0-9_\-]{8,})",
    re.IGNORECASE,
)
_BEARER_AUTH_RE = re.compile(
    r"(Bearer\s+)[a-zA-Z0-9_\-\.]{8,}",
    re.IGNORECASE,
)


def redact_secrets(text: Any, extra_secrets: Optional[List[Optional[str]]] = None) -> str:
    """Redact API keys, tokens, and secret query parameters from log strings and HTTP bodies."""
    s = str(text or "")
    if not s:
        return s
    s = _SECRET_PARAM_RE.sub(r"\1[REDACTED]", s)
    s = _URL_SECRET_PATH_RE.sub(r"\1[REDACTED_SECRET]", s)
    s = _BEARER_AUTH_RE.sub(r"\1[REDACTED]", s)
    candidates: List[str] = []
    if extra_secrets:
        for val in extra_secrets:
            if val and isinstance(val, str) and len(val.strip()) >= 6:
                candidates.append(val.strip())
    for env_name in (
        "ETHERSCAN_API_KEY",
        "OPENSEA_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "BASESCAN_API_KEY",
        "ARBISCAN_API_KEY",
        "OPTIMISM_ETHERSCAN_API_KEY",
        "POLYGONSCAN_API_KEY",
        "ROBINHOOD_EXPLORER_API_KEY",
    ):
        env_val = os.environ.get(env_name, "").strip()
        if len(env_val) >= 6:
            candidates.append(env_val)
    for secret in candidates:
        if secret in s:
            s = s.replace(secret, "[REDACTED]")
    return s


class ExplorerRateLimiter:
    """Async rate limiter to respect explorer API rate limits."""

    def __init__(self, min_interval: float = 0.22):
        self.min_interval = min_interval
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self._last_call = time.monotonic()


KNOWN_MINT_SELECTORS: Dict[str, str] = {
    "0x1249c58b": "mint()",
    "0xa0712d68": "mint(uint256)",
    "0x40c10f19": "mint(address,uint256)",
    "0x6a627842": "mint(address)",
    "0x2db11544": "publicMint(uint256)",
    "0x84bb1e42": "mintPublic(uint256)",
    "0x4e71d92d": "claim()",
    "0x379607f5": "claim(uint256)",
    "0xefef39a1": "purchase(uint256)",
    "0x646760c3": "freeMint(uint256)",
    "0x5b70ea9f": "freeMint()",
    "0x731133e9": "mint(address,uint256,uint256,bytes)",
    "0x156e29f6": "mint(address,uint256,uint256)",
    "0x6352211e": "ownerOf(uint256)",
    "0x00000000": "fallback()",
    "0x94bf804d": "mint(uint256,address)",
    "0x14f710fe": "mintWithSignature(tuple,bytes)",
    "0x57f7789e": "claim(address,uint256,address,uint256,tuple,bytes)",
    "0x84bc3eb0": "claim(address,uint256,uint256,address,uint256,tuple,bytes)",
    "0xd96a094a": "buy(uint256)",
    "0xa6f2ae3a": "buy()",
    "0xf242432a": "safeTransferFrom(address,address,uint256,uint256,bytes)",
}

# In-memory local signature cache (seeded with KNOWN_MINT_SELECTORS)
LOCAL_SIGNATURE_CACHE: Dict[str, str] = dict(KNOWN_MINT_SELECTORS)

FOURBYTE_API_URL = "https://www.4byte.directory/api/v1/signatures/"
ETHERSCAN_V2_API_URL = "https://api.etherscan.io/v2/api"
ETHERSCAN_V2_SUPPORTED_CHAIN_IDS = {1, 8453, 42161, 10, 137, 999, 1329, 80094, 33139, 2741, 143, 4326}
DEFAULT_BLOCKSCOUT_BY_CHAIN_ID: Dict[int, str] = {
    1: "https://eth.blockscout.com",
    8453: "https://base.blockscout.com",
    42161: "https://arbitrum.blockscout.com",
    10: "https://optimism.blockscout.com",
    137: "https://polygon.blockscout.com",
    4663: "https://explorer.mainnet.chain.robinhood.com",
    57073: "https://explorer.inkonchain.com",
    5042: "https://explorer.arc.io",
}


def resolve_selector_from_abi(selector_hex: str, abi: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    """Match a 4-byte hex selector against a contract ABI to get the exact function signature."""
    if not selector_hex or not abi or not isinstance(abi, list):
        return None
    sel = selector_hex.lower()
    if not sel.startswith("0x"):
        sel = "0x" + sel
    sel = sel[:10]

    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        name = item.get("name")
        inputs = item.get("inputs", [])
        if not name:
            continue
        input_types = ",".join(inp.get("type", "") for inp in inputs if isinstance(inp, dict))
        sig = f"{name}({input_types})"
        computed = "0x" + keccak(text=sig).hex()[:8].lower()
        if computed == sel:
            LOCAL_SIGNATURE_CACHE[sel] = sig
            return sig
    return None


async def decode_function_selector(
    selector_hex: str,
    abi: Optional[List[Dict[str, Any]]] = None,
    db: Optional[Any] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> Optional[str]:
    """
    Decode a 4-byte function selector using:
    1. Contract ABI (if available)
    2. Local signature cache (in-memory + SQLite `selector_signatures` table)
    3. 4byte.directory REST API (`https://www.4byte.directory/api/v1/signatures/?hex_signature=...`)
    4. Fallback to the raw 4-byte selector (`0x...`).
    """
    if not selector_hex:
        return None
    sel = selector_hex.strip().lower()
    if not sel.startswith("0x"):
        sel = "0x" + sel
    sel = sel[:10]
    if len(sel) < 10 or sel == "0x":
        return None

    # 1. Contract ABI
    abi_sig = resolve_selector_from_abi(sel, abi)
    if abi_sig:
        if db is not None and hasattr(db, "set_cached_selector"):
            try:
                await db.set_cached_selector(sel, abi_sig)
            except Exception:
                pass
        return abi_sig

    # 2. In-memory local signature cache
    if sel in LOCAL_SIGNATURE_CACHE:
        return LOCAL_SIGNATURE_CACHE[sel]

    # 3. SQLite local signature cache
    if db is not None and hasattr(db, "get_cached_selector"):
        try:
            cached = await db.get_cached_selector(sel)
            if cached:
                LOCAL_SIGNATURE_CACHE[sel] = cached
                return cached
        except Exception:
            pass

    # 4. 4byte.directory API lookup
    owns_client = False
    client = http_client
    try:
        if client is None or getattr(client, "is_closed", False) is True:
            client = httpx.AsyncClient(timeout=6.0, follow_redirects=True)
            owns_client = True
        resp = await client.get(FOURBYTE_API_URL, params={"hex_signature": sel})
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results") if isinstance(data, dict) else None
            if isinstance(results, list) and results:
                # Prefer earliest registered signature (lowest id) or mint/claim signature on collision
                sorted_res = sorted(
                    [r for r in results if isinstance(r, dict) and r.get("text_signature")],
                    key=lambda r: (
                        0 if any(k in str(r.get("text_signature", "")).lower() for k in ("mint", "claim", "buy", "purchase")) else 1,
                        int(r.get("id", 999999999)),
                    ),
                )
                if sorted_res:
                    text_sig = str(sorted_res[0]["text_signature"]).strip()
                    if text_sig:
                        LOCAL_SIGNATURE_CACHE[sel] = text_sig
                        if db is not None and hasattr(db, "set_cached_selector"):
                            try:
                                await db.set_cached_selector(sel, text_sig)
                            except Exception:
                                pass
                        return text_sig
        else:
            logger.warning(
                "4byte.directory lookup failed for selector %s: HTTP status=%d body=%s",
                sel,
                resp.status_code,
                resp.text[:500],
            )
    except Exception as e:
        logger.warning("4byte.directory lookup error for selector %s: %s", sel, e)
    finally:
        if owns_client and client is not None:
            await client.aclose()

    # 5. Fallback to raw selector
    return sel



def _format_eth_wei(wei: Optional[int], symbol: str = "ETH", decimals: int = 18) -> Optional[str]:
    if wei is None:
        return None
    if wei == 0:
        return f"0 {symbol} (Free)"
    div = 10 ** max(0, int(decimals))
    eth = wei / div
    if eth >= 0.0001:
        return f"{eth:.4f}".rstrip("0").rstrip(".") + f" {symbol}"
    return f"{eth:.6f} {symbol}"


def _parse_int_or_iso_timestamp(val: Any) -> Optional[int]:
    """Parse an integer/hex unix timestamp or ISO-8601 timestamp string into unix seconds."""
    if val is None or val == "":
        return None
    if isinstance(val, int):
        return val if val > 0 else None
    s = str(val).strip()
    if not s:
        return None
    try:
        if s.startswith("0x"):
            parsed = int(s, 16)
        else:
            parsed = int(s)
        return parsed if parsed > 0 else None
    except ValueError:
        pass
    try:
        from datetime import datetime, timezone
        iso_s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ts = int(dt.timestamp())
        return ts if ts > 0 else None
    except Exception:
        return None


def _parse_block_num(val: Any) -> Optional[int]:
    """Parse an integer or hex block number."""
    if val is None or val == "":
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    s = str(val).strip()
    if not s:
        return None
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def build_etherscan_family_links(
    base_url: str,
    address: Optional[str] = None,
    tx_hash: Optional[str] = None,
    block_number: Optional[int] = None,
    is_proxy: bool = False,
) -> Dict[str, Optional[str]]:
    """
    Build URLs for Etherscan-family block explorers (Etherscan, Basescan, Arbiscan, etc.).
    Format:
    - address: {base_url}/address/{address}
    - tx: {base_url}/tx/{tx_hash}
    - write_contract: {base_url}/address/{address}#writeContract (or #writeProxyContract)
    - block: {base_url}/block/{block_number}
    """
    clean_base = (base_url or "").rstrip("/")
    if not clean_base:
        return {"address": None, "tx": None, "write_contract": None, "block": None}
    addr_clean = address.strip() if address else None
    tx_clean = tx_hash.strip() if tx_hash else None
    write_anchor = "#writeProxyContract" if is_proxy else "#writeContract"

    return {
        "address": f"{clean_base}/address/{addr_clean}" if addr_clean else None,
        "tx": f"{clean_base}/tx/{tx_clean}" if tx_clean else None,
        "write_contract": f"{clean_base}/address/{addr_clean}{write_anchor}" if addr_clean else None,
        "block": f"{clean_base}/block/{block_number}" if block_number is not None else None,
    }


def build_blockscout_family_links(
    base_url: str,
    address: Optional[str] = None,
    tx_hash: Optional[str] = None,
    block_number: Optional[int] = None,
    is_proxy: bool = False,
) -> Dict[str, Optional[str]]:
    """
    Build URLs for Blockscout-family block explorers (Robinhood Blockscout, Ink Explorer, etc.).
    Format:
    - address: {base_url}/address/{address}
    - tx: {base_url}/tx/{tx_hash}
    - write_contract: {base_url}/address/{address}?tab=write_contract (or ?tab=write_proxy)
    - block: {base_url}/block/{block_number}
    """
    clean_base = (base_url or "").rstrip("/")
    if not clean_base:
        return {"address": None, "tx": None, "write_contract": None, "block": None}
    addr_clean = address.strip() if address else None
    tx_clean = tx_hash.strip() if tx_hash else None
    write_query = "?tab=write_proxy" if is_proxy else "?tab=write_contract"

    return {
        "address": f"{clean_base}/address/{addr_clean}" if addr_clean else None,
        "tx": f"{clean_base}/tx/{tx_clean}" if tx_clean else None,
        "write_contract": f"{clean_base}/address/{addr_clean}{write_query}" if addr_clean else None,
        "block": f"{clean_base}/block/{block_number}" if block_number is not None else None,
    }


def build_explorer_links(
    family: str,
    base_url: str,
    address: Optional[str] = None,
    tx_hash: Optional[str] = None,
    block_number: Optional[int] = None,
    is_proxy: bool = False,
) -> Dict[str, Optional[str]]:
    """Dispatch to family-specific link builder (etherscan or blockscout)."""
    fam = (family or "etherscan").strip().lower()
    if fam == "blockscout":
        return build_blockscout_family_links(
            base_url=base_url,
            address=address,
            tx_hash=tx_hash,
            block_number=block_number,
            is_proxy=is_proxy,
        )
    return build_etherscan_family_links(
        base_url=base_url,
        address=address,
        tx_hash=tx_hash,
        block_number=block_number,
        is_proxy=is_proxy,
    )


class BlockExplorer(ABC):
    """Abstract base interface for EVM block explorers (Etherscan, Blockscout)."""

    def __init__(
        self,
        explorer_type: str,
        explorer_url: str,
        api_base_url: str,
        chain_id: int = 1,
        api_key: Optional[str] = None,
        native_token_symbol: str = "ETH",
        native_token_decimals: int = 18,
        rate_limit_interval: float = 0.22,
        explorer_name: Optional[str] = None,
        explorer_base_url: Optional[str] = None,
        explorer_family: Optional[str] = None,
    ):
        self.explorer_type = explorer_type
        eff_base_url = (explorer_base_url or explorer_url or "https://etherscan.io").rstrip("/")
        self.explorer_url = eff_base_url
        self.explorer_base_url = eff_base_url
        self.explorer_name = explorer_name
        self.explorer_family = (explorer_family or ("blockscout" if "blockscout" in explorer_type.lower() else "etherscan")).lower()
        self.api_base_url = api_base_url.rstrip("/")
        self.chain_id = chain_id
        self.api_key = api_key
        self.native_token_symbol = native_token_symbol
        self.native_token_decimals = int(native_token_decimals) if native_token_decimals is not None else 18
        self._limiter = ExplorerRateLimiter(min_interval=rate_limit_interval)
        self._http: Optional[httpx.AsyncClient] = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http is None or getattr(self._http, "is_closed", False) is True:
            self._http = httpx.AsyncClient(
                timeout=12.0,
                follow_redirects=True,
                headers={"User-Agent": "DegenAlertBot/1.0", "Accept": "application/json"},
            )
        return self._http

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    def address_url(self, address: str) -> str:
        links = build_explorer_links(self.explorer_family, self.explorer_url, address=address)
        return links.get("address") or f"{self.explorer_url}/address/{address}"

    def write_contract_url(self, address: str) -> str:
        links = build_explorer_links(self.explorer_family, self.explorer_url, address=address, is_proxy=False)
        return links.get("write_contract") or f"{self.explorer_url}/address/{address}#writeContract"

    def write_proxy_url(self, address: str) -> str:
        links = build_explorer_links(self.explorer_family, self.explorer_url, address=address, is_proxy=True)
        return links.get("write_contract") or f"{self.explorer_url}/address/{address}#writeProxyContract"

    def tx_url(self, tx_hash: str) -> str:
        links = build_explorer_links(self.explorer_family, self.explorer_url, tx_hash=tx_hash)
        return links.get("tx") or f"{self.explorer_url}/tx/{tx_hash}"

    def block_url(self, block_number: int) -> str:
        links = build_explorer_links(self.explorer_family, self.explorer_url, block_number=block_number)
        return links.get("block") or f"{self.explorer_url}/block/{block_number}"

    @abstractmethod
    async def fetch_verification_and_abi(
        self, address: str
    ) -> Tuple[Optional[bool], str, Optional[str], Optional[List[Dict[str, Any]]]]:
        """Return (is_verified, status_str, proxy_impl_address, parsed_abi). Returns (None, 'unavailable', None, None) if lookup fails."""

    @abstractmethod
    async def fetch_deployer(self, address: str) -> Optional[str]:
        """Return contract creator / deployer address."""

    async def fetch_contract_creation(
        self, address: str
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Return (deployer_address, creation_tx_hash, deployed_block, deployed_timestamp)
        using the explorer's contract-creation endpoint.
        """
        deployer = await self.fetch_deployer(address)
        return deployer, None, None, None

    @abstractmethod
    async def fetch_deployer_history(
        self, deployer: str
    ) -> Tuple[Optional[int], Optional[str]]:
        """Return (first_tx_timestamp, earliest_funder_description)."""

    @abstractmethod
    async def fetch_recent_mint_tx(
        self, address: str, abi: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[Optional[int], Optional[str]]:
        """Return (tx_value_wei, mint_function_name) from recent mint transactions."""

    @abstractmethod
    async def fetch_top_minters(
        self, address: str, known_total_supply: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[float]]:
        """Return (top_5_minters_list, top_5_concentration_pct)."""

    @abstractmethod
    async def fetch_latest_contract_tx(
        self, address: str
    ) -> Tuple[Optional[int], Optional[str]]:
        """Return (block_number, tx_hash) for the most recent on-chain transfer/transaction of the contract."""

    async def fetch_deployer_created_contracts(self, deployer: str) -> List[str]:
        """Return list of contract addresses deployed by `deployer` according to the block explorer."""
        return []

    async def fetch_token_holder_counts(
        self, address: str
    ) -> Tuple[Optional[int], Optional[int]]:
        """Return (holder_count, unique_holders) for a token contract, or (None, None) when unavailable."""
        return None, None


class BlockscoutExplorer(BlockExplorer):
    """Blockscout REST v2 + legacy RPC explorer implementation."""

    def __init__(
        self,
        explorer_url: str,
        api_base_url: Optional[str] = None,
        chain_id: int = 1,
        api_key: Optional[str] = None,
        native_token_symbol: str = "ETH",
        native_token_decimals: int = 18,
        rate_limit_interval: float = 0.20,
        explorer_name: Optional[str] = None,
        explorer_base_url: Optional[str] = None,
        explorer_family: Optional[str] = None,
    ):
        super().__init__(
            explorer_type="blockscout",
            explorer_url=explorer_url,
            api_base_url=api_base_url or explorer_url,
            chain_id=chain_id,
            api_key=api_key,
            native_token_symbol=native_token_symbol,
            native_token_decimals=native_token_decimals,
            rate_limit_interval=rate_limit_interval,
            explorer_name=explorer_name,
            explorer_base_url=explorer_base_url,
            explorer_family=explorer_family or "blockscout",
        )

    async def _call_v2(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        await self._limiter.acquire()
        url = f"{self.api_base_url}/{path.lstrip('/')}"
        q = dict(params or {})
        if self.api_key:
            q["apikey"] = self.api_key
        client = await self._get_http_client()
        try:
            resp = await client.get(url, params=q)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 429:
                try:
                    from app.watchdog import get_warning_dispatcher
                    asyncio.create_task(
                        get_warning_dispatcher().notify_rate_limit(
                            service="Blockscout",
                            chain_name=f"Chain {self.chain_id}",
                            detail=f"HTTP 429 Rate Limit on {path}",
                        )
                    )
                except Exception:
                    pass
            elif resp.status_code == 401:
                try:
                    from app.watchdog import get_warning_dispatcher
                    asyncio.create_task(
                        get_warning_dispatcher().notify_api_key_error(
                            service="Blockscout",
                            chain_name=f"Chain {self.chain_id}",
                            status_code=401,
                            detail=f"HTTP 401 Unauthorized on {path}",
                        )
                    )
                except Exception:
                    pass
            logger.warning(
                "Blockscout v2 API failure (%s, chain_id=%d, path=%s): HTTP status=%d body=%s",
                self.api_base_url,
                self.chain_id,
                path,
                resp.status_code,
                redact_secrets(resp.text[:1000], [self.api_key]),
            )
        except Exception as e:
            logger.warning(
                "Blockscout v2 request error (%s, chain_id=%d) on %s: %s",
                self.api_base_url,
                self.chain_id,
                path,
                redact_secrets(e, [self.api_key]),
            )
        return None

    async def _call_rpc_api(self, params: dict) -> Optional[dict]:
        await self._limiter.acquire()
        base = self.api_base_url[:-4] if self.api_base_url.endswith("/api") else self.api_base_url
        url = f"{base}/api"
        q = dict(params)
        if self.api_key:
            q["apikey"] = self.api_key
        client = await self._get_http_client()
        try:
            resp = await client.get(url, params=q)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and data.get("status") == "0":
                    logger.warning(
                        "Blockscout RPC API non-success (%s, chain_id=%d, action=%s): HTTP status=%d body=%s",
                        self.api_base_url,
                        self.chain_id,
                        params.get("action"),
                        resp.status_code,
                        redact_secrets(resp.text[:1000], [self.api_key]),
                    )
                return data
            logger.warning(
                "Blockscout RPC API HTTP failure (%s, chain_id=%d, action=%s): HTTP status=%d body=%s",
                self.api_base_url,
                self.chain_id,
                params.get("action"),
                resp.status_code,
                redact_secrets(resp.text[:1000], [self.api_key]),
            )
        except Exception as e:
            logger.warning(
                "Blockscout RPC API request error (%s, chain_id=%d, action=%s): %s",
                self.api_base_url,
                self.chain_id,
                params.get("action"),
                redact_secrets(e, [self.api_key]),
            )
        return None

    async def fetch_verification_and_abi(
        self, address: str
    ) -> Tuple[Optional[bool], str, Optional[str], Optional[List[Dict[str, Any]]]]:
        # 1. Try Blockscout v2 /api/v2/smart-contracts/{address}
        sc_v2 = await self._call_v2(f"/api/v2/smart-contracts/{address}")
        if sc_v2 and isinstance(sc_v2, dict) and ("is_verified" in sc_v2 or "abi" in sc_v2):
            is_verified = bool(sc_v2.get("is_verified"))
            abi = sc_v2.get("abi") if isinstance(sc_v2.get("abi"), list) else None
            impl_addr = None
            implementations = sc_v2.get("implementations")
            if isinstance(implementations, list) and implementations:
                first_impl = implementations[0]
                if isinstance(first_impl, dict):
                    raw_i = first_impl.get("address_hash") or first_impl.get("address")
                    if raw_i:
                        try:
                            impl_addr = to_checksum_address(raw_i)
                        except Exception:
                            pass
            return is_verified, ("Verified ✅" if is_verified else "Unverified ⚠️"), impl_addr, abi

        # 2. Try Blockscout legacy getsourcecode
        data = await self._call_rpc_api(
            {"module": "contract", "action": "getsourcecode", "address": address}
        )
        if data and isinstance(data, dict) and data.get("status") in ("0", "1"):
            res = data.get("result")
            if isinstance(res, list) and len(res) > 0 and isinstance(res[0], dict):
                item = res[0]
                source = (item.get("SourceCode") or "").strip()
                abi_str = (item.get("ABI") or "").strip()
                is_verified = bool(source) and abi_str != "Contract source code not verified"
                parsed_abi = None
                if is_verified and abi_str.startswith("["):
                    try:
                        parsed_abi = json.loads(abi_str)
                    except Exception:
                        pass
                impl_addr = None
                impl_raw = item.get("Implementation", "")
                if impl_raw and impl_raw.startswith("0x") and len(impl_raw) == 42:
                    try:
                        impl_addr = to_checksum_address(impl_raw)
                    except Exception:
                        pass
                return is_verified, ("Verified ✅" if is_verified else "Unverified ⚠️"), impl_addr, parsed_abi
            return False, "Unverified ⚠️", None, None

        return None, "unavailable", None, None

    async def fetch_deployer(self, address: str) -> Optional[str]:
        v2_data = await self._call_v2(f"/api/v2/addresses/{address}")
        if v2_data and isinstance(v2_data, dict):
            creator = v2_data.get("creator_address_hash")
            if creator and creator.startswith("0x"):
                try:
                    return to_checksum_address(creator)
                except Exception:
                    return creator

        data = await self._call_rpc_api(
            {"module": "contract", "action": "getcontractcreation", "contractaddresses": address}
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
            creator = data["result"][0].get("contractCreator")
            if creator:
                try:
                    return to_checksum_address(creator)
                except Exception:
                    return creator
        return None

    async def fetch_contract_creation(
        self, address: str
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Query Blockscout v2 /api/v2/addresses/{address} + creation tx and legacy getcontractcreation
        to determine (deployer, creation_tx_hash, deployed_block, deployed_timestamp).
        """
        deployer: Optional[str] = None
        tx_hash: Optional[str] = None
        block_num: Optional[int] = None
        timestamp: Optional[int] = None

        # 1. Blockscout v2 /api/v2/addresses/{address}
        v2_data = await self._call_v2(f"/api/v2/addresses/{address}")
        if v2_data and isinstance(v2_data, dict):
            raw_creator = v2_data.get("creator_address_hash")
            if raw_creator and str(raw_creator).startswith("0x"):
                try:
                    deployer = to_checksum_address(str(raw_creator))
                except Exception:
                    deployer = str(raw_creator)
            raw_tx = v2_data.get("creation_transaction_hash") or v2_data.get("creation_tx_hash")
            if raw_tx and str(raw_tx).startswith("0x"):
                tx_hash = str(raw_tx)

        # If we got creation_tx_hash from v2, inspect /api/v2/transactions/{tx_hash} for block & timestamp
        if tx_hash:
            tx_v2 = await self._call_v2(f"/api/v2/transactions/{tx_hash}")
            if tx_v2 and isinstance(tx_v2, dict):
                block_num = _parse_block_num(tx_v2.get("block_number") or tx_v2.get("block"))
                timestamp = _parse_int_or_iso_timestamp(tx_v2.get("timestamp"))
                if not deployer:
                    frm = (tx_v2.get("from") or {}).get("hash") if isinstance(tx_v2.get("from"), dict) else None
                    if frm and str(frm).startswith("0x"):
                        try:
                            deployer = to_checksum_address(str(frm))
                        except Exception:
                            deployer = str(frm)

        # 2. Legacy getcontractcreation endpoint
        if not deployer or not tx_hash or block_num is None or timestamp is None:
            data = await self._call_rpc_api(
                {"module": "contract", "action": "getcontractcreation", "contractaddresses": address}
            )
            if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
                item = data["result"][0]
                if isinstance(item, dict):
                    if not deployer and item.get("contractCreator"):
                        try:
                            deployer = to_checksum_address(item["contractCreator"])
                        except Exception:
                            deployer = item["contractCreator"]
                    if not tx_hash and item.get("txHash"):
                        tx_hash = str(item["txHash"])
                    if block_num is None:
                        block_num = _parse_block_num(item.get("blockNumber"))
                    if timestamp is None:
                        timestamp = _parse_int_or_iso_timestamp(
                            item.get("timestamp") or item.get("timeStamp")
                        )

        return deployer, tx_hash, block_num, timestamp

    async def fetch_deployer_history(
        self, deployer: str
    ) -> Tuple[Optional[int], Optional[str]]:
        data = await self._call_rpc_api(
            {
                "module": "account",
                "action": "txlist",
                "address": deployer,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": 15,
                "sort": "asc",
            }
        )
        if not data or data.get("status") != "1" or not isinstance(data.get("result"), list) or not data["result"]:
            return None, None

        txs = data["result"]
        first_ts: Optional[int] = None
        try:
            first_ts = int(txs[0].get("timeStamp", 0)) or None
        except (ValueError, TypeError):
            first_ts = None

        funder_str: Optional[str] = None
        dep_lower = deployer.lower()
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            to_addr = (tx.get("to") or "").lower()
            from_addr = tx.get("from") or ""
            val_str = tx.get("value") or "0"
            try:
                val_wei = int(val_str)
            except ValueError:
                val_wei = 0
            if to_addr == dep_lower and from_addr and from_addr.lower() != dep_lower and val_wei > 0:
                funder_checksum = to_checksum_address(from_addr)
                eth_str = _format_eth_wei(val_wei, self.native_token_symbol, self.native_token_decimals)
                funder_str = f"{funder_checksum} ({eth_str})"
                break

        if not funder_str and txs:
            first_from = txs[0].get("from")
            if first_from and first_from.lower() != dep_lower:
                try:
                    funder_str = to_checksum_address(first_from)
                except Exception:
                    funder_str = first_from

        return first_ts, funder_str

    async def fetch_recent_mint_tx(
        self, address: str, abi: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[Optional[int], Optional[str]]:
        bs_txs = await self._call_v2(f"/api/v2/addresses/{address}/transactions")
        if bs_txs and isinstance(bs_txs.get("items"), list):
            client = await self._get_http_client()
            for tx in bs_txs["items"][:15]:
                method = tx.get("method") or ""
                raw_input = tx.get("raw_input") or ""
                sel = raw_input[:10].lower() if len(raw_input) >= 10 else ""
                if (
                    any(k in method.lower() for k in ("mint", "claim", "purchase", "buy"))
                    or sel in LOCAL_SIGNATURE_CACHE
                    or sel
                ):
                    val_str = tx.get("value") or "0"
                    try:
                        val_wei = int(val_str)
                    except ValueError:
                        val_wei = 0
                    decoded_sel = await decode_function_selector(sel, abi=abi, http_client=client) if sel else None
                    if decoded_sel and not decoded_sel.startswith("0x"):
                        fn_name = decoded_sel
                    elif method and not method.startswith("0x"):
                        fn_name = f"{method}()" if "(" not in method else method
                    else:
                        fn_name = decoded_sel or (sel if sel else None)
                    return val_wei, fn_name
        return None, None

    async def fetch_top_minters(
        self, address: str, known_total_supply: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[float]]:
        bs_transfers = await self._call_v2(f"/api/v2/tokens/{address}/transfers")
        if bs_transfers and isinstance(bs_transfers.get("items"), list):
            counts: Dict[str, int] = {}
            total = 0
            zero_addr = "0x0000000000000000000000000000000000000000"
            for item in bs_transfers["items"]:
                if not isinstance(item, dict):
                    continue
                frm_hash = ((item.get("from") or {}).get("hash") or "").lower()
                to_hash = (item.get("to") or {}).get("hash")
                if to_hash and to_hash.lower() != zero_addr and frm_hash == zero_addr:
                    addr_cs = to_checksum_address(to_hash)
                    counts[addr_cs] = counts.get(addr_cs, 0) + 1
                    total += 1

            if total == 0:
                bs_holders = await self._call_v2(f"/api/v2/tokens/{address}/holders")
                if bs_holders and isinstance(bs_holders.get("items"), list):
                    token_info = bs_holders["items"][0].get("token") or {} if bs_holders["items"] else {}
                    try:
                        supply = int(token_info.get("total_supply") or 0)
                    except ValueError:
                        supply = 0
                    if supply <= 0 and known_total_supply and known_total_supply > 0:
                        supply = known_total_supply
                    top_list = []
                    for h in bs_holders["items"][:5]:
                        owner_hash = (h.get("address") or {}).get("hash")
                        val_str = h.get("value") or "0"
                        try:
                            cnt = int(val_str)
                        except ValueError:
                            cnt = 0
                        if owner_hash and owner_hash.lower() != zero_addr and cnt > 0:
                            pct = round((cnt / supply) * 100.0, 1) if supply > 0 else 0.0
                            top_list.append({"address": to_checksum_address(owner_hash), "count": cnt, "pct": pct})
                    if top_list:
                        top5_pct = round(sum(x["pct"] for x in top_list), 1)
                        return top_list, min(100.0, top5_pct)

            if total > 0:
                sorted_minters = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
                top_list = [
                    {
                        "address": m_addr,
                        "count": cnt,
                        "pct": round((cnt / total) * 100.0, 1),
                    }
                    for m_addr, cnt in sorted_minters
                ]
                top5_pct = round(sum(x["pct"] for x in top_list), 1)
                return top_list, min(100.0, top5_pct)

        return [], None

    async def fetch_latest_contract_tx(
        self, address: str
    ) -> Tuple[Optional[int], Optional[str]]:
        # 1. Check token transfers on Blockscout v2
        bs_transfers = await self._call_v2(f"/api/v2/tokens/{address}/transfers")
        if bs_transfers and isinstance(bs_transfers.get("items"), list) and bs_transfers["items"]:
            first = bs_transfers["items"][0]
            if isinstance(first, dict):
                blk = first.get("block_number")
                txh = first.get("transaction_hash") or first.get("tx_hash")
                if blk and txh:
                    try:
                        return int(blk), str(txh)
                    except (ValueError, TypeError):
                        pass

        # 2. Check address transactions on Blockscout v2
        bs_txs = await self._call_v2(f"/api/v2/addresses/{address}/transactions")
        if bs_txs and isinstance(bs_txs.get("items"), list) and bs_txs["items"]:
            first = bs_txs["items"][0]
            if isinstance(first, dict):
                blk = first.get("block_number")
                txh = first.get("hash")
                if blk and txh:
                    try:
                        return int(blk), str(txh)
                    except (ValueError, TypeError):
                        pass

        return None, None

    async def fetch_deployer_created_contracts(self, deployer: str) -> List[str]:
        created: List[str] = []
        bs_txs = await self._call_v2(f"/api/v2/addresses/{deployer}/transactions")
        if bs_txs and isinstance(bs_txs.get("items"), list):
            for tx in bs_txs["items"]:
                if not isinstance(tx, dict):
                    continue
                cc = tx.get("created_contract")
                raw_addr = cc.get("hash") if isinstance(cc, dict) else None
                if raw_addr and str(raw_addr).startswith("0x"):
                    try:
                        cs = to_checksum_address(str(raw_addr))
                    except Exception:
                        cs = str(raw_addr)
                    if cs.lower() not in {x.lower() for x in created}:
                        created.append(cs)
        if created:
            return created

        data = await self._call_rpc_api(
            {
                "module": "account",
                "action": "txlist",
                "address": deployer,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": 100,
                "sort": "desc",
            }
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list):
            for tx in data["result"]:
                if not isinstance(tx, dict):
                    continue
                c_addr = (tx.get("contractAddress") or "").strip()
                if c_addr and c_addr.startswith("0x") and len(c_addr) == 42:
                    try:
                        cs = to_checksum_address(c_addr)
                    except Exception:
                        cs = c_addr
                    if cs.lower() not in {x.lower() for x in created}:
                        created.append(cs)
        return created

    async def fetch_token_holder_counts(
        self, address: str
    ) -> Tuple[Optional[int], Optional[int]]:
        tok_v2 = await self._call_v2(f"/api/v2/tokens/{address}")
        if tok_v2 and isinstance(tok_v2, dict):
            raw_holders = tok_v2.get("holders") or tok_v2.get("holders_count")
            if raw_holders is not None:
                try:
                    cnt = int(str(raw_holders))
                    if cnt >= 0:
                        return cnt, cnt
                except (ValueError, TypeError):
                    pass

        bs_holders = await self._call_v2(f"/api/v2/tokens/{address}/holders")
        if bs_holders and isinstance(bs_holders.get("items"), list) and bs_holders["items"]:
            zero_addr = "0x0000000000000000000000000000000000000000"
            uniq = set()
            for h in bs_holders["items"]:
                if not isinstance(h, dict):
                    continue
                owner_hash = ((h.get("address") or {}).get("hash") or "").lower()
                if owner_hash and owner_hash != zero_addr:
                    uniq.add(owner_hash)
            if uniq:
                return len(uniq), len(uniq)

        return None, None


class EtherscanExplorer(BlockExplorer):
    """Etherscan V2 explorer implementation (`https://api.etherscan.io/v2/api?chainid=...`) with automatic Blockscout fallback."""

    def __init__(
        self,
        explorer_url: str = "https://etherscan.io",
        api_base_url: str = ETHERSCAN_V2_API_URL,
        chain_id: int = 1,
        api_key: Optional[str] = None,
        native_token_symbol: str = "ETH",
        native_token_decimals: int = 18,
        fallback_blockscout: Optional[BlockscoutExplorer] = None,
        rate_limit_interval: float = 0.22,
        explorer_name: Optional[str] = None,
        explorer_base_url: Optional[str] = None,
        explorer_family: Optional[str] = None,
    ):
        # Always normalize V1 Basescan/Etherscan/Arbiscan/Polygonscan URLs to Etherscan V2 API for supported chains
        normalized_api_url = (api_base_url or ETHERSCAN_V2_API_URL).rstrip("/")
        if chain_id in ETHERSCAN_V2_SUPPORTED_CHAIN_IDS or "/v2/" not in normalized_api_url:
            normalized_api_url = ETHERSCAN_V2_API_URL
        super().__init__(
            explorer_type="etherscan",
            explorer_url=explorer_url,
            api_base_url=normalized_api_url,
            chain_id=chain_id,
            api_key=api_key,
            native_token_symbol=native_token_symbol,
            native_token_decimals=native_token_decimals,
            rate_limit_interval=rate_limit_interval,
            explorer_name=explorer_name,
            explorer_base_url=explorer_base_url,
            explorer_family=explorer_family or "etherscan",
        )
        self.fallback = fallback_blockscout
        self._plan_unsupported: bool = False
        self._missing_key_warned: bool = False

    async def close(self):
        await super().close()
        if self.fallback:
            await self.fallback.close()

    async def _call_etherscan(self, params: dict) -> Optional[dict]:
        if self._plan_unsupported:
            return None

        if not self.api_key and self._http is None:
            if not self._missing_key_warned:
                self._missing_key_warned = True
                logger.warning(
                    "ETHERSCAN_API_KEY is not configured for chain_id=%d — skipping Etherscan V2 API and using Blockscout fallback",
                    self.chain_id,
                )
            return None

        await self._limiter.acquire()
        q = dict(params)
        q["chainid"] = self.chain_id
        if self.api_key:
            q["apikey"] = self.api_key
        client = await self._get_http_client()
        try:
            resp = await client.get(self.api_base_url, params=q)
            redacted_body = redact_secrets(resp.text[:1000], [self.api_key])
            if resp.status_code != 200:
                if resp.status_code == 429:
                    try:
                        from app.watchdog import get_warning_dispatcher
                        asyncio.create_task(
                            get_warning_dispatcher().notify_rate_limit(
                                service="Etherscan V2",
                                chain_name=f"Chain {self.chain_id}",
                                detail=redacted_body[:120],
                            )
                        )
                    except Exception:
                        pass
                elif resp.status_code == 401:
                    try:
                        from app.watchdog import get_warning_dispatcher
                        asyncio.create_task(
                            get_warning_dispatcher().notify_api_key_error(
                                service="Etherscan V2",
                                chain_name=f"Chain {self.chain_id}",
                                status_code=401,
                                detail=redacted_body[:120],
                            )
                        )
                    except Exception:
                        pass
                logger.warning(
                    "Etherscan V2 API HTTP failure (chain_id=%d, action=%s): HTTP status=%d body=%s",
                    self.chain_id,
                    params.get("action"),
                    resp.status_code,
                    redacted_body,
                )
                return None
            data = resp.json()
            if isinstance(data, dict) and data.get("status") == "1" and isinstance(data.get("result"), (list, dict, str)):
                return data
            logger.warning(
                "Etherscan V2 API non-success response (chain_id=%d, action=%s): HTTP status=%d body=%s",
                self.chain_id,
                params.get("action"),
                resp.status_code,
                redacted_body,
            )
            body_low = redacted_body.lower()
            if any(
                phrase in body_low
                for phrase in (
                    "not supported for this chain",
                    "upgrade your api plan",
                    "free api access is not supported",
                    "chainid is not supported",
                )
            ):
                self._plan_unsupported = True
                logger.warning(
                    "Etherscan V2 does not cover chain_id=%d on the current API plan — falling back to Blockscout (%s)",
                    self.chain_id,
                    self.fallback.api_base_url if self.fallback else "unavailable",
                )
        except Exception as e:
            logger.warning(
                "Etherscan V2 API request error (chain_id=%d, action=%s): %s",
                self.chain_id,
                params.get("action"),
                redact_secrets(e, [self.api_key]),
            )
        return None

    async def fetch_verification_and_abi(
        self, address: str
    ) -> Tuple[Optional[bool], str, Optional[str], Optional[List[Dict[str, Any]]]]:
        data = await self._call_etherscan(
            {"module": "contract", "action": "getsourcecode", "address": address}
        )
        if data and data.get("status") == "1" and data.get("result"):
            res = data["result"]
            if isinstance(res, list) and len(res) > 0 and isinstance(res[0], dict):
                item = res[0]
                source = (item.get("SourceCode") or "").strip()
                abi_str = (item.get("ABI") or "").strip()
                is_verified = bool(source) and abi_str != "Contract source code not verified"
                parsed_abi = None
                if is_verified and abi_str.startswith("["):
                    try:
                        parsed_abi = json.loads(abi_str)
                    except Exception:
                        pass
                impl_addr = None
                impl_raw = item.get("Implementation", "")
                if impl_raw and impl_raw.startswith("0x") and len(impl_raw) == 42:
                    try:
                        impl_addr = to_checksum_address(impl_raw)
                    except Exception:
                        pass
                return is_verified, ("Verified ✅" if is_verified else "Unverified ⚠️"), impl_addr, parsed_abi

        if self.fallback:
            return await self.fallback.fetch_verification_and_abi(address)
        return None, "unavailable", None, None

    async def fetch_deployer(self, address: str) -> Optional[str]:
        data = await self._call_etherscan(
            {"module": "contract", "action": "getcontractcreation", "contractaddresses": address}
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
            creator = data["result"][0].get("contractCreator")
            if creator:
                try:
                    return to_checksum_address(creator)
                except Exception:
                    return creator

        if self.fallback:
            return await self.fallback.fetch_deployer(address)
        return None

    async def fetch_contract_creation(
        self, address: str
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Query Etherscan V2 `getcontractcreation` (and `txlist` if blockNumber/timestamp omitted)
        with Blockscout fallback to determine (deployer, creation_tx_hash, deployed_block, deployed_timestamp).
        """
        deployer: Optional[str] = None
        tx_hash: Optional[str] = None
        block_num: Optional[int] = None
        timestamp: Optional[int] = None

        data = await self._call_etherscan(
            {"module": "contract", "action": "getcontractcreation", "contractaddresses": address}
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
            item = data["result"][0]
            if isinstance(item, dict):
                creator = item.get("contractCreator")
                if creator:
                    try:
                        deployer = to_checksum_address(creator)
                    except Exception:
                        deployer = creator
                if item.get("txHash"):
                    tx_hash = str(item["txHash"])
                block_num = _parse_block_num(item.get("blockNumber"))
                timestamp = _parse_int_or_iso_timestamp(
                    item.get("timestamp") or item.get("timeStamp")
                )

        # If Etherscan getcontractcreation did not return blockNumber/timestamp directly, check earliest tx
        if (deployer or tx_hash) and (block_num is None or timestamp is None):
            tx_data = await self._call_etherscan(
                {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "page": 1,
                    "offset": 1,
                    "sort": "asc",
                }
            )
            if tx_data and tx_data.get("status") == "1" and isinstance(tx_data.get("result"), list) and tx_data["result"]:
                tx0 = tx_data["result"][0]
                if isinstance(tx0, dict):
                    if block_num is None:
                        block_num = _parse_block_num(tx0.get("blockNumber"))
                    if timestamp is None:
                        timestamp = _parse_int_or_iso_timestamp(
                            tx0.get("timeStamp") or tx0.get("timestamp")
                        )
                    if not tx_hash and tx0.get("hash"):
                        tx_hash = str(tx0["hash"])

        if self.fallback and (not deployer or block_num is None or timestamp is None):
            fb_dep, fb_tx, fb_blk, fb_ts = await self.fallback.fetch_contract_creation(address)
            deployer = deployer or fb_dep
            tx_hash = tx_hash or fb_tx
            if block_num is None:
                block_num = fb_blk
            if timestamp is None:
                timestamp = fb_ts

        return deployer, tx_hash, block_num, timestamp

    async def fetch_deployer_history(
        self, deployer: str
    ) -> Tuple[Optional[int], Optional[str]]:
        data = await self._call_etherscan(
            {
                "module": "account",
                "action": "txlist",
                "address": deployer,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": 15,
                "sort": "asc",
            }
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
            txs = data["result"]
            first_ts: Optional[int] = None
            try:
                first_ts = int(txs[0].get("timeStamp", 0)) or None
            except (ValueError, TypeError):
                first_ts = None

            funder_str: Optional[str] = None
            dep_lower = deployer.lower()
            for tx in txs:
                if not isinstance(tx, dict):
                    continue
                to_addr = (tx.get("to") or "").lower()
                from_addr = tx.get("from") or ""
                val_str = tx.get("value") or "0"
                try:
                    val_wei = int(val_str)
                except ValueError:
                    val_wei = 0
                if to_addr == dep_lower and from_addr and from_addr.lower() != dep_lower and val_wei > 0:
                    funder_checksum = to_checksum_address(from_addr)
                    eth_str = _format_eth_wei(val_wei, self.native_token_symbol, self.native_token_decimals)
                    funder_str = f"{funder_checksum} ({eth_str})"
                    break

            if not funder_str and txs:
                first_from = txs[0].get("from")
                if first_from and first_from.lower() != dep_lower:
                    try:
                        funder_str = to_checksum_address(first_from)
                    except Exception:
                        funder_str = first_from
            return first_ts, funder_str

        if self.fallback:
            return await self.fallback.fetch_deployer_history(deployer)
        return None, None

    async def fetch_recent_mint_tx(
        self, address: str, abi: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[Optional[int], Optional[str]]:
        data = await self._call_etherscan(
            {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": 15,
                "sort": "desc",
            }
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list):
            client = await self._get_http_client()
            for tx in data["result"][:15]:
                if not isinstance(tx, dict):
                    continue
                fn_field = (tx.get("functionName") or "").strip()
                raw_input = (tx.get("input") or "").strip()
                sel = raw_input[:10].lower() if len(raw_input) >= 10 else ""
                if (
                    any(k in fn_field.lower() for k in ("mint", "claim", "purchase", "buy"))
                    or sel in LOCAL_SIGNATURE_CACHE
                    or (sel and sel != "0x")
                ):
                    val_str = tx.get("value") or "0"
                    try:
                        val_wei = int(val_str)
                    except ValueError:
                        val_wei = 0
                    decoded_sel = await decode_function_selector(sel, abi=abi, http_client=client) if sel else None
                    if decoded_sel and not decoded_sel.startswith("0x"):
                        fn_name = decoded_sel
                    elif fn_field and not fn_field.startswith("0x"):
                        fn_name = fn_field.split("(")[0].strip() + "(" + fn_field.split("(", 1)[1] if "(" in fn_field else f"{fn_field}()"
                    else:
                        fn_name = decoded_sel or (sel if sel else None)
                    return val_wei, fn_name

        if self.fallback:
            return await self.fallback.fetch_recent_mint_tx(address, abi=abi)
        return None, None

    async def fetch_top_minters(
        self, address: str, known_total_supply: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[float]]:
        zero_addr = "0x0000000000000000000000000000000000000000"
        for action in ("tokennfttx", "token1155tx"):
            data = await self._call_etherscan(
                {
                    "module": "account",
                    "action": action,
                    "contractaddress": address,
                    "page": 1,
                    "offset": 100,
                    "sort": "desc",
                }
            )
            if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
                counts: Dict[str, int] = {}
                total = 0
                for item in data["result"]:
                    if not isinstance(item, dict):
                        continue
                    frm = (item.get("from") or "").lower()
                    to_addr = (item.get("to") or "").strip()
                    if to_addr and to_addr.lower() != zero_addr and frm == zero_addr:
                        qty = 1
                        if action == "token1155tx":
                            try:
                                qty = max(1, int(item.get("tokenValue") or 1))
                            except (ValueError, TypeError):
                                qty = 1
                        try:
                            addr_cs = to_checksum_address(to_addr)
                        except Exception:
                            addr_cs = to_addr
                        counts[addr_cs] = counts.get(addr_cs, 0) + qty
                        total += qty
                if total > 0:
                    sorted_minters = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
                    top_list = [
                        {
                            "address": m_addr,
                            "count": cnt,
                            "pct": round((cnt / total) * 100.0, 1),
                        }
                        for m_addr, cnt in sorted_minters
                    ]
                    top5_pct = round(sum(x["pct"] for x in top_list), 1)
                    return top_list, min(100.0, top5_pct)

        if self.fallback:
            return await self.fallback.fetch_top_minters(address, known_total_supply=known_total_supply)
        return [], None

    async def fetch_latest_contract_tx(
        self, address: str
    ) -> Tuple[Optional[int], Optional[str]]:
        data = await self._call_etherscan(
            {
                "module": "account",
                "action": "tokennfttx",
                "contractaddress": address,
                "page": 1,
                "offset": 1,
                "sort": "desc",
            }
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
            item = data["result"][0]
            if isinstance(item, dict):
                blk = item.get("blockNumber")
                txh = item.get("hash")
                if blk and txh:
                    try:
                        return int(blk), str(txh)
                    except (ValueError, TypeError):
                        pass

        if self.fallback:
            return await self.fallback.fetch_latest_contract_tx(address)
        return None, None

    async def fetch_deployer_created_contracts(self, deployer: str) -> List[str]:
        created: List[str] = []
        data = await self._call_etherscan(
            {
                "module": "account",
                "action": "txlist",
                "address": deployer,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": 100,
                "sort": "desc",
            }
        )
        if data and data.get("status") == "1" and isinstance(data.get("result"), list):
            for tx in data["result"]:
                if not isinstance(tx, dict):
                    continue
                c_addr = (tx.get("contractAddress") or "").strip()
                if c_addr and c_addr.startswith("0x") and len(c_addr) == 42:
                    try:
                        cs = to_checksum_address(c_addr)
                    except Exception:
                        cs = c_addr
                    if cs.lower() not in {x.lower() for x in created}:
                        created.append(cs)
            if created:
                return created

        if self.fallback:
            return await self.fallback.fetch_deployer_created_contracts(deployer)
        return created

    async def fetch_token_holder_counts(
        self, address: str
    ) -> Tuple[Optional[int], Optional[int]]:
        zero_addr = "0x0000000000000000000000000000000000000000"
        for action in ("tokennfttx", "token1155tx"):
            data = await self._call_etherscan(
                {
                    "module": "account",
                    "action": action,
                    "contractaddress": address,
                    "page": 1,
                    "offset": 200,
                    "sort": "asc",
                }
            )
            if data and data.get("status") == "1" and isinstance(data.get("result"), list) and data["result"]:
                balances: Dict[str, int] = {}
                for item in data["result"]:
                    if not isinstance(item, dict):
                        continue
                    frm = (item.get("from") or "").strip().lower()
                    to_addr = (item.get("to") or "").strip().lower()
                    qty = 1
                    if action == "token1155tx":
                        try:
                            qty = max(1, int(item.get("tokenValue") or 1))
                        except (ValueError, TypeError):
                            qty = 1
                    if frm and frm != zero_addr:
                        balances[frm] = balances.get(frm, 0) - qty
                    if to_addr and to_addr != zero_addr:
                        balances[to_addr] = balances.get(to_addr, 0) + qty
                positive_holders = [w for w, b in balances.items() if b > 0]
                if positive_holders:
                    return len(positive_holders), len(positive_holders)

        if self.fallback:
            return await self.fallback.fetch_token_holder_counts(address)
        return None, None


class NoneExplorer(BlockExplorer):
    """Fallback explorer implementation for chains with explorer_type: 'none'."""

    def __init__(
        self,
        explorer_url: str = "",
        api_base_url: str = "",
        chain_id: int = 1,
        api_key: Optional[str] = None,
        native_token_symbol: str = "ETH",
        native_token_decimals: int = 18,
        explorer_name: Optional[str] = None,
        explorer_base_url: Optional[str] = None,
        explorer_family: Optional[str] = None,
    ):
        super().__init__(
            explorer_type="none",
            explorer_url=explorer_url or "",
            api_base_url=api_base_url or "",
            chain_id=chain_id,
            api_key=api_key,
            native_token_symbol=native_token_symbol,
            native_token_decimals=native_token_decimals,
            explorer_name=explorer_name,
            explorer_base_url=explorer_base_url,
            explorer_family=explorer_family or "etherscan",
        )

    async def fetch_verification_and_abi(
        self, address: str
    ) -> Tuple[Optional[bool], str, Optional[str], Optional[List[Dict[str, Any]]]]:
        return None, "unavailable", None, None

    async def fetch_deployer(self, address: str) -> Optional[str]:
        return None

    async def fetch_contract_creation(
        self, address: str
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        return None, None, None, None

    async def fetch_deployer_history(
        self, deployer: str
    ) -> Tuple[Optional[int], Optional[str]]:
        return None, None

    async def fetch_recent_mint_tx(
        self, address: str, abi: Optional[List[Dict[str, Any]]] = None
    ) -> Tuple[Optional[int], Optional[str]]:
        return None, None

    async def fetch_top_minters(
        self, address: str, known_total_supply: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[float]]:
        return [], None

    async def fetch_latest_contract_tx(
        self, address: str
    ) -> Tuple[Optional[int], Optional[str]]:
        return None, None


def create_explorer(
    explorer_type: str,
    explorer_url: str,
    api_base_url: str,
    chain_id: int = 1,
    api_key: Optional[str] = None,
    native_token_symbol: str = "ETH",
    native_token_decimals: int = 18,
    blockscout_fallback_url: Optional[str] = None,
    explorer_name: Optional[str] = None,
    explorer_base_url: Optional[str] = None,
    explorer_family: Optional[str] = None,
) -> BlockExplorer:
    """Factory creating an EtherscanExplorer (V2), BlockscoutExplorer, or NoneExplorer instance."""
    etype = (explorer_type or "etherscan").lower().strip()
    eff_base_url = (explorer_base_url or explorer_url or "https://etherscan.io").rstrip("/")
    eff_family = (explorer_family or ("blockscout" if etype == "blockscout" else "etherscan")).lower().strip()

    if etype == "none":
        return NoneExplorer(
            explorer_url=eff_base_url,
            api_base_url=api_base_url or eff_base_url,
            chain_id=chain_id,
            native_token_symbol=native_token_symbol,
            native_token_decimals=native_token_decimals,
            explorer_name=explorer_name,
            explorer_base_url=eff_base_url,
            explorer_family=eff_family,
        )
    if etype == "blockscout":
        return BlockscoutExplorer(
            explorer_url=eff_base_url,
            api_base_url=api_base_url or eff_base_url,
            chain_id=chain_id,
            api_key=api_key,
            native_token_symbol=native_token_symbol,
            native_token_decimals=native_token_decimals,
            explorer_name=explorer_name,
            explorer_base_url=eff_base_url,
            explorer_family=eff_family,
        )

    eff_fallback_url = blockscout_fallback_url or DEFAULT_BLOCKSCOUT_BY_CHAIN_ID.get(chain_id)
    fallback = None
    if eff_fallback_url:
        fallback = BlockscoutExplorer(
            explorer_url=eff_fallback_url,
            api_base_url=eff_fallback_url,
            chain_id=chain_id,
            native_token_symbol=native_token_symbol,
            native_token_decimals=native_token_decimals,
            explorer_family="blockscout",
        )
    return EtherscanExplorer(
        explorer_url=eff_base_url,
        api_base_url=api_base_url or ETHERSCAN_V2_API_URL,
        chain_id=chain_id,
        api_key=api_key,
        native_token_symbol=native_token_symbol,
        native_token_decimals=native_token_decimals,
        fallback_blockscout=fallback,
        explorer_name=explorer_name,
        explorer_base_url=eff_base_url,
        explorer_family=eff_family,
    )


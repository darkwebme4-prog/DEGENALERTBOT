"""Comprehensive contract enrichment: on-chain getters, ABI risk scan, deployer & funding, top-5 minters, and OpenSea data."""

import asyncio
import base64
from datetime import datetime, timezone
import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, Tuple, List
import httpx
from eth_utils import to_checksum_address

from app.rpc import EvmRpcClient, RPCError
from app.proxy import ProxyDetector
from app.detector import NftDetector
from app.risk import detect_mixer_from_text_or_address
from app.explorer import (
    BlockExplorer,
    create_explorer,
    KNOWN_MINT_SELECTORS,
    resolve_selector_from_abi,
    decode_function_selector,
    redact_secrets,
)

logger = logging.getLogger(__name__)
ETH_ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")
ETH_ADDRESS_RE = ETH_ADDR_RE
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# Known 4-byte selectors for bytecode risk scanning when ABI is unavailable
BYTECODE_RISK_SELECTORS: Dict[str, List[Tuple[str, str]]] = {
    "owner_mint": [
        ("ownerMint(uint256)", "f19e75d4"),
        ("ownerMint(address,uint256)", "484b973c"),
        ("devMint(uint256)", "375a069a"),
        ("teamMint(uint256)", "6373a6b1"),
        ("reserveNFTs()", "e0a80853"),
        ("adminMint(address,uint256)", "853828b6"),
        ("airdrop(address[],uint256[])", "67243482"),
    ],
    "blacklist": [
        ("blacklist(address)", "f9f92be4"),
        ("setBlacklist(address,bool)", "153b0d1e"),
        ("blacklistAddress(address,bool)", "404e5129"),
        ("blockAddress(address)", "0f3a9f65"),
    ],
    "pausable_transfers": [
        ("pause()", "8456cb59"),
        ("setPaused(bool)", "16c38b3c"),
    ],
    "set_base_uri": [
        ("setBaseURI(string)", "55f804b3"),
        ("setNotRevealedURI(string)", "f2c4ce1e"),
        ("setContractURI(string)", "938e3d7b"),
    ],
}

COINGECKO_PLATFORM_MAP: Dict[str, str] = {
    "ethereum": "ethereum",
    "base": "base",
    "arbitrum": "arbitrum-one",
    "optimism": "optimistic-ethereum",
    "matic": "polygon-pos",
    "polygon": "polygon-pos",
}


class AsyncRateLimiter:
    """Simple async rate limiter enforcing minimum interval between requests."""

    def __init__(self, calls_per_second: float = 3.0):
        self.min_interval = 1.0 / max(0.1, calls_per_second)
        self._lock = asyncio.Lock()
        self._last_call = 0.0

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self._last_call = time.monotonic()


@dataclass
class EnrichmentResult:
    contract_address: str
    chain: str = "ethereum"
    chain_name: str = "Ethereum"
    chain_id: int = 1
    native_token_symbol: str = "ETH"
    native_token_decimals: int = 18
    explorer_name: Optional[str] = None
    explorer_base_url: Optional[str] = None
    explorer_family: str = "etherscan"
    explorer_api_type: str = "etherscan_v2"
    explorer_url: str = "https://etherscan.io"
    explorer_type: str = "etherscan"
    opensea_chain_slug: Optional[str] = "ethereum"

    @property
    def effective_explorer_base_url(self) -> str:
        return (self.explorer_base_url or self.explorer_url or "https://etherscan.io").rstrip("/")

    @property
    def effective_explorer_name(self) -> str:
        if self.explorer_name:
            return self.explorer_name
        return "Blockscout Explorer" if (self.explorer_family or "").lower() == "blockscout" else "Etherscan"

    @property
    def effective_explorer_family(self) -> str:
        if self.explorer_family:
            return self.explorer_family.lower()
        if "blockscout" in (self.explorer_type or "").lower():
            return "blockscout"
        return "etherscan"

    trigger_block_number: Optional[int] = None
    trigger_tx_hash: Optional[str] = None

    # Contract deployment & age
    contract_deployed_block: Optional[int] = None
    contract_deployed_timestamp: Optional[int] = None
    contract_deployed_tx_hash: Optional[str] = None
    contract_age_seconds: Optional[int] = None
    contract_age_formatted: str = "unavailable"
    contract_deployment_date: Optional[str] = None
    contract_age_label: Optional[str] = None

    deployer: Optional[str] = None
    deployer_age_seconds: Optional[int] = None
    deployer_age_formatted: str = "unavailable"
    deployer_tx_count: Optional[int] = None
    is_source_verified: Optional[bool] = None
    verification_status: str = "unavailable"
    is_proxy: Optional[bool] = None
    proxy_type: Optional[str] = None
    proxy_implementation: Optional[str] = None

    # Extended NFT & On-chain fields
    collection_name: Optional[str] = None
    symbol: Optional[str] = None
    standard: Optional[str] = None
    total_supply: Optional[int] = None
    max_supply: Optional[int] = None
    max_supply_source: Optional[str] = None
    owner: Optional[str] = None
    is_ownership_renounced: Optional[bool] = None
    is_paused: Optional[bool] = None
    paused_source: Optional[str] = None
    mint_price_formatted: Optional[str] = None
    mint_function_name: Optional[str] = None
    royalty_receiver: Optional[str] = None
    royalty_bps: Optional[int] = None
    token_uri: Optional[str] = None
    contract_uri: Optional[str] = None
    contract_uri_status: Optional[str] = None
    contract_uri_error: Optional[str] = None
    token_uri_status: Optional[str] = None
    token_uri_error: Optional[str] = None
    metadata_name: Optional[str] = None
    metadata_description: Optional[str] = None
    metadata_image: Optional[str] = None
    metadata_external_link: Optional[str] = None
    is_revealed: Optional[bool] = None
    reveal_status_text: str = "unavailable"
    deployer_funding_source: Optional[str] = None
    deployer_funder_address: Optional[str] = None
    deployer_funder_tx_count: Optional[int] = None
    deployer_funder_age_seconds: Optional[int] = None
    deployer_funded_from_mixer: Optional[bool] = None
    deployer_funded_from_fresh_wallet: Optional[bool] = None

    abi_available: bool = False
    risky_functions: Optional[Dict[str, List[str]]] = None
    honeypot_sim_reverted: Optional[bool] = None
    honeypot_sim_detail: Optional[str] = None
    risk_report: Optional[Dict[str, Any]] = None

    top_minters: List[Dict[str, Any]] = field(default_factory=list)
    top5_concentration_pct: Optional[float] = None
    mints_per_minute: Optional[float] = None
    self_mints: int = 0
    self_mint_pct: Optional[float] = None
    owner_is_top_minter: Optional[bool] = None
    recent_token_id: Optional[str] = None
    opensea_slug: Optional[str] = None
    opensea_collection_contract: Optional[str] = None
    opensea_floor: Optional[str] = None
    opensea_listings: Optional[int] = None
    opensea_volume_24h: Optional[str] = None
    opensea_num_owners: Optional[int] = None
    opensea_socials: Dict[str, str] = field(default_factory=dict)
    metadata_socials: Dict[str, str] = field(default_factory=dict)
    social_sources: Dict[str, str] = field(default_factory=dict)
    social_missing_reason: Optional[str] = None
    has_project_footprint: Optional[bool] = None

    # Quality Score inputs & report
    mature_minter_share_pct: Optional[float] = None
    mature_minters_checked: Optional[int] = None
    sybil_or_contract_mint_share_pct: Optional[float] = None
    total_eth_spent_non_owner: Optional[float] = None
    clustered_unique_minters: Optional[int] = None
    quality_report: Optional[Dict[str, Any]] = None
    alert_tier: Optional[str] = None

    # Smart-Wallet Watchlist & Deployer Reputation
    watched_wallets_minted: List[str] = field(default_factory=list)
    deployer_contracts_deployed: Optional[int] = None
    deployer_reached_90pct_minted: Optional[int] = None
    deployer_owner_held_above_50pct: Optional[int] = None
    owner_held_pct: Optional[float] = None

    # Bytecode template matching
    runtime_bytecode_hash: Optional[str] = None
    stripped_bytecode_hash: Optional[str] = None
    template_label: Optional[str] = None
    template_risk_flag: Optional[str] = None
    template_match_count: int = 0

    # Mint Simulation
    simulation_status: str = "not_checked"  # "success" | "reverted" | "not_checked"
    simulation_revert_reason: Optional[str] = None
    simulation_classification: Optional[str] = None
    simulation_tested_function: Optional[str] = None

    # Cross-Chain Deployer & Funding Clusters
    cross_chain_deployer_contracts: List[Dict[str, Any]] = field(default_factory=list)
    cross_chain_deployer_status: str = "ok"
    funding_clusters_detected: List[Dict[str, Any]] = field(default_factory=list)
    funding_clusters_status: str = "ok"

    # Live-Mint Check (LIVE | SLOWING | ENDED | SOLD OUT)
    live_mint_check: Optional[Dict[str, Any]] = None

    # Link Resolution (Socials, Mint Link, Marketplaces with Safety Checks)
    resolved_links: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnrichmentResult":
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


def format_duration(seconds: Optional[int]) -> str:
    """Format seconds into human-readable duration (e.g., '3d 4h old' or 'Fresh (5 mins old)')."""
    if seconds is None or seconds < 0:
        return "Unknown"
    if seconds < 3600:
        mins = max(1, seconds // 60)
        return f"Fresh ({mins} min{'s' if mins != 1 else ''} old)"
    hours = seconds // 3600
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} old"
    days = hours // 24
    rem_hours = hours % 24
    if days > 365:
        years = days // 365
        rem_days = days % 365
        return f"{years}y {rem_days}d old"
    return f"{days}d {rem_hours}h old"


def format_contract_age(age_seconds: Optional[int]) -> str:
    """Format contract age in concise form (e.g. '3h old' or '2y 4mo old')."""
    if age_seconds is None or age_seconds < 0:
        return "unavailable"
    if age_seconds < 60:
        return f"{max(1, age_seconds)}s old"
    if age_seconds < 3600:
        return f"{age_seconds // 60}m old"
    if age_seconds < 86400:
        hours = age_seconds // 3600
        rem_mins = (age_seconds % 3600) // 60
        if rem_mins > 0 and hours < 6:
            return f"{hours}h {rem_mins}m old"
        return f"{hours}h old"
    if age_seconds < 86400 * 30:
        days = age_seconds // 86400
        rem_hours = (age_seconds % 86400) // 3600
        if rem_hours > 0:
            return f"{days}d {rem_hours}h old"
        return f"{days}d old"
    if age_seconds < 86400 * 365:
        months = age_seconds // (86400 * 30)
        rem_days = (age_seconds % (86400 * 30)) // 86400
        if rem_days > 0:
            return f"{months}mo {rem_days}d old"
        return f"{months}mo old"
    years = age_seconds // (86400 * 365)
    rem_months = (age_seconds % (86400 * 365)) // (86400 * 30)
    if rem_months > 0:
        return f"{years}y {rem_months}mo old"
    return f"{years}y old"


def format_deployment_date(deployed_timestamp: Optional[int]) -> Optional[str]:
    """Format unix deployment timestamp as 'YYYY-MM-DD HH:MM UTC'."""
    if deployed_timestamp is None or deployed_timestamp <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(int(deployed_timestamp), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return None


def classify_contract_age(
    age_seconds: Optional[int], max_contract_age_hours: float = 72.0
) -> Optional[str]:
    """Return '🆕 FRESH DEPLOY' if within max_contract_age_hours else '♻️ OLD CONTRACT SURGE'."""
    if age_seconds is None or age_seconds < 0:
        return None
    if age_seconds <= max_contract_age_hours * 3600:
        return "🆕 FRESH DEPLOY"
    return "♻️ OLD CONTRACT SURGE"


IPFS_GATEWAYS: Tuple[str, str] = (
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/",
)
ARWEAVE_GATEWAY: str = "https://arweave.net/"


def resolve_uri_to_gateway_urls(uri: str, sample_token_id: Optional[str] = None) -> List[str]:
    """
    Convert an ipfs://, ar://, or http(s):// metadata URI into ordered HTTP URLs to try:
      - ipfs://<cid> -> two public gateways (`https://ipfs.io/ipfs/<cid>`, `https://cloudflare-ipfs.com/ipfs/<cid>`)
      - ar://<tx_id> -> Arweave gateway (`https://arweave.net/<tx_id>`)
      - http(s)://   -> [uri]
    """
    if not uri or not isinstance(uri, str):
        return []
    clean = uri.strip()
    if not clean:
        return []

    if "{id}" in clean or "{ID}" in clean:
        try:
            tid_int = int(str(sample_token_id), 0) if sample_token_id is not None else 1
            hex_id = f"{tid_int:064x}"
        except (ValueError, TypeError):
            hex_id = "1".zfill(64)
        clean = clean.replace("{id}", hex_id).replace("{ID}", hex_id)

    if clean.startswith("ipfs://"):
        cid_path = clean[len("ipfs://"):].lstrip("/")
        if cid_path.startswith("ipfs/"):
            cid_path = cid_path[len("ipfs/"):].lstrip("/")
        return [f"{gw}{cid_path}" for gw in IPFS_GATEWAYS] if cid_path else []

    if clean.startswith("ar://"):
        ar_path = clean[len("ar://"):].lstrip("/")
        return [f"{ARWEAVE_GATEWAY}{ar_path}"] if ar_path else []

    if clean.startswith("http://") or clean.startswith("https://"):
        return [clean]

    return []


def _normalize_social_url(kind: str, raw_val: Any) -> Optional[str]:
    """Normalize a website, twitter, discord, or telegram link from metadata JSON without inventing URLs."""
    if not raw_val or not isinstance(raw_val, str):
        return None
    val = raw_val.strip()
    if not val or val.lower() in ("null", "none", "n/a", "unavailable", "todo", "tbd"):
        return None

    low = val.lower()
    if kind == "twitter":
        if low.startswith("http://") or low.startswith("https://"):
            if "twitter.com/" in low or "x.com/" in low:
                return val
            return None
        handle = val.lstrip("@").strip("/")
        if handle and re.fullmatch(r"[A-Za-z0-9_]{1,30}", handle):
            return f"https://x.com/{handle}"
        return None

    if kind == "discord":
        if low.startswith("http://") or low.startswith("https://"):
            if "discord.gg/" in low or "discord.com/" in low or "discordapp.com/" in low:
                return val
            return None
        if low.startswith("discord.gg/") or low.startswith("discord.com/invite/"):
            return f"https://{val}"
        return None

    if kind == "telegram":
        if low.startswith("http://") or low.startswith("https://"):
            if "t.me/" in low or "telegram.me/" in low or "telegram.org/" in low:
                return val
            return None
        if low.startswith("t.me/") or low.startswith("telegram.me/"):
            return f"https://{val}"
        handle = val.lstrip("@").strip("/")
        if handle and re.fullmatch(r"[A-Za-z0-9_]{3,64}", handle):
            return f"https://t.me/{handle}"
        return None

    if kind == "website":
        if low.startswith("http://") or low.startswith("https://"):
            if any(
                d in low
                for d in ("twitter.com/", "x.com/", "discord.gg/", "discord.com/", "t.me/", "telegram.me/")
            ):
                return None
            return val
        return None

    return None


def extract_socials_from_metadata_json(data: Any) -> Dict[str, str]:
    """
    Extract website, twitter, discord, and telegram links from contractURI or tokenURI JSON metadata.
    Never invents a link if not present in the metadata.
    """
    socials: Dict[str, str] = {}
    if not isinstance(data, dict):
        return socials

    # Candidate dicts to inspect (top-level + nested links/socials/properties)
    dicts_to_scan: List[Dict[str, Any]] = [data]
    for sub_key in ("links", "socials", "social_links", "social", "properties", "extensions"):
        sub = data.get(sub_key)
        if isinstance(sub, dict):
            dicts_to_scan.append(sub)
            if isinstance(sub.get("links"), dict):
                dicts_to_scan.append(sub["links"])
            if isinstance(sub.get("socials"), dict):
                dicts_to_scan.append(sub["socials"])

    for d in dicts_to_scan:
        # Twitter
        if "twitter" not in socials:
            for tk in ("twitter", "twitter_url", "twitter_username", "x", "x_url", "twitterUrl", "twitter_handle"):
                if tk in d:
                    norm = _normalize_social_url("twitter", d.get(tk))
                    if norm:
                        socials["twitter"] = norm
                        break

        # Discord
        if "discord" not in socials:
            for dk in ("discord", "discord_url", "discord_link", "discordUrl", "discord_invite"):
                if dk in d:
                    norm = _normalize_social_url("discord", d.get(dk))
                    if norm:
                        socials["discord"] = norm
                        break

        # Telegram
        if "telegram" not in socials:
            for tgk in ("telegram", "telegram_url", "telegram_link", "telegram_username", "tg", "tg_url", "telegramUrl"):
                if tgk in d:
                    norm = _normalize_social_url("telegram", d.get(tgk))
                    if norm:
                        socials["telegram"] = norm
                        break

        # Website (also inspect external_link / external_url in case it's a Twitter, Discord, or Telegram URL)
        for wk in (
            "external_link",
            "external_url",
            "website",
            "website_url",
            "project_url",
            "homepage",
            "externalUrl",
            "externalLink",
        ):
            if wk in d:
                raw_w = d.get(wk)
                if "twitter" not in socials:
                    tw_norm = _normalize_social_url("twitter", raw_w)
                    if tw_norm:
                        socials["twitter"] = tw_norm
                        continue
                if "discord" not in socials:
                    dc_norm = _normalize_social_url("discord", raw_w)
                    if dc_norm:
                        socials["discord"] = dc_norm
                        continue
                if "telegram" not in socials:
                    tg_norm = _normalize_social_url("telegram", raw_w)
                    if tg_norm:
                        socials["telegram"] = tg_norm
                        continue
                if "website" not in socials:
                    web_norm = _normalize_social_url("website", raw_w)
                    if web_norm:
                        socials["website"] = web_norm

    return socials


def parse_metadata_json(data: Any) -> Dict[str, Any]:
    """
    Parse a resolved contractURI or tokenURI JSON object for:
      - name
      - description
      - image
      - external_link (or external_url)
      - socials (website, twitter, discord, telegram)
    """
    if not isinstance(data, dict):
        return {
            "name": None,
            "description": None,
            "image": None,
            "external_link": None,
            "socials": {},
        }

    def _clean_str(val: Any) -> Optional[str]:
        if isinstance(val, str):
            s = val.strip()
            if s and s.lower() not in ("null", "none", "n/a", "unavailable"):
                return s
        return None

    name = _clean_str(data.get("name") or data.get("collection_name") or data.get("title"))
    description = _clean_str(data.get("description"))
    image = _clean_str(data.get("image") or data.get("image_url") or data.get("image_data"))
    external_link = _clean_str(
        data.get("external_link")
        or data.get("external_url")
        or data.get("externalLink")
        or data.get("externalUrl")
        or data.get("website")
        or data.get("project_url")
        or data.get("homepage")
    )
    socials = extract_socials_from_metadata_json(data)

    return {
        "name": name,
        "description": description,
        "image": image,
        "external_link": external_link,
        "socials": socials,
    }


def format_eth_wei(wei: Optional[int], symbol: str = "ETH", decimals: int = 18) -> Optional[str]:
    """Format wei integer into human-readable native token string."""
    if wei is None:
        return None
    if wei == 0:
        return f"0 {symbol} (Free)"
    div = 10 ** max(0, int(decimals))
    eth = wei / div
    if eth >= 0.0001:
        return f"{eth:.4f}".rstrip("0").rstrip(".") + f" {symbol}"
    return f"{eth:.6f} {symbol}"


def scan_abi_for_risky_functions(abi: Optional[List[Dict[str, Any]]], bytecode_hex: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Scan contract ABI (or bytecode 4-byte selectors if ABI is unavailable) for risky functions:
      - owner_mint (owner-only mint, devMint, reserve, airdrop)
      - blacklist (blacklist, blockAddress, denyList)
      - pausable_transfers (pause, setPaused, pauseTransfers, transfer restrictions)
      - set_base_uri (setBaseURI, setTokenURI, setNotRevealedURI)
    """
    findings: Dict[str, List[str]] = {
        "owner_mint": [],
        "blacklist": [],
        "pausable_transfers": [],
        "set_base_uri": [],
    }

    if abi and isinstance(abi, list):
        for item in abi:
            if not isinstance(item, dict) or item.get("type") != "function":
                continue
            name = item.get("name", "")
            if not name:
                continue
            state_mutability = item.get("stateMutability", "")
            if state_mutability in ("view", "pure"):
                continue

            lower = name.lower()

            if any(
                kw in lower
                for kw in (
                    "ownermint",
                    "devmint",
                    "teammint",
                    "adminmint",
                    "reservenft",
                    "reserve",
                    "airdrop",
                    "mintforaddress",
                    "minttoowner",
                )
            ):
                if f"{name}()" not in findings["owner_mint"]:
                    findings["owner_mint"].append(f"{name}()")

            if any(
                kw in lower
                for kw in (
                    "blacklist",
                    "denylist",
                    "blockaddress",
                    "banaddress",
                    "sanction",
                )
            ):
                if f"{name}()" not in findings["blacklist"]:
                    findings["blacklist"].append(f"{name}()")

            if lower in (
                "pause",
                "unpause",
                "setpaused",
                "pausetransfers",
                "flipsalestate",
                "setmintpaused",
                "settradingenabled",
                "enabletrading",
                "settransferallowed",
                "locktransfers",
            ) or any(
                kw in lower
                for kw in (
                    "pausetransfer",
                    "locktransfer",
                    "restricttransfer",
                    "settrading",
                )
            ):
                if f"{name}()" not in findings["pausable_transfers"]:
                    findings["pausable_transfers"].append(f"{name}()")

            if any(
                kw in lower
                for kw in (
                    "setbaseuri",
                    "settokenuri",
                    "setnotrevealeduri",
                    "setplaceholderuri",
                    "seturi",
                    "setmetadatauri",
                )
            ):
                if f"{name}()" not in findings["set_base_uri"]:
                    findings["set_base_uri"].append(f"{name}()")

        return findings

    if bytecode_hex and len(bytecode_hex) > 10:
        clean_code = bytecode_hex.lower().replace("0x", "")
        for category, selector_list in BYTECODE_RISK_SELECTORS.items():
            for sig_label, sel_hex in selector_list:
                if f"63{sel_hex}" in clean_code:
                    findings[category].append(sig_label)

    return findings


class ContractEnricher:
    """Fetches real on-chain, explorer, security, concentration, and OpenSea data for a contract."""

    def __init__(
        self,
        rpc_client: EvmRpcClient,
        etherscan_api_key: Optional[str] = None,
        etherscan_base_url: str = "https://api.etherscan.io/v2/api",
        blockscout_base_url: str = "https://eth.blockscout.com",
        opensea_api_key: Optional[str] = None,
        opensea_base_url: str = "https://api.opensea.io",
        db: Optional[Any] = None,
        cache_ttl_seconds: int = 600,
        explorer: Optional[BlockExplorer] = None,
        chain: str = "ethereum",
        chain_name: str = "Ethereum",
        chain_id: int = 1,
        native_token_symbol: str = "ETH",
        native_token_decimals: int = 18,
        explorer_url: str = "https://etherscan.io",
        explorer_type: str = "etherscan",
        opensea_chain_slug: Optional[str] = "ethereum",
        max_contract_age_hours: float = 72.0,
        explorer_name: Optional[str] = None,
        explorer_base_url: Optional[str] = None,
        explorer_family: Optional[str] = None,
        explorer_api_type: Optional[str] = None,
    ):
        self.rpc = rpc_client
        self.detector = NftDetector(rpc_client)
        self.proxy_detector = ProxyDetector(rpc_client)
        self.etherscan_key = etherscan_api_key
        self.etherscan_url = etherscan_base_url
        self.blockscout_url = blockscout_base_url.rstrip("/")
        self.opensea_key = opensea_api_key
        self.opensea_url = opensea_base_url.rstrip("/")
        self.db = db
        self.cache_ttl_seconds = cache_ttl_seconds
        self.max_contract_age_hours = max_contract_age_hours

        self.chain = (chain or "ethereum").lower()
        self.chain_name = chain_name or "Ethereum"
        self.chain_id = chain_id
        self.native_token_symbol = native_token_symbol or "ETH"
        self.native_token_decimals = int(native_token_decimals) if native_token_decimals is not None else 18
        self.explorer_url = explorer_url.rstrip("/")
        self.explorer_type = (explorer_type or "etherscan").lower()
        self.opensea_chain_slug = opensea_chain_slug
        self.explorer_name = explorer_name
        self.explorer_base_url = (explorer_base_url or explorer_url or "https://etherscan.io").rstrip("/")
        self.explorer_family = (explorer_family or ("blockscout" if "blockscout" in (explorer_type or "").lower() else "etherscan")).lower()
        self.explorer_api_type = (explorer_api_type or explorer_type or "etherscan_v2").lower()

        self.explorer: BlockExplorer = explorer or create_explorer(
            explorer_type=self.explorer_type,
            explorer_url=self.explorer_base_url,
            api_base_url=self.etherscan_url if self.explorer_type == "etherscan" else self.blockscout_url,
            chain_id=self.chain_id,
            api_key=self.etherscan_key,
            native_token_symbol=self.native_token_symbol,
            native_token_decimals=self.native_token_decimals,
            blockscout_fallback_url=self.blockscout_url,
            explorer_name=self.explorer_name,
            explorer_base_url=self.explorer_base_url,
            explorer_family=self.explorer_family,
        )

        self._http: Optional[httpx.AsyncClient] = None
        self._market_limiter = AsyncRateLimiter(calls_per_second=2.0)
        self.last_deployment_lookup_errors: Dict[str, str] = {}
        self._last_code_search_error: Dict[str, str] = {}
        self._last_opensea_verified_contract: Dict[str, Optional[str]] = {}
        self._last_opensea_token_id: Dict[str, Optional[str]] = {}
        self._last_opensea_volume_24h: Dict[str, Optional[str]] = {}
        self._last_opensea_num_owners: Dict[str, Optional[int]] = {}
        self._last_mint_tx_input: Dict[str, str] = {}
        from app.links import LinkResolver
        self.link_resolver = LinkResolver(
            db=self.db,
            cache_ttl_seconds=self.cache_ttl_seconds,
        )

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http is None or getattr(self._http, "is_closed", False) is True:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                headers={"User-Agent": "DegenAlertBot/1.0", "Accept": "application/json"},
            )
        return self._http

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None
        if hasattr(self, "link_resolver"):
            await self.link_resolver.close()
        await self.explorer.close()

    async def fetch_deployer_from_etherscan(self, address: str) -> Optional[str]:
        """Fetch deployer address via Explorer interface."""
        return await self.explorer.fetch_deployer(address)

    async def find_first_code_block(
        self, address: str, upper_block: Optional[int] = None
    ) -> Tuple[Optional[int], Optional[int]]:
        """
        Binary search via RPC `eth_getCode` to find the first block where `address` has deployed bytecode,
        and fetch that block's timestamp via `eth_getBlockByNumber`.
        Returns (deployed_block, deployed_timestamp).
        """
        addr_low = address.lower()
        try:
            high: Optional[int] = upper_block if (isinstance(upper_block, int) and upper_block > 0) else None
            if high is None:
                blk_num = await self.rpc.eth_block_number()
                if isinstance(blk_num, int) and blk_num > 0:
                    high = blk_num
            if high is None or high <= 0:
                self._last_code_search_error[addr_low] = "eth_blockNumber unavailable for upper bound"
                return None, None

            code_high = await self.rpc.eth_get_code(address, hex(high))
            if not isinstance(code_high, str) or len(code_high) <= 2 or code_high in ("0x", "0x0"):
                self._last_code_search_error[addr_low] = f"eth_getCode returned no bytecode at block #{high}"
                return None, None

            current_high = high
            low: Optional[int] = None
            step = 64
            saw_empty_code = False
            pruned_error: Optional[Exception] = None
            while True:
                probe = max(0, current_high - step)
                try:
                    code_probe = await self.rpc.eth_get_code(address, hex(probe))
                except Exception as probe_err:
                    pruned_error = probe_err
                    low = current_high if current_high == high else (probe + 1)
                    break
                if not isinstance(code_probe, str):
                    self._last_code_search_error[addr_low] = f"eth_getCode returned non-string at block #{probe}"
                    return None, None
                has_code = len(code_probe) > 2 and code_probe not in ("0x", "0x0")
                if not has_code:
                    saw_empty_code = True
                    low = probe + 1
                    break
                if probe == 0:
                    # If block 0 also claims to have code while high > 0, RPC/mock is not block-height aware
                    self._last_code_search_error[addr_low] = "eth_getCode returned bytecode at genesis block #0 (RPC not block-height aware)"
                    return None, None
                current_high = probe
                step *= 8

            while low < current_high:
                mid = (low + current_high) // 2
                try:
                    code_mid = await self.rpc.eth_get_code(address, hex(mid))
                except Exception as mid_err:
                    pruned_error = mid_err
                    low = mid + 1
                    continue
                if not isinstance(code_mid, str):
                    self._last_code_search_error[addr_low] = f"eth_getCode returned non-string at block #{mid}"
                    return None, None
                if len(code_mid) > 2 and code_mid not in ("0x", "0x0"):
                    current_high = mid
                else:
                    saw_empty_code = True
                    low = mid + 1

            first_block = current_high
            deployed_ts: Optional[int] = None
            blk = await self.rpc.eth_get_block_by_number(first_block, full_txs=False)
            if isinstance(blk, dict) and blk.get("timestamp") is not None:
                raw_ts = blk["timestamp"]
                if isinstance(raw_ts, int):
                    deployed_ts = raw_ts
                elif isinstance(raw_ts, str):
                    deployed_ts = int(raw_ts, 16) if raw_ts.startswith("0x") else int(raw_ts)

            if not saw_empty_code:
                # We hit an RPC state pruning / pre-Bedrock boundary before seeing 0x (empty code).
                # Only return this lower-bound age if the earliest readable block with code is ALREADY
                # older than max_contract_age_hours (proving the contract is old). Otherwise fail closed.
                if deployed_ts is not None and (int(time.time()) - deployed_ts) > self.max_contract_age_hours * 3600:
                    self._last_code_search_error.pop(addr_low, None)
                    return first_block, deployed_ts
                self._last_code_search_error[addr_low] = (
                    f"eth_getCode hit historical state boundary at block #{first_block} without finding creation block"
                    + (f" ({pruned_error})" if pruned_error else "")
                )
                return None, None

            if deployed_ts is None:
                self._last_code_search_error[addr_low] = f"found first code block #{first_block} but eth_getBlockByNumber returned no timestamp"
            else:
                self._last_code_search_error.pop(addr_low, None)
            return first_block, deployed_ts
        except Exception as e:
            self._last_code_search_error[addr_low] = f"eth_getCode binary search failed: {type(e).__name__}: {e}"
            logger.debug("RPC binary search for first code block failed for %s: %s", address, e)
            return None, None

    async def resolve_factory_deployment_via_trace(
        self,
        address: str,
        reference_block: Optional[int] = None,
        tx_hash: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Resolve factory deployment (deployer, creation_tx_hash, deployed_block, deployed_timestamp)
        via RPC trace calls (`trace_filter`, `trace_transaction`, `debug_traceTransaction`,
        `trace_block`, `debug_traceBlockByNumber`).
        """
        addr_lower = address.lower()
        found_deployer: Optional[str] = None
        found_tx: Optional[str] = tx_hash
        found_block: Optional[int] = None
        found_ts: Optional[int] = None

        # 1. Try trace_filter for create traces targeting `address`
        try:
            to_blk_hex = hex(reference_block) if (isinstance(reference_block, int) and reference_block > 0) else "latest"
            traces = await self.rpc.call(
                "trace_filter",
                [{"toAddress": [address], "fromBlock": "0x0", "toBlock": to_blk_hex}],
                retries=1,
            )
            if isinstance(traces, list):
                for tr in traces:
                    if not isinstance(tr, dict):
                        continue
                    res_obj = tr.get("result") or {}
                    created_addr = (res_obj.get("address") or "").strip().lower() if isinstance(res_obj, dict) else ""
                    if tr.get("type") == "create" or created_addr == addr_lower:
                        raw_bn = tr.get("blockNumber")
                        if raw_bn is not None:
                            found_block = int(raw_bn, 16) if isinstance(raw_bn, str) and raw_bn.startswith("0x") else int(raw_bn)
                        if tr.get("transactionHash"):
                            found_tx = str(tr["transactionHash"])
                        act = tr.get("action") or {}
                        if isinstance(act, dict) and isinstance(act.get("from"), str):
                            found_deployer = act["from"]
                        break
        except Exception:
            pass

        # 2. If tx_hash is known, try trace_transaction / debug_traceTransaction
        if found_block is None and found_tx:
            try:
                tx_traces = await self.rpc.call("trace_transaction", [found_tx], retries=1)
                if isinstance(tx_traces, list):
                    for tr in tx_traces:
                        if not isinstance(tr, dict):
                            continue
                        res_obj = tr.get("result") or {}
                        created_addr = (res_obj.get("address") or "").strip().lower() if isinstance(res_obj, dict) else ""
                        if created_addr == addr_lower:
                            raw_bn = tr.get("blockNumber")
                            if raw_bn is not None:
                                found_block = int(raw_bn, 16) if isinstance(raw_bn, str) and raw_bn.startswith("0x") else int(raw_bn)
                            act = tr.get("action") or {}
                            if isinstance(act, dict) and isinstance(act.get("from"), str):
                                found_deployer = act["from"]
                            break
            except Exception:
                pass

        # 3. If reference_block is provided and found_block is still None, check receipt.contractAddress or trace_block / debug_traceBlockByNumber
        # NEVER use log matching (`allow_log_fallback=False`) here because reference_block is typically a mint block!
        if found_block is None and isinstance(reference_block, int) and reference_block > 0:
            dep_from_blk, tx_from_blk = await self.resolve_deployer_from_rpc_block(
                address, reference_block, allow_log_fallback=False
            )
            if dep_from_blk or tx_from_blk:
                found_deployer = found_deployer or dep_from_blk
                found_tx = found_tx or tx_from_blk
                found_block = reference_block

        # Resolve block timestamp if found_block was discovered
        if found_block is not None:
            try:
                blk = await self.rpc.eth_get_block_by_number(found_block, full_txs=False)
                if isinstance(blk, dict) and blk.get("timestamp") is not None:
                    raw_ts = blk["timestamp"]
                    found_ts = int(raw_ts, 16) if isinstance(raw_ts, str) and raw_ts.startswith("0x") else int(raw_ts)
            except Exception:
                pass

        if found_deployer and found_deployer.startswith("0x"):
            try:
                found_deployer = to_checksum_address(found_deployer)
            except Exception:
                pass

        return found_deployer, found_tx, found_block, found_ts

    async def resolve_deployer_from_rpc_block(
        self,
        address: str,
        deployed_block: int,
        allow_log_fallback: bool = True,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get the deployer from RPC for a known deployment block without fetching full blocks:
          1. Fetch block receipts (`eth_getBlockReceipts(deployed_block)`).
          2. Find the transaction whose receipt `contractAddress` matches `address`, and read `from` (and `transactionHash`).
          3. If it's a factory deployment (no top-level receipt `contractAddress` match), fall back to an RPC trace call
             (`trace_block` or `debug_traceBlockByNumber`) or (only when `deployed_block` is already verified) receipt log matching.
        Returns (deployer_address, creation_tx_hash).
        """
        addr_lower = address.lower()
        tx_from_by_hash: Dict[str, str] = {}

        # 1. Check block receipts for receipt.contractAddress == address
        receipts: Optional[List[Dict[str, Any]]] = None
        try:
            res_receipts = await self.rpc.eth_get_block_receipts(deployed_block)
            if isinstance(res_receipts, list):
                receipts = res_receipts
                for rcpt in receipts:
                    if isinstance(rcpt, dict):
                        txh = rcpt.get("transactionHash")
                        frm = rcpt.get("from")
                        if isinstance(txh, str) and isinstance(frm, str):
                            tx_from_by_hash[txh.lower()] = frm
        except Exception:
            receipts = None

        if isinstance(receipts, list):
            for rcpt in receipts:
                if not isinstance(rcpt, dict):
                    continue
                c_addr = (rcpt.get("contractAddress") or "").strip().lower()
                if c_addr == addr_lower:
                    txh = rcpt.get("transactionHash")
                    frm = rcpt.get("from") or (tx_from_by_hash.get(str(txh).lower()) if txh else None)
                    if isinstance(frm, str) and frm.startswith("0x"):
                        try:
                            frm = to_checksum_address(frm)
                        except Exception:
                            pass
                        return frm, (str(txh) if isinstance(txh, str) else None)

                # Check Abstract / ZKsync ContractDeployer system event in receipt logs
                for lg in rcpt.get("logs") or []:
                    if not isinstance(lg, dict):
                        continue
                    l_addr = (lg.get("address") or "").strip().lower()
                    topics = lg.get("topics") or []
                    if (
                        l_addr == "0x0000000000000000000000000000000000008006"
                        and len(topics) >= 4
                        and str(topics[0]).lower() == "0x290afdae231a3fc0bbae8b1af63698b0a1d79b21ad17df0342dfb952fe74f8e5"
                    ):
                        c_in_topic = str(topics[3]).lower()
                        if c_in_topic.endswith(addr_lower.replace("0x", "")):
                            dep_hex = "0x" + str(topics[1])[-40:]
                            try:
                                dep_hex = to_checksum_address(dep_hex)
                            except Exception:
                                pass
                            txh = rcpt.get("transactionHash")
                            return dep_hex, (str(txh) if isinstance(txh, str) else None)

        # 2. Factory deployment fallback: try trace_block (Parity/Erigon/Reth) or debug_traceBlockByNumber (Geth)
        try:
            traces = await self.rpc.call("trace_block", [hex(deployed_block)], retries=1)
            if isinstance(traces, list):
                for tr in traces:
                    if not isinstance(tr, dict):
                        continue
                    if tr.get("type") == "create":
                        res_obj = tr.get("result") or {}
                        created_addr = (res_obj.get("address") or "").strip().lower() if isinstance(res_obj, dict) else ""
                        if created_addr == addr_lower:
                            txh = tr.get("transactionHash")
                            act = tr.get("action") or {}
                            frm = (
                                (tx_from_by_hash.get(str(txh).lower()) if isinstance(txh, str) else None)
                                or (act.get("from") if isinstance(act, dict) else None)
                            )
                            if isinstance(frm, str) and frm.startswith("0x"):
                                try:
                                    frm = to_checksum_address(frm)
                                except Exception:
                                    pass
                                return frm, (str(txh) if isinstance(txh, str) else None)
        except Exception:
            pass

        try:
            dbg_traces = await self.rpc.call(
                "debug_traceBlockByNumber",
                [hex(deployed_block), {"tracer": "callTracer"}],
                retries=1,
            )
            if isinstance(dbg_traces, list):
                def _find_create_in_frame(frame: Dict[str, Any]) -> bool:
                    ftype = str(frame.get("type") or "").upper()
                    fto = str(frame.get("to") or "").strip().lower()
                    if ftype in ("CREATE", "CREATE2") and fto == addr_lower:
                        return True
                    for sub in frame.get("calls") or []:
                        if isinstance(sub, dict) and _find_create_in_frame(sub):
                            return True
                    return False

                for item in dbg_traces:
                    if not isinstance(item, dict):
                        continue
                    txh = item.get("txHash")
                    root_frame = item.get("result") if isinstance(item.get("result"), dict) else item
                    if isinstance(root_frame, dict) and _find_create_in_frame(root_frame):
                        frm = (
                            (tx_from_by_hash.get(str(txh).lower()) if isinstance(txh, str) else None)
                            or root_frame.get("from")
                        )
                        if isinstance(frm, str) and frm.startswith("0x"):
                            try:
                                frm = to_checksum_address(frm)
                            except Exception:
                                pass
                            return frm, (str(txh) if isinstance(txh, str) else None)
        except Exception:
            pass

        # 3. Also check if any receipt in deployed_block emitted logs from `address` (factory deploy + init)
        # Only allowed when `deployed_block` has ALREADY been verified as the creation block!
        if allow_log_fallback and isinstance(receipts, list):
            for rcpt in receipts:
                if not isinstance(rcpt, dict):
                    continue
                for lg in rcpt.get("logs") or []:
                    if isinstance(lg, dict) and (lg.get("address") or "").strip().lower() == addr_lower:
                        txh = rcpt.get("transactionHash")
                        frm = rcpt.get("from") or (tx_from_by_hash.get(str(txh).lower()) if txh else None)
                        if isinstance(frm, str) and frm.startswith("0x"):
                            try:
                                frm = to_checksum_address(frm)
                            except Exception:
                                pass
                            return frm, (str(txh) if isinstance(txh, str) else None)

        return None, None

    async def resolve_abstract_contract_deployment(
        self, address: str
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Specialized deployment resolver for Abstract (ZKsync EraVM, chain_id 2741).
        On Abstract, contracts are deployed via the system ContractDeployer (0x8006),
        emitting ContractDeployed(address indexed deployer, bytes32 indexed bytecodeHash, address indexed contractAddress).
        """
        addr_clean = address.lower().replace("0x", "")
        padded_contract = "0x" + "0" * 24 + addr_clean
        deployer_sys_addr = "0x0000000000000000000000000000000000008006"
        contract_deployed_topic = "0x290afdae231a3fc0bbae8b1af63698b0a1d79b21ad17df0342dfb952fe74f8e5"

        try:
            logs = await self.rpc.eth_get_logs(
                from_block=0,
                to_block="latest",
                address=deployer_sys_addr,
                topics=[contract_deployed_topic, None, None, padded_contract],
            )
            if isinstance(logs, list) and logs:
                lg = logs[0]
                topics = lg.get("topics") or []
                deployer = None
                if len(topics) > 1 and isinstance(topics[1], str) and len(topics[1]) >= 42:
                    raw_dep = "0x" + topics[1][-40:]
                    try:
                        deployer = to_checksum_address(raw_dep)
                    except Exception:
                        deployer = raw_dep
                tx_hash = lg.get("transactionHash")
                blk_num = lg.get("blockNumber")
                if isinstance(blk_num, str) and blk_num.startswith("0x"):
                    blk_num = int(blk_num, 16)
                elif isinstance(blk_num, int):
                    pass
                else:
                    blk_num = None

                blk_ts = None
                if blk_num is not None:
                    blk = await self.rpc.eth_get_block_by_number(blk_num, full_txs=False)
                    if isinstance(blk, dict) and blk.get("timestamp") is not None:
                        raw_ts = blk["timestamp"]
                        blk_ts = int(raw_ts, 16) if isinstance(raw_ts, str) and raw_ts.startswith("0x") else int(raw_ts)

                return deployer, tx_hash, blk_num, blk_ts
        except Exception as e:
            logger.debug("Abstract ContractDeployer log query failed for %s: %s", address, e)
        return None, None, None, None

    async def resolve_contract_deployment(
        self,
        address: str,
        reference_block: Optional[int] = None,
        known_deployer: Optional[str] = None,
        known_deployed_block: Optional[int] = None,
        known_deployed_timestamp: Optional[int] = None,
        known_deployed_tx_hash: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Determine real deployment (deployer, creation_tx_hash, deployed_block, deployed_timestamp)
        for a candidate contract using, in order:
          0. Check SQLite `contracts` table cache first (never using 'first seen by the bot' as deployment time).
          1. Explorer's contract-creation endpoint (`fetch_contract_creation`).
          2. Binary search over `eth_getCode` across block numbers (`find_first_code_block`) to find the first block
             where the contract has code.
          3. Trace call for factory deployments (`resolve_factory_deployment_via_trace` / `resolve_deployer_from_rpc_block`).
          4. Cache the result in SQLite (`contracts` table). If deployment time cannot be determined, record the reason
             and store as `age_unknown`.
        """
        checksum_addr = to_checksum_address(address)
        addr_low = checksum_addr.lower()
        deployer = known_deployer
        tx_hash = known_deployed_tx_hash
        deployed_block = known_deployed_block
        deployed_timestamp = known_deployed_timestamp
        failure_reasons: List[str] = []

        # 0. Check SQLite cache first
        existing_rec = None
        if self.db is not None and hasattr(self.db, "get_contract"):
            try:
                existing_rec = await self.db.get_contract(checksum_addr, chain=self.chain)
                if existing_rec:
                    deployer = deployer or existing_rec.deployer
                    tx_hash = tx_hash or existing_rec.deployed_tx_hash
                    if deployed_block is None and existing_rec.deployed_block is not None:
                        deployed_block = existing_rec.deployed_block
                    if deployed_timestamp is None and existing_rec.deployed_timestamp is not None:
                        deployed_timestamp = existing_rec.deployed_timestamp
            except Exception as e:
                logger.debug("Failed reading cached contract deployment from SQLite: %s", e)

        if deployed_block is not None and deployed_timestamp is not None and deployer:
            try:
                deployer = to_checksum_address(deployer)
            except Exception:
                pass
            self.last_deployment_lookup_errors.pop(addr_low, None)
            return deployer, tx_hash, deployed_block, deployed_timestamp

        # 1. Step 1 (in order): Explorer's contract-creation endpoint
        if (deployed_block is None or deployed_timestamp is None or not deployer) and hasattr(
            self.explorer, "fetch_contract_creation"
        ):
            try:
                creation_res = await self.explorer.fetch_contract_creation(checksum_addr)
                if (
                    isinstance(creation_res, tuple)
                    and len(creation_res) == 4
                    and any(x is not None for x in creation_res)
                ):
                    exp_dep, exp_tx, exp_blk, exp_ts = creation_res
                    if not deployer and isinstance(exp_dep, str):
                        deployer = exp_dep
                    if not tx_hash and isinstance(exp_tx, str):
                        tx_hash = exp_tx
                    if deployed_block is None and isinstance(exp_blk, int):
                        deployed_block = exp_blk
                    if deployed_timestamp is None and isinstance(exp_ts, int):
                        deployed_timestamp = exp_ts
                else:
                    failure_reasons.append("explorer contract-creation endpoint returned no data")
            except Exception as e:
                failure_reasons.append(f"explorer contract-creation error ({type(e).__name__}: {e})")
                logger.debug("Explorer fetch_contract_creation failed for %s: %s", checksum_addr, e)

        # If creation tx_hash is known (e.g. from Explorer Step 1), resolve block & deployer from RPC receipt/tx
        if tx_hash and (deployed_block is None or not deployer):
            try:
                receipt = await self.rpc.eth_get_transaction_receipt(tx_hash)
                if isinstance(receipt, dict):
                    if deployed_block is None and receipt.get("blockNumber") is not None:
                        raw_bn = receipt["blockNumber"]
                        deployed_block = (
                            int(raw_bn, 16)
                            if isinstance(raw_bn, str) and raw_bn.startswith("0x")
                            else int(raw_bn)
                        )
                    if not deployer and isinstance(receipt.get("from"), str):
                        deployer = receipt["from"]
            except Exception:
                pass

        if deployed_block is not None and deployed_timestamp is None:
            try:
                blk = await self.rpc.eth_get_block_by_number(deployed_block, full_txs=False)
                if isinstance(blk, dict) and blk.get("timestamp") is not None:
                    raw_ts = blk["timestamp"]
                    deployed_timestamp = (
                        int(raw_ts, 16)
                        if isinstance(raw_ts, str) and raw_ts.startswith("0x")
                        else int(raw_ts)
                    )
            except Exception:
                pass

        # On Abstract (ZKsync EraVM, chain_id 2741), resolve via ContractDeployer event (0x8006)
        if (self.chain == "abstract" or getattr(self, "chain_id", None) == 2741) and (
            deployed_block is None or deployed_timestamp is None or not deployer
        ):
            abs_dep, abs_tx, abs_blk, abs_ts = await self.resolve_abstract_contract_deployment(checksum_addr)
            if abs_dep and not deployer:
                deployer = abs_dep
            if abs_tx and not tx_hash:
                tx_hash = abs_tx
            if abs_blk is not None and deployed_block is None:
                deployed_block = abs_blk
            if abs_ts is not None and deployed_timestamp is None:
                deployed_timestamp = abs_ts

        # 2. Step 2 (in order): Binary search over eth_getCode across block numbers
        if deployed_block is None or deployed_timestamp is None:
            code_blk, code_ts = await self.find_first_code_block(
                checksum_addr, upper_block=reference_block
            )
            if deployed_block is None and code_blk is not None:
                deployed_block = code_blk
            if deployed_timestamp is None and code_ts is not None:
                deployed_timestamp = code_ts
            if deployed_block is None:
                err_detail = self._last_code_search_error.get(
                    addr_low, "eth_getCode binary search returned no block"
                )
                failure_reasons.append(err_detail)

        # 3. Step 3 (in order): Trace call for factory deployments
        if deployed_block is None or deployed_timestamp is None:
            tr_dep, tr_tx, tr_blk, tr_ts = await self.resolve_factory_deployment_via_trace(
                checksum_addr, reference_block=reference_block, tx_hash=tx_hash
            )
            if not deployer and tr_dep:
                deployer = tr_dep
            if not tx_hash and tr_tx:
                tx_hash = tr_tx
            if deployed_block is None and tr_blk is not None:
                deployed_block = tr_blk
            if deployed_timestamp is None and tr_ts is not None:
                deployed_timestamp = tr_ts
            if deployed_block is None:
                failure_reasons.append("factory trace call returned no creation block")

        # If deployed_block is now known, resolve deployer from RPC block receipts or factory trace if still missing
        if deployed_block is not None and not deployer:
            rpc_dep, rpc_tx = await self.resolve_deployer_from_rpc_block(checksum_addr, deployed_block)
            if rpc_dep:
                deployer = rpc_dep
            if not tx_hash and rpc_tx:
                tx_hash = rpc_tx

        if not deployer:
            try:
                fb_dep = await self.fetch_deployer_from_etherscan(checksum_addr)
                if isinstance(fb_dep, str):
                    deployer = fb_dep
            except Exception:
                pass

        if deployed_block is not None and deployed_timestamp is None:
            try:
                blk = await self.rpc.eth_get_block_by_number(deployed_block, full_txs=False)
                if isinstance(blk, dict) and blk.get("timestamp") is not None:
                    raw_ts = blk["timestamp"]
                    if isinstance(raw_ts, int):
                        deployed_timestamp = raw_ts
                    elif isinstance(raw_ts, str):
                        deployed_timestamp = int(raw_ts, 16) if raw_ts.startswith("0x") else int(raw_ts)
            except Exception as e:
                failure_reasons.append(
                    f"eth_getBlockByNumber({deployed_block}) failed to resolve timestamp: {e}"
                )

        if deployer:
            try:
                deployer = to_checksum_address(deployer)
            except Exception:
                pass

        if deployed_block is None or deployed_timestamp is None:
            reason_str = "; ".join(failure_reasons) if failure_reasons else "deployment block/timestamp unavailable"
            self.last_deployment_lookup_errors[addr_low] = reason_str
        else:
            self.last_deployment_lookup_errors.pop(addr_low, None)

        # 4. Cache in SQLite `contracts` table
        if self.db is not None and hasattr(self.db, "upsert_contract"):
            try:
                from app.db import ContractRecord
                rec = existing_rec or ContractRecord(
                    address=checksum_addr,
                    chain=self.chain,
                    standard="UNKNOWN",
                    created_at=int(time.time()),
                )
                rec.chain = self.chain
                if deployer:
                    rec.deployer = deployer
                if tx_hash:
                    rec.deployed_tx_hash = tx_hash
                if deployed_block is not None:
                    rec.deployed_block = deployed_block
                if deployed_timestamp is not None:
                    rec.deployed_timestamp = deployed_timestamp
                elif deployed_block is None or deployed_timestamp is None:
                    rec.age_status = "age_unknown"
                    rec.rejection_reason = f"age_unknown: {self.last_deployment_lookup_errors.get(addr_low, 'lookup failed')}"
                await self.db.upsert_contract(rec)
            except Exception as e:
                logger.debug("Failed caching contract deployment in SQLite for %s: %s", checksum_addr, e)

        return deployer, tx_hash, deployed_block, deployed_timestamp

    async def _fetch_uri_json_with_status(
        self,
        uri: Optional[str],
        sample_token_id: Optional[str] = None,
        source_label: str = "metadata",
        as_of_timestamp: Optional[int] = None,
    ) -> Tuple[Optional[Dict[str, Any]], str, Optional[str]]:
        """
        Resolve an HTTP, IPFS (trying two public gateways with a short timeout),
        Arweave, or data:application/json(;base64) URI into a parsed JSON dict.
        Caches resolved payloads in SQLite `uri_metadata_cache`.
        Returns (parsed_json_or_none, status, error_message_or_none) where status is:
          - 'ok': valid JSON dict parsed
          - 'not implemented': empty URI
          - 'fetch failed': network, HTTP, decoding, or JSON error (logged at WARNING)
        """
        if not uri or not isinstance(uri, str):
            return None, "not implemented", None
        clean = uri.strip()
        if not clean:
            return None, "not implemented", None

        # Replace ERC-1155 {id} template if present
        if "{id}" in clean or "{ID}" in clean:
            try:
                tid_int = int(str(sample_token_id), 0) if sample_token_id is not None else 1
                hex_id = f"{tid_int:064x}"
            except (ValueError, TypeError):
                hex_id = "1".zfill(64)
            clean = clean.replace("{id}", hex_id).replace("{ID}", hex_id)

        # 0. Check SQLite URI metadata cache first
        if self.db is not None and hasattr(self.db, "get_cached_uri_metadata"):
            try:
                cached_meta = await self.db.get_cached_uri_metadata(
                    clean,
                    ttl_seconds=self.cache_ttl_seconds,
                    as_of_timestamp=as_of_timestamp,
                    chain=self.chain,
                )
                if cached_meta is not None:
                    c_payload, c_status, c_err = cached_meta
                    if c_status == "ok" and isinstance(c_payload, dict):
                        return c_payload, "ok", None
            except Exception as e:
                logger.debug("Failed reading SQLite URI metadata cache for %s: %s", clean[:80], e)

        async def _save_cache(payload_obj: Optional[Dict[str, Any]], st: str, err_txt: Optional[str]) -> None:
            if self.db is not None and hasattr(self.db, "set_cached_uri_metadata"):
                try:
                    await self.db.set_cached_uri_metadata(
                        clean,
                        payload_obj,
                        status=st,
                        error=err_txt,
                        updated_at=as_of_timestamp,
                        chain=self.chain,
                    )
                except Exception as e:
                    logger.debug("Failed writing SQLite URI metadata cache for %s: %s", clean[:80], e)

        # 1. Inline data:application/json or data:text/plain;base64
        if clean.lower().startswith("data:application/json") or clean.lower().startswith("data:text/plain"):
            try:
                header, sep, payload = clean.partition(",")
                if not sep:
                    raise ValueError("Malformed data URI: missing comma separator")
                if ";base64" in header.lower():
                    b64_str = payload.strip()
                    rem = len(b64_str) % 4
                    if rem:
                        b64_str += "=" * (4 - rem)
                    decoded_bytes = base64.b64decode(b64_str)
                    parsed = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))
                else:
                    unquoted = urllib.parse.unquote(payload)
                    parsed = json.loads(unquoted)
                if isinstance(parsed, dict):
                    await _save_cache(parsed, "ok", None)
                    return parsed, "ok", None
                err_msg = f"Decoded data URI is not a JSON object ({type(parsed).__name__})"
                logger.warning("Metadata %s fetch failed for data URI: %s", source_label, err_msg)
                return None, "fetch failed", err_msg
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                logger.warning("Metadata %s fetch failed decoding data URI: %s", source_label, err_msg)
                return None, "fetch failed", err_msg

        # 2. Inline raw JSON string
        if clean.startswith("{") and clean.endswith("}"):
            try:
                parsed = json.loads(clean)
                if isinstance(parsed, dict):
                    await _save_cache(parsed, "ok", None)
                    return parsed, "ok", None
                err_msg = "Inline JSON is not a JSON object"
                logger.warning("Metadata %s fetch failed for inline JSON: %s", source_label, err_msg)
                return None, "fetch failed", err_msg
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                logger.warning("Metadata %s fetch failed parsing inline JSON: %s", source_label, err_msg)
                return None, "fetch failed", err_msg

        # 3. Convert ipfs:// (two public gateways), ar:// (Arweave gateway), or http(s)://
        gateway_urls = resolve_uri_to_gateway_urls(clean, sample_token_id=sample_token_id)
        if not gateway_urls:
            err_msg = f"Unsupported or invalid metadata URI: {clean[:100]}"
            logger.warning("Metadata %s fetch failed: %s", source_label, err_msg)
            return None, "fetch failed", err_msg

        client = await self._get_http_client()
        gateway_errors: List[str] = []
        for http_url in gateway_urls:
            try:
                resp = await client.get(http_url, timeout=3.5)
                if resp.status_code == 200:
                    parsed = resp.json()
                    if isinstance(parsed, dict):
                        await _save_cache(parsed, "ok", None)
                        return parsed, "ok", None
                    gateway_errors.append(f"{http_url} returned non-dict JSON ({type(parsed).__name__})")
                else:
                    gateway_errors.append(f"{http_url} -> HTTP {resp.status_code}")
            except Exception as exc:
                gateway_errors.append(f"{http_url} -> {type(exc).__name__}: {exc}")

        err_summary = "; ".join(gateway_errors) if gateway_errors else f"Failed fetching {clean[:100]}"
        logger.warning(
            "Metadata %s fetch failed for URI %s on %s: %s",
            source_label,
            clean[:120],
            self.chain_name,
            err_summary,
        )
        return None, "fetch failed", err_summary

    async def _fetch_uri_json(
        self, uri: str, sample_token_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Resolve an HTTP, IPFS, Arweave, or data:application/json URI into a parsed JSON dict."""
        parsed, _, _ = await self._fetch_uri_json_with_status(uri, sample_token_id=sample_token_id)
        return parsed

    async def resolve_metadata_and_socials(
        self,
        contract_uri: Optional[str],
        token_uri: Optional[str],
        sample_token_id: Optional[str] = None,
        contract_uri_call_status: Optional[str] = None,
        contract_uri_call_error: Optional[str] = None,
        token_uri_call_status: Optional[str] = None,
        token_uri_call_error: Optional[str] = None,
        as_of_timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        (1) Resolve contractURI() if present and parse JSON for name, description, image,
            external_link, and Twitter, Discord, or Telegram fields.
        (2) If contractURI fails or lacks fields/links, resolve tokenURI(tokenId) / uri(id)
            the same way and read external_url and social fields.
        (3) Track provenance ('via contractURI', 'via tokenURI') and distinguish missing reasons:
            'not implemented' (when call reverts), 'no links in metadata' (when JSON has none),
            and 'fetch failed' (for network/parse errors).
        """
        c_status = contract_uri_call_status or ("ok" if contract_uri else "not implemented")
        c_error = contract_uri_call_error
        t_status = token_uri_call_status or ("ok" if token_uri else "not implemented")
        t_error = token_uri_call_error

        meta_name: Optional[str] = None
        meta_description: Optional[str] = None
        meta_image: Optional[str] = None
        meta_external_link: Optional[str] = None
        merged_socials: Dict[str, str] = {}
        social_sources: Dict[str, str] = {}

        # 1. Try contractURI first
        if contract_uri:
            c_json, fetch_st, fetch_err = await self._fetch_uri_json_with_status(
                contract_uri,
                sample_token_id=sample_token_id,
                source_label="contractURI",
                as_of_timestamp=as_of_timestamp,
            )
            if fetch_st == "ok" and isinstance(c_json, dict):
                c_parsed = parse_metadata_json(c_json)
                meta_name = c_parsed.get("name")
                meta_description = c_parsed.get("description")
                meta_image = c_parsed.get("image")
                meta_external_link = c_parsed.get("external_link")
                c_socials = c_parsed.get("socials") or {}
                for k, v in c_socials.items():
                    if v:
                        merged_socials[k] = v
                        social_sources[k] = "via contractURI"
                c_status = "ok" if c_socials else "no links in metadata"
                c_error = None
            else:
                c_status = "fetch failed"
                c_error = fetch_err

        # 2. If contractURI failed or did not yield complete metadata/links, resolve tokenURI / uri(id)
        if token_uri:
            t_json, fetch_st, fetch_err = await self._fetch_uri_json_with_status(
                token_uri,
                sample_token_id=sample_token_id,
                source_label="tokenURI",
                as_of_timestamp=as_of_timestamp,
            )
            if fetch_st == "ok" and isinstance(t_json, dict):
                t_parsed = parse_metadata_json(t_json)
                if not meta_name and t_parsed.get("name"):
                    meta_name = t_parsed["name"]
                if not meta_description and t_parsed.get("description"):
                    meta_description = t_parsed["description"]
                if not meta_image and t_parsed.get("image"):
                    meta_image = t_parsed["image"]
                if not meta_external_link and t_parsed.get("external_link"):
                    meta_external_link = t_parsed["external_link"]
                t_socials = t_parsed.get("socials") or {}
                for k, v in t_socials.items():
                    if v and k not in merged_socials:
                        merged_socials[k] = v
                        social_sources[k] = "via tokenURI"
                t_status = "ok" if t_socials else "no links in metadata"
                t_error = None
            else:
                t_status = "fetch failed"
                t_error = fetch_err

        return {
            "name": meta_name,
            "description": meta_description,
            "image": meta_image,
            "external_link": meta_external_link,
            "socials": merged_socials,
            "social_sources": social_sources,
            "contract_uri_status": c_status,
            "contract_uri_error": c_error,
            "token_uri_status": t_status,
            "token_uri_error": t_error,
        }

    async def fetch_metadata_socials(
        self,
        contract_uri: Optional[str],
        token_uri: Optional[str],
        sample_token_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Read contractURI and tokenURI metadata when available and extract
        website, twitter, discord, and telegram links without inventing any link.
        """
        res = await self.resolve_metadata_and_socials(
            contract_uri=contract_uri,
            token_uri=token_uri,
            sample_token_id=sample_token_id,
        )
        return res["socials"]

    async def fetch_deployer_history(self, deployer_address: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Fetch deployer's earliest transactions via Explorer interface to determine:
        1. first_tx_timestamp (for deployer age)
        2. deployer_funding_source (earliest incoming transfer funder + amount)
        """
        return await self.explorer.fetch_deployer_history(deployer_address)

    async def fetch_deployer_first_tx_time(self, deployer_address: str) -> Optional[int]:
        """Return earliest transaction timestamp for deployer."""
        first_ts, _ = await self.fetch_deployer_history(deployer_address)
        return first_ts

    async def check_etherscan_source_verified(
        self, address: str
    ) -> Tuple[Optional[bool], str, Optional[str]]:
        is_ver, status_txt, impl, _ = await self.fetch_verification_and_abi(address)
        return is_ver, status_txt, impl

    async def fetch_verification_and_abi(
        self, address: str
    ) -> Tuple[Optional[bool], str, Optional[str], Optional[List[Dict[str, Any]]]]:
        """Fetch verification status, proxy implementation, and parsed ABI via Explorer interface."""
        return await self.explorer.fetch_verification_and_abi(address)

    async def fetch_mint_tx_insights(
        self,
        address: str,
        abi: Optional[List[Dict[str, Any]]] = None,
        trigger_tx_hash: Optional[str] = None,
    ) -> Tuple[Optional[int], Optional[str]]:
        """
        Inspect triggering or recent mint transactions to determine:
        1. tx_value_wei (mint price paid in transaction)
        2. mint_function_name (decoded function signature via ABI, local signature cache, or 4byte.directory, falling back to raw selector)
        """
        tx_hashes: List[str] = []
        if trigger_tx_hash:
            tx_hashes.append(trigger_tx_hash)
        if self.db is not None:
            try:
                recent = await self.db.get_recent_mint_tx_hashes(address, limit=3, chain=self.chain)
                for h in recent:
                    if h not in tx_hashes:
                        tx_hashes.append(h)
            except Exception:
                pass

        for txh in tx_hashes:
            try:
                tx = await self.rpc.eth_get_transaction_by_hash(txh)
                if not isinstance(tx, dict):
                    continue
                val_hex = tx.get("value", "0x0")
                val_wei = int(val_hex, 16) if isinstance(val_hex, str) else int(val_hex or 0)
                inp = tx.get("input") or tx.get("data") or ""
                if isinstance(inp, str) and len(inp) >= 10:
                    self._last_mint_tx_input[address.lower()] = inp
                fn_name = None
                if isinstance(inp, str) and len(inp) >= 10:
                    sel = inp[:10].lower()
                    fn_name = await decode_function_selector(
                        sel,
                        abi=abi,
                        db=self.db,
                        http_client=await self._get_http_client(),
                    )
                return val_wei, fn_name
            except Exception:
                continue

        val_wei, fn_name = await self.explorer.fetch_recent_mint_tx(address, abi=abi)
        if val_wei is not None or fn_name is not None:
            if fn_name and fn_name.startswith("0x") and len(fn_name) == 10:
                fn_name = await decode_function_selector(
                    fn_name,
                    abi=abi,
                    db=self.db,
                    http_client=await self._get_http_client(),
                )
            return val_wei, fn_name

        # Check verified ABI for payable / mint functions if no recent tx could be decoded
        if abi and isinstance(abi, list):
            for item in abi:
                if isinstance(item, dict) and item.get("type") == "function":
                    name = item.get("name", "")
                    if any(k in name.lower() for k in ("publicmint", "mint", "claim", "purchase")) and item.get("stateMutability") in ("payable", "nonpayable"):
                        inputs = ",".join(i.get("type", "") for i in item.get("inputs", []))
                        return None, f"{name}({inputs})"

        return None, None

    async def fetch_top_minters_with_fallback(
        self, address: str, known_total_supply: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[float]]:
        """
        Compute top-5 minter wallet concentration from SQLite, or fallback to Explorer recent token transfers.
        """
        if self.db is not None:
            try:
                total_qty, top_list = await self.db.get_top_minters(address, limit=5, chain=self.chain)
                if total_qty > 0 and top_list:
                    top5_pct = round(sum(item["pct"] for item in top_list), 1)
                    return top_list, min(100.0, top5_pct)
            except Exception as e:
                logger.debug("SQLite get_top_minters failed: %s", e)

        return await self.explorer.fetch_top_minters(address, known_total_supply=known_total_supply)

    async def fetch_opensea_data(
        self, address: str
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Dict[str, str]]:
        """
        Fetch OpenSea collection data (slug, floor, listings, socials) via the OpenSea API v2
        if indexed and chain is supported. Verifies that the resolved collection's contract
        address matches `address` before returning `slug`. If it doesn't match, omits it.
        """
        addr_low = address.lower()
        self._last_opensea_verified_contract[addr_low] = None
        self._last_opensea_token_id[addr_low] = None

        if not self.opensea_chain_slug:
            return None, None, None, {}

        if not self.opensea_key and self._http is None:
            if not getattr(self, "_opensea_missing_key_warned", False):
                self._opensea_missing_key_warned = True
                logger.warning(
                    "OPENSEA_API_KEY is not configured — OpenSea v2 API lookups disabled on chain=%s",
                    self.chain,
                )
            return None, None, None, {}

        slug: Optional[str] = None
        verified_contract: Optional[str] = None
        floor_str: Optional[str] = None
        listings_count: Optional[int] = None
        socials: Dict[str, str] = {}

        client = await self._get_http_client()

        # 1. OpenSea v2 API: resolve collection slug for contract & chain
        await self._market_limiter.acquire()
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self.opensea_key:
            headers["x-api-key"] = self.opensea_key

        try:
            r1 = await client.get(
                f"{self.opensea_url}/api/v2/chain/{self.opensea_chain_slug}/contract/{address}",
                headers=headers,
            )
            if r1.status_code == 200:
                c_data = r1.json()
                if isinstance(c_data, dict):
                    returned_addr = str(c_data.get("address") or "").strip().lower()
                    if returned_addr and returned_addr != addr_low:
                        logger.warning(
                            "OpenSea contract endpoint address mismatch for %s on %s (got %s) — omitting collection",
                            address,
                            self.opensea_chain_slug,
                            returned_addr,
                        )
                    elif c_data.get("collection"):
                        slug = str(c_data["collection"]).strip() or None
                        if returned_addr == addr_low:
                            verified_contract = to_checksum_address(address)
            else:
                logger.warning(
                    "OpenSea v2 contract lookup failed (%s on %s): HTTP status=%d body=%s",
                    address,
                    self.opensea_chain_slug,
                    r1.status_code,
                    redact_secrets(r1.text[:500], [self.opensea_key]),
                )

            # Fallback OpenSea v2 endpoint: /api/v2/chain/{chain}/contract/{address}/nfts
            if not slug and self.opensea_key:
                r_nfts = await client.get(
                    f"{self.opensea_url}/api/v2/chain/{self.opensea_chain_slug}/contract/{address}/nfts",
                    params={"limit": 1},
                    headers=headers,
                )
                if r_nfts.status_code == 200:
                    nfts_data = r_nfts.json()
                    if isinstance(nfts_data, dict) and isinstance(nfts_data.get("nfts"), list) and nfts_data["nfts"]:
                        first_nft = nfts_data["nfts"][0]
                        if isinstance(first_nft, dict):
                            nft_contract = str(first_nft.get("contract") or "").strip().lower()
                            if nft_contract and nft_contract != addr_low:
                                logger.warning(
                                    "OpenSea NFTs endpoint contract mismatch for %s on %s (got %s) — omitting",
                                    address,
                                    self.opensea_chain_slug,
                                    nft_contract,
                                )
                            else:
                                if first_nft.get("identifier") is not None:
                                    self._last_opensea_token_id[addr_low] = str(first_nft["identifier"]).strip()
                                if first_nft.get("collection"):
                                    slug = str(first_nft["collection"]).strip() or None
                                    if nft_contract == addr_low:
                                        verified_contract = to_checksum_address(address)

            if slug:
                r2 = await client.get(
                    f"{self.opensea_url}/api/v2/collections/{slug}",
                    headers=headers,
                )
                if r2.status_code == 200:
                    col = r2.json()
                    if isinstance(col, dict):
                        # Verify that the resolved collection's contract address matches `address`
                        col_contracts: List[str] = []
                        has_contract_field = False
                        if "contracts" in col and isinstance(col.get("contracts"), list):
                            has_contract_field = True
                            for c_obj in col["contracts"]:
                                if isinstance(c_obj, dict) and c_obj.get("address"):
                                    c_chain = str(c_obj.get("chain") or "").strip().lower()
                                    if not c_chain or c_chain == self.opensea_chain_slug.lower():
                                        col_contracts.append(str(c_obj["address"]).strip().lower())
                                elif isinstance(c_obj, str) and c_obj.strip():
                                    col_contracts.append(c_obj.strip().lower())
                        if "primary_asset_contracts" in col and isinstance(col.get("primary_asset_contracts"), list):
                            has_contract_field = True
                            for c_obj in col["primary_asset_contracts"]:
                                if isinstance(c_obj, dict) and c_obj.get("address"):
                                    col_contracts.append(str(c_obj["address"]).strip().lower())
                        if isinstance(col.get("contract"), str) and col["contract"].strip():
                            has_contract_field = True
                            col_contracts.append(col["contract"].strip().lower())

                        if has_contract_field and addr_low not in col_contracts:
                            logger.warning(
                                "OpenSea collection %r contract address mismatch for %s on %s (collection contracts=%s) — omitting collection link",
                                slug,
                                address,
                                self.opensea_chain_slug,
                                col_contracts,
                            )
                            slug = None
                            verified_contract = None
                        else:
                            verified_contract = to_checksum_address(address)
                            if col.get("twitter_username"):
                                tw = _normalize_social_url("twitter", col["twitter_username"])
                                if tw:
                                    socials["twitter"] = tw
                            if col.get("discord_url"):
                                dc = _normalize_social_url("discord", col["discord_url"])
                                if dc:
                                    socials["discord"] = dc
                            if col.get("project_url"):
                                wb = _normalize_social_url("website", col["project_url"])
                                if wb:
                                    socials["website"] = wb
                            if col.get("telegram_url") or col.get("telegram_username"):
                                tg = _normalize_social_url(
                                    "telegram", col.get("telegram_url") or col.get("telegram_username")
                                )
                                if tg:
                                    socials["telegram"] = tg
                else:
                    logger.warning(
                        "OpenSea v2 collection details failed (slug=%s): HTTP status=%d body=%s",
                        slug,
                        r2.status_code,
                        redact_secrets(r2.text[:500], [self.opensea_key]),
                    )
                    if not verified_contract:
                        slug = None

                if slug:
                    r3 = await client.get(
                        f"{self.opensea_url}/api/v2/collections/{slug}/stats",
                        headers=headers,
                    )
                    if r3.status_code == 200:
                        stats_json = r3.json()
                        if isinstance(stats_json, dict):
                            st = stats_json.get("total") or {}
                            fp = st.get("floor_price")
                            sym = st.get("floor_price_symbol") or self.native_token_symbol
                            if fp is not None:
                                floor_str = f"{fp} {sym}"
                            if st.get("num_owners") is not None:
                                try:
                                    self._last_opensea_num_owners[addr_low] = int(st["num_owners"])
                                except (ValueError, TypeError):
                                    pass
                            vol_24h_val = st.get("one_day_volume") or st.get("volume_24h")
                            intervals = stats_json.get("intervals")
                            if vol_24h_val is None and isinstance(intervals, list):
                                for iv in intervals:
                                    if isinstance(iv, dict) and str(iv.get("interval", "")).lower() in ("one_day", "1d", "24h"):
                                        vol_24h_val = iv.get("volume")
                                        break
                            if vol_24h_val is not None:
                                try:
                                    v_float = float(vol_24h_val)
                                    self._last_opensea_volume_24h[addr_low] = (
                                        f"{v_float:.4f}".rstrip("0").rstrip(".") + f" {sym}"
                                    )
                                except (ValueError, TypeError):
                                    self._last_opensea_volume_24h[addr_low] = f"{vol_24h_val} {sym}"
                    else:
                        logger.warning(
                            "OpenSea v2 collection stats failed (slug=%s): HTTP status=%d body=%s",
                            slug,
                            r3.status_code,
                            redact_secrets(r3.text[:500], [self.opensea_key]),
                        )

                    r4 = await client.get(
                        f"{self.opensea_url}/api/v2/listings/collection/{slug}/all",
                        params={"limit": 100},
                        headers=headers,
                    )
                    if r4.status_code == 200:
                        listings_json = r4.json()
                        if isinstance(listings_json, dict) and isinstance(listings_json.get("listings"), list):
                            listings_count = len(listings_json["listings"])
        except Exception as e:
            logger.warning(
                "OpenSea API lookup error for %s on %s: %s",
                address,
                self.opensea_chain_slug,
                redact_secrets(e, [self.opensea_key]),
            )

        self._last_opensea_verified_contract[addr_low] = verified_contract if slug else None

        # 2. CoinGecko NFT v3 API fallback ONLY for floor price (never sets OpenSea slug or socials!)
        cg_platform = COINGECKO_PLATFORM_MAP.get(self.opensea_chain_slug.lower())
        if cg_platform and not floor_str:
            await self._market_limiter.acquire()
            try:
                cg_resp = await client.get(
                    f"https://api.coingecko.com/api/v3/nfts/{cg_platform}/contract/{address.lower()}"
                )
                if cg_resp.status_code == 200:
                    cg = cg_resp.json()
                    if isinstance(cg, dict) and isinstance(cg.get("floor_price"), dict):
                        fp_eth = cg["floor_price"].get("native_currency")
                        fp_usd = cg["floor_price"].get("usd")
                        if fp_eth is not None:
                            floor_str = f"{fp_eth} {self.native_token_symbol}" + (f" (${fp_usd:,.0f})" if fp_usd else "")
            except Exception as e:
                logger.debug("CoinGecko NFT fallback failed for %s: %s", address, redact_secrets(e))

        return slug, floor_str, listings_count, socials

    @staticmethod
    def _is_evm_revert_error(exc: Exception) -> Tuple[bool, str]:
        """Return (True, reason) if the exception is an on-chain EVM execution revert."""
        msg = str(exc)
        low = msg.lower()
        if isinstance(exc, RPCError) and any(
            kw in low
            for kw in (
                "revert",
                "execution error",
                "vm execution",
                "code=3",
                "code=-32000",
                "invalid opcode",
            )
        ):
            clean = msg.replace("RPC Error (eth_call):", "").strip()
            return True, clean
        return False, msg

    async def simulate_transfer_or_approval_honeypot(
        self,
        address: str,
        standard: Optional[str] = None,
        sample_holder: Optional[str] = None,
        sample_token_id: Optional[str] = None,
        fallback_sender: Optional[str] = None,
    ) -> Tuple[Optional[bool], Optional[str]]:
        """
        Simulate an NFT approval (`setApprovalForAll`) and, when a holder/tokenId is known,
        a transfer (`transferFrom`) via `eth_call` to detect honeypot / transfer-locked contracts.
        Returns:
          (True, detail)  -> reverted on-chain (honeypot / transfer lock detected)
          (False, detail) -> simulated call succeeded without revert
          (None, detail)  -> simulation could not be executed (RPC failure or no response)
        """
        sender = (
            sample_holder
            or fallback_sender
            or "0x000000000000000000000000000000000000dEaD"
        )
        operator_padded = "0" * 24 + "000000000000000000000000000000000000beef"
        bool_true_padded = "0" * 63 + "1"
        # setApprovalForAll(address,bool) selector = 0xa22cb465
        approval_data = f"0xa22cb465{operator_padded}{bool_true_padded}"

        try:
            try:
                res = await self.rpc.eth_call(address, approval_data, from_addr=sender)
            except TypeError:
                res = await self.rpc.eth_call(address, approval_data)
        except Exception as exc:
            is_rev, reason = self._is_evm_revert_error(exc)
            if is_rev:
                return True, f"setApprovalForAll reverted: {reason}"
            return None, "eth_call simulation failed due to RPC error"

        if not isinstance(res, str):
            return None, "eth_call returned no data"

        # If we have a sample_holder and numeric sample_token_id for ERC-721, also simulate transferFrom
        if sample_holder and sample_token_id is not None and (standard in (None, "ERC721", "ERC-721", "UNKNOWN")):
            try:
                tid_int = int(sample_token_id)
                if tid_int >= 0:
                    holder_clean = sample_holder.lower().replace("0x", "").rjust(64, "0")
                    recipient_clean = "0" * 24 + "000000000000000000000000000000000000beef"
                    tid_hex = hex(tid_int)[2:].rjust(64, "0")
                    # First check ownerOf(tid) == sample_holder so we only test transferFrom if holder still owns it
                    owner_of_data = f"0x6352211e{tid_hex}"
                    owner_res = await self.rpc.eth_call(address, owner_of_data)
                    if isinstance(owner_res, str) and len(owner_res) >= 42:
                        actual_owner = "0x" + owner_res[-40:].lower()
                        if actual_owner == sample_holder.lower():
                            # transferFrom(address,address,uint256) selector = 0x23b872dd
                            tf_data = f"0x23b872dd{holder_clean}{recipient_clean}{tid_hex}"
                            try:
                                await self.rpc.eth_call(address, tf_data, from_addr=sample_holder)
                            except TypeError:
                                await self.rpc.eth_call(address, tf_data)
                            return False, f"transferFrom(token #{tid_int}) & setApprovalForAll succeeded"
            except Exception as exc:
                is_rev, reason = self._is_evm_revert_error(exc)
                if is_rev:
                    return True, f"transferFrom(token #{sample_token_id}) reverted: {reason}"

        return False, "setApprovalForAll(operator, true) succeeded"

    @staticmethod
    def _decode_revert_reason(raw_data: Any, default_msg: str = "") -> str:
        """Decode ABI-encoded revert error string or panic code from eth_call revert data."""
        raw_str = str(raw_data or default_msg or "").strip()
        m_hex = re.search(r"0x[0-9a-fA-F]{8,}", raw_str)
        hex_data = m_hex.group(0).lower() if m_hex else (raw_str.lower() if raw_str.startswith("0x") else "")

        if hex_data:
            # 0x08c379a0: Error(string)
            if hex_data.startswith("0x08c379a0") and len(hex_data) >= 138:
                try:
                    payload = bytes.fromhex(hex_data[10:])
                    if len(payload) >= 64:
                        str_len = int.from_bytes(payload[32:64], "big")
                        str_bytes = payload[64 : 64 + str_len]
                        decoded = str_bytes.decode("utf-8", errors="replace").strip()
                        if decoded:
                            return decoded
                except Exception:
                    pass
            # 0x4e487b71: Panic(uint256)
            elif hex_data.startswith("0x4e487b71") and len(hex_data) >= 74:
                try:
                    payload = bytes.fromhex(hex_data[10:])
                    code = int.from_bytes(payload[:32], "big")
                    return f"Panic(0x{code:x})"
                except Exception:
                    pass
            # Custom error selector
            elif len(hex_data) >= 10 and not default_msg:
                custom_sel = hex_data[:10]
                return f"CustomError({custom_sel})"

        clean = default_msg or raw_str
        for prefix in (
            "RPC Error (eth_call):",
            "execution reverted:",
            "VM Exception while processing transaction: revert",
            "revert",
        ):
            if prefix.lower() in clean.lower():
                idx = clean.lower().find(prefix.lower())
                clean = clean[idx + len(prefix) :].strip()
        clean = re.sub(r"\(code=[-\d]+\)", "", clean).strip()
        return clean or default_msg or "Execution reverted"

    async def fetch_and_match_bytecode_template(
        self,
        address: str,
    ) -> Dict[str, Any]:
        """
        Fetch runtime bytecode via eth_getCode, strip trailing metadata hash,
        record SHA-256 hashes in SQLite, and match against known_templates.
        """
        try:
            code = await self.rpc.eth_get_code(address)
            if not code or code == "0x" or code.strip() == "":
                return {
                    "runtime_bytecode_hash": None,
                    "stripped_bytecode_hash": None,
                    "template_label": None,
                    "template_risk_flag": None,
                    "template_match_count": 0,
                    "status": "empty",
                }

            if self.db is not None:
                rec = await self.db.record_contract_bytecode(
                    contract_address=address,
                    bytecode=code,
                    chain=self.chain,
                )
                t_hash = rec["stripped_bytecode_sha256"]
                t_info = await self.db.get_template_info(t_hash)
                return {
                    "runtime_bytecode_hash": rec["bytecode_sha256"],
                    "stripped_bytecode_hash": t_hash,
                    "template_label": t_info.get("label"),
                    "template_risk_flag": t_info.get("risk_flag"),
                    "template_match_count": t_info.get("match_count", 1),
                    "status": "ok",
                }
            else:
                from app.db import strip_bytecode_metadata, compute_bytecode_hash
                clean_hex = code[2:] if code.startswith("0x") else code
                b_hash = compute_bytecode_hash(clean_hex)
                s_hex = strip_bytecode_metadata(clean_hex)
                s_hash = compute_bytecode_hash(s_hex)
                return {
                    "runtime_bytecode_hash": b_hash,
                    "stripped_bytecode_hash": s_hash,
                    "template_label": None,
                    "template_risk_flag": "neutral",
                    "template_match_count": 1,
                    "status": "ok",
                }
        except Exception as e:
            logger.debug("Failed fetching/matching bytecode template for %s: %s", address, e)
            return {
                "runtime_bytecode_hash": None,
                "stripped_bytecode_hash": None,
                "template_label": None,
                "template_risk_flag": None,
                "template_match_count": 0,
                "status": "unavailable",
            }

    async def simulate_mint(
        self,
        address: str,
        mint_function_name: Optional[str] = None,
        tx_price_wei: Optional[int] = None,
        observed_input_data: Optional[str] = None,
        abi: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Simulate a mint using `eth_call` from a throwaway address with NO key and NO signing.
        Tries the mint function discovered from observed mint transactions, with quantity 1
        and observed price in wei.
        Never signs or sends any transaction.
        """
        throwaway = "0x000000000000000000000000000000000000dEaD"

        sim_data: Optional[str] = None
        fn_tested: Optional[str] = mint_function_name

        if observed_input_data and isinstance(observed_input_data, str) and len(observed_input_data) >= 10:
            sel = observed_input_data[:10].lower()
            if len(observed_input_data) == 10:
                sim_data = sel
            elif len(observed_input_data) == 74:
                qty_one = (1).to_bytes(32, "big").hex()
                sim_data = f"{sel}{qty_one}"
            elif len(observed_input_data) >= 138:
                qty_one = (1).to_bytes(32, "big").hex()
                addr_padded = throwaway[2:].lower().rjust(64, "0")
                if "address" in str(fn_tested or "").lower():
                    sim_data = f"{sel}{addr_padded}{qty_one}"
                else:
                    sim_data = f"{sel}{qty_one}{observed_input_data[74:]}"
            else:
                sim_data = observed_input_data
        elif mint_function_name and isinstance(mint_function_name, str):
            fn_clean = mint_function_name.strip()
            if fn_clean.startswith("0x") and len(fn_clean) == 10:
                sel = fn_clean.lower()
                qty_one = (1).to_bytes(32, "big").hex()
                sim_data = f"{sel}{qty_one}"
            elif "(" in fn_clean and fn_clean.endswith(")"):
                from eth_utils import keccak
                sel = "0x" + keccak(text=fn_clean)[:4].hex()
                if fn_clean.endswith("()"):
                    sim_data = sel
                elif "address" in fn_clean:
                    addr_padded = throwaway[2:].lower().rjust(64, "0")
                    qty_one = (1).to_bytes(32, "big").hex()
                    sim_data = f"{sel}{addr_padded}{qty_one}"
                else:
                    qty_one = (1).to_bytes(32, "big").hex()
                    sim_data = f"{sel}{qty_one}"

        if not sim_data:
            return {
                "status": "not_checked",
                "revert_reason": None,
                "classification": "not checked",
                "tested_function": None,
                "detail": "not checked (mint function could not be determined)",
            }

        price = int(tx_price_wei) if tx_price_wei is not None else 0

        try:
            try:
                res = await self.rpc.eth_call(
                    to=address,
                    data=sim_data,
                    from_addr=throwaway,
                    value=price,
                )
            except TypeError:
                res = await self.rpc.eth_call(to=address, data=sim_data, from_addr=throwaway)

            if isinstance(res, str):
                return {
                    "status": "success",
                    "revert_reason": None,
                    "classification": "Open / Public Mint",
                    "tested_function": fn_tested or sim_data[:10],
                    "detail": f"Simulation succeeded (1 qty @ {price / (10 ** self.native_token_decimals):.4f} {self.native_token_symbol} via {fn_tested or sim_data[:10]})",
                }
        except Exception as exc:
            err_data = getattr(exc, "data", None)
            err_msg = str(exc)
            revert_reason = self._decode_revert_reason(err_data, default_msg=err_msg)

            low_rev = revert_reason.lower()
            allowlist_keywords = (
                "allowlist",
                "whitelist",
                "merkle",
                "signature",
                "signer",
                "not eligible",
                "not on list",
                "presale",
                "wl only",
                "proof",
                "not authorized",
                "unauthorized",
                "only whitelisted",
            )
            closed_keywords = (
                "closed",
                "not active",
                "not started",
                "sale paused",
                "paused",
                "sold out",
                "max supply",
                "ended",
                "inactive",
                "not live",
                "disabled",
                "exceeded max",
                "reached max",
            )

            if any(k in low_rev for k in allowlist_keywords):
                classification = "Allowlist Gating"
            elif any(k in low_rev for k in closed_keywords):
                classification = "Closed / Inactive Mint"
            else:
                classification = "Reverted (Other)"

            return {
                "status": "reverted",
                "revert_reason": revert_reason,
                "classification": classification,
                "tested_function": fn_tested or sim_data[:10],
                "detail": f"{classification}: {revert_reason}",
            }

        return {
            "status": "not_checked",
            "revert_reason": None,
            "classification": "not checked",
            "tested_function": fn_tested,
            "detail": "not checked",
        }

    async def resolve_cross_chain_deployers(
        self,
        deployer: Optional[str],
        contract_address: str,
        deployed_timestamp: Optional[int],
    ) -> Tuple[List[Dict[str, Any]], str]:
        """Record contract deployer and fetch other contracts by this deployer across all configured chains."""
        if not deployer or deployer == ZERO_ADDRESS:
            return [], "unavailable"

        if self.db is None:
            return [], "none"

        try:
            await self.db.record_cross_chain_deployer(
                deployer=deployer,
                chain=self.chain,
                contract_address=contract_address,
                deploy_time=deployed_timestamp,
                alert_status="unalerted",
            )
            others = await self.db.get_cross_chain_deployer_contracts(
                deployer=deployer,
                exclude_chain=self.chain,
                exclude_contract=contract_address,
            )
            status = "ok" if others else "none"
            return others, status
        except Exception as e:
            logger.debug("Failed resolving cross-chain deployer for %s: %s", deployer, e)
            return [], "unavailable"

    async def resolve_funding_clusters(
        self,
        contract_address: str,
        deployer: Optional[str],
        deployer_funding_source: Optional[str],
        minter_funding_pairs: Optional[List[Tuple[str, str]]],
    ) -> Tuple[List[Dict[str, Any]], str]:
        """Record wallet-funder pairs and detect funding clusters appearing across multiple alerted contracts."""
        if self.db is None:
            return [], "none"

        try:
            sources_to_check: List[str] = []

            # 1. Deployer funder
            if deployer and deployer_funding_source:
                m_funder = ETH_ADDRESS_RE.search(deployer_funding_source)
                if m_funder:
                    f_addr = m_funder.group(0).lower()
                    sources_to_check.append(f_addr)
                    await self.db.record_funding_cluster(
                        wallet=deployer,
                        funding_source=f_addr,
                        chain=self.chain,
                        contract_address=contract_address,
                    )

            # 2. Minters funders
            if minter_funding_pairs:
                for w, f in minter_funding_pairs:
                    if f and f != ZERO_ADDRESS:
                        sources_to_check.append(f.lower())
                        await self.db.record_funding_cluster(
                            wallet=w,
                            funding_source=f,
                            chain=self.chain,
                            contract_address=contract_address,
                        )

            if not sources_to_check:
                return [], "none"

            detected = await self.db.find_cross_contract_funding_clusters(
                funding_sources=sources_to_check,
                current_contract=contract_address,
                current_chain=self.chain,
            )
            status = "ok" if detected else "none"
            return detected, status
        except Exception as e:
            logger.debug("Failed resolving funding clusters for %s: %s", contract_address, e)
            return [], "unavailable"

    async def enrich_contract(
        self,
        address: str,
        known_deployer: Optional[str] = None,
        as_of_timestamp: Optional[int] = None,
        rolling_mints_per_minute: Optional[float] = None,
        force_refresh: bool = False,
        trigger_block_number: Optional[int] = None,
        trigger_tx_hash: Optional[str] = None,
        recent_token_id: Optional[str] = None,
    ) -> EnrichmentResult:
        """
        Perform complete enrichment for an NFT contract with SQLite caching and rate limiting.
        Never invents fallback values if an on-chain or explorer lookup fails.
        """
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        checksum_addr = to_checksum_address(address)

        # 0. Check SQLite Cache first (unless force_refresh)
        if self.db is not None and not force_refresh:
            try:
                cached = await self.db.get_cached_enrichment(
                    checksum_addr,
                    ttl_seconds=self.cache_ttl_seconds,
                    as_of_timestamp=now,
                    chain=self.chain,
                )
                if cached:
                    logger.info("Using SQLite cached enrichment for %s on %s", checksum_addr, self.chain_name)
                    res = EnrichmentResult.from_dict(cached)
                    total_qty, top_minters = await self.db.get_top_minters(checksum_addr, limit=5, chain=self.chain)
                    if total_qty > 0 and top_minters:
                        res.top_minters = top_minters
                        res.top5_concentration_pct = min(100.0, round(sum(x["pct"] for x in top_minters), 1))
                    if hasattr(self.db, "get_self_mint_stats"):
                        sm_cnt, sm_tot, sm_pct = await self.db.get_self_mint_stats(
                            checksum_addr, owner=res.owner, deployer=res.deployer, chain=self.chain
                        )
                        res.self_mints = sm_cnt
                        if sm_tot > 0:
                            res.self_mint_pct = sm_pct
                    if hasattr(self.db, "get_watched_minters_for_contract"):
                        try:
                            res.watched_wallets_minted = await self.db.get_watched_minters_for_contract(
                                checksum_addr, chain=self.chain
                            )
                        except Exception:
                            pass
                    zero_addr = "0x0000000000000000000000000000000000000000"
                    owner_dep_set = {
                        a.strip().lower()
                        for a in (res.owner, res.deployer)
                        if isinstance(a, str) and a.strip() and a.strip().lower() != zero_addr
                    }
                    if res.top_minters and owner_dep_set:
                        t1_addr = str(res.top_minters[0].get("address", "")).strip().lower()
                        t1_cnt = int(res.top_minters[0].get("count", 0))
                        res.owner_is_top_minter = (t1_addr in owner_dep_set) or (res.self_mints > 0 and res.self_mints >= t1_cnt)
                    if rolling_mints_per_minute is not None:
                        res.mints_per_minute = rolling_mints_per_minute
                    if trigger_block_number is not None:
                        res.trigger_block_number = trigger_block_number
                    if trigger_tx_hash is not None:
                        res.trigger_tx_hash = trigger_tx_hash
                    if recent_token_id is not None:
                        res.recent_token_id = str(recent_token_id)
                    if res.contract_deployed_timestamp is not None:
                        res.contract_age_seconds = max(0, now - res.contract_deployed_timestamp)
                        res.contract_age_formatted = format_contract_age(res.contract_age_seconds)
                        res.contract_deployment_date = format_deployment_date(res.contract_deployed_timestamp)
                        res.contract_age_label = classify_contract_age(
                            res.contract_age_seconds, self.max_contract_age_hours
                        )
                    return res
            except Exception as e:
                logger.debug("Cache read failed for %s: %s", checksum_addr, e)

        # Gather observed token IDs and sample holder from real mint events first
        observed_token_ids: List[int] = []
        if recent_token_id is not None:
            try:
                tid_val = int(str(recent_token_id), 0)
                if tid_val >= 0:
                    observed_token_ids.append(tid_val)
            except (ValueError, TypeError):
                pass

        sample_holder: Optional[str] = None
        sample_token_id: Optional[str] = recent_token_id
        if self.db is not None:
            if hasattr(self.db, "get_observed_token_ids"):
                try:
                    db_tids = await self.db.get_observed_token_ids(checksum_addr, limit=5, chain=self.chain)
                    for t in db_tids:
                        if t not in observed_token_ids:
                            observed_token_ids.append(t)
                except Exception:
                    pass
            if hasattr(self.db, "get_sample_mint_holder"):
                try:
                    db_holder, db_token_id = await self.db.get_sample_mint_holder(
                        checksum_addr, chain=self.chain
                    )
                    sample_holder = db_holder
                    if sample_token_id is None and db_token_id is not None:
                        sample_token_id = str(db_token_id)
                    if db_token_id is not None:
                        try:
                            dtid = int(str(db_token_id), 0)
                            if dtid >= 0 and dtid not in observed_token_ids:
                                observed_token_ids.append(dtid)
                        except (ValueError, TypeError):
                            pass
                except Exception:
                    pass

        # 1. On-chain Standard, Metadata, Supply, Owner, Paused, Price Getter, Royalties
        detected_std, is_nft = await self.detector.detect_nft_standard(checksum_addr)
        standard: Optional[str] = detected_std if is_nft else None

        name, symbol = await self.detector.fetch_metadata(checksum_addr)
        total_supply, max_supply, max_supply_getter = await self.detector.fetch_supply_info(checksum_addr)
        owner, is_renounced = await self.detector.fetch_owner_info(checksum_addr)
        is_paused, paused_getter = await self.detector.fetch_paused_state(checksum_addr)
        getter_price_wei, price_getter_name = await self.detector.fetch_getter_mint_price(checksum_addr)
        royalty_receiver, royalty_bps = await self.detector.fetch_royalty_info(
            checksum_addr, token_ids=observed_token_ids
        )
        token_uri, contract_uri, is_revealed, reveal_reason = await self.detector.fetch_uri_info(
            checksum_addr,
            standard=standard or "ERC721",
            token_ids=observed_token_ids,
        )

        # 2. Proxy detection via EIP-1967 / EIP-1822 / OpenZeppelin storage slots
        is_proxy, proxy_impl, proxy_type = await self.proxy_detector.detect_proxy(checksum_addr)

        # 3. Source verification & ABI (and implementation ABI if proxy)
        is_verified, verification_status, etherscan_impl, abi = await self.fetch_verification_and_abi(checksum_addr)
        if not is_proxy and etherscan_impl:
            is_proxy = True
            proxy_impl = etherscan_impl
            proxy_type = "Explorer Verified Proxy"

        impl_abi = None
        if is_proxy and proxy_impl:
            try:
                _, _, _, impl_abi = await self.fetch_verification_and_abi(proxy_impl)
            except Exception:
                pass

        effective_abi = impl_abi or abi

        # 4. Scan ABI (or bytecode) for risky functions
        bytecode_hex: Optional[str] = None
        if not effective_abi:
            try:
                code_res = await self.rpc.eth_get_code(proxy_impl or checksum_addr)
                if isinstance(code_res, str) and len(code_res) > 10:
                    bytecode_hex = code_res
            except Exception:
                pass

        if effective_abi or bytecode_hex:
            risky_functions: Optional[Dict[str, List[str]]] = scan_abi_for_risky_functions(
                effective_abi, bytecode_hex=bytecode_hex
            )
        else:
            risky_functions = None

        # 5. Resolve Contract Deployment (deployer, creation tx, deployment block, deployment timestamp)
        deployer, deployed_tx_hash, deployed_block, deployed_timestamp = await self.resolve_contract_deployment(
            checksum_addr,
            reference_block=trigger_block_number,
            known_deployer=known_deployer,
        )

        # Persist resolved owner & deployer on the SQLite contract record so rolling stats exclude them
        if self.db is not None and hasattr(self.db, "upsert_contract") and (owner or deployer):
            try:
                from app.db import ContractRecord
                existing_rec = await self.db.get_contract(checksum_addr, chain=self.chain)
                rec = existing_rec or ContractRecord(
                    address=checksum_addr,
                    chain=self.chain,
                    standard=standard or "UNKNOWN",
                    created_at=now,
                )
                rec.chain = self.chain
                if owner and owner != "0x0000000000000000000000000000000000000000":
                    rec.owner = owner
                if deployer:
                    rec.deployer = deployer
                await self.db.upsert_contract(rec)
            except Exception:
                pass

        contract_age_seconds: Optional[int] = None
        contract_age_formatted = "unavailable"
        contract_deployment_date: Optional[str] = None
        contract_age_label: Optional[str] = None
        if deployed_timestamp is not None and deployed_timestamp > 0:
            contract_age_seconds = max(0, now - deployed_timestamp)
            contract_age_formatted = format_contract_age(contract_age_seconds)
            contract_deployment_date = format_deployment_date(deployed_timestamp)
            contract_age_label = classify_contract_age(
                contract_age_seconds, self.max_contract_age_hours
            )

        # 5b. Deployer age, tx count, and funding source (+ mixer / fresh funder wallet check)
        deployer_age_seconds: Optional[int] = None
        deployer_tx_count: Optional[int] = None
        deployer_funding_source: Optional[str] = None
        deployer_funder_address: Optional[str] = None
        deployer_funder_tx_count: Optional[int] = None
        deployer_funder_age_seconds: Optional[int] = None
        deployer_funded_from_mixer: Optional[bool] = None
        deployer_funded_from_fresh_wallet: Optional[bool] = None

        if deployer:
            try:
                tx_cnt = await self.rpc.eth_get_transaction_count(deployer)
                if isinstance(tx_cnt, int):
                    deployer_tx_count = tx_cnt
            except Exception as e:
                logger.debug("Failed getting deployer tx count: %s", e)

            first_tx_time, deployer_funding_source = await self.fetch_deployer_history(deployer)
            if first_tx_time:
                deployer_age_seconds = max(0, now - first_tx_time)

            if deployer_funding_source:
                mixer_label = detect_mixer_from_text_or_address(deployer_funding_source)
                m_funder = ETH_ADDR_RE.search(deployer_funding_source)
                if m_funder:
                    deployer_funder_address = m_funder.group(0)
                    if not mixer_label:
                        mixer_label = detect_mixer_from_text_or_address(deployer_funder_address)

                if mixer_label:
                    deployer_funded_from_mixer = True
                    deployer_funded_from_fresh_wallet = False
                elif deployer_funder_address:
                    deployer_funded_from_mixer = False
                    try:
                        f_cnt = await self.rpc.eth_get_transaction_count(deployer_funder_address)
                        if isinstance(f_cnt, int):
                            deployer_funder_tx_count = f_cnt
                    except Exception:
                        pass

                    try:
                        f_first_ts, _ = await self.fetch_deployer_history(deployer_funder_address)
                        if f_first_ts:
                            deployer_funder_age_seconds = max(0, now - f_first_ts)
                    except Exception:
                        pass

                    if deployer_funder_age_seconds is not None and deployer_funder_age_seconds < 7 * 86400:
                        deployer_funded_from_fresh_wallet = True
                    elif deployer_funder_tx_count is not None and deployer_funder_tx_count <= 3:
                        deployer_funded_from_fresh_wallet = True
                    elif deployer_funder_age_seconds is not None or deployer_funder_tx_count is not None:
                        deployer_funded_from_fresh_wallet = False

        if deployer_age_seconds is not None:
            age_formatted = format_duration(deployer_age_seconds)
        else:
            age_formatted = "unavailable"

        # 6. Mint price (tx value + getter) & mint function name
        tx_price_wei, mint_fn_name = await self.fetch_mint_tx_insights(
            checksum_addr, abi=effective_abi, trigger_tx_hash=trigger_tx_hash
        )
        price_parts = []
        if tx_price_wei is not None:
            price_parts.append(f"{format_eth_wei(tx_price_wei, self.native_token_symbol, self.native_token_decimals)} (tx)")
        if getter_price_wei is not None:
            price_parts.append(f"{format_eth_wei(getter_price_wei, self.native_token_symbol, self.native_token_decimals)} ({price_getter_name})")
        mint_price_formatted = " | ".join(price_parts) if price_parts else None

        # 7. Top-5 minter concentration & Owner/Deployer self-mint stats
        top_minters, top5_pct = await self.fetch_top_minters_with_fallback(
            checksum_addr, known_total_supply=max_supply or total_supply
        )

        self_mints = 0
        self_mint_pct: Optional[float] = None
        if self.db is not None and hasattr(self.db, "get_self_mint_stats"):
            try:
                sm_cnt, sm_tot, sm_pct = await self.db.get_self_mint_stats(
                    checksum_addr, owner=owner, deployer=deployer, chain=self.chain
                )
                self_mints = sm_cnt
                if sm_tot > 0:
                    self_mint_pct = sm_pct
            except Exception as e:
                logger.debug("Failed computing self_mint_stats: %s", e)

        zero_addr = "0x0000000000000000000000000000000000000000"
        owner_deployer_set = {
            a.strip().lower()
            for a in (owner, deployer)
            if isinstance(a, str) and a.strip() and a.strip().lower() != zero_addr
        }
        owner_is_top_minter: Optional[bool] = None
        if top_minters and owner_deployer_set:
            top1_addr = str(top_minters[0].get("address", "")).strip().lower()
            top1_cnt = int(top_minters[0].get("count", 0))
            owner_is_top_minter = (top1_addr in owner_deployer_set) or (self_mints > 0 and self_mints >= top1_cnt)

        # 8. Sample holder & recently minted token ID from real mint events + honeypot check
        if not sample_holder and top_minters:
            sample_holder = top_minters[0].get("address")
        if sample_token_id is None and observed_token_ids:
            sample_token_id = str(observed_token_ids[0])

        honeypot_reverted, honeypot_detail = await self.simulate_transfer_or_approval_honeypot(
            address=checksum_addr,
            standard=standard,
            sample_holder=sample_holder,
            sample_token_id=sample_token_id,
            fallback_sender=owner or deployer,
        )

        # 9. OpenSea / Market data (slug, floor, listings, socials) + contractURI/tokenURI metadata & socials
        os_slug, os_floor, os_listings, os_socials = await self.fetch_opensea_data(checksum_addr)
        if sample_token_id is None:
            os_tid = self._last_opensea_token_id.get(checksum_addr.lower())
            if os_tid is not None:
                sample_token_id = str(os_tid)
        os_verified_contract = self._last_opensea_verified_contract.get(checksum_addr.lower())

        uri_call_statuses = getattr(self.detector, "last_uri_statuses", {}).get(checksum_addr.lower()) or {}
        meta_res = await self.resolve_metadata_and_socials(
            contract_uri=contract_uri,
            token_uri=token_uri,
            sample_token_id=sample_token_id,
            contract_uri_call_status=uri_call_statuses.get("contract_uri_status"),
            contract_uri_call_error=uri_call_statuses.get("contract_uri_error"),
            token_uri_call_status=uri_call_statuses.get("token_uri_status"),
            token_uri_call_error=uri_call_statuses.get("token_uri_error"),
            as_of_timestamp=now,
        )

        metadata_socials: Dict[str, str] = dict(meta_res.get("socials") or {})
        social_sources: Dict[str, str] = dict(meta_res.get("social_sources") or {})
        merged_socials: Dict[str, str] = dict(metadata_socials)
        for k, v in os_socials.items():
            if v and k not in merged_socials:
                merged_socials[k] = v
                social_sources[k] = "via OpenSea"

        c_uri_status = meta_res.get("contract_uri_status")
        c_uri_error = meta_res.get("contract_uri_error")
        t_uri_status = meta_res.get("token_uri_status")
        t_uri_error = meta_res.get("token_uri_error")

        # Distinguish missing-data reason: "no links in metadata", "fetch failed", or "not implemented"
        if (
            c_uri_status in ("ok", "no links in metadata")
            or t_uri_status in ("ok", "no links in metadata")
            or bool(os_slug)
        ):
            social_missing_reason = "no links in metadata"
        elif c_uri_status == "fetch failed" or t_uri_status == "fetch failed":
            social_missing_reason = "fetch failed"
        else:
            social_missing_reason = "not implemented"

        # Project footprint check: True if contractURI, tokenURI metadata, or OpenSea data is present
        has_contract_uri_meta = bool(contract_uri) and c_uri_status in ("ok", "no links in metadata")
        has_token_uri_meta = bool(token_uri) and t_uri_status in ("ok", "no links in metadata")
        has_opensea_data = bool(os_slug) or bool(os_socials) or bool(os_floor)
        if has_contract_uri_meta or has_token_uri_meta or has_opensea_data:
            has_project_footprint: Optional[bool] = True
        elif (
            contract_uri is None
            and token_uri is None
            and c_uri_status == "fetch failed"
            and t_uri_status == "fetch failed"
        ):
            # Both on-chain eth_calls failed due to RPC network outage -> cannot check
            has_project_footprint = None
        else:
            has_project_footprint = False

        eff_collection_name = name or meta_res.get("name")

        # 10. Resolve trigger block / tx hash from Explorer if not already provided
        eff_block = trigger_block_number
        eff_tx = trigger_tx_hash
        if eff_block is None or not eff_tx:
            try:
                latest_blk, latest_tx = await self.explorer.fetch_latest_contract_tx(checksum_addr)
                if eff_block is None and latest_blk is not None:
                    eff_block = latest_blk
                if not eff_tx and latest_tx:
                    eff_tx = latest_tx
            except Exception:
                pass

        # 10b. Quality Score inputs (mature minters, contract/sybil share, total ETH spent, clustered minters)
        q_metrics = await self.compute_minter_quality_metrics(
            address=checksum_addr,
            owner=owner,
            deployer=deployer,
            as_of_timestamp=now,
            tx_price_wei=tx_price_wei,
            top_minters=top_minters,
        )

        # 10c. Watched wallets & Deployer reputation
        watched_minted: List[str] = []
        if self.db is not None and hasattr(self.db, "get_watched_minters_for_contract"):
            try:
                watched_minted = await self.db.get_watched_minters_for_contract(checksum_addr, chain=self.chain)
            except Exception:
                watched_minted = []

        owner_held_pct: Optional[float] = self_mint_pct
        if owner_held_pct is None and top_minters and owner_deployer_set:
            owner_pct_sum = sum(
                float(tm.get("pct", 0.0) or 0.0)
                for tm in top_minters
                if str(tm.get("address", "")).strip().lower() in owner_deployer_set
            )
            if owner_pct_sum > 0:
                owner_held_pct = round(owner_pct_sum, 1)

        dep_rep = await self.resolve_deployer_reputation(
            deployer=deployer,
            contract_address=checksum_addr,
            total_supply=total_supply,
            max_supply=max_supply,
            owner_held_pct=owner_held_pct,
            as_of_timestamp=now,
        )

        os_vol_24h = self._last_opensea_volume_24h.get(checksum_addr.lower()) if os_slug else None
        os_num_owners = self._last_opensea_num_owners.get(checksum_addr.lower()) if os_slug else None

        # 10d. Bytecode Template Matching
        tmpl_res = await self.fetch_and_match_bytecode_template(checksum_addr)

        # 10e. Mint Simulation via read-only eth_call
        observed_inp = self._last_mint_tx_input.get(checksum_addr.lower())
        sim_res = await self.simulate_mint(
            address=checksum_addr,
            mint_function_name=mint_fn_name,
            tx_price_wei=tx_price_wei or getter_price_wei,
            observed_input_data=observed_inp,
            abi=effective_abi,
        )

        # 10f. Cross-Chain Deployers
        cross_dep_contracts, cross_dep_status = await self.resolve_cross_chain_deployers(
            deployer=deployer,
            contract_address=checksum_addr,
            deployed_timestamp=deployed_timestamp,
        )

        # 10g. Funding Clusters Detection
        funding_clusters, funding_clusters_status = await self.resolve_funding_clusters(
            contract_address=checksum_addr,
            deployer=deployer,
            deployer_funding_source=deployer_funding_source,
            minter_funding_pairs=q_metrics.get("minter_funding_pairs"),
        )

        # 10h. Link Resolution (Socials, Mint Link, Marketplaces with Safety & SSRF Checks)
        resolved_links_dict = None
        if hasattr(self, "link_resolver"):
            try:
                links_obj = await self.link_resolver.resolve_all_links(
                    contract_address=checksum_addr,
                    chain=self.chain,
                    chain_id=self.chain_id,
                    explorer_url=self.explorer_base_url,
                    metadata_socials=merged_socials,
                    social_sources=social_sources,
                    opensea_slug=os_slug,
                    opensea_chain_slug=self.opensea_chain_slug,
                    real_token_id=sample_token_id,
                    as_of_timestamp=now,
                    force_refresh=force_refresh,
                    explorer_family=self.explorer_family,
                )
                resolved_links_dict = links_obj.to_dict()
                for sk, slink in links_obj.socials.items():
                    if slink.url and sk not in merged_socials:
                        merged_socials[sk] = slink.url
                        social_sources[sk] = slink.source
            except Exception as e:
                logger.debug("Link resolution error for %s: %s", checksum_addr, e)

        result = EnrichmentResult(
            contract_address=checksum_addr,
            chain=self.chain,
            chain_name=self.chain_name,
            chain_id=self.chain_id,
            native_token_symbol=self.native_token_symbol,
            native_token_decimals=self.native_token_decimals,
            explorer_name=self.explorer_name,
            explorer_base_url=self.explorer_base_url,
            explorer_family=self.explorer_family,
            explorer_api_type=self.explorer_api_type,
            explorer_url=self.explorer_base_url,
            explorer_type=self.explorer_type,
            opensea_chain_slug=self.opensea_chain_slug,
            trigger_block_number=eff_block,
            trigger_tx_hash=eff_tx,
            contract_deployed_block=deployed_block,
            contract_deployed_timestamp=deployed_timestamp,
            contract_deployed_tx_hash=deployed_tx_hash,
            contract_age_seconds=contract_age_seconds,
            contract_age_formatted=contract_age_formatted,
            contract_deployment_date=contract_deployment_date,
            contract_age_label=contract_age_label,
            deployer=deployer,
            deployer_age_seconds=deployer_age_seconds,
            deployer_age_formatted=age_formatted,
            deployer_tx_count=deployer_tx_count,
            is_source_verified=is_verified,
            verification_status=verification_status,
            is_proxy=is_proxy,
            proxy_type=proxy_type,
            proxy_implementation=proxy_impl,
            collection_name=eff_collection_name,
            symbol=symbol,
            standard=standard,
            total_supply=total_supply,
            max_supply=max_supply,
            max_supply_source=max_supply_getter,
            owner=owner,
            is_ownership_renounced=is_renounced,
            is_paused=is_paused,
            paused_source=paused_getter,
            mint_price_formatted=mint_price_formatted,
            mint_function_name=mint_fn_name,
            royalty_receiver=royalty_receiver,
            royalty_bps=royalty_bps,
            token_uri=token_uri,
            contract_uri=contract_uri,
            contract_uri_status=c_uri_status,
            contract_uri_error=c_uri_error,
            token_uri_status=t_uri_status,
            token_uri_error=t_uri_error,
            metadata_name=meta_res.get("name"),
            metadata_description=meta_res.get("description"),
            metadata_image=meta_res.get("image"),
            metadata_external_link=meta_res.get("external_link"),
            is_revealed=is_revealed,
            reveal_status_text=reveal_reason,
            deployer_funding_source=deployer_funding_source,
            deployer_funder_address=deployer_funder_address,
            deployer_funder_tx_count=deployer_funder_tx_count,
            deployer_funder_age_seconds=deployer_funder_age_seconds,
            deployer_funded_from_mixer=deployer_funded_from_mixer,
            deployer_funded_from_fresh_wallet=deployer_funded_from_fresh_wallet,
            abi_available=bool(effective_abi),
            risky_functions=risky_functions,
            honeypot_sim_reverted=honeypot_reverted,
            honeypot_sim_detail=honeypot_detail,
            top_minters=top_minters,
            top5_concentration_pct=top5_pct,
            mints_per_minute=rolling_mints_per_minute,
            self_mints=self_mints,
            self_mint_pct=self_mint_pct,
            owner_is_top_minter=owner_is_top_minter,
            recent_token_id=sample_token_id,
            opensea_slug=os_slug,
            opensea_collection_contract=os_verified_contract,
            opensea_floor=os_floor,
            opensea_listings=os_listings,
            opensea_volume_24h=os_vol_24h,
            opensea_num_owners=os_num_owners,
            opensea_socials=merged_socials,
            metadata_socials=metadata_socials,
            social_sources=social_sources,
            social_missing_reason=social_missing_reason,
            has_project_footprint=has_project_footprint,
            mature_minter_share_pct=q_metrics.get("mature_minter_share_pct"),
            mature_minters_checked=q_metrics.get("mature_minters_checked"),
            sybil_or_contract_mint_share_pct=q_metrics.get("sybil_or_contract_mint_share_pct"),
            total_eth_spent_non_owner=q_metrics.get("total_eth_spent_non_owner"),
            clustered_unique_minters=q_metrics.get("clustered_unique_minters"),
            watched_wallets_minted=watched_minted,
            deployer_contracts_deployed=dep_rep.get("contracts_deployed"),
            deployer_reached_90pct_minted=dep_rep.get("reached_90pct_minted"),
            deployer_owner_held_above_50pct=dep_rep.get("owner_held_above_50pct"),
            owner_held_pct=owner_held_pct,
            runtime_bytecode_hash=tmpl_res.get("runtime_bytecode_hash"),
            stripped_bytecode_hash=tmpl_res.get("stripped_bytecode_hash"),
            template_label=tmpl_res.get("template_label"),
            template_risk_flag=tmpl_res.get("template_risk_flag"),
            template_match_count=tmpl_res.get("template_match_count", 0),
            simulation_status=sim_res.get("status", "not_checked"),
            simulation_revert_reason=sim_res.get("revert_reason"),
            simulation_classification=sim_res.get("classification"),
            simulation_tested_function=sim_res.get("tested_function"),
            cross_chain_deployer_contracts=cross_dep_contracts,
            cross_chain_deployer_status=cross_dep_status,
            funding_clusters_detected=funding_clusters,
            funding_clusters_status=funding_clusters_status,
            resolved_links=resolved_links_dict,
        )

        # 11. Save to SQLite Cache
        if self.db is not None:
            try:
                await self.db.set_cached_enrichment(
                    checksum_addr, result.to_dict(), updated_at=now, chain=self.chain
                )
            except Exception as e:
                logger.debug("Failed writing enrichment cache for %s: %s", checksum_addr, e)

        return result

    async def compute_minter_quality_metrics(
        self,
        address: str,
        owner: Optional[str],
        deployer: Optional[str],
        as_of_timestamp: int,
        tx_price_wei: Optional[int] = None,
        top_minters: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Compute real on-chain/explorer Quality Score inputs for non-owner minters:
          - mature_minter_share_pct: share of checked minters with wallet age > 30 days and nonce > 5
          - sybil_or_contract_mint_share_pct: share of mints from contracts or repeated by the same funder
          - total_eth_spent_non_owner: total ETH (or native token) spent by non-owner minters
          - clustered_unique_minters: real unique minters after funding clustering
        Any input that cannot be loaded from real RPC/explorer data is returned as None ('not checked').
        """
        sample_minters: List[Dict[str, Any]] = []
        base_unique_minters: int = 0
        total_non_owner_qty: int = 0

        if self.db is not None:
            if hasattr(self.db, "get_non_owner_minters_sample"):
                try:
                    sample_minters = await self.db.get_non_owner_minters_sample(
                        address, owner=owner, deployer=deployer, limit=8, chain=self.chain
                    )
                except Exception:
                    sample_minters = []
            if hasattr(self.db, "get_rolling_stats"):
                try:
                    rstats = await self.db.get_rolling_stats(
                        address,
                        window_seconds=86400 * 7,
                        as_of_timestamp=as_of_timestamp,
                        chain=self.chain,
                        excluded_addresses=[x for x in (owner, deployer) if x],
                    )
                    base_unique_minters = int(rstats.unique_minters or 0)
                    total_non_owner_qty = int(rstats.total_mints or 0)
                except Exception:
                    pass

        if not sample_minters and top_minters:
            zero_addr = "0x0000000000000000000000000000000000000000"
            excluded = {zero_addr, ""}
            for cand in (owner, deployer):
                if cand:
                    excluded.add(cand.strip().lower())
            for tm in top_minters:
                m_addr = str(tm.get("address", "")).strip().lower()
                if m_addr and m_addr not in excluded:
                    sample_minters.append(
                        {
                            "address": m_addr,
                            "quantity": int(tm.get("count", 1) or 1),
                            "tx_hash": "",
                        }
                    )
            if base_unique_minters <= 0:
                base_unique_minters = len(sample_minters)
            if total_non_owner_qty <= 0:
                total_non_owner_qty = sum(int(m["quantity"]) for m in sample_minters)

        mature_count = 0
        checked_mature_count = 0
        funder_map: Dict[str, List[Dict[str, Any]]] = {}
        contract_minter_addrs: set = set()
        history_loaded_count = 0

        for m in sample_minters[:6]:
            m_addr = m["address"]
            first_ts: Optional[int] = None
            funder_str: Optional[str] = None
            try:
                first_ts, funder_str = await self.fetch_deployer_history(m_addr)
            except Exception:
                first_ts, funder_str = None, None

            nonce_val: Optional[int] = None
            try:
                raw_nonce = await self.rpc.eth_get_transaction_count(m_addr)
                if isinstance(raw_nonce, int):
                    nonce_val = raw_nonce
            except Exception:
                nonce_val = None

            if first_ts is not None and first_ts > 0 and nonce_val is not None:
                checked_mature_count += 1
                wallet_age_days = max(0.0, (as_of_timestamp - first_ts) / 86400.0)
                if wallet_age_days > 30.0 and nonce_val > 5:
                    mature_count += 1

            if first_ts is not None or funder_str is not None:
                history_loaded_count += 1
                funder_addr: Optional[str] = None
                if funder_str:
                    m_f = ETH_ADDR_RE.search(funder_str)
                    if m_f:
                        funder_addr = m_f.group(0).lower()
                    elif funder_str.strip().lower() == "contract":
                        contract_minter_addrs.add(m_addr)
                if funder_addr:
                    funder_map.setdefault(funder_addr, []).append(m)

                # Check if minter is a smart contract
                try:
                    code = await self.rpc.eth_get_code(m_addr)
                    if (
                        isinstance(code, str)
                        and len(code) > 2
                        and code not in ("0x", "0x0")
                        and (code != "0x60806040" or nonce_val == 0)
                    ):
                        contract_minter_addrs.add(m_addr)
                except Exception:
                    pass

        mature_minter_share_pct: Optional[float] = None
        if checked_mature_count > 0:
            mature_minter_share_pct = round((mature_count / checked_mature_count) * 100.0, 1)

        sybil_or_contract_mint_share_pct: Optional[float] = None
        clustered_unique_minters: Optional[int] = None
        if history_loaded_count > 0 and sample_minters:
            repeated_funder_addrs: set = set()
            duplicate_funder_wallets = 0
            for f_addr, funded_list in funder_map.items():
                if len(funded_list) >= 2:
                    duplicate_funder_wallets += len(funded_list) - 1
                    for item in funded_list:
                        repeated_funder_addrs.add(item["address"])

            flagged_addrs = contract_minter_addrs | repeated_funder_addrs
            sampled_qty = sum(int(m["quantity"]) for m in sample_minters[:6]) or 1
            flagged_qty = sum(
                int(m["quantity"]) for m in sample_minters[:6] if m["address"] in flagged_addrs
            )
            sybil_or_contract_mint_share_pct = round((flagged_qty / sampled_qty) * 100.0, 1)
            eff_base_unique = max(base_unique_minters, len(sample_minters))
            clustered_unique_minters = max(1, eff_base_unique - duplicate_funder_wallets)

        # Total native currency spent by non-owner minters
        total_eth_spent_non_owner: Optional[float] = None
        native_div = float(10 ** self.native_token_decimals)
        if tx_price_wei is not None and total_non_owner_qty > 0:
            total_eth_spent_non_owner = round((int(tx_price_wei) * total_non_owner_qty) / native_div, 6)
        elif sample_minters:
            fetched_wei_sum = 0
            fetched_tx_count = 0
            for m in sample_minters[:5]:
                txh = m.get("tx_hash")
                if not txh:
                    continue
                try:
                    tx_obj = await self.rpc.eth_get_transaction_by_hash(txh)
                    if isinstance(tx_obj, dict) and tx_obj.get("value") is not None:
                        raw_v = tx_obj["value"]
                        val_wei = int(raw_v, 16) if isinstance(raw_v, str) and raw_v.startswith("0x") else int(raw_v)
                        fetched_wei_sum += val_wei
                        fetched_tx_count += 1
                except Exception:
                    continue
            if fetched_tx_count > 0:
                total_eth_spent_non_owner = round(fetched_wei_sum / native_div, 6)

        minter_funding_pairs: List[Tuple[str, str]] = []
        for f_addr, m_list in funder_map.items():
            for item in m_list:
                minter_funding_pairs.append((item.get("address", ""), f_addr))

        return {
            "mature_minter_share_pct": mature_minter_share_pct,
            "mature_minters_checked": checked_mature_count if checked_mature_count > 0 else None,
            "sybil_or_contract_mint_share_pct": sybil_or_contract_mint_share_pct,
            "total_eth_spent_non_owner": total_eth_spent_non_owner,
            "clustered_unique_minters": clustered_unique_minters,
            "minter_funding_pairs": minter_funding_pairs,
        }

    async def resolve_deployer_reputation(
        self,
        deployer: Optional[str],
        contract_address: str,
        total_supply: Optional[int],
        max_supply: Optional[int],
        owner_held_pct: Optional[float],
        as_of_timestamp: int,
    ) -> Dict[str, Optional[int]]:
        """
        Track and resolve deployer reputation:
          - contracts_deployed
          - reached_90pct_minted
          - owner_held_above_50pct
        Uses real explorer creation history and SQLite `deployer_reputation` / `deployer_contracts`.
        """
        if not deployer:
            return {
                "contracts_deployed": None,
                "reached_90pct_minted": None,
                "owner_held_above_50pct": None,
            }

        rep: Optional[Dict[str, Any]] = None
        if self.db is not None and hasattr(self.db, "record_deployer_contract_metrics"):
            try:
                rep = await self.db.record_deployer_contract_metrics(
                    deployer_address=deployer,
                    contract_address=contract_address,
                    total_supply=total_supply,
                    max_supply=max_supply,
                    owner_held_pct=owner_held_pct,
                    chain=self.chain,
                    updated_at=as_of_timestamp,
                )
            except Exception as e:
                logger.debug("Failed recording deployer contract metrics: %s", e)

        explorer_created: List[str] = []
        if hasattr(self.explorer, "fetch_deployer_created_contracts"):
            try:
                res = await self.explorer.fetch_deployer_created_contracts(deployer)
                if isinstance(res, list):
                    explorer_created = [str(x) for x in res if x]
            except Exception:
                explorer_created = []

        if explorer_created and self.db is not None and hasattr(self.db, "upsert_deployer_reputation"):
            current_dep = int((rep or {}).get("contracts_deployed") or 1)
            current_90 = int((rep or {}).get("reached_90pct_minted") or 0)
            current_50 = int((rep or {}).get("owner_held_above_50pct") or 0)
            all_addrs = {a.lower() for a in explorer_created} | {contract_address.lower()}
            if len(all_addrs) > current_dep:
                try:
                    rep = await self.db.upsert_deployer_reputation(
                        deployer_address=deployer,
                        contracts_deployed=len(all_addrs),
                        reached_90pct_minted=current_90,
                        owner_held_above_50pct=current_50,
                        chain=self.chain,
                        updated_at=as_of_timestamp,
                    )
                except Exception:
                    pass

        if rep:
            return {
                "contracts_deployed": int(rep.get("contracts_deployed", 1)),
                "reached_90pct_minted": int(rep.get("reached_90pct_minted", 0)),
                "owner_held_above_50pct": int(rep.get("owner_held_above_50pct", 0)),
            }

        # Fallback when DB is not attached
        pct_minted = (
            (total_supply / max_supply) * 100.0
            if (total_supply is not None and max_supply is not None and max_supply > 0)
            else None
        )
        return {
            "contracts_deployed": max(1, len(explorer_created)),
            "reached_90pct_minted": 1 if (pct_minted is not None and pct_minted >= 90.0) else 0,
            "owner_held_above_50pct": 1 if (owner_held_pct is not None and owner_held_pct > 50.0) else 0,
        }

    async def collect_outcome_snapshot(
        self,
        address: str,
        as_of_timestamp: Optional[int] = None,
        interval_label: Optional[str] = None,
        alerted_at: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Fetch real outcome metrics for a contract at 1h, 24h, or 7d post-alert:
          - holder_count
          - unique_holders
          - pct_max_supply_minted (if known)
          - floor_price (if indexed on OpenSea)
          - listing_count (if indexed on OpenSea)
          - volume_24h (if indexed on OpenSea)
        Stores 'unavailable' for any field whose source fails or is not indexed.
        """
        checksum_addr = to_checksum_address(address)
        addr_low = checksum_addr.lower()

        total_supply: Optional[int] = None
        max_supply: Optional[int] = None
        try:
            total_supply, max_supply, _ = await self.detector.fetch_supply_info(checksum_addr)
        except Exception:
            total_supply, max_supply = None, None

        pct_max_supply_minted: str = "unavailable"
        if total_supply is not None and max_supply is not None and max_supply > 0 and total_supply >= 0:
            pct_val = round((total_supply / max_supply) * 100.0, 1)
            pct_max_supply_minted = f"{pct_val:.1f}%"

        os_slug, os_floor, os_listings, _ = await self.fetch_opensea_data(checksum_addr)
        os_vol_24h = self._last_opensea_volume_24h.get(addr_low) if os_slug else None
        os_num_owners = self._last_opensea_num_owners.get(addr_low) if os_slug else None

        exp_holder_cnt: Optional[int] = None
        exp_unique_holders: Optional[int] = None
        if hasattr(self.explorer, "fetch_token_holder_counts"):
            try:
                res_holders = await self.explorer.fetch_token_holder_counts(checksum_addr)
                if isinstance(res_holders, tuple) and len(res_holders) == 2:
                    exp_holder_cnt, exp_unique_holders = res_holders
            except Exception:
                exp_holder_cnt, exp_unique_holders = None, None

        unique_holders_val = exp_unique_holders if exp_unique_holders is not None else os_num_owners
        holder_count_val = exp_holder_cnt if exp_holder_cnt is not None else unique_holders_val

        return {
            "holder_count": str(holder_count_val) if isinstance(holder_count_val, int) else "unavailable",
            "unique_holders": str(unique_holders_val) if isinstance(unique_holders_val, int) else "unavailable",
            "pct_max_supply_minted": pct_max_supply_minted,
            "floor_price": os_floor if (os_slug and os_floor) else "unavailable",
            "listing_count": str(os_listings) if (os_slug and isinstance(os_listings, int)) else "unavailable",
            "volume_24h": os_vol_24h if (os_slug and os_vol_24h) else "unavailable",
        }



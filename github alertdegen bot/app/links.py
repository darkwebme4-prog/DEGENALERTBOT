"""
Comprehensive Link Resolution & Safety Engine for NFT Alerts.

Features:
1. Socials: collects website, X, Discord, and Telegram from contractURI, token metadata,
   OpenSea collection API, and optionally from project website HTML with source tracking.
2. Mint Link: uses project's mint page if found, otherwise checks mint platforms (Zora,
   Manifold, mint.fun, Highlight) verifying existence, and falls back to explorer's Write Contract tab.
3. Marketplaces: OpenSea (verified slug or verified minted token ID link), Magic Eden,
   Blur (Ethereum only), and chain-specific marketplaces, each included only if confirmed to resolve.
4. Safety: shows domain, labels 'from contract metadata, unverified', flags URL shorteners,
   flags lookalike/typosquatting domains, and flags domains registered in the last 30 days via RDAP.
   Enforces SSRF protection: blocks private, loopback, and link-local IPs; limits responses to 1 MB
   with short timeout and max 3 redirects; never executes scripts.
5. SQLite caching and formatting with 'No public mint page or socials found' fallback.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
import ipaddress
import json
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSRF Protection & Safe HTTP Fetcher
# ---------------------------------------------------------------------------

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Unspecified
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (Cloud metadata 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
    ipaddress.ip_network("2002::/16"),          # 6to4
]


def is_safe_ip(ip_str: str) -> bool:
    """Return True if ip_str is a routable public Internet IP, False if private/loopback/link-local/reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False
        for net in BLOCKED_IP_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def validate_url_host(url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate that url has http/https scheme and its resolved DNS IPs are safe public IPs.
    Returns (is_safe, domain, error_reason).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, None, f"Invalid URL: {e}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, None, f"Unsupported scheme: {parsed.scheme}"

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, None, "Missing hostname"

    # Block direct IP literals if unsafe
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        if not is_safe_ip(str(ip)):
            return False, hostname, f"Blocked unsafe direct IP: {hostname}"
        return True, hostname, None
    except ValueError:
        pass

    # Resolve via DNS and check all returned IP addresses
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        if not addr_infos:
            return False, hostname, f"No DNS records found for host: {hostname}"
        for family, socktype, proto, canonname, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            if not is_safe_ip(ip_str):
                return False, hostname, f"Blocked private/loopback/link-local IP ({ip_str}) for host {hostname}"
        return True, hostname, None
    except socket.gaierror as e:
        return False, hostname, f"DNS resolution failed for {hostname}: {e}"
    except Exception as e:
        return False, hostname, f"Host validation error: {e}"


async def safe_fetch_http(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
    max_bytes: int = 1_048_576,  # 1 MB limit
    max_redirects: int = 3,
    timeout: float = 5.0,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[int], Optional[str], Optional[bytes]]:
    """
    SSRF-safe HTTP fetcher:
    - Blocks private, loopback, and link-local IPs at initial connection and on every redirect.
    - Limits response size to max_bytes (1 MB).
    - Enforces short timeouts (connect=3s, read=5s).
    - Follows at most max_redirects (3).
    - Never executes scripts.
    Returns (status_code, content_type, response_bytes).
    """
    req_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; DegenAlertBot/1.0; +https://alertbot.local)",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*",
    }
    if headers:
        req_headers.update(headers)

    current_url = url
    close_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=3.0), verify=True)
        close_client = True

    try:
        for _ in range(max_redirects + 1):
            is_safe, domain, err = validate_url_host(current_url)
            if not is_safe:
                logger.debug("safe_fetch_http blocked unsafe URL %s: %s", current_url, err)
                return None, None, None

            try:
                resp = await client.get(
                    current_url,
                    headers=req_headers,
                    follow_redirects=False,
                )
            except Exception as exc:
                logger.debug("safe_fetch_http GET failed for %s: %s", current_url, exc)
                return None, None, None

            # Handle redirects manually to re-validate destination IP
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    return resp.status_code, resp.headers.get("Content-Type"), None
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            content_type = resp.headers.get("Content-Type", "")
            raw_content = resp.content
            if len(raw_content) > max_bytes:
                raw_content = raw_content[:max_bytes]

            return resp.status_code, content_type, raw_content

        return None, None, None
    finally:
        if close_client:
            await client.aclose()


# ---------------------------------------------------------------------------
# Safety Analyzers (Shorteners, Lookalikes, RDAP Age)
# ---------------------------------------------------------------------------

KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "t.ly",
    "rb.gy",
    "bl.ink",
    "lnkd.in",
    "trib.al",
}

LEGIT_CRYPTO_DOMAINS = {
    "opensea.io": "opensea",
    "blur.io": "blur",
    "magiceden.io": "magiceden",
    "uniswap.org": "uniswap",
    "etherscan.io": "etherscan",
    "metamask.io": "metamask",
    "zora.co": "zora",
    "manifold.xyz": "manifold",
    "mint.fun": "mintfun",
    "highlight.xyz": "highlight",
    "x.com": "twitter",
    "twitter.com": "twitter",
    "discord.com": "discord",
    "discord.gg": "discord",
    "t.me": "telegram",
    "telegram.org": "telegram",
}

PROTECTED_BRANDS = [
    "opensea",
    "blur",
    "magiceden",
    "uniswap",
    "etherscan",
    "metamask",
    "zora",
    "manifold",
    "mintfun",
    "highlight",
    "twitter",
    "discord",
    "telegram",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein distance between two strings without external dependencies."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            dels = curr[j] + 1
            subs = prev[j] + (c1 != c2)
            curr.append(min(ins, dels, subs))
        prev = curr
    return prev[-1]


def is_url_shortener(domain: str) -> bool:
    """Return True if the domain is a known URL shortener service."""
    d = domain.lower().strip(".")
    return d in KNOWN_SHORTENERS or any(d.endswith("." + s) for s in KNOWN_SHORTENERS)


def is_lookalike_domain(domain: str) -> bool:
    """
    Detect typosquatting, lookalike, or phishing domains targeting popular crypto brands.
    Checks Punycode (IDN homograph) and string edit distance.
    """
    d = domain.lower().strip(".")
    for legit in LEGIT_CRYPTO_DOMAINS:
        if d == legit or d.endswith("." + legit):
            return False

    if "xn--" in d:
        return True

    parts = d.split(".")
    sld = parts[-2] if len(parts) >= 2 else parts[0]

    for brand in PROTECTED_BRANDS:
        # e.g., opensea-airdrop, blur-claim, 0pensea
        if brand in sld and sld != brand:
            return True
        dist = levenshtein_distance(sld, brand)
        if 1 <= dist <= 2 and len(sld) >= len(brand) - 1:
            return True

    return False


async def check_domain_registration_age(
    domain: str,
    client: Optional[httpx.AsyncClient] = None,
    db: Optional[Any] = None,
    as_of_timestamp: Optional[int] = None,
) -> Tuple[Optional[int], Optional[str]]:
    """
    Check domain registration age via RDAP protocol with SQLite caching.
    Returns (registration_timestamp, safety_flag).
    If domain was registered within the last 30 days, returns safety flag:
      '⚠️ newly registered domain (<30d)'
    """
    dom = domain.lower().strip(".")
    now = as_of_timestamp if as_of_timestamp is not None else int(time.time())

    # 1. Check SQLite cache first
    if db is not None and hasattr(db, "get_cached_domain_rdap"):
        cached = await db.get_cached_domain_rdap(dom, ttl_seconds=86400 * 7, as_of_timestamp=now)
        if cached:
            reg_ts = cached.get("registration_timestamp")
            if reg_ts is not None:
                age_days = (now - reg_ts) / 86400.0
                if 0 <= age_days < 30.0:
                    return reg_ts, f"⚠️ newly registered domain (<30d, {int(age_days)}d ago)"
                return reg_ts, None
            return None, None

    # Skip RDAP lookup for major legitimate public platforms
    if any(dom == legit or dom.endswith("." + legit) for legit in LEGIT_CRYPTO_DOMAINS):
        return None, None

    # 2. Query public RDAP service with SSRF protection
    rdap_url = f"https://rdap.org/domain/{dom}"
    status, c_type, raw_bytes = await safe_fetch_http(
        rdap_url,
        client=client,
        max_bytes=256_000,
        timeout=4.0,
    )

    reg_timestamp: Optional[int] = None
    if status == 200 and raw_bytes:
        try:
            data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            events = data.get("events") or []
            for ev in events:
                if isinstance(ev, dict) and ev.get("eventAction") == "registration":
                    ev_date_str = ev.get("eventDate")
                    if ev_date_str:
                        # Parse ISO 8601 string
                        clean_date = ev_date_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_date)
                        reg_timestamp = int(dt.timestamp())
                        break
        except Exception as e:
            logger.debug("RDAP JSON parse error for %s: %s", dom, e)

    # 3. Cache result in SQLite
    if db is not None and hasattr(db, "set_cached_domain_rdap"):
        await db.set_cached_domain_rdap(
            domain=dom,
            registration_timestamp=reg_timestamp,
            status="ok" if reg_timestamp else "unavailable",
            timestamp=now,
        )

    if reg_timestamp is not None:
        age_days = (now - reg_timestamp) / 86400.0
        if 0 <= age_days < 30.0:
            return reg_timestamp, f"⚠️ newly registered domain (<30d, {int(age_days)}d ago)"

    return reg_timestamp, None


# ---------------------------------------------------------------------------
# HTML Parser for Website Socials & Mint Pages
# ---------------------------------------------------------------------------

class WebPageSocialAndMintExtractor(HTMLParser):
    """
    Zero-dependency HTML Parser to extract Twitter/X, Discord, Telegram, and Mint links
    from a project website without executing any scripts.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.twitter: Optional[str] = None
        self.discord: Optional[str] = None
        self.telegram: Optional[str] = None
        self.mint_links: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        if tag.lower() == "a":
            attr_dict = {k.lower(): (v or "") for k, v in attrs}
            href = attr_dict.get("href")
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                return

            full_url = urllib.parse.urljoin(self.base_url, href.strip())
            low_url = full_url.lower()

            # Socials
            if not self.twitter and ("twitter.com/" in low_url or "x.com/" in low_url):
                # Clean handle
                m = re.search(r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,30})", full_url)
                if m and m.group(1).lower() not in ("share", "intent", "search", "home"):
                    self.twitter = f"https://x.com/{m.group(1)}"

            if not self.discord and ("discord.gg/" in low_url or "discord.com/invite/" in low_url):
                self.discord = full_url

            if not self.telegram and ("t.me/" in low_url or "telegram.me/" in low_url):
                self.telegram = full_url

            # Mint page candidates
            parsed_full = urllib.parse.urlparse(full_url)
            parsed_base = urllib.parse.urlparse(self.base_url)
            # Only consider same-domain links for project mint page
            if parsed_full.netloc == parsed_base.netloc:
                path = parsed_full.path.lower()
                if any(k in path for k in ("/mint", "mint.html", "minting", "/claim")):
                    if full_url not in self.mint_links:
                        self.mint_links.append(full_url)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ResolvedLink:
    url: str
    domain: str
    title: str
    source: str  # "from contract metadata, unverified", "via OpenSea", "via website HTML", "verified platform"
    safety_flags: List[str] = field(default_factory=list)
    is_verified: bool = False
    http_status: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "title": self.title,
            "source": self.source,
            "safety_flags": self.safety_flags,
            "is_verified": self.is_verified,
            "http_status": self.http_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResolvedLink":
        return cls(
            url=data.get("url", ""),
            domain=data.get("domain", ""),
            title=data.get("title", ""),
            source=data.get("source", ""),
            safety_flags=list(data.get("safety_flags") or []),
            is_verified=bool(data.get("is_verified", False)),
            http_status=data.get("http_status"),
        )


@dataclass
class ResolvedLinksResult:
    mint_link: Optional[ResolvedLink] = None
    mint_fallback_link: Optional[ResolvedLink] = None  # Explorer Write Contract tab
    marketplaces: List[ResolvedLink] = field(default_factory=list)
    socials: Dict[str, ResolvedLink] = field(default_factory=dict)
    has_public_mint_or_socials: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mint_link": self.mint_link.to_dict() if self.mint_link else None,
            "mint_fallback_link": self.mint_fallback_link.to_dict() if self.mint_fallback_link else None,
            "marketplaces": [m.to_dict() for m in self.marketplaces],
            "socials": {k: v.to_dict() for k, v in self.socials.items()},
            "has_public_mint_or_socials": self.has_public_mint_or_socials,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResolvedLinksResult":
        return cls(
            mint_link=ResolvedLink.from_dict(data["mint_link"]) if data.get("mint_link") else None,
            mint_fallback_link=ResolvedLink.from_dict(data["mint_fallback_link"]) if data.get("mint_fallback_link") else None,
            marketplaces=[ResolvedLink.from_dict(m) for m in (data.get("marketplaces") or [])],
            socials={k: ResolvedLink.from_dict(v) for k, v in (data.get("socials") or {}).items()},
            has_public_mint_or_socials=bool(data.get("has_public_mint_or_socials", False)),
        )


# ---------------------------------------------------------------------------
# Link Resolver Engine
# ---------------------------------------------------------------------------

class LinkResolver:
    """
    End-to-end link resolution engine for NFT alerts:
    - Resolves and verifies socials with safety checks (shorteners, lookalikes, domain age).
    - Checks mint platforms and project mint pages with live resolution.
    - Resolves marketplaces (OpenSea, Magic Eden, Blur, chain-specific) only if confirmed.
    - Caches all lookups in SQLite.
    """

    def __init__(
        self,
        db: Optional[Any] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        cache_ttl_seconds: int = 1800,
    ):
        self.db = db
        self.http_client = http_client
        self.cache_ttl_seconds = cache_ttl_seconds
        self._internal_http: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self.http_client is not None and not getattr(self.http_client, "is_closed", False):
            return self.http_client
        if self._internal_http is None or self._internal_http.is_closed:
            self._internal_http = httpx.AsyncClient(
                timeout=httpx.Timeout(5.0, connect=3.0),
                headers={"User-Agent": "Mozilla/5.0 (compatible; DegenAlertBot/1.0)"},
            )
        return self._internal_http

    async def close(self):
        if self._internal_http and not self._internal_http.is_closed:
            await self._internal_http.aclose()
            self._internal_http = None

    async def analyze_url_safety(
        self,
        url: str,
        source: str,
        as_of_timestamp: Optional[int] = None,
    ) -> ResolvedLink:
        """Analyze a URL, extracting domain, unverified metadata label, and safety flags."""
        parsed = urllib.parse.urlparse(url)
        domain = (parsed.hostname or "").lower().strip()
        flags: List[str] = []

        # 1. URL Shortener flag
        if is_url_shortener(domain):
            flags.append("⚠️ URL shortener")

        # 2. Lookalike / typosquatting domain flag
        if is_lookalike_domain(domain):
            flags.append("⚠️ lookalike domain")

        # 3. Domain registration age check (< 30 days) via RDAP
        client = await self._get_client()
        _, age_flag = await check_domain_registration_age(
            domain, client=client, db=self.db, as_of_timestamp=as_of_timestamp
        )
        if age_flag:
            flags.append(age_flag)

        # Standardize source label for metadata origins
        eff_source = source
        if "metadata" in source.lower() or "contracturi" in source.lower() or "tokenuri" in source.lower():
            eff_source = "from contract metadata, unverified"

        title = domain
        return ResolvedLink(
            url=url,
            domain=domain,
            title=title,
            source=eff_source,
            safety_flags=flags,
            is_verified=source.startswith("via OpenSea") or source == "verified platform",
        )

    async def resolve_website_html_socials_and_mint(
        self,
        website_url: str,
        as_of_timestamp: Optional[int] = None,
    ) -> Tuple[Dict[str, str], Optional[str]]:
        """
        Safely fetch website HTML (1MB limit, 3 redirects max, SSRF protected, no scripts)
        and extract Twitter, Discord, Telegram, and project mint link.
        """
        client = await self._get_client()
        status, c_type, raw_bytes = await safe_fetch_http(
            website_url,
            client=client,
            max_bytes=1_048_576,
            timeout=5.0,
        )

        extracted_socials: Dict[str, str] = {}
        project_mint_page: Optional[str] = None

        if status == 200 and raw_bytes:
            try:
                html_text = raw_bytes.decode("utf-8", errors="replace")
                parser = WebPageSocialAndMintExtractor(website_url)
                parser.feed(html_text)

                if parser.twitter:
                    extracted_socials["twitter"] = parser.twitter
                if parser.discord:
                    extracted_socials["discord"] = parser.discord
                if parser.telegram:
                    extracted_socials["telegram"] = parser.telegram

                if parser.mint_links:
                    project_mint_page = parser.mint_links[0]
            except Exception as e:
                logger.debug("Failed parsing website HTML for %s: %s", website_url, e)

        return extracted_socials, project_mint_page

    async def resolve_mint_link(
        self,
        contract_address: str,
        chain: str,
        explorer_url: str,
        project_website_url: Optional[str] = None,
        candidate_mint_page: Optional[str] = None,
        opensea_slug: Optional[str] = None,
        explorer_family: Optional[str] = None,
    ) -> Tuple[Optional[ResolvedLink], Optional[ResolvedLink]]:
        """
        Determine public mint link:
        1. Project mint page if found and resolves (HTTP 200).
        2. Mint platforms (Zora, Manifold, mint.fun, Highlight, OpenSea drop) if confirmed to exist.
        3. Fallback: Explorer Write Contract tab (formatted correctly per explorer family).
        """
        addr = contract_address.lower()
        client = await self._get_client()

        fallback_link = None
        if explorer_url:
            from app.explorer import build_explorer_links
            fam = explorer_family or ("blockscout" if "blockscout" in (explorer_url or "").lower() else "etherscan")
            fallback_url = build_explorer_links(fam, explorer_url, address=contract_address)["write_contract"]
            if fallback_url:
                fallback_link = ResolvedLink(
                    url=fallback_url,
                    domain=urllib.parse.urlparse(explorer_url).netloc.lower(),
                    title="Write Contract",
                    source="explorer fallback",
                    is_verified=True,
                )

        # 1. Project's own mint page
        candidate_pages = []
        if candidate_mint_page:
            candidate_pages.append(candidate_mint_page)
        if project_website_url:
            p_clean = project_website_url.rstrip("/")
            candidate_pages.append(f"{p_clean}/mint")

        for p_url in candidate_pages:
            status, _, _ = await safe_fetch_http(p_url, client=client, timeout=4.0)
            if status == 200:
                link = await self.analyze_url_safety(p_url, source="project mint page")
                link.title = "Project Mint"
                link.http_status = 200
                return link, fallback_link

        # 2. Mint Platforms (verify URL format, chain support, and real existence)
        platform_candidates: List[Tuple[str, str, str]] = []

        # Zora (Ethereum: eth, Base: base, Optimism: oeth, Arbitrum: arb, Zora: zora)
        zora_prefixes = {
            "ethereum": "eth",
            "base": "base",
            "optimism": "oeth",
            "arbitrum": "arb",
            "zora": "zora",
        }
        if chain in zora_prefixes:
            z_pref = zora_prefixes[chain]
            platform_candidates.append(("Zora", f"https://zora.co/collect/{z_pref}:{addr}", "zora.co"))

        # mint.fun (Ethereum: ethereum, Base: base, Optimism: op, Arbitrum: arbitrum, Zora: zora)
        mintfun_slugs = {
            "ethereum": "ethereum",
            "base": "base",
            "optimism": "op",
            "arbitrum": "arbitrum",
            "zora": "zora",
        }
        if chain in mintfun_slugs:
            mf_slug = mintfun_slugs[chain]
            platform_candidates.append(("mint.fun", f"https://mint.fun/{mf_slug}/{addr}", "mint.fun"))

        # Manifold (Ethereum, Optimism, Base, Arbitrum, Polygon)
        if chain in ("ethereum", "base", "optimism", "arbitrum", "polygon"):
            platform_candidates.append(("Manifold", f"https://gallery.manifold.xyz/{addr}", "manifold.xyz"))

        # Highlight (Ethereum, Base, Optimism, Arbitrum, Polygon, Zora)
        if chain in ("ethereum", "base", "optimism", "arbitrum", "polygon", "zora"):
            platform_candidates.append(("Highlight", f"https://highlight.xyz/mint/{addr}", "highlight.xyz"))

        # Check each platform candidate via safe GET/HEAD
        for plat_name, plat_url, plat_domain in platform_candidates:
            status, _, raw_bytes = await safe_fetch_http(plat_url, client=client, timeout=4.0)
            if status == 200 and raw_bytes:
                # Confirm page is not a generic 404/not-found disguised as 200
                low_text = raw_bytes.decode("utf-8", errors="replace").lower()
                if not any(k in low_text for k in ("collection not found", "page not found", "404 not found")):
                    link = await self.analyze_url_safety(plat_url, source="verified platform")
                    link.title = plat_name
                    link.is_verified = True
                    link.http_status = 200
                    return link, fallback_link

        return None, fallback_link

    async def resolve_marketplace_links(
        self,
        contract_address: str,
        chain: str,
        chain_id: int,
        opensea_slug: Optional[str] = None,
        opensea_chain_slug: Optional[str] = None,
        real_token_id: Optional[str] = None,
    ) -> List[ResolvedLink]:
        """
        Determine marketplace links: OpenSea, Magic Eden, Blur (Ethereum only), and chain-specific marketplaces.
        Each included ONLY if confirmed to resolve for that contract.
        """
        addr = contract_address.lower()
        client = await self._get_client()
        marketplaces: List[ResolvedLink] = []

        # 1. OpenSea
        os_chain = opensea_chain_slug or chain
        if opensea_slug:
            os_url = f"https://opensea.io/collection/{opensea_slug}"
            link = await self.analyze_url_safety(os_url, source="via OpenSea")
            link.title = "OpenSea"
            link.is_verified = True
            marketplaces.append(link)
        elif real_token_id is not None and os_chain:
            # Token link built from real verified token ID
            os_token_url = f"https://opensea.io/assets/{os_chain}/{addr}/{real_token_id}"
            link = await self.analyze_url_safety(os_token_url, source="via OpenSea (token link)")
            link.title = f"OpenSea (#{real_token_id})"
            link.is_verified = True
            marketplaces.append(link)

        # 2. Magic Eden (Ethereum, Base, Polygon, Arbitrum, Monad, Sei, Berachain, ApeChain)
        me_chains = {
            "ethereum": "ethereum",
            "base": "base",
            "polygon": "polygon",
            "arbitrum": "arbitrum",
            "monad": "monad",
            "sei": "sei",
            "berachain": "berachain",
            "apechain": "apechain",
        }
        if chain in me_chains:
            me_c = me_chains[chain]
            me_url = f"https://magiceden.io/collections/{me_c}/{addr}"
            status, _, raw_bytes = await safe_fetch_http(me_url, client=client, timeout=4.0)
            if status == 200 and raw_bytes:
                low_text = raw_bytes.decode("utf-8", errors="replace").lower()
                if "collection not found" not in low_text and "404" not in low_text:
                    link = await self.analyze_url_safety(me_url, source="verified platform")
                    link.title = "Magic Eden"
                    link.is_verified = True
                    marketplaces.append(link)

        # 3. Blur (Ethereum ONLY!)
        if chain == "ethereum" or chain_id == 1:
            blur_url = f"https://blur.io/collection/{addr}"
            status, _, raw_bytes = await safe_fetch_http(blur_url, client=client, timeout=4.0)
            if status == 200 and raw_bytes:
                low_text = raw_bytes.decode("utf-8", errors="replace").lower()
                if "collection not found" not in low_text and "page not found" not in low_text:
                    link = await self.analyze_url_safety(blur_url, source="verified platform")
                    link.title = "Blur"
                    link.is_verified = True
                    marketplaces.append(link)

        # 4. Chain-Specific Marketplaces
        chain_specific: List[Tuple[str, str]] = []
        if chain == "berachain":
            chain_specific.append(("Kingdomly", f"https://kingdomly.app/collection/{addr}"))
        elif chain == "sei":
            chain_specific.append(("Pallet", f"https://pallet.exchange/collection/{addr}"))
        elif chain == "arbitrum":
            chain_specific.append(("Trove", f"https://trove.treasure.lol/collection/{addr}"))
        elif chain == "polygon":
            chain_specific.append(("Element", f"https://element.market/collections/{addr}"))

        for cs_name, cs_url in chain_specific:
            status, _, raw_bytes = await safe_fetch_http(cs_url, client=client, timeout=4.0)
            if status == 200 and raw_bytes:
                low_text = raw_bytes.decode("utf-8", errors="replace").lower()
                if "not found" not in low_text:
                    link = await self.analyze_url_safety(cs_url, source="verified platform")
                    link.title = cs_name
                    link.is_verified = True
                    marketplaces.append(link)

        return marketplaces

    async def resolve_all_links(
        self,
        contract_address: str,
        chain: str,
        chain_id: int,
        explorer_url: str,
        metadata_socials: Optional[Dict[str, str]] = None,
        social_sources: Optional[Dict[str, str]] = None,
        opensea_slug: Optional[str] = None,
        opensea_chain_slug: Optional[str] = None,
        real_token_id: Optional[str] = None,
        as_of_timestamp: Optional[int] = None,
        force_refresh: bool = False,
        explorer_family: Optional[str] = None,
    ) -> ResolvedLinksResult:
        """
        Perform complete link resolution for a contract with SQLite caching and safety checks.
        Never invents any link.
        """
        addr = contract_address.lower()
        ck = (chain or "ethereum").lower()
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())

        # 0. Check SQLite Cache first
        if self.db is not None and not force_refresh and hasattr(self.db, "get_cached_resolved_links"):
            cached = await self.db.get_cached_resolved_links(
                contract_address=addr,
                chain=ck,
                ttl_seconds=self.cache_ttl_seconds,
                as_of_timestamp=now,
            )
            if cached and isinstance(cached, dict):
                try:
                    return ResolvedLinksResult.from_dict(cached)
                except Exception as e:
                    logger.debug("Failed deserializing cached links for %s: %s", addr, e)

        # 1. Socials: gather base socials from metadata and OpenSea
        eff_socials = dict(metadata_socials or {})
        eff_sources = dict(social_sources or {})

        # 2. Optionally parse website HTML for additional socials and mint links
        website_url = eff_socials.get("website")
        project_mint_link: Optional[str] = None
        if website_url:
            html_socials, html_mint = await self.resolve_website_html_socials_and_mint(
                website_url, as_of_timestamp=now
            )
            if html_mint:
                project_mint_link = html_mint
            for k, v in html_socials.items():
                if v and k not in eff_socials:
                    eff_socials[k] = v
                    eff_sources[k] = "via website HTML"

        # 3. Analyze safety for all socials
        resolved_socials: Dict[str, ResolvedLink] = {}
        for k in ("website", "twitter", "discord", "telegram"):
            url = eff_socials.get(k)
            if url:
                src = eff_sources.get(k, "from contract metadata, unverified")
                res_link = await self.analyze_url_safety(url, source=src, as_of_timestamp=now)
                # Pretty titles
                res_link.title = "X" if k == "twitter" else k.capitalize()
                resolved_socials[k] = res_link

        # 4. Resolve public mint link and fallback Write Contract tab
        mint_link, fallback_link = await self.resolve_mint_link(
            contract_address=addr,
            chain=ck,
            explorer_url=explorer_url,
            project_website_url=website_url,
            candidate_mint_page=project_mint_link,
            opensea_slug=opensea_slug,
            explorer_family=explorer_family,
        )

        # 5. Resolve marketplace links
        marketplaces = await self.resolve_marketplace_links(
            contract_address=addr,
            chain=ck,
            chain_id=chain_id,
            opensea_slug=opensea_slug,
            opensea_chain_slug=opensea_chain_slug,
            real_token_id=real_token_id,
        )

        has_public = bool(mint_link is not None or len(resolved_socials) > 0)

        result = ResolvedLinksResult(
            mint_link=mint_link,
            mint_fallback_link=fallback_link,
            marketplaces=marketplaces,
            socials=resolved_socials,
            has_public_mint_or_socials=has_public,
        )

        # 6. Save in SQLite cache
        if self.db is not None and hasattr(self.db, "set_cached_resolved_links"):
            try:
                await self.db.set_cached_resolved_links(
                    contract_address=addr,
                    chain=ck,
                    payload=result.to_dict(),
                    timestamp=now,
                )
            except Exception as e:
                logger.debug("Failed caching resolved links for %s: %s", addr, e)

        return result

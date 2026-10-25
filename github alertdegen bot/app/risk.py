"""Configurable contract risk scoring engine built exclusively from real on-chain and explorer checks."""

from dataclasses import dataclass, field, asdict
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from app.chains import _fallback_yaml_parse

# Known Tornado Cash, Railgun, and mixer router/pool addresses across Ethereum, Base, Arbitrum, Optimism, Polygon
KNOWN_MIXER_ADDRESSES: Dict[str, str] = {
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash Router",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash Proxy",
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado Cash 0.1 ETH",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 1 ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 10 ETH",
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado Cash 100 ETH",
    "0x84443cfd09a48af6ef360c6976c5392ac5023a1f": "Tornado Cash L2 Pool",
    "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd": "Tornado Cash Polygon Pool",
    "0xdf231d99ff8b6c6cbf4e9b9a945cbacef9339178": "Tornado Cash Arbitrum Pool",
    "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9": "Railgun Relay",
}

MIXER_KEYWORDS = (
    "tornado",
    "mixer",
    "railgun",
    "aztec",
    "sinbad",
    "blender",
    "cyclone",
    "privacy pool",
)


def detect_mixer_from_text_or_address(text_or_addr: Optional[str]) -> Optional[str]:
    """Return mixer label if address or funding description matches a known mixer."""
    if not text_or_addr:
        return None
    low = text_or_addr.lower()
    for addr_hex, label in KNOWN_MIXER_ADDRESSES.items():
        if addr_hex in low:
            return label
    for kw in MIXER_KEYWORDS:
        if kw in low:
            return f"Mixer ({kw})"
    return None


@dataclass
class RiskConfig:
    medium_threshold: int = 25
    high_threshold: int = 50
    weights: Dict[str, int] = field(
        default_factory=lambda: {
            "unverified_source": 15,
            "proxy_or_upgradeable": 10,
            "owner_mint_or_no_cap": 15,
            "transfer_restrictions_abi": 15,
            "mutable_base_uri": 10,
            "young_deployer": 15,
            "suspicious_deployer_funding": 15,
            "velocity_quality": 30,
            "owner_is_top_minter": 35,
            "excessive_self_mints": 40,
            "honeypot_simulation": 50,
            "no_project_footprint": 15,
        }
    )
    parameters: Dict[str, float] = field(
        default_factory=lambda: {
            "deployer_min_age_days": 7.0,
            "funder_min_age_days": 7.0,
            "funder_min_tx_count": 3.0,
            "max_top5_concentration_pct": 50.0,
            "max_single_minter_pct": 25.0,
            "max_mints_per_wallet_ratio": 5.0,
            "max_self_mint_pct": 30.0,
        }
    )


def load_risk_config(config_path: str = "risk.yaml") -> RiskConfig:
    """Load risk scoring weights, thresholds, and parameters from YAML config file."""
    cfg = RiskConfig()
    path = Path(config_path)
    if not path.exists():
        alt = Path(__file__).resolve().parent.parent / config_path
        if alt.exists():
            path = alt
        else:
            return cfg

    try:
        raw_text = path.read_text(encoding="utf-8")
        try:
            import yaml  # type: ignore
            raw = yaml.safe_load(raw_text) or {}
        except ImportError:
            raw = _fallback_yaml_parse(raw_text)
    except Exception:
        return cfg

    if not isinstance(raw, dict):
        return cfg

    thresholds = raw.get("thresholds")
    if isinstance(thresholds, dict):
        if "medium" in thresholds:
            cfg.medium_threshold = int(thresholds["medium"])
        if "high" in thresholds:
            cfg.high_threshold = int(thresholds["high"])

    weights = raw.get("weights")
    if isinstance(weights, dict):
        for k, v in weights.items():
            try:
                cfg.weights[str(k)] = int(v)
            except (ValueError, TypeError):
                pass

    params = raw.get("parameters")
    if isinstance(params, dict):
        for k, v in params.items():
            try:
                cfg.parameters[str(k)] = float(v)
            except (ValueError, TypeError):
                pass

    return cfg


@dataclass
class RiskCheckResult:
    key: str
    name: str
    status: str  # "passed" | "failed" | "not_checked"
    weight: int
    points_awarded: int
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskCheckResult":
        return cls(
            key=str(data.get("key", "")),
            name=str(data.get("name", "")),
            status=str(data.get("status", "not_checked")),
            weight=int(data.get("weight", 0)),
            points_awarded=int(data.get("points_awarded", 0)),
            detail=str(data.get("detail", "not checked")),
        )


@dataclass
class RiskScoreReport:
    contract_address: str = ""
    chain: str = "ethereum"
    score: int = 0
    risk_level: str = "Low"  # "Low" | "Medium" | "High"
    reasons: List[str] = field(default_factory=list)
    checks: List[RiskCheckResult] = field(default_factory=list)
    scored_at: int = 0
    medium_threshold: int = 25
    high_threshold: int = 50

    @property
    def failed_checks(self) -> List[RiskCheckResult]:
        return [c for c in self.checks if c.status == "failed"]

    @property
    def passed_checks(self) -> List[RiskCheckResult]:
        return [c for c in self.checks if c.status == "passed"]

    @property
    def not_checked_checks(self) -> List[RiskCheckResult]:
        return [c for c in self.checks if c.status == "not_checked"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_address": self.contract_address,
            "chain": self.chain,
            "score": self.score,
            "risk_level": self.risk_level,
            "reasons": list(self.reasons),
            "checks": [c.to_dict() for c in self.checks],
            "scored_at": self.scored_at,
            "medium_threshold": self.medium_threshold,
            "high_threshold": self.high_threshold,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskScoreReport":
        checks_raw = data.get("checks") or []
        checks = [
            RiskCheckResult.from_dict(c) if isinstance(c, dict) else c
            for c in checks_raw
        ]
        return cls(
            contract_address=str(data.get("contract_address", "")),
            chain=str(data.get("chain", "ethereum")),
            score=int(data.get("score", 0)),
            risk_level=str(data.get("risk_level", "Low")),
            reasons=list(data.get("reasons") or []),
            checks=checks,
            scored_at=int(data.get("scored_at", 0)),
            medium_threshold=int(data.get("medium_threshold", 25)),
            high_threshold=int(data.get("high_threshold", 50)),
        )


class RiskScorer:
    """Evaluates real contract enrichment & velocity data into a structured RiskScoreReport."""

    def __init__(self, risk_config: Optional[RiskConfig] = None):
        self.config = risk_config or load_risk_config()

    def evaluate(
        self,
        enrichment: Any,
        stats: Optional[Any] = None,
        as_of_timestamp: Optional[int] = None,
    ) -> RiskScoreReport:
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        w = self.config.weights
        p = self.config.parameters

        checks: List[RiskCheckResult] = []
        reasons: List[str] = []
        force_high = False

        def _add_check(key: str, name: str, status: str, detail: str, default_weight: int = 10):
            if key == "velocity_quality" and "top_wallet_concentration" in w:
                weight = int(w["top_wallet_concentration"])
            else:
                weight = int(w.get(key, default_weight))
            pts = weight if status == "failed" else 0
            checks.append(
                RiskCheckResult(
                    key=key,
                    name=name,
                    status=status,
                    weight=weight,
                    points_awarded=pts,
                    detail=detail,
                )
            )
            if status == "failed":
                reasons.append(f"{name} (+{pts}): {detail}")

        # 1. Unverified Source (+)
        if enrichment.is_source_verified is None:
            _add_check(
                "unverified_source",
                "Unverified Source",
                "not_checked",
                "not checked (explorer verification status unavailable)",
                15,
            )
        elif enrichment.is_source_verified is False:
            _add_check(
                "unverified_source",
                "Unverified Source",
                "failed",
                "Contract source code is not verified on explorer",
                15,
            )
        else:
            _add_check(
                "unverified_source",
                "Unverified Source",
                "passed",
                "Contract source code is verified on explorer",
                15,
            )

        # 2. Proxy or Upgradeable Contract (+)
        if enrichment.is_proxy is None:
            _add_check(
                "proxy_or_upgradeable",
                "Proxy / Upgradeable Contract",
                "not_checked",
                "not checked (EIP-1967/1822 storage slots unavailable)",
                10,
            )
        elif enrichment.is_proxy is True:
            p_type = getattr(enrichment, "proxy_type", None) or "EIP-1967"
            _add_check(
                "proxy_or_upgradeable",
                "Proxy / Upgradeable Contract",
                "failed",
                f"Upgradeable proxy detected ({p_type})",
                10,
            )
        else:
            _add_check(
                "proxy_or_upgradeable",
                "Proxy / Upgradeable Contract",
                "passed",
                "Non-proxy contract",
                10,
            )

        # 3. Owner-Only Mint or No Supply Cap (+)
        rf = getattr(enrichment, "risky_functions", None)
        max_sup = getattr(enrichment, "max_supply", None)
        tot_sup = getattr(enrichment, "total_supply", None)
        is_renounced = getattr(enrichment, "is_ownership_renounced", None)

        owner_mints = (rf.get("owner_mint") or []) if isinstance(rf, dict) else []
        has_active_owner_mint = bool(owner_mints) and (is_renounced is not True)

        if rf is None and max_sup is None and tot_sup is None:
            _add_check(
                "owner_mint_or_no_cap",
                "Owner-Only Mint / Supply Cap",
                "not_checked",
                "not checked (ABI/bytecode and supply getters unavailable)",
                15,
            )
        else:
            fail_parts = []
            if has_active_owner_mint:
                fail_parts.append(f"Owner/admin mint in ABI ({', '.join(owner_mints[:2])})")
            if max_sup is None or max_sup <= 0:
                fail_parts.append("No max supply cap detected on-chain")

            if fail_parts:
                _add_check(
                    "owner_mint_or_no_cap",
                    "Owner-Only Mint / Supply Cap",
                    "failed",
                    "; ".join(fail_parts),
                    15,
                )
            elif rf is None:
                _add_check(
                    "owner_mint_or_no_cap",
                    "Owner-Only Mint / Supply Cap",
                    "not_checked",
                    f"not checked (Max supply {max_sup:,} found, but ABI unavailable for owner-mint scan)",
                    15,
                )
            else:
                _add_check(
                    "owner_mint_or_no_cap",
                    "Owner-Only Mint / Supply Cap",
                    "passed",
                    f"Fixed max supply ({max_sup:,}) and no active owner-only mint",
                    15,
                )

        # 4. Blacklist, Pause, or Transfer-Restriction Functions in ABI (+)
        is_paused = getattr(enrichment, "is_paused", None)
        if rf is None and is_paused is None:
            _add_check(
                "transfer_restrictions_abi",
                "Blacklist / Pause / Transfer Restrictions",
                "not_checked",
                "not checked (ABI/bytecode unavailable)",
                15,
            )
        else:
            bl_fns = (rf.get("blacklist") or []) if isinstance(rf, dict) else []
            pause_fns = (rf.get("pausable_transfers") or []) if isinstance(rf, dict) else []
            restrict_fns = (rf.get("transfer_restrictions") or []) if isinstance(rf, dict) else []
            combined_fns = list(dict.fromkeys(bl_fns + pause_fns + restrict_fns))

            if combined_fns or is_paused is True:
                r_parts = []
                if combined_fns:
                    r_parts.append(f"Found {', '.join(combined_fns[:3])}")
                if is_paused is True:
                    r_parts.append("Contract is currently paused")
                _add_check(
                    "transfer_restrictions_abi",
                    "Blacklist / Pause / Transfer Restrictions",
                    "failed",
                    "; ".join(r_parts),
                    15,
                )
            elif rf is None:
                _add_check(
                    "transfer_restrictions_abi",
                    "Blacklist / Pause / Transfer Restrictions",
                    "not_checked",
                    "not checked (ABI/bytecode unavailable)",
                    15,
                )
            else:
                _add_check(
                    "transfer_restrictions_abi",
                    "Blacklist / Pause / Transfer Restrictions",
                    "passed",
                    "No blacklist, pause, or transfer-restriction functions detected",
                    15,
                )

        # 5. Mutable Base URI (+)
        if rf is None:
            _add_check(
                "mutable_base_uri",
                "Mutable Base URI",
                "not_checked",
                "not checked (ABI/bytecode unavailable)",
                10,
            )
        else:
            uri_fns = rf.get("set_base_uri") or []
            if uri_fns and is_renounced is not True:
                _add_check(
                    "mutable_base_uri",
                    "Mutable Base URI",
                    "failed",
                    f"Mutable metadata URI function ({', '.join(uri_fns[:2])})",
                    10,
                )
            elif uri_fns and is_renounced is True:
                _add_check(
                    "mutable_base_uri",
                    "Mutable Base URI",
                    "passed",
                    f"URI setter ({uri_fns[0]}) inactive because ownership is renounced",
                    10,
                )
            else:
                _add_check(
                    "mutable_base_uri",
                    "Mutable Base URI",
                    "passed",
                    "No mutable baseURI functions detected",
                    10,
                )

        # 6. Deployer Wallet Younger Than 7 Days (+)
        min_age_days = int(p.get("deployer_min_age_days", 7))
        min_age_seconds = min_age_days * 86400
        dep_age = getattr(enrichment, "deployer_age_seconds", None)
        dep_age_fmt = getattr(enrichment, "deployer_age_formatted", "unavailable")

        if dep_age is None:
            _add_check(
                "young_deployer",
                f"Deployer Wallet < {min_age_days}d",
                "not_checked",
                "not checked (deployer first tx timestamp unavailable)",
                15,
            )
        elif dep_age < min_age_seconds:
            _add_check(
                "young_deployer",
                f"Deployer Wallet < {min_age_days}d",
                "failed",
                f"Deployer wallet is younger than {min_age_days} days ({dep_age_fmt})",
                15,
            )
        else:
            _add_check(
                "young_deployer",
                f"Deployer Wallet < {min_age_days}d",
                "passed",
                f"Deployer wallet age ≥ {min_age_days} days ({dep_age_fmt})",
                15,
            )

        # 7. Deployer Funded from Mixer or Fresh Wallet (+)
        funded_mixer = getattr(enrichment, "deployer_funded_from_mixer", None)
        funded_fresh = getattr(enrichment, "deployer_funded_from_fresh_wallet", None)
        funding_src = getattr(enrichment, "deployer_funding_source", None)
        funder_txs = getattr(enrichment, "deployer_funder_tx_count", None)
        funder_age = getattr(enrichment, "deployer_funder_age_seconds", None)

        if funded_mixer is None and funded_fresh is None and funding_src:
            mixer_match = detect_mixer_from_text_or_address(funding_src)
            if mixer_match:
                funded_mixer = True

        if funded_mixer is True:
            _add_check(
                "suspicious_deployer_funding",
                "Deployer Funding (Mixer / Fresh Wallet)",
                "failed",
                f"Deployer funded via mixer/privacy source ({funding_src or 'mixer'})",
                15,
            )
        elif funded_fresh is True:
            meta = []
            if funder_txs is not None:
                meta.append(f"{funder_txs} txs")
            if funder_age is not None:
                days = funder_age // 86400
                meta.append(f"{days}d old" if days > 0 else "<1d old")
            meta_str = f" [{', '.join(meta)}]" if meta else ""
            _add_check(
                "suspicious_deployer_funding",
                "Deployer Funding (Mixer / Fresh Wallet)",
                "failed",
                f"Deployer funded by a fresh wallet ({funding_src or 'unknown'}{meta_str})",
                15,
            )
        elif funded_mixer is False and funded_fresh is False:
            _add_check(
                "suspicious_deployer_funding",
                "Deployer Funding (Mixer / Fresh Wallet)",
                "passed",
                f"Deployer funded by established wallet ({funding_src or 'verified'})",
                15,
            )
        else:
            _add_check(
                "suspicious_deployer_funding",
                "Deployer Funding (Mixer / Fresh Wallet)",
                "not_checked",
                "not checked (deployer funding wallet history unavailable)",
                15,
            )

        # 8. Velocity Quality & Top-Wallet Concentration (++)
        top5_pct = getattr(enrichment, "top5_concentration_pct", None)
        top_minters = getattr(enrichment, "top_minters", None) or []
        top1_pct = float(top_minters[0].get("pct", 0.0)) if top_minters else None

        total_mints = getattr(stats, "total_mints", 0) if stats else 0
        unique_minters = getattr(stats, "unique_minters", 0) if stats else 0
        mints_per_wallet = (total_mints / unique_minters) if unique_minters > 0 else None

        max_top5 = float(p.get("max_top5_concentration_pct", 50.0))
        max_top1 = float(p.get("max_single_minter_pct", 25.0))
        max_ratio = float(p.get("max_mints_per_wallet_ratio", 5.0))

        if top5_pct is None and mints_per_wallet is None:
            _add_check(
                "velocity_quality",
                "Velocity Quality & Concentration",
                "not_checked",
                "not checked (no mint concentration or velocity sample available)",
                30,
            )
        else:
            vel_issues = []
            if top5_pct is not None and top5_pct > max_top5:
                vel_issues.append(f"Top-5 wallets hold {top5_pct:.1f}% (> {max_top5:.0f}%)")
            if top1_pct is not None and top1_pct > max_top1:
                vel_issues.append(f"Top wallet holds {top1_pct:.1f}% (> {max_top1:.0f}%)")
            if mints_per_wallet is not None and mints_per_wallet > max_ratio:
                vel_issues.append(f"Sweep ratio {mints_per_wallet:.1f} mints/wallet (> {max_ratio:.1f})")

            if vel_issues:
                _add_check(
                    "velocity_quality",
                    "Velocity Quality & Concentration",
                    "failed",
                    "; ".join(vel_issues),
                    30,
                )
            elif top5_pct is not None:
                ratio_part = f", {mints_per_wallet:.1f} mints/wallet" if mints_per_wallet is not None else ""
                _add_check(
                    "velocity_quality",
                    "Velocity Quality & Concentration",
                    "passed",
                    f"Healthy distribution (Top-5 concentration: {top5_pct:.1f}%{ratio_part})",
                    30,
                )
            else:
                _add_check(
                    "velocity_quality",
                    "Velocity Quality & Concentration",
                    "not_checked",
                    "not checked (top-5 minter concentration unavailable)",
                    30,
                )

        # 9. Owner / Deployer is Top Minter (++)
        owner_top = getattr(enrichment, "owner_is_top_minter", None)
        owner_addr = getattr(enrichment, "owner", None) or getattr(enrichment, "owner_address", None)
        deployer_addr = getattr(enrichment, "deployer", None) or getattr(enrichment, "deployer_address", None)
        zero_addr = "0x0000000000000000000000000000000000000000"
        owner_deployer_set = {
            a.strip().lower()
            for a in (owner_addr, deployer_addr)
            if isinstance(a, str) and a.strip() and a.strip().lower() != zero_addr
        }

        if owner_top is None and top_minters and owner_deployer_set:
            top1_addr = str(top_minters[0].get("address", "")).strip().lower()
            top1_cnt = int(top_minters[0].get("count", 0))
            self_cnt = getattr(enrichment, "self_mints", None)
            if top1_addr in owner_deployer_set:
                owner_top = True
            elif self_cnt is not None and self_cnt > 0 and self_cnt >= top1_cnt:
                owner_top = True
            else:
                owner_top = False

        if owner_top is True:
            _add_check(
                "owner_is_top_minter",
                "Owner / Deployer is Top Minter",
                "failed",
                "Contract owner or deployer is the #1 minter wallet",
                35,
            )
        elif owner_top is False:
            _add_check(
                "owner_is_top_minter",
                "Owner / Deployer is Top Minter",
                "passed",
                "Top minter is independent of contract owner/deployer",
                35,
            )
        else:
            _add_check(
                "owner_is_top_minter",
                "Owner / Deployer is Top Minter",
                "not_checked",
                "not checked (owner/deployer or top-minter wallet data unavailable)",
                35,
            )

        # 10. Excessive Owner/Deployer Self-Mints (> 30% -> +40 and HIGH)
        self_mints = getattr(enrichment, "self_mints", None)
        self_mint_pct = getattr(enrichment, "self_mint_pct", None)
        if self_mints is None and stats is not None and getattr(stats, "raw_total_mints", 0) > 0:
            self_mints = int(getattr(stats, "self_mints", 0))
            raw_tot = int(getattr(stats, "raw_total_mints", 0))
            if raw_tot > 0:
                self_mint_pct = round((self_mints / raw_tot) * 100.0, 1)

        max_self_pct = float(p.get("max_self_mint_pct", 30.0))
        if self_mint_pct is not None and self_mint_pct > max_self_pct:
            force_high = True
            _add_check(
                "excessive_self_mints",
                f"Owner / Deployer Self-Mints (> {max_self_pct:.0f}%)",
                "failed",
                f"Owner/Deployer self-mints are {self_mint_pct:.1f}% of total mints ({self_mints or 0} self-mints > {max_self_pct:.0f}%)",
                40,
            )
        elif self_mint_pct is not None and (owner_deployer_set or (self_mints is not None and self_mints == 0 and (owner_addr or deployer_addr))):
            _add_check(
                "excessive_self_mints",
                f"Owner / Deployer Self-Mints (> {max_self_pct:.0f}%)",
                "passed",
                f"Owner/Deployer self-mints: {self_mints or 0} ({self_mint_pct:.1f}% ≤ {max_self_pct:.0f}%)",
                40,
            )
        else:
            _add_check(
                "excessive_self_mints",
                f"Owner / Deployer Self-Mints (> {max_self_pct:.0f}%)",
                "not_checked",
                "not checked (owner/deployer or self-mint ratio unavailable)",
                40,
            )

        # 11. Simulated Transfer / Approval via eth_call (Honeypot Check) (+++)
        hp_reverted = getattr(enrichment, "honeypot_sim_reverted", None)
        hp_detail = getattr(enrichment, "honeypot_sim_detail", None)

        if hp_reverted is None:
            _add_check(
                "honeypot_simulation",
                "Honeypot Simulation (eth_call)",
                "not_checked",
                f"not checked ({hp_detail or 'simulated transfer/approval could not be run'})",
                50,
            )
        elif hp_reverted is True:
            _add_check(
                "honeypot_simulation",
                "Honeypot Simulation (eth_call)",
                "failed",
                f"Simulated eth_call reverted ({hp_detail or 'transfer/approval reverted — possible honeypot'})",
                50,
            )
        else:
            _add_check(
                "honeypot_simulation",
                "Honeypot Simulation (eth_call)",
                "passed",
                f"Simulated eth_call succeeded ({hp_detail or 'transfer/approval allowed'})",
                50,
            )

        # 12. No Project Footprint (+)
        hp_footprint = getattr(enrichment, "has_project_footprint", None)
        c_uri = getattr(enrichment, "contract_uri", None)
        t_uri = getattr(enrichment, "token_uri", None)
        c_uri_st = getattr(enrichment, "contract_uri_status", None)
        t_uri_st = getattr(enrichment, "token_uri_status", None)
        os_slug = getattr(enrichment, "opensea_slug", None)
        os_socials = getattr(enrichment, "opensea_socials", None) or {}
        meta_socials = getattr(enrichment, "metadata_socials", None) or {}
        meta_name = getattr(enrichment, "metadata_name", None)

        if hp_footprint is None:
            if (
                bool(os_slug)
                or bool(os_socials)
                or bool(meta_socials)
                or bool(meta_name)
                or (c_uri and c_uri_st != "fetch failed")
                or (t_uri and t_uri_st != "fetch failed")
            ):
                hp_footprint = True
            elif (
                c_uri_st in ("not implemented", "fetch failed")
                or t_uri_st in ("not implemented", "fetch failed")
            ) and not (
                c_uri is None
                and t_uri is None
                and c_uri_st == "fetch failed"
                and t_uri_st == "fetch failed"
            ):
                hp_footprint = False

        if hp_footprint is True:
            footprint_parts = []
            if c_uri and c_uri_st != "fetch failed":
                footprint_parts.append("contractURI")
            if t_uri and t_uri_st != "fetch failed":
                footprint_parts.append("tokenURI metadata")
            if os_slug or os_socials:
                footprint_parts.append("OpenSea")
            fp_desc = ", ".join(footprint_parts) if footprint_parts else "metadata/OpenSea"
            _add_check(
                "no_project_footprint",
                "No Project Footprint",
                "passed",
                f"Project metadata footprint present ({fp_desc})",
                15,
            )
        elif hp_footprint is False:
            _add_check(
                "no_project_footprint",
                "No Project Footprint",
                "failed",
                "No contractURI, no tokenURI metadata, and no OpenSea data",
                15,
            )
        else:
            _add_check(
                "no_project_footprint",
                "No Project Footprint",
                "not_checked",
                "not checked (contractURI, tokenURI, and OpenSea lookup status unavailable)",
                15,
            )

        total_score = sum(c.points_awarded for c in checks)
        if force_high or total_score >= self.config.high_threshold:
            level = "High"
        elif total_score >= self.config.medium_threshold:
            level = "Medium"
        else:
            level = "Low"

        return RiskScoreReport(
            contract_address=getattr(enrichment, "contract_address", ""),
            chain=getattr(enrichment, "chain", "ethereum"),
            score=total_score,
            risk_level=level,
            reasons=reasons,
            checks=checks,
            scored_at=now,
            medium_threshold=self.config.medium_threshold,
            high_threshold=self.config.high_threshold,
        )


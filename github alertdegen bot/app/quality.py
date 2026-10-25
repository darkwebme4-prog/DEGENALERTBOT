"""Configurable Quality Score (0-100) and Alert Tier (Tier A, Tier B, Tier C) engine."""

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    import yaml
except ImportError:
    yaml = None

from app.chains import _fallback_yaml_parse


DEFAULT_QUALITY_WEIGHTS: Dict[str, int] = {
    "mature_minters": 25,
    "low_sybil_and_contracts": 20,
    "total_eth_spent": 20,
    "clustered_unique_minters": 20,
    "contract_age": 15,
}


@dataclass
class QualityConfig:
    """Configurable weights and thresholds for the 0-100 Quality Score and Alert Tiers."""

    weights: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_QUALITY_WEIGHTS))
    mature_wallet_min_age_days: float = 30.0
    mature_wallet_min_nonce: int = 5
    min_mature_minter_share_pct: float = 30.0
    max_sybil_or_contract_share_pct: float = 25.0
    min_total_eth_spent: float = 0.05
    min_clustered_unique_minters: int = 10
    max_contract_age_hours: float = 72.0
    tier_a_min_quality: int = 60
    tier_b_min_quality: int = 35
    digest_interval_seconds: int = 3600
    enforce_tiers: bool = False

    def weight(self, key: str) -> int:
        return int(self.weights.get(key, DEFAULT_QUALITY_WEIGHTS.get(key, 0)))


def load_quality_config(config_path: str = "quality.yaml") -> QualityConfig:
    """Load configurable quality scoring weights and thresholds from YAML."""
    path = Path(config_path)
    if not path.exists():
        return QualityConfig()

    try:
        content = path.read_text(encoding="utf-8")
        if yaml is not None:
            raw = yaml.safe_load(content) or {}
        else:
            raw = _fallback_yaml_parse(content) or {}
    except Exception:
        return QualityConfig()

    if not isinstance(raw, dict):
        return QualityConfig()

    weights = dict(DEFAULT_QUALITY_WEIGHTS)
    raw_weights = raw.get("weights")
    if isinstance(raw_weights, dict):
        for k, v in raw_weights.items():
            try:
                weights[str(k)] = int(v)
            except (ValueError, TypeError):
                pass

    thresholds = raw.get("thresholds") if isinstance(raw.get("thresholds"), dict) else {}

    def _int_val(key: str, default: int) -> int:
        val = thresholds.get(key, raw.get(key, default))
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _float_val(key: str, default: float) -> float:
        val = thresholds.get(key, raw.get(key, default))
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def _bool_val(key: str, default: bool) -> bool:
        val = thresholds.get(key, raw.get(key, default))
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.strip().lower() in ("1", "true", "yes", "on")
        return bool(val)

    return QualityConfig(
        weights=weights,
        mature_wallet_min_age_days=_float_val("mature_wallet_min_age_days", 30.0),
        mature_wallet_min_nonce=_int_val("mature_wallet_min_nonce", 5),
        min_mature_minter_share_pct=_float_val("min_mature_minter_share_pct", 30.0),
        max_sybil_or_contract_share_pct=_float_val("max_sybil_or_contract_share_pct", 25.0),
        min_total_eth_spent=_float_val("min_total_eth_spent", 0.05),
        min_clustered_unique_minters=_int_val("min_clustered_unique_minters", 10),
        max_contract_age_hours=_float_val("max_contract_age_hours", 72.0),
        tier_a_min_quality=_int_val("tier_a_min_quality", 60),
        tier_b_min_quality=_int_val("tier_b_min_quality", 35),
        digest_interval_seconds=_int_val("digest_interval_seconds", 3600),
        enforce_tiers=_bool_val("enforce_tiers", False),
    )


@dataclass
class QualityCheckResult:
    """Single quality check outcome: 'passed', 'failed', or 'not_checked'."""

    key: str
    name: str
    weight: int
    status: str  # "passed" | "failed" | "not_checked"
    points_awarded: int
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QualityScoreReport:
    """Full quality score evaluation (0-100) and Alert Tier classification."""

    score: int
    alert_tier: str  # "Tier A" | "Tier B" | "Tier C"
    tier_reason: str
    checks: List[QualityCheckResult] = field(default_factory=list)
    tier_a_min_quality: int = 60
    tier_b_min_quality: int = 35
    reasons: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.reasons and self.checks:
            self.reasons = [c.detail for c in self.checks if c.status == "passed"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "alert_tier": self.alert_tier,
            "tier_reason": self.tier_reason,
            "checks": [c.to_dict() for c in self.checks],
            "tier_a_min_quality": self.tier_a_min_quality,
            "tier_b_min_quality": self.tier_b_min_quality,
            "reasons": self.reasons,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QualityScoreReport":
        raw_checks = data.get("checks") or []
        checks = [
            QualityCheckResult(**c) if isinstance(c, dict) else c
            for c in raw_checks
        ]
        reasons = list(data.get("reasons") or [c.detail for c in checks if getattr(c, "status", None) == "passed"])
        return cls(
            score=int(data.get("score", 0)),
            alert_tier=str(data.get("alert_tier", "Tier C")),
            tier_reason=str(data.get("tier_reason", "")),
            checks=checks,
            tier_a_min_quality=int(data.get("tier_a_min_quality", 60)),
            tier_b_min_quality=int(data.get("tier_b_min_quality", 35)),
            reasons=reasons,
        )


class QualityScorer:
    """
    Evaluates a separate 0-100 Quality Score and Alert Tier (Tier A, Tier B, Tier C).
    Rule: Any check that cannot run or whose input failed to load is marked 'not_checked'
    (displayed as 'not checked') and NEVER counts as passed (points_awarded = 0).
    """

    def __init__(self, config: Optional[QualityConfig] = None):
        self.config = config or QualityConfig()

    def evaluate(
        self,
        enrichment: Any,
        stats: Optional[Any] = None,
        risk_report: Optional[Any] = None,
        max_contract_age_hours: Optional[float] = None,
        as_of_timestamp: Optional[int] = None,
    ) -> QualityScoreReport:
        cfg = self.config
        checks: List[QualityCheckResult] = []

        # 1. Share of minters with wallets older than 30 days and a nonce above 5
        w_mature = cfg.weight("mature_minters")
        mature_share = getattr(enrichment, "mature_minter_share_pct", None)
        mature_checked_cnt = getattr(enrichment, "mature_minters_checked", None)
        min_days = cfg.mature_wallet_min_age_days
        min_nonce = cfg.mature_wallet_min_nonce
        if mature_share is None or (mature_checked_cnt is not None and int(mature_checked_cnt) <= 0):
            checks.append(
                QualityCheckResult(
                    key="mature_minters",
                    name=f"Mature Minters (>{int(min_days)}d & Nonce >{min_nonce})",
                    weight=w_mature,
                    status="not_checked",
                    points_awarded=0,
                    detail="not checked",
                )
            )
        elif float(mature_share) >= cfg.min_mature_minter_share_pct:
            checks.append(
                QualityCheckResult(
                    key="mature_minters",
                    name=f"Mature Minters (>{int(min_days)}d & Nonce >{min_nonce})",
                    weight=w_mature,
                    status="passed",
                    points_awarded=w_mature,
                    detail=(
                        f"{float(mature_share):.1f}% of checked minters meet age & nonce "
                        f"(≥ {cfg.min_mature_minter_share_pct:.0f}%)"
                    ),
                )
            )
        else:
            checks.append(
                QualityCheckResult(
                    key="mature_minters",
                    name=f"Mature Minters (>{int(min_days)}d & Nonce >{min_nonce})",
                    weight=w_mature,
                    status="failed",
                    points_awarded=0,
                    detail=(
                        f"Only {float(mature_share):.1f}% of checked minters meet age & nonce "
                        f"(< {cfg.min_mature_minter_share_pct:.0f}%)"
                    ),
                )
            )

        # 2. Share of mints sent from contracts or repeated by the same funder
        w_sybil = cfg.weight("low_sybil_and_contracts")
        sybil_share = getattr(enrichment, "sybil_or_contract_mint_share_pct", None)
        if sybil_share is None:
            checks.append(
                QualityCheckResult(
                    key="low_sybil_and_contracts",
                    name="Contract / Same-Funder Mint Share",
                    weight=w_sybil,
                    status="not_checked",
                    points_awarded=0,
                    detail="not checked",
                )
            )
        elif float(sybil_share) <= cfg.max_sybil_or_contract_share_pct:
            checks.append(
                QualityCheckResult(
                    key="low_sybil_and_contracts",
                    name="Contract / Same-Funder Mint Share",
                    weight=w_sybil,
                    status="passed",
                    points_awarded=w_sybil,
                    detail=(
                        f"{float(sybil_share):.1f}% from contracts/repeated funder "
                        f"(≤ {cfg.max_sybil_or_contract_share_pct:.0f}%)"
                    ),
                )
            )
        else:
            checks.append(
                QualityCheckResult(
                    key="low_sybil_and_contracts",
                    name="Contract / Same-Funder Mint Share",
                    weight=w_sybil,
                    status="failed",
                    points_awarded=0,
                    detail=(
                        f"{float(sybil_share):.1f}% from contracts/repeated funder "
                        f"(> {cfg.max_sybil_or_contract_share_pct:.0f}%)"
                    ),
                )
            )

        # 3. Total ETH spent by non-owner minters
        w_eth = cfg.weight("total_eth_spent")
        eth_spent = getattr(enrichment, "total_eth_spent_non_owner", None)
        sym = getattr(enrichment, "native_token_symbol", None) or "ETH"
        if eth_spent is None:
            checks.append(
                QualityCheckResult(
                    key="total_eth_spent",
                    name=f"Total {sym} Spent (Non-Owner Minters)",
                    weight=w_eth,
                    status="not_checked",
                    points_awarded=0,
                    detail="not checked",
                )
            )
        elif float(eth_spent) >= cfg.min_total_eth_spent:
            checks.append(
                QualityCheckResult(
                    key="total_eth_spent",
                    name=f"Total {sym} Spent (Non-Owner Minters)",
                    weight=w_eth,
                    status="passed",
                    points_awarded=w_eth,
                    detail=f"{float(eth_spent):.4f} {sym} spent (≥ {cfg.min_total_eth_spent:g} {sym})",
                )
            )
        else:
            checks.append(
                QualityCheckResult(
                    key="total_eth_spent",
                    name=f"Total {sym} Spent (Non-Owner Minters)",
                    weight=w_eth,
                    status="failed",
                    points_awarded=0,
                    detail=f"{float(eth_spent):.4f} {sym} spent (< {cfg.min_total_eth_spent:g} {sym})",
                )
            )

        # 4. Real unique minters (after funding clustering)
        w_clustered = cfg.weight("clustered_unique_minters")
        clustered_minters = getattr(enrichment, "clustered_unique_minters", None)
        if clustered_minters is None:
            checks.append(
                QualityCheckResult(
                    key="clustered_unique_minters",
                    name="Real Unique Minters (Funding Clustered)",
                    weight=w_clustered,
                    status="not_checked",
                    points_awarded=0,
                    detail="not checked",
                )
            )
        elif int(clustered_minters) >= cfg.min_clustered_unique_minters:
            checks.append(
                QualityCheckResult(
                    key="clustered_unique_minters",
                    name="Real Unique Minters (Funding Clustered)",
                    weight=w_clustered,
                    status="passed",
                    points_awarded=w_clustered,
                    detail=(
                        f"{int(clustered_minters)} clustered unique minters "
                        f"(≥ {cfg.min_clustered_unique_minters})"
                    ),
                )
            )
        else:
            checks.append(
                QualityCheckResult(
                    key="clustered_unique_minters",
                    name="Real Unique Minters (Funding Clustered)",
                    weight=w_clustered,
                    status="failed",
                    points_awarded=0,
                    detail=(
                        f"{int(clustered_minters)} clustered unique minters "
                        f"(< {cfg.min_clustered_unique_minters})"
                    ),
                )
            )

        # 5. Contract age
        w_age = cfg.weight("contract_age")
        age_secs = getattr(enrichment, "contract_age_seconds", None)
        if age_secs is None and getattr(enrichment, "contract_deployed_timestamp", None) is not None:
            ref_ts = as_of_timestamp
            if ref_ts is None and stats is not None:
                ref_ts = getattr(stats, "as_of_timestamp", None)
            if ref_ts is None:
                ref_ts = int(time.time())
            dep_ts = int(enrichment.contract_deployed_timestamp)
            if dep_ts > 0:
                age_secs = max(0, int(ref_ts) - dep_ts)

        eff_max_age_h = (
            float(max_contract_age_hours)
            if max_contract_age_hours is not None
            else cfg.max_contract_age_hours
        )
        if age_secs is None or int(age_secs) < 0:
            checks.append(
                QualityCheckResult(
                    key="contract_age",
                    name="Contract Age (Fresh Deploy)",
                    weight=w_age,
                    status="not_checked",
                    points_awarded=0,
                    detail="not checked",
                )
            )
        else:
            age_fmt = getattr(enrichment, "contract_age_formatted", None)
            if not age_fmt or age_fmt in ("unavailable", "Unknown"):
                age_fmt = f"{int(age_secs)}s old"
            if int(age_secs) <= eff_max_age_h * 3600:
                checks.append(
                    QualityCheckResult(
                        key="contract_age",
                        name="Contract Age (Fresh Deploy)",
                        weight=w_age,
                        status="passed",
                        points_awarded=w_age,
                        detail=f"Fresh deploy ({age_fmt}, ≤ {eff_max_age_h:g}h)",
                    )
                )
            else:
                checks.append(
                    QualityCheckResult(
                        key="contract_age",
                        name="Contract Age (Fresh Deploy)",
                        weight=w_age,
                        status="failed",
                        points_awarded=0,
                        detail=f"Old contract ({age_fmt}, > {eff_max_age_h:g}h)",
                    )
                )

        total_score = min(100, max(0, sum(c.points_awarded for c in checks if c.status == "passed")))

        risk_level = "Low"
        if risk_report is not None:
            if isinstance(risk_report, dict):
                risk_level = str(risk_report.get("risk_level", "Low")).capitalize()
            else:
                risk_level = str(getattr(risk_report, "risk_level", "Low")).capitalize()

        is_fresh = age_secs is not None and 0 <= int(age_secs) <= eff_max_age_h * 3600

        if risk_level == "Low" and total_score >= cfg.tier_a_min_quality and is_fresh:
            alert_tier = "Tier A"
            tier_reason = (
                f"Risk Low, Quality {total_score}/100 ≥ {cfg.tier_a_min_quality}, Fresh Deploy (Immediate Alert)"
            )
        elif risk_level in ("Low", "Medium") and total_score >= cfg.tier_b_min_quality and is_fresh:
            alert_tier = "Tier B"
            tier_reason = (
                f"Risk {risk_level}, Quality {total_score}/100 ≥ {cfg.tier_b_min_quality} (Hourly Digest)"
            )
        else:
            alert_tier = "Tier C"
            tier_reason = (
                f"Risk {risk_level}, Quality {total_score}/100, Fresh={is_fresh} (Logged Only)"
            )

        return QualityScoreReport(
            score=total_score,
            alert_tier=alert_tier,
            tier_reason=tier_reason,
            checks=checks,
            tier_a_min_quality=cfg.tier_a_min_quality,
            tier_b_min_quality=cfg.tier_b_min_quality,
        )

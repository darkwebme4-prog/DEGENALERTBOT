"""Telegram Bot API dispatcher and interactive command listener (/start, /status, /chains, /test, /explain, /help)."""

import asyncio
import html
import logging
import re
import time
from typing import Optional, Any, Dict, List, Tuple
import urllib.parse
import httpx

from app.enrichment import (
    EnrichmentResult,
    format_contract_age,
    format_deployment_date,
    classify_contract_age,
)
from app.db import RollingStats
from app.risk import RiskScorer, RiskScoreReport, RiskCheckResult
from app.quality import QualityScorer, QualityScoreReport, QualityCheckResult
from app.rpc import redact_rpc_url

logger = logging.getLogger(__name__)

ETH_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _short_addr(addr: Optional[str]) -> str:
    if not addr or len(addr) < 10:
        return addr or "unavailable"
    return f"{addr[:6]}...{addr[-4:]}"


def _short_uri(uri: Optional[str], max_len: int = 44) -> str:
    if not uri:
        return "unavailable"
    clean = uri.strip()
    if len(clean) <= max_len:
        return html.escape(clean)
    return html.escape(clean[: max_len - 3] + "...")


def _explorer_display_name(
    explorer_url: str,
    explorer_type: str = "etherscan",
    explorer_name: Optional[str] = None,
) -> str:
    """Return the explorer's actual name (e.g. Berascan, Basescan, Arbiscan, etc.)."""
    if explorer_name and explorer_name.strip():
        return explorer_name.strip()
    u = (explorer_url or "").lower()
    if "basescan" in u:
        return "Basescan"
    if "arbiscan" in u:
        return "Arbiscan"
    if "optimistic.etherscan" in u or "optimism" in u:
        return "Optimistic Etherscan"
    if "polygonscan" in u:
        return "Polygonscan"
    if "robinhood" in u:
        return "Robinhood Chain Blockscout"
    if "hyperevmscan" in u or "hyperscan" in u or "hypurrscan" in u:
        return "HyperEVMScan"
    if "seiscan" in u or "seitrace" in u:
        return "Seiscan"
    if "berascan" in u:
        return "Berascan"
    if "apescan" in u:
        return "Apescan"
    if "inkonchain" in u or "ink" in u:
        return "Ink Explorer"
    if "abscan" in u:
        return "Abscan"
    if "monadscan" in u:
        return "MonadScan"
    if "megaeth" in u:
        return "MegaETH Blockscout"
    if "arc" in u:
        return "Arc Explorer"
    if explorer_type == "blockscout":
        return "Blockscout Explorer"
    return "Etherscan"


def _risk_level_badge(level: str) -> str:
    lvl = (level or "Low").capitalize()
    if lvl == "High":
        return "High 🔴"
    if lvl == "Medium":
        return "Medium 🟡"
    return "Low 🟢"


def _tier_badge(tier: str) -> str:
    t = (tier or "Tier C").strip()
    if t == "Tier A":
        return "Tier A 🏆 (Immediate)"
    if t == "Tier B":
        return "Tier B 📋 (Hourly Digest)"
    return "Tier C 📝 (Log Only)"


def _format_alert_risk_lines(report: RiskScoreReport) -> List[str]:
    """Format the top-of-alert Risk Score header and check statuses."""
    badge = _risk_level_badge(report.risk_level)
    out = [
        f"🛡 <b>Risk Score:</b> <b>{badge}</b> (<code>{report.score} pts</code>)",
    ]
    failed_checks = [c for c in report.checks if c.status == "failed"]
    passed_checks = [c for c in report.checks if c.status == "passed"]
    not_checked = [c for c in report.checks if c.status == "not_checked"]

    if failed_checks:
        for c in failed_checks:
            out.append(
                f"  • ⚠️ <b>{html.escape(c.name)}</b> (<code>+{c.points_awarded}</code>): {html.escape(c.detail)}"
            )
    else:
        out.append("  • ✅ <b>Reasons:</b> No risk flags triggered")

    for c in passed_checks:
        out.append(f"  • ✅ <b>{html.escape(c.name)}:</b> {html.escape(c.detail)}")

    for c in not_checked:
        out.append(f"  • ❔ <b>{html.escape(c.name)}:</b> <code>not checked</code>")

    return out


def _format_alert_quality_lines(report: QualityScoreReport) -> List[str]:
    """Format the top-of-alert Quality Score (0-100) and Alert Tier header and check statuses."""
    t_badge = _tier_badge(report.alert_tier)
    out = [
        f"🏆 <b>Quality Score:</b> <b><code>{report.score}/100</code></b> | 🎯 <b>Alert Tier:</b> <b>{html.escape(t_badge)}</b>",
    ]
    for c in report.checks:
        if c.status == "passed":
            out.append(
                f"  • ✅ <b>{html.escape(c.name)}</b> (<code>+{c.points_awarded}/{c.weight}</code>): {html.escape(c.detail)}"
            )
        elif c.status == "failed":
            out.append(
                f"  • ⚠️ <b>{html.escape(c.name)}</b> (<code>0/{c.weight}</code>): {html.escape(c.detail)}"
            )
        else:
            out.append(f"  • ❔ <b>{html.escape(c.name)}:</b> <code>not checked</code>")
    return out


def _format_watched_wallet_priority_lines(
    watched_wallets: Optional[List[Any]],
    explorer_base_url: str,
) -> List[str]:
    """Format priority header lines when 1 or 2+ watched wallets minted a contract."""
    if not watched_wallets:
        return []
    eff_explorer = (explorer_base_url or "https://etherscan.io").rstrip("/")
    links = []
    labels = []
    for w in watched_wallets[:5]:
        if isinstance(w, dict):
            addr = str(w.get("address") or w.get("wallet_address") or "")
            lbl = w.get("label")
        else:
            addr = str(w)
            lbl = None
        short = _short_addr(addr)
        lbl_str = f" ({html.escape(lbl)})" if lbl else ""
        if lbl:
            labels.append(lbl)
        links.append(f'<a href="{eff_explorer}/address/{addr}"><code>{short}</code></a>{lbl_str}')

    if len(watched_wallets) >= 2:
        return [
            f"🔥🚨 <b>HIGH PRIORITY: {len(watched_wallets)} WATCHED WALLETS MINTED</b> 🚨🔥",
            f"  • 👀 <b>Watched Minters ({len(watched_wallets)}):</b> {', '.join(links)}",
        ]
    return [
        "⭐ <b>PRIORITY ALERT: WATCHED WALLET MINT</b> ⭐",
        f"  • 👀 <b>Watched Minter:</b> {links[0]}",
    ]


def build_explain_message(
    contract_address: str,
    risk_report: RiskScoreReport,
    contract_name: Optional[str] = None,
    contract_symbol: Optional[str] = None,
    chain_name: str = "Ethereum",
    chain_id: int = 1,
    explorer_base_url: str = "https://etherscan.io",
) -> str:
    """Build the full /explain <contract> risk breakdown message."""
    eff_explorer = (explorer_base_url or "https://etherscan.io").rstrip("/")
    explorer_link = f"{eff_explorer}/address/{contract_address}"
    name_str = html.escape(contract_name) if contract_name else "unavailable"
    sym_str = html.escape(contract_symbol) if contract_symbol else "unavailable"
    badge = _risk_level_badge(risk_report.risk_level)

    failed_cnt = sum(1 for c in risk_report.checks if c.status == "failed")
    passed_cnt = sum(1 for c in risk_report.checks if c.status == "passed")
    not_checked_cnt = sum(1 for c in risk_report.checks if c.status == "not_checked")

    lines = [
        "🔍 <b>Contract Risk Score Breakdown</b>",
        "",
        f"⛓ <b>Chain:</b> <b>{html.escape(chain_name)}</b> (Chain ID: <code>{chain_id}</code>)",
        f"🏷 <b>Collection:</b> <b>{name_str}</b> (<code>{sym_str}</code>)",
        f"📜 <b>Contract:</b> <a href=\"{explorer_link}\"><code>{contract_address}</code></a>",
        "",
        f"🛡 <b>Overall Risk:</b> <b>{badge}</b> (<code>{risk_report.score} pts</code>)",
        f"📏 <b>Thresholds:</b> <code>Low &lt; {risk_report.medium_threshold} | Medium {risk_report.medium_threshold}–{risk_report.high_threshold - 1} | High ≥ {risk_report.high_threshold}</code>",
        f"📊 <b>Summary:</b> ⚠️ <code>{failed_cnt}</code> failed | ✅ <code>{passed_cnt}</code> passed | ❔ <code>{not_checked_cnt}</code> not checked",
        "",
        "📋 <b>Triggered Risk Reasons:</b>",
    ]

    if risk_report.reasons:
        for r in risk_report.reasons:
            lines.append(f"  • ⚠️ {html.escape(r)}")
    else:
        lines.append("  • ✅ None triggered")

    lines.append("")
    lines.append("🧪 <b>Full Check Breakdown (Real Checks Only):</b>")
    for c in risk_report.checks:
        if c.status == "failed":
            lines.append(
                f"  • ⚠️ <b>{html.escape(c.name)}</b> — <b>FAILED</b> (<code>+{c.points_awarded} / {c.weight} pts</code>)\n"
                f"    └ <code>{html.escape(c.detail)}</code>"
            )
        elif c.status == "passed":
            lines.append(
                f"  • ✅ <b>{html.escape(c.name)}</b> — <b>PASSED</b> (<code>+0 / {c.weight} pts</code>)\n"
                f"    └ <code>{html.escape(c.detail)}</code>"
            )
        else:
            lines.append(
                f"  • ❔ <b>{html.escape(c.name)}</b> — <code>not checked</code> (<code>0 / {c.weight} pts</code>)\n"
                f"    └ <code>{html.escape(c.detail)}</code>"
            )

    return "\n".join(lines)


def _format_live_mint_status_header(
    live_check: Optional[Dict[str, Any]],
    enrichment: EnrichmentResult,
) -> List[str]:
    """
    Format the top-of-alert status banner showing LIVE, SLOWING, ENDED, or SOLD OUT,
    along with the real mint price and the live check reason.
    If a check can't run, shows 'not checked' and never treats it as passed.
    """
    chk = live_check or getattr(enrichment, "live_mint_check", None)
    if chk and isinstance(chk, dict):
        status = chk.get("status", "LIVE")
        reason = chk.get("reason", "Open public mint verified via simulation")
        real_price = chk.get("mint_price") or enrichment.mint_price_formatted or "not checked"
    else:
        # Fallback when live_mint_check was not precomputed
        sim_st = getattr(enrichment, "simulation_status", "not_checked")
        tot = getattr(enrichment, "total_supply", None)
        max_s = getattr(enrichment, "max_supply", None)
        is_p = getattr(enrichment, "is_paused", None)

        if tot is not None and max_s is not None and max_s > 0 and tot >= max_s:
            status = "SOLD OUT"
            reason = f"Total supply ({tot:,}) reached max supply ({max_s:,})"
        elif is_p is True:
            status = "ENDED"
            reason = f"Contract is paused ({getattr(enrichment, 'paused_source', None) or 'paused()'})"
        elif sim_st == "success":
            status = "LIVE"
            reason = "Open public mint verified via simulation"
        elif sim_st == "reverted":
            status = "ENDED"
            rev = getattr(enrichment, "simulation_revert_reason", "reverted")
            cls_name = getattr(enrichment, "simulation_classification", "Reverted")
            reason = f"Simulation failed: {cls_name} ({rev})"
        else:
            status = "ENDED"
            reason = "Mint simulation not checked"
        real_price = enrichment.mint_price_formatted or "not checked"

    badge = "🟢" if status == "LIVE" else ("🟡" if status == "SLOWING" else "🔴")

    return [
        f"{badge} <b>STATUS: {html.escape(status)}</b> | <b>Mint Price:</b> <code>{html.escape(str(real_price))}</code>",
        f"<b>Live Check:</b> <i>{html.escape(str(reason))}</i>",
    ]


def _format_mint_simulation_line(enrichment: EnrichmentResult) -> str:
    """Format the Mint Simulation line reporting success, revert reason & classification, or 'not checked'."""
    status = getattr(enrichment, "simulation_status", "not_checked")
    revert_reason = getattr(enrichment, "simulation_revert_reason", None)
    classification = getattr(enrichment, "simulation_classification", None)
    tested_fn = getattr(enrichment, "simulation_tested_function", None)

    if status == "success":
        fn_part = f" via <code>{html.escape(tested_fn)}</code>" if tested_fn else ""
        return f"✅ <b>Succeeded</b> (1 qty{fn_part})"
    elif status == "reverted":
        cls_part = f" — <b>{html.escape(classification)}</b>" if classification and classification != "Reverted (Other)" else ""
        rev_part = f" (<code>{html.escape(revert_reason)}</code>)" if revert_reason else ""
        return f"🚫 <b>Reverted</b>{cls_part}{rev_part}"
    else:
        return "❔ <code>not checked</code>"


def _format_bytecode_template_line(enrichment: EnrichmentResult) -> str:
    """Format Bytecode Template line showing template label, risk flag badge, and match count."""
    label = getattr(enrichment, "template_label", None)
    risk_flag = getattr(enrichment, "template_risk_flag", None) or "neutral"
    match_cnt = int(getattr(enrichment, "template_match_count", 0) or 0)
    hash_val = getattr(enrichment, "stripped_bytecode_hash", None)

    if not hash_val:
        return "<code>unavailable</code>"

    plural = "contract" if match_cnt == 1 else "contracts"
    cnt_str = f"matched {match_cnt} {plural}"

    if label:
        if risk_flag == "scam":
            badge = "⚠️ <b>Scam</b>"
        elif risk_flag == "legit":
            badge = "✅ <b>Legit</b>"
        else:
            badge = "ℹ️ <b>Neutral</b>"
        return f"{badge} — {html.escape(label)} (<code>{cnt_str}</code>)"
    elif match_cnt > 0:
        return f"ℹ️ Unlabeled (<code>{cnt_str}</code>)"
    else:
        return f"<code>{cnt_str}</code>"


def _format_cross_chain_deployer_line(enrichment: EnrichmentResult) -> str:
    """Format Other Deployer Contracts line showing other contracts across configured chains with alert status and 7d outcome."""
    status = getattr(enrichment, "cross_chain_deployer_status", "ok")
    if status == "unavailable":
        return "<code>unavailable</code>"

    contracts = getattr(enrichment, "cross_chain_deployer_contracts", []) or []
    if not contracts:
        return "✅ None across configured chains"

    items = []
    for c in contracts[:3]:
        ck = html.escape(str(c.get("chain", "")).capitalize())
        c_addr = _short_addr(c.get("contract_address"))
        astat = html.escape(str(c.get("alert_status", "unalerted")))
        out7d = html.escape(str(c.get("outcome_7d", "unavailable")))
        items.append(f"{ck} <code>{c_addr}</code> (status: <code>{astat}</code> | 7d: <code>{out7d}</code>)")
    rem = len(contracts) - len(items)
    rem_str = f" +{rem} more" if rem > 0 else ""
    return "; ".join(items) + rem_str


def _format_funding_clusters_line(enrichment: EnrichmentResult) -> str:
    """Format Cross-Contract Funding line flagging funding sources appearing on multiple alerted contracts."""
    status = getattr(enrichment, "funding_clusters_status", "ok")
    if status == "unavailable":
        return "<code>unavailable</code>"

    clusters = getattr(enrichment, "funding_clusters_detected", []) or []
    if not clusters:
        return "✅ None detected"

    snippets = []
    for cl in clusters[:3]:
        src = _short_addr(cl.get("funding_source"))
        other_cnt = int(cl.get("other_contracts_count", 0))
        alerted_cnt = int(cl.get("alerted_contracts_count", 0))
        tot = int(cl.get("total_contracts_count", other_cnt + 1))
        alerted_tag = f", <b>{alerted_cnt} alerted</b>" if alerted_cnt > 0 else ""
        snippets.append(f"<code>{src}</code> appeared on <b>{tot} contracts</b>{alerted_tag}")
    return "⚠️ " + "; ".join(snippets)


def _format_compact_links_block(
    enrichment: EnrichmentResult,
    explorer_base_url: str = "https://etherscan.io",
    contract_address: Optional[str] = None,
    explorer_label: str = "Explorer",
) -> List[str]:
    """
    Format a compact links section at the bottom of the alert:
    - Mint link (project mint page or verified platform like Zora/Manifold/mint.fun, or explorer Write Contract fallback)
    - Marketplace links (OpenSea slug or verified minted token ID link, Magic Eden, Blur for Ethereum only, chain-specific)
    - Socials (website, X, Discord, Telegram with domain, source label 'from contract metadata, unverified', and safety flags)
    - If no public mint page or socials found: outputs 'No public mint page or socials found'
    """
    from app.explorer import build_explorer_links

    eff_explorer = (
        getattr(enrichment, "effective_explorer_base_url", None)
        or getattr(enrichment, "explorer_base_url", None)
        or getattr(enrichment, "explorer_url", None)
        or explorer_base_url
    ).rstrip("/")
    eff_family = getattr(enrichment, "effective_explorer_family", None) or getattr(enrichment, "explorer_family", None) or "etherscan"
    addr = contract_address or getattr(enrichment, "address", None) or getattr(enrichment, "contract_address", "")
    write_contract_url = build_explorer_links(eff_family, eff_explorer, address=addr)["write_contract"] or f"{eff_explorer}/address/{addr}"

    res_links = getattr(enrichment, "resolved_links", None)
    if not res_links or not isinstance(res_links, dict):
        meta_soc = getattr(enrichment, "metadata_socials", None) or {}
        os_soc = getattr(enrichment, "opensea_socials", None) or {}
        merged = {**os_soc, **meta_soc}
        if not merged:
            return [
                "🌐 <b>Links:</b> <i>No public mint page or socials found</i>",
                f'  • <b>Fallback Mint:</b> <a href="{write_contract_url}">Write Contract ({html.escape(explorer_label)})</a>',
            ]
        soc_parts = []
        for k in ("website", "twitter", "discord", "telegram"):
            u = merged.get(k)
            if u:
                dom = urllib.parse.urlparse(u).netloc.lower()
                lbl = "X" if k == "twitter" else k.capitalize()
                soc_parts.append(
                    f'<a href="{html.escape(u)}">{lbl}</a> <code>({html.escape(dom)})</code> (<code>from contract metadata, unverified</code>)'
                )
        lines = [
            "🌐 <b>Links:</b>",
            f'  • <b>Fallback Mint:</b> <a href="{write_contract_url}">Write Contract ({html.escape(explorer_label)})</a>',
        ]
        if soc_parts:
            lines.append("  • <b>Socials:</b> " + " | ".join(soc_parts))
        return lines

    has_public = bool(res_links.get("has_public_mint_or_socials"))
    mint_link = res_links.get("mint_link")
    fallback_link = res_links.get("mint_fallback_link") or {"url": write_contract_url, "title": f"Write Contract ({explorer_label})"}
    marketplaces = res_links.get("marketplaces") or []
    socials = res_links.get("socials") or {}

    lines = []
    if not has_public:
        lines.append("🌐 <b>Links:</b> <i>No public mint page or socials found</i>")
        fb_url = fallback_link.get("url") or write_contract_url
        fb_title = fallback_link.get("title") or f"Write Contract ({explorer_label})"
        lines.append(f'  • <b>Fallback Mint:</b> <a href="{html.escape(fb_url)}">{html.escape(fb_title)}</a>')
        if marketplaces:
            mp_snippets = []
            for m in marketplaces:
                mp_url = html.escape(str(m.get("url", "")))
                mp_title = html.escape(str(m.get("title", "Marketplace")))
                mp_snippets.append(f'<a href="{mp_url}">{mp_title}</a>')
            lines.append("  • <b>Marketplaces:</b> " + " | ".join(mp_snippets))
        return lines

    lines.append("🌐 <b>Links:</b>")

    # 1. Mint Link
    if mint_link and isinstance(mint_link, dict) and mint_link.get("url"):
        m_url = html.escape(str(mint_link.get("url", "")))
        m_title = html.escape(str(mint_link.get("title", "Mint")))
        m_dom = html.escape(str(mint_link.get("domain", "")))
        m_src = mint_link.get("source")
        src_tag = f" (<code>{html.escape(m_src)}</code>)" if m_src and m_src != "verified platform" else ""
        flags = mint_link.get("safety_flags") or []
        flags_tag = f" {' '.join([html.escape(f) for f in flags])}" if flags else ""
        dom_tag = f" <code>({m_dom})</code>" if m_dom else ""
        lines.append(f'  • <b>Mint:</b> <a href="{m_url}">{m_title}</a>{dom_tag}{src_tag}{flags_tag}')
    else:
        fb_url = fallback_link.get("url") or write_contract_url
        fb_title = fallback_link.get("title") or f"Write Contract ({explorer_label})"
        lines.append(f'  • <b>Mint (Fallback):</b> <a href="{html.escape(fb_url)}">{html.escape(fb_title)}</a>')

    # 2. Marketplaces
    if marketplaces:
        mp_snippets = []
        for m in marketplaces:
            mp_url = html.escape(str(m.get("url", "")))
            mp_title = html.escape(str(m.get("title", "Marketplace")))
            mp_snippets.append(f'<a href="{mp_url}">{mp_title}</a>')
        lines.append("  • <b>Marketplaces:</b> " + " | ".join(mp_snippets))

    # 3. Socials
    if socials and isinstance(socials, dict):
        soc_snippets = []
        for k in ("website", "twitter", "discord", "telegram"):
            s = socials.get(k)
            if s and isinstance(s, dict) and s.get("url"):
                s_url = html.escape(str(s.get("url", "")))
                s_title = html.escape(str(s.get("title", k.capitalize())))
                s_dom = html.escape(str(s.get("domain", "")))
                s_src = s.get("source")
                src_tag = f" (<code>{html.escape(s_src)}</code>)" if s_src else ""
                flags = s.get("safety_flags") or []
                flags_tag = f" {' '.join([html.escape(f) for f in flags])}" if flags else ""
                dom_tag = f" <code>({s_dom})</code>" if s_dom else ""
                soc_snippets.append(f'<a href="{s_url}">{s_title}</a>{dom_tag}{src_tag}{flags_tag}')
        if soc_snippets:
            lines.append("  • <b>Socials:</b> " + " | ".join(soc_snippets))

    return lines


def build_alert_message(
    contract_name: Optional[str],
    contract_symbol: Optional[str],
    stats: RollingStats,
    enrichment: EnrichmentResult,
    standard: Optional[str] = None,
    explorer_base_url: Optional[str] = None,
    trigger_block_number: Optional[int] = None,
    trigger_tx_hash: Optional[str] = None,
    risk_report: Optional[RiskScoreReport] = None,
    quality_report: Optional[QualityScoreReport] = None,
    live_check: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Construct a rich HTML formatted Telegram alert message containing watched-wallet priority banner,
    Quality Score (0-100), Alert Tier, and Risk Score at the top, chain info, contract age & deployment date,
    triggering block number & transaction hash, deployer reputation, and all on-chain, security,
    minter concentration, metadata social links, and OpenSea fields.
    Shows 'unavailable' for any field that failed or returned nothing, and 'not checked' for checks that could not run.
    Uses ✅ for safe and ⚠️ for risky flags.
    """
    addr = enrichment.contract_address
    eff_name = contract_name or enrichment.collection_name
    eff_sym = contract_symbol or enrichment.symbol
    eff_std = (
        standard
        if standard and standard not in ("UNKNOWN", "unavailable")
        else (
            enrichment.standard
            if enrichment.standard and enrichment.standard not in ("UNKNOWN", "unavailable")
            else "unavailable"
        )
    )

    chain_name = getattr(enrichment, "chain_name", None) or "Ethereum"
    chain_id = getattr(enrichment, "chain_id", None) or 1
    explorer_type = getattr(enrichment, "explorer_type", "etherscan") or "etherscan"
    eff_explorer_url = (
        explorer_base_url
        or getattr(enrichment, "effective_explorer_base_url", None)
        or getattr(enrichment, "explorer_base_url", None)
        or getattr(enrichment, "explorer_url", None)
        or "https://etherscan.io"
    ).rstrip("/")
    eff_explorer_name = (
        getattr(enrichment, "effective_explorer_name", None)
        or getattr(enrichment, "explorer_name", None)
        or _explorer_display_name(eff_explorer_url, explorer_type)
    )
    explorer_label = eff_explorer_name
    eff_explorer_family = (
        getattr(enrichment, "effective_explorer_family", None)
        or getattr(enrichment, "explorer_family", None)
        or ("blockscout" if explorer_type == "blockscout" else "etherscan")
    )

    from app.explorer import build_explorer_links
    exp_links = build_explorer_links(
        family=eff_explorer_family,
        base_url=eff_explorer_url,
        address=addr,
        tx_hash=trigger_tx_hash or getattr(enrichment, "trigger_tx_hash", None),
        block_number=trigger_block_number if trigger_block_number is not None else getattr(enrichment, "trigger_block_number", None),
        is_proxy=bool(enrichment.is_proxy),
    )
    explorer_link = exp_links["address"] or f"{eff_explorer_url}/address/{addr}"
    write_tab_link = exp_links["write_contract"] or f"{eff_explorer_url}/address/{addr}#writeContract"
    write_proxy_link = build_explorer_links(
        family=eff_explorer_family,
        base_url=eff_explorer_url,
        address=addr,
        is_proxy=True,
    )["write_contract"] or f"{eff_explorer_url}/address/{addr}#writeProxyContract"

    name_str = html.escape(eff_name) if eff_name else "unavailable"
    sym_str = html.escape(eff_sym) if eff_sym else "unavailable"

    # Contract Age, Deployment Date, and Fresh/Old Label
    deployed_ts = getattr(enrichment, "contract_deployed_timestamp", None)
    deployed_blk = getattr(enrichment, "contract_deployed_block", None)
    age_secs = getattr(enrichment, "contract_age_seconds", None)
    if age_secs is None and deployed_ts is not None and deployed_ts > 0:
        ref_ts = stats.as_of_timestamp or int(time.time())
        age_secs = max(0, ref_ts - deployed_ts)

    raw_age_fmt = getattr(enrichment, "contract_age_formatted", None)
    if raw_age_fmt and raw_age_fmt not in ("unavailable", "Unknown"):
        age_fmt = raw_age_fmt
    elif age_secs is not None:
        age_fmt = format_contract_age(age_secs)
    else:
        age_fmt = "unavailable"

    dep_date = getattr(enrichment, "contract_deployment_date", None) or format_deployment_date(deployed_ts)
    age_label = getattr(enrichment, "contract_age_label", None) or classify_contract_age(age_secs)

    if age_fmt != "unavailable":
        age_parts = [f"<code>{html.escape(age_fmt)}</code>"]
        if dep_date and deployed_blk is not None:
            age_parts.append(f"(Deployed: <code>{html.escape(dep_date)}</code>, Block <code>#{deployed_blk}</code>)")
        elif dep_date:
            age_parts.append(f"(Deployed: <code>{html.escape(dep_date)}</code>)")
        elif deployed_blk is not None:
            age_parts.append(f"(Block <code>#{deployed_blk}</code>)")
        if age_label:
            age_parts.append(f"— <b>{html.escape(age_label)}</b>")
        contract_age_str = " ".join(age_parts)
    else:
        contract_age_str = "<code>unavailable</code>"

    # Triggering Block Number & Transaction Hash
    eff_block = (
        trigger_block_number
        if trigger_block_number is not None
        else getattr(enrichment, "trigger_block_number", None)
    )
    eff_tx = trigger_tx_hash or getattr(enrichment, "trigger_tx_hash", None)

    if eff_block is not None:
        block_link = exp_links.get("block") or f"{eff_explorer_url}/block/{eff_block}"
        trigger_block_str = f'<a href="{block_link}"><code>#{eff_block}</code></a>'
    else:
        trigger_block_str = "<code>unavailable</code>"

    if eff_tx:
        tx_link = exp_links.get("tx") or f"{eff_explorer_url}/tx/{eff_tx}"
        trigger_tx_str = f'<a href="{tx_link}"><code>{_short_addr(eff_tx)}</code></a>'
    else:
        tx_link = None
        trigger_tx_str = "<code>unavailable</code>"

    # OpenSea link resolution:
    # 1. Verify that any resolved collection's contract address matches the alerted contract (`addr`).
    #    If it does not match, omit the collection link.
    # 2. Build OpenSea asset links explicitly from chain, contract address, and token ID:
    #    https://opensea.io/assets/<chain>/<contract>/<tokenId>
    # 3. If neither verified collection nor token ID is available -> "Not indexed on OpenSea yet" with NO broken link.
    os_chain_slug = getattr(enrichment, "opensea_chain_slug", "ethereum")
    recent_token_id = getattr(enrichment, "recent_token_id", None)
    clean_recent_tid = str(recent_token_id).strip() if recent_token_id is not None else ""

    os_col_contract = getattr(enrichment, "opensea_collection_contract", None)
    collection_contract_matches = (
        os_col_contract is None
        or (isinstance(os_col_contract, str) and os_col_contract.strip().lower() == addr.lower())
    )
    verified_os_slug = enrichment.opensea_slug if (enrichment.opensea_slug and collection_contract_matches) else None

    explicit_asset_link: Optional[str] = (
        f"https://opensea.io/assets/{html.escape(os_chain_slug)}/{addr}/{html.escape(clean_recent_tid)}"
        if (os_chain_slug and clean_recent_tid)
        else None
    )

    if verified_os_slug:
        collection_link = f"https://opensea.io/collection/{html.escape(verified_os_slug)}"
        opensea_link: Optional[str] = explicit_asset_link or collection_link
        if explicit_asset_link:
            os_status_str = (
                f'<a href="{collection_link}"><code>{html.escape(verified_os_slug)}</code></a> '
                f'(<a href="{explicit_asset_link}">Token #{html.escape(clean_recent_tid)}</a>)'
            )
        else:
            os_status_str = f'<a href="{collection_link}"><code>{html.escape(verified_os_slug)}</code></a>'
    elif explicit_asset_link:
        opensea_link = explicit_asset_link
        os_status_str = f'<a href="{explicit_asset_link}">Token #{html.escape(clean_recent_tid)}</a> (<code>slug unavailable</code>)'
    else:
        opensea_link = None
        os_status_str = "<code>Not indexed on OpenSea yet</code>"

    # 1. Supply
    total_sup_str = f"<code>{enrichment.total_supply:,}</code>" if enrichment.total_supply is not None else "<code>unavailable</code>"
    if enrichment.max_supply is not None:
        src = f" ({html.escape(enrichment.max_supply_source)})" if enrichment.max_supply_source else ""
        max_sup_str = f"<code>{enrichment.max_supply:,}</code>{src}"
    else:
        max_sup_str = "<code>unavailable</code>"

    # 2. Owner & Renounced status
    if enrichment.owner:
        if enrichment.is_ownership_renounced:
            owner_str = "✅ Renounced (<code>0x0000...0000</code>)"
        else:
            o_link = f"{eff_explorer_url}/address/{enrichment.owner}"
            owner_str = f'⚠️ Active Owner (<a href="{o_link}">{_short_addr(enrichment.owner)}</a>)'
    else:
        owner_str = "<code>unavailable</code>"

    # 3. Paused state
    if enrichment.is_paused is not None:
        p_src = f" via {html.escape(enrichment.paused_source)}" if enrichment.paused_source else ""
        paused_str = f"⚠️ Paused{p_src}" if enrichment.is_paused else f"✅ Active (Not Paused){p_src}"
    else:
        paused_str = "<code>unavailable</code>"

    # 4. Mint price & Mint function
    mint_price_str = f"<code>{html.escape(enrichment.mint_price_formatted)}</code>" if enrichment.mint_price_formatted else "<code>unavailable</code>"
    mint_fn_str = f"<code>{html.escape(enrichment.mint_function_name)}</code>" if enrichment.mint_function_name else "<code>unavailable</code>"

    # 5. Royalty info (ERC-2981)
    if enrichment.royalty_bps is not None:
        pct = enrichment.royalty_bps / 100.0
        flag = "✅" if pct <= 10.0 else "⚠️"
        rec_str = ""
        if enrichment.royalty_receiver:
            r_link = f"{eff_explorer_url}/address/{enrichment.royalty_receiver}"
            rec_str = f' to <a href="{r_link}">{_short_addr(enrichment.royalty_receiver)}</a>'
        royalty_str = f"{flag} <code>{pct:.1f}%</code>{rec_str}"
    else:
        royalty_str = "<code>unavailable</code>"

    # 6. tokenURI / contractURI & Reveal status & Metadata Social Links
    c_uri_status = getattr(enrichment, "contract_uri_status", None)
    t_uri_status = getattr(enrichment, "token_uri_status", None)

    if enrichment.token_uri:
        if t_uri_status in ("fetch failed", "no links in metadata"):
            token_uri_str = f"<code>{_short_uri(enrichment.token_uri)}</code> (<code>{html.escape(t_uri_status)}</code>)"
        else:
            token_uri_str = f"<code>{_short_uri(enrichment.token_uri)}</code>"
    else:
        t_fallback = t_uri_status if t_uri_status in ("not implemented", "fetch failed", "no links in metadata") else "unavailable"
        token_uri_str = f"<code>{html.escape(t_fallback)}</code>"

    if enrichment.contract_uri:
        if c_uri_status in ("fetch failed", "no links in metadata"):
            contract_uri_str = f"<code>{_short_uri(enrichment.contract_uri)}</code> (<code>{html.escape(c_uri_status)}</code>)"
        else:
            contract_uri_str = f"<code>{_short_uri(enrichment.contract_uri)}</code>"
    else:
        c_fallback = c_uri_status if c_uri_status in ("not implemented", "fetch failed", "no links in metadata") else "unavailable"
        contract_uri_str = f"<code>{html.escape(c_fallback)}</code>"

    if enrichment.is_revealed is True:
        reveal_str = f"✅ Revealed ({html.escape(enrichment.reveal_status_text)})"
    elif enrichment.is_revealed is False:
        reveal_str = f"⚠️ Unrevealed ({html.escape(enrichment.reveal_status_text)})"
    else:
        reveal_str = "<code>unavailable</code>"

    meta_socials = getattr(enrichment, "metadata_socials", None) or {}
    os_socials = getattr(enrichment, "opensea_socials", None) or {}
    social_sources = getattr(enrichment, "social_sources", None) or {}
    missing_reason = getattr(enrichment, "social_missing_reason", None)

    def _resolve_missing_social_reason() -> str:
        if missing_reason in ("not implemented", "no links in metadata", "fetch failed"):
            return missing_reason
        if c_uri_status in ("ok", "no links in metadata") or t_uri_status in ("ok", "no links in metadata") or verified_os_slug:
            return "no links in metadata"
        if c_uri_status == "fetch failed" or t_uri_status == "fetch failed":
            return "fetch failed"
        if c_uri_status == "not implemented" and t_uri_status == "not implemented":
            return "not implemented"
        return "unavailable"

    eff_missing_reason = _resolve_missing_social_reason()

    def _fmt_social_field(key: str) -> Tuple[Optional[str], Optional[str], str]:
        url = meta_socials.get(key) or os_socials.get(key)
        if url:
            src = social_sources.get(key)
            if not src:
                if key in meta_socials and meta_socials.get(key):
                    src = "via contractURI" if enrichment.contract_uri else "via tokenURI"
                else:
                    src = "via OpenSea"
            return url, src, f'<a href="{html.escape(url)}">{html.escape(url)}</a> (<code>{html.escape(src)}</code>)'
        return None, None, f"<code>{html.escape(eff_missing_reason)}</code>"

    website_url, website_src, website_str = _fmt_social_field("website")
    twitter_url, twitter_src, twitter_str = _fmt_social_field("twitter")
    discord_url, discord_src, discord_str = _fmt_social_field("discord")
    telegram_url, telegram_src, telegram_str = _fmt_social_field("telegram")

    # 7. Deployer, Deployer Age & Deployer Funding Source
    if enrichment.deployer:
        d_link = f"{eff_explorer_url}/address/{enrichment.deployer}"
        deployer_str = f'<a href="{d_link}">{_short_addr(enrichment.deployer)}</a>'
    else:
        deployer_str = "<code>unavailable</code>"

    if enrichment.deployer_age_formatted and enrichment.deployer_age_formatted not in ("Unknown", "unavailable"):
        is_mature = (
            enrichment.deployer_age_seconds is not None and enrichment.deployer_age_seconds >= 86400 * 7
        )
        age_flag = "✅" if is_mature else "⚠️"
        tx_suffix = f" ({enrichment.deployer_tx_count} txs)" if enrichment.deployer_tx_count is not None else ""
        deployer_age_str = f"{age_flag} <code>{html.escape(enrichment.deployer_age_formatted)}{tx_suffix}</code>"
    else:
        deployer_age_str = "<code>unavailable</code>"

    if enrichment.deployer_funding_source:
        m_funder = ETH_ADDRESS_RE.search(enrichment.deployer_funding_source)
        if m_funder:
            f_addr = m_funder.group(0)
            f_link = f"{eff_explorer_url}/address/{f_addr}"
            rest = html.escape(enrichment.deployer_funding_source.replace(f_addr, "")).strip()
            funding_str = f'<a href="{f_link}">{_short_addr(f_addr)}</a>' + (f" <code>{rest}</code>" if rest else "")
        else:
            funding_str = f"<code>{html.escape(enrichment.deployer_funding_source)}</code>"
    else:
        funding_str = "<code>unavailable</code>"

    if getattr(enrichment, "deployer_contracts_deployed", None) is not None:
        rep_dep = int(enrichment.deployer_contracts_deployed or 0)
        rep_90 = int(getattr(enrichment, "deployer_reached_90pct_minted", 0) or 0)
        rep_50 = int(getattr(enrichment, "deployer_owner_held_above_50pct", 0) or 0)
        rep_flag = "⚠️" if rep_50 > 0 else "✅"
        deployer_rep_str = (
            f"{rep_flag} <code>{rep_dep} deployed | {rep_90} reached ≥90% minted | "
            f"{rep_50} with &gt;50% owner-held supply</code>"
        )
    else:
        deployer_rep_str = "<code>unavailable</code>"

    # 8. Explorer Verified & Proxy Status
    if enrichment.is_source_verified is True:
        verified_str = "✅ Verified"
    elif enrichment.is_source_verified is False:
        verified_str = "⚠️ Unverified"
    else:
        verified_str = "<code>unavailable</code>"

    if enrichment.is_proxy is True:
        impl_part = ""
        if enrichment.proxy_implementation:
            impl_link = f"{eff_explorer_url}/address/{enrichment.proxy_implementation}"
            impl_part = f' (<a href="{impl_link}">{_short_addr(enrichment.proxy_implementation)}</a>)'
        proxy_str = f"⚠️ Proxy: {html.escape(enrichment.proxy_type or 'EIP-1967')}{impl_part}"
    elif enrichment.is_proxy is False:
        proxy_str = "✅ Non-Proxy"
    else:
        proxy_str = "<code>unavailable</code>"

    # 9. ABI / Bytecode Scan for Risky Functions
    rf = enrichment.risky_functions

    def _fmt_risk(category_key: str) -> str:
        if rf is None:
            return "<code>unavailable</code>"
        fn_list = rf.get(category_key) or []
        if fn_list:
            return f"⚠️ <code>{html.escape(', '.join(fn_list[:3]))}</code>"
        return "✅ None detected"

    # 10. Velocity, Self-Mints & Top-5 Minter Concentration
    window_mins = max(1, stats.window_seconds // 60)
    mpm_val = enrichment.mints_per_minute if enrichment.mints_per_minute is not None else stats.mints_per_minute

    self_mints_val = (
        enrichment.self_mints
        if getattr(enrichment, "self_mints", None) is not None
        else getattr(stats, "self_mints", 0)
    )
    self_mint_pct = getattr(enrichment, "self_mint_pct", None)
    if self_mint_pct is None and self_mints_val > 0:
        denom = stats.total_mints + self_mints_val
        if denom > 0:
            self_mint_pct = round((self_mints_val / denom) * 100.0, 1)

    if self_mint_pct is not None and self_mint_pct > 30.0:
        self_mint_flag = "⚠️ "
    elif self_mints_val == 0:
        self_mint_flag = "✅ "
    else:
        self_mint_flag = ""
    self_mint_pct_suffix = (
        f" (<code>{self_mint_pct:.1f}%</code> of total)"
        if self_mint_pct is not None and self_mints_val > 0
        else ""
    )
    self_mints_line = (
        f"  • <b>Owner/Deployer self-mints:</b> {self_mint_flag}<code>{self_mints_val}</code>{self_mint_pct_suffix}"
    )

    owner_set = {
        a.lower()
        for a in (getattr(enrichment, "owner", None), getattr(enrichment, "deployer", None))
        if a and a.lower() != "0x0000000000000000000000000000000000000000"
    }
    if enrichment.top_minters:
        conc_pct = enrichment.top5_concentration_pct or 0.0
        top1_pct = float(enrichment.top_minters[0].get("pct", 0.0) or 0.0)
        owner_top = bool(getattr(enrichment, "owner_is_top_minter", False))
        conc_flag = "⚠️" if (conc_pct > 50.0 or top1_pct > 50.0 or owner_top) else "✅"
        minter_snippets = []
        for idx, tm in enumerate(enrichment.top_minters[:5], start=1):
            m_addr = tm.get("address", "")
            m_cnt = tm.get("count", 0)
            m_pct = tm.get("pct", 0.0)
            m_link = f"{eff_explorer_url}/address/{m_addr}"
            is_owner_tag = " ⚠️ <b>(Owner/Deployer)</b>" if (tm.get("is_owner") or m_addr.lower() in owner_set) else ""
            minter_snippets.append(
                f'    {idx}. <a href="{m_link}">{_short_addr(m_addr)}</a>: <code>{m_cnt}</code> (<code>{m_pct}%</code>){is_owner_tag}'
            )
        top_minters_block = (
            f"  • <b>Top-5 Concentration:</b> {conc_flag} <code>{conc_pct}%</code>\n"
            + "\n".join(minter_snippets)
        )
    else:
        top_minters_block = "  • <b>Top-5 Concentration:</b> <code>unavailable</code>"

    # 11. OpenSea Data
    os_slug_str = f"<code>{html.escape(verified_os_slug)}</code>" if verified_os_slug else "<code>unavailable</code>"
    os_floor_str = (
        f"<code>{html.escape(enrichment.opensea_floor)}</code>"
        if (enrichment.opensea_floor and collection_contract_matches)
        else "<code>unavailable</code>"
    )
    os_listings_str = (
        f"<code>{enrichment.opensea_listings}</code>"
        if (enrichment.opensea_listings is not None and collection_contract_matches)
        else "<code>unavailable</code>"
    )
    os_vol_str = (
        f"<code>{html.escape(str(enrichment.opensea_volume_24h))}</code>"
        if (getattr(enrichment, "opensea_volume_24h", None) and collection_contract_matches)
        else "<code>unavailable</code>"
    )

    soc_links = []
    if twitter_url:
        soc_links.append(f'<a href="{html.escape(twitter_url)}">Twitter</a> (<code>{html.escape(twitter_src or "via OpenSea")}</code>)')
    if discord_url:
        soc_links.append(f'<a href="{html.escape(discord_url)}">Discord</a> (<code>{html.escape(discord_src or "via OpenSea")}</code>)')
    if website_url:
        soc_links.append(f'<a href="{html.escape(website_url)}">Website</a> (<code>{html.escape(website_src or "via OpenSea")}</code>)')
    if telegram_url:
        soc_links.append(f'<a href="{html.escape(telegram_url)}">Telegram</a> (<code>{html.escape(telegram_src or "via contractURI")}</code>)')
    os_socials_str = " | ".join(soc_links) if soc_links else f"<code>{html.escape(eff_missing_reason)}</code>"

    action_links = [
        f'<a href="{explorer_link}">{html.escape(explorer_label)}</a>',
        f'<a href="{write_tab_link}">Write Contract</a>',
    ]
    if tx_link:
        action_links.append(f'<a href="{tx_link}">Trigger Tx</a>')
    if enrichment.is_proxy:
        action_links.append(f'<a href="{write_proxy_link}">Write Proxy</a>')
    if opensea_link:
        action_links.append(f'<a href="{opensea_link}">OpenSea</a>')
    else:
        action_links.append("<code>Not indexed on OpenSea yet</code>")

    if risk_report is None:
        raw_rr = getattr(enrichment, "risk_report", None)
        if isinstance(raw_rr, dict):
            risk_report = RiskScoreReport.from_dict(raw_rr)
        elif isinstance(raw_rr, RiskScoreReport):
            risk_report = raw_rr
        else:
            risk_report = RiskScorer().evaluate(enrichment=enrichment, stats=stats)

    if quality_report is None:
        raw_qr = getattr(enrichment, "quality_report", None)
        if isinstance(raw_qr, dict):
            quality_report = QualityScoreReport.from_dict(raw_qr)
        elif isinstance(raw_qr, QualityScoreReport):
            quality_report = raw_qr
        else:
            quality_report = QualityScorer().evaluate(
                enrichment=enrichment,
                stats=stats,
                risk_report=risk_report,
            )

    priority_lines = _format_watched_wallet_priority_lines(
        getattr(enrichment, "watched_wallets_minted", None),
        eff_explorer_url,
    )
    quality_lines = _format_alert_quality_lines(quality_report)
    risk_lines = _format_alert_risk_lines(risk_report)

    header_line = (
        f"🚨 <b>HOT NFT MINT DETECTED</b> — <b>{html.escape(age_label)}</b>"
        if age_label
        else "🚨 <b>HOT NFT MINT DETECTED</b>"
    )

    status_lines = _format_live_mint_status_header(live_check, enrichment)

    chk = live_check or getattr(enrichment, "live_mint_check", None)
    if chk and isinstance(chk, dict):
        live_mins_str = chk.get("minutes_str", "not checked")
        live_sup_str = chk.get("supply_str", "not checked")
        live_paused_str = chk.get("paused_str", "not checked")
        live_sim_str = chk.get("simulation_str", "not checked")
        live_st = chk.get("status", "LIVE")
    else:
        live_st = "LIVE" if getattr(enrichment, "simulation_status", None) == "success" else "ENDED"
        live_mins_str = "not checked"
        live_sup_str = f"{enrichment.total_supply:,}" if enrichment.total_supply is not None else "not checked"
        live_paused_str = "Active (Not paused)" if enrichment.is_paused is False else ("Paused" if enrichment.is_paused is True else "not checked")
        live_sim_str = "Succeeded" if getattr(enrichment, "simulation_status", None) == "success" else "not checked"

    live_st_badge = "🟢" if live_st == "LIVE" else ("🟡" if live_st == "SLOWING" else "🔴")
    live_detail_line = (
        f"  • <b>Live-Mint Check:</b> {live_st_badge} <code>{html.escape(live_st)}</code> "
        f"(Last mint: <code>{html.escape(live_mins_str)}</code> | "
        f"Supply: <code>{html.escape(live_sup_str)}</code> | "
        f"Paused: <code>{html.escape(live_paused_str)}</code> | "
        f"Simulation: <code>{html.escape(live_sim_str)}</code>)"
    )

    lines = [
        header_line,
        "",
        *status_lines,
        "",
        *priority_lines,
        *quality_lines,
        *risk_lines,
        "",
        f"⛓ <b>Chain:</b> <b>{html.escape(chain_name)}</b> (Chain ID: <code>{chain_id}</code>)",
        f"🏷 <b>Collection:</b> <b>{name_str}</b> (<code>{sym_str}</code>)",
        f"📜 <b>Contract:</b> <a href=\"{explorer_link}\"><code>{addr}</code></a>",
        f"⏳ <b>Contract Age:</b> {contract_age_str}",
        f"🧱 <b>Trigger Block:</b> {trigger_block_str}",
        f"🔗 <b>Trigger Tx:</b> {trigger_tx_str}",
        f"💎 <b>Standard:</b> <code>{html.escape(eff_std)}</code>",
        f"📦 <b>Supply:</b> {total_sup_str} / Max: {max_sup_str}",
        "",
        "💰 <b>Mint &amp; Metadata Mechanics:</b>",
        live_detail_line,
        f"  • <b>Mint Price:</b> {mint_price_str}",
        f"  • <b>Mint Function:</b> {mint_fn_str}",
        f"  • <b>Mint Simulation:</b> {_format_mint_simulation_line(enrichment)}",
        f"  • <b>Paused State:</b> {paused_str}",
        f"  • <b>Royalty (ERC-2981):</b> {royalty_str}",
        f"  • <b>Reveal Status:</b> {reveal_str}",
        f"  • <b>tokenURI:</b> {token_uri_str}",
        f"  • <b>contractURI:</b> {contract_uri_str}",
        f"  • <b>Website:</b> {website_str}",
        f"  • <b>Twitter:</b> {twitter_str}",
        f"  • <b>Discord:</b> {discord_str}",
        f"  • <b>Telegram:</b> {telegram_str}",
        "",
        "📊 <b>Mint Velocity &amp; Concentration:</b>",
        f"  • <b>Mints/Min ({window_mins}m window):</b> <code>{mpm_val}</code>/min (<code>{stats.unique_minters}</code> minters, <code>{stats.total_mints}</code> mints)",
        self_mints_line,
        top_minters_block,
        "",
        "🔍 <b>Deployer &amp; Contract Security:</b>",
        f"  • <b>Owner:</b> {owner_str}",
        f"  • <b>Deployer:</b> {deployer_str}",
        f"  • <b>Deployer Age:</b> {deployer_age_str}",
        f"  • <b>Deployer Reputation:</b> {deployer_rep_str}",
        f"  • <b>Funding Source:</b> {funding_str}",
        f"  • <b>Bytecode Template:</b> {_format_bytecode_template_line(enrichment)}",
        f"  • <b>Other Deployer Contracts:</b> {_format_cross_chain_deployer_line(enrichment)}",
        f"  • <b>Cross-Contract Funding:</b> {_format_funding_clusters_line(enrichment)}",
        f"  • <b>Explorer Source ({html.escape(explorer_label)}):</b> {verified_str}",
        f"  • <b>Proxy (EIP-1967):</b> {proxy_str}",
        "",
        "🛡 <b>ABI / Selector Risk Scan:</b>",
        f"  • <b>Owner/Admin Mint:</b> {_fmt_risk('owner_mint')}",
        f"  • <b>Blacklist:</b> {_fmt_risk('blacklist')}",
        f"  • <b>Pausable Transfers:</b> {_fmt_risk('pausable_transfers')}",
        f"  • <b>Mutable BaseURI:</b> {_fmt_risk('set_base_uri')}",
        "",
        "🌊 <b>OpenSea Market Data:</b>",
        f"  • <b>OpenSea:</b> {os_status_str}",
        f"  • <b>Slug:</b> {os_slug_str}",
        f"  • <b>Floor:</b> {os_floor_str} | <b>Listings:</b> {os_listings_str} | <b>24h Vol:</b> {os_vol_str}",
        f"  • <b>Socials:</b> {os_socials_str}",
        "",
        *_format_compact_links_block(
            enrichment,
            explorer_base_url=explorer_base_url or eff_explorer_url,
            contract_address=addr,
            explorer_label=explorer_label,
        ),
        "",
        "🔗 " + " | ".join(action_links),
    ]

    return "\n".join(lines)


def build_mute_inline_keyboard(
    chain_id: int,
    contract_address: str,
    chain_key: str = "ethereum",
) -> Dict[str, Any]:
    """Build an inline Telegram keyboard button to mute a contract on a chain."""
    addr_norm = (contract_address or "").strip().lower()
    return {
        "inline_keyboard": [
            [
                {
                    "text": "🔇 Mute Contract",
                    "callback_data": f"mute:{int(chain_id)}:{addr_norm}",
                }
            ]
        ]
    }


def build_realert_message(
    *,
    contract_address: str,
    contract_name: Optional[str],
    contract_symbol: Optional[str],
    chain_name: str,
    chain_id: int,
    stats: RollingStats,
    enrichment: EnrichmentResult,
    previous_unique_minters: int,
    is_sold_out: bool,
    explorer_base_url: str = "https://etherscan.io",
    live_check: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a concise re-alert update message sent as a reply to the original alert
    when REALERT_AFTER_HOURS > 0 and a meaningful change occurred (unique minters doubled or sold out).
    """
    eff_explorer = (enrichment.explorer_url or explorer_base_url).rstrip("/")
    addr = contract_address or enrichment.address
    explorer_link = f"{eff_explorer}/address/{addr}"
    name_str = html.escape(contract_name or enrichment.collection_name or "Unknown")
    sym_str = html.escape(contract_symbol or enrichment.symbol or "NFT")

    reasons: List[str] = []
    if is_sold_out:
        reasons.append("🔥 <b>MINT SOLD OUT</b>")
    if stats.unique_minters >= max(1, previous_unique_minters) * 2:
        reasons.append(
            f"📈 <b>Unique Minters Doubled:</b> <code>{previous_unique_minters}</code> → <code>{stats.unique_minters}</code>"
        )
    if not reasons:
        reasons.append(f"📈 <b>Minter Surge:</b> <code>{stats.unique_minters}</code> unique minters")

    total_sup_str = f"<code>{enrichment.total_supply:,}</code>" if enrichment.total_supply is not None else "<code>unavailable</code>"
    max_sup_str = f"<code>{enrichment.max_supply:,}</code>" if enrichment.max_supply is not None else "<code>Open / Unlimited</code>"
    window_mins = max(1, stats.window_seconds // 60)

    status_lines = _format_live_mint_status_header(live_check, enrichment)

    lines = [
        f"🔔 <b>MINT UPDATE — {name_str} (<code>{sym_str}</code>)</b>",
        "",
        *status_lines,
        "",
        f"⛓ <b>Chain:</b> <b>{html.escape(chain_name)}</b> (Chain ID: <code>{chain_id}</code>)",
        f"📜 <b>Contract:</b> <a href=\"{explorer_link}\"><code>{html.escape(addr)}</code></a>",
        *([f"• {r}" for r in reasons]),
        f"• <b>Velocity ({window_mins}m):</b> <code>{stats.mints_per_minute}</code>/min (<code>{stats.unique_minters}</code> non-owner minters, <code>{stats.total_mints}</code> mints)",
        f"• <b>Supply:</b> {total_sup_str} / Max: {max_sup_str}",
        "",
        *_format_compact_links_block(
            enrichment,
            explorer_base_url=explorer_base_url,
            contract_address=addr,
            explorer_label=chain_name,
        ),
    ]
    return "\n".join(lines)


def _format_since(last_block_ts: Optional[float]) -> str:
    if last_block_ts is None:
        return "<code>Waiting...</code>"
    elapsed = max(0.0, time.time() - last_block_ts)
    if elapsed < 60:
        return f"<code>{elapsed:.1f}s ago</code>"
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    return f"<code>{mins}m {secs}s ago</code>"


def build_chains_message(
    chains: Dict[str, Any],
    subscribers: Optional[Dict[str, Any]] = None,
) -> str:
    """Build the /chains response listing all configured chains and their live state."""
    lines = [
        "⛓ <b>Configured EVM Chains</b>",
        "",
    ]
    for key, cfg in chains.items():
        is_enabled = getattr(cfg, "enabled", True)
        sub = subscribers.get(key) if subscribers else None
        if not is_enabled:
            state = "⚪ Disabled"
        elif sub is not None:
            is_polling = getattr(sub, "active_mode", None) == "polling" or getattr(cfg, "mode", "websocket") == "polling"
            is_conn = bool(getattr(sub, "ws_connected", False) or getattr(sub, "polling_connected", False) is True)
            if is_conn:
                conn_state = "🟢 Connected (Polling)" if is_polling else "🟢 Connected"
            else:
                conn_state = "🔴 Reconnecting"

            blk_num = getattr(sub, "last_block_number", None)
            blk_time = getattr(sub, "last_block_received_at", None)
            head_blk = getattr(sub, "latest_head_block", None) or blk_num
            proc_blk = getattr(sub, "_last_processed_block", None)

            if blk_num is not None:
                secs_ago = max(0, int(time.time() - blk_time)) if blk_time else 0
                lag = max(0, head_blk - proc_blk) if (head_blk is not None and proc_blk is not None) else 0
                state = f"{conn_state} | Block: #{blk_num} ({secs_ago}s ago) | Lag: {lag} blocks"
            else:
                state = f"{conn_state} | Block: #waiting | Lag: 0 blocks"
        else:
            mode_str = getattr(cfg, "mode", "websocket")
            state = f"🟢 Configured ({mode_str.capitalize()})"

        win_m = max(1, cfg.window // 60)
        cd_m = max(1, cfg.cooldown // 60)
        os_slug = cfg.opensea_chain_slug or "unavailable"
        exp_name = getattr(cfg, "effective_explorer_name", None) or getattr(cfg, "explorer_name", None) or cfg.explorer_type
        exp_url = getattr(cfg, "effective_explorer_base_url", None) or getattr(cfg, "explorer_base_url", None) or cfg.explorer_url
        lines.append(
            f"• <b>{html.escape(cfg.name)}</b> (ID: <code>{cfg.chain_id}</code>) — {state}\n"
            f"  Mode: <code>{html.escape(getattr(cfg, 'mode', 'websocket'))}</code> | "
            f"Token: <code>{html.escape(cfg.native_token_symbol)}</code> | "
            f"Explorer: <a href=\"{html.escape(exp_url)}\">{html.escape(exp_name)}</a> | "
            f"OpenSea: <code>{html.escape(os_slug)}</code>\n"
            f"  Confirmations: <code>{cfg.confirmation_depth}</code> | "
            f"Threshold: <code>{cfg.mint_threshold}</code> minters / <code>{win_m}m</code> (cooldown <code>{cd_m}m</code>)"
        )
        lines.append("")

    return "\n".join(lines).strip()


def _safe_int_metric(obj: Any, method_name: str, attr_name: str) -> int:
    if obj is None:
        return 0
    val = getattr(obj, attr_name, None)
    if isinstance(val, int) and not isinstance(val, bool) and val > 0:
        return val
    fn = getattr(obj, method_name, None)
    if callable(fn) and not asyncio.iscoroutinefunction(fn):
        try:
            res = fn()
            if asyncio.iscoroutine(res):
                res.close()
            elif isinstance(res, int) and not isinstance(res, bool):
                return res
        except Exception:
            pass
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    return 0


async def build_status_message(
    config: Any,
    db: Any,
    subscriber: Optional[Any] = None,
    rpc: Optional[Any] = None,
    subscribers: Optional[Dict[str, Any]] = None,
    rpcs: Optional[Dict[str, Any]] = None,
    chains: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the /status response message.
    Supports both multi-chain status (per-chain block number, time since last block,
    contracts tracked, connection state, RPC calls/hour, subscription events/hour,
    and 24h alert/rejection/duplicate metrics) and single-chain status.
    Always returns a complete status or explicit error diagnostics.
    """
    errors = []

    # Unpack MultiChainSubscriberManager if passed via `subscriber`
    if subscribers is None and subscriber is not None and hasattr(subscriber, "subscribers"):
        subscribers = getattr(subscriber, "subscribers")
    if rpcs is None and subscriber is not None and hasattr(subscriber, "rpcs"):
        rpcs = getattr(subscriber, "rpcs")

    # Multi-chain mode
    if subscribers and isinstance(subscribers, dict):
        per_chain_contracts: Dict[str, int] = {}
        per_chain_mints: Dict[str, int] = {}
        total_contracts = 0
        total_mints_5m = 0
        alerts_sent_24h = 0
        rejected_old_24h = 0
        rejected_unknown_age_24h = 0
        duplicates_suppressed_24h = 0

        try:
            metrics = await db.get_status_metrics(window_seconds=300)
            total_contracts = metrics.get("contracts_tracked", 0)
            total_mints_5m = metrics.get("mints_last_window", 0)
            per_chain_contracts = metrics.get("per_chain_contracts", {})
            per_chain_mints = metrics.get("per_chain_mints_last_window", {})
            alerts_sent_24h = int(metrics.get("alerts_sent_24h", 0) or 0)
            rejected_old_24h = int(metrics.get("rejected_old_24h", 0) or 0)
            rejected_unknown_age_24h = int(metrics.get("rejected_unknown_age_24h", 0) or 0)
            duplicates_suppressed_24h = int(metrics.get("duplicates_suppressed_24h", 0) or 0)
        except Exception as e:
            err_desc = redact_rpc_url(f"{type(e).__name__}: {e or repr(e)}")
            errors.append(f"SQLite query failed: {err_desc}")

        lines = [
            "📊 <b>DegenAlert Live Multi-Chain Status</b>",
            f"📜 <b>Total Contracts Tracked:</b> <code>{total_contracts}</code> | 🔥 <b>Mints (5m):</b> <code>{total_mints_5m}</code>",
            (
                f"🚨 <b>Alerts Sent (24h):</b> <code>{alerts_sent_24h}</code> | "
                f"♻️ <b>Rejected Old (24h):</b> <code>{rejected_old_24h}</code> | "
                f"❓ <b>Rejected Unknown Age (24h):</b> <code>{rejected_unknown_age_24h}</code> | "
                f"🔇 <b>Duplicates Suppressed (24h):</b> <code>{duplicates_suppressed_24h}</code>"
            ),
            "",
        ]

        # Probe HTTP RPC block numbers concurrently with a short timeout for any chain missing a recent WS block
        async def _probe_chain(chain_key: str, sub: Any) -> str:
            c_name = getattr(sub, "chain_name", chain_key.capitalize())
            c_id = getattr(sub, "chain_id", "")
            ws_ok = bool(getattr(sub, "ws_connected", False))
            is_polling = getattr(sub, "active_mode", None) == "polling"
            polling_ok = getattr(sub, "polling_connected", False) is True
            last_err = getattr(sub, "last_ws_error", None)
            last_blk = getattr(sub, "last_block_number", None)
            last_ts = getattr(sub, "last_block_received_at", None)

            chain_rpc = (rpcs or {}).get(chain_key) or getattr(sub, "rpc", None)
            if last_blk is None and chain_rpc is not None:
                try:
                    last_blk = await asyncio.wait_for(chain_rpc.eth_block_number(), timeout=3.0)
                    if last_blk:
                        sub.last_block_number = last_blk
                        if last_ts is None:
                            last_ts = time.time()
                            sub.last_block_received_at = last_ts
                except Exception as exc:
                    if not last_err:
                        last_err = redact_rpc_url(f"{type(exc).__name__}: {exc}")

            if is_polling and (polling_ok or ws_ok):
                conn_str = "Connected 🟢 (Polling)"
            elif ws_ok:
                conn_str = "Connected 🟢"
            else:
                safe_err = redact_rpc_url(str(last_err)) if last_err else "reconnecting"
                short_err = html.escape(safe_err[:60])
                conn_str = f"Reconnecting 🔴 (<code>{short_err}</code>)"

            blk_str = f"<code>#{last_blk}</code>" if last_blk is not None else "<code>Unavailable</code>"
            since_str = _format_since(last_ts)
            c_tracked = per_chain_contracts.get(chain_key.lower(), 0)
            c_mints = per_chain_mints.get(chain_key.lower(), 0)
            id_badge = f" (<code>{c_id}</code>)" if c_id else ""

            rpc_1h = _safe_int_metric(chain_rpc, "get_rpc_calls_last_hour", "rpc_calls_per_hour")
            if rpc_1h == 0:
                rpc_1h = _safe_int_metric(sub, "get_rpc_calls_last_hour", "rpc_calls_per_hour")
            sub_1h = _safe_int_metric(sub, "get_subscription_events_last_hour", "subscription_events_per_hour")

            return (
                f"⛓ <b>{html.escape(c_name)}</b>{id_badge}\n"
                f"  • <b>State:</b> {conn_str}\n"
                f"  • <b>Block:</b> {blk_str} ({since_str})\n"
                f"  • <b>Tracked:</b> <code>{c_tracked}</code> contracts | <b>5m Mints:</b> <code>{c_mints}</code>\n"
                f"  • <b>RPC Calls (1h):</b> <code>{rpc_1h}</code> | <b>Sub Events (1h):</b> <code>{sub_1h}</code>"
            )

        chain_blocks = await asyncio.gather(
            *[_probe_chain(k, s) for k, s in subscribers.items()]
        )
        lines.extend(chain_blocks)

        if errors:
            lines.append("")
            lines.append("⚠️ <b>Diagnostics / Errors:</b>")
            for err in errors:
                lines.append(f"  • <code>{html.escape(redact_rpc_url(err))}</code>")

        # Show configured disabled chains if any
        if config and hasattr(config, "get_chains"):
            try:
                all_cfg_chains = config.get_chains(only_enabled=False)
                disabled_names = [
                    f"{c.name} ({c.chain_id})"
                    for c in all_cfg_chains.values()
                    if not getattr(c, "enabled", True)
                ]
                if disabled_names:
                    lines.append("")
                    lines.append(
                        f"⚪ <b>Configured Inactive Chains ({len(disabled_names)}):</b> "
                        + ", ".join(f"<code>{html.escape(n)}</code>" for n in disabled_names)
                    )
            except Exception:
                pass

        return "\n".join(lines)

    # Single-chain fallback mode
    ws_state = "Unknown"
    if subscriber is not None:
        if getattr(subscriber, "ws_connected", False):
            ws_state = "Connected 🟢"
        else:
            last_err = getattr(subscriber, "last_ws_error", None)
            err_suffix = f" ({html.escape(redact_rpc_url(str(last_err)))})" if last_err else ""
            ws_state = f"Reconnecting 🔴{err_suffix}"

    http_rpc_state = "Unknown"
    rpc_block_num: Optional[int] = None
    if rpc is not None:
        t0 = time.monotonic()
        try:
            rpc_block_num = await rpc.eth_block_number()
            latency_ms = int((time.monotonic() - t0) * 1000)
            http_rpc_state = f"Online 🟢 ({latency_ms}ms)"
        except Exception as e:
            err_desc = redact_rpc_url(f"{type(e).__name__}: {e or repr(e)}")
            http_rpc_state = f"Error 🔴 ({html.escape(err_desc)})"
            errors.append(f"RPC check failed: {err_desc}")

    last_block = getattr(subscriber, "last_block_number", None) if subscriber else None
    last_block_ts = getattr(subscriber, "last_block_received_at", None) if subscriber else None

    effective_block = last_block or rpc_block_num
    block_str = f"<code>#{effective_block}</code>" if effective_block is not None else "<code>Unavailable</code>"

    if last_block_ts is not None:
        since_str = _format_since(last_block_ts)
    else:
        since_str = "<code>Waiting for first block...</code>"

    contracts_str = "<code>Error</code>"
    mints_5m_str = "<code>Error</code>"
    alerts_sent_24h = 0
    rejected_old_24h = 0
    rejected_unknown_age_24h = 0
    duplicates_suppressed_24h = 0
    try:
        metrics = await db.get_status_metrics(window_seconds=300)
        contracts_str = f"<code>{metrics['contracts_tracked']}</code>"
        mints_5m_str = f"<code>{metrics['mints_last_window']}</code> (total: <code>{metrics['total_mints']}</code>)"
        alerts_sent_24h = int(metrics.get("alerts_sent_24h", 0) or 0)
        rejected_old_24h = int(metrics.get("rejected_old_24h", 0) or 0)
        rejected_unknown_age_24h = int(metrics.get("rejected_unknown_age_24h", 0) or 0)
        duplicates_suppressed_24h = int(metrics.get("duplicates_suppressed_24h", 0) or 0)
    except Exception as e:
        err_desc = redact_rpc_url(f"{type(e).__name__}: {e or repr(e)}")
        errors.append(f"SQLite query failed: {err_desc}")
        contracts_str = f"<code>Error ({html.escape(type(e).__name__)})</code>"
        mints_5m_str = f"<code>Error ({html.escape(type(e).__name__)})</code>"

    rpc_1h = _safe_int_metric(rpc, "get_rpc_calls_last_hour", "rpc_calls_per_hour")
    if rpc_1h == 0:
        rpc_1h = _safe_int_metric(subscriber, "get_rpc_calls_last_hour", "rpc_calls_per_hour")
    sub_1h = _safe_int_metric(subscriber, "get_subscription_events_last_hour", "subscription_events_per_hour")

    lines = [
        "📊 <b>DegenAlert Live Status</b>",
        "",
        f"🧱 <b>Current Block:</b> {block_str}",
        f"⏱ <b>Last Block Received:</b> {since_str}",
        f"📜 <b>Contracts Tracked:</b> {contracts_str}",
        f"🔥 <b>Mints (Last 5m):</b> {mints_5m_str}",
        f"🚨 <b>Alerts Sent (24h):</b> <code>{alerts_sent_24h}</code> | ♻️ <b>Rejected Old (24h):</b> <code>{rejected_old_24h}</code>",
        f"❓ <b>Rejected Unknown Age (24h):</b> <code>{rejected_unknown_age_24h}</code> | 🔇 <b>Duplicates Suppressed (24h):</b> <code>{duplicates_suppressed_24h}</code>",
        f"📡 <b>RPC Calls (1h):</b> <code>{rpc_1h}</code> | <b>Sub Events (1h):</b> <code>{sub_1h}</code>",
        "🔌 <b>RPC Connection State:</b>",
        f"  • <b>WebSocket:</b> {ws_state}",
        f"  • <b>HTTP RPC:</b> {http_rpc_state}",
    ]

    if errors:
        lines.append("")
        lines.append("⚠️ <b>Diagnostics / Errors:</b>")
        for err in errors:
            lines.append(f"  • <code>{html.escape(redact_rpc_url(err))}</code>")

    return "\n".join(lines)


async def build_rejected_message(db: Any, limit: int = 20) -> str:
    """Build the /rejected Telegram reply listing the last N rejected contracts and why."""
    rows: List[Dict[str, Any]] = []
    if db is not None and hasattr(db, "get_recent_rejected_contracts"):
        try:
            rows = await db.get_recent_rejected_contracts(limit=limit)
        except Exception as e:
            return f"⚠️ <b>Failed querying rejected contracts:</b> <code>{html.escape(str(e))}</code>"

    lines = [
        f"🚫 <b>Last {limit} Rejected Contracts</b>",
        "",
    ]
    if not rows:
        lines.append("<i>No rejected contracts recorded yet.</i>")
        return "\n".join(lines)

    for idx, r in enumerate(rows[:limit], start=1):
        chain_key = str(r.get("chain") or "ethereum")
        addr = str(r.get("contract_address") or "")
        status = str(r.get("status") or "rejected")
        dep_date = str(r.get("deployment_date") or "unknown")
        age_fmt = str(r.get("age_formatted") or status)
        reason = str(r.get("reason") or "unspecified")
        lines.append(
            f"<b>{idx}.</b> [<code>{html.escape(chain_key)}</code>] <code>{html.escape(addr)}</code>\n"
            f"   • <b>Status:</b> <code>{html.escape(status)}</code> | <b>Deployed:</b> <code>{html.escape(dep_date)}</code> | <b>Age:</b> <code>{html.escape(age_fmt)}</code>\n"
            f"   • <b>Why:</b> {html.escape(reason)}"
        )

    return "\n".join(lines)


async def build_muted_message(db: Any, limit: int = 50) -> str:
    """Build the /muted Telegram reply listing muted contracts and how to unmute them."""
    rows: List[Dict[str, Any]] = []
    if db is not None and hasattr(db, "get_muted_contracts"):
        try:
            rows = await db.get_muted_contracts(limit=limit)
        except Exception as e:
            return f"⚠️ <b>Failed querying muted contracts:</b> <code>{html.escape(str(e))}</code>"

    lines = [
        "🔇 <b>Muted Contracts</b>",
        "",
    ]
    if not rows:
        lines.append("<i>No contracts are currently muted.</i>")
        return "\n".join(lines)

    for idx, r in enumerate(rows[:limit], start=1):
        chain_key = str(r.get("chain") or "ethereum")
        chain_id = r.get("chain_id")
        addr = str(r.get("contract_address") or "")
        reason = str(r.get("reason") or "Muted by user")
        lines.append(
            f"<b>{idx}.</b> [<code>{html.escape(chain_key)}</code> (ID: <code>{chain_id}</code>)] <code>{html.escape(addr)}</code>\n"
            f"   • <b>Reason:</b> {html.escape(reason)}\n"
            f"   • <b>Unmute:</b> <code>/unmute {html.escape(addr)} {html.escape(chain_key)}</code>"
        )

    return "\n".join(lines)


async def build_outcomes_message(db: Any, limit: int = 20) -> str:
    """Build the /outcomes Telegram reply listing the last 20 alerted contracts with their latest snapshot."""
    rows: List[Dict[str, Any]] = []
    if db is not None and hasattr(db, "get_last_alerted_outcomes"):
        try:
            rows = await db.get_last_alerted_outcomes(limit=limit)
        except Exception as e:
            return f"⚠️ <b>Failed querying outcome snapshots:</b> <code>{html.escape(str(e))}</code>"

    lines = [
        f"📈 <b>Last {limit} Alerted Contracts &amp; Latest Outcomes</b>",
        "",
    ]
    if not rows:
        lines.append("<i>No alerted contracts recorded yet.</i>")
        return "\n".join(lines)

    for idx, r in enumerate(rows[:limit], start=1):
        chain_key = str(r.get("chain") or "ethereum")
        addr = str(r.get("contract_address") or "")
        name = str(r.get("contract_name") or "Unknown")
        tier = str(r.get("alert_tier") or "Tier A")
        q_score = r.get("quality_score")
        q_str = f"{q_score}/100" if q_score is not None else "unavailable"
        r_level = str(r.get("risk_level") or "Low")
        r_score = r.get("risk_score")
        r_str = f"{r_level} ({r_score}/100)" if r_score is not None else r_level

        snap = r.get("latest_snapshot")
        if snap and isinstance(snap, dict):
            iv = str(snap.get("interval_label") or "1h")
            h_cnt = str(snap.get("holder_count") or "unavailable")
            u_cnt = str(snap.get("unique_holders") or "unavailable")
            pct_m = str(snap.get("pct_max_supply_minted") or "unavailable")
            if pct_m != "unavailable" and not pct_m.endswith("%"):
                pct_m = f"{pct_m}%"
            floor_p = str(snap.get("floor_price") or "unavailable")
            list_cnt = str(snap.get("listing_count") or "unavailable")
            vol_24h = str(snap.get("volume_24h") or "unavailable")
            snap_summary = (
                f"   • <b>Snapshot (<code>{html.escape(iv)}</code>):</b> "
                f"Holders: <code>{html.escape(h_cnt)}</code> | "
                f"Unique: <code>{html.escape(u_cnt)}</code> | "
                f"Max Supply Minted: <code>{html.escape(pct_m)}</code>\n"
                f"   • <b>Market:</b> Floor: <code>{html.escape(floor_p)}</code> | "
                f"Listings: <code>{html.escape(list_cnt)}</code> | "
                f"24h Vol: <code>{html.escape(vol_24h)}</code>"
            )
        else:
            snap_summary = "   • <b>Snapshot:</b> <code>pending (1h / 24h / 7d)</code>"

        lines.append(
            f"<b>{idx}. {html.escape(name)}</b> [<code>{html.escape(chain_key)}</code>] <code>{html.escape(addr)}</code>\n"
            f"   • <b>Tier:</b> <code>{html.escape(tier)}</code> | "
            f"<b>Quality:</b> <code>{html.escape(q_str)}</code> | "
            f"<b>Risk:</b> <code>{html.escape(r_str)}</code>\n"
            f"{snap_summary}"
        )

    return "\n".join(lines)


async def build_stats_message(db: Any) -> str:
    """Build the /stats Telegram reply showing per-tier and per-risk-level outcome averages."""
    data: Dict[str, Any] = {"by_tier": {}, "by_risk": {}}
    if db is not None and hasattr(db, "get_outcome_stats_by_tier_and_risk"):
        try:
            data = await db.get_outcome_stats_by_tier_and_risk()
        except Exception as e:
            return f"⚠️ <b>Failed querying outcome stats:</b> <code>{html.escape(str(e))}</code>"

    def _fmt_val(v: Any, suffix: str = "") -> str:
        if v is None:
            return "unavailable"
        return f"{v}{suffix}"

    def _fmt_bucket(label: str, b: Dict[str, Any]) -> str:
        alerts_n = int(b.get("alerts_count", 0) or 0)
        snaps_n = int(b.get("snapshots_count", 0) or 0)
        avg_q = _fmt_val(b.get("avg_quality_score"), "/100")
        avg_r = _fmt_val(b.get("avg_risk_score"), "/100")
        avg_uh = _fmt_val(b.get("avg_unique_holders"))
        avg_pct = _fmt_val(b.get("avg_pct_max_supply_minted"), "%")
        avg_fl = _fmt_val(b.get("avg_floor_price"), " ETH")
        avg_li = _fmt_val(b.get("avg_listing_count"))
        avg_vol = _fmt_val(b.get("avg_volume_24h"), " ETH")
        return (
            f"• <b>{html.escape(label)}</b> (Alerts: <code>{alerts_n}</code> | Snapshots: <code>{snaps_n}</code>)\n"
            f"  Avg Quality: <code>{html.escape(avg_q)}</code> | Avg Risk: <code>{html.escape(avg_r)}</code>\n"
            f"  Avg Unique Holders: <code>{html.escape(avg_uh)}</code> | Avg % Minted: <code>{html.escape(avg_pct)}</code>\n"
            f"  Avg Floor: <code>{html.escape(avg_fl)}</code> | Avg Listings: <code>{html.escape(avg_li)}</code> | Avg 24h Vol: <code>{html.escape(avg_vol)}</code>"
        )

    lines = [
        "📊 <b>Outcome Averages by Alert Tier &amp; Risk Level</b>",
        "",
        "🏆 <b>By Alert Tier:</b>",
    ]
    by_tier = data.get("by_tier") or {}
    for t_key in ("Tier A", "Tier B", "Tier C"):
        b = by_tier.get(t_key) or {"alerts_count": 0, "snapshots_count": 0}
        lines.append(_fmt_bucket(t_key, b))

    lines.append("")
    lines.append("🛡 <b>By Risk Level:</b>")
    by_risk = data.get("by_risk") or {}
    for r_key in ("Low", "Medium", "High"):
        b = by_risk.get(r_key) or {"alerts_count": 0, "snapshots_count": 0}
        lines.append(_fmt_bucket(f"Risk: {r_key}", b))

    return "\n".join(lines)


async def build_watch_list_message(db: Any) -> str:
    """Build the watchlist summary message for /watch."""
    rows: List[Dict[str, Any]] = []
    if db is not None and hasattr(db, "get_watch_wallets"):
        try:
            rows = await db.get_watch_wallets()
        except Exception as e:
            return f"⚠️ <b>Failed querying watched wallets:</b> <code>{html.escape(str(e))}</code>"

    lines = [
        "👀 <b>Smart-Wallet Watchlist</b>",
        "",
    ]
    if not rows:
        lines.append("<i>No wallets are currently on the watchlist.</i>")
    else:
        for idx, r in enumerate(rows, start=1):
            w_addr = str(r.get("wallet_address") or "")
            lbl = str(r.get("label") or "").strip()
            lbl_part = f" — <b>{html.escape(lbl)}</b>" if lbl else ""
            lines.append(
                f"<b>{idx}.</b> <code>{html.escape(w_addr)}</code>{lbl_part}\n"
                f"   • Unwatch: <code>/unwatch {html.escape(w_addr)}</code>"
            )
    lines.append("")
    lines.append("<b>Commands:</b>")
    lines.append("• <code>/watch &lt;address&gt; [label]</code> — Add a wallet to watchlist")
    lines.append("• <code>/unwatch &lt;address&gt;</code> — Remove a wallet from watchlist")
    lines.append("• <code>/suggest_wallets</code> — Review early minters from best 7d outcome collections")
    return "\n".join(lines)


async def build_suggest_wallets_message(db: Any, limit: int = 15) -> str:
    """
    Build the /suggest_wallets Telegram reply listing wallets that minted early into
    collections with the best 7d outcomes for manual review (never auto-added).
    """
    rows: List[Dict[str, Any]] = []
    if db is not None and hasattr(db, "suggest_wallets_from_best_7d_outcomes"):
        try:
            rows = await db.suggest_wallets_from_best_7d_outcomes(limit=limit)
        except Exception as e:
            return f"⚠️ <b>Failed generating wallet suggestions:</b> <code>{html.escape(str(e))}</code>"

    lines = [
        "🧠 <b>Suggested Smart Wallets (Early Minters in Best 7d Outcome Collections)</b>",
        "<i>For manual review only — no wallets are auto-added to your watchlist.</i>",
        "",
    ]
    if not rows:
        lines.append("<i>No 7d outcome snapshots with early non-owner minters available yet.</i>")
        return "\n".join(lines)

    for idx, r in enumerate(rows[:limit], start=1):
        w_addr = str(r.get("wallet_address") or "")
        col_cnt = int(r.get("collections_count", 0) or 0)
        mints_cnt = int(r.get("early_mints_count", 0) or 0)
        best_fl = r.get("best_7d_floor_eth")
        best_vol = r.get("best_7d_volume_eth")
        best_uh = r.get("best_7d_unique_holders")
        cols = r.get("collections") or []
        col_str = ", ".join(html.escape(str(c)) for c in cols[:3])

        fl_str = f"{best_fl} ETH" if best_fl is not None else "unavailable"
        vol_str = f"{best_vol} ETH" if best_vol is not None else "unavailable"
        uh_str = str(best_uh) if best_uh is not None else "unavailable"

        lines.append(
            f"<b>{idx}.</b> <code>{html.escape(w_addr)}</code>\n"
            f"   • <b>Top 7d Collections Minted Early:</b> <code>{col_cnt}</code> (<code>{mints_cnt}</code> early mints)\n"
            f"   • <b>Best 7d Outcome:</b> Floor: <code>{html.escape(fl_str)}</code> | 24h Vol: <code>{html.escape(vol_str)}</code> | Holders: <code>{html.escape(uh_str)}</code>\n"
            + (f"   • <b>Collections:</b> <code>{col_str}</code>\n" if col_str else "")
            + f"   • <b>Add manually:</b> <code>/watch {html.escape(w_addr)}</code>"
        )

    return "\n".join(lines)


def build_tier_b_digest_message(items: List[Dict[str, Any]]) -> str:
    """Build an hourly digest message summarizing queued Tier B alerts."""
    lines = [
        f"⏱ <b>Hourly Tier B Mint Digest ({len(items)} contract{'s' if len(items) != 1 else ''})</b>",
        "",
    ]
    for idx, item in enumerate(items, start=1):
        chain_key = str(item.get("chain") or "ethereum")
        addr = str(item.get("contract_address") or "")
        name = str(item.get("contract_name") or "Unknown")
        sym = str(item.get("contract_symbol") or "NFT")
        q_score = int(item.get("quality_score", 0) or 0)
        r_score = int(item.get("risk_score", 0) or 0)
        r_level = str(item.get("risk_level") or "Low")
        u_minters = int(item.get("unique_minters", 0) or 0)
        t_mints = int(item.get("total_mints", 0) or 0)
        lines.append(
            f"<b>{idx}. {html.escape(name)}</b> (<code>{html.escape(sym)}</code>) on <b>{html.escape(chain_key.capitalize())}</b>\n"
            f"   • <b>Contract:</b> <code>{html.escape(addr)}</code>\n"
            f"   • <b>Quality:</b> <code>{q_score}/100</code> | <b>Risk:</b> <code>{html.escape(r_level)} ({r_score}/100)</code>\n"
            f"   • <b>Activity:</b> <code>{u_minters}</code> unique minters (<code>{t_mints}</code> mints)"
        )
    return "\n".join(lines)


class TelegramNotifier:
    """Dispatches alerts and handles interactive commands via Telegram Bot API."""

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        is_mock: bool = False,
        simulation_mode: bool = False,
    ):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.simulation_mode = bool(simulation_mode or is_mock)
        self.is_mock = self.simulation_mode
        self._http: Optional[httpx.AsyncClient] = None
        self._polling: bool = False
        self.last_reply_markup: Optional[Dict[str, Any]] = None
        self.last_reply_to_message_id: Optional[Any] = None

    async def _get_client(self, force_new: bool = False) -> httpx.AsyncClient:
        if force_new and self._http and not self._http.is_closed:
            try:
                await self._http.aclose()
            except Exception:
                pass
            self._http = None

        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(15.0, connect=10.0),
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10, keepalive_expiry=20.0),
            )
        return self._http

    async def close(self):
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    async def get_bot_info(self) -> Optional[dict]:
        """Verify bot token and fetch bot profile via getMe."""
        if self.simulation_mode or not self.bot_token:
            return None
        from app.explorer import redact_secrets
        url = f"https://api.telegram.org/bot{self.bot_token}/getMe"
        client = await self._get_client()
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if data.get("ok"):
                return data.get("result")
        except Exception as e:
            logger.error(
                "Failed verifying Telegram bot token (%s): %s",
                type(e).__name__,
                redact_secrets(e, [self.bot_token]),
            )
        return None

    async def discover_chat_id(self) -> Optional[str]:
        """Attempt to auto-discover chat_id from recent bot updates (e.g., /start message)."""
        if self.simulation_mode or not self.bot_token:
            return None
        from app.explorer import redact_secrets
        url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
        client = await self._get_client()
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            if data.get("ok") and data.get("result"):
                for update in reversed(data["result"]):
                    for key in ("message", "channel_post", "my_chat_member", "edited_message"):
                        obj = update.get(key)
                        if obj and "chat" in obj and "id" in obj["chat"]:
                            discovered = str(obj["chat"]["id"])
                            self.chat_id = discovered
                            logger.info("Auto-discovered Telegram chat_id (✅ set)")
                            return discovered
        except Exception as e:
            logger.debug(
                "Could not auto-discover Telegram chat_id (%s): %s",
                type(e).__name__,
                redact_secrets(e, [self.bot_token]),
            )
        return None

    async def send_alert(
        self,
        text: str,
        disable_web_page_preview: bool = True,
        target_chat_id: Optional[str] = None,
        parse_mode: Optional[str] = "HTML",
        reply_markup: Optional[Dict[str, Any]] = None,
        reply_to_message_id: Optional[Any] = None,
    ) -> Optional[str]:
        """
        Send an alert message to the configured Telegram chat with retry & connection recovery.
        Supports optional inline keyboard (`reply_markup`) and replying to a prior message (`reply_to_message_id`).
        Returns the Telegram message ID if successful, or None.
        """
        self.last_reply_markup = reply_markup
        self.last_reply_to_message_id = reply_to_message_id

        if self.simulation_mode or self.is_mock:
            logger.info("=== [SIMULATION MODE TELEGRAM ALERT] ===\n%s\n========================================", text)
            return "sim-msg-id"

        if not self.bot_token:
            logger.warning("Telegram bot token missing and SIMULATION_MODE=false. Alert dropped.")
            return None

        dest_chat_id = target_chat_id or self.chat_id
        if not dest_chat_id:
            dest_chat_id = await self.discover_chat_id()

        if not dest_chat_id:
            logger.warning(
                "TELEGRAM_CHAT_ID is not set and no messages found in getUpdates. "
                "Please message @degenalert0bot on Telegram (e.g. send /start) or set TELEGRAM_CHAT_ID in .env. "
                "Logging alert to console instead:\n%s",
                text,
            )
            return None

        from app.explorer import redact_secrets
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload: Dict[str, Any] = {
            "chat_id": dest_chat_id,
            "text": text,
            "disable_web_page_preview": disable_web_page_preview,
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        if reply_to_message_id is not None:
            raw_reply_id = str(reply_to_message_id).strip()
            if raw_reply_id.isdigit():
                payload["reply_to_message_id"] = int(raw_reply_id)
                payload["allow_sending_without_reply"] = True
            elif raw_reply_id:
                payload["reply_to_message_id"] = raw_reply_id

        for attempt in range(3):
            client = await self._get_client(force_new=(attempt > 0))
            try:
                resp = await client.post(url, json=payload)
                if resp.status_code == 400 and (parse_mode or "reply_to_message_id" in payload):
                    logger.warning(
                        "Telegram sendMessage returned 400, retrying as plain text without reply_to: %s",
                        redact_secrets(resp.text, [self.bot_token]),
                    )
                    payload.pop("parse_mode", None)
                    payload.pop("reply_to_message_id", None)
                    resp = await client.post(url, json=payload)

                resp.raise_for_status()
                data = resp.json()
                if data.get("ok"):
                    msg_id = str(data["result"]["message_id"])
                    logger.info("Telegram message sent successfully (message_id=%s)", msg_id)
                    return msg_id
                else:
                    logger.error("Telegram API error response: %s", redact_secrets(data, [self.bot_token]))
                    return None
            except httpx.HTTPStatusError as e:
                logger.error(
                    "Telegram HTTP status error (attempt %d/3): HTTP status=%d - %s",
                    attempt + 1,
                    e.response.status_code,
                    redact_secrets(e.response.text, [self.bot_token]),
                )
            except Exception as e:
                logger.warning(
                    "Telegram send error (attempt %d/3) [%s]: %s",
                    attempt + 1,
                    type(e).__name__,
                    redact_secrets(e, [self.bot_token]),
                )
                if attempt < 2:
                    await asyncio.sleep(1.0 * (attempt + 1))

        logger.error("Failed sending Telegram message after 3 attempts.")
        try:
            from app.watchdog import get_warning_dispatcher
            asyncio.create_task(
                get_warning_dispatcher().notify_telegram_send_failure("Failed sending Telegram message after 3 attempts.")
            )
        except Exception:
            pass
        return None

    async def answer_callback_query(
        self,
        callback_query_id: str,
        text: Optional[str] = None,
        show_alert: bool = False,
    ) -> bool:
        """Acknowledge an inline button press via Telegram answerCallbackQuery."""
        if self.simulation_mode or self.is_mock or not self.bot_token or not callback_query_id:
            return True
        from app.explorer import redact_secrets
        url = f"https://api.telegram.org/bot{self.bot_token}/answerCallbackQuery"
        payload: Dict[str, Any] = {"callback_query_id": callback_query_id, "show_alert": show_alert}
        if text:
            payload["text"] = text
        try:
            client = await self._get_client()
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.debug(
                "Failed answering Telegram callback query (%s): %s",
                type(e).__name__,
                redact_secrets(e, [self.bot_token]),
            )
            return False

    async def handle_callback_query(
        self,
        callback_query: Dict[str, Any],
        db: Any,
        chains: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Handle inline keyboard callback queries (e.g. `mute:<chain_id>:<contract_address>`)."""
        cb_id = str(callback_query.get("id") or "")
        data = str(callback_query.get("data") or "").strip()
        msg = callback_query.get("message") or {}
        chat_id = str(msg.get("chat", {}).get("id") or self.chat_id or "")

        if data.startswith("mute:"):
            parts = data.split(":")
            if len(parts) >= 3:
                try:
                    chain_id = int(parts[1])
                except ValueError:
                    chain_id = 1
                raw_addr = parts[2]
                from eth_utils import to_checksum_address
                try:
                    checksum_addr = to_checksum_address(raw_addr)
                except Exception:
                    checksum_addr = raw_addr

                from app.db import CHAIN_ID_TO_KEY
                chain_key = CHAIN_ID_TO_KEY.get(chain_id, "ethereum")
                chain_name = chain_key.capitalize()
                if chains:
                    for ck, ccfg in chains.items():
                        if getattr(ccfg, "chain_id", None) == chain_id:
                            chain_key = ck
                            chain_name = ccfg.name
                            break

                if db is not None and hasattr(db, "mute_contract"):
                    await db.mute_contract(
                        contract_address=checksum_addr,
                        chain=chain_key,
                        chain_id=chain_id,
                        reason="Muted via inline Telegram button",
                    )

                await self.answer_callback_query(cb_id, text=f"🔇 Muted {checksum_addr[:10]}...")
                confirm = (
                    f"🔇 <b>Contract Muted:</b> <code>{html.escape(checksum_addr)}</code> on <b>{html.escape(chain_name)}</b> (Chain ID: <code>{chain_id}</code>)\n"
                    f"Use <code>/unmute {html.escape(checksum_addr)} {html.escape(chain_key)}</code> to unmute."
                )
                return await self.send_alert(confirm, target_chat_id=chat_id or None)

        if cb_id:
            await self.answer_callback_query(cb_id)
        return None

    async def handle_command(
        self,
        raw_text: str,
        chat_id: str,
        config: Any,
        db: Any,
        subscriber: Optional[Any] = None,
        rpc: Optional[Any] = None,
        pipeline: Optional[Any] = None,
        chains: Optional[Dict[str, Any]] = None,
        pipelines: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ):
        """Process a single Telegram bot command (/start, /status, /chain, /chains, /outcomes, /stats, /watch, /unwatch, /suggest_wallets, /rejected, /muted, /unmute, /test, /explain, /help)."""
        parts = raw_text.strip().split()
        cmd = parts[0].split("@")[0].lower() if parts else ""
        try:
            if chains is None and hasattr(config, "get_chains"):
                try:
                    chains = config.get_chains()
                except Exception:
                    chains = {}

            if pipelines is None and subscriber is not None and hasattr(subscriber, "pipelines"):
                pipelines = getattr(subscriber, "pipelines")

            if cmd in ("/start", "/help"):
                chain_names = ", ".join(c.name for c in chains.values()) if chains else "Ethereum"
                win_m = max(1, config.alert_window_seconds // 60)
                cd_m = max(1, config.alert_cooldown_seconds // 60)
                reply = (
                    "🟢 <b>DegenAlert Multi-Chain NFT Mint Radar Online!</b>\n\n"
                    f"✅ <b>Subscribed Chat ID:</b> <code>{chat_id}</code>\n"
                    f"⛓ <b>Active Chains:</b> <code>{html.escape(chain_names)}</code>\n"
                    f"🎯 <b>Default Threshold:</b> <code>{config.alert_min_unique_minters}</code> unique minters in <code>{win_m}m</code>\n"
                    f"⏱ <b>Default Cooldown:</b> <code>{cd_m}m</code>\n\n"
                    "<b>Available Commands:</b>\n"
                    "• /start — Bot configuration &amp; overview\n"
                    "• /status — Per-chain block height, latency, 24h alert/rejection metrics &amp; connection state\n"
                    "• /chain — List configured EVM chains with block telemetry\n"
                    "• <code>/chain enable &lt;name&gt;</code> — Enable chain &amp; start listener (Admin)\n"
                    "• <code>/chain disable &lt;name&gt;</code> — Disable chain &amp; stop listener (Admin)\n"
                    "• <code>/chain threshold &lt;name&gt; &lt;minters&gt; &lt;window_minutes&gt;</code> — Update thresholds (Admin)\n"
                    "• /outcomes — List last 20 alerted contracts with latest 1h/24h/7d snapshot\n"
                    "• /stats — Per-tier &amp; per-risk-level outcome averages\n"
                    "• <code>/watch &lt;address&gt; [label]</code> — Watch a smart wallet (or list watched wallets)\n"
                    "• <code>/unwatch &lt;address&gt;</code> — Remove a wallet from watchlist\n"
                    "• /suggest_wallets — Review early minters from best 7d outcome collections\n"
                    "• <code>/label_template &lt;address&gt; &lt;label&gt; &lt;scam|neutral|legit&gt;</code> — Label contract bytecode template\n"
                    "• /rejected — List the last 20 rejected contracts and why\n"
                    "• /muted — List all muted contracts\n"
                    "• <code>/unmute &lt;address&gt; &lt;chain&gt;</code> — Unmute a muted contract\n"
                    "• <code>/test &lt;address&gt; [chain]</code> — Run live enrichment &amp; security scan on a real contract\n"
                    "• <code>/explain &lt;address&gt; [chain]</code> — Full risk score &amp; check-by-check breakdown for a contract"
                )
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd in ("/chain", "/chains"):
                subs = getattr(subscriber, "subscribers", None) if subscriber else None
                all_chains = (
                    config.get_chains(only_enabled=False)
                    if (config and hasattr(config, "get_chains"))
                    else (chains or {})
                )

                if len(parts) == 1:
                    reply = build_chains_message(chains=all_chains, subscribers=subs)
                    await self.send_alert(reply, target_chat_id=chat_id)
                else:
                    subcmd = parts[1].lower().strip()
                    admin_id = str(
                        getattr(config, "telegram_chat_id", "")
                        or os.environ.get("TELEGRAM_CHAT_ID", "")
                        or "7590638752"
                    ).strip()
                    caller_id = str(user_id or chat_id).strip()
                    is_admin = (caller_id == admin_id) or (str(chat_id).strip() == admin_id)

                    if subcmd == "enable":
                        if not is_admin:
                            await self.send_alert(
                                "⛔ <b>Unauthorized:</b> /chain enable is restricted to the bot owner.",
                                target_chat_id=chat_id,
                            )
                            return
                        if len(parts) < 3:
                            await self.send_alert(
                                "⚠️ <b>Usage:</b> <code>/chain enable &lt;chain_name&gt;</code>",
                                target_chat_id=chat_id,
                            )
                            return
                        target_name = parts[2].lower().strip()
                        matched_key = None
                        matched_cfg = None
                        for k, c in all_chains.items():
                            c_name = getattr(c, "name", "").lower()
                            if k == target_name or c_name == target_name or c_name.replace(" ", "") == target_name:
                                matched_key = k
                                matched_cfg = c
                                break

                        if not matched_cfg:
                            avail = ", ".join(all_chains.keys())
                            await self.send_alert(
                                f"⚠️ <b>Unknown chain:</b> <code>{html.escape(target_name)}</code>.\nAvailable chains: <code>{html.escape(avail)}</code>",
                                target_chat_id=chat_id,
                            )
                            return

                        # Run pre-flight check before enabling (unless in simulation mode)
                        is_sim = getattr(self, "simulation_mode", False) or getattr(config, "simulation_mode", False)
                        preflight_passed = True
                        preflight_msg = "Pre-flight skipped in simulation mode"
                        preflight_details: Dict[str, Any] = {}

                        if not is_sim:
                            from app.chains import run_chain_preflight_check
                            preflight_passed, preflight_msg, preflight_details = await run_chain_preflight_check(matched_cfg)
                            if not preflight_passed:
                                await self.send_alert(
                                    f"❌ <b>Pre-flight Check Failed:</b> <code>{html.escape(matched_cfg.name)}</code>\n"
                                    f"• <b>Reason:</b> <code>{html.escape(preflight_msg)}</code>\n\n"
                                    f"Chain was not enabled and remains disabled.",
                                    target_chat_id=chat_id,
                                )
                                return

                        # If preflight switched from WebSocket to Polling due to rejected/failed eth_subscribe
                        if preflight_details.get("switched_to_polling"):
                            matched_cfg.mode = "polling"

                        # Set last processed block to current block so it starts from latest and doesn't backfill history
                        start_block = preflight_details.get("latest_block")
                        if start_block is not None and db is not None and hasattr(db, "set_last_processed_block"):
                            await db.set_last_processed_block(matched_key, start_block)

                        if db is not None and hasattr(db, "set_chain_enabled"):
                            await db.set_chain_enabled(matched_key, True)

                        matched_cfg.enabled = True
                        if chains is not None:
                            chains[matched_key] = matched_cfg

                        if subscriber is not None and hasattr(subscriber, "start_chain"):
                            await subscriber.start_chain(matched_key, matched_cfg, config, db, self)

                        blk_note = f"\n• <b>Starting Block:</b> <code>#{start_block}</code> (no history backfill)" if start_block else ""
                        mode_note = f"\n• <b>Mode:</b> <code>{matched_cfg.mode}</code>" + (" (switched from websocket after pre-flight)" if preflight_details.get("switched_to_polling") else "")
                        await self.send_alert(
                            f"✅ <b>Chain Enabled:</b> <code>{html.escape(matched_cfg.name)}</code> (<code>{html.escape(matched_key)}</code>)"
                            f"{mode_note}"
                            f"{blk_note}\n"
                            f"State persisted to SQLite database.",
                            target_chat_id=chat_id,
                        )

                    elif subcmd == "disable":
                        if not is_admin:
                            await self.send_alert(
                                "⛔ <b>Unauthorized:</b> /chain disable is restricted to the bot owner.",
                                target_chat_id=chat_id,
                            )
                            return
                        if len(parts) < 3:
                            await self.send_alert(
                                "⚠️ <b>Usage:</b> <code>/chain disable &lt;chain_name&gt;</code>",
                                target_chat_id=chat_id,
                            )
                            return
                        target_name = parts[2].lower().strip()
                        matched_key = None
                        matched_cfg = None
                        for k, c in all_chains.items():
                            c_name = getattr(c, "name", "").lower()
                            if k == target_name or c_name == target_name or c_name.replace(" ", "") == target_name:
                                matched_key = k
                                matched_cfg = c
                                break

                        if not matched_cfg:
                            avail = ", ".join(all_chains.keys())
                            await self.send_alert(
                                f"⚠️ <b>Unknown chain:</b> <code>{html.escape(target_name)}</code>.\nAvailable chains: <code>{html.escape(avail)}</code>",
                                target_chat_id=chat_id,
                            )
                            return

                        if db is not None and hasattr(db, "set_chain_enabled"):
                            await db.set_chain_enabled(matched_key, False)

                        matched_cfg.enabled = False
                        if chains is not None and matched_key in chains:
                            chains[matched_key].enabled = False

                        if subscriber is not None and hasattr(subscriber, "stop_chain"):
                            await subscriber.stop_chain(matched_key)

                        await self.send_alert(
                            f"🛑 <b>Chain Disabled:</b> <code>{html.escape(matched_cfg.name)}</code> (<code>{html.escape(matched_key)}</code>)\n"
                            f"State persisted to SQLite database.",
                            target_chat_id=chat_id,
                        )

                    elif subcmd == "threshold":
                        if not is_admin:
                            await self.send_alert(
                                "⛔ <b>Unauthorized:</b> /chain threshold is restricted to the bot owner.",
                                target_chat_id=chat_id,
                            )
                            return
                        if len(parts) < 5:
                            await self.send_alert(
                                "⚠️ <b>Usage:</b> <code>/chain threshold &lt;name&gt; &lt;minters&gt; &lt;window_minutes&gt;</code>",
                                target_chat_id=chat_id,
                            )
                            return
                        target_name = parts[2].lower().strip()
                        matched_key = None
                        matched_cfg = None
                        for k, c in all_chains.items():
                            c_name = getattr(c, "name", "").lower()
                            if k == target_name or c_name == target_name or c_name.replace(" ", "") == target_name:
                                matched_key = k
                                matched_cfg = c
                                break

                        if not matched_cfg:
                            avail = ", ".join(all_chains.keys())
                            await self.send_alert(
                                f"⚠️ <b>Unknown chain:</b> <code>{html.escape(target_name)}</code>.\nAvailable chains: <code>{html.escape(avail)}</code>",
                                target_chat_id=chat_id,
                            )
                            return

                        try:
                            minters = int(parts[3])
                            if minters <= 0:
                                raise ValueError
                        except ValueError:
                            await self.send_alert("⚠️ <code>minters</code> must be a positive integer.", target_chat_id=chat_id)
                            return

                        try:
                            win_min = float(parts[4])
                            if win_min <= 0:
                                raise ValueError
                            win_sec = int(round(win_min * 60))
                        except ValueError:
                            await self.send_alert("⚠️ <code>window_minutes</code> must be a positive number.", target_chat_id=chat_id)
                            return

                        if db is not None and hasattr(db, "set_chain_threshold"):
                            await db.set_chain_threshold(matched_key, minters=minters, window_seconds=win_sec)

                        matched_cfg.mint_threshold = minters
                        matched_cfg.min_mints = minters
                        matched_cfg.window = win_sec

                        if pipelines and matched_key in pipelines:
                            p = pipelines[matched_key]
                            p.min_unique_minters = minters
                            p.min_mints = minters
                            p.window_seconds = win_sec

                        await self.send_alert(
                            f"⚙️ <b>Threshold Updated:</b> <code>{html.escape(matched_cfg.name)}</code>\n"
                            f"• <b>Mint Threshold:</b> <code>{minters}</code> unique minters\n"
                            f"• <b>Window:</b> <code>{win_min:g}m</code> (<code>{win_sec}s</code>)\n"
                            f"State persisted to SQLite database.",
                            target_chat_id=chat_id,
                        )

                    else:
                        usage_msg = (
                            "⚠️ <b>Invalid /chain command syntax.</b>\n\n"
                            "Available commands:\n"
                            "• <code>/chain</code> — List configured chains and live connection state\n"
                            "• <code>/chain enable &lt;name&gt;</code> — Enable a chain\n"
                            "• <code>/chain disable &lt;name&gt;</code> — Disable a chain\n"
                            "• <code>/chain threshold &lt;name&gt; &lt;minters&gt; &lt;window_minutes&gt;</code> — Update thresholds"
                        )
                        await self.send_alert(usage_msg, target_chat_id=chat_id)

            elif cmd == "/outcomes":
                reply = await build_outcomes_message(db=db, limit=20)
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/stats":
                reply = await build_stats_message(db=db)
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/label_template":
                match = ETH_ADDRESS_RE.search(raw_text)
                if not match:
                    usage_msg = (
                        "⚠️ <b>Missing contract address or invalid arguments.</b>\n"
                        "Usage: <code>/label_template &lt;address&gt; &lt;label&gt; &lt;scam|neutral|legit&gt; [chain]</code>\n"
                        "Example: <code>/label_template 0xBd3531dA5CF5857e7CfAA92426877b022e612cf8 OpenZeppelinERC721 legit</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                from eth_utils import to_checksum_address
                target_addr = to_checksum_address(match.group(0))

                non_addr_tokens = [p for p in parts[1:] if not ETH_ADDRESS_RE.fullmatch(p)]
                valid_flags = ("scam", "neutral", "legit")

                flag: Optional[str] = None
                chain_key: str = "ethereum"
                flag_idx = -1
                for idx, tok in enumerate(non_addr_tokens):
                    if tok.lower() in valid_flags:
                        flag = tok.lower()
                        flag_idx = idx
                        break

                if not flag:
                    usage_msg = (
                        "⚠️ <b>Missing or invalid risk flag.</b>\n"
                        "Usage: <code>/label_template &lt;address&gt; &lt;label&gt; &lt;scam|neutral|legit&gt;</code>\n"
                        "Flag must be one of: <code>scam</code>, <code>neutral</code>, <code>legit</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                label_tokens = non_addr_tokens[:flag_idx]
                tail_tokens = non_addr_tokens[flag_idx + 1:]
                if tail_tokens:
                    tok_low = tail_tokens[0].lower()
                    if chains and tok_low in chains:
                        chain_key = tok_low
                    elif tok_low in ("ethereum", "base", "arbitrum", "optimism", "polygon", "robinhood"):
                        chain_key = tok_low

                label = " ".join(label_tokens).strip()
                if not label:
                    usage_msg = (
                        "⚠️ <b>Missing template label.</b>\n"
                        "Usage: <code>/label_template &lt;address&gt; &lt;label&gt; &lt;scam|neutral|legit&gt;</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                res = None
                if db is not None and hasattr(db, "label_template_by_address"):
                    res = await db.label_template_by_address(
                        contract_address=target_addr,
                        label=label,
                        risk_flag=flag,
                        chain=chain_key,
                    )

                if not res and db is not None:
                    target_rpc = None
                    if subscriber is not None and hasattr(subscriber, "rpcs") and getattr(subscriber, "rpcs"):
                        target_rpc = getattr(subscriber, "rpcs").get(chain_key)
                    if not target_rpc:
                        target_rpc = rpc
                    if not target_rpc and chains and chain_key in chains:
                        from app.rpc import EvmRpcClient
                        ccfg = chains[chain_key]
                        target_rpc = EvmRpcClient(ccfg.effective_http_rpc_url)

                    if target_rpc:
                        try:
                            code = await target_rpc.eth_get_code(target_addr)
                            if code and code != "0x" and len(code) > 2:
                                await db.record_contract_bytecode(
                                    contract_address=target_addr,
                                    bytecode=code,
                                    chain=chain_key,
                                )
                                res = await db.label_template_by_address(
                                    contract_address=target_addr,
                                    label=label,
                                    risk_flag=flag,
                                    chain=chain_key,
                                )
                        except Exception as exc:
                            logger.debug("Failed fetching bytecode for /label_template: %s", exc)

                if res:
                    t_hash = res.get("template_hash", "")
                    match_cnt = res.get("match_count", 1)
                    badge = "⚠️ <b>Scam</b>" if flag == "scam" else ("✅ <b>Legit</b>" if flag == "legit" else "ℹ️ <b>Neutral</b>")
                    reply = (
                        "🏷 <b>Bytecode Template Labeled:</b>\n"
                        f"  • <b>Contract:</b> <code>{html.escape(target_addr)}</code>\n"
                        f"  • <b>Template SHA-256:</b> <code>{html.escape(t_hash)}</code>\n"
                        f"  • <b>Label:</b> <b>{html.escape(res.get('label', label))}</b>\n"
                        f"  • <b>Risk Flag:</b> {badge}\n"
                        f"  • <b>Matching Contracts:</b> <code>{match_cnt}</code>"
                    )
                else:
                    reply = (
                        f"⚠️ <b>Could not label template:</b> No bytecode found for <code>{html.escape(target_addr)}</code> "
                        f"on <code>{html.escape(chain_key)}</code> (contract may not be deployed or is an EOA)."
                    )
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/watch":
                match = ETH_ADDRESS_RE.search(raw_text)
                if not match:
                    reply = await build_watch_list_message(db=db)
                    await self.send_alert(reply, target_chat_id=chat_id)
                    return

                from eth_utils import to_checksum_address
                target_addr = to_checksum_address(match.group(0))
                label_tokens = [p for p in parts[1:] if not ETH_ADDRESS_RE.fullmatch(p)]
                label = " ".join(label_tokens).strip() or None
                if db is not None and hasattr(db, "add_watch_wallet"):
                    await db.add_watch_wallet(target_addr, label=label, added_by=f"chat:{chat_id}")
                lbl_suffix = f" (<b>{html.escape(label)}</b>)" if label else ""
                reply = (
                    f"⭐ <b>Added Wallet to Watchlist:</b> <code>{html.escape(target_addr)}</code>{lbl_suffix}\n"
                    "Alerts will include a priority label when this wallet mints a contract, and high-priority when 2+ watched wallets mint the same contract."
                )
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/unwatch":
                match = ETH_ADDRESS_RE.search(raw_text)
                if not match:
                    usage_msg = (
                        "⚠️ <b>Missing wallet address.</b>\n"
                        "Usage: <code>/unwatch &lt;address&gt;</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                from eth_utils import to_checksum_address
                target_addr = to_checksum_address(match.group(0))
                removed = False
                if db is not None and hasattr(db, "remove_watch_wallet"):
                    removed = await db.remove_watch_wallet(target_addr)
                if removed:
                    reply = f"🗑 <b>Removed Wallet from Watchlist:</b> <code>{html.escape(target_addr)}</code>"
                else:
                    reply = f"ℹ️ Wallet <code>{html.escape(target_addr)}</code> was not on the watchlist."
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/suggest_wallets":
                reply = await build_suggest_wallets_message(db=db, limit=15)
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/rejected":
                reply = await build_rejected_message(db=db, limit=20)
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/muted":
                reply = await build_muted_message(db=db, limit=50)
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/unmute":
                match = ETH_ADDRESS_RE.search(raw_text)
                if not match:
                    avail_chains = ", ".join(chains.keys()) if chains else "ethereum"
                    usage_msg = (
                        "⚠️ <b>Missing contract address.</b>\n"
                        "Usage: <code>/unmute &lt;address&gt; &lt;chain&gt;</code>\n"
                        "Example: <code>/unmute 0xBd3531dA5CF5857e7CfAA92426877b022e612cf8 ethereum</code>\n"
                        f"Available chains: <code>{html.escape(avail_chains)}</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                from eth_utils import to_checksum_address
                target_addr = to_checksum_address(match.group(0))

                selected_chain_key: Optional[str] = None
                selected_chain_id: Optional[int] = None
                lower_tokens = [p.lower() for p in parts[1:] if not ETH_ADDRESS_RE.fullmatch(p)]

                if chains:
                    for ck, ccfg in chains.items():
                        if ck in lower_tokens or ccfg.name.lower() in lower_tokens or str(ccfg.chain_id) in lower_tokens:
                            selected_chain_key = ck
                            selected_chain_id = ccfg.chain_id
                            break

                if not selected_chain_key and lower_tokens:
                    from app.db import CHAIN_KEY_TO_ID, CHAIN_ID_TO_KEY
                    for tok in lower_tokens:
                        if tok in CHAIN_KEY_TO_ID:
                            selected_chain_key = tok
                            selected_chain_id = CHAIN_KEY_TO_ID[tok]
                            break
                        if tok.isdigit() and int(tok) in CHAIN_ID_TO_KEY:
                            selected_chain_id = int(tok)
                            selected_chain_key = CHAIN_ID_TO_KEY[selected_chain_id]
                            break

                if not selected_chain_key and db is not None and hasattr(db, "get_muted_contracts"):
                    try:
                        muted_rows = await db.get_muted_contracts(limit=100)
                        for mr in muted_rows:
                            if str(mr.get("contract_address", "")).lower() == target_addr.lower():
                                selected_chain_key = str(mr.get("chain") or "ethereum")
                                selected_chain_id = int(mr.get("chain_id") or 1)
                                break
                    except Exception:
                        pass

                selected_chain_key = selected_chain_key or "ethereum"
                unmuted = False
                if db is not None and hasattr(db, "unmute_contract"):
                    unmuted = await db.unmute_contract(
                        contract_address=target_addr,
                        chain=selected_chain_key,
                        chain_id=selected_chain_id,
                    )

                if unmuted:
                    reply = (
                        f"🔊 <b>Contract Unmuted:</b> <code>{html.escape(target_addr)}</code> on <code>{html.escape(selected_chain_key)}</code>"
                    )
                else:
                    reply = (
                        f"ℹ️ Contract <code>{html.escape(target_addr)}</code> on <code>{html.escape(selected_chain_key)}</code> was not muted (or has now been cleared)."
                    )
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/status":
                reply = await build_status_message(
                    config=config,
                    db=db,
                    subscriber=subscriber,
                    rpc=rpc,
                    chains=chains,
                )
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd in ("/heartbeat", "/hb"):
                from app.watchdog import HeartbeatReporter
                sub_map = getattr(subscriber, "subscribers", {}) if subscriber else {}
                rpc_map = getattr(subscriber, "rpcs", {}) if subscriber else {}
                hb = HeartbeatReporter(
                    db=db,
                    telegram=self,
                    subscribers=sub_map,
                    rpcs=rpc_map,
                    interval_hours=float(getattr(config, "heartbeat_interval_hours", 6.0)),
                )
                now_ts = int(time.time())
                period_sec = int(float(getattr(config, "heartbeat_interval_hours", 6.0)) * 3600.0)
                reply = await hb.build_heartbeat_message(since_timestamp=now_ts - period_sec, as_of_timestamp=now_ts)
                await self.send_alert(reply, target_chat_id=chat_id)

            elif cmd == "/explain":
                match = ETH_ADDRESS_RE.search(raw_text)
                if not match:
                    avail_chains = ", ".join(chains.keys()) if chains else "ethereum"
                    usage_msg = (
                        "⚠️ <b>Missing contract address.</b>\n"
                        "Usage: <code>/explain &lt;address&gt; [chain]</code>\n"
                        "Example: <code>/explain 0xBd3531dA5CF5857e7CfAA92426877b022e612cf8 ethereum</code>\n"
                        f"Available chains: <code>{html.escape(avail_chains)}</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                from eth_utils import to_checksum_address
                target_addr = to_checksum_address(match.group(0))

                # 1. Determine chain: explicit argument -> tracked chain in DB -> default "ethereum"
                selected_chain_key: Optional[str] = None
                if chains:
                    lower_tokens = [p.lower() for p in parts[1:] if not ETH_ADDRESS_RE.fullmatch(p)]
                    for ck, ccfg in chains.items():
                        if ck in lower_tokens or ccfg.name.lower() in lower_tokens:
                            selected_chain_key = ck
                            break

                if not selected_chain_key and db is not None and hasattr(db, "find_tracked_contract_chain"):
                    try:
                        selected_chain_key = await db.find_tracked_contract_chain(target_addr)
                    except Exception:
                        selected_chain_key = None

                selected_chain_key = selected_chain_key or "ethereum"
                chain_cfg = chains.get(selected_chain_key) if chains else None

                target_pipeline = None
                if pipelines and selected_chain_key in pipelines:
                    target_pipeline = pipelines[selected_chain_key]
                elif pipeline is not None and getattr(pipeline, "chain_key", "ethereum") == selected_chain_key:
                    target_pipeline = pipeline

                if target_pipeline is not None and hasattr(target_pipeline, "explain_contract"):
                    contract_rec, _, enrichment, risk_report = await target_pipeline.explain_contract(target_addr)
                    reply = build_explain_message(
                        contract_address=target_addr,
                        risk_report=risk_report,
                        contract_name=contract_rec.name or enrichment.collection_name,
                        contract_symbol=contract_rec.symbol or enrichment.symbol,
                        chain_name=target_pipeline.chain_name,
                        chain_id=target_pipeline.chain_id,
                        explorer_base_url=target_pipeline.explorer_url,
                    )
                    await self.send_alert(reply, target_chat_id=chat_id)
                elif db is not None and hasattr(db, "get_latest_risk_score"):
                    stored = await db.get_latest_risk_score(target_addr, chain=selected_chain_key)
                    if stored and rpc is None and target_pipeline is None:
                        contract_rec = await db.get_contract(target_addr, chain=selected_chain_key)
                        r_cfg = config.get_risk_config() if hasattr(config, "get_risk_config") else None
                        risk_report = RiskScoreReport.from_dict(
                            {
                                **stored,
                                "medium_threshold": r_cfg.medium_threshold if r_cfg else 25,
                                "high_threshold": r_cfg.high_threshold if r_cfg else 50,
                            }
                        )
                        reply = build_explain_message(
                            contract_address=target_addr,
                            risk_report=risk_report,
                            contract_name=contract_rec.name if contract_rec else None,
                            contract_symbol=contract_rec.symbol if contract_rec else None,
                            chain_name=chain_cfg.name if chain_cfg else selected_chain_key.capitalize(),
                            chain_id=chain_cfg.chain_id if chain_cfg else 1,
                            explorer_base_url=chain_cfg.explorer_url if chain_cfg else "https://etherscan.io",
                        )
                        await self.send_alert(reply, target_chat_id=chat_id)
                    else:
                        from app.pipeline import AlertPipeline
                        from app.rpc import EvmRpcClient
                        eff_rpc = rpc or EvmRpcClient(
                            chain_cfg.effective_http_rpc_url if chain_cfg else config.effective_http_rpc_url
                        )
                        temp_pipeline = AlertPipeline(
                            config=config,
                            db=db,
                            rpc=eff_rpc,
                            telegram=self,
                            chain_config=chain_cfg,
                        )
                        try:
                            contract_rec, _, enrichment, risk_report = await temp_pipeline.explain_contract(target_addr)
                            reply = build_explain_message(
                                contract_address=target_addr,
                                risk_report=risk_report,
                                contract_name=contract_rec.name or enrichment.collection_name,
                                contract_symbol=contract_rec.symbol or enrichment.symbol,
                                chain_name=temp_pipeline.chain_name,
                                chain_id=temp_pipeline.chain_id,
                                explorer_base_url=temp_pipeline.explorer_url,
                            )
                            await self.send_alert(reply, target_chat_id=chat_id)
                        finally:
                            await temp_pipeline.enricher.close()

            elif cmd == "/test":
                match = ETH_ADDRESS_RE.search(raw_text)
                if not match:
                    avail_chains = ", ".join(chains.keys()) if chains else "ethereum"
                    usage_msg = (
                        "⚠️ <b>Missing contract address.</b>\n"
                        "Usage: <code>/test &lt;address&gt; &lt;chain&gt;</code>\n"
                        "Example: <code>/test 0xBd3531dA5CF5857e7CfAA92426877b022e612cf8 ethereum</code>\n"
                        f"Available chains: <code>{html.escape(avail_chains)}</code>"
                    )
                    await self.send_alert(usage_msg, target_chat_id=chat_id)
                    return

                target_addr = match.group(0)

                # Check if user specified a chain key/name in the command (e.g. `/test 0x... base` or `/test base 0x...`)
                selected_chain_key = "ethereum"
                if chains:
                    lower_tokens = [p.lower() for p in parts[1:] if not ETH_ADDRESS_RE.fullmatch(p)]
                    for ck, ccfg in chains.items():
                        if ck in lower_tokens or ccfg.name.lower() in lower_tokens:
                            selected_chain_key = ck
                            break

                target_pipeline = None
                if pipelines and selected_chain_key in pipelines:
                    target_pipeline = pipelines[selected_chain_key]
                elif pipeline is not None:
                    target_pipeline = pipeline

                if target_pipeline is not None:
                    await target_pipeline.trigger_alert_for_address(
                        address=target_addr,
                        target_chat_id=chat_id,
                        record_alert=False,
                    )
                else:
                    from app.pipeline import AlertPipeline
                    from app.rpc import EvmRpcClient
                    chain_cfg = chains.get(selected_chain_key) if chains else None
                    eff_rpc = rpc or EvmRpcClient(
                        chain_cfg.effective_http_rpc_url if chain_cfg else config.effective_http_rpc_url
                    )
                    temp_pipeline = AlertPipeline(
                        config=config,
                        db=db,
                        rpc=eff_rpc,
                        telegram=self,
                        chain_config=chain_cfg,
                    )
                    try:
                        await temp_pipeline.trigger_alert_for_address(
                            address=target_addr,
                            target_chat_id=chat_id,
                            record_alert=False,
                        )
                    finally:
                        await temp_pipeline.enricher.close()

        except Exception as e:
            err_msg = f"⚠️ Command {cmd} failed with error: {type(e).__name__}: {e or repr(e)}"
            logger.error(err_msg)
            await self.send_alert(err_msg, target_chat_id=chat_id, parse_mode=None)

    async def start_command_listener(
        self,
        config: Any,
        db: Any,
        subscriber: Optional[Any] = None,
        rpc: Optional[Any] = None,
        pipeline: Optional[Any] = None,
        chains: Optional[Dict[str, Any]] = None,
        pipelines: Optional[Dict[str, Any]] = None,
    ):
        """Background long-polling loop to respond to commands and inline mute button callbacks."""
        if self.simulation_mode or self.is_mock or not self.bot_token:
            return

        self._polling = True
        offset: Optional[int] = None
        logger.info("Telegram command listener started (/start, /status, /chains, /rejected, /muted, /unmute, /test, /explain, /help)")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            limits=httpx.Limits(max_keepalive_connections=2, max_connections=5, keepalive_expiry=25.0),
        ) as poll_client:
            while getattr(self, "_polling", False):
                try:
                    url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
                    params = {"timeout": 15}
                    if offset is not None:
                        params["offset"] = offset

                    resp = await poll_client.get(url, params=params)
                    resp.raise_for_status()
                    data = resp.json()

                    if data.get("ok") and data.get("result"):
                        for update in data["result"]:
                            offset = update["update_id"] + 1
                            if "callback_query" in update and isinstance(update["callback_query"], dict):
                                asyncio.create_task(
                                    self.handle_callback_query(
                                        callback_query=update["callback_query"],
                                        db=db,
                                        chains=chains,
                                    )
                                )
                                continue

                            msg = update.get("message") or update.get("channel_post")
                            if not msg:
                                continue

                            chat_id = str(msg.get("chat", {}).get("id", ""))
                            text = (msg.get("text") or "").strip()
                            if not chat_id or not text:
                                continue

                            if not self.chat_id:
                                self.chat_id = chat_id

                            sender_id = str((msg.get("from") or {}).get("id") or "").strip() or chat_id
                            logger.info("Received Telegram command %r from chat_id=%s (sender_id=%s)", text, chat_id, sender_id)
                            asyncio.create_task(
                                self.handle_command(
                                    raw_text=text,
                                    chat_id=chat_id,
                                    config=config,
                                    db=db,
                                    subscriber=subscriber,
                                    rpc=rpc,
                                    pipeline=pipeline,
                                    chains=chains,
                                    pipelines=pipelines,
                                    user_id=sender_id,
                                )
                            )

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not getattr(self, "_polling", False):
                        break
                    logger.warning("Telegram command polling error (%s): %r", type(e).__name__, e)
                    await asyncio.sleep(2.0)

    def stop_command_listener(self):
        """Stop the background Telegram command listener."""
        self._polling = False


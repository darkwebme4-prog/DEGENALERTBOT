"""Web server and REST API for the Ethereum Wallet Transaction Filter."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import Any, Optional

from aiohttp import web

from app.config import Settings, get_settings
from app.wallet_filter import (
    FilterCriteria,
    WalletTransactionFilterService,
    normalize_target_address,
    parse_wallet_addresses,
    results_to_csv,
)

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _parse_optional_float(val: Any) -> Optional[float]:
    if val is None or val == "":
        return None
    try:
        parsed = float(val)
        return parsed if parsed >= 0 else None
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid numeric value: {val}") from exc


def _parse_optional_int(val: Any, default: Optional[int] = None) -> Optional[int]:
    if val is None or val == "":
        return default
    try:
        return int(val)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid integer value: {val}") from exc


SETTINGS_KEY = web.AppKey("settings", Settings)
SERVICE_KEY = web.AppKey("filter_service", WalletTransactionFilterService)


def create_web_app(
    settings: Optional[Settings] = None,
    service: Optional[WalletTransactionFilterService] = None,
) -> web.Application:
    """Create and configure the aiohttp web application."""
    cfg = settings or get_settings()
    filter_service = service or WalletTransactionFilterService(settings=cfg)

    app = web.Application(client_max_size=20 * 1024 * 1024)
    app[SETTINGS_KEY] = cfg
    app[SERVICE_KEY] = filter_service

    async def on_cleanup(app_instance: web.Application) -> None:
        svc: WalletTransactionFilterService = app_instance[SERVICE_KEY]
        await svc.close()

    app.on_cleanup.append(on_cleanup)

    async def index_handler(_request: web.Request) -> web.StreamResponse:
        index_path = STATIC_DIR / "index.html"
        if not index_path.exists():
            return web.Response(text="index.html not found", status=404)
        return web.FileResponse(index_path)

    async def config_handler(request: web.Request) -> web.Response:
        app_cfg: Settings = request.app[SETTINGS_KEY]
        chains_map = app_cfg.get_chains()
        chains_list = []
        for key, c in chains_map.items():
            chains_list.append(
                {
                    "key": key,
                    "name": c.name,
                    "chain_id": c.chain_id,
                    "symbol": c.native_token_symbol,
                    "explorer_url": c.explorer_url,
                }
            )
        if not chains_list:
            chains_list.append(
                {
                    "key": "ethereum",
                    "name": "Ethereum",
                    "chain_id": 1,
                    "symbol": "ETH",
                    "explorer_url": "https://etherscan.io",
                }
            )

        has_api_key = bool(
            (app_cfg.etherscan_api_key and app_cfg.etherscan_api_key.strip())
            or os.environ.get("ETHERSCAN_API_KEY", "").strip()
        )
        return web.json_response(
            {
                "default_chain": "ethereum",
                "chains": chains_list,
                "has_configured_api_key": has_api_key,
            }
        )

    async def parse_wallets_handler(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        raw_wallets = body.get("wallets", "")
        valid, invalid = parse_wallet_addresses(raw_wallets)
        return web.json_response(
            {
                "valid_wallets": valid,
                "valid_count": len(valid),
                "invalid_tokens": invalid[:50],
                "invalid_count": len(invalid),
            }
        )

    async def discover_senders_handler(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        try:
            target = normalize_target_address(body.get("target_address"))
            if not target:
                return web.json_response(
                    {"error": "Please enter a valid 0x target address first."},
                    status=400,
                )
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)

        chain_key = str(body.get("chain") or "ethereum").strip().lower()
        api_key_override = str(body.get("api_key") or "").strip() or None
        limit = min(max(int(body.get("limit") or 50), 1), 250)

        svc: WalletTransactionFilterService = request.app[SERVICE_KEY]
        try:
            senders = await svc.discover_senders_for_target(
                target_address=target,
                chain_key=chain_key,
                api_key_override=api_key_override,
                limit=limit,
            )
            return web.json_response(
                {
                    "target_address": target,
                    "wallets": senders,
                    "count": len(senders),
                }
            )
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=502)

    async def filter_wallets_handler(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        raw_wallets = body.get("wallets", "")
        valid_wallets, invalid_tokens = parse_wallet_addresses(raw_wallets)

        try:
            target_address = normalize_target_address(body.get("target_address"))
            if not valid_wallets and not target_address:
                return web.json_response(
                    {
                        "error": "Please paste or upload a sheet of wallet addresses (0x...) to filter.",
                        "invalid_tokens": invalid_tokens[:20],
                    },
                    status=400,
                )
            count_mode = str(body.get("count_mode") or "min").strip().lower()
            if count_mode not in {"exact", "min", "max", "range"}:
                return web.json_response(
                    {"error": f"Invalid count_mode: {count_mode}"},
                    status=400,
                )

            exact_count = _parse_optional_int(body.get("exact_count"), default=100)
            if exact_count is not None and exact_count < 0:
                return web.json_response(
                    {"error": "Transaction count cannot be negative."},
                    status=400,
                )

            min_count = _parse_optional_int(body.get("min_count"), default=None)
            max_count = _parse_optional_int(body.get("max_count"), default=None)
            min_eth = _parse_optional_float(body.get("min_eth"))
            max_eth = _parse_optional_float(body.get("max_eth"))
            if min_eth is not None and max_eth is not None and min_eth > max_eth:
                return web.json_response(
                    {"error": "min_eth cannot be greater than max_eth."},
                    status=400,
                )

            start_block = _parse_optional_int(body.get("start_block"), default=0) or 0
            end_block = _parse_optional_int(body.get("end_block"), default=99999999) or 99999999
            require_nonzero_eth = bool(body.get("require_nonzero_eth", False))
            only_successful = bool(body.get("only_successful", True))
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)

        chain_key = str(body.get("chain") or "ethereum").strip().lower()
        api_key_override = str(body.get("api_key") or "").strip() or None

        criteria = FilterCriteria(
            target_address=target_address,
            chain_key=chain_key,
            count_mode=count_mode,
            exact_count=exact_count if exact_count is not None else 100,
            min_count=min_count,
            max_count=max_count,
            min_eth=min_eth,
            max_eth=max_eth,
            require_nonzero_eth=require_nonzero_eth,
            only_successful=only_successful,
            start_block=start_block,
            end_block=end_block,
        )

        svc: WalletTransactionFilterService = request.app[SERVICE_KEY]
        try:
            data = await svc.filter_wallets(
                wallets=valid_wallets,
                criteria=criteria,
                api_key_override=api_key_override,
            )
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=502)

        data["invalid_tokens"] = invalid_tokens[:50]
        data["invalid_count"] = len(invalid_tokens)
        return web.json_response(data)

    async def export_csv_handler(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        results = body.get("results") or []
        matched_only = bool(body.get("matched_only", True))
        csv_text = results_to_csv(results, matched_only=matched_only)
        filename = "matched_wallets.csv" if matched_only else "all_scanned_wallets.csv"
        return web.Response(
            text=csv_text,
            content_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    app.router.add_get("/", index_handler)
    app.router.add_get("/api/config", config_handler)
    app.router.add_post("/api/parse-wallets", parse_wallets_handler)
    app.router.add_post("/api/discover-senders", discover_senders_handler)
    app.router.add_post("/api/filter-wallets", filter_wallets_handler)
    app.router.add_post("/api/export-csv", export_csv_handler)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Ethereum Wallet Transaction Filter Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app = create_web_app()
    logger.info("Starting Ethereum Wallet Filter website on http://%s:%d", args.host, args.port)
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

"""Main entry point for Multi-Chain EVM NFT Mint Radar & Alert Bot."""

import argparse
import asyncio
import logging
import logging.handlers
from pathlib import Path
import signal
import sys
import time
from typing import Dict

from app.chains import ChainConfig
from app.config import get_settings
from app.db import Database
from app.rpc import EvmRpcClient
from app.telegram import TelegramNotifier
from app.pipeline import AlertPipeline
from app.subscriber import WebSocketSubscriber, MultiChainSubscriberManager
from app.replay import BlockReplayer
from app.watchdog import (
    get_warning_dispatcher,
    ProcessWatchdog,
    HeartbeatReporter,
    HealthServer,
)


def setup_logging(log_level_str: str = "INFO", log_file_path: str = "logs/alertbot.log"):
    """Configure console logging and rotating file logging (max 10MB, 5 backups)."""
    level = getattr(logging, (log_level_str or "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    # Clear existing handlers to prevent duplicate lines
    for h in list(root.handlers):
        root.removeHandler(h)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 1. Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # 2. Rotating file handler (10MB max, 5 backup files)
    try:
        log_path = Path(log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(log_path),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except Exception as e:
        sys.stderr.write(f"Warning: Could not setup rotating log file at {log_file_path}: {e}\n")

    # Silence httpx request URL logging to prevent exposing bot tokens in logs
    logging.getLogger("httpx").setLevel(logging.WARNING)


# Initial default logger setup
setup_logging("INFO", "logs/alertbot.log")
logger = logging.getLogger("alertbot")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Multi-Chain EVM NFT Mint Velocity Radar & Alert Bot",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--chains-config",
        type=str,
        default=None,
        help="Path to chains.yaml configuration file",
    )
    parser.add_argument(
        "--chain",
        type=str,
        default=None,
        help="Target a specific chain key (e.g. ethereum, base, arbitrum, optimism, polygon, robinhood)",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Run in historical block replay mode instead of live WebSocket streaming",
    )
    parser.add_argument(
        "--start-block",
        type=int,
        default=None,
        help="Start block number for replay mode",
    )
    parser.add_argument(
        "--end-block",
        type=int,
        default=None,
        help="End block number for replay mode",
    )
    parser.add_argument(
        "--minters",
        type=int,
        default=None,
        help="Override mint_threshold (minimum unique minters)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help="Override window (seconds)",
    )
    parser.add_argument(
        "--min-mints",
        type=int,
        default=None,
        help="Override min_mints threshold",
    )
    parser.add_argument(
        "--cooldown",
        type=int,
        default=None,
        help="Override cooldown (seconds)",
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        help="Enable simulation mode (logs alerts to console instead of Telegram API)",
    )
    parser.add_argument(
        "--mock-telegram",
        action="store_true",
        help="Deprecated alias for --simulation",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Override SQLite database file path",
    )
    return parser


def run_startup_env_check(
    settings,
    chains: Dict[str, ChainConfig] | None = None,
) -> Dict[str, bool]:
    """
    Validate required environment variables on startup, print a checklist showing ONLY
    variable names with '✅ set' or '❌ missing' (never printing secret values),
    log clear warnings for any missing keys, and disable features that depend on them.
    """
    ws_rpc_ok = bool((settings.ws_rpc_url or "").strip())
    http_rpc_ok = bool((settings.effective_http_rpc_url or "").strip())
    tg_token_ok = bool((settings.telegram_bot_token or "").strip())
    tg_chat_ok = bool((settings.telegram_chat_id or "").strip())
    etherscan_ok = bool((settings.etherscan_api_key or "").strip())
    opensea_ok = bool((settings.opensea_api_key or "").strip())

    checklist: Dict[str, bool] = {
        "WS_RPC_URL": ws_rpc_ok,
        "HTTP_RPC_URL": http_rpc_ok,
    }

    if chains:
        for ck, cfg in list(chains.items()):
            env_name = cfg.ws_rpc_env or f"{ck.upper()}_WS_RPC_URL"
            chain_rpc_ok = bool((cfg.effective_ws_rpc_url or "").strip()) and bool(
                (cfg.effective_http_rpc_url or "").strip()
            )
            checklist[env_name] = chain_rpc_ok
            if not chain_rpc_ok:
                logger.warning(
                    "Startup check: %s is ❌ missing — disabling chain listener for %s.",
                    env_name,
                    cfg.name,
                )
                chains.pop(ck, None)

    checklist["TELEGRAM_BOT_TOKEN"] = tg_token_ok
    checklist["TELEGRAM_CHAT_ID"] = tg_chat_ok
    checklist["ETHERSCAN_API_KEY"] = etherscan_ok
    checklist["OPENSEA_API_KEY"] = opensea_ok

    print("=" * 68)
    print("      STARTUP ENVIRONMENT VARIABLE CHECKLIST")
    print("=" * 68)
    for var_name, is_set in checklist.items():
        status_str = "✅ set" if is_set else "❌ missing"
        print(f" • {var_name}: {status_str}")
    print("=" * 68)

    if not ws_rpc_ok or not http_rpc_ok:
        logger.warning(
            "Startup check: WS_RPC_URL / HTTP_RPC_URL is ❌ missing — default single-chain RPC fallback is disabled."
        )
    if not tg_token_ok:
        settings.telegram_bot_token = None
        logger.warning(
            "Startup check: TELEGRAM_BOT_TOKEN is ❌ missing — live Telegram alert dispatch and command polling are disabled."
        )
    if not tg_chat_ok:
        settings.telegram_chat_id = None
        logger.warning(
            "Startup check: TELEGRAM_CHAT_ID is ❌ missing — automatic channel alerts are disabled until chat_id is configured or discovered via /start."
        )
    if not etherscan_ok:
        settings.etherscan_api_key = None
        logger.warning(
            "Startup check: ETHERSCAN_API_KEY is ❌ missing — Etherscan V2 API lookups are disabled; falling back to Blockscout explorer instances."
        )
    if not opensea_ok:
        settings.opensea_api_key = None
        logger.warning(
            "Startup check: OPENSEA_API_KEY is ❌ missing — OpenSea v2 API collection/market lookups are disabled."
        )

    return checklist


async def run_bot(args: argparse.Namespace):
    settings = get_settings()

    if args.chains_config is not None:
        settings.chains_config_path = args.chains_config
    if args.minters is not None:
        settings.alert_min_unique_minters = args.minters
    if args.window is not None:
        settings.alert_window_seconds = args.window
    if args.min_mints is not None:
        settings.alert_min_mints = args.min_mints
    if args.cooldown is not None:
        settings.alert_cooldown_seconds = args.cooldown
    if args.db is not None:
        settings.sqlite_db_path = args.db
    if args.simulation or args.mock_telegram:
        settings.simulation_mode = True

    setup_logging(settings.log_level, settings.log_file_path)

    db = Database(settings.sqlite_db_path)
    await db.init_db()

    chains: Dict[str, ChainConfig] = settings.get_chains()

    # Apply persisted chain overrides from SQLite (enabled/disabled, threshold, window)
    try:
        overrides = await db.get_chain_overrides()
        all_configured_chains = settings.get_chains(only_enabled=False)
        for ck, ovr in overrides.items():
            if ck in all_configured_chains:
                target_c = all_configured_chains[ck]
                if ovr.get("enabled") is not None:
                    target_c.enabled = bool(ovr["enabled"])
                if ovr.get("mint_threshold") is not None:
                    target_c.mint_threshold = ovr["mint_threshold"]
                    target_c.min_mints = ovr["mint_threshold"]
                if ovr.get("window") is not None:
                    target_c.window = ovr["window"]
                if target_c.enabled:
                    chains[ck] = target_c
                elif ck in chains:
                    chains.pop(ck, None)
    except Exception as e:
        logger.warning("Could not apply SQLite chain overrides on startup: %s", e)

    if args.chain:
        ck = args.chain.lower()
        if ck not in chains:
            logger.error("Unknown chain %r. Available chains: %s", args.chain, ", ".join(chains.keys()))
            sys.exit(1)
        chains = {ck: chains[ck]}

    for cfg in chains.values():
        if args.minters is not None:
            cfg.mint_threshold = args.minters
        if args.window is not None:
            cfg.window = args.window
        if args.min_mints is not None:
            cfg.min_mints = args.min_mints
        if args.cooldown is not None:
            cfg.cooldown = args.cooldown

    # Run startup environment checklist (never prints secret values; disables features missing keys)
    env_checklist = run_startup_env_check(settings, chains)
    if not chains:
        logger.error("No active chains with valid RPC URLs remain after startup check. Exiting.")
        sys.exit(1)

    # Startup validation: for each enabled chain, call eth_chainId and refuse to run if mismatch
    for chain_key in list(chains.keys()):
        cfg = chains[chain_key]
        chk_rpc = EvmRpcClient(
            cfg.effective_http_rpc_url,
            chain_name=cfg.name,
            fallback_rpc_url=cfg.http_rpc_url,
        )
        try:
            actual_chain_id = await chk_rpc.eth_chain_id()
            if actual_chain_id != cfg.chain_id:
                logger.error(
                    "[%s] Startup chain ID verification FAILED: expected %d, got %d. Refusing to run chain.",
                    cfg.name,
                    cfg.chain_id,
                    actual_chain_id,
                )
                chains.pop(chain_key, None)
            else:
                logger.info("[%s] Startup verified eth_chainId == %d", cfg.name, actual_chain_id)
        except Exception as e:
            logger.error(
                "[%s] Startup chain ID verification error: %s. Refusing to run chain.",
                cfg.name,
                e,
            )
            chains.pop(chain_key, None)
        finally:
            await chk_rpc.close()

    if not chains:
        logger.error("No valid active chains remain after startup chain ID verification. Exiting.")
        sys.exit(1)

    telegram = TelegramNotifier(
        bot_token=settings.telegram_bot_token,
        chat_id=settings.telegram_chat_id,
        simulation_mode=settings.simulation_mode,
    )

    bot_status = "SIMULATION MODE (Console Only)"
    if not settings.simulation_mode:
        if env_checklist.get("TELEGRAM_BOT_TOKEN"):
            bot_info = await telegram.get_bot_info()
            if bot_info:
                username = bot_info.get("username", "unknown")
                if not telegram.chat_id:
                    await telegram.discover_chat_id()
                chat_status = "TELEGRAM_CHAT_ID: ✅ set" if telegram.chat_id else "waiting for /start message to auto-detect chat_id"
                bot_status = f"ACTIVE (@{username} | {chat_status})"
            else:
                bot_status = "ACTIVE (TELEGRAM_BOT_TOKEN: ✅ set)"
        else:
            bot_status = "DISABLED (TELEGRAM_BOT_TOKEN: ❌ missing)"

    print("=" * 68)
    print("      MULTI-CHAIN EVM NFT MINT VELOCITY RADAR & ALERT BOT")
    print("=" * 68)
    print(f" • Mode: {'REPLAY' if args.replay else 'LIVE MULTI-CHAIN WEBSOCKET'}")
    print(f" • Simulation Mode: {settings.simulation_mode}")
    print(f" • Chains ({len(chains)}): {', '.join(f'{c.name} ({c.chain_id})' for c in chains.values())}")
    print(f" • SQLite DB: {settings.sqlite_db_path}")
    print(f" • Telegram: {bot_status}")
    print("=" * 68)

    if args.replay:
        target_cfg = next(iter(chains.values()))
        rpc = EvmRpcClient(
            target_cfg.effective_http_rpc_url,
            chain_name=target_cfg.name,
            fallback_rpc_url=target_cfg.http_rpc_url,
        )
        pipeline = AlertPipeline(
            config=settings,
            db=db,
            rpc=rpc,
            telegram=telegram,
            chain_config=target_cfg,
        )
        if args.start_block is None or args.end_block is None:
            try:
                latest = await rpc.eth_block_number()
                start = args.start_block or (latest - 10)
                end = args.end_block or latest
            except Exception as e:
                logger.error("Could not determine latest block from RPC: %s", e)
                sys.exit(1)
        else:
            start = args.start_block
            end = args.end_block

        replayer = BlockReplayer(pipeline=pipeline, rpc=rpc)
        try:
            results = await replayer.replay_range(start_block=start, end_block=end)
            print("\n" + "=" * 68)
            print(f"Replay complete on {target_cfg.name}! Results: {results}")
            print("=" * 68)
        finally:
            await pipeline.close()
            await rpc.close()

    else:
        rpcs: Dict[str, EvmRpcClient] = {}
        pipelines: Dict[str, AlertPipeline] = {}
        subscribers: Dict[str, WebSocketSubscriber] = {}

        for chain_key, cfg in chains.items():
            rpc_client = EvmRpcClient(
                cfg.effective_http_rpc_url,
                chain_name=cfg.name,
                fallback_rpc_url=cfg.http_rpc_url,
            )
            pipe = AlertPipeline(
                config=settings,
                db=db,
                rpc=rpc_client,
                telegram=telegram,
                chain_config=cfg,
            )
            sub = WebSocketSubscriber(
                config=settings,
                pipeline=pipe,
                rpc=rpc_client,
                chain_config=cfg,
            )
            rpcs[chain_key] = rpc_client
            pipelines[chain_key] = pipe
            subscribers[chain_key] = sub

        warning_dispatcher = get_warning_dispatcher(telegram=telegram)
        warning_dispatcher.cooldown_seconds = settings.warning_cooldown_seconds

        manager = MultiChainSubscriberManager(
            subscribers=subscribers,
            pipelines=pipelines,
            rpcs=rpcs,
            warning_dispatcher=warning_dispatcher,
        )

        process_watchdog = ProcessWatchdog(timeout_seconds=settings.main_loop_watchdog_timeout_seconds)
        process_watchdog.start()

        heartbeat_reporter = HeartbeatReporter(
            db=db,
            telegram=telegram,
            subscribers=subscribers,
            rpcs=rpcs,
            interval_hours=settings.heartbeat_interval_hours,
        )

        health_server = HealthServer(
            port=settings.healthcheck_port,
            healthcheck_url=settings.healthcheck_url,
            subscribers=subscribers,
        )
        if settings.healthcheck_enabled or settings.healthcheck_url:
            await health_server.start()

        stop_event = asyncio.Event()

        def handle_signal():
            logger.info("Shutdown signal received. Stopping all chain subscribers...")
            stop_event.set()
            telegram.stop_command_listener()
            asyncio.create_task(manager.stop_all())

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, handle_signal)
            except NotImplementedError:
                pass

        default_pipeline = pipelines.get("ethereum") or next(iter(pipelines.values()))
        default_rpc = rpcs.get("ethereum") or next(iter(rpcs.values()))

        async def _run_periodic_tasks():
            last_digest_time = time.time()
            last_outcome_time = time.time()
            digest_interval = 3600
            try:
                qc = settings.get_quality_config()
                if qc and getattr(qc, "digest_interval_seconds", None):
                    digest_interval = int(qc.digest_interval_seconds)
            except Exception:
                pass

            while not stop_event.is_set():
                try:
                    await asyncio.sleep(10.0)
                    if stop_event.is_set():
                        break

                    # Signal process liveness watchdog on every tick
                    process_watchdog.heartbeat()

                    now = time.time()

                    # 1. Run due outcome snapshots (every 60s)
                    if now - last_outcome_time >= 60.0:
                        last_outcome_time = now
                        for p in pipelines.values():
                            await p.run_due_outcome_snapshots()

                    # 2. Flush Tier B digest if due
                    if now - last_digest_time >= digest_interval:
                        last_digest_time = now
                        if default_pipeline:
                            await default_pipeline.flush_hourly_digest(all_chains=True)

                    # 3. Check and send periodic heartbeat if due (default every 6 hours)
                    await heartbeat_reporter.send_heartbeat_if_due()

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.debug("Error in periodic outcome/digest loop: %s", e)

        manager_task = asyncio.create_task(manager.start_all())
        periodic_task = asyncio.create_task(_run_periodic_tasks())
        cmd_listener_task = None
        if env_checklist.get("TELEGRAM_BOT_TOKEN"):
            cmd_listener_task = asyncio.create_task(
                telegram.start_command_listener(
                    settings,
                    db,
                    subscriber=manager,
                    rpc=default_rpc,
                    pipeline=default_pipeline,
                    chains=chains,
                    pipelines=pipelines,
                )
            )
        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            telegram.stop_command_listener()
            periodic_task.cancel()
            await process_watchdog.stop()
            await health_server.stop()
            await manager.stop_all()
            tasks_to_gather = [manager_task, periodic_task]
            if cmd_listener_task is not None:
                cmd_listener_task.cancel()
                tasks_to_gather.append(cmd_listener_task)
            await asyncio.gather(*tasks_to_gather, return_exceptions=True)
            logger.info("Multi-chain alert bot shut down successfully.")


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(run_bot(args))
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")


if __name__ == "__main__":
    main()

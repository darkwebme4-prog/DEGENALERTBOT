"""Core processing pipeline: deployment detection, mint tracking, rolling window aggregation, and alerting."""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from eth_utils import to_checksum_address

from app.chains import ChainConfig
from app.config import Settings
from app.db import Database, ContractRecord, MintRecord, RollingStats
from app.detector import NftDetector
from app.enrichment import (
    ContractEnricher,
    EnrichmentResult,
    format_contract_age,
    format_deployment_date,
)
from app.explorer import BlockExplorer, create_explorer
from app.quality import QualityScorer, QualityScoreReport
from app.risk import RiskScorer, RiskScoreReport
from app.telegram import (
    TelegramNotifier,
    build_alert_message,
    build_mute_inline_keyboard,
    build_realert_message,
    build_tier_b_digest_message,
)
from app.rpc import EvmRpcClient

logger = logging.getLogger(__name__)

# Event Signatures
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE_TOPIC = "0xc3d5816c9e8027b633e30b4057d371b1479daebf26c6f0181667db600d04f7e0"
TRANSFER_BATCH_TOPIC = "0x4a390057ba5654dcefb164ad5d609bfb4f1b22c8216453529fb41f17336500a5"

ZERO_ADDRESS_32BYTES = "0x" + "0" * 64
ZERO_ADDRESS_PLAIN = "0x0000000000000000000000000000000000000000"


def _topic_to_address(topic: str) -> Optional[str]:
    """Extract checksummed address from a 32-byte hex topic."""
    if not topic:
        return None
    raw = topic.replace("0x", "")
    if len(raw) < 40:
        return None
    try:
        return to_checksum_address("0x" + raw[-40:])
    except Exception:
        return None


def is_zero_address(topic_or_addr: str) -> bool:
    """Check if address or 32-byte topic represents the zero address."""
    clean = topic_or_addr.replace("0x", "").lower()
    return bool(clean) and clean == "0" * len(clean)


async def evaluate_contract_age_gate(
    *,
    contract: ContractRecord,
    chain_key: str,
    chain_name: str,
    chain_id: Optional[int] = None,
    as_of_timestamp: int,
    max_contract_age_hours: float,
    alert_on_old_contracts: bool,
    lookup_failure_reason: Optional[str] = None,
    db: Optional[Database] = None,
) -> Tuple[bool, str, str]:
    """
    Single shared fail-closed contract age gate used across ALL alert paths
    (live detection, /test, and historical block replay).

    Returns (allowed: bool, status: str, reason: str).
    - If deployment timestamp is missing or <= 0: fails closed (`status="rejected_unknown_age"`),
      logs contract address, chain, deployment date, age, and failure reason, and stores
      `rejected_unknown_age` in SQLite (`contracts`, `rejected_contracts`, and `alert_state`).
    - If contract age exceeds `max_contract_age_hours` and `alert_on_old_contracts` is False:
      rejects (`status="rejected_old"`), logs contract address, chain, deployment date, and age,
      and caches the rejection in SQLite (`contracts`, `rejected_contracts`, and `alert_state`)
      so the same old contract isn't re-checked on every mint.
    """
    checksum_addr = to_checksum_address(contract.address)
    deployed_ts = contract.deployed_timestamp
    deployed_blk = contract.deployed_block

    if deployed_ts is None or deployed_ts <= 0:
        reason = (
            lookup_failure_reason
            or "deployment time could not be determined via explorer contract-creation, eth_getCode binary search, or trace"
        )
        status = "rejected_unknown_age"
        logger.warning(
            "🚫 [%s] Rejected contract %s | chain=%s | deployed=unknown | age=rejected_unknown_age | reason=%s",
            chain_name,
            checksum_addr,
            chain_key,
            reason,
        )
        contract.age_status = status
        contract.rejection_reason = reason
        if db is not None:
            try:
                await db.upsert_contract(contract)
            except Exception as e:
                logger.debug("Failed updating contract rejected_unknown_age status for %s: %s", checksum_addr, e)
            if hasattr(db, "record_rejected_contract"):
                try:
                    await db.record_rejected_contract(
                        contract_address=checksum_addr,
                        chain=chain_key,
                        chain_id=chain_id,
                        status=status,
                        reason=reason,
                        deployed_block=deployed_blk,
                        deployed_timestamp=None,
                        deployment_date="unknown",
                        age_seconds=None,
                        age_formatted="rejected_unknown_age",
                        rejected_at=as_of_timestamp,
                    )
                except Exception as e:
                    logger.debug("Failed recording rejected contract %s: %s", checksum_addr, e)
        return False, status, reason

    age_secs = max(0, int(as_of_timestamp) - int(deployed_ts))
    deployment_date = format_deployment_date(deployed_ts)
    age_formatted = format_contract_age(age_secs)
    max_age_secs = max_contract_age_hours * 3600.0

    if age_secs > max_age_secs and not alert_on_old_contracts:
        status = "rejected_old"
        reason = (
            f"Contract age {age_formatted} ({age_secs / 3600.0:.1f}h, deployed {deployment_date}) "
            f"exceeds MAX_CONTRACT_AGE_HOURS ({max_contract_age_hours:g}h)"
        )
        logger.info(
            "🚫 [%s] Rejected old contract %s | chain=%s | deployed=%s | age=%s (%.1fh > max %gh) | reason=%s",
            chain_name,
            checksum_addr,
            chain_key,
            deployment_date,
            age_formatted,
            age_secs / 3600.0,
            max_contract_age_hours,
            reason,
        )
        contract.age_status = status
        contract.rejection_reason = reason
        if db is not None:
            try:
                await db.upsert_contract(contract)
            except Exception as e:
                logger.debug("Failed updating contract rejected_old status for %s: %s", checksum_addr, e)
            if hasattr(db, "record_rejected_contract"):
                try:
                    await db.record_rejected_contract(
                        contract_address=checksum_addr,
                        chain=chain_key,
                        chain_id=chain_id,
                        status=status,
                        reason=reason,
                        deployed_block=deployed_blk,
                        deployed_timestamp=deployed_ts,
                        deployment_date=deployment_date,
                        age_seconds=age_secs,
                        age_formatted=age_formatted,
                        rejected_at=as_of_timestamp,
                    )
                except Exception as e:
                    logger.debug("Failed recording rejected contract %s: %s", checksum_addr, e)
        return False, status, reason

    status = "fresh" if age_secs <= max_age_secs else "old_allowed"
    contract.age_status = status
    contract.rejection_reason = None
    return True, status, "passed"


class AlertPipeline:
    """End-to-end per-chain pipeline connecting event ingestion, database rolling count, and alerting."""

    def __init__(
        self,
        config: Settings,
        db: Database,
        rpc: EvmRpcClient,
        telegram: TelegramNotifier,
        chain_config: Optional[ChainConfig] = None,
        explorer: Optional[BlockExplorer] = None,
        quality_scorer: Optional[QualityScorer] = None,
        enforce_alert_tiers: Optional[bool] = None,
    ):
        self.config = config
        self.db = db
        self.rpc = rpc
        self.telegram = telegram
        self.chain_config = chain_config

        self.chain_key = chain_config.key if chain_config else "ethereum"
        self.chain_name = chain_config.name if chain_config else "Ethereum"
        self.chain_id = chain_config.chain_id if chain_config else 1
        self.native_token_symbol = chain_config.native_token_symbol if chain_config else "ETH"
        self.native_token_decimals = (
            int(getattr(chain_config, "native_token_decimals", 18))
            if chain_config and getattr(chain_config, "native_token_decimals", None) is not None
            else 18
        )
        self.explorer_url = chain_config.explorer_url if chain_config else "https://etherscan.io"
        self.explorer_type = chain_config.explorer_type if chain_config else "etherscan"
        self.explorer_name = getattr(chain_config, "explorer_name", None) if chain_config else None
        self.explorer_base_url = (
            getattr(chain_config, "effective_explorer_base_url", None)
            or (chain_config.explorer_base_url if chain_config else None)
            or self.explorer_url
        )
        self.explorer_family = (
            getattr(chain_config, "effective_explorer_family", None)
            or getattr(chain_config, "explorer_family", None)
            or ("blockscout" if "blockscout" in (self.explorer_type or "").lower() else "etherscan")
        )
        self.explorer_api_type = (
            getattr(chain_config, "effective_explorer_api_type", None)
            or getattr(chain_config, "explorer_api_type", None)
            or self.explorer_type
        )
        self.opensea_chain_slug = chain_config.opensea_chain_slug if chain_config else "ethereum"

        self.min_unique_minters = (
            chain_config.mint_threshold if chain_config else config.alert_min_unique_minters
        )
        self.min_mints = (
            chain_config.min_mints if chain_config else config.alert_min_mints
        )
        self.window_seconds = (
            chain_config.window if chain_config else config.alert_window_seconds
        )
        self.cooldown_seconds = (
            chain_config.cooldown if chain_config else config.alert_cooldown_seconds
        )
        self.max_contract_age_hours = (
            chain_config.max_contract_age_hours
            if chain_config and getattr(chain_config, "max_contract_age_hours", None) is not None
            else getattr(config, "max_contract_age_hours", 72.0)
        )
        self.alert_on_old_contracts = (
            chain_config.alert_on_old_contracts
            if chain_config and getattr(chain_config, "alert_on_old_contracts", None) is not None
            else getattr(config, "alert_on_old_contracts", False)
        )
        self.realert_after_hours = (
            chain_config.realert_after_hours
            if chain_config and getattr(chain_config, "realert_after_hours", None) is not None
            else getattr(config, "realert_after_hours", 0.0)
        )
        self.live_mint_max_minutes = (
            float(getattr(chain_config, "live_mint_max_minutes", 10.0))
            if chain_config and getattr(chain_config, "live_mint_max_minutes", None) is not None
            else 10.0
        )
        self.slowing_mint_max_minutes = (
            float(getattr(chain_config, "slowing_mint_max_minutes", 30.0))
            if chain_config and getattr(chain_config, "slowing_mint_max_minutes", None) is not None
            else 30.0
        )

        api_key = (
            chain_config.resolve_explorer_api_key(config.etherscan_api_key)
            if chain_config
            else config.etherscan_api_key
        )
        api_base_url = (
            chain_config.explorer_api_base_url
            if chain_config
            else config.etherscan_base_url
        )
        blockscout_fallback = (
            chain_config.blockscout_fallback_url
            if chain_config
            else config.blockscout_base_url
        )

        self.explorer = explorer or create_explorer(
            explorer_type=self.explorer_type,
            explorer_url=self.explorer_base_url,
            api_base_url=api_base_url,
            chain_id=self.chain_id,
            api_key=api_key,
            native_token_symbol=self.native_token_symbol,
            native_token_decimals=self.native_token_decimals,
            blockscout_fallback_url=blockscout_fallback,
            explorer_name=self.explorer_name,
            explorer_base_url=self.explorer_base_url,
            explorer_family=self.explorer_family,
        )

        self.detector = NftDetector(rpc)
        self.risk_scorer = RiskScorer(
            config.get_risk_config() if hasattr(config, "get_risk_config") else None
        )
        self.quality_scorer = quality_scorer or QualityScorer(
            config.get_quality_config() if hasattr(config, "get_quality_config") else None
        )
        self.enforce_alert_tiers = bool(
            enforce_alert_tiers
            if enforce_alert_tiers is not None
            else (getattr(config, "enforce_alert_tiers", False) or self.quality_scorer.config.enforce_tiers)
        )
        self.enricher = ContractEnricher(
            rpc_client=rpc,
            etherscan_api_key=api_key,
            etherscan_base_url=api_base_url,
            blockscout_base_url=blockscout_fallback or self.explorer_base_url,
            opensea_api_key=config.opensea_api_key,
            opensea_base_url=config.opensea_base_url,
            db=db,
            cache_ttl_seconds=config.enrichment_cache_ttl_seconds,
            explorer=self.explorer,
            chain=self.chain_key,
            chain_name=self.chain_name,
            chain_id=self.chain_id,
            native_token_symbol=self.native_token_symbol,
            native_token_decimals=self.native_token_decimals,
            explorer_url=self.explorer_base_url,
            explorer_type=self.explorer_type,
            opensea_chain_slug=self.opensea_chain_slug,
            max_contract_age_hours=self.max_contract_age_hours,
            explorer_name=self.explorer_name,
            explorer_base_url=self.explorer_base_url,
            explorer_family=self.explorer_family,
            explorer_api_type=self.explorer_api_type,
        )
        self._non_nft_cache: set[str] = set()
        self._alert_locks: Dict[str, asyncio.Lock] = {}
        self._multi_watched_alerted: set[str] = set()

    async def initialize(self):
        """Initialize database schema."""
        await self.db.init_db()

    async def close(self):
        """Cleanup network resources."""
        await self.enricher.close()
        await self.telegram.close()

    async def process_block_deployments(self, block: Dict[str, Any]) -> List[str]:
        """
        Scan a block for contract creations, check ERC-165, and register new NFT contracts.
        Returns list of newly detected NFT contract addresses.
        """
        detected: List[str] = []
        txs = block.get("transactions", [])
        block_num = int(block.get("number", "0"), 16) if isinstance(block.get("number"), str) else block.get("number", 0)
        block_ts = int(block.get("timestamp", "0"), 16) if isinstance(block.get("timestamp"), str) else block.get("timestamp", int(time.time()))

        for tx in txs:
            if not isinstance(tx, dict):
                continue

            to_addr = tx.get("to")
            if to_addr is None or to_addr == "0x" or is_zero_address(to_addr):
                tx_hash = tx.get("hash")
                deployer = tx.get("from")
                try:
                    receipt = await self.rpc.eth_get_transaction_receipt(tx_hash)
                    if not receipt:
                        continue
                    contract_addr = receipt.get("contractAddress")
                    if not contract_addr:
                        continue

                    contract_addr = to_checksum_address(contract_addr)
                    standard, is_nft = await self.detector.detect_nft_standard(contract_addr)
                    if is_nft:
                        name, symbol = await self.detector.fetch_metadata(contract_addr)
                        record = ContractRecord(
                            address=contract_addr,
                            chain=self.chain_key,
                            standard=standard,
                            name=name,
                            symbol=symbol,
                            deployer=to_checksum_address(deployer) if deployer else None,
                            deployed_block=block_num,
                            deployed_tx_hash=tx_hash,
                            deployed_timestamp=block_ts,
                            created_at=int(time.time()),
                        )
                        await self.db.upsert_contract(record)
                        detected.append(contract_addr)
                        logger.info(
                            "✨ [%s] Deployed NFT detected: %s (%s, Name=%s, Symbol=%s, Deployer=%s)",
                            self.chain_name, contract_addr, standard, name, symbol, deployer
                        )
                    else:
                        self._non_nft_cache.add(contract_addr.lower())
                except Exception as e:
                    logger.debug("[%s] Error checking deployment tx %s: %s", self.chain_name, tx_hash, e)

        return detected

    def _effective_realert_after_hours(self) -> float:
        """Return effective REALERT_AFTER_HOURS (0 = alert once per contract and never re-alert)."""
        val = self.realert_after_hours
        if val is None or val == 0:
            cfg_val = getattr(self.config, "realert_after_hours", 0.0)
            if cfg_val:
                val = cfg_val
        return max(0.0, float(val or 0.0))

    async def parse_log_as_mint(self, log: Dict[str, Any], block_timestamp: int) -> Optional[MintRecord]:
        """
        Check if an EVM log is a mint (Transfer from 0 address) for ERC-721 or ERC-1155.
        Returns MintRecord if valid mint, else None.
        """
        topics = log.get("topics", [])
        if not topics:
            return None

        topic0 = topics[0].lower()
        contract_addr = log.get("address")
        if not contract_addr:
            return None
        contract_addr = to_checksum_address(contract_addr)
        tx_hash = log.get("transactionHash", "")
        block_num = int(log.get("blockNumber", "0"), 16) if isinstance(log.get("blockNumber"), str) else log.get("blockNumber", 0)
        raw_log_idx = log.get("logIndex", 0)
        if isinstance(raw_log_idx, str):
            try:
                log_index = int(raw_log_idx, 16) if raw_log_idx.startswith("0x") else int(raw_log_idx)
            except ValueError:
                log_index = 0
        elif isinstance(raw_log_idx, int):
            log_index = raw_log_idx
        else:
            log_index = 0

        # 1. ERC-721 Transfer: Transfer(address from, address to, uint256 tokenId)
        # Discard events client-side that lack a token ID topic (len(topics) < 4 -> ERC-20 mints).
        if topic0 == TRANSFER_TOPIC.lower():
            if len(topics) >= 4 and topics[3]:
                from_topic = topics[1]
                to_topic = topics[2]
                if is_zero_address(from_topic):
                    minter = _topic_to_address(to_topic)
                    if minter and not is_zero_address(minter):
                        token_id = str(int(topics[3], 16))
                        return MintRecord(
                            contract_address=contract_addr,
                            minter_address=minter,
                            tx_hash=tx_hash,
                            block_number=block_num,
                            timestamp=block_timestamp,
                            token_id=token_id,
                            quantity=1,
                            chain=self.chain_key,
                            chain_id=self.chain_id,
                            log_index=log_index,
                        )

        # 2. ERC-1155 TransferSingle: TransferSingle(operator, from, to, id, value)
        elif topic0 == TRANSFER_SINGLE_TOPIC.lower():
            if len(topics) >= 4:
                from_topic = topics[2]
                to_topic = topics[3]
                if is_zero_address(from_topic):
                    minter = _topic_to_address(to_topic)
                    if minter and not is_zero_address(minter):
                        raw_data = (log.get("data") or "").replace("0x", "")
                        token_id = None
                        qty = 1
                        if len(raw_data) >= 64:
                            try:
                                token_id = str(int(raw_data[:64], 16))
                                if len(raw_data) >= 128:
                                    parsed_qty = int(raw_data[64:128], 16)
                                    if 0 < parsed_qty <= 100000:
                                        qty = parsed_qty
                            except Exception:
                                pass
                        return MintRecord(
                            contract_address=contract_addr,
                            minter_address=minter,
                            tx_hash=tx_hash,
                            block_number=block_num,
                            timestamp=block_timestamp,
                            token_id=token_id,
                            quantity=qty,
                            chain=self.chain_key,
                            chain_id=self.chain_id,
                            log_index=log_index,
                        )

        # 3. ERC-1155 TransferBatch: TransferBatch(operator, from, to, ids, values)
        elif topic0 == TRANSFER_BATCH_TOPIC.lower():
            if len(topics) >= 4:
                from_topic = topics[2]
                to_topic = topics[3]
                if is_zero_address(from_topic):
                    minter = _topic_to_address(to_topic)
                    if minter and not is_zero_address(minter):
                        raw_data = (log.get("data") or "").replace("0x", "")
                        token_id = None
                        if len(raw_data) >= 256:
                            try:
                                ids_offset = int(raw_data[:64], 16) * 2
                                if len(raw_data) >= ids_offset + 128:
                                    arr_len = int(raw_data[ids_offset : ids_offset + 64], 16)
                                    if arr_len > 0:
                                        token_id = str(int(raw_data[ids_offset + 64 : ids_offset + 128], 16))
                            except Exception:
                                pass
                        return MintRecord(
                            contract_address=contract_addr,
                            minter_address=minter,
                            tx_hash=tx_hash,
                            block_number=block_num,
                            timestamp=block_timestamp,
                            token_id=token_id,
                            quantity=1,
                            chain=self.chain_key,
                            chain_id=self.chain_id,
                            log_index=log_index,
                        )

        return None

    async def ensure_contract_registered(self, contract_address: str, block_number: int, timestamp: int) -> Optional[ContractRecord]:
        """
        Verify if contract is tracked as an NFT on this chain and cache the result in SQLite.
        Called when a contract crosses the mint threshold (or is explicitly inspected).
        Returns ContractRecord if NFT, or None if non-NFT.
        """
        addr_lower = contract_address.lower()
        if addr_lower in self._non_nft_cache:
            return None

        record = await self.db.get_contract(contract_address, chain=self.chain_key)
        if record and record.standard == "NON_NFT":
            self._non_nft_cache.add(addr_lower)
            return None
        if record and record.standard in ("ERC721", "ERC1155") and (record.name is not None or record.symbol is not None):
            return record

        standard, is_nft = await self.detector.detect_nft_standard(contract_address)
        if not is_nft:
            self._non_nft_cache.add(addr_lower)
            non_nft_record = ContractRecord(
                address=contract_address,
                chain=self.chain_key,
                standard="NON_NFT",
                deployed_block=record.deployed_block if record else None,
                deployed_timestamp=record.deployed_timestamp if record else None,
                created_at=record.created_at if record else int(time.time()),
            )
            await self.db.upsert_contract(non_nft_record)
            return None

        name, symbol = await self.detector.fetch_metadata(contract_address)
        new_record = ContractRecord(
            address=contract_address,
            chain=self.chain_key,
            standard=standard,
            name=name,
            symbol=symbol,
            deployer=record.deployer if record else None,
            owner=record.owner if record else None,
            deployed_block=record.deployed_block if record else None,
            deployed_tx_hash=record.deployed_tx_hash if record else None,
            deployed_timestamp=record.deployed_timestamp if record else None,
            created_at=record.created_at if record else int(time.time()),
        )
        await self.db.upsert_contract(new_record)
        return new_record

    async def process_mint(self, mint: MintRecord) -> Optional[RollingStats]:
        """
        Process a mint event with ZERO RPC calls until the contract crosses the mint threshold:
        1. Skip known non-NFTs from cache/SQLite
        2. Deduplicate event by (chain_id, tx_hash, log_index) and store mint in SQLite
        3. Calculate rolling stats for chain window (excluding owner, deployer, and zero address)
        4. ONLY if unique minters & total mints cross threshold:
           check persistent `alert_state` (skipping muted, rejected_old, rejected_unknown_age, or already-alerted
           contracts without making RPC calls), then verify NFT standard, run enrichment calls, and trigger alert.
        """
        mint.chain = self.chain_key
        if mint.chain_id is None:
            mint.chain_id = self.chain_id
        addr_lower = mint.contract_address.lower()
        if addr_lower in self._non_nft_cache:
            return None

        existing_contract = await self.db.get_contract(mint.contract_address, chain=self.chain_key)
        if existing_contract and existing_contract.standard == "NON_NFT":
            self._non_nft_cache.add(addr_lower)
            return None

        if existing_contract is None:
            existing_contract = ContractRecord(
                address=mint.contract_address,
                chain=self.chain_key,
                standard="UNKNOWN",
                deployed_block=None,
                deployed_timestamp=None,
                created_at=int(time.time()),
            )
            await self.db.upsert_contract(existing_contract)

        rowid = await self.db.record_mint(mint)
        if rowid == 0:
            # Event (chain_id, tx_hash, log_index) was already processed; suppressed duplicate recorded in DB
            return None

        stats = await self.db.get_rolling_stats(
            contract_address=mint.contract_address,
            window_seconds=self.window_seconds,
            as_of_timestamp=mint.timestamp,
            chain=self.chain_key,
        )

        logger.debug(
            "[%s] Contract %s rolling stats: %d minters, %d mints, self_mints=%d, rate=%.2f/m (window=%ds)",
            self.chain_name, mint.contract_address, stats.unique_minters, stats.total_mints,
            stats.self_mints, stats.mints_per_minute, stats.window_seconds
        )

        watched_minters: List[Dict[str, Any]] = []
        if hasattr(self.db, "get_watched_minters_for_contract"):
            try:
                watched_minters = await self.db.get_watched_minters_for_contract(
                    mint.contract_address, chain=self.chain_key
                )
            except Exception:
                watched_minters = []
        is_watched_mint = any(
            str(w.get("wallet_address", "")).lower() == mint.minter_address.lower()
            for w in watched_minters
        )
        is_multi_watched_upgrade = (
            is_watched_mint
            and len(watched_minters) >= 2
            and addr_lower not in self._multi_watched_alerted
        )

        if (
            (stats.unique_minters >= self.min_unique_minters and stats.total_mints >= self.min_mints)
            or is_watched_mint
        ):
            lock = self._alert_locks.setdefault(addr_lower, asyncio.Lock())
            async with lock:
                # Fast-path check against persistent SQLite `alert_state` BEFORE any RPC calls
                state_row = await self.db.get_alert_state(
                    self.chain_id, mint.contract_address, chain=self.chain_key
                )
                if state_row is not None:
                    st = state_row.get("status")
                    if st == "muted":
                        await self.db.record_suppressed_duplicate(
                            chain_id=self.chain_id,
                            chain=self.chain_key,
                            contract_address=mint.contract_address,
                            tx_hash=mint.tx_hash,
                            log_index=mint.log_index,
                            duplicate_type="muted_contract",
                            reason="Contract is muted",
                            suppressed_at=mint.timestamp,
                        )
                        return stats
                    if st in ("rejected_old", "too_old") and not self.alert_on_old_contracts:
                        await self.db.record_suppressed_duplicate(
                            chain_id=self.chain_id,
                            chain=self.chain_key,
                            contract_address=mint.contract_address,
                            tx_hash=mint.tx_hash,
                            log_index=mint.log_index,
                            duplicate_type="cached_rejected_old",
                            reason="Cached rejected_old contract skipped without re-checking age",
                            suppressed_at=mint.timestamp,
                        )
                        return stats
                    if st in ("rejected_unknown_age", "age_unknown"):
                        await self.db.record_suppressed_duplicate(
                            chain_id=self.chain_id,
                            chain=self.chain_key,
                            contract_address=mint.contract_address,
                            tx_hash=mint.tx_hash,
                            log_index=mint.log_index,
                            duplicate_type="cached_rejected_unknown_age",
                            reason="Cached rejected_unknown_age contract skipped",
                            suppressed_at=mint.timestamp,
                        )
                        return stats
                    if st == "alerted" and not is_multi_watched_upgrade:
                        realert_hours = self._effective_realert_after_hours()
                        last_alerted_at = int(state_row.get("last_alerted_at") or 0)
                        if realert_hours <= 0:
                            await self.db.record_suppressed_duplicate(
                                chain_id=self.chain_id,
                                chain=self.chain_key,
                                contract_address=mint.contract_address,
                                tx_hash=mint.tx_hash,
                                log_index=mint.log_index,
                                duplicate_type="duplicate_alert",
                                reason="Already alerted (REALERT_AFTER_HOURS=0)",
                                suppressed_at=mint.timestamp,
                            )
                            return stats
                        if (mint.timestamp - last_alerted_at) < (realert_hours * 3600.0):
                            await self.db.record_suppressed_duplicate(
                                chain_id=self.chain_id,
                                chain=self.chain_key,
                                contract_address=mint.contract_address,
                                tx_hash=mint.tx_hash,
                                log_index=mint.log_index,
                                duplicate_type="realert_cooldown",
                                reason=f"REALERT_AFTER_HOURS ({realert_hours:g}h) not elapsed",
                                suppressed_at=mint.timestamp,
                            )
                            return stats

                stats = await self.db.get_rolling_stats(
                    contract_address=mint.contract_address,
                    window_seconds=self.window_seconds,
                    as_of_timestamp=mint.timestamp,
                    chain=self.chain_key,
                )
                if (
                    (stats.unique_minters >= self.min_unique_minters and stats.total_mints >= self.min_mints)
                    or is_watched_mint
                ):
                    # Only run RPC detection & enrichment calls AFTER threshold is crossed (or watched wallet mints)
                    contract = await self.ensure_contract_registered(
                        mint.contract_address, mint.block_number, mint.timestamp
                    )
                    if not contract:
                        return None

                    if len(watched_minters) >= 2:
                        self._multi_watched_alerted.add(addr_lower)

                    await self._trigger_alert(
                        contract,
                        stats,
                        mint.timestamp,
                        trigger_block_number=mint.block_number,
                        trigger_tx_hash=mint.tx_hash,
                        recent_token_id=mint.token_id,
                        enforce_age_filter=True,
                        enforce_threshold_filter=not is_watched_mint,
                        watched_wallet_override=is_multi_watched_upgrade,
                    )
                    stats = await self.db.get_rolling_stats(
                        contract_address=mint.contract_address,
                        window_seconds=self.window_seconds,
                        as_of_timestamp=mint.timestamp,
                        chain=self.chain_key,
                    )

        return stats

    async def check_contract_age_gate(
        self,
        contract: ContractRecord,
        as_of_timestamp: int,
        lookup_failure_reason: Optional[str] = None,
    ) -> Tuple[bool, str, str]:
        """
        Shared method wrapper around `evaluate_contract_age_gate` used by every alert path
        (live detection, /test, and replay).
        """
        failure_reason = lookup_failure_reason
        if not failure_reason and hasattr(self.enricher, "last_deployment_lookup_errors"):
            failure_reason = self.enricher.last_deployment_lookup_errors.get(contract.address.lower())
        return await evaluate_contract_age_gate(
            contract=contract,
            chain_key=self.chain_key,
            chain_name=self.chain_name,
            chain_id=self.chain_id,
            as_of_timestamp=as_of_timestamp,
            max_contract_age_hours=self.max_contract_age_hours,
            alert_on_old_contracts=self.alert_on_old_contracts,
            lookup_failure_reason=failure_reason,
            db=self.db,
        )

    async def evaluate_live_mint_status(
        self,
        contract_address: str,
        enrichment: EnrichmentResult,
        stats: RollingStats,
        as_of_timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Compute real-time live-mint health check right before every alert:
        1. minutes since the last observed mint
        2. whether totalSupply is below max supply (when known)
        3. paused state
        4. result of an eth_call mint simulation from throwaway address with no signing

        Labels: LIVE, SLOWING, ENDED, or SOLD OUT with explicit reason.
        If a check cannot run, shows 'not checked' and never treats it as passed.
        Configurable per-chain thresholds (live_mint_max_minutes, slowing_mint_max_minutes).
        Never signs or sends any transaction (read-only eth_call only).
        """
        addr = contract_address.lower()
        now_ts = as_of_timestamp or int(time.time())

        # 1. Minutes since last observed mint
        last_mint_ts = None
        if self.db is not None and hasattr(self.db, "get_last_mint_timestamp"):
            try:
                last_mint_ts = await self.db.get_last_mint_timestamp(addr, chain=self.chain_key)
            except Exception as e:
                logger.debug("[%s] get_last_mint_timestamp error: %s", self.chain_name, e)

        if last_mint_ts is None:
            last_mint_ts = getattr(stats, "as_of_timestamp", None) or as_of_timestamp

        minutes_since_last_mint: Optional[float] = None
        mins_str = "not checked"
        if last_mint_ts is not None:
            gap_sec = max(0, now_ts - last_mint_ts)
            minutes_since_last_mint = round(gap_sec / 60.0, 2)
            mins_str = f"{minutes_since_last_mint:.1f}m"

        # 2. Total supply vs Max supply (when known)
        tot_sup = enrichment.total_supply
        max_sup = enrichment.max_supply
        is_below_max: Optional[bool] = None
        supply_check_str = "not checked"
        if tot_sup is not None and max_sup is not None and max_sup > 0:
            is_below_max = bool(tot_sup < max_sup)
            supply_check_str = f"{tot_sup:,} / {max_sup:,}"
        elif tot_sup is not None and (max_sup is None or max_sup <= 0):
            is_below_max = True  # Uncapped or max supply unknown
            supply_check_str = f"{tot_sup:,} (uncapped / max unknown)"
        elif tot_sup is not None:
            supply_check_str = f"{tot_sup:,}"

        # 3. Paused state
        is_paused = getattr(enrichment, "is_paused", None)
        paused_source = getattr(enrichment, "paused_source", None)
        paused_str = "not checked"
        if is_paused is True:
            paused_str = f"Paused ({paused_source or 'paused()'})"
        elif is_paused is False:
            paused_str = "Active (Not paused)"

        # 4. Mint simulation via eth_call
        sim_status = getattr(enrichment, "simulation_status", "not_checked")
        sim_reason = getattr(enrichment, "simulation_revert_reason", None)
        sim_class = getattr(enrichment, "simulation_classification", "not checked")
        sim_tested_fn = getattr(enrichment, "simulation_tested_function", None)

        sim_str = "not checked"
        if sim_status == "success":
            sim_str = "Succeeded"
        elif sim_status == "reverted":
            sim_str = f"Reverted ({sim_class}: {sim_reason})"
        else:
            sim_str = "not checked"

        # Real mint price
        price_str = (
            enrichment.mint_price_formatted
            if enrichment.mint_price_formatted and enrichment.mint_price_formatted != "unavailable"
            else None
        )
        if not price_str and getattr(enrichment, "tx_price_wei", None) is not None:
            from app.enrichment import format_eth_wei
            price_str = format_eth_wei(enrichment.tx_price_wei, self.native_token_symbol, self.native_token_decimals)
        if not price_str or price_str == "unavailable":
            price_str = "not checked"

        # Configurable time thresholds per chain
        live_max = float(getattr(self.chain_config, "live_mint_max_minutes", 10.0) if self.chain_config else 10.0)
        slowing_max = float(getattr(self.chain_config, "slowing_mint_max_minutes", 30.0) if self.chain_config else 30.0)

        # Evaluate status and reason
        # Rule: "If a check can't run, show 'not checked' and never treat it as passed."
        status: str
        reason: str

        # SOLD OUT Check
        if is_below_max is False:
            status = "SOLD OUT"
            reason = f"Total supply ({tot_sup:,}) reached max supply ({max_sup:,})"
        elif sim_status == "reverted" and any(k in (sim_reason or "").lower() for k in ("sold out", "max supply", "exceeded max", "reached max")):
            status = "SOLD OUT"
            reason = f"Simulation reverted: {sim_reason}"

        # ENDED Check
        elif is_paused is True:
            status = "ENDED"
            reason = f"Contract is paused ({paused_source or 'paused()'})"
        elif minutes_since_last_mint is not None and minutes_since_last_mint > slowing_max:
            status = "ENDED"
            reason = f"No mints observed in {minutes_since_last_mint:.1f}m (exceeds {slowing_max:g}m limit)"
        elif sim_status == "reverted":
            status = "ENDED"
            reason = f"Simulation failed: {sim_class} ({sim_reason})"
        elif sim_status == "not_checked":
            status = "ENDED"
            reason = "Mint simulation not checked (cannot verify open mint)"
        elif minutes_since_last_mint is None:
            status = "ENDED"
            reason = "Last mint timestamp not checked (no observed mint activity)"

        # SLOWING Check
        elif minutes_since_last_mint is not None and minutes_since_last_mint > live_max:
            status = "SLOWING"
            reason = f"Mint velocity slowing ({minutes_since_last_mint:.1f}m since last mint, threshold is {live_max:g}m)"

        # LIVE Check
        elif sim_status == "success" and minutes_since_last_mint is not None and minutes_since_last_mint <= live_max and is_paused is not True:
            status = "LIVE"
            reason = f"Open public mint verified via simulation ({minutes_since_last_mint:.1f}m since last mint)"
        else:
            status = "ENDED"
            reason = "Live mint conditions not fully satisfied"

        return {
            "status": status,
            "reason": reason,
            "minutes_since_last_mint": minutes_since_last_mint,
            "minutes_str": mins_str,
            "is_below_max_supply": is_below_max,
            "supply_str": supply_check_str,
            "is_paused": is_paused,
            "paused_str": paused_str,
            "simulation_status": sim_status,
            "simulation_str": sim_str,
            "simulation_tested_function": sim_tested_fn,
            "mint_price": price_str,
            "live_max_minutes": live_max,
            "slowing_max_minutes": slowing_max,
        }

    async def _trigger_alert(
        self,
        contract: ContractRecord,
        stats: RollingStats,
        as_of_timestamp: int,
        target_chat_id: Optional[str] = None,
        record_alert: bool = True,
        trigger_block_number: Optional[int] = None,
        trigger_tx_hash: Optional[str] = None,
        recent_token_id: Optional[str] = None,
        enforce_age_filter: bool = True,
        enforce_threshold_filter: bool = False,
        watched_wallet_override: bool = False,
    ) -> Optional[str]:
        """
        Single shared alert gate used by ALL alert paths (live detection, replay after reconnect, and /test).
        1. Checks persistent SQLite `alert_state` keyed on (chain_id, contract_address) before any alert.
        2. Enforces single-alert-by-default (`REALERT_AFTER_HOURS = 0`) and meaningful-change reply updates.
        3. Resolves real contract deployment and enforces fail-closed `MAX_CONTRACT_AGE_HOURS` (`rejected_old` / `rejected_unknown_age`).
        4. Evaluates Risk Score (0-100) and Quality Score (0-100) + Alert Tier (Tier A, Tier B, Tier C).
        5. Enforces non-owner unique minter threshold and attaches inline Mute button to every alert.
        """
        # 0. Check persistent `alert_state` table keyed on (chain_id, contract_address) before sending any alert
        state_row = await self.db.get_alert_state(
            self.chain_id, contract.address, chain=self.chain_key
        )
        is_realert_candidate = False
        if state_row is not None:
            st = state_row.get("status")
            if st == "muted":
                await self.db.record_suppressed_duplicate(
                    chain_id=self.chain_id,
                    chain=self.chain_key,
                    contract_address=contract.address,
                    tx_hash=trigger_tx_hash,
                    duplicate_type="muted_contract",
                    reason="Contract is muted in alert_state",
                    suppressed_at=as_of_timestamp,
                )
                logger.info("🔇 [%s] Suppressing alert for muted contract %s", self.chain_name, contract.address)
                return None

            if st in ("rejected_old", "too_old") and not self.alert_on_old_contracts:
                await self.db.record_suppressed_duplicate(
                    chain_id=self.chain_id,
                    chain=self.chain_key,
                    contract_address=contract.address,
                    tx_hash=trigger_tx_hash,
                    duplicate_type="cached_rejected_old",
                    reason="Contract is cached as rejected_old in alert_state",
                    suppressed_at=as_of_timestamp,
                )
                logger.info("🚫 [%s] Suppressing alert for cached rejected_old contract %s", self.chain_name, contract.address)
                return None

            if st in ("rejected_unknown_age", "age_unknown") and not (
                contract.deployed_timestamp and contract.deployed_timestamp > 0
            ):
                await self.db.record_suppressed_duplicate(
                    chain_id=self.chain_id,
                    chain=self.chain_key,
                    contract_address=contract.address,
                    tx_hash=trigger_tx_hash,
                    duplicate_type="cached_rejected_unknown_age",
                    reason="Contract is cached as rejected_unknown_age in alert_state",
                    suppressed_at=as_of_timestamp,
                )
                logger.info("🚫 [%s] Suppressing alert for cached rejected_unknown_age contract %s", self.chain_name, contract.address)
                return None

            if st == "alerted" and not watched_wallet_override:
                realert_hours = self._effective_realert_after_hours()
                last_alerted_at = int(state_row.get("last_alerted_at") or 0)
                if realert_hours <= 0:
                    await self.db.record_suppressed_duplicate(
                        chain_id=self.chain_id,
                        chain=self.chain_key,
                        contract_address=contract.address,
                        tx_hash=trigger_tx_hash,
                        duplicate_type="duplicate_alert",
                        reason="Contract already alerted (REALERT_AFTER_HOURS=0)",
                        suppressed_at=as_of_timestamp,
                    )
                    logger.info(
                        "⏭ [%s] Suppressing duplicate alert for %s: already alerted once (REALERT_AFTER_HOURS=0)",
                        self.chain_name,
                        contract.address,
                    )
                    return None
                if (as_of_timestamp - last_alerted_at) < (realert_hours * 3600.0):
                    await self.db.record_suppressed_duplicate(
                        chain_id=self.chain_id,
                        chain=self.chain_key,
                        contract_address=contract.address,
                        tx_hash=trigger_tx_hash,
                        duplicate_type="realert_cooldown",
                        reason=f"REALERT_AFTER_HOURS ({realert_hours:g}h) not elapsed since last_alerted_at={last_alerted_at}",
                        suppressed_at=as_of_timestamp,
                    )
                    logger.info(
                        "⏭ [%s] Suppressing re-alert for %s: REALERT_AFTER_HOURS (%gh) not elapsed",
                        self.chain_name,
                        contract.address,
                        realert_hours,
                    )
                    return None
                is_realert_candidate = True

        # 1. For every candidate contract, resolve real deployment block, timestamp, and deployer first
        dep_addr, dep_tx, dep_blk, dep_ts = await self.enricher.resolve_contract_deployment(
            address=contract.address,
            reference_block=trigger_block_number,
            known_deployer=contract.deployer,
            known_deployed_block=contract.deployed_block,
            known_deployed_timestamp=contract.deployed_timestamp,
            known_deployed_tx_hash=contract.deployed_tx_hash,
        )
        if dep_addr:
            contract.deployer = dep_addr
        if dep_tx:
            contract.deployed_tx_hash = dep_tx
        if dep_blk is not None:
            contract.deployed_block = dep_blk
        if dep_ts is not None:
            contract.deployed_timestamp = dep_ts

        # 2. Enforce MAX_CONTRACT_AGE_HOURS & fail-closed rejected_unknown_age check via the single shared function
        allowed, _, _ = await self.check_contract_age_gate(
            contract=contract,
            as_of_timestamp=as_of_timestamp,
        )
        if not allowed:
            return None

        logger.info(
            "🚀 [%s] ENRICHING & ALERTING: Contract %s (%d unique minters in %ds)",
            self.chain_name, contract.address, stats.unique_minters, stats.window_seconds
        )

        enrichment = await self.enricher.enrich_contract(
            address=contract.address,
            known_deployer=contract.deployer,
            as_of_timestamp=as_of_timestamp,
            rolling_mints_per_minute=stats.mints_per_minute,
            trigger_block_number=trigger_block_number,
            trigger_tx_hash=trigger_tx_hash,
            recent_token_id=recent_token_id,
        )

        # Re-evaluate rolling stats excluding resolved owner, deployer, and zero address
        excluded_addrs = [
            a for a in (enrichment.owner, enrichment.deployer, contract.owner, contract.deployer) if a
        ]
        stats = await self.db.get_rolling_stats(
            contract_address=contract.address,
            window_seconds=self.window_seconds,
            as_of_timestamp=as_of_timestamp,
            chain=self.chain_key,
            excluded_addresses=excluded_addrs,
        )
        enrichment.mints_per_minute = stats.mints_per_minute
        if stats.self_mints > (enrichment.self_mints or 0):
            enrichment.self_mints = stats.self_mints
            denom = stats.total_mints + stats.self_mints
            if denom > 0:
                enrichment.self_mint_pct = round((stats.self_mints / denom) * 100.0, 1)

        # Persist resolved owner & deployer so subsequent rolling window checks exclude them immediately
        if enrichment.collection_name and not contract.name:
            contract.name = enrichment.collection_name
        if enrichment.symbol and not contract.symbol:
            contract.symbol = enrichment.symbol
        if enrichment.standard and contract.standard in ("UNKNOWN", "", None):
            contract.standard = enrichment.standard
        contract.chain = self.chain_key
        contract.owner = enrichment.owner or contract.owner
        contract.deployer = enrichment.deployer or contract.deployer
        if enrichment.contract_deployed_block is not None:
            contract.deployed_block = enrichment.contract_deployed_block
        if enrichment.contract_deployed_timestamp is not None:
            contract.deployed_timestamp = enrichment.contract_deployed_timestamp
        if enrichment.contract_deployed_tx_hash:
            contract.deployed_tx_hash = enrichment.contract_deployed_tx_hash
        contract.is_proxy = enrichment.is_proxy
        contract.proxy_implementation = enrichment.proxy_implementation
        contract.is_verified = enrichment.is_source_verified
        await self.db.upsert_contract(contract)

        # Enforce threshold check strictly on non-owner, non-deployer, non-zero unique minters
        if enforce_threshold_filter and not enrichment.watched_wallets_minted and (
            stats.unique_minters < self.min_unique_minters
            or stats.total_mints < self.min_mints
        ):
            logger.info(
                "⏭ [%s] Skipping alert for %s: after excluding owner/deployer self-mints (%d self-mints), "
                "non-owner unique minters=%d (min=%d), non-owner mints=%d (min=%d)",
                self.chain_name,
                contract.address,
                stats.self_mints,
                stats.unique_minters,
                self.min_unique_minters,
                stats.total_mints,
                self.min_mints,
            )
            return None

        is_sold_out = bool(
            enrichment.total_supply is not None
            and enrichment.max_supply is not None
            and enrichment.max_supply > 0
            and enrichment.total_supply >= enrichment.max_supply
        )

        # If re-alerting (`REALERT_AFTER_HOURS > 0` on an already-alerted contract), require a meaningful change:
        # either real non-owner unique minters doubled OR the mint sold out.
        if is_realert_candidate and state_row is not None and not watched_wallet_override:
            prev_unique = int(state_row.get("last_unique_minters") or 0)
            prev_sold_out = bool(state_row.get("last_sold_out"))
            minters_doubled = stats.unique_minters >= max(1, prev_unique) * 2
            newly_sold_out = is_sold_out and not prev_sold_out
            if not (minters_doubled or newly_sold_out):
                await self.db.record_suppressed_duplicate(
                    chain_id=self.chain_id,
                    chain=self.chain_key,
                    contract_address=contract.address,
                    tx_hash=trigger_tx_hash,
                    duplicate_type="realert_no_meaningful_change",
                    reason=f"No meaningful change (unique_minters={stats.unique_minters} vs prev={prev_unique}, sold_out={is_sold_out})",
                    suppressed_at=as_of_timestamp,
                )
                logger.info(
                    "⏭ [%s] Suppressing re-alert for %s: no meaningful change (minters %d -> %d, sold_out=%s)",
                    self.chain_name,
                    contract.address,
                    prev_unique,
                    stats.unique_minters,
                    is_sold_out,
                )
                return None

        risk_report = self.risk_scorer.evaluate(
            enrichment=enrichment,
            stats=stats,
            as_of_timestamp=as_of_timestamp,
        )
        enrichment.risk_report = risk_report.to_dict()

        await self.db.record_risk_score(
            contract_address=contract.address,
            score=risk_report.score,
            risk_level=risk_report.risk_level,
            reasons=risk_report.reasons,
            checks=[c.to_dict() for c in risk_report.checks],
            scored_at=as_of_timestamp,
            chain=self.chain_key,
        )

        quality_report = self.quality_scorer.evaluate(
            enrichment=enrichment,
            stats=stats,
            risk_report=risk_report,
            max_contract_age_hours=self.max_contract_age_hours,
        )
        enrichment.quality_report = quality_report.to_dict()
        enrichment.alert_tier = quality_report.alert_tier

        if hasattr(self.db, "record_quality_score"):
            await self.db.record_quality_score(
                contract_address=contract.address,
                score=quality_report.score,
                alert_tier=quality_report.alert_tier,
                tier_reason=quality_report.tier_reason,
                reasons=quality_report.reasons,
                checks=[c.to_dict() for c in quality_report.checks],
                scored_at=as_of_timestamp,
                chain=self.chain_key,
            )

        eff_contract_name = contract.name or enrichment.collection_name
        eff_contract_symbol = contract.symbol or enrichment.symbol
        watched_cnt = len(enrichment.watched_wallets_minted or [])

        # Alert Tier Routing when `self.enforce_alert_tiers` is enabled:
        # - Tier A (or watched wallet mint or manual /test): immediate alert
        # - Tier B: queued into hourly digest (`digest_queue`)
        # - Tier C: logged only
        if (
            self.enforce_alert_tiers
            and not is_realert_candidate
            and target_chat_id is None
            and watched_cnt == 0
        ):
            if quality_report.alert_tier == "Tier B":
                if hasattr(self.db, "enqueue_tier_b_digest"):
                    await self.db.enqueue_tier_b_digest(
                        contract_address=contract.address,
                        chain=self.chain_key,
                        chain_id=self.chain_id,
                        contract_name=eff_contract_name,
                        contract_symbol=eff_contract_symbol,
                        quality_score=quality_report.score,
                        risk_score=risk_report.score,
                        risk_level=risk_report.risk_level,
                        unique_minters=stats.unique_minters,
                        total_mints=stats.total_mints,
                        queued_at=as_of_timestamp,
                    )
                await self.db.record_alert(
                    contract_address=contract.address,
                    unique_minters=stats.unique_minters,
                    total_mints=stats.total_mints,
                    mints_per_minute=stats.mints_per_minute,
                    window_seconds=stats.window_seconds,
                    alerted_at=as_of_timestamp,
                    telegram_message_id=None,
                    chain=self.chain_key,
                    chain_id=self.chain_id,
                    is_sold_out=is_sold_out,
                    contract_name=eff_contract_name,
                    alert_tier=quality_report.alert_tier,
                    quality_score=quality_report.score,
                    risk_score=risk_report.score,
                    risk_level=risk_report.risk_level,
                    watched_wallets_count=watched_cnt,
                )
                logger.info(
                    "⏱ [%s] Tier B contract %s queued for hourly digest (Quality=%d/100, Risk=%s %d/100)",
                    self.chain_name,
                    contract.address,
                    quality_report.score,
                    risk_report.risk_level,
                    risk_report.score,
                )
                return None

            if quality_report.alert_tier == "Tier C":
                await self.db.record_alert(
                    contract_address=contract.address,
                    unique_minters=stats.unique_minters,
                    total_mints=stats.total_mints,
                    mints_per_minute=stats.mints_per_minute,
                    window_seconds=stats.window_seconds,
                    alerted_at=as_of_timestamp,
                    telegram_message_id=None,
                    chain=self.chain_key,
                    chain_id=self.chain_id,
                    is_sold_out=is_sold_out,
                    contract_name=eff_contract_name,
                    alert_tier=quality_report.alert_tier,
                    quality_score=quality_report.score,
                    risk_score=risk_report.score,
                    risk_level=risk_report.risk_level,
                    watched_wallets_count=watched_cnt,
                )
                logger.info(
                    "📝 [%s] Tier C contract %s logged only (Quality=%d/100, Risk=%s %d/100)",
                    self.chain_name,
                    contract.address,
                    quality_report.score,
                    risk_report.risk_level,
                    risk_report.score,
                )
                return None

        # Live-mint check that runs right before every alert is sent
        live_check = await self.evaluate_live_mint_status(
            contract_address=contract.address,
            enrichment=enrichment,
            stats=stats,
            as_of_timestamp=as_of_timestamp,
        )
        enrichment.live_mint_check = live_check

        # Only send alerts for LIVE contracts
        if record_alert and live_check.get("status") != "LIVE":
            logger.info(
                "⏭ [%s] Suppressing alert for %s: live-mint check status is %s (%s)",
                self.chain_name,
                contract.address,
                live_check.get("status"),
                live_check.get("reason"),
            )
            await self.db.record_suppressed_duplicate(
                chain_id=self.chain_id,
                chain=self.chain_key,
                contract_address=contract.address,
                tx_hash=trigger_tx_hash,
                duplicate_type=f"not_live_{str(live_check.get('status')).lower().replace(' ', '_')}",
                reason=f"Live-mint check: {live_check.get('status')} ({live_check.get('reason')})",
                suppressed_at=as_of_timestamp,
            )
            return None

        mute_kb = build_mute_inline_keyboard(
            chain_id=self.chain_id,
            contract_address=contract.address,
            chain_key=self.chain_key,
        )
        reply_to_id: Optional[str] = None

        if is_realert_candidate and state_row is not None and not watched_wallet_override:
            prev_unique = int(state_row.get("last_unique_minters") or 0)
            reply_to_id = state_row.get("first_message_id") or state_row.get("last_message_id")
            msg = build_realert_message(
                contract_address=contract.address,
                contract_name=eff_contract_name,
                contract_symbol=eff_contract_symbol,
                chain_name=self.chain_name,
                chain_id=self.chain_id,
                stats=stats,
                enrichment=enrichment,
                previous_unique_minters=prev_unique,
                is_sold_out=is_sold_out,
                explorer_base_url=self.explorer_url,
                live_check=live_check,
            )
        else:
            msg = build_alert_message(
                contract_name=eff_contract_name,
                contract_symbol=eff_contract_symbol,
                stats=stats,
                enrichment=enrichment,
                standard=contract.standard if contract.standard not in ("UNKNOWN", "", None) else enrichment.standard,
                explorer_base_url=self.explorer_url,
                trigger_block_number=enrichment.trigger_block_number or trigger_block_number,
                trigger_tx_hash=enrichment.trigger_tx_hash or trigger_tx_hash,
                risk_report=risk_report,
                quality_report=quality_report,
                live_check=live_check,
            )

        try:
            msg_id = await self.telegram.send_alert(
                msg,
                target_chat_id=target_chat_id,
                reply_markup=mute_kb,
                reply_to_message_id=reply_to_id,
            )
        except TypeError:
            msg_id = await self.telegram.send_alert(msg, target_chat_id=target_chat_id)

        # Always persist `alert_state` keyed on (chain_id, contract_address) across live, replay, and /test
        await self.db.record_alert(
            contract_address=contract.address,
            unique_minters=stats.unique_minters,
            total_mints=stats.total_mints,
            mints_per_minute=stats.mints_per_minute,
            window_seconds=stats.window_seconds,
            alerted_at=as_of_timestamp,
            telegram_message_id=msg_id,
            chain=self.chain_key,
            chain_id=self.chain_id,
            is_sold_out=is_sold_out,
            contract_name=eff_contract_name,
            alert_tier=quality_report.alert_tier,
            quality_score=quality_report.score,
            risk_score=risk_report.score,
            risk_level=risk_report.risk_level,
            watched_wallets_count=watched_cnt,
        )

        if enrichment.deployer and hasattr(self.db, "record_cross_chain_deployer"):
            try:
                await self.db.record_cross_chain_deployer(
                    deployer=enrichment.deployer,
                    chain=self.chain_key,
                    contract_address=contract.address,
                    deploy_time=enrichment.contract_deployed_timestamp,
                    alert_status="alerted",
                )
            except Exception:
                pass

        if hasattr(self.db, "auto_flag_high_risk_templates") and (
            risk_report.risk_level == "High"
            or (enrichment.owner_held_pct is not None and enrichment.owner_held_pct > 50.0)
            or (enrichment.deployer_owner_held_above_50pct is not None and enrichment.deployer_owner_held_above_50pct > 0)
        ):
            try:
                await self.db.auto_flag_high_risk_templates()
            except Exception as e:
                logger.debug("Failed auto-flagging high risk templates: %s", e)

        return msg_id

    async def flush_hourly_digest(
        self,
        target_chat_id: Optional[str] = None,
        all_chains: bool = False,
    ) -> Optional[str]:
        """Flush queued Tier B alerts into a single hourly digest message."""
        if not hasattr(self.db, "get_pending_digest_items"):
            return None
        items = await self.db.get_pending_digest_items(
            chain=None if all_chains else self.chain_key
        )
        if not items:
            return None
        msg = build_tier_b_digest_message(items)
        msg_id = await self.telegram.send_alert(msg, target_chat_id=target_chat_id)
        if hasattr(self.db, "mark_digest_items_sent"):
            await self.db.mark_digest_items_sent([int(i["id"]) for i in items if i.get("id") is not None])
        return msg_id

    async def run_due_outcome_snapshots(
        self,
        as_of_timestamp: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Collect 1h, 24h, and 7d outcome snapshots for any alerted contracts on this chain that are due."""
        if not hasattr(self.db, "get_due_outcome_snapshots"):
            return []
        due_list = await self.db.get_due_outcome_snapshots(
            as_of_timestamp=as_of_timestamp,
            chain=self.chain_key,
        )
        collected: List[Dict[str, Any]] = []
        for item in due_list:
            try:
                snap = await self.enricher.collect_outcome_snapshot(
                    address=item["contract_address"],
                    interval_label=item["interval_label"],
                    alerted_at=item["alerted_at"],
                    as_of_timestamp=as_of_timestamp,
                )
                collected.append(snap)
            except Exception as e:
                logger.warning(
                    "[%s] Outcome snapshot (%s) failed for %s: %s",
                    self.chain_name,
                    item.get("interval_label"),
                    item.get("contract_address"),
                    e,
                )
        return collected

    async def trigger_alert_for_address(
        self,
        address: str,
        target_chat_id: Optional[str] = None,
        record_alert: bool = False,
    ) -> Optional[str]:
        """
        Run the full real enrichment & alert pipeline for a given contract address (e.g., via /test <address> <chain>).
        Routes through the single shared `_trigger_alert` function so `alert_state`, `REALERT_AFTER_HOURS`,
        and the fail-closed `MAX_CONTRACT_AGE_HOURS` gate cannot be bypassed.
        """
        checksum_addr = to_checksum_address(address)
        now = int(time.time())

        contract = await self.db.get_contract(checksum_addr, chain=self.chain_key)
        if not contract:
            standard, _ = await self.detector.detect_nft_standard(checksum_addr)
            name, symbol = await self.detector.fetch_metadata(checksum_addr)
            contract = ContractRecord(
                address=checksum_addr,
                chain=self.chain_key,
                standard=standard,
                name=name,
                symbol=symbol,
                created_at=now,
            )
            await self.db.upsert_contract(contract)

        stats = await self.db.get_rolling_stats(
            contract_address=checksum_addr,
            window_seconds=self.window_seconds,
            as_of_timestamp=now,
            chain=self.chain_key,
        )

        latest_block, latest_tx = await self.db.get_latest_mint_event(
            checksum_addr, chain=self.chain_key
        )

        return await self._trigger_alert(
            contract=contract,
            stats=stats,
            as_of_timestamp=now,
            target_chat_id=target_chat_id,
            record_alert=record_alert,
            trigger_block_number=latest_block or contract.deployed_block,
            trigger_tx_hash=latest_tx or contract.deployed_tx_hash,
            enforce_age_filter=True,
        )


    async def explain_contract(
        self,
        address: str,
    ) -> Tuple[ContractRecord, RollingStats, EnrichmentResult, RiskScoreReport]:
        """
        Evaluate or retrieve the full risk score breakdown for a contract on this chain,
        logging the evaluation to SQLite `risk_scores`.
        """
        checksum_addr = to_checksum_address(address)
        now = int(time.time())

        contract = await self.db.get_contract(checksum_addr, chain=self.chain_key)
        if not contract:
            standard, _ = await self.detector.detect_nft_standard(checksum_addr)
            name, symbol = await self.detector.fetch_metadata(checksum_addr)
            contract = ContractRecord(
                address=checksum_addr,
                chain=self.chain_key,
                standard=standard,
                name=name,
                symbol=symbol,
                created_at=now,
            )
            await self.db.upsert_contract(contract)

        stats = await self.db.get_rolling_stats(
            contract_address=checksum_addr,
            window_seconds=self.window_seconds,
            as_of_timestamp=now,
            chain=self.chain_key,
        )
        latest_block, latest_tx = await self.db.get_latest_mint_event(
            checksum_addr, chain=self.chain_key
        )

        enrichment = await self.enricher.enrich_contract(
            address=checksum_addr,
            known_deployer=contract.deployer,
            as_of_timestamp=now,
            rolling_mints_per_minute=stats.mints_per_minute,
            trigger_block_number=latest_block or contract.deployed_block,
            trigger_tx_hash=latest_tx or contract.deployed_tx_hash,
        )

        excluded_addrs = [
            a for a in (enrichment.owner, enrichment.deployer, contract.owner, contract.deployer) if a
        ]
        stats = await self.db.get_rolling_stats(
            contract_address=checksum_addr,
            window_seconds=self.window_seconds,
            as_of_timestamp=now,
            chain=self.chain_key,
            excluded_addresses=excluded_addrs,
        )
        enrichment.mints_per_minute = stats.mints_per_minute
        if stats.self_mints > (enrichment.self_mints or 0):
            enrichment.self_mints = stats.self_mints
            denom = stats.total_mints + stats.self_mints
            if denom > 0:
                enrichment.self_mint_pct = round((stats.self_mints / denom) * 100.0, 1)

        risk_report = self.risk_scorer.evaluate(
            enrichment=enrichment,
            stats=stats,
            as_of_timestamp=now,
        )
        enrichment.risk_report = risk_report.to_dict()

        await self.db.record_risk_score(
            contract_address=checksum_addr,
            score=risk_report.score,
            risk_level=risk_report.risk_level,
            reasons=risk_report.reasons,
            checks=[c.to_dict() for c in risk_report.checks],
            scored_at=now,
            chain=self.chain_key,
        )

        quality_report = self.quality_scorer.evaluate(
            enrichment=enrichment,
            stats=stats,
            risk_report=risk_report,
            max_contract_age_hours=self.max_contract_age_hours,
        )
        enrichment.quality_report = quality_report.to_dict()
        enrichment.alert_tier = quality_report.alert_tier
        if hasattr(self.db, "record_quality_score"):
            await self.db.record_quality_score(
                contract_address=checksum_addr,
                score=quality_report.score,
                alert_tier=quality_report.alert_tier,
                tier_reason=quality_report.tier_reason,
                reasons=quality_report.reasons,
                checks=[c.to_dict() for c in quality_report.checks],
                scored_at=now,
                chain=self.chain_key,
            )

        return contract, stats, enrichment, risk_report

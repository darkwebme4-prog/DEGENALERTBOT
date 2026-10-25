"""SQLite database layer using aiosqlite for multi-chain rolling counts, mints, contracts, and enrichment caching."""

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Union
from dataclasses import dataclass
import aiosqlite

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def strip_bytecode_metadata(bytecode: Union[str, bytes]) -> str:
    """
    Strip Solidity / Vyper trailing CBOR metadata hash from EVM runtime bytecode.
    Returns normalized hex string without '0x' prefix.
    """
    if isinstance(bytecode, str):
        raw = bytecode.strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
    else:
        raw = bytecode.hex().lower()

    if len(raw) < 4:
        return raw

    try:
        b = bytes.fromhex(raw)
    except ValueError:
        return raw

    if len(b) < 4:
        return raw

    # 1. Solidity solc appends a 2-byte big-endian length at the end of the runtime bytecode
    cbor_len = int.from_bytes(b[-2:], "big")
    if 0 < cbor_len < len(b) - 2:
        cbor_candidate = b[-(cbor_len + 2) : -2]
        # CBOR map header starts with 0xa1..0xa5 or contains 'ipfs', 'bzzr', 'solc', 'vyper'
        if cbor_candidate.startswith((b"\xa1", b"\xa2", b"\xa3", b"\xa4", b"\xa5")) or any(
            marker in cbor_candidate for marker in (b"ipfs", b"bzzr", b"solc", b"vyper")
        ):
            return b[: -(cbor_len + 2)].hex()

    # 2. Pattern match fallback for standard CBOR headers (a26469706673 for ipfs, a165627a7a72 for bzzr)
    for marker in (b"\xa2\x64ipfs", b"\xa1\x65bzzr", b"\xa2\x65bzzr"):
        idx = b.rfind(marker)
        if idx != -1 and len(b) - idx <= 128:
            return b[:idx].hex()

    return raw


def compute_bytecode_hash(stripped_bytecode_hex: str) -> str:
    """Compute SHA-256 hash of stripped runtime bytecode hex."""
    clean = stripped_bytecode_hex.strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    try:
        raw_b = bytes.fromhex(clean)
    except ValueError:
        raw_b = clean.encode("utf-8")
    return hashlib.sha256(raw_b).hexdigest()

CHAIN_KEY_TO_ID: Dict[str, int] = {
    "ethereum": 1,
    "base": 8453,
    "arbitrum": 42161,
    "optimism": 10,
    "polygon": 137,
    "robinhood": 4663,
}

CHAIN_ID_TO_KEY: Dict[int, str] = {v: k for k, v in CHAIN_KEY_TO_ID.items()}


def resolve_chain_id(chain: Optional[str] = None, chain_id: Optional[int] = None) -> int:
    """Resolve numeric chain_id from explicit chain_id or chain key."""
    if chain_id is not None and int(chain_id) > 0:
        if int(chain_id) == 1 and chain and chain.lower() in CHAIN_KEY_TO_ID and chain.lower() != "ethereum":
            return CHAIN_KEY_TO_ID[chain.lower()]
        return int(chain_id)
    if chain:
        ck = chain.strip().lower()
        if ck in CHAIN_KEY_TO_ID:
            return CHAIN_KEY_TO_ID[ck]
        try:
            return int(ck)
        except ValueError:
            pass
    return 1


@dataclass
class ContractRecord:
    address: str
    chain: str = "ethereum"
    standard: str = "UNKNOWN"
    name: Optional[str] = None
    symbol: Optional[str] = None
    owner: Optional[str] = None
    deployer: Optional[str] = None
    deployed_block: Optional[int] = None
    deployed_tx_hash: Optional[str] = None
    deployed_timestamp: Optional[int] = None
    is_proxy: Optional[bool] = None
    proxy_implementation: Optional[str] = None
    is_verified: Optional[bool] = None
    age_status: Optional[str] = None
    rejection_reason: Optional[str] = None
    created_at: int = 0


@dataclass
class MintRecord:
    contract_address: str
    minter_address: str
    tx_hash: str
    block_number: int
    timestamp: int
    token_id: Optional[str] = None
    quantity: int = 1
    chain: str = "ethereum"
    chain_id: Optional[int] = None
    log_index: int = 0


@dataclass
class RollingStats:
    contract_address: str
    total_mints: int
    unique_minters: int
    mints_per_minute: float
    window_seconds: int
    as_of_timestamp: int
    chain: str = "ethereum"
    self_mints: int = 0
    raw_total_mints: int = 0


class Database:
    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = db_path
        self._ensure_dir()

    def _ensure_dir(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    async def _table_columns(db: aiosqlite.Connection, table_name: str) -> List[str]:
        async with db.execute(f"PRAGMA table_info({table_name})") as cur:
            rows = await cur.fetchall()
            return [r[1] for r in rows]

    async def init_db(self):
        """Create tables and indexes with `chain` column on every table, migrating legacy tables if needed."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")

            # Check if legacy single-chain `contracts` table exists without `chain` column
            cols_contracts = await self._table_columns(db, "contracts")
            if cols_contracts and "chain" not in cols_contracts:
                await db.execute("ALTER TABLE contracts RENAME TO contracts_legacy;")
                await db.execute(
                    """
                    CREATE TABLE contracts (
                        chain TEXT NOT NULL DEFAULT 'ethereum',
                        address TEXT NOT NULL,
                        standard TEXT NOT NULL DEFAULT 'UNKNOWN',
                        name TEXT,
                        symbol TEXT,
                        owner TEXT,
                        deployer TEXT,
                        deployed_block INTEGER,
                        deployed_tx_hash TEXT,
                        deployed_timestamp INTEGER,
                        is_proxy INTEGER,
                        proxy_implementation TEXT,
                        is_verified INTEGER,
                        age_status TEXT,
                        rejection_reason TEXT,
                        created_at INTEGER NOT NULL,
                        PRIMARY KEY (chain, address)
                    );
                    """
                )
                await db.execute(
                    """
                    INSERT OR IGNORE INTO contracts (
                        chain, address, standard, name, symbol, deployer,
                        deployed_block, deployed_tx_hash, deployed_timestamp,
                        is_proxy, proxy_implementation, is_verified, created_at
                    )
                    SELECT
                        'ethereum', address, standard, name, symbol, deployer,
                        deployed_block, deployed_tx_hash, deployed_timestamp,
                        is_proxy, proxy_implementation, is_verified, created_at
                    FROM contracts_legacy;
                    """
                )
                await db.execute("DROP TABLE contracts_legacy;")
            else:
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS contracts (
                        chain TEXT NOT NULL DEFAULT 'ethereum',
                        address TEXT NOT NULL,
                        standard TEXT NOT NULL DEFAULT 'UNKNOWN',
                        name TEXT,
                        symbol TEXT,
                        owner TEXT,
                        deployer TEXT,
                        deployed_block INTEGER,
                        deployed_tx_hash TEXT,
                        deployed_timestamp INTEGER,
                        is_proxy INTEGER,
                        proxy_implementation TEXT,
                        is_verified INTEGER,
                        age_status TEXT,
                        rejection_reason TEXT,
                        created_at INTEGER NOT NULL,
                        PRIMARY KEY (chain, address)
                    );
                    """
                )
                cols_contracts_after = await self._table_columns(db, "contracts")
                if "owner" not in cols_contracts_after:
                    await db.execute("ALTER TABLE contracts ADD COLUMN owner TEXT;")
                if "age_status" not in cols_contracts_after:
                    await db.execute("ALTER TABLE contracts ADD COLUMN age_status TEXT;")
                if "rejection_reason" not in cols_contracts_after:
                    await db.execute("ALTER TABLE contracts ADD COLUMN rejection_reason TEXT;")

            # Clear any legacy heuristic "first seen" deployed_timestamp where deployed_timestamp == created_at or deployed_block is NULL
            await db.execute(
                """
                UPDATE contracts
                SET deployed_block = NULL, deployed_timestamp = NULL
                WHERE deployed_tx_hash IS NULL AND deployer IS NULL AND deployed_timestamp IS NOT NULL
                  AND (deployed_block IS NULL OR deployed_timestamp = created_at);
                """
            )

            # Mints table
            cols_mints = await self._table_columns(db, "mints")
            if cols_mints and "chain" not in cols_mints:
                await db.execute("ALTER TABLE mints ADD COLUMN chain TEXT NOT NULL DEFAULT 'ethereum';")
            else:
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS mints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        chain TEXT NOT NULL DEFAULT 'ethereum',
                        chain_id INTEGER NOT NULL DEFAULT 1,
                        contract_address TEXT NOT NULL,
                        minter_address TEXT NOT NULL,
                        tx_hash TEXT NOT NULL,
                        log_index INTEGER NOT NULL DEFAULT 0,
                        block_number INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        token_id TEXT,
                        quantity INTEGER NOT NULL DEFAULT 1
                    );
                    """
                )
            cols_mints_after = await self._table_columns(db, "mints")
            if "chain_id" not in cols_mints_after:
                await db.execute("ALTER TABLE mints ADD COLUMN chain_id INTEGER NOT NULL DEFAULT 1;")
            if "log_index" not in cols_mints_after:
                await db.execute("ALTER TABLE mints ADD COLUMN log_index INTEGER NOT NULL DEFAULT 0;")

            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_mints_chain_contract_ts
                ON mints (chain, contract_address, timestamp);
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_mints_chain_contract_minter
                ON mints (chain, contract_address, minter_address);
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_mints_chain_ts
                ON mints (chain, timestamp);
                """
            )

            # Event deduplication table keyed on (chain_id, tx_hash, log_index)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_events (
                    chain_id INTEGER NOT NULL,
                    tx_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    contract_address TEXT NOT NULL,
                    processed_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, tx_hash, log_index)
                );
                """
            )

            # Persistent alert state table keyed on (chain_id, contract_address)
            # Status values: 'alerted', 'rejected_old', 'rejected_unknown_age', 'muted'
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_state (
                    chain_id INTEGER NOT NULL,
                    contract_address TEXT NOT NULL,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    first_alerted_at INTEGER,
                    last_alerted_at INTEGER,
                    alert_count INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    first_message_id TEXT,
                    last_message_id TEXT,
                    last_unique_minters INTEGER NOT NULL DEFAULT 0,
                    last_total_mints INTEGER NOT NULL DEFAULT 0,
                    last_sold_out INTEGER NOT NULL DEFAULT 0,
                    deployed_block INTEGER,
                    deployed_timestamp INTEGER,
                    deployment_date TEXT,
                    age_seconds INTEGER,
                    age_formatted TEXT,
                    reason TEXT,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain_id, contract_address)
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alert_state_status_updated
                ON alert_state (status, updated_at DESC);
                """
            )

            # Suppressed duplicates table (tracks duplicate events and duplicate alerts suppressed in 24h)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS suppressed_duplicates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id INTEGER NOT NULL DEFAULT 1,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    contract_address TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    suppressed_at INTEGER NOT NULL
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_suppressed_duplicates_at
                ON suppressed_duplicates (suppressed_at DESC);
                """
            )

            # Alerts table
            cols_alerts = await self._table_columns(db, "alerts")
            if cols_alerts and "chain" not in cols_alerts:
                await db.execute("ALTER TABLE alerts ADD COLUMN chain TEXT NOT NULL DEFAULT 'ethereum';")
            else:
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        chain TEXT NOT NULL DEFAULT 'ethereum',
                        contract_address TEXT NOT NULL,
                        contract_name TEXT,
                        unique_minters INTEGER NOT NULL,
                        total_mints INTEGER NOT NULL,
                        mints_per_minute REAL NOT NULL,
                        window_seconds INTEGER NOT NULL,
                        alerted_at INTEGER NOT NULL,
                        telegram_message_id TEXT,
                        alert_tier TEXT NOT NULL DEFAULT 'Tier C',
                        quality_score INTEGER,
                        risk_score INTEGER,
                        risk_level TEXT NOT NULL DEFAULT 'Low',
                        watched_wallets_count INTEGER NOT NULL DEFAULT 0
                    );
                    """
                )
            cols_alerts_after = await self._table_columns(db, "alerts")
            if "contract_name" not in cols_alerts_after:
                await db.execute("ALTER TABLE alerts ADD COLUMN contract_name TEXT;")
            if "alert_tier" not in cols_alerts_after:
                await db.execute("ALTER TABLE alerts ADD COLUMN alert_tier TEXT NOT NULL DEFAULT 'Tier C';")
            if "quality_score" not in cols_alerts_after:
                await db.execute("ALTER TABLE alerts ADD COLUMN quality_score INTEGER;")
            if "risk_score" not in cols_alerts_after:
                await db.execute("ALTER TABLE alerts ADD COLUMN risk_score INTEGER;")
            if "risk_level" not in cols_alerts_after:
                await db.execute("ALTER TABLE alerts ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'Low';")
            if "watched_wallets_count" not in cols_alerts_after:
                await db.execute("ALTER TABLE alerts ADD COLUMN watched_wallets_count INTEGER NOT NULL DEFAULT 0;")

            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alerts_chain_contract_at
                ON alerts (chain, contract_address, alerted_at);
                """
            )

            # Enrichment cache table
            cols_cache = await self._table_columns(db, "contract_enrichment_cache")
            if cols_cache and "chain" not in cols_cache:
                await db.execute("ALTER TABLE contract_enrichment_cache RENAME TO contract_enrichment_cache_legacy;")
                await db.execute(
                    """
                    CREATE TABLE contract_enrichment_cache (
                        chain TEXT NOT NULL DEFAULT 'ethereum',
                        contract_address TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (chain, contract_address)
                    );
                    """
                )
                await db.execute(
                    """
                    INSERT OR IGNORE INTO contract_enrichment_cache (
                        chain, contract_address, payload_json, updated_at
                    )
                    SELECT 'ethereum', contract_address, payload_json, updated_at
                    FROM contract_enrichment_cache_legacy;
                    """
                )
                await db.execute("DROP TABLE contract_enrichment_cache_legacy;")
            else:
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS contract_enrichment_cache (
                        chain TEXT NOT NULL DEFAULT 'ethereum',
                        contract_address TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at INTEGER NOT NULL,
                        PRIMARY KEY (chain, contract_address)
                    );
                    """
                )

            # Risk scores log table (stores every evaluated risk score and check breakdown)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    contract_address TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    checks_json TEXT NOT NULL,
                    scored_at INTEGER NOT NULL
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_risk_scores_chain_contract_at
                ON risk_scores (chain, contract_address, scored_at DESC);
                """
            )

            # Quality scores log table (stores every evaluated quality score, tier, and check breakdown)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS quality_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    contract_address TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    alert_tier TEXT NOT NULL,
                    tier_reason TEXT NOT NULL,
                    checks_json TEXT NOT NULL,
                    scored_at INTEGER NOT NULL
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_quality_scores_chain_contract_at
                ON quality_scores (chain, contract_address, scored_at DESC);
                """
            )

            # Outcome snapshots table (stores 1h, 24h, and 7d post-alert snapshots for every alerted contract)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS outcome_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    chain_id INTEGER NOT NULL DEFAULT 1,
                    contract_address TEXT NOT NULL,
                    interval_label TEXT NOT NULL,
                    alerted_at INTEGER NOT NULL,
                    target_timestamp INTEGER NOT NULL,
                    captured_at INTEGER NOT NULL,
                    holder_count TEXT NOT NULL DEFAULT 'unavailable',
                    holder_count_num INTEGER,
                    unique_holders TEXT NOT NULL DEFAULT 'unavailable',
                    unique_holders_num INTEGER,
                    pct_max_supply_minted TEXT NOT NULL DEFAULT 'unavailable',
                    pct_max_supply_minted_num REAL,
                    floor_price TEXT NOT NULL DEFAULT 'unavailable',
                    floor_price_num REAL,
                    listing_count TEXT NOT NULL DEFAULT 'unavailable',
                    listing_count_num INTEGER,
                    volume_24h TEXT NOT NULL DEFAULT 'unavailable',
                    volume_24h_num REAL,
                    UNIQUE(chain, contract_address, interval_label)
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_outcome_snapshots_chain_contract
                ON outcome_snapshots (chain, contract_address, captured_at DESC);
                """
            )

            # Tier B hourly digest queue table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS digest_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    chain_id INTEGER NOT NULL DEFAULT 1,
                    contract_address TEXT NOT NULL,
                    contract_name TEXT,
                    contract_symbol TEXT,
                    quality_score INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    unique_minters INTEGER NOT NULL,
                    total_mints INTEGER NOT NULL,
                    mints_per_minute REAL NOT NULL,
                    queued_at INTEGER NOT NULL,
                    sent_at INTEGER,
                    UNIQUE(chain, contract_address)
                );
                """
            )

            # Smart-wallet watchlist table (editable via /watch and /unwatch)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS watch_wallets (
                    address TEXT PRIMARY KEY,
                    label TEXT,
                    added_at INTEGER NOT NULL
                );
                """
            )

            # Deployer reputation table and per-contract deployer history
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS deployer_reputation (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    deployer_address TEXT NOT NULL,
                    contracts_deployed INTEGER NOT NULL DEFAULT 0,
                    reached_90pct_minted INTEGER NOT NULL DEFAULT 0,
                    owner_held_above_50pct INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain, deployer_address)
                );
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS deployer_contracts (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    deployer_address TEXT NOT NULL,
                    contract_address TEXT NOT NULL,
                    total_supply INTEGER,
                    max_supply INTEGER,
                    pct_minted REAL,
                    reached_90pct INTEGER NOT NULL DEFAULT 0,
                    owner_held_pct REAL,
                    owner_held_above_50pct INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain, deployer_address, contract_address)
                );
                """
            )

            # 4byte selector signature cache table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS selector_signatures (
                    selector TEXT PRIMARY KEY,
                    signature TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                """
            )

            # Rejected contracts table (tracks rejected_unknown_age and rejected_old rejections for /rejected)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS rejected_contracts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    contract_address TEXT NOT NULL,
                    deployed_block INTEGER,
                    deployed_timestamp INTEGER,
                    deployment_date TEXT,
                    age_seconds INTEGER,
                    age_formatted TEXT,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    rejected_at INTEGER NOT NULL,
                    UNIQUE(chain, contract_address)
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_rejected_contracts_at
                ON rejected_contracts (rejected_at DESC, id DESC);
                """
            )

            # URI metadata cache table (caches resolved contractURI / tokenURI JSON payloads)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS uri_metadata_cache (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    uri TEXT NOT NULL,
                    payload_json TEXT,
                    status TEXT NOT NULL,
                    error TEXT,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain, uri)
                );
                """
            )

            # Per-chain block sync state table (tracks last_processed_block for polling/websocket resume across restarts)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_sync_state (
                    chain TEXT PRIMARY KEY,
                    last_processed_block INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                """
            )

            # Contract runtime bytecodes and stripped metadata hashes
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS contract_bytecodes (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    contract_address TEXT NOT NULL,
                    bytecode_sha256 TEXT NOT NULL,
                    stripped_bytecode_sha256 TEXT NOT NULL,
                    bytecode_size INTEGER NOT NULL,
                    captured_at INTEGER NOT NULL,
                    PRIMARY KEY (chain, contract_address)
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_contract_bytecodes_stripped
                ON contract_bytecodes (stripped_bytecode_sha256);
                """
            )

            # Known bytecode templates (label, risk_flag: scam | neutral | legit)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS known_templates (
                    template_hash TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    risk_flag TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'manual',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                """
            )

            # Cross-chain deployer history (deployer, chain, contract, deploy_time, outcome, alert_status)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS cross_chain_deployers (
                    deployer TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    contract_address TEXT NOT NULL,
                    deploy_time INTEGER NOT NULL,
                    alert_status TEXT NOT NULL DEFAULT 'unalerted',
                    outcome_7d TEXT DEFAULT 'unavailable',
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (deployer, chain, contract_address)
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cross_chain_deployers_deployer
                ON cross_chain_deployers (deployer, deploy_time DESC);
                """
            )

            # Funding-clusters table (wallet, funding_source, chain, contract_address)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS funding_clusters (
                    wallet TEXT NOT NULL,
                    funding_source TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    contract_address TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (wallet, funding_source, chain, contract_address)
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_funding_clusters_source
                ON funding_clusters (funding_source);
                """
            )

            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS chain_overrides (
                    chain_key TEXT PRIMARY KEY,
                    enabled INTEGER,
                    mint_threshold INTEGER,
                    min_mints INTEGER,
                    window INTEGER,
                    cooldown INTEGER,
                    updated_at REAL NOT NULL
                );
                """
            )

            # Resolved links cache table (caches resolved mint links, marketplaces, and socials per contract)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS resolved_links_cache (
                    chain TEXT NOT NULL DEFAULT 'ethereum',
                    contract_address TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (chain, contract_address)
                );
                """
            )

            # Domain RDAP / WHOIS cache table (caches registration timestamps for safety checks)
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS domain_rdap_cache (
                    domain TEXT PRIMARY KEY,
                    registration_timestamp INTEGER,
                    status TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                """
            )

            await db.commit()

    async def upsert_contract(self, contract: ContractRecord):
        """Insert or update a contract record scoped by chain."""
        now = int(time.time())
        created_at = contract.created_at or now
        addr = contract.address.lower()
        chain = (contract.chain or "ethereum").lower()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO contracts (
                    chain, address, standard, name, symbol, owner, deployer,
                    deployed_block, deployed_tx_hash, deployed_timestamp,
                    is_proxy, proxy_implementation, is_verified,
                    age_status, rejection_reason, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, address) DO UPDATE SET
                    standard = coalesce(excluded.standard, contracts.standard),
                    name = coalesce(excluded.name, contracts.name),
                    symbol = coalesce(excluded.symbol, contracts.symbol),
                    owner = coalesce(excluded.owner, contracts.owner),
                    deployer = coalesce(excluded.deployer, contracts.deployer),
                    deployed_block = coalesce(excluded.deployed_block, contracts.deployed_block),
                    deployed_tx_hash = coalesce(excluded.deployed_tx_hash, contracts.deployed_tx_hash),
                    deployed_timestamp = coalesce(excluded.deployed_timestamp, contracts.deployed_timestamp),
                    is_proxy = coalesce(excluded.is_proxy, contracts.is_proxy),
                    proxy_implementation = coalesce(excluded.proxy_implementation, contracts.proxy_implementation),
                    is_verified = coalesce(excluded.is_verified, contracts.is_verified),
                    age_status = coalesce(excluded.age_status, contracts.age_status),
                    rejection_reason = coalesce(excluded.rejection_reason, contracts.rejection_reason);
                """,
                (
                    chain,
                    addr,
                    contract.standard,
                    contract.name,
                    contract.symbol,
                    contract.owner.lower() if contract.owner else None,
                    contract.deployer.lower() if contract.deployer else None,
                    contract.deployed_block,
                    contract.deployed_tx_hash,
                    contract.deployed_timestamp,
                    int(contract.is_proxy) if contract.is_proxy is not None else None,
                    contract.proxy_implementation.lower() if contract.proxy_implementation else None,
                    int(contract.is_verified) if contract.is_verified is not None else None,
                    contract.age_status,
                    contract.rejection_reason,
                    created_at,
                ),
            )
            await db.commit()

    async def get_contract(self, address: str, chain: str = "ethereum") -> Optional[ContractRecord]:
        """Fetch a contract record by address and chain."""
        addr = address.lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM contracts WHERE chain = ? AND address = ?",
                (chain_key, addr),
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return None
                keys = row.keys()
                return ContractRecord(
                    address=row["address"],
                    chain=row["chain"],
                    standard=row["standard"],
                    name=row["name"],
                    symbol=row["symbol"],
                    owner=row["owner"] if "owner" in keys else None,
                    deployer=row["deployer"],
                    deployed_block=row["deployed_block"],
                    deployed_tx_hash=row["deployed_tx_hash"],
                    deployed_timestamp=row["deployed_timestamp"],
                    is_proxy=bool(row["is_proxy"]) if row["is_proxy"] is not None else None,
                    proxy_implementation=row["proxy_implementation"],
                    is_verified=bool(row["is_verified"]) if row["is_verified"] is not None else None,
                    age_status=row["age_status"] if "age_status" in keys else None,
                    rejection_reason=row["rejection_reason"] if "rejection_reason" in keys else None,
                    created_at=row["created_at"],
                )

    async def record_mint(self, mint: MintRecord) -> int:
        """
        Insert a single mint event, deduplicating by (chain_id, tx_hash, log_index).
        Returns the inserted mint rowid (> 0), or 0 if the event was a duplicate and suppressed.
        """
        addr = mint.contract_address.lower()
        minter = mint.minter_address.lower()
        chain_key = (mint.chain or "ethereum").lower()
        cid = resolve_chain_id(chain_key, mint.chain_id)
        log_idx = int(mint.log_index or 0)
        tx_clean = (mint.tx_hash or "").strip().lower()
        now_ts = int(mint.timestamp or time.time())

        async with aiosqlite.connect(self.db_path) as db:
            if tx_clean:
                cur_dedup = await db.execute(
                    """
                    INSERT OR IGNORE INTO processed_events (
                        chain_id, tx_hash, log_index, block_number, contract_address, processed_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (cid, tx_clean, log_idx, int(mint.block_number), addr, now_ts),
                )
                if cur_dedup.rowcount == 0:
                    await db.execute(
                        """
                        INSERT INTO suppressed_duplicates (
                            chain_id, chain, contract_address, reason, suppressed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (cid, chain_key, addr, f"duplicate_event:{tx_clean}:{log_idx}", now_ts),
                    )
                    await db.commit()
                    return 0

            cursor = await db.execute(
                """
                INSERT INTO mints (
                    chain, chain_id, contract_address, minter_address, tx_hash,
                    log_index, block_number, timestamp, token_id, quantity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_key,
                    cid,
                    addr,
                    minter,
                    mint.tx_hash,
                    log_idx,
                    mint.block_number,
                    mint.timestamp,
                    str(mint.token_id) if mint.token_id is not None else None,
                    mint.quantity,
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def record_mints_batch(self, mints: List[MintRecord]):
        """Batch insert mint records in a single transaction, deduplicating by (chain_id, tx_hash, log_index)."""
        if not mints:
            return
        async with aiosqlite.connect(self.db_path) as db:
            for m in mints:
                addr = m.contract_address.lower()
                minter = m.minter_address.lower()
                chain_key = (m.chain or "ethereum").lower()
                cid = resolve_chain_id(chain_key, m.chain_id)
                log_idx = int(m.log_index or 0)
                tx_clean = (m.tx_hash or "").strip().lower()
                now_ts = int(m.timestamp or time.time())
                if tx_clean:
                    cur_dedup = await db.execute(
                        """
                        INSERT OR IGNORE INTO processed_events (
                            chain_id, tx_hash, log_index, block_number, contract_address, processed_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (cid, tx_clean, log_idx, int(m.block_number), addr, now_ts),
                    )
                    if cur_dedup.rowcount == 0:
                        await db.execute(
                            """
                            INSERT INTO suppressed_duplicates (
                                chain_id, chain, contract_address, reason, suppressed_at
                            ) VALUES (?, ?, ?, ?, ?)
                            """,
                            (cid, chain_key, addr, f"duplicate_event:{tx_clean}:{log_idx}", now_ts),
                        )
                        continue
                await db.execute(
                    """
                    INSERT INTO mints (
                        chain, chain_id, contract_address, minter_address, tx_hash,
                        log_index, block_number, timestamp, token_id, quantity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chain_key,
                        cid,
                        addr,
                        minter,
                        m.tx_hash,
                        log_idx,
                        m.block_number,
                        m.timestamp,
                        str(m.token_id) if m.token_id is not None else None,
                        m.quantity,
                    ),
                )
            await db.commit()

    async def get_rolling_stats(
        self,
        contract_address: str,
        window_seconds: int,
        as_of_timestamp: Optional[int] = None,
        chain: str = "ethereum",
        excluded_addresses: Optional[List[str]] = None,
    ) -> RollingStats:
        """
        Calculate rolling count of total mints and unique minters for a contract on a chain
        within the past window_seconds from as_of_timestamp.
        Excludes contract owner, deployer, and the zero address (0x000...000) from unique_minters
        and total_mints, while counting owner/deployer mints separately in self_mints.
        """
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        cutoff = now - window_seconds
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()

        excluded_set = {ZERO_ADDRESS, ""}
        owner_deployer_set = set()
        if excluded_addresses:
            for ex in excluded_addresses:
                if ex:
                    ex_low = ex.strip().lower()
                    excluded_set.add(ex_low)
                    if ex_low != ZERO_ADDRESS:
                        owner_deployer_set.add(ex_low)

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT owner, deployer FROM contracts WHERE chain = ? AND address = ?",
                (chain_key, addr),
            ) as cur_c:
                crow = await cur_c.fetchone()
                if crow:
                    for col_val in crow:
                        if col_val:
                            c_low = str(col_val).strip().lower()
                            excluded_set.add(c_low)
                            if c_low != ZERO_ADDRESS:
                                owner_deployer_set.add(c_low)

            async with db.execute(
                """
                SELECT minter_address, COALESCE(SUM(quantity), 0) AS cnt
                FROM mints
                WHERE chain = ? AND contract_address = ? AND timestamp >= ? AND timestamp <= ?
                GROUP BY minter_address
                """,
                (chain_key, addr, cutoff, now),
            ) as cursor:
                rows = await cursor.fetchall()

        total_mints = 0
        unique_minters = 0
        self_mints = 0
        raw_total_mints = 0

        for minter_addr, cnt in rows:
            m_low = (minter_addr or "").strip().lower()
            c_int = int(cnt)
            raw_total_mints += c_int
            if m_low in owner_deployer_set:
                self_mints += c_int
            elif m_low not in excluded_set:
                total_mints += c_int
                unique_minters += 1

        minutes = max(window_seconds / 60.0, 1.0 / 60.0)
        mints_per_minute = round(total_mints / minutes, 2)

        return RollingStats(
            contract_address=addr,
            total_mints=total_mints,
            unique_minters=unique_minters,
            mints_per_minute=mints_per_minute,
            window_seconds=window_seconds,
            as_of_timestamp=now,
            chain=chain_key,
            self_mints=self_mints,
            raw_total_mints=raw_total_mints,
        )

    async def is_in_cooldown(
        self,
        contract_address: str,
        cooldown_seconds: int,
        as_of_timestamp: Optional[int] = None,
        chain: str = "ethereum",
    ) -> bool:
        """Check if an alert was triggered for this contract on this chain within cooldown_seconds."""
        if cooldown_seconds <= 0:
            return False
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        cutoff = now - cooldown_seconds
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT 1 FROM alerts
                WHERE chain = ? AND contract_address = ? AND alerted_at >= ?
                LIMIT 1
                """,
                (chain_key, addr, cutoff),
            ) as cursor:
                row = await cursor.fetchone()
                return row is not None

    async def record_alert(
        self,
        contract_address: str,
        unique_minters: int,
        total_mints: int,
        mints_per_minute: float,
        window_seconds: int,
        alerted_at: Optional[int] = None,
        telegram_message_id: Optional[str] = None,
        chain: str = "ethereum",
        chain_id: Optional[int] = None,
        sold_out: bool = False,
        is_sold_out: Optional[bool] = None,
        contract_name: Optional[str] = None,
        alert_tier: str = "Tier C",
        quality_score: Optional[int] = None,
        risk_score: Optional[int] = None,
        risk_level: str = "Low",
        watched_wallets_count: int = 0,
    ) -> int:
        """Record an alert firing in `alerts` and update `alert_state` keyed on (chain_id, contract_address)."""
        ts = alerted_at if alerted_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        cid = resolve_chain_id(chain_key, chain_id)
        eff_sold_out = bool(is_sold_out if is_sold_out is not None else sold_out)
        eff_tier = str(alert_tier or "Tier C")
        eff_risk_level = str(risk_level or "Low")

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO alerts (
                    chain, contract_address, contract_name, unique_minters, total_mints,
                    mints_per_minute, window_seconds, alerted_at, telegram_message_id,
                    alert_tier, quality_score, risk_score, risk_level, watched_wallets_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_key,
                    addr,
                    contract_name,
                    unique_minters,
                    total_mints,
                    mints_per_minute,
                    window_seconds,
                    ts,
                    telegram_message_id,
                    eff_tier,
                    int(quality_score) if quality_score is not None else None,
                    int(risk_score) if risk_score is not None else None,
                    eff_risk_level,
                    int(watched_wallets_count or 0),
                ),
            )
            await db.execute(
                """
                INSERT INTO alert_state (
                    chain_id, contract_address, chain, first_alerted_at, last_alerted_at,
                    alert_count, status, first_message_id, last_message_id,
                    last_unique_minters, last_total_mints, last_sold_out, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, 'alerted', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, contract_address) DO UPDATE SET
                    chain = excluded.chain,
                    first_alerted_at = coalesce(alert_state.first_alerted_at, excluded.first_alerted_at),
                    last_alerted_at = excluded.last_alerted_at,
                    alert_count = alert_state.alert_count + 1,
                    status = CASE WHEN alert_state.status = 'muted' THEN 'muted' ELSE 'alerted' END,
                    first_message_id = coalesce(alert_state.first_message_id, excluded.first_message_id),
                    last_message_id = coalesce(excluded.last_message_id, alert_state.last_message_id),
                    last_unique_minters = excluded.last_unique_minters,
                    last_total_mints = excluded.last_total_mints,
                    last_sold_out = CASE WHEN excluded.last_sold_out = 1 THEN 1 ELSE alert_state.last_sold_out END,
                    updated_at = excluded.updated_at;
                """,
                (
                    cid,
                    addr,
                    chain_key,
                    ts,
                    ts,
                    telegram_message_id,
                    telegram_message_id,
                    int(unique_minters),
                    int(total_mints),
                    1 if eff_sold_out else 0,
                    ts,
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def get_status_metrics(
        self,
        window_seconds: int = 300,
        as_of_timestamp: Optional[int] = None,
        chain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return live SQLite counts (global, per-chain, and 24-hour alert/rejection/duplicate metrics) for /status."""
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        cutoff = now - window_seconds
        cutoff_24h = now - 86400

        async with aiosqlite.connect(self.db_path) as db:
            if chain:
                ck = chain.lower()
                async with db.execute("SELECT COUNT(*) FROM contracts WHERE chain = ?", (ck,)) as cur:
                    row = await cur.fetchone()
                    contracts_count = int(row[0]) if row else 0
                async with db.execute(
                    "SELECT COUNT(*) FROM mints WHERE chain = ? AND timestamp >= ?",
                    (ck, cutoff),
                ) as cur:
                    row = await cur.fetchone()
                    recent_mints_count = int(row[0]) if row else 0
                async with db.execute("SELECT COUNT(*) FROM mints WHERE chain = ?", (ck,)) as cur:
                    row = await cur.fetchone()
                    total_mints_count = int(row[0]) if row else 0
                async with db.execute("SELECT COUNT(*) FROM alerts WHERE chain = ?", (ck,)) as cur:
                    row = await cur.fetchone()
                    alerts_count = int(row[0]) if row else 0
                async with db.execute(
                    "SELECT COUNT(*) FROM alerts WHERE chain = ? AND alerted_at >= ?",
                    (ck, cutoff_24h),
                ) as cur:
                    row = await cur.fetchone()
                    alerts_24h = int(row[0]) if row else 0
                async with db.execute(
                    "SELECT COUNT(*) FROM alert_state WHERE chain = ? AND status IN ('rejected_old', 'too_old') AND updated_at >= ?",
                    (ck, cutoff_24h),
                ) as cur:
                    row = await cur.fetchone()
                    rejected_old_24h = int(row[0]) if row else 0
                async with db.execute(
                    "SELECT COUNT(*) FROM alert_state WHERE chain = ? AND status IN ('rejected_unknown_age', 'age_unknown') AND updated_at >= ?",
                    (ck, cutoff_24h),
                ) as cur:
                    row = await cur.fetchone()
                    rejected_unk_24h = int(row[0]) if row else 0
                async with db.execute(
                    "SELECT COUNT(*) FROM suppressed_duplicates WHERE chain = ? AND suppressed_at >= ?",
                    (ck, cutoff_24h),
                ) as cur:
                    row = await cur.fetchone()
                    dups_24h = int(row[0]) if row else 0
                return {
                    "contracts_tracked": contracts_count,
                    "mints_last_window": recent_mints_count,
                    "total_mints": total_mints_count,
                    "total_alerts": alerts_count,
                    "alerts_sent_24h": alerts_24h,
                    "rejected_old_24h": rejected_old_24h,
                    "rejected_unknown_age_24h": rejected_unk_24h,
                    "duplicates_suppressed_24h": dups_24h,
                }

            async with db.execute("SELECT COUNT(*) FROM contracts") as cur:
                row = await cur.fetchone()
                contracts_count = int(row[0]) if row else 0

            async with db.execute(
                "SELECT COUNT(*) FROM mints WHERE timestamp >= ?",
                (cutoff,),
            ) as cur:
                row = await cur.fetchone()
                recent_mints_count = int(row[0]) if row else 0

            async with db.execute("SELECT COUNT(*) FROM mints") as cur:
                row = await cur.fetchone()
                total_mints_count = int(row[0]) if row else 0

            async with db.execute("SELECT COUNT(*) FROM alerts") as cur:
                row = await cur.fetchone()
                alerts_count = int(row[0]) if row else 0

            async with db.execute("SELECT COUNT(*) FROM alerts WHERE alerted_at >= ?", (cutoff_24h,)) as cur:
                row = await cur.fetchone()
                alerts_24h = int(row[0]) if row else 0

            async with db.execute(
                "SELECT COUNT(*) FROM alert_state WHERE status IN ('rejected_old', 'too_old') AND updated_at >= ?",
                (cutoff_24h,),
            ) as cur:
                row = await cur.fetchone()
                rejected_old_24h = int(row[0]) if row else 0

            async with db.execute(
                "SELECT COUNT(*) FROM alert_state WHERE status IN ('rejected_unknown_age', 'age_unknown') AND updated_at >= ?",
                (cutoff_24h,),
            ) as cur:
                row = await cur.fetchone()
                rejected_unk_24h = int(row[0]) if row else 0

            async with db.execute(
                "SELECT COUNT(*) FROM suppressed_duplicates WHERE suppressed_at >= ?",
                (cutoff_24h,),
            ) as cur:
                row = await cur.fetchone()
                dups_24h = int(row[0]) if row else 0

            per_chain_contracts: Dict[str, int] = {}
            async with db.execute("SELECT chain, COUNT(*) FROM contracts GROUP BY chain") as cur:
                async for r in cur:
                    per_chain_contracts[str(r[0]).lower()] = int(r[1])

            per_chain_mints_5m: Dict[str, int] = {}
            async with db.execute(
                "SELECT chain, COUNT(*) FROM mints WHERE timestamp >= ? GROUP BY chain",
                (cutoff,),
            ) as cur:
                async for r in cur:
                    per_chain_mints_5m[str(r[0]).lower()] = int(r[1])

        return {
            "contracts_tracked": contracts_count,
            "mints_last_window": recent_mints_count,
            "total_mints": total_mints_count,
            "total_alerts": alerts_count,
            "alerts_sent_24h": alerts_24h,
            "rejected_old_24h": rejected_old_24h,
            "rejected_unknown_age_24h": rejected_unk_24h,
            "duplicates_suppressed_24h": dups_24h,
            "per_chain_contracts": per_chain_contracts,
            "per_chain_mints_last_window": per_chain_mints_5m,
        }

    async def get_cached_enrichment(
        self,
        contract_address: str,
        ttl_seconds: int = 600,
        as_of_timestamp: Optional[int] = None,
        chain: str = "ethereum",
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached contract enrichment payload if within TTL."""
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        cutoff = now - ttl_seconds
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT payload_json FROM contract_enrichment_cache
                WHERE chain = ? AND contract_address = ? AND updated_at >= ?
                """,
                (chain_key, addr, cutoff),
            ) as cur:
                row = await cur.fetchone()
                if row and row[0]:
                    try:
                        return json.loads(row[0])
                    except Exception:
                        return None
        return None

    async def set_cached_enrichment(
        self,
        contract_address: str,
        payload: Dict[str, Any],
        updated_at: Optional[int] = None,
        chain: str = "ethereum",
    ):
        """Store or update contract enrichment payload in SQLite cache."""
        now = updated_at if updated_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        payload_str = json.dumps(payload)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO contract_enrichment_cache (chain, contract_address, payload_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(chain, contract_address) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at;
                """,
                (chain_key, addr, payload_str, now),
            )
            await db.commit()

    async def get_cached_uri_metadata(
        self,
        uri: str,
        ttl_seconds: int = 3600,
        as_of_timestamp: Optional[int] = None,
        chain: str = "ethereum",
    ) -> Optional[Tuple[Optional[Dict[str, Any]], str, Optional[str]]]:
        """Retrieve cached resolved URI metadata (payload_dict, status, error) if within TTL."""
        if not uri:
            return None
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        cutoff = now - ttl_seconds
        chain_key = (chain or "ethereum").lower()

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT payload_json, status, error
                FROM uri_metadata_cache
                WHERE chain = ? AND uri = ? AND updated_at >= ?
                """,
                (chain_key, uri.strip(), cutoff),
            ) as cur:
                row = await cur.fetchone()
                if row:
                    parsed: Optional[Dict[str, Any]] = None
                    if row[0]:
                        try:
                            obj = json.loads(row[0])
                            if isinstance(obj, dict):
                                parsed = obj
                        except Exception:
                            parsed = None
                    return parsed, str(row[1]), (str(row[2]) if row[2] is not None else None)
        return None

    async def set_cached_uri_metadata(
        self,
        uri: str,
        payload: Optional[Dict[str, Any]],
        status: str,
        error: Optional[str] = None,
        updated_at: Optional[int] = None,
        chain: str = "ethereum",
    ) -> None:
        """Store resolved URI metadata JSON and status in SQLite cache."""
        if not uri:
            return
        now = updated_at if updated_at is not None else int(time.time())
        chain_key = (chain or "ethereum").lower()
        payload_str = json.dumps(payload) if isinstance(payload, dict) else None

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO uri_metadata_cache (chain, uri, payload_json, status, error, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, uri) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    status = excluded.status,
                    error = excluded.error,
                    updated_at = excluded.updated_at;
                """,
                (chain_key, uri.strip(), payload_str, status, error, now),
            )
            await db.commit()

    async def get_last_processed_block(self, chain: str = "ethereum") -> Optional[int]:
        """Fetch the last processed block number for a chain from SQLite."""
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT last_processed_block FROM chain_sync_state WHERE chain = ?;",
                (chain_key,),
            ) as cursor:
                row = await cursor.fetchone()
                if row and row[0] is not None:
                    return int(row[0])
                return None

    async def set_last_processed_block(
        self,
        chain: str,
        block_number: int,
        updated_at: Optional[int] = None,
    ) -> None:
        """Persist the last processed block number for a chain in SQLite."""
        chain_key = (chain or "ethereum").lower()
        now = updated_at if updated_at is not None else int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO chain_sync_state (chain, last_processed_block, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(chain) DO UPDATE SET
                    last_processed_block = excluded.last_processed_block,
                    updated_at = excluded.updated_at;
                """,
                (chain_key, int(block_number), now),
            )
            await db.commit()

    async def get_heartbeat_metrics(self, since_timestamp: int) -> Dict[str, Any]:
        """Fetch telemetry metrics for the given period for the Telegram heartbeat."""
        async with aiosqlite.connect(self.db_path) as db:
            # 1. Distinct contracts seen in mints
            async with db.execute(
                "SELECT count(DISTINCT contract_address) FROM mints WHERE timestamp >= ?;",
                (since_timestamp,),
            ) as cursor:
                row = await cursor.fetchone()
                contracts_seen = int(row[0]) if row and row[0] is not None else 0

            # 2. Threshold candidates (crossed >= 15 unique minters in period)
            async with db.execute(
                """
                SELECT count(*) FROM (
                    SELECT contract_address FROM mints
                    WHERE timestamp >= ?
                    GROUP BY chain, contract_address
                    HAVING count(DISTINCT minter_address) >= 15
                );
                """,
                (since_timestamp,),
            ) as cursor:
                row = await cursor.fetchone()
                threshold_candidates = int(row[0]) if row and row[0] is not None else 0

            # 3. Rejections by status / reason from rejected_contracts and suppressed_duplicates
            rejections: Dict[str, int] = {}
            async with db.execute(
                "SELECT status, count(*) FROM rejected_contracts WHERE rejected_at >= ? GROUP BY status;",
                (since_timestamp,),
            ) as cursor:
                for st, cnt in await cursor.fetchall():
                    if st:
                        rejections[st] = rejections.get(st, 0) + int(cnt)

            async with db.execute(
                "SELECT duplicate_type, count(*) FROM suppressed_duplicates WHERE suppressed_at >= ? GROUP BY duplicate_type;",
                (since_timestamp,),
            ) as cursor:
                for dt, cnt in await cursor.fetchall():
                    if dt and not str(dt).startswith("duplicate_event:"):
                        rejections[dt] = rejections.get(dt, 0) + int(cnt)

            # 4. Alerts count
            async with db.execute(
                "SELECT count(*) FROM alerts WHERE alerted_at >= ?;",
                (since_timestamp,),
            ) as cursor:
                row = await cursor.fetchone()
                alerts_count = int(row[0]) if row and row[0] is not None else 0

            return {
                "contracts_seen": contracts_seen,
                "threshold_candidates": threshold_candidates,
                "rejections": rejections,
                "alerts_count": alerts_count,
            }

    async def get_top_minters(
        self,
        contract_address: str,
        limit: int = 5,
        chain: str = "ethereum",
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Compute top-N minter wallets and their percentage share of recorded mints for a contract.
        Excludes the zero address (0x000...000).
        Returns (total_minted_quantity, [{"address": str, "count": int, "pct": float}, ...]).
        """
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT COALESCE(SUM(quantity), 0)
                FROM mints
                WHERE chain = ? AND contract_address = ? AND minter_address != ? AND minter_address != ''
                """,
                (chain_key, addr, ZERO_ADDRESS),
            ) as cur:
                row = await cur.fetchone()
                total_qty = int(row[0]) if row and row[0] else 0

            if total_qty <= 0:
                return 0, []

            async with db.execute(
                """
                SELECT minter_address, COALESCE(SUM(quantity), 0) AS minted_qty
                FROM mints
                WHERE chain = ? AND contract_address = ? AND minter_address != ? AND minter_address != ''
                GROUP BY minter_address
                ORDER BY minted_qty DESC
                LIMIT ?
                """,
                (chain_key, addr, ZERO_ADDRESS, limit),
            ) as cur:
                rows = await cur.fetchall()

        top_list = []
        for minter_addr, qty in rows:
            q = int(qty)
            pct = round((q / total_qty) * 100.0, 1) if total_qty > 0 else 0.0
            top_list.append(
                {
                    "address": minter_addr,
                    "count": q,
                    "pct": pct,
                }
            )
        return total_qty, top_list

    async def get_self_mint_stats(
        self,
        contract_address: str,
        owner: Optional[str] = None,
        deployer: Optional[str] = None,
        chain: str = "ethereum",
    ) -> Tuple[int, int, float]:
        """
        Return (self_mints_count, total_mints_including_self, self_mint_pct) for a contract.
        Self-mints are mints by the contract owner or deployer (excluding the zero address).
        """
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        owner_deployer_set = set()
        for candidate in (owner, deployer):
            if candidate:
                c_low = candidate.strip().lower()
                if c_low and c_low != ZERO_ADDRESS:
                    owner_deployer_set.add(c_low)

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT owner, deployer FROM contracts WHERE chain = ? AND address = ?",
                (chain_key, addr),
            ) as cur_c:
                crow = await cur_c.fetchone()
                if crow:
                    for col_val in crow:
                        if col_val:
                            c_low = str(col_val).strip().lower()
                            if c_low and c_low != ZERO_ADDRESS:
                                owner_deployer_set.add(c_low)

            async with db.execute(
                """
                SELECT minter_address, COALESCE(SUM(quantity), 0) AS cnt
                FROM mints
                WHERE chain = ? AND contract_address = ? AND minter_address != ? AND minter_address != ''
                GROUP BY minter_address
                """,
                (chain_key, addr, ZERO_ADDRESS),
            ) as cur:
                rows = await cur.fetchall()

        self_mints = 0
        total_all = 0
        for minter_addr, cnt in rows:
            m_low = (minter_addr or "").strip().lower()
            c_int = int(cnt)
            total_all += c_int
            if m_low in owner_deployer_set:
                self_mints += c_int

        pct = round((self_mints / total_all) * 100.0, 1) if total_all > 0 else 0.0
        return self_mints, total_all, pct

    async def get_observed_token_ids(
        self,
        contract_address: str,
        limit: int = 5,
        chain: str = "ethereum",
    ) -> List[int]:
        """Fetch distinct numeric token IDs observed in real mint events for a contract."""
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT DISTINCT token_id
                FROM mints
                WHERE chain = ? AND contract_address = ? AND token_id IS NOT NULL AND token_id != ''
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (chain_key, addr, limit),
            ) as cur:
                rows = await cur.fetchall()
        token_ids: List[int] = []
        for (tid_str,) in rows:
            try:
                val = int(str(tid_str), 0)
                if val >= 0 and val not in token_ids:
                    token_ids.append(val)
            except (ValueError, TypeError):
                continue
        return token_ids

    async def get_cached_selector(self, selector: str) -> Optional[str]:
        """Retrieve a cached function signature for a 4-byte selector (e.g. '0xa0712d68')."""
        sel = selector.strip().lower()
        if not sel.startswith("0x"):
            sel = "0x" + sel
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT signature FROM selector_signatures WHERE selector = ?",
                (sel,),
            ) as cur:
                row = await cur.fetchone()
                return str(row[0]) if row and row[0] else None

    async def set_cached_selector(self, selector: str, signature: str):
        """Persist a decoded function signature for a 4-byte selector in SQLite."""
        sel = selector.strip().lower()
        if not sel.startswith("0x"):
            sel = "0x" + sel
        now = int(time.time())
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO selector_signatures (selector, signature, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(selector) DO UPDATE SET
                    signature = excluded.signature,
                    updated_at = excluded.updated_at;
                """,
                (sel, signature, now),
            )
            await db.commit()

    async def get_recent_mint_tx_hashes(
        self,
        contract_address: str,
        limit: int = 5,
        chain: str = "ethereum",
    ) -> List[str]:
        """Fetch recent distinct transaction hashes for mints of a contract."""
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT DISTINCT tx_hash
                FROM mints
                WHERE chain = ? AND contract_address = ? AND tx_hash != ''
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (chain_key, addr, limit),
            ) as cur:
                rows = await cur.fetchall()
                return [r[0] for r in rows if r[0]]

    async def get_latest_mint_event(
        self,
        contract_address: str,
        chain: str = "ethereum",
    ) -> Tuple[Optional[int], Optional[str]]:
        """Fetch the most recent (block_number, tx_hash) recorded in SQLite for a contract."""
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT block_number, tx_hash
                FROM mints
                WHERE chain = ? AND contract_address = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT 1
                """,
                (chain_key, addr),
            ) as cur:
                row = await cur.fetchone()
                if row:
                    blk = int(row[0]) if row[0] is not None else None
                    txh = str(row[1]) if row[1] else None
                    return blk, txh
                return None, None

    async def get_sample_mint_holder(
        self,
        contract_address: str,
        chain: str = "ethereum",
    ) -> Tuple[Optional[str], Optional[str]]:
        """Fetch a recent (minter_address, token_id) recorded in SQLite for honeypot simulation and token links."""
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT minter_address, token_id
                FROM mints
                WHERE chain = ? AND contract_address = ? AND minter_address != '' AND minter_address != ?
                ORDER BY (CASE WHEN token_id IS NOT NULL AND token_id != '' THEN 0 ELSE 1 END), timestamp DESC, id DESC
                LIMIT 1
                """,
                (chain_key, addr, ZERO_ADDRESS),
            ) as cur:
                row = await cur.fetchone()
                if row:
                    return str(row[0]) if row[0] else None, str(row[1]) if row[1] not in (None, "") else None
                return None, None

    async def record_risk_score(
        self,
        contract_address: str,
        score: int,
        risk_level: str,
        reasons: List[str],
        checks: List[Dict[str, Any]],
        scored_at: Optional[int] = None,
        chain: str = "ethereum",
    ) -> int:
        """Persist a computed risk score and its full check-by-check breakdown to SQLite."""
        ts = scored_at if scored_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        reasons_str = json.dumps(reasons)
        checks_str = json.dumps(checks)

        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                """
                INSERT INTO risk_scores (
                    chain, contract_address, score, risk_level,
                    reasons_json, checks_json, scored_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (chain_key, addr, int(score), str(risk_level), reasons_str, checks_str, ts),
            )
            await db.commit()
            return cur.lastrowid

    async def get_latest_risk_score(
        self,
        contract_address: str,
        chain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent logged risk score and check breakdown for a contract."""
        addr = contract_address.lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                query = (
                    "SELECT * FROM risk_scores WHERE chain = ? AND contract_address = ? "
                    "ORDER BY scored_at DESC, id DESC LIMIT 1"
                )
                params: Tuple[Any, ...] = (chain.lower(), addr)
            else:
                query = (
                    "SELECT * FROM risk_scores WHERE contract_address = ? "
                    "ORDER BY scored_at DESC, id DESC LIMIT 1"
                )
                params = (addr,)

            async with db.execute(query, params) as cur:
                row = await cur.fetchone()
                if not row:
                    return None
                try:
                    reasons = json.loads(row["reasons_json"]) if row["reasons_json"] else []
                except Exception:
                    reasons = []
                try:
                    checks = json.loads(row["checks_json"]) if row["checks_json"] else []
                except Exception:
                    checks = []
                return {
                    "id": row["id"],
                    "chain": row["chain"],
                    "contract_address": row["contract_address"],
                    "score": int(row["score"]),
                    "risk_level": row["risk_level"],
                    "reasons": reasons,
                    "checks": checks,
                    "scored_at": int(row["scored_at"]),
                }

    async def find_tracked_contract_chain(self, contract_address: str) -> Optional[str]:
        """Find which chain a contract is tracked on across risk_scores, contracts, or mints."""
        addr = contract_address.lower()
        async with aiosqlite.connect(self.db_path) as db:
            for sql in (
                "SELECT chain FROM risk_scores WHERE contract_address = ? ORDER BY scored_at DESC LIMIT 1",
                "SELECT chain FROM contracts WHERE address = ? ORDER BY created_at DESC LIMIT 1",
                "SELECT chain FROM mints WHERE contract_address = ? ORDER BY timestamp DESC LIMIT 1",
            ):
                async with db.execute(sql, (addr,)) as cur:
                    row = await cur.fetchone()
                    if row and row[0]:
                        return str(row[0]).lower()
        return None

    async def record_rejected_contract(
        self,
        contract_address: str,
        status: str,
        reason: str,
        chain: str = "ethereum",
        chain_id: Optional[int] = None,
        deployed_block: Optional[int] = None,
        deployed_timestamp: Optional[int] = None,
        deployment_date: Optional[str] = None,
        age_seconds: Optional[int] = None,
        age_formatted: Optional[str] = None,
        rejected_at: Optional[int] = None,
    ) -> int:
        """
        Store a rejected contract ('rejected_unknown_age' or 'rejected_old') in SQLite `rejected_contracts`,
        `alert_state` (keyed on (chain_id, contract_address)), and `contracts`.
        """
        now = rejected_at if rejected_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        cid = resolve_chain_id(chain_key, chain_id)

        state_status = status
        if status == "too_old":
            state_status = "rejected_old"
        elif status == "age_unknown":
            state_status = "rejected_unknown_age"

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO rejected_contracts (
                    chain, contract_address, deployed_block, deployed_timestamp,
                    deployment_date, age_seconds, age_formatted, status, reason, rejected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, contract_address) DO UPDATE SET
                    deployed_block = coalesce(excluded.deployed_block, rejected_contracts.deployed_block),
                    deployed_timestamp = coalesce(excluded.deployed_timestamp, rejected_contracts.deployed_timestamp),
                    deployment_date = coalesce(excluded.deployment_date, rejected_contracts.deployment_date),
                    age_seconds = coalesce(excluded.age_seconds, rejected_contracts.age_seconds),
                    age_formatted = coalesce(excluded.age_formatted, rejected_contracts.age_formatted),
                    status = excluded.status,
                    reason = excluded.reason,
                    rejected_at = excluded.rejected_at;
                """,
                (
                    chain_key,
                    addr,
                    deployed_block,
                    deployed_timestamp,
                    deployment_date,
                    age_seconds,
                    age_formatted,
                    status,
                    reason,
                    now,
                ),
            )
            await db.execute(
                """
                INSERT INTO alert_state (
                    chain_id, contract_address, chain, first_alerted_at, last_alerted_at,
                    alert_count, status, deployed_block, deployed_timestamp,
                    deployment_date, age_seconds, age_formatted, reason, updated_at
                ) VALUES (?, ?, ?, NULL, NULL, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, contract_address) DO UPDATE SET
                    chain = excluded.chain,
                    status = CASE WHEN alert_state.status = 'muted' THEN 'muted' ELSE excluded.status END,
                    deployed_block = coalesce(excluded.deployed_block, alert_state.deployed_block),
                    deployed_timestamp = coalesce(excluded.deployed_timestamp, alert_state.deployed_timestamp),
                    deployment_date = coalesce(excluded.deployment_date, alert_state.deployment_date),
                    age_seconds = coalesce(excluded.age_seconds, alert_state.age_seconds),
                    age_formatted = coalesce(excluded.age_formatted, alert_state.age_formatted),
                    reason = excluded.reason,
                    updated_at = excluded.updated_at;
                """,
                (
                    cid,
                    addr,
                    chain_key,
                    state_status,
                    deployed_block,
                    deployed_timestamp,
                    deployment_date,
                    age_seconds,
                    age_formatted,
                    reason,
                    now,
                ),
            )
            await db.execute(
                """
                INSERT INTO contracts (
                    chain, address, standard, deployed_block, deployed_timestamp,
                    age_status, rejection_reason, created_at
                ) VALUES (?, ?, 'UNKNOWN', ?, ?, ?, ?, ?)
                ON CONFLICT(chain, address) DO UPDATE SET
                    deployed_block = coalesce(excluded.deployed_block, contracts.deployed_block),
                    deployed_timestamp = coalesce(excluded.deployed_timestamp, contracts.deployed_timestamp),
                    age_status = excluded.age_status,
                    rejection_reason = excluded.rejection_reason;
                """,
                (chain_key, addr, deployed_block, deployed_timestamp, status, reason, now),
            )
            await db.commit()
            return cursor.lastrowid

    async def get_recent_rejected_contracts(
        self,
        limit: int = 20,
        chain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the last N rejected contracts ordered by rejected_at DESC."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                query = (
                    "SELECT * FROM rejected_contracts WHERE chain = ? "
                    "ORDER BY rejected_at DESC, id DESC LIMIT ?"
                )
                params: Tuple[Any, ...] = (chain.lower(), limit)
            else:
                query = (
                    "SELECT * FROM rejected_contracts "
                    "ORDER BY rejected_at DESC, id DESC LIMIT ?"
                )
                params = (limit,)

            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()
                return [
                    {
                        "id": r["id"],
                        "chain": r["chain"],
                        "contract_address": r["contract_address"],
                        "deployed_block": r["deployed_block"],
                        "deployed_timestamp": r["deployed_timestamp"],
                        "deployment_date": r["deployment_date"],
                        "age_seconds": r["age_seconds"],
                        "age_formatted": r["age_formatted"],
                        "status": r["status"],
                        "reason": r["reason"],
                        "rejected_at": r["rejected_at"],
                    }
                    for r in rows
                ]

    async def get_alert_state(
        self,
        chain_id: int,
        contract_address: str,
        chain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch persistent alert state keyed on (chain_id, contract_address).
        Status is one of: 'alerted', 'rejected_old', 'rejected_unknown_age', 'muted'.
        """
        addr = contract_address.lower()
        cid = resolve_chain_id(chain, chain_id)
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM alert_state WHERE chain_id = ? AND contract_address = ?;",
                (cid, addr),
            ) as cur:
                row = await cur.fetchone()
                if not row:
                    return None
                return {
                    "chain_id": int(row["chain_id"]),
                    "contract_address": row["contract_address"],
                    "chain": row["chain"],
                    "first_alerted_at": row["first_alerted_at"],
                    "last_alerted_at": row["last_alerted_at"],
                    "alert_count": int(row["alert_count"] or 0),
                    "status": row["status"],
                    "first_message_id": row["first_message_id"],
                    "last_message_id": row["last_message_id"],
                    "last_unique_minters": int(row["last_unique_minters"] or 0),
                    "last_total_mints": int(row["last_total_mints"] or 0),
                    "last_sold_out": bool(row["last_sold_out"]),
                    "deployed_block": row["deployed_block"],
                    "deployed_timestamp": row["deployed_timestamp"],
                    "deployment_date": row["deployment_date"],
                    "age_seconds": row["age_seconds"],
                    "age_formatted": row["age_formatted"],
                    "reason": row["reason"],
                    "updated_at": int(row["updated_at"]),
                }

    async def upsert_alert_state(
        self,
        chain_id: int,
        contract_address: str,
        status: str,
        chain: str = "ethereum",
        first_alerted_at: Optional[int] = None,
        last_alerted_at: Optional[int] = None,
        alert_count: Optional[int] = None,
        first_message_id: Optional[str] = None,
        last_message_id: Optional[str] = None,
        last_unique_minters: Optional[int] = None,
        last_total_mints: Optional[int] = None,
        last_sold_out: Optional[bool] = None,
        deployed_block: Optional[int] = None,
        deployed_timestamp: Optional[int] = None,
        deployment_date: Optional[str] = None,
        age_seconds: Optional[int] = None,
        age_formatted: Optional[str] = None,
        reason: Optional[str] = None,
        updated_at: Optional[int] = None,
    ) -> None:
        """Insert or update a row in `alert_state` keyed on (chain_id, contract_address)."""
        now = updated_at if updated_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or CHAIN_ID_TO_KEY.get(int(chain_id), "ethereum")).lower()
        cid = resolve_chain_id(chain_key, chain_id)
        cnt = int(alert_count) if alert_count is not None else (1 if status == "alerted" else 0)
        sold_int = 1 if last_sold_out else 0

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO alert_state (
                    chain_id, contract_address, chain, first_alerted_at, last_alerted_at,
                    alert_count, status, first_message_id, last_message_id,
                    last_unique_minters, last_total_mints, last_sold_out,
                    deployed_block, deployed_timestamp, deployment_date,
                    age_seconds, age_formatted, reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, contract_address) DO UPDATE SET
                    chain = excluded.chain,
                    first_alerted_at = coalesce(alert_state.first_alerted_at, excluded.first_alerted_at),
                    last_alerted_at = coalesce(excluded.last_alerted_at, alert_state.last_alerted_at),
                    alert_count = CASE
                        WHEN ? IS NOT NULL THEN excluded.alert_count
                        ELSE alert_state.alert_count
                    END,
                    status = excluded.status,
                    first_message_id = coalesce(alert_state.first_message_id, excluded.first_message_id),
                    last_message_id = coalesce(excluded.last_message_id, alert_state.last_message_id),
                    last_unique_minters = coalesce(?, alert_state.last_unique_minters),
                    last_total_mints = coalesce(?, alert_state.last_total_mints),
                    last_sold_out = CASE WHEN ? = 1 THEN 1 ELSE alert_state.last_sold_out END,
                    deployed_block = coalesce(excluded.deployed_block, alert_state.deployed_block),
                    deployed_timestamp = coalesce(excluded.deployed_timestamp, alert_state.deployed_timestamp),
                    deployment_date = coalesce(excluded.deployment_date, alert_state.deployment_date),
                    age_seconds = coalesce(excluded.age_seconds, alert_state.age_seconds),
                    age_formatted = coalesce(excluded.age_formatted, alert_state.age_formatted),
                    reason = coalesce(excluded.reason, alert_state.reason),
                    updated_at = excluded.updated_at;
                """,
                (
                    cid,
                    addr,
                    chain_key,
                    first_alerted_at,
                    last_alerted_at,
                    cnt,
                    status,
                    first_message_id,
                    last_message_id,
                    int(last_unique_minters or 0),
                    int(last_total_mints or 0),
                    sold_int,
                    deployed_block,
                    deployed_timestamp,
                    deployment_date,
                    age_seconds,
                    age_formatted,
                    reason,
                    now,
                    alert_count,
                    last_unique_minters,
                    last_total_mints,
                    sold_int,
                ),
            )
            await db.commit()

    async def mute_contract(
        self,
        contract_address: str,
        chain_id: Optional[int] = None,
        chain: str = "ethereum",
        reason: str = "Muted via Telegram",
        muted_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Mark a contract as `muted` in `alert_state` keyed on (chain_id, contract_address)."""
        now = muted_at if muted_at is not None else int(time.time())
        chain_key = (chain or (CHAIN_ID_TO_KEY.get(int(chain_id), "ethereum") if chain_id else "ethereum")).lower()
        cid = resolve_chain_id(chain_key, chain_id)
        addr = contract_address.lower()
        await self.upsert_alert_state(
            chain_id=cid,
            contract_address=addr,
            chain=chain_key,
            status="muted",
            reason=reason or "Muted via Telegram",
            updated_at=now,
        )
        return (await self.get_alert_state(cid, addr, chain=chain_key)) or {
            "chain_id": cid,
            "contract_address": addr,
            "chain": chain_key,
            "status": "muted",
            "reason": reason or "Muted via Telegram",
            "updated_at": now,
        }

    async def unmute_contract(
        self,
        contract_address: str,
        chain: Optional[str] = None,
        chain_id: Optional[int] = None,
    ) -> bool:
        """
        Unmute a contract in `alert_state`.
        Removes the 'muted' state so the contract is no longer muted.
        Returns True if a muted record was found and unmuted.
        """
        addr = contract_address.lower()
        async with aiosqlite.connect(self.db_path) as db:
            if chain_id is not None or chain is not None:
                cid = resolve_chain_id(chain, chain_id)
                cur = await db.execute(
                    "DELETE FROM alert_state WHERE chain_id = ? AND contract_address = ? AND status = 'muted';",
                    (cid, addr),
                )
                if cur.rowcount == 0 and chain:
                    cur = await db.execute(
                        "DELETE FROM alert_state WHERE chain = ? AND contract_address = ? AND status = 'muted';",
                        (chain.lower(), addr),
                    )
            else:
                cur = await db.execute(
                    "DELETE FROM alert_state WHERE contract_address = ? AND status = 'muted';",
                    (addr,),
                )
            await db.commit()
            return (cur.rowcount or 0) > 0

    async def get_muted_contracts(
        self,
        limit: int = 50,
        chain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return all muted contracts from `alert_state` ordered by updated_at DESC."""
        from eth_utils import to_checksum_address
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                query = (
                    "SELECT * FROM alert_state WHERE status = 'muted' AND chain = ? "
                    "ORDER BY updated_at DESC LIMIT ?"
                )
                params: Tuple[Any, ...] = (chain.lower(), limit)
            else:
                query = (
                    "SELECT * FROM alert_state WHERE status = 'muted' "
                    "ORDER BY updated_at DESC LIMIT ?"
                )
                params = (limit,)
            async with db.execute(query, params) as cur:
                rows = await cur.fetchall()
                return [
                    {
                        "chain_id": int(r["chain_id"]),
                        "chain": r["chain"],
                        "contract_address": to_checksum_address(r["contract_address"]),
                        "status": r["status"],
                        "alert_count": int(r["alert_count"] or 0),
                        "first_alerted_at": r["first_alerted_at"],
                        "last_alerted_at": r["last_alerted_at"],
                        "reason": r["reason"],
                        "updated_at": int(r["updated_at"]),
                    }
                    for r in rows
                ]

    async def record_suppressed_duplicate(
        self,
        contract_address: Optional[str] = None,
        reason: str = "duplicate_alert",
        chain: str = "ethereum",
        chain_id: Optional[int] = None,
        tx_hash: Optional[str] = None,
        log_index: Optional[int] = None,
        duplicate_type: Optional[str] = None,
        suppressed_at: Optional[int] = None,
    ) -> None:
        """Record a suppressed duplicate alert or event in SQLite for 24h /status reporting."""
        now = suppressed_at if suppressed_at is not None else int(time.time())
        addr = (contract_address or "").lower()
        chain_key = (chain or "ethereum").lower()
        cid = resolve_chain_id(chain_key, chain_id)
        eff_reason = f"{duplicate_type}: {reason}" if duplicate_type and reason else (reason or duplicate_type or "duplicate_alert")
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO suppressed_duplicates (
                    chain_id, chain, contract_address, reason, suppressed_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (cid, chain_key, addr, eff_reason, now),
            )
            await db.commit()

    async def record_quality_score(
        self,
        contract_address: str,
        score: int,
        alert_tier: str,
        tier_reason: str = "",
        checks: Optional[List[Dict[str, Any]]] = None,
        scored_at: Optional[int] = None,
        chain: str = "ethereum",
        reasons: Optional[List[str]] = None,
    ) -> int:
        """Persist a computed quality score, alert tier, and check breakdown to SQLite."""
        ts = scored_at if scored_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        checks_str = json.dumps(checks or [])
        eff_tier_reason = str(tier_reason or "")
        if not eff_tier_reason and reasons:
            eff_tier_reason = "; ".join(str(r) for r in reasons)

        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                """
                INSERT INTO quality_scores (
                    chain, contract_address, score, alert_tier,
                    tier_reason, checks_json, scored_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (chain_key, addr, int(score), str(alert_tier), eff_tier_reason, checks_str, ts),
            )
            await db.commit()
            return cur.lastrowid

    async def get_latest_quality_score(
        self,
        contract_address: str,
        chain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent logged quality score and tier for a contract."""
        addr = contract_address.lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                query = (
                    "SELECT * FROM quality_scores WHERE chain = ? AND contract_address = ? "
                    "ORDER BY scored_at DESC, id DESC LIMIT 1"
                )
                params: Tuple[Any, ...] = (chain.lower(), addr)
            else:
                query = (
                    "SELECT * FROM quality_scores WHERE contract_address = ? "
                    "ORDER BY scored_at DESC, id DESC LIMIT 1"
                )
                params = (addr,)
            async with db.execute(query, params) as cur:
                row = await cur.fetchone()
                if not row:
                    return None
                try:
                    checks = json.loads(row["checks_json"]) if row["checks_json"] else []
                except Exception:
                    checks = []
                return {
                    "id": row["id"],
                    "chain": row["chain"],
                    "contract_address": row["contract_address"],
                    "score": int(row["score"]),
                    "alert_tier": row["alert_tier"],
                    "tier_reason": row["tier_reason"],
                    "checks": checks,
                    "scored_at": int(row["scored_at"]),
                }

    @staticmethod
    def _normalize_outcome_field(val: Any, is_pct: bool = False) -> Tuple[str, Optional[float]]:
        """Normalize an outcome field to (display_str_or_unavailable, numeric_value_or_None)."""
        if val is None:
            return "unavailable", None
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            num = float(val)
            if is_pct:
                return f"{num:.1f}%", num
            if isinstance(val, int) or num.is_integer():
                return str(int(num)), num
            return f"{num:.4f}".rstrip("0").rstrip("."), num
        s = str(val).strip()
        if not s or s.lower() in ("unavailable", "none", "null", "n/a", "unknown"):
            return "unavailable", None
        import re
        m = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)", s.replace(",", ""))
        num_val: Optional[float] = None
        if m:
            try:
                num_val = float(m.group(1))
            except ValueError:
                num_val = None
        return s, num_val

    async def upsert_outcome_snapshot(
        self,
        contract_address: str,
        interval_label: str,
        alerted_at: int,
        holder_count: Any = "unavailable",
        unique_holders: Any = "unavailable",
        pct_max_supply_minted: Any = "unavailable",
        floor_price: Any = "unavailable",
        listing_count: Any = "unavailable",
        volume_24h: Any = "unavailable",
        chain: str = "ethereum",
        chain_id: Optional[int] = None,
        target_timestamp: Optional[int] = None,
        captured_at: Optional[int] = None,
    ) -> int:
        """
        Store or update a 1h, 24h, or 7d outcome snapshot for an alerted contract.
        Always stores 'unavailable' when a source fails or returns None.
        """
        now = captured_at if captured_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        cid = resolve_chain_id(chain_key, chain_id)
        interval_clean = str(interval_label).strip().lower()
        interval_seconds_map = {"1h": 3600, "24h": 86400, "7d": 604800}
        target_ts = (
            int(target_timestamp)
            if target_timestamp is not None
            else int(alerted_at) + interval_seconds_map.get(interval_clean, 3600)
        )

        hc_str, hc_num = self._normalize_outcome_field(holder_count)
        uh_str, uh_num = self._normalize_outcome_field(unique_holders)
        pct_str, pct_num = self._normalize_outcome_field(pct_max_supply_minted, is_pct=True)
        fp_str, fp_num = self._normalize_outcome_field(floor_price)
        lc_str, lc_num = self._normalize_outcome_field(listing_count)
        vol_str, vol_num = self._normalize_outcome_field(volume_24h)

        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                """
                INSERT INTO outcome_snapshots (
                    chain, chain_id, contract_address, interval_label,
                    alerted_at, target_timestamp, captured_at,
                    holder_count, holder_count_num,
                    unique_holders, unique_holders_num,
                    pct_max_supply_minted, pct_max_supply_minted_num,
                    floor_price, floor_price_num,
                    listing_count, listing_count_num,
                    volume_24h, volume_24h_num
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, contract_address, interval_label) DO UPDATE SET
                    captured_at = excluded.captured_at,
                    holder_count = excluded.holder_count,
                    holder_count_num = excluded.holder_count_num,
                    unique_holders = excluded.unique_holders,
                    unique_holders_num = excluded.unique_holders_num,
                    pct_max_supply_minted = excluded.pct_max_supply_minted,
                    pct_max_supply_minted_num = excluded.pct_max_supply_minted_num,
                    floor_price = excluded.floor_price,
                    floor_price_num = excluded.floor_price_num,
                    listing_count = excluded.listing_count,
                    listing_count_num = excluded.listing_count_num,
                    volume_24h = excluded.volume_24h,
                    volume_24h_num = excluded.volume_24h_num;
                """,
                (
                    chain_key,
                    cid,
                    addr,
                    interval_clean,
                    int(alerted_at),
                    target_ts,
                    now,
                    hc_str,
                    int(hc_num) if hc_num is not None else None,
                    uh_str,
                    int(uh_num) if uh_num is not None else None,
                    pct_str,
                    pct_num,
                    fp_str,
                    fp_num,
                    lc_str,
                    int(lc_num) if lc_num is not None else None,
                    vol_str,
                    vol_num,
                ),
            )
            await db.commit()
            return cur.lastrowid

    async def get_due_outcome_snapshots(
        self,
        as_of_timestamp: Optional[int] = None,
        chain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return a list of due (1h, 24h, 7d) outcome snapshots that have reached their target timestamp
        for alerted contracts and have not yet been captured in `outcome_snapshots`.
        """
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())
        intervals = [("1h", 3600), ("24h", 86400), ("7d", 604800)]
        due: List[Dict[str, Any]] = []

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                q = (
                    "SELECT chain, contract_address, MIN(alerted_at) AS first_alerted_at "
                    "FROM alerts WHERE chain = ? GROUP BY chain, contract_address"
                )
                params: Tuple[Any, ...] = (chain.lower(),)
            else:
                q = (
                    "SELECT chain, contract_address, MIN(alerted_at) AS first_alerted_at "
                    "FROM alerts GROUP BY chain, contract_address"
                )
                params = ()
            async with db.execute(q, params) as cur:
                alerted_rows = await cur.fetchall()

            for row in alerted_rows:
                ck = str(row["chain"]).lower()
                c_addr = str(row["contract_address"]).lower()
                first_ts = int(row["first_alerted_at"])
                async with db.execute(
                    "SELECT interval_label FROM outcome_snapshots WHERE chain = ? AND contract_address = ?",
                    (ck, c_addr),
                ) as cur_s:
                    existing_labels = {str(r[0]).lower() for r in await cur_s.fetchall()}

                for label, delta_sec in intervals:
                    target_ts = first_ts + delta_sec
                    if now >= target_ts and label not in existing_labels:
                        due.append(
                            {
                                "chain": ck,
                                "chain_id": resolve_chain_id(ck),
                                "contract_address": c_addr,
                                "interval_label": label,
                                "alerted_at": first_ts,
                                "target_timestamp": target_ts,
                            }
                        )
        return due

    async def get_outcome_snapshots_for_contract(
        self,
        contract_address: str,
        chain: str = "ethereum",
    ) -> List[Dict[str, Any]]:
        """Fetch all captured outcome snapshots (1h, 24h, 7d) for a contract."""
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        order_map = {"1h": 1, "24h": 2, "7d": 3}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM outcome_snapshots WHERE chain = ? AND contract_address = ?",
                (chain_key, addr),
            ) as cur:
                rows = [dict(r) for r in await cur.fetchall()]
        rows.sort(key=lambda r: (order_map.get(str(r.get("interval_label", "")).lower(), 99), r.get("captured_at", 0)))
        return rows

    async def get_last_alerted_outcomes(
        self,
        limit: int = 20,
        chain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return the last N alerted contracts ordered by most recent alert,
        each paired with its latest captured outcome snapshot (7d > 24h > 1h).
        """
        from eth_utils import to_checksum_address
        interval_priority = {"7d": 3, "24h": 2, "1h": 1}

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                q = """
                    SELECT
                        a.chain,
                        a.contract_address,
                        MAX(a.contract_name) AS contract_name,
                        MIN(a.alerted_at) AS first_alerted_at,
                        MAX(a.alerted_at) AS last_alerted_at,
                        MAX(a.alert_tier) AS alert_tier,
                        MAX(a.quality_score) AS quality_score,
                        MAX(a.risk_score) AS risk_score,
                        MAX(a.risk_level) AS risk_level
                    FROM alerts a
                    WHERE a.chain = ?
                    GROUP BY a.chain, a.contract_address
                    ORDER BY last_alerted_at DESC, MAX(a.id) DESC
                    LIMIT ?
                """
                params: Tuple[Any, ...] = (chain.lower(), limit)
            else:
                q = """
                    SELECT
                        a.chain,
                        a.contract_address,
                        MAX(a.contract_name) AS contract_name,
                        MIN(a.alerted_at) AS first_alerted_at,
                        MAX(a.alerted_at) AS last_alerted_at,
                        MAX(a.alert_tier) AS alert_tier,
                        MAX(a.quality_score) AS quality_score,
                        MAX(a.risk_score) AS risk_score,
                        MAX(a.risk_level) AS risk_level
                    FROM alerts a
                    GROUP BY a.chain, a.contract_address
                    ORDER BY last_alerted_at DESC, MAX(a.id) DESC
                    LIMIT ?
                """
                params = (limit,)

            async with db.execute(q, params) as cur:
                alert_rows = await cur.fetchall()

            results: List[Dict[str, Any]] = []
            for r in alert_rows:
                ck = str(r["chain"]).lower()
                addr_low = str(r["contract_address"]).lower()
                try:
                    addr_cs = to_checksum_address(addr_low)
                except Exception:
                    addr_cs = addr_low

                c_name = r["contract_name"]
                if not c_name:
                    async with db.execute(
                        "SELECT name FROM contracts WHERE chain = ? AND address = ?",
                        (ck, addr_low),
                    ) as cur_c:
                        crow = await cur_c.fetchone()
                        if crow and crow["name"]:
                            c_name = crow["name"]

                q_score = r["quality_score"]
                a_tier = r["alert_tier"]
                if q_score is None:
                    async with db.execute(
                        "SELECT score, alert_tier FROM quality_scores WHERE chain = ? AND contract_address = ? ORDER BY scored_at DESC LIMIT 1",
                        (ck, addr_low),
                    ) as cur_q:
                        qrow = await cur_q.fetchone()
                        if qrow:
                            q_score = qrow["score"]
                            a_tier = qrow["alert_tier"]

                r_score = r["risk_score"]
                r_level = r["risk_level"]
                if r_score is None:
                    async with db.execute(
                        "SELECT score, risk_level FROM risk_scores WHERE chain = ? AND contract_address = ? ORDER BY scored_at DESC LIMIT 1",
                        (ck, addr_low),
                    ) as cur_r:
                        rrow = await cur_r.fetchone()
                        if rrow:
                            r_score = rrow["score"]
                            r_level = rrow["risk_level"]

                async with db.execute(
                    "SELECT * FROM outcome_snapshots WHERE chain = ? AND contract_address = ?",
                    (ck, addr_low),
                ) as cur_s:
                    snaps = [dict(s) for s in await cur_s.fetchall()]

                latest_snap: Optional[Dict[str, Any]] = None
                if snaps:
                    snaps.sort(
                        key=lambda s: (
                            interval_priority.get(str(s.get("interval_label", "")).lower(), 0),
                            int(s.get("captured_at") or 0),
                        ),
                        reverse=True,
                    )
                    latest_snap = snaps[0]

                results.append(
                    {
                        "chain": ck,
                        "contract_address": addr_cs,
                        "contract_name": c_name or "unavailable",
                        "first_alerted_at": int(r["first_alerted_at"]),
                        "last_alerted_at": int(r["last_alerted_at"]),
                        "alert_tier": a_tier or "Tier C",
                        "quality_score": int(q_score) if q_score is not None else None,
                        "risk_score": int(r_score) if r_score is not None else None,
                        "risk_level": r_level or "Low",
                        "latest_snapshot": latest_snap,
                        "snapshots": snaps,
                    }
                )
        return results

    async def get_outcome_stats_by_tier_and_risk(
        self,
        chain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compute per-tier ('Tier A', 'Tier B', 'Tier C') and per-risk-level ('Low', 'Medium', 'High')
        averages across alerted contracts and their latest outcome snapshots for /stats.
        """
        outcomes = await self.get_last_alerted_outcomes(limit=1000, chain=chain)

        def _empty_bucket() -> Dict[str, List[float]]:
            return {
                "count": [],
                "quality_score": [],
                "risk_score": [],
                "holder_count": [],
                "unique_holders": [],
                "pct_max_supply_minted": [],
                "floor_price": [],
                "listing_count": [],
                "volume_24h": [],
            }

        by_tier: Dict[str, Dict[str, List[float]]] = {
            "Tier A": _empty_bucket(),
            "Tier B": _empty_bucket(),
            "Tier C": _empty_bucket(),
        }
        by_risk: Dict[str, Dict[str, List[float]]] = {
            "Low": _empty_bucket(),
            "Medium": _empty_bucket(),
            "High": _empty_bucket(),
        }

        def _add_to_bucket(bucket: Dict[str, List[float]], item: Dict[str, Any]):
            bucket["count"].append(1.0)
            if item.get("quality_score") is not None:
                bucket["quality_score"].append(float(item["quality_score"]))
            if item.get("risk_score") is not None:
                bucket["risk_score"].append(float(item["risk_score"]))
            snap = item.get("latest_snapshot")
            if isinstance(snap, dict):
                if snap.get("holder_count_num") is not None:
                    bucket["holder_count"].append(float(snap["holder_count_num"]))
                if snap.get("unique_holders_num") is not None:
                    bucket["unique_holders"].append(float(snap["unique_holders_num"]))
                if snap.get("pct_max_supply_minted_num") is not None:
                    bucket["pct_max_supply_minted"].append(float(snap["pct_max_supply_minted_num"]))
                if snap.get("floor_price_num") is not None:
                    bucket["floor_price"].append(float(snap["floor_price_num"]))
                if snap.get("listing_count_num") is not None:
                    bucket["listing_count"].append(float(snap["listing_count_num"]))
                if snap.get("volume_24h_num") is not None:
                    bucket["volume_24h"].append(float(snap["volume_24h_num"]))

        for item in outcomes:
            tier_key = str(item.get("alert_tier") or "Tier C")
            if tier_key not in by_tier:
                tier_key = "Tier C"
            risk_key = str(item.get("risk_level") or "Low").capitalize()
            if risk_key not in by_risk:
                risk_key = "Low"
            _add_to_bucket(by_tier[tier_key], item)
            _add_to_bucket(by_risk[risk_key], item)

        def _summarize(bucket: Dict[str, List[float]]) -> Dict[str, Any]:
            def _avg(vals: List[float], decimals: int = 1) -> Optional[float]:
                if not vals:
                    return None
                return round(sum(vals) / len(vals), decimals)

            return {
                "count": len(bucket["count"]),
                "avg_quality_score": _avg(bucket["quality_score"], 1),
                "avg_risk_score": _avg(bucket["risk_score"], 1),
                "avg_holder_count": _avg(bucket["holder_count"], 1),
                "avg_unique_holders": _avg(bucket["unique_holders"], 1),
                "avg_pct_max_supply_minted": _avg(bucket["pct_max_supply_minted"], 1),
                "avg_floor_price": _avg(bucket["floor_price"], 4),
                "avg_listing_count": _avg(bucket["listing_count"], 1),
                "avg_volume_24h": _avg(bucket["volume_24h"], 4),
            }

        return {
            "total_tracked_alerts": len(outcomes),
            "by_tier": {k: _summarize(v) for k, v in by_tier.items()},
            "by_risk_level": {k: _summarize(v) for k, v in by_risk.items()},
        }

    async def enqueue_tier_b_digest(
        self,
        contract_address: str,
        quality_score: int,
        risk_score: int,
        risk_level: str,
        unique_minters: int,
        total_mints: int,
        mints_per_minute: float,
        contract_name: Optional[str] = None,
        contract_symbol: Optional[str] = None,
        chain: str = "ethereum",
        chain_id: Optional[int] = None,
        queued_at: Optional[int] = None,
    ) -> int:
        """Queue a Tier B contract alert for the hourly digest."""
        now = queued_at if queued_at is not None else int(time.time())
        addr = contract_address.lower()
        chain_key = (chain or "ethereum").lower()
        cid = resolve_chain_id(chain_key, chain_id)

        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                """
                INSERT INTO digest_queue (
                    chain, chain_id, contract_address, contract_name, contract_symbol,
                    quality_score, risk_score, risk_level,
                    unique_minters, total_mints, mints_per_minute, queued_at, sent_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(chain, contract_address) DO UPDATE SET
                    contract_name = coalesce(excluded.contract_name, digest_queue.contract_name),
                    contract_symbol = coalesce(excluded.contract_symbol, digest_queue.contract_symbol),
                    quality_score = excluded.quality_score,
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    unique_minters = excluded.unique_minters,
                    total_mints = excluded.total_mints,
                    mints_per_minute = excluded.mints_per_minute,
                    queued_at = excluded.queued_at;
                """,
                (
                    chain_key,
                    cid,
                    addr,
                    contract_name,
                    contract_symbol,
                    int(quality_score),
                    int(risk_score),
                    str(risk_level),
                    int(unique_minters),
                    int(total_mints),
                    float(mints_per_minute),
                    now,
                ),
            )
            await db.commit()
            return cur.lastrowid

    async def get_pending_digest_items(
        self,
        chain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return all unsent Tier B digest items ordered by quality_score DESC, queued_at ASC."""
        from eth_utils import to_checksum_address
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                q = (
                    "SELECT * FROM digest_queue WHERE sent_at IS NULL AND chain = ? "
                    "ORDER BY quality_score DESC, queued_at ASC"
                )
                params: Tuple[Any, ...] = (chain.lower(),)
            else:
                q = (
                    "SELECT * FROM digest_queue WHERE sent_at IS NULL "
                    "ORDER BY quality_score DESC, queued_at ASC"
                )
                params = ()
            async with db.execute(q, params) as cur:
                rows = await cur.fetchall()
                out = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["contract_address"] = to_checksum_address(d["contract_address"])
                    except Exception:
                        pass
                    out.append(d)
                return out

    async def mark_digest_items_sent(
        self,
        item_ids: List[int],
        sent_at: Optional[int] = None,
    ) -> None:
        """Mark Tier B digest queue items as sent."""
        if not item_ids:
            return
        now = sent_at if sent_at is not None else int(time.time())
        placeholders = ",".join("?" for _ in item_ids)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                f"UPDATE digest_queue SET sent_at = ? WHERE id IN ({placeholders})",
                (now, *[int(i) for i in item_ids]),
            )
            await db.commit()

    async def add_watch_wallet(
        self,
        address: str,
        label: Optional[str] = None,
        added_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Add or update a wallet in `watch_wallets` (/watch <address>)."""
        from eth_utils import to_checksum_address
        now = added_at if added_at is not None else int(time.time())
        addr_low = address.strip().lower()
        try:
            addr_cs = to_checksum_address(addr_low)
        except Exception:
            addr_cs = address.strip()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO watch_wallets (address, label, added_at)
                VALUES (?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                    label = coalesce(excluded.label, watch_wallets.label),
                    added_at = excluded.added_at;
                """,
                (addr_low, label, now),
            )
            await db.commit()
        return {
            "address": addr_cs,
            "wallet_address": addr_cs,
            "label": label,
            "added_at": now,
        }

    async def remove_watch_wallet(self, address: str) -> bool:
        """Remove a wallet from `watch_wallets` (/unwatch <address>). Returns True if removed."""
        addr_low = address.strip().lower()
        async with aiosqlite.connect(self.db_path) as db:
            cur = await db.execute(
                "DELETE FROM watch_wallets WHERE address = ?;",
                (addr_low,),
            )
            await db.commit()
            return (cur.rowcount or 0) > 0

    async def get_watch_wallets(self) -> List[Dict[str, Any]]:
        """List all watched wallets in `watch_wallets` ordered by added_at DESC."""
        from eth_utils import to_checksum_address
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM watch_wallets ORDER BY added_at DESC"
            ) as cur:
                rows = await cur.fetchall()
                out = []
                for r in rows:
                    raw = str(r["address"])
                    try:
                        cs = to_checksum_address(raw)
                    except Exception:
                        cs = raw
                    out.append(
                        {
                            "address": cs,
                            "wallet_address": cs,
                            "label": r["label"],
                            "added_at": int(r["added_at"]),
                        }
                    )
                return out

    async def get_watched_minters_for_contract(
        self,
        contract_address: str,
        chain: str = "ethereum",
    ) -> List[str]:
        """Return checksummed addresses of any watched wallets that have minted `contract_address` on `chain`."""
        from eth_utils import to_checksum_address
        addr_low = contract_address.strip().lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT DISTINCT m.minter_address
                FROM mints m
                INNER JOIN watch_wallets w ON LOWER(m.minter_address) = LOWER(w.address)
                WHERE m.chain = ? AND m.contract_address = ?
                ORDER BY m.timestamp ASC
                """,
                (chain_key, addr_low),
            ) as cur:
                rows = await cur.fetchall()
                watched: List[str] = []
                for (m_addr,) in rows:
                    if m_addr:
                        try:
                            watched.append(to_checksum_address(str(m_addr)))
                        except Exception:
                            watched.append(str(m_addr))
                return watched

    async def record_deployer_contract_metrics(
        self,
        deployer_or_contract: str = "",
        contract_address: Optional[str] = None,
        deployer_address: Optional[str] = None,
        deployer: Optional[str] = None,
        total_supply: Optional[int] = None,
        max_supply: Optional[int] = None,
        owner_held_pct: Optional[float] = None,
        reached_90pct_minted: Optional[Any] = None,
        owner_held_above_50pct: Optional[Any] = None,
        chain: str = "ethereum",
        updated_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Record per-contract metrics for a deployer in `deployer_contracts` and recompute
        aggregate `deployer_reputation` (contracts_deployed, reached_90pct_minted, owner_held_above_50pct).
        """
        dep_raw = deployer or deployer_address
        c_raw = contract_address

        if not dep_raw and not c_raw:
            c_raw = deployer_or_contract
        elif not dep_raw:
            dep_raw = deployer_or_contract
        elif not c_raw:
            c_raw = deployer_or_contract

        now = updated_at if updated_at is not None else int(time.time())
        dep_low = (dep_raw or ZERO_ADDRESS).strip().lower()
        addr_low = (c_raw or "").strip().lower()
        chain_key = (chain or "ethereum").lower()

        pct_minted: Optional[float] = None
        reached_90 = 0
        if reached_90pct_minted is not None:
            reached_90 = 1 if bool(reached_90pct_minted) else 0
        elif (
            total_supply is not None
            and max_supply is not None
            and int(max_supply) > 0
            and int(total_supply) >= 0
        ):
            pct_minted = round((int(total_supply) / int(max_supply)) * 100.0, 2)
            if pct_minted >= 90.0:
                reached_90 = 1

        owner_gt_50 = 0
        if owner_held_above_50pct is not None:
            owner_gt_50 = 1 if bool(owner_held_above_50pct) else 0
        elif owner_held_pct is not None and float(owner_held_pct) > 50.0:
            owner_gt_50 = 1

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO deployer_contracts (
                    chain, deployer_address, contract_address,
                    total_supply, max_supply, pct_minted, reached_90pct,
                    owner_held_pct, owner_held_above_50pct, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, deployer_address, contract_address) DO UPDATE SET
                    total_supply = coalesce(excluded.total_supply, deployer_contracts.total_supply),
                    max_supply = coalesce(excluded.max_supply, deployer_contracts.max_supply),
                    pct_minted = coalesce(excluded.pct_minted, deployer_contracts.pct_minted),
                    reached_90pct = CASE WHEN excluded.reached_90pct = 1 THEN 1 ELSE deployer_contracts.reached_90pct END,
                    owner_held_pct = coalesce(excluded.owner_held_pct, deployer_contracts.owner_held_pct),
                    owner_held_above_50pct = CASE WHEN excluded.owner_held_above_50pct = 1 THEN 1 ELSE deployer_contracts.owner_held_above_50pct END,
                    updated_at = excluded.updated_at;
                """,
                (
                    chain_key,
                    dep_low,
                    addr_low,
                    total_supply,
                    max_supply,
                    pct_minted,
                    reached_90,
                    owner_held_pct,
                    owner_gt_50,
                    now,
                ),
            )

            # Also include any contracts in `contracts` table with this deployer
            async with db.execute(
                "SELECT address FROM contracts WHERE chain = ? AND LOWER(deployer) = ?",
                (chain_key, dep_low),
            ) as cur_c:
                for (c_addr,) in await cur_c.fetchall():
                    if c_addr:
                        await db.execute(
                            """
                            INSERT OR IGNORE INTO deployer_contracts (
                                chain, deployer_address, contract_address, updated_at
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (chain_key, dep_low, str(c_addr).lower(), now),
                        )

            async with db.execute(
                """
                SELECT
                    COUNT(*),
                    COALESCE(SUM(reached_90pct), 0),
                    COALESCE(SUM(owner_held_above_50pct), 0)
                FROM deployer_contracts
                WHERE chain = ? AND deployer_address = ?
                """,
                (chain_key, dep_low),
            ) as cur_agg:
                agg_row = await cur_agg.fetchone()
                c_dep = int(agg_row[0] or 0) if agg_row else 0
                c_90 = int(agg_row[1] or 0) if agg_row else 0
                c_50 = int(agg_row[2] or 0) if agg_row else 0

            await db.execute(
                """
                INSERT INTO deployer_reputation (
                    chain, deployer_address, contracts_deployed,
                    reached_90pct_minted, owner_held_above_50pct, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, deployer_address) DO UPDATE SET
                    contracts_deployed = MAX(deployer_reputation.contracts_deployed, excluded.contracts_deployed),
                    reached_90pct_minted = MAX(deployer_reputation.reached_90pct_minted, excluded.reached_90pct_minted),
                    owner_held_above_50pct = MAX(deployer_reputation.owner_held_above_50pct, excluded.owner_held_above_50pct),
                    updated_at = excluded.updated_at;
                """,
                (chain_key, dep_low, c_dep, c_90, c_50, now),
            )
            await db.commit()

        return (await self.get_deployer_reputation(dep_low, chain=chain_key)) or {
            "chain": chain_key,
            "deployer_address": dep_low,
            "contracts_deployed": c_dep,
            "reached_90pct_minted": c_90,
            "owner_held_above_50pct": c_50,
            "updated_at": now,
        }

    async def upsert_deployer_reputation(
        self,
        deployer_address: str,
        contracts_deployed: int,
        reached_90pct_minted: int = 0,
        owner_held_above_50pct: int = 0,
        chain: str = "ethereum",
        updated_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Directly upsert deployer reputation counts in SQLite."""
        now = updated_at if updated_at is not None else int(time.time())
        dep_low = deployer_address.strip().lower()
        chain_key = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO deployer_reputation (
                    chain, deployer_address, contracts_deployed,
                    reached_90pct_minted, owner_held_above_50pct, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, deployer_address) DO UPDATE SET
                    contracts_deployed = MAX(deployer_reputation.contracts_deployed, excluded.contracts_deployed),
                    reached_90pct_minted = MAX(deployer_reputation.reached_90pct_minted, excluded.reached_90pct_minted),
                    owner_held_above_50pct = MAX(deployer_reputation.owner_held_above_50pct, excluded.owner_held_above_50pct),
                    updated_at = excluded.updated_at;
                """,
                (
                    chain_key,
                    dep_low,
                    int(contracts_deployed),
                    int(reached_90pct_minted),
                    int(owner_held_above_50pct),
                    now,
                ),
            )
            await db.commit()
        return (await self.get_deployer_reputation(dep_low, chain=chain_key)) or {
            "chain": chain_key,
            "deployer_address": dep_low,
            "contracts_deployed": int(contracts_deployed),
            "reached_90pct_minted": int(reached_90pct_minted),
            "owner_held_above_50pct": int(owner_held_above_50pct),
            "updated_at": now,
        }

    async def get_deployer_reputation(
        self,
        deployer_address: str,
        chain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch deployer reputation for `deployer_address` (scoped to `chain` or aggregated across chains)."""
        dep_low = deployer_address.strip().lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                async with db.execute(
                    "SELECT * FROM deployer_reputation WHERE chain = ? AND deployer_address = ?",
                    (chain.lower(), dep_low),
                ) as cur:
                    row = await cur.fetchone()
                    if not row:
                        return None
                    return {
                        "chain": row["chain"],
                        "deployer_address": row["deployer_address"],
                        "contracts_deployed": int(row["contracts_deployed"]),
                        "reached_90pct_minted": int(row["reached_90pct_minted"]),
                        "owner_held_above_50pct": int(row["owner_held_above_50pct"]),
                        "updated_at": int(row["updated_at"]),
                    }
            else:
                async with db.execute(
                    """
                    SELECT
                        COALESCE(SUM(contracts_deployed), 0) AS c_dep,
                        COALESCE(SUM(reached_90pct_minted), 0) AS c_90,
                        COALESCE(SUM(owner_held_above_50pct), 0) AS c_50,
                        MAX(updated_at) AS upd
                    FROM deployer_reputation
                    WHERE deployer_address = ?
                    """,
                    (dep_low,),
                ) as cur:
                    row = await cur.fetchone()
                    if not row or row["upd"] is None:
                        return None
                    return {
                        "chain": "all",
                        "deployer_address": dep_low,
                        "contracts_deployed": int(row["c_dep"]),
                        "reached_90pct_minted": int(row["c_90"]),
                        "owner_held_above_50pct": int(row["c_50"]),
                        "updated_at": int(row["upd"]),
                    }

    async def get_non_owner_minters_sample(
        self,
        contract_address: str,
        owner: Optional[str] = None,
        deployer: Optional[str] = None,
        limit: int = 10,
        chain: str = "ethereum",
    ) -> List[Dict[str, Any]]:
        """
        Return up to `limit` distinct non-owner minters for a contract with their total minted quantity
        and a sample tx_hash, for Quality Score on-chain/explorer verification.
        """
        addr_low = contract_address.strip().lower()
        chain_key = (chain or "ethereum").lower()
        excluded = {ZERO_ADDRESS, ""}
        for cand in (owner, deployer):
            if cand:
                excluded.add(cand.strip().lower())

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT owner, deployer FROM contracts WHERE chain = ? AND address = ?",
                (chain_key, addr_low),
            ) as cur_c:
                crow = await cur_c.fetchone()
                if crow:
                    for v in crow:
                        if v:
                            excluded.add(str(v).strip().lower())

            async with db.execute(
                """
                SELECT
                    minter_address,
                    COALESCE(SUM(quantity), 0) AS qty,
                    MAX(tx_hash) AS sample_tx_hash,
                    MIN(timestamp) AS first_mint_ts
                FROM mints
                WHERE chain = ? AND contract_address = ?
                GROUP BY minter_address
                ORDER BY first_mint_ts ASC
                """,
                (chain_key, addr_low),
            ) as cur:
                rows = await cur.fetchall()

        sample: List[Dict[str, Any]] = []
        for m_addr, qty, txh, first_ts in rows:
            m_low = (m_addr or "").strip().lower()
            if not m_low or m_low in excluded:
                continue
            sample.append(
                {
                    "address": m_low,
                    "quantity": int(qty or 1),
                    "tx_hash": str(txh or ""),
                    "first_mint_ts": int(first_ts or 0),
                }
            )
            if len(sample) >= limit:
                break
        return sample

    async def suggest_wallets_from_best_7d_outcomes(
        self,
        limit: int = 15,
        top_collections: int = 10,
        early_rank_limit: int = 15,
    ) -> List[Dict[str, Any]]:
        """
        Identify wallets that minted early into collections with the best 7d outcomes
        in `outcome_snapshots` for manual review (/suggest_wallets).
        NEVER auto-adds any wallet to `watch_wallets`.
        """
        from eth_utils import to_checksum_address

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            # 1. Fetch best 7d outcome snapshots ordered by floor price, 24h volume, % max supply minted, unique holders
            async with db.execute(
                """
                SELECT *
                FROM outcome_snapshots
                WHERE interval_label = '7d'
                  AND (
                      COALESCE(floor_price_num, 0) > 0
                      OR COALESCE(volume_24h_num, 0) > 0
                      OR COALESCE(pct_max_supply_minted_num, 0) > 0
                      OR COALESCE(unique_holders_num, 0) > 0
                  )
                ORDER BY
                    COALESCE(floor_price_num, 0) DESC,
                    COALESCE(volume_24h_num, 0) DESC,
                    COALESCE(pct_max_supply_minted_num, 0) DESC,
                    COALESCE(unique_holders_num, 0) DESC
                LIMIT ?
                """,
                (top_collections,),
            ) as cur:
                best_snaps = [dict(r) for r in await cur.fetchall()]

            if not best_snaps:
                return []

            async with db.execute("SELECT address FROM watch_wallets") as cur_w:
                watched_set = {str(r[0]).lower() for r in await cur_w.fetchall() if r[0]}

            wallet_stats: Dict[str, Dict[str, Any]] = {}

            for snap in best_snaps:
                ck = str(snap["chain"]).lower()
                c_addr = str(snap["contract_address"]).lower()

                # Exclude contract owner & deployer
                excluded = {ZERO_ADDRESS, ""}
                c_name = None
                async with db.execute(
                    "SELECT name, owner, deployer FROM contracts WHERE chain = ? AND address = ?",
                    (ck, c_addr),
                ) as cur_c:
                    crow = await cur_c.fetchone()
                    if crow:
                        c_name = crow["name"]
                        if crow["owner"]:
                            excluded.add(str(crow["owner"]).lower())
                        if crow["deployer"]:
                            excluded.add(str(crow["deployer"]).lower())

                # Find earliest minters into this collection
                async with db.execute(
                    """
                    SELECT
                        minter_address,
                        MIN(timestamp) AS first_mint_ts,
                        MIN(block_number) AS first_mint_block,
                        COALESCE(SUM(quantity), 0) AS minted_qty
                    FROM mints
                    WHERE chain = ? AND contract_address = ?
                    GROUP BY minter_address
                    ORDER BY first_mint_ts ASC, first_mint_block ASC
                    LIMIT ?
                    """,
                    (ck, c_addr, early_rank_limit + 5),
                ) as cur_m:
                    minter_rows = await cur_m.fetchall()

                rank = 0
                for mrow in minter_rows:
                    w_addr = str(mrow["minter_address"] or "").strip().lower()
                    if not w_addr or w_addr in excluded:
                        continue
                    rank += 1
                    if rank > early_rank_limit:
                        break

                    try:
                        c_addr_cs = to_checksum_address(c_addr)
                    except Exception:
                        c_addr_cs = c_addr

                    fp_raw = snap.get("floor_price_num")
                    fp_val = (
                        float(fp_raw)
                        if fp_raw is not None
                        else (
                            float(snap.get("floor_price"))
                            if snap.get("floor_price") not in ("unavailable", None)
                            else 0.0
                        )
                    )
                    vol_raw = snap.get("volume_24h_num")
                    vol_val = (
                        float(vol_raw)
                        if vol_raw is not None
                        else (
                            float(snap.get("volume_24h"))
                            if snap.get("volume_24h") not in ("unavailable", None)
                            else 0.0
                        )
                    )
                    uh_raw = snap.get("unique_holders_num")
                    uh_val = (
                        int(uh_raw)
                        if uh_raw is not None
                        else (
                            int(snap.get("unique_holders"))
                            if snap.get("unique_holders") not in ("unavailable", None)
                            else 0
                        )
                    )

                    cs_addr = to_checksum_address(w_addr) if len(w_addr) == 42 else w_addr
                    entry = wallet_stats.setdefault(
                        w_addr,
                        {
                            "address": cs_addr,
                            "wallet_address": cs_addr,
                            "early_collections_count": 0,
                            "collections_count": 0,
                            "early_mints_count": 0,
                            "best_early_rank": rank,
                            "best_7d_floor_eth": None,
                            "best_7d_volume_eth": None,
                            "best_7d_unique_holders": None,
                            "already_watched": w_addr in watched_set,
                            "collections": [],
                            "max_floor_price_num": 0.0,
                            "max_volume_24h_num": 0.0,
                        },
                    )
                    entry["early_collections_count"] += 1
                    entry["collections_count"] += 1
                    entry["early_mints_count"] += int(mrow["minted_qty"] or 1)
                    entry["best_early_rank"] = min(entry["best_early_rank"], rank)
                    if fp_val > 0 and (entry["best_7d_floor_eth"] is None or fp_val > entry["best_7d_floor_eth"]):
                        entry["best_7d_floor_eth"] = fp_val
                    if vol_val > 0 and (entry["best_7d_volume_eth"] is None or vol_val > entry["best_7d_volume_eth"]):
                        entry["best_7d_volume_eth"] = vol_val
                    if uh_val > 0 and (entry["best_7d_unique_holders"] is None or uh_val > entry["best_7d_unique_holders"]):
                        entry["best_7d_unique_holders"] = uh_val
                    entry["max_floor_price_num"] = max(entry["max_floor_price_num"], fp_val)
                    entry["max_volume_24h_num"] = max(entry["max_volume_24h_num"], vol_val)
                    entry["collections"].append(
                        {
                            "chain": ck,
                            "contract_address": c_addr_cs,
                            "contract_name": c_name or c_addr_cs[:10],
                            "early_rank": rank,
                            "floor_7d": snap.get("floor_price", "unavailable"),
                            "volume_24h": snap.get("volume_24h", "unavailable"),
                            "pct_minted": snap.get("pct_max_supply_minted", "unavailable"),
                        }
                    )

        suggestions = list(wallet_stats.values())
        suggestions.sort(
            key=lambda x: (
                0 if not x["already_watched"] else 1,
                -x["early_collections_count"],
                -x["max_floor_price_num"],
                -x["max_volume_24h_num"],
                x["best_early_rank"],
            )
        )
        return suggestions[:limit]

    # =========================================================================
    # Bytecode Template Matching & Known Templates
    # =========================================================================

    async def record_contract_bytecode(
        self,
        contract_address: str,
        bytecode: Union[str, bytes],
        chain: str = "ethereum",
        captured_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Record raw runtime bytecode and stripped bytecode SHA-256 hash in SQLite."""
        now = captured_at if captured_at is not None else int(time.time())
        addr_low = contract_address.strip().lower()
        chain_key = (chain or "ethereum").lower()

        if isinstance(bytecode, bytes):
            raw_hex = bytecode.hex().lower()
        else:
            raw_hex = bytecode.strip().lower()
            if raw_hex.startswith("0x"):
                raw_hex = raw_hex[2:]

        bytecode_size = len(raw_hex) // 2
        bytecode_sha256 = compute_bytecode_hash(raw_hex)
        stripped_hex = strip_bytecode_metadata(raw_hex)
        stripped_sha256 = compute_bytecode_hash(stripped_hex)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO contract_bytecodes (
                    chain, contract_address, bytecode_sha256,
                    stripped_bytecode_sha256, bytecode_size, captured_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chain, contract_address) DO UPDATE SET
                    bytecode_sha256 = excluded.bytecode_sha256,
                    stripped_bytecode_sha256 = excluded.stripped_bytecode_sha256,
                    bytecode_size = excluded.bytecode_size,
                    captured_at = excluded.captured_at;
                """,
                (chain_key, addr_low, bytecode_sha256, stripped_sha256, bytecode_size, now),
            )
            await db.commit()

        return {
            "chain": chain_key,
            "contract_address": addr_low,
            "bytecode_sha256": bytecode_sha256,
            "stripped_bytecode_sha256": stripped_sha256,
            "template_hash": stripped_sha256,
            "bytecode_size": bytecode_size,
            "captured_at": now,
        }

    async def get_contract_bytecode(
        self,
        contract_address: str,
        chain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch recorded bytecode info for a contract."""
        addr_low = contract_address.strip().lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            if chain:
                q = "SELECT * FROM contract_bytecodes WHERE chain = ? AND contract_address = ?"
                params: Tuple[Any, ...] = (chain.lower(), addr_low)
            else:
                q = "SELECT * FROM contract_bytecodes WHERE contract_address = ? ORDER BY captured_at DESC LIMIT 1"
                params = (addr_low,)
            async with db.execute(q, params) as cur:
                row = await cur.fetchone()
                if not row:
                    return None
                return dict(row)

    async def upsert_known_template(
        self,
        template_hash: str,
        label: str,
        risk_flag: str,
        source: str = "manual",
        updated_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Record or update a template classification in known_templates (risk_flag: scam | neutral | legit)."""
        now = updated_at if updated_at is not None else int(time.time())
        t_hash = template_hash.strip().lower()
        clean_flag = risk_flag.strip().lower()
        if clean_flag not in ("scam", "neutral", "legit"):
            clean_flag = "neutral"
        clean_label = label.strip()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO known_templates (
                    template_hash, label, risk_flag, source, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(template_hash) DO UPDATE SET
                    label = excluded.label,
                    risk_flag = excluded.risk_flag,
                    source = excluded.source,
                    updated_at = excluded.updated_at;
                """,
                (t_hash, clean_label, clean_flag, source, now, now),
            )
            await db.commit()

        return await self.get_template_info(t_hash)

    async def get_template_info(self, template_hash: str) -> Dict[str, Any]:
        """Fetch template label, risk flag, and count of matching contracts in SQLite."""
        t_hash = template_hash.strip().lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM known_templates WHERE template_hash = ?",
                (t_hash,),
            ) as cur:
                t_row = await cur.fetchone()

            async with db.execute(
                "SELECT COUNT(DISTINCT contract_address) FROM contract_bytecodes WHERE stripped_bytecode_sha256 = ?",
                (t_hash,),
            ) as cur_cnt:
                cnt_row = await cur_cnt.fetchone()
                match_cnt = int(cnt_row[0] or 0) if cnt_row else 0

        if t_row:
            return {
                "template_hash": t_hash,
                "label": t_row["label"],
                "risk_flag": t_row["risk_flag"],
                "source": t_row["source"],
                "match_count": match_cnt,
                "is_known": True,
            }
        return {
            "template_hash": t_hash,
            "label": None,
            "risk_flag": "neutral",
            "source": "unlabeled",
            "match_count": match_cnt,
            "is_known": False,
        }

    async def label_template_by_address(
        self,
        contract_address: str,
        label: str,
        risk_flag: str,
        chain: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Look up template hash from contract_bytecodes and upsert entry into known_templates."""
        cb = await self.get_contract_bytecode(contract_address, chain=chain)
        if not cb:
            return None
        t_hash = cb["stripped_bytecode_sha256"]
        return await self.upsert_known_template(
            template_hash=t_hash,
            label=label,
            risk_flag=risk_flag,
            source="manual",
        )

    async def auto_flag_high_risk_templates(self) -> List[Dict[str, Any]]:
        """Automatically flag templates that previously produced a High risk alert with owner-held supply above 50%."""
        flagged = []
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            q = """
                SELECT DISTINCT
                    cb.stripped_bytecode_sha256 AS template_hash,
                    a.contract_address,
                    a.chain
                FROM alerts a
                INNER JOIN contract_bytecodes cb ON LOWER(a.contract_address) = LOWER(cb.contract_address)
                LEFT JOIN deployer_contracts dc ON LOWER(a.contract_address) = LOWER(dc.contract_address)
                LEFT JOIN contracts c ON LOWER(a.contract_address) = LOWER(c.address)
                LEFT JOIN deployer_reputation dr ON LOWER(c.deployer) = LOWER(dr.deployer_address)
                WHERE (a.risk_level = 'High' OR a.risk_score >= 50)
                  AND (
                      COALESCE(dc.owner_held_above_50pct, 1) = 1
                      OR COALESCE(dc.owner_held_pct, 0) > 50.0
                      OR COALESCE(dr.owner_held_above_50pct, 0) > 0
                  )
            """
            async with db.execute(q) as cur:
                rows = await cur.fetchall()

        for r in rows:
            t_hash = str(r["template_hash"])
            existing = await self.get_template_info(t_hash)
            if not existing.get("is_known") or existing.get("risk_flag") != "scam":
                res = await self.upsert_known_template(
                    template_hash=t_hash,
                    label="Auto High-Risk (>50% Owner Held)",
                    risk_flag="scam",
                    source="auto_high_risk",
                )
                flagged.append(res)
        return flagged

    # =========================================================================
    # Cross-Chain Deployer & Funding-Clusters Tracking
    # =========================================================================

    async def record_cross_chain_deployer(
        self,
        deployer: str,
        chain: str,
        contract_address: str,
        deploy_time: Optional[int] = None,
        alert_status: Optional[str] = None,
        outcome_7d: Optional[str] = None,
        updated_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Record (deployer, chain, contract, deploy_time, outcome, alert_status) in cross_chain_deployers."""
        now = updated_at if updated_at is not None else int(time.time())
        dep_low = deployer.strip().lower()
        chain_key = (chain or "ethereum").lower()
        addr_low = contract_address.strip().lower()
        d_time = int(deploy_time) if deploy_time is not None else now
        status = (alert_status or "unalerted").strip().lower()
        outcome = (outcome_7d or "unavailable").strip()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO cross_chain_deployers (
                    deployer, chain, contract_address, deploy_time,
                    alert_status, outcome_7d, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(deployer, chain, contract_address) DO UPDATE SET
                    deploy_time = coalesce(excluded.deploy_time, cross_chain_deployers.deploy_time),
                    alert_status = CASE WHEN excluded.alert_status != 'unalerted' THEN excluded.alert_status ELSE cross_chain_deployers.alert_status END,
                    outcome_7d = CASE WHEN excluded.outcome_7d != 'unavailable' THEN excluded.outcome_7d ELSE cross_chain_deployers.outcome_7d END,
                    updated_at = excluded.updated_at;
                """,
                (dep_low, chain_key, addr_low, d_time, status, outcome, now),
            )
            await db.commit()

        return {
            "deployer": dep_low,
            "chain": chain_key,
            "contract_address": addr_low,
            "deploy_time": d_time,
            "alert_status": status,
            "outcome_7d": outcome,
            "updated_at": now,
        }

    async def get_cross_chain_deployer_contracts(
        self,
        deployer: str,
        exclude_chain: Optional[str] = None,
        exclude_contract: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch other contracts by the same deployer across all configured chains with alert status and 7d outcome."""
        from eth_utils import to_checksum_address
        dep_low = deployer.strip().lower()
        ex_chain = (exclude_chain or "").strip().lower()
        ex_addr = (exclude_contract or "").strip().lower()

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT ccd.*, c.name AS contract_name,
                       os.floor_price, os.volume_24h, os.unique_holders
                FROM cross_chain_deployers ccd
                LEFT JOIN contracts c ON ccd.chain = c.chain AND ccd.contract_address = c.address
                LEFT JOIN outcome_snapshots os ON ccd.chain = os.chain AND ccd.contract_address = os.contract_address AND os.interval_label = '7d'
                WHERE ccd.deployer = ?
                ORDER BY ccd.deploy_time DESC
                """,
                (dep_low,),
            ) as cur:
                rows = await cur.fetchall()

        out = []
        for r in rows:
            ck = str(r["chain"]).lower()
            c_addr = str(r["contract_address"]).lower()
            if ex_chain and ex_addr and ck == ex_chain and c_addr == ex_addr:
                continue

            try:
                cs_addr = to_checksum_address(c_addr)
            except Exception:
                cs_addr = c_addr

            outcome_7d = r["outcome_7d"]
            if (not outcome_7d or outcome_7d == "unavailable") and r["floor_price"] and r["floor_price"] != "unavailable":
                fp = r["floor_price"]
                vol = r["volume_24h"] or "0"
                outcome_7d = f"Floor: {fp} | 24h Vol: {vol}"
            elif not outcome_7d:
                outcome_7d = "unavailable"

            out.append(
                {
                    "chain": ck,
                    "contract_address": cs_addr,
                    "contract_name": r["contract_name"] or cs_addr[:10],
                    "deploy_time": int(r["deploy_time"]),
                    "alert_status": str(r["alert_status"] or "unalerted"),
                    "outcome_7d": outcome_7d,
                }
            )
        return out

    async def record_funding_cluster(
        self,
        wallet: str,
        funding_source: str,
        chain: str,
        contract_address: str,
        created_at: Optional[int] = None,
    ) -> None:
        """Record (wallet, funding_source, chain, contract_address) in funding_clusters."""
        now = created_at if created_at is not None else int(time.time())
        w_low = wallet.strip().lower()
        f_low = funding_source.strip().lower()
        chain_key = (chain or "ethereum").lower()
        addr_low = contract_address.strip().lower()

        if not f_low or f_low == ZERO_ADDRESS:
            return

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT OR IGNORE INTO funding_clusters (
                    wallet, funding_source, chain, contract_address, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (w_low, f_low, chain_key, addr_low, now),
            )
            await db.commit()

    async def find_cross_contract_funding_clusters(
        self,
        funding_sources: List[str],
        current_contract: str,
        current_chain: str = "ethereum",
    ) -> List[Dict[str, Any]]:
        """Check if any given funding sources appeared across multiple contracts (especially alerted contracts)."""
        from eth_utils import to_checksum_address
        cleaned = list({f.strip().lower() for f in funding_sources if f and f.strip().lower() != ZERO_ADDRESS})
        if not cleaned:
            return []

        cur_contract = current_contract.strip().lower()
        placeholders = ",".join("?" for _ in cleaned)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            q = f"""
                SELECT
                    fc.funding_source,
                    COUNT(DISTINCT fc.contract_address) AS total_contracts_count,
                    COUNT(DISTINCT a.contract_address) AS alerted_contracts_count,
                    GROUP_CONCAT(DISTINCT fc.chain) AS chains,
                    GROUP_CONCAT(DISTINCT fc.contract_address) AS contracts
                FROM funding_clusters fc
                LEFT JOIN alerts a ON LOWER(fc.contract_address) = LOWER(a.contract_address)
                WHERE fc.funding_source IN ({placeholders})
                  AND LOWER(fc.contract_address) != ?
                GROUP BY fc.funding_source
                HAVING total_contracts_count >= 1
            """
            params = list(cleaned) + [cur_contract]
            async with db.execute(q, params) as cur:
                rows = await cur.fetchall()

        results = []
        for r in rows:
            f_src = str(r["funding_source"])
            try:
                cs_src = to_checksum_address(f_src)
            except Exception:
                cs_src = f_src

            total_cnt = int(r["total_contracts_count"] or 0)
            alerted_cnt = int(r["alerted_contracts_count"] or 0)
            chains = [c.strip() for c in str(r["chains"] or "").split(",") if c.strip()]
            contracts = [c.strip() for c in str(r["contracts"] or "").split(",") if c.strip()]

            results.append(
                {
                    "funding_source": cs_src,
                    "other_contracts_count": total_cnt,
                    "alerted_contracts_count": alerted_cnt,
                    "total_contracts_count": total_cnt + 1,
                    "chains": chains,
                    "sample_contracts": contracts[:3],
                }
            )
        return results

    async def get_last_mint_timestamp(
        self, contract_address: str, chain: str = "ethereum"
    ) -> Optional[int]:
        """Return the unix timestamp of the most recent observed mint for this contract."""
        addr = contract_address.lower()
        c = (chain or "ethereum").lower()
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT MAX(timestamp) FROM mints WHERE contract_address = ? AND chain = ?",
                (addr, c),
            ) as cur:
                row = await cur.fetchone()
                if row and row[0] is not None:
                    return int(row[0])
        return None

    async def set_chain_enabled(self, chain_key: str, enabled: bool) -> None:
        """Persist runtime enabled state override for a chain."""
        ck = chain_key.strip().lower()
        now = time.time()
        en_int = 1 if enabled else 0
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO chain_overrides (chain_key, enabled, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(chain_key) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (ck, en_int, now),
            )
            await db.commit()

    async def set_chain_threshold(
        self, chain_key: str, minters: int, window_seconds: int
    ) -> None:
        """Persist runtime threshold overrides for a chain."""
        ck = chain_key.strip().lower()
        now = time.time()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO chain_overrides (chain_key, mint_threshold, min_mints, window, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(chain_key) DO UPDATE SET
                    mint_threshold = excluded.mint_threshold,
                    min_mints = excluded.min_mints,
                    window = excluded.window,
                    updated_at = excluded.updated_at
                """,
                (ck, int(minters), int(minters), int(window_seconds), now),
            )
            await db.commit()

    async def get_chain_overrides(self) -> Dict[str, Dict[str, Any]]:
        """Return all persisted chain overrides indexed by chain_key."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT chain_key, enabled, mint_threshold, min_mints, window, cooldown, updated_at FROM chain_overrides"
            ) as cur:
                rows = await cur.fetchall()
        result: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            ck = str(r["chain_key"]).lower()
            result[ck] = {
                "chain_key": ck,
                "enabled": bool(r["enabled"]) if r["enabled"] is not None else None,
                "mint_threshold": int(r["mint_threshold"]) if r["mint_threshold"] is not None else None,
                "min_mints": int(r["min_mints"]) if r["min_mints"] is not None else None,
                "window": int(r["window"]) if r["window"] is not None else None,
                "cooldown": int(r["cooldown"]) if r["cooldown"] is not None else None,
                "updated_at": float(r["updated_at"]) if r["updated_at"] is not None else None,
            }
        return result

    async def get_chain_override(self, chain_key: str) -> Optional[Dict[str, Any]]:
        """Return persisted chain override for a single chain_key."""
        ck = chain_key.strip().lower()
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT chain_key, enabled, mint_threshold, min_mints, window, cooldown, updated_at FROM chain_overrides WHERE chain_key = ?",
                (ck,),
            ) as cur:
                r = await cur.fetchone()
        if not r:
            return None
        return {
            "chain_key": ck,
            "enabled": bool(r["enabled"]) if r["enabled"] is not None else None,
            "mint_threshold": int(r["mint_threshold"]) if r["mint_threshold"] is not None else None,
            "min_mints": int(r["min_mints"]) if r["min_mints"] is not None else None,
            "window": int(r["window"]) if r["window"] is not None else None,
            "cooldown": int(r["cooldown"]) if r["cooldown"] is not None else None,
            "updated_at": float(r["updated_at"]) if r["updated_at"] is not None else None,
        }

    async def get_cached_resolved_links(
        self,
        contract_address: str,
        chain: str = "ethereum",
        ttl_seconds: int = 1800,
        as_of_timestamp: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached resolved links if within TTL."""
        addr = contract_address.lower()
        ck = (chain or "ethereum").lower()
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT payload_json, updated_at FROM resolved_links_cache WHERE chain = ? AND contract_address = ?",
                (ck, addr),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        updated_at = int(row["updated_at"] or 0)
        if ttl_seconds > 0 and (now - updated_at) > ttl_seconds:
            return None
        try:
            return json.loads(row["payload_json"])
        except Exception:
            return None

    async def set_cached_resolved_links(
        self,
        contract_address: str,
        chain: str = "ethereum",
        payload: Optional[Dict[str, Any]] = None,
        timestamp: Optional[int] = None,
    ):
        """Persist resolved links payload in SQLite."""
        addr = contract_address.lower()
        ck = (chain or "ethereum").lower()
        now = timestamp if timestamp is not None else int(time.time())
        payload_str = json.dumps(payload or {})

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO resolved_links_cache (chain, contract_address, payload_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(chain, contract_address) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (ck, addr, payload_str, now),
            )
            await db.commit()

    async def get_cached_domain_rdap(
        self,
        domain: str,
        ttl_seconds: int = 86400 * 7,
        as_of_timestamp: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached domain RDAP registration timestamp."""
        dom = domain.lower().strip()
        now = as_of_timestamp if as_of_timestamp is not None else int(time.time())

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT domain, registration_timestamp, status, updated_at FROM domain_rdap_cache WHERE domain = ?",
                (dom,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        updated_at = int(row["updated_at"] or 0)
        if ttl_seconds > 0 and (now - updated_at) > ttl_seconds:
            return None
        return {
            "domain": row["domain"],
            "registration_timestamp": int(row["registration_timestamp"]) if row["registration_timestamp"] is not None else None,
            "status": row["status"],
            "updated_at": updated_at,
        }

    async def set_cached_domain_rdap(
        self,
        domain: str,
        registration_timestamp: Optional[int],
        status: str = "ok",
        timestamp: Optional[int] = None,
    ):
        """Persist domain RDAP registration timestamp in SQLite."""
        dom = domain.lower().strip()
        now = timestamp if timestamp is not None else int(time.time())

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO domain_rdap_cache (domain, registration_timestamp, status, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    registration_timestamp = excluded.registration_timestamp,
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (dom, registration_timestamp, status, now),
            )
            await db.commit()







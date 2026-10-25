"""Ethereum Wallet Transaction Filter engine.

Supports:
1. Fast on-chain Wallet Transaction Count filtering (via batched JSON-RPC `eth_getTransactionCount`
   and `eth_getBalance` with Etherscan/Blockscout fallback) — ideal for pasting a sheet of
   wallets and filtering the ones with e.g. 100 transactions (at least >= N, exact = N, <= N, or range)
   and downloading the matched wallets as a CSV file.
2. Optional Target Address / ETH value filtering (via Etherscan V2 / Blockscout transaction history)
   when a specific target recipient/contract address is specified.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

import httpx
from eth_utils import to_checksum_address

from app.config import Settings, get_settings
from app.explorer import (
    DEFAULT_BLOCKSCOUT_BY_CHAIN_ID,
    ETHERSCAN_V2_API_URL,
    ExplorerRateLimiter,
    redact_secrets,
)

logger = logging.getLogger(__name__)

ADDRESS_REGEX = re.compile(r"0x[a-fA-F0-9]{40}", re.IGNORECASE)
WEI_PER_ETH = Decimal("1000000000000000000")

PUBLIC_HTTP_RPC_FALLBACKS: Dict[int, str] = {
    1: "https://ethereum-rpc.publicnode.com",
    8453: "https://base-rpc.publicnode.com",
    42161: "https://arbitrum-one-rpc.publicnode.com",
    10: "https://optimism-rpc.publicnode.com",
    137: "https://polygon-bor-rpc.publicnode.com",
    4663: "https://rpc.mainnet.chain.robinhood.com",
}


def _checksum_addr(addr: str) -> str:
    s = addr.strip()
    if s.startswith("0X"):
        s = "0x" + s[2:]
    return to_checksum_address(s)


def parse_wallet_addresses(raw_input: Any) -> Tuple[List[str], List[str]]:
    """Extract and deduplicate valid checksummed EVM addresses from pasted spreadsheet/CSV/text.

    Handles multi-column pasted spreadsheets (Excel / Google Sheets / CSV), newline lists,
    comma-separated lists, or JSON arrays.
    Returns (valid_checksum_addresses, invalid_tokens).
    """
    if isinstance(raw_input, list):
        text = "\n".join(str(item) for item in raw_input if item is not None)
    else:
        text = str(raw_input or "")

    valid: List[str] = []
    invalid: List[str] = []
    seen_lower = set()

    # Process line-by-line so multi-column spreadsheet rows with extra columns
    # (e.g. "1\t0xabc...\tMy Wallet") cleanly extract the 0x address without flagging labels as invalid
    lines = text.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        found_in_line = ADDRESS_REGEX.findall(line_str)
        if found_in_line:
            for match_addr in found_in_line:
                low = match_addr.lower()
                if low not in seen_lower:
                    seen_lower.add(low)
                    valid.append(_checksum_addr(match_addr))
        else:
            # Check if line is just a header row
            tokens = [
                tok.strip().strip("\"'`")
                for tok in re.split(r"[\s,;\t]+", line_str)
                if tok.strip().strip("\"'`")
            ]
            header_words = {
                "address",
                "addresses",
                "wallet",
                "wallets",
                "from",
                "sender",
                "account",
                "id",
                "no",
                "index",
                "tx",
                "transactions",
                "balance",
                "label",
                "name",
            }
            if any(t.lower() in header_words for t in tokens):
                continue
            for tok in tokens:
                if tok.lower() not in header_words:
                    invalid.append(tok)

    return valid, invalid


def normalize_target_address(address: Optional[str]) -> Optional[str]:
    """Validate and checksum a single target recipient/contract address."""
    if not address or not str(address).strip():
        return None
    cleaned = str(address).strip()
    if not ADDRESS_REGEX.fullmatch(cleaned):
        raise ValueError(f"Invalid Ethereum address: {cleaned}")
    return _checksum_addr(cleaned)


def eth_to_wei(eth_value: Optional[float | int | str | Decimal]) -> Optional[int]:
    """Convert an ETH value (float/str/Decimal) to integer wei."""
    if eth_value is None or eth_value == "":
        return None
    try:
        dec = Decimal(str(eth_value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"Invalid ETH amount: {eth_value}") from exc
    if dec < 0:
        raise ValueError("ETH amount cannot be negative")
    return int(dec * WEI_PER_ETH)


def wei_to_eth_str(wei: int) -> str:
    """Format wei integer into a clean ETH decimal string."""
    if wei == 0:
        return "0"
    dec = Decimal(wei) / WEI_PER_ETH
    formatted = f"{dec:.6f}".rstrip("0").rstrip(".")
    return formatted or "0"


@dataclass
class FilterCriteria:
    """Criteria for filtering wallets by their on-chain transactions."""

    target_address: Optional[str] = None
    chain_key: str = "ethereum"
    chain_id: int = 1
    count_mode: str = "min"  # "min" (>= N), "exact" (= N), "max" (<= N), "range" (min..max)
    exact_count: int = 100
    min_count: Optional[int] = None
    max_count: Optional[int] = None
    min_eth: Optional[float] = None
    max_eth: Optional[float] = None
    require_nonzero_eth: bool = False
    only_successful: bool = True
    start_block: int = 0
    end_block: int = 99999999

    def matches_count(self, count: int) -> bool:
        mode = (self.count_mode or "min").lower().strip()
        if mode == "exact":
            return count == self.exact_count
        if mode == "min":
            threshold = self.min_count if self.min_count is not None else self.exact_count
            return count >= threshold
        if mode == "max":
            threshold = self.max_count if self.max_count is not None else self.exact_count
            return count <= threshold
        if mode == "range":
            low = self.min_count if self.min_count is not None else 0
            high = self.max_count if self.max_count is not None else 999999999
            return low <= count <= high
        return count >= self.exact_count


@dataclass
class MatchingTransaction:
    """A single transaction from a wallet that matched the filter criteria."""

    tx_hash: str
    from_address: str
    to_address: str
    value_wei: int
    value_eth: str
    block_number: int
    timestamp: int
    method: str
    explorer_url: str


@dataclass
class WalletFilterResult:
    """Evaluation result for a single wallet."""

    wallet: str
    matched: bool
    matching_tx_count: int
    total_wallet_txs_scanned: int
    total_eth_sent_wei: int
    total_eth_sent: str
    eth_balance_wei: int = 0
    eth_balance: str = "0"
    first_match_timestamp: Optional[int] = None
    last_match_timestamp: Optional[int] = None
    matching_txs: List[MatchingTransaction] = field(default_factory=list)
    explorer_url: str = ""
    data_source: str = "rpc"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def results_to_csv(results: List[Dict[str, Any]], matched_only: bool = True) -> str:
    """Serialize wallet filter results into a CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "wallet_address",
            "transactions_made",
            "eth_balance",
            "matched",
            "total_eth_sent_in_filter",
            "explorer_url",
        ]
    )
    for row in results:
        if matched_only and not row.get("matched"):
            continue
        writer.writerow(
            [
                row.get("wallet", ""),
                row.get("matching_tx_count", 0),
                row.get("eth_balance", "0"),
                "YES" if row.get("matched") else "NO",
                row.get("total_eth_sent", "0"),
                row.get("explorer_url", ""),
            ]
        )
    return output.getvalue()


class WalletTransactionFilterService:
    """Fetches wallet transaction counts & history on Ethereum and filters wallets."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        rate_limit_interval: float = 0.21,
    ):
        self.settings = settings or get_settings()
        self._external_client = http_client is not None
        self._http = http_client
        self._limiter = ExplorerRateLimiter(min_interval=rate_limit_interval)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None or getattr(self._http, "is_closed", False):
            self._http = httpx.AsyncClient(
                timeout=15.0,
                follow_redirects=True,
                headers={"User-Agent": "EthWalletFilter/1.0", "Accept": "application/json"},
            )
        return self._http

    async def close(self) -> None:
        if not self._external_client and self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    def resolve_chain_info(self, chain_key: str = "ethereum") -> Dict[str, Any]:
        """Resolve chain_id, RPC URLs, explorer URLs, and API key from chains.yaml and Settings."""
        chains = self.settings.get_chains()
        key = (chain_key or "ethereum").lower().strip()
        if key not in chains:
            key = "ethereum"
        cfg = chains.get(key)
        if cfg:
            api_key = cfg.resolve_explorer_api_key(self.settings.etherscan_api_key)
            blockscout_url = (
                cfg.blockscout_fallback_url
                or DEFAULT_BLOCKSCOUT_BY_CHAIN_ID.get(cfg.chain_id, "https://eth.blockscout.com")
            )
            http_rpc = cfg.effective_http_rpc_url or PUBLIC_HTTP_RPC_FALLBACKS.get(
                cfg.chain_id, "https://ethereum-rpc.publicnode.com"
            )
            return {
                "chain_key": key,
                "name": cfg.name,
                "chain_id": cfg.chain_id,
                "symbol": cfg.native_token_symbol,
                "http_rpc_url": http_rpc,
                "public_rpc_url": PUBLIC_HTTP_RPC_FALLBACKS.get(
                    cfg.chain_id, "https://ethereum-rpc.publicnode.com"
                ),
                "explorer_url": cfg.explorer_url.rstrip("/"),
                "etherscan_api_url": ETHERSCAN_V2_API_URL,
                "blockscout_url": blockscout_url.rstrip("/"),
                "api_key": api_key,
            }
        return {
            "chain_key": "ethereum",
            "name": "Ethereum",
            "chain_id": 1,
            "symbol": "ETH",
            "http_rpc_url": self.settings.effective_http_rpc_url,
            "public_rpc_url": "https://ethereum-rpc.publicnode.com",
            "explorer_url": "https://etherscan.io",
            "etherscan_api_url": ETHERSCAN_V2_API_URL,
            "blockscout_url": "https://eth.blockscout.com",
            "api_key": self.settings.etherscan_api_key or os.environ.get("ETHERSCAN_API_KEY"),
        }

    async def fetch_batch_wallet_nonces_and_balances(
        self,
        wallets: List[str],
        chain_info: Dict[str, Any],
    ) -> Dict[str, Tuple[int, int, str]]:
        """Fast batch lookup of `eth_getTransactionCount` (txs made) and `eth_getBalance` via JSON-RPC.

        Returns dict mapping lowercase wallet -> (tx_count, balance_wei, data_source).
        """
        client = await self._get_client()
        rpc_urls = []
        primary_rpc = chain_info.get("http_rpc_url")
        public_rpc = chain_info.get("public_rpc_url")
        if primary_rpc:
            rpc_urls.append(primary_rpc)
        if public_rpc and public_rpc not in rpc_urls:
            rpc_urls.append(public_rpc)

        out: Dict[str, Tuple[int, int, str]] = {}
        chunk_size = 50

        for i in range(0, len(wallets), chunk_size):
            chunk = wallets[i : i + chunk_size]
            batch_payload = []
            for idx, w in enumerate(chunk):
                batch_payload.append(
                    {
                        "jsonrpc": "2.0",
                        "id": f"nonce_{idx}",
                        "method": "eth_getTransactionCount",
                        "params": [w, "latest"],
                    }
                )
                batch_payload.append(
                    {
                        "jsonrpc": "2.0",
                        "id": f"bal_{idx}",
                        "method": "eth_getBalance",
                        "params": [w, "latest"],
                    }
                )

            chunk_resolved = False
            for rpc_url in rpc_urls:
                try:
                    resp = await client.post(rpc_url, json=batch_payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            by_id = {
                                item.get("id"): item.get("result")
                                for item in data
                                if isinstance(item, dict) and "id" in item
                            }
                            for idx, w in enumerate(chunk):
                                raw_nonce = by_id.get(f"nonce_{idx}")
                                raw_bal = by_id.get(f"bal_{idx}")
                                if raw_nonce is not None:
                                    tx_cnt = int(str(raw_nonce), 16) if str(raw_nonce).startswith("0x") else int(raw_nonce)
                                    bal_wei = (
                                        int(str(raw_bal), 16)
                                        if raw_bal and str(raw_bal).startswith("0x")
                                        else int(raw_bal or 0)
                                    )
                                    out[w.lower()] = (tx_cnt, bal_wei, "rpc")
                            if len(out) >= i + len(chunk):
                                chunk_resolved = True
                                break
                except Exception as exc:
                    logger.warning("Batch JSON-RPC failed on %s: %s", redact_secrets(rpc_url), redact_secrets(exc))

            # Individual fallback if batch RPC was rejected or partially failed
            if not chunk_resolved:
                for w in chunk:
                    if w.lower() in out:
                        continue
                    tx_cnt, bal_wei, src = await self._fetch_single_wallet_nonce(w, rpc_urls, chain_info)
                    out[w.lower()] = (tx_cnt, bal_wei, src)

        return out

    async def _fetch_single_wallet_nonce(
        self,
        wallet: str,
        rpc_urls: List[str],
        chain_info: Dict[str, Any],
    ) -> Tuple[int, int, str]:
        client = await self._get_client()
        for rpc_url in rpc_urls:
            try:
                resp = await client.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getTransactionCount",
                        "params": [wallet, "latest"],
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    res = data.get("result") if isinstance(data, dict) else None
                    if isinstance(res, str) and res.startswith("0x"):
                        return int(res, 16), 0, "rpc"
            except Exception:
                pass

        # Etherscan proxy fallback
        api_key = chain_info.get("api_key")
        if api_key:
            await self._limiter.acquire()
            try:
                resp = await client.get(
                    chain_info["etherscan_api_url"],
                    params={
                        "chainid": chain_info.get("chain_id", 1),
                        "module": "proxy",
                        "action": "eth_getTransactionCount",
                        "address": wallet,
                        "tag": "latest",
                        "apikey": api_key,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    res = data.get("result") if isinstance(data, dict) else None
                    if isinstance(res, str) and res.startswith("0x"):
                        return int(res, 16), 0, "etherscan_proxy"
            except Exception:
                pass

        return 0, 0, "unavailable"

    async def fetch_wallet_transactions(
        self,
        wallet: str,
        chain_info: Dict[str, Any],
        start_block: int = 0,
        end_block: int = 99999999,
        api_key_override: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """Fetch normal transactions for `wallet` via Etherscan V2 with Blockscout fallback."""
        api_key = (api_key_override or chain_info.get("api_key") or "").strip() or None
        chain_id = int(chain_info.get("chain_id", 1))
        client = await self._get_client()

        # 1. Try Etherscan V2 API when api_key is present
        if api_key:
            await self._limiter.acquire()
            params = {
                "chainid": chain_id,
                "module": "account",
                "action": "txlist",
                "address": wallet,
                "startblock": start_block,
                "endblock": end_block,
                "page": 1,
                "offset": 2500,
                "sort": "desc",
                "apikey": api_key,
            }
            try:
                resp = await client.get(chain_info["etherscan_api_url"], params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    status = str(data.get("status", ""))
                    result = data.get("result")
                    msg = str(data.get("message", "")).lower()
                    if status == "1" and isinstance(result, list):
                        return self._normalize_rpc_txlist(result), "etherscan"
                    if status == "0" and (
                        "no transactions found" in msg
                        or (isinstance(result, list) and len(result) == 0)
                    ):
                        return [], "etherscan"
            except Exception as exc:
                logger.warning(
                    "Etherscan V2 txlist error for %s: %s",
                    wallet,
                    redact_secrets(exc, [api_key]),
                )

        # 2. Fallback to Blockscout RPC-compatible txlist endpoint
        blockscout_base = chain_info.get("blockscout_url", "https://eth.blockscout.com").rstrip("/")
        await self._limiter.acquire()
        bs_rpc_params = {
            "module": "account",
            "action": "txlist",
            "address": wallet,
            "startblock": start_block,
            "endblock": end_block,
            "page": 1,
            "offset": 2500,
            "sort": "desc",
        }
        try:
            resp = await client.get(f"{blockscout_base}/api", params=bs_rpc_params)
            if resp.status_code == 200:
                data = resp.json()
                status = str(data.get("status", ""))
                result = data.get("result")
                msg = str(data.get("message", "")).lower()
                if status == "1" and isinstance(result, list):
                    return self._normalize_rpc_txlist(result), "blockscout"
                if status == "0" and (
                    "no transactions found" in msg
                    or (isinstance(result, list) and len(result) == 0)
                ):
                    return [], "blockscout"
        except Exception as exc:
            logger.warning("Blockscout RPC txlist error for %s: %s", wallet, exc)

        # 3. Fallback to Blockscout REST v2 endpoint
        await self._limiter.acquire()
        try:
            resp = await client.get(
                f"{blockscout_base}/api/v2/addresses/{wallet}/transactions",
                params={"filter": "from"},
            )
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items")
                if isinstance(items, list):
                    return self._normalize_blockscout_v2_txs(items), "blockscout_v2"
            elif resp.status_code == 404:
                return [], "blockscout_v2"
        except Exception as exc:
            logger.warning("Blockscout v2 transactions error for %s: %s", wallet, exc)

        raise RuntimeError(f"Unable to fetch transactions for {wallet} from Etherscan or Blockscout")

    @staticmethod
    def _normalize_rpc_txlist(raw_txs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for tx in raw_txs:
            if not isinstance(tx, dict):
                continue
            tx_hash = str(tx.get("hash") or "").strip()
            from_addr = str(tx.get("from") or "").strip()
            to_addr = str(tx.get("to") or tx.get("contractAddress") or "").strip()
            try:
                value_wei = int(str(tx.get("value") or "0"))
            except ValueError:
                value_wei = 0
            try:
                block_number = int(str(tx.get("blockNumber") or "0"))
            except ValueError:
                block_number = 0
            try:
                timestamp = int(str(tx.get("timeStamp") or tx.get("timestamp") or "0"))
            except ValueError:
                timestamp = 0

            is_error = str(tx.get("isError") or "0").strip()
            txreceipt_status = str(tx.get("txreceipt_status") or "1").strip()
            is_success = (is_error == "0") and (txreceipt_status != "0")

            fn_name = str(tx.get("functionName") or "").strip()
            raw_input = str(tx.get("input") or "0x").strip()
            if fn_name:
                method = fn_name.split("(")[0].strip()
            elif raw_input in ("", "0x", "0x0"):
                method = "ETH Transfer"
            else:
                method = raw_input[:10]

            normalized.append(
                {
                    "hash": tx_hash,
                    "from": from_addr,
                    "to": to_addr,
                    "value_wei": value_wei,
                    "block_number": block_number,
                    "timestamp": timestamp,
                    "is_success": is_success,
                    "method": method,
                }
            )
        return normalized

    @staticmethod
    def _normalize_blockscout_v2_txs(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            tx_hash = str(item.get("hash") or "").strip()
            frm_obj = item.get("from")
            to_obj = item.get("to") or item.get("created_contract")
            from_addr = str(frm_obj.get("hash") if isinstance(frm_obj, dict) else (frm_obj or "")).strip()
            to_addr = str(to_obj.get("hash") if isinstance(to_obj, dict) else (to_obj or "")).strip()
            try:
                value_wei = int(str(item.get("value") or "0"))
            except ValueError:
                value_wei = 0
            try:
                block_number = int(str(item.get("block_number") or item.get("block") or "0"))
            except ValueError:
                block_number = 0

            ts_raw = item.get("timestamp")
            timestamp = 0
            if ts_raw:
                try:
                    from datetime import datetime, timezone

                    iso_s = str(ts_raw).replace("Z", "+00:00")
                    dt = datetime.fromisoformat(iso_s)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    timestamp = int(dt.timestamp())
                except Exception:
                    timestamp = 0

            status_str = str(item.get("status") or "ok").lower()
            result_str = str(item.get("result") or "success").lower()
            is_success = status_str in ("ok", "1", "true", "success") and "revert" not in result_str

            method = str(item.get("method") or "").strip()
            raw_input = str(item.get("raw_input") or "0x").strip()
            if not method:
                method = "ETH Transfer" if raw_input in ("", "0x", "0x0") else raw_input[:10]

            normalized.append(
                {
                    "hash": tx_hash,
                    "from": from_addr,
                    "to": to_addr,
                    "value_wei": value_wei,
                    "block_number": block_number,
                    "timestamp": timestamp,
                    "is_success": is_success,
                    "method": method,
                }
            )
        return normalized

    async def evaluate_wallet(
        self,
        wallet: str,
        criteria: FilterCriteria,
        chain_info: Dict[str, Any],
        api_key_override: Optional[str] = None,
    ) -> WalletFilterResult:
        """Fetch detailed transactions for a single wallet and evaluate against `criteria`."""
        wallet_cs = _checksum_addr(wallet)
        explorer_base = chain_info.get("explorer_url", "https://etherscan.io").rstrip("/")
        wallet_explorer_url = f"{explorer_base}/address/{wallet_cs}"

        try:
            txs, source = await self.fetch_wallet_transactions(
                wallet=wallet_cs,
                chain_info=chain_info,
                start_block=criteria.start_block,
                end_block=criteria.end_block,
                api_key_override=api_key_override,
            )
        except Exception as exc:
            return WalletFilterResult(
                wallet=wallet_cs,
                matched=False,
                matching_tx_count=0,
                total_wallet_txs_scanned=0,
                total_eth_sent_wei=0,
                total_eth_sent="0",
                explorer_url=wallet_explorer_url,
                data_source="error",
                error=str(exc),
            )

        target_lower = criteria.target_address.lower().strip() if criteria.target_address else ""
        wallet_lower = wallet_cs.lower()
        min_wei = eth_to_wei(criteria.min_eth) if criteria.min_eth is not None else None
        max_wei = eth_to_wei(criteria.max_eth) if criteria.max_eth is not None else None

        matching_txs: List[MatchingTransaction] = []
        total_eth_wei = 0

        for tx in txs:
            if (tx.get("from") or "").lower() != wallet_lower:
                continue

            tx_to = (tx.get("to") or "").strip()
            if target_lower and tx_to.lower() != target_lower:
                continue

            if criteria.only_successful and not tx.get("is_success", True):
                continue

            blk = int(tx.get("block_number") or 0)
            if blk and (blk < criteria.start_block or blk > criteria.end_block):
                continue

            val_wei = int(tx.get("value_wei") or 0)
            if criteria.require_nonzero_eth and val_wei <= 0 and (min_wei is None or min_wei > 0):
                continue
            if min_wei is not None and val_wei < min_wei:
                continue
            if max_wei is not None and val_wei > max_wei:
                continue

            total_eth_wei += val_wei
            tx_hash = tx.get("hash") or ""
            to_cs = _checksum_addr(tx_to) if ADDRESS_REGEX.fullmatch(tx_to) else tx_to
            matching_txs.append(
                MatchingTransaction(
                    tx_hash=tx_hash,
                    from_address=wallet_cs,
                    to_address=to_cs,
                    value_wei=val_wei,
                    value_eth=wei_to_eth_str(val_wei),
                    block_number=blk,
                    timestamp=int(tx.get("timestamp") or 0),
                    method=tx.get("method") or "ETH Transfer",
                    explorer_url=f"{explorer_base}/tx/{tx_hash}" if tx_hash else wallet_explorer_url,
                )
            )

        matching_count = len(matching_txs)
        is_match = criteria.matches_count(matching_count)

        timestamps = [m.timestamp for m in matching_txs if m.timestamp > 0]
        first_ts = min(timestamps) if timestamps else None
        last_ts = max(timestamps) if timestamps else None

        return WalletFilterResult(
            wallet=wallet_cs,
            matched=is_match,
            matching_tx_count=matching_count,
            total_wallet_txs_scanned=len(txs),
            total_eth_sent_wei=total_eth_wei,
            total_eth_sent=wei_to_eth_str(total_eth_wei),
            first_match_timestamp=first_ts,
            last_match_timestamp=last_ts,
            matching_txs=matching_txs,
            explorer_url=wallet_explorer_url,
            data_source=source,
        )

    async def filter_wallets(
        self,
        wallets: List[str],
        criteria: FilterCriteria,
        api_key_override: Optional[str] = None,
        concurrency: int = 4,
    ) -> Dict[str, Any]:
        """Filter a sheet/list of wallets.

        - If `criteria.target_address` is NOT set and no per-tx ETH filter is set:
          uses fast batched JSON-RPC `eth_getTransactionCount` + `eth_getBalance` to check
          how many transactions each wallet has made on Ethereum.
        - If `criteria.target_address` IS set (or per-tx ETH value filter is set):
          evaluates detailed transaction history via Etherscan / Blockscout.
        """
        chain_info = self.resolve_chain_info(criteria.chain_key)
        criteria.chain_id = chain_info["chain_id"]
        explorer_base = chain_info.get("explorer_url", "https://etherscan.io").rstrip("/")

        use_detailed_tx_scan = bool(
            criteria.target_address
            or criteria.min_eth is not None
            or criteria.max_eth is not None
            or criteria.start_block > 0
            or criteria.end_block < 99999999
        )

        if not wallets and criteria.target_address:
            results = await self._evaluate_from_target_transactions(
                criteria=criteria,
                chain_info=chain_info,
                api_key_override=api_key_override,
            )
        elif not use_detailed_tx_scan:
            # Fast batch RPC mode for filtering a sheet of wallets by total transactions made!
            nonce_map = await self.fetch_batch_wallet_nonces_and_balances(wallets, chain_info)
            results = []
            for w in wallets:
                w_cs = _checksum_addr(w)
                tx_cnt, bal_wei, src = nonce_map.get(w_cs.lower(), (0, 0, "rpc"))
                is_match = criteria.matches_count(tx_cnt)
                results.append(
                    WalletFilterResult(
                        wallet=w_cs,
                        matched=is_match,
                        matching_tx_count=tx_cnt,
                        total_wallet_txs_scanned=tx_cnt,
                        total_eth_sent_wei=0,
                        total_eth_sent="0",
                        eth_balance_wei=bal_wei,
                        eth_balance=wei_to_eth_str(bal_wei),
                        explorer_url=f"{explorer_base}/address/{w_cs}",
                        data_source=src,
                    )
                )
        else:
            sem = asyncio.Semaphore(max(1, concurrency))

            async def _worker(addr: str) -> WalletFilterResult:
                async with sem:
                    return await self.evaluate_wallet(
                        wallet=addr,
                        criteria=criteria,
                        chain_info=chain_info,
                        api_key_override=api_key_override,
                    )

            results = await asyncio.gather(*[_worker(w) for w in wallets])

        matched_results = [r for r in results if r.matched]
        unmatched_results = [r for r in results if not r.matched]
        total_matched_eth_wei = sum(r.total_eth_sent_wei for r in matched_results)
        total_matched_balance_wei = sum(r.eth_balance_wei for r in matched_results)
        total_matching_txs = sum(r.matching_tx_count for r in matched_results)

        return {
            "chain": {
                "key": chain_info["chain_key"],
                "name": chain_info["name"],
                "chain_id": chain_info["chain_id"],
                "symbol": chain_info["symbol"],
                "explorer_url": chain_info["explorer_url"],
            },
            "criteria": {
                "target_address": criteria.target_address,
                "count_mode": criteria.count_mode,
                "exact_count": criteria.exact_count,
                "min_count": criteria.min_count,
                "max_count": criteria.max_count,
                "min_eth": criteria.min_eth,
                "max_eth": criteria.max_eth,
                "require_nonzero_eth": criteria.require_nonzero_eth,
                "only_successful": criteria.only_successful,
                "start_block": criteria.start_block,
                "end_block": criteria.end_block,
            },
            "summary": {
                "total_wallets_scanned": len(results),
                "matched_wallets_count": len(matched_results),
                "unmatched_wallets_count": len(unmatched_results),
                "total_matching_txs": total_matching_txs,
                "total_eth_sent_matched": wei_to_eth_str(total_matched_eth_wei),
                "total_eth_balance_matched": wei_to_eth_str(total_matched_balance_wei),
                "scan_mode": "detailed_txs" if use_detailed_tx_scan else "wallet_tx_count",
            },
            "matched_wallets": [r.wallet for r in matched_results],
            "results": [r.to_dict() for r in results],
        }

    async def _evaluate_from_target_transactions(
        self,
        criteria: FilterCriteria,
        chain_info: Dict[str, Any],
        api_key_override: Optional[str] = None,
    ) -> List[WalletFilterResult]:
        """Scan `criteria.target_address`'s incoming transactions and group by sender wallet."""
        target_cs = _checksum_addr(criteria.target_address or "")
        target_lower = target_cs.lower()
        explorer_base = chain_info.get("explorer_url", "https://etherscan.io").rstrip("/")

        txs, source = await self.fetch_wallet_transactions(
            wallet=target_cs,
            chain_info=chain_info,
            start_block=criteria.start_block,
            end_block=criteria.end_block,
            api_key_override=api_key_override,
        )

        min_wei = eth_to_wei(criteria.min_eth) if criteria.min_eth is not None else None
        max_wei = eth_to_wei(criteria.max_eth) if criteria.max_eth is not None else None

        grouped_all_counts: Dict[str, int] = {}
        grouped_matches: Dict[str, List[MatchingTransaction]] = {}
        sender_checksum: Dict[str, str] = {}

        for tx in txs:
            tx_to = (tx.get("to") or "").strip().lower()
            frm_raw = (tx.get("from") or "").strip()
            if tx_to != target_lower or not ADDRESS_REGEX.fullmatch(frm_raw):
                continue
            frm_low = frm_raw.lower()
            if frm_low == target_lower:
                continue

            if frm_low not in sender_checksum:
                sender_checksum[frm_low] = _checksum_addr(frm_raw)
                grouped_all_counts[frm_low] = 0
                grouped_matches[frm_low] = []

            grouped_all_counts[frm_low] += 1

            if criteria.only_successful and not tx.get("is_success", True):
                continue

            blk = int(tx.get("block_number") or 0)
            if blk and (blk < criteria.start_block or blk > criteria.end_block):
                continue

            val_wei = int(tx.get("value_wei") or 0)
            if criteria.require_nonzero_eth and val_wei <= 0 and (min_wei is None or min_wei > 0):
                continue
            if min_wei is not None and val_wei < min_wei:
                continue
            if max_wei is not None and val_wei > max_wei:
                continue

            tx_hash = tx.get("hash") or ""
            wallet_cs = sender_checksum[frm_low]
            grouped_matches[frm_low].append(
                MatchingTransaction(
                    tx_hash=tx_hash,
                    from_address=wallet_cs,
                    to_address=target_cs,
                    value_wei=val_wei,
                    value_eth=wei_to_eth_str(val_wei),
                    block_number=blk,
                    timestamp=int(tx.get("timestamp") or 0),
                    method=tx.get("method") or "ETH Transfer",
                    explorer_url=f"{explorer_base}/tx/{tx_hash}" if tx_hash else f"{explorer_base}/address/{wallet_cs}",
                )
            )

        results: List[WalletFilterResult] = []
        for frm_low, wallet_cs in sender_checksum.items():
            m_txs = grouped_matches[frm_low]
            m_count = len(m_txs)
            is_match = criteria.matches_count(m_count)
            total_wei = sum(t.value_wei for t in m_txs)
            timestamps = [t.timestamp for t in m_txs if t.timestamp > 0]
            results.append(
                WalletFilterResult(
                    wallet=wallet_cs,
                    matched=is_match,
                    matching_tx_count=m_count,
                    total_wallet_txs_scanned=grouped_all_counts[frm_low],
                    total_eth_sent_wei=total_wei,
                    total_eth_sent=wei_to_eth_str(total_wei),
                    first_match_timestamp=min(timestamps) if timestamps else None,
                    last_match_timestamp=max(timestamps) if timestamps else None,
                    matching_txs=m_txs,
                    explorer_url=f"{explorer_base}/address/{wallet_cs}",
                    data_source=source,
                )
            )
        return results

    async def discover_senders_for_target(
        self,
        target_address: str,
        chain_key: str = "ethereum",
        api_key_override: Optional[str] = None,
        limit: int = 100,
    ) -> List[str]:
        """Discover unique sender wallet addresses that sent ETH to `target_address`."""
        target_cs = normalize_target_address(target_address)
        if not target_cs:
            return []
        chain_info = self.resolve_chain_info(chain_key)
        txs, _ = await self.fetch_wallet_transactions(
            wallet=target_cs,
            chain_info=chain_info,
            api_key_override=api_key_override,
        )
        target_low = target_cs.lower()
        senders: List[str] = []
        seen = set()
        for tx in txs:
            to_addr = (tx.get("to") or "").lower()
            frm_addr = (tx.get("from") or "").strip()
            val_wei = int(tx.get("value_wei") or 0)
            if to_addr == target_low and val_wei > 0 and ADDRESS_REGEX.fullmatch(frm_addr):
                low = frm_addr.lower()
                if low not in seen and low != target_low:
                    seen.add(low)
                    senders.append(_checksum_addr(frm_addr))
                    if len(senders) >= limit:
                        break
        return senders

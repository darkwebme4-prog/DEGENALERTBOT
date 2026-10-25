"""ERC-165 interface verification and on-chain NFT state & metadata detection."""

import logging
from typing import List, Optional, Tuple
from eth_abi import decode, encode
from eth_utils import to_checksum_address
from app.rpc import EvmRpcClient, RPCError

logger = logging.getLogger(__name__)

# ERC-165 Interface IDs
ERC165_INTERFACE_ID = "01ffc9a7"
ERC721_INTERFACE_ID = "80ac58cd"
ERC1155_INTERFACE_ID = "d9b67a26"
ERC2981_INTERFACE_ID = "2a55205a"

# Calldata for supportsInterface(bytes4)
ERC721_CALLDATA = f"0x{ERC165_INTERFACE_ID}{ERC721_INTERFACE_ID}".ljust(74, "0")
ERC1155_CALLDATA = f"0x{ERC165_INTERFACE_ID}{ERC1155_INTERFACE_ID}".ljust(74, "0")

# Metadata & Supply Selectors
NAME_CALLDATA = "0x06fdde03"            # name()
SYMBOL_CALLDATA = "0x95d89b41"          # symbol()
TOTAL_SUPPLY_CALLDATA = "0x18160ddd"    # totalSupply()

MAX_SUPPLY_GETTERS = [
    ("maxSupply()", "0xd5abeb01"),
    ("MAX_SUPPLY()", "0x32cb6b0c"),
    ("collectionSize()", "0x45c0f533"),
    ("MAX_ELEMENTS()", "0x859994a0"),
]

OWNER_CALLDATA = "0x8da5cb5b"           # owner()

PAUSED_GETTERS = [
    ("paused()", "0x5c975abb", False),
    ("isPaused()", "0xb187bd26", False),
    ("mintPaused()", "0x7e4831d3", False),
    ("saleIsActive()", "0xeb8d2444", True),  # inverted: True means NOT paused
]

PRICE_GETTERS = [
    ("price()", "0xa035b1fe"),
    ("cost()", "0x13faede6"),
    ("mintPrice()", "0x6817c76c"),
    ("MINT_PRICE()", "0xc002d23d"),
    ("publicPrice()", "0xa945bf80"),
    ("PRICE()", "0x8b7afe2e"),
]

ROYALTY_INFO_SELECTOR = "0x2a55205a"    # royaltyInfo(uint256,uint256)
TOKEN_URI_SELECTOR = "0xc87b56dd"       # tokenURI(uint256)
ERC1155_URI_SELECTOR = "0x0e89341c"     # uri(uint256)
CONTRACT_URI_CALLDATA = "0xe8a3d485"    # contractURI()


def _is_true_result(hex_result: str) -> bool:
    """Check if 32-byte hex result represents boolean true (1)."""
    if not hex_result or hex_result == "0x":
        return False
    clean = hex_result.lower().replace("0x", "")
    if len(clean) < 64:
        return False
    try:
        val = int(clean[-64:], 16)
        return val == 1
    except ValueError:
        return False


def _decode_uint256(hex_data: str) -> Optional[int]:
    """Safely decode a uint256 return value."""
    if not hex_data or hex_data == "0x":
        return None
    clean = hex_data.lower().replace("0x", "")
    if len(clean) < 64:
        return None
    try:
        val = int(clean[:64], 16)
        return val
    except ValueError:
        return None


def _decode_bool(hex_data: str) -> Optional[bool]:
    """Safely decode a bool return value (must be 0 or 1)."""
    val = _decode_uint256(hex_data)
    if val in (0, 1):
        return bool(val)
    return None


def _decode_string_or_bytes32(hex_data: str) -> Optional[str]:
    """Safely decode an ABI string or legacy bytes32 string."""
    if not hex_data or hex_data == "0x":
        return None
    try:
        raw = bytes.fromhex(hex_data.replace("0x", ""))
        if len(raw) >= 64:
            try:
                (decoded,) = decode(["string"], raw)
                res = decoded.strip("\x00").strip()
                return res if res else None
            except Exception:
                pass
        if len(raw) >= 32:
            res = raw[:32].decode("utf-8", errors="ignore").strip("\x00").strip()
            return res if res else None
    except Exception:
        pass
    return None


def _classify_eth_call_error(exc: Exception) -> Tuple[str, str]:
    """
    Distinguish on-chain revert ('not implemented') from network/RPC failure ('fetch failed').
    Returns (status_code, error_message).
    """
    msg = str(exc)
    low = msg.lower()
    revert_keywords = (
        "revert",
        "execution error",
        "vm execution",
        "code=3",
        "code': 3",
        "code=-32000",
        "code': -32000",
        "invalid opcode",
        "function selector was not recognized",
        "bad instruction",
    )
    if isinstance(exc, RPCError) and any(kw in low for kw in revert_keywords):
        return "not implemented", msg
    if any(kw in low for kw in ("execution reverted", "reverted", "invalid opcode")):
        return "not implemented", msg
    return "fetch failed", f"{type(exc).__name__}: {msg}"


class NftDetector:
    """Checks contract interfaces via ERC-165 and extracts on-chain NFT metadata and state."""

    def __init__(self, rpc_client: EvmRpcClient):
        self.rpc = rpc_client
        self.last_uri_statuses: dict[str, dict[str, Optional[str]]] = {}

    async def check_erc165(self, address: str, interface_id: str) -> bool:
        """Query supportsInterface(bytes4) on a contract address."""
        calldata = f"0x{ERC165_INTERFACE_ID}{interface_id.replace('0x', '')}".ljust(74, "0")
        try:
            result = await self.rpc.eth_call(to=address, data=calldata)
            return _is_true_result(result)
        except (RPCError, Exception) as e:
            logger.debug("ERC-165 check failed for %s (interface %s): %s", address, interface_id, e)
            return False

    async def detect_nft_standard(self, address: str) -> Tuple[str, bool]:
        """
        Detect whether a contract is ERC-721 or ERC-1155 using ERC-165.
        Returns (standard: str, is_nft: bool).
        """
        is_721 = await self.check_erc165(address, ERC721_INTERFACE_ID)
        if is_721:
            return "ERC721", True

        is_1155 = await self.check_erc165(address, ERC1155_INTERFACE_ID)
        if is_1155:
            return "ERC1155", True

        return "UNKNOWN", False

    async def fetch_metadata(self, address: str) -> Tuple[Optional[str], Optional[str]]:
        """Fetch token name and symbol if available."""
        name = None
        symbol = None
        try:
            name_res = await self.rpc.eth_call(to=address, data=NAME_CALLDATA)
            name = _decode_string_or_bytes32(name_res)
        except Exception:
            pass

        try:
            sym_res = await self.rpc.eth_call(to=address, data=SYMBOL_CALLDATA)
            symbol = _decode_string_or_bytes32(sym_res)
        except Exception:
            pass

        return name, symbol

    async def fetch_supply_info(self, address: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        """
        Fetch totalSupply() and max supply (trying maxSupply(), MAX_SUPPLY(), collectionSize()).
        Returns (total_supply, max_supply, max_supply_getter_name).
        """
        total_supply = None
        try:
            res = await self.rpc.eth_call(to=address, data=TOTAL_SUPPLY_CALLDATA)
            val = _decode_uint256(res)
            if val is not None and val < 10**18:
                total_supply = val
        except Exception:
            pass

        max_supply = None
        max_getter = None
        for label, selector in MAX_SUPPLY_GETTERS:
            try:
                res = await self.rpc.eth_call(to=address, data=selector)
                val = _decode_uint256(res)
                if val is not None and 0 < val < 10**15:
                    max_supply = val
                    max_getter = label
                    break
            except Exception:
                continue

        return total_supply, max_supply, max_getter

    async def fetch_owner_info(self, address: str) -> Tuple[Optional[str], Optional[bool]]:
        """
        Fetch owner() and whether ownership is renounced (0x0 address).
        Returns (owner_address, is_renounced).
        """
        try:
            res = await self.rpc.eth_call(to=address, data=OWNER_CALLDATA)
            if not res or res == "0x":
                return None, None
            clean = res.lower().replace("0x", "")
            if len(clean) < 64:
                return None, None
            if clean[:24] != "0" * 24:
                return None, None
            addr_hex = clean[-40:]
            if addr_hex == "0" * 40:
                return "0x0000000000000000000000000000000000000000", True
            # Reject boolean / precompile low integers (1..9) that are not real EOAs/contracts
            if int(addr_hex, 16) <= 9:
                return None, None
            return to_checksum_address("0x" + addr_hex), False
        except Exception:
            return None, None

    async def fetch_paused_state(self, address: str) -> Tuple[Optional[bool], Optional[str]]:
        """
        Check paused(), isPaused(), mintPaused(), or saleIsActive().
        Returns (is_paused: Optional[bool], getter_name: Optional[str]).
        """
        for label, selector, inverted in PAUSED_GETTERS:
            try:
                res = await self.rpc.eth_call(to=address, data=selector)
                val = _decode_bool(res)
                if val is not None:
                    is_paused = (not val) if inverted else val
                    return is_paused, label
            except Exception:
                continue
        return None, None

    async def fetch_getter_mint_price(self, address: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Try price(), cost(), mintPrice(), MINT_PRICE(), publicPrice().
        Returns (price_wei: Optional[int], getter_name: Optional[str]).
        """
        for label, selector in PRICE_GETTERS:
            try:
                res = await self.rpc.eth_call(to=address, data=selector)
                val = _decode_uint256(res)
                if val is not None and val < 10**24:
                    return val, label
            except Exception:
                continue
        return None, None

    async def fetch_royalty_info(
        self,
        address: str,
        token_ids: Optional[List[int]] = None,
    ) -> Tuple[Optional[str], Optional[int]]:
        """
        Check ERC-2981 royaltyInfo(uint256 tokenId, uint256 salePrice) with salePrice=10000.
        Uses observed token IDs when available.
        Returns (receiver_address: Optional[str], royalty_bps: Optional[int]).
        """
        candidate_tids: List[int] = []
        if token_ids:
            for tid in token_ids:
                if tid is not None and int(tid) >= 0 and int(tid) not in candidate_tids:
                    candidate_tids.append(int(tid))
        if not candidate_tids:
            candidate_tids = [1, 0]

        for token_id in candidate_tids:
            try:
                args_hex = encode(["uint256", "uint256"], [token_id, 10000]).hex()
                calldata = f"{ROYALTY_INFO_SELECTOR}{args_hex}"
                res = await self.rpc.eth_call(to=address, data=calldata)
                if not res or res == "0x":
                    continue
                raw = bytes.fromhex(res.replace("0x", ""))
                if len(raw) >= 64:
                    receiver, amount = decode(["address", "uint256"], raw[:64])
                    if 0 <= amount <= 10000:
                        return to_checksum_address(receiver), int(amount)
            except Exception:
                continue
        return None, None

    async def fetch_contract_uri(self, address: str) -> Tuple[Optional[str], str, Optional[str]]:
        """
        Call contractURI() with revert handling.
        Returns (contract_uri, status, error_detail) where status is:
          - 'ok': contractURI() returned a non-empty URI string
          - 'not implemented': call reverted or returned empty response
          - 'fetch failed': RPC network/connection error (logged)
        """
        try:
            res_c = await self.rpc.eth_call(to=address, data=CONTRACT_URI_CALLDATA)
            contract_uri = _decode_string_or_bytes32(res_c)
            if contract_uri:
                return contract_uri, "ok", None
            return None, "not implemented", None
        except Exception as exc:
            status, err_detail = _classify_eth_call_error(exc)
            if status == "fetch failed":
                logger.warning("contractURI() RPC call failed for %s: %s", address, err_detail)
            return None, status, (err_detail if status == "fetch failed" else None)

    async def fetch_uri_info(
        self,
        address: str,
        standard: str = "ERC721",
        token_ids: Optional[List[int]] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[bool], str]:
        """
        Fetch contractURI() with revert handling and tokenURI(id) / uri(id) using actual
        token IDs from observed mint events (retrying with uri(id) for ERC-1155), and
        determine whether metadata looks revealed.
        Returns (token_uri, contract_uri, is_revealed, reveal_reason).
        """
        token_uri_1 = None
        token_uri_2 = None

        # 1. Call contractURI() with revert handling
        contract_uri, contract_uri_status, contract_uri_err = await self.fetch_contract_uri(address)

        # 2. Call tokenURI(tokenId) / uri(id) using real token IDs from observed mint events
        candidate_tids: List[int] = []
        if token_ids:
            for t in token_ids:
                try:
                    val = int(t)
                    if val >= 0 and val not in candidate_tids:
                        candidate_tids.append(val)
                except (ValueError, TypeError):
                    continue

        if standard == "ERC1155":
            selectors = [ERC1155_URI_SELECTOR, TOKEN_URI_SELECTOR]
        else:
            selectors = [TOKEN_URI_SELECTOR, ERC1155_URI_SELECTOR]

        matched_selector = selectors[0]
        matched_tid: Optional[int] = None
        token_uri_status = "not implemented"
        token_uri_err: Optional[str] = None
        saw_network_err: Optional[str] = None

        for tid in candidate_tids:
            for sel in selectors:
                try:
                    calldata = f"{sel}{encode(['uint256'], [tid]).hex()}"
                    res = await self.rpc.eth_call(to=address, data=calldata)
                    uri = _decode_string_or_bytes32(res)
                    if uri:
                        token_uri_1 = uri
                        matched_selector = sel
                        matched_tid = tid
                        token_uri_status = "ok"
                        break
                except Exception as exc:
                    st, err_msg = _classify_eth_call_error(exc)
                    if st == "fetch failed":
                        saw_network_err = err_msg
                    continue
            if token_uri_1:
                break

        if not token_uri_1 and saw_network_err:
            token_uri_status = "fetch failed"
            token_uri_err = saw_network_err
            logger.warning("tokenURI/uri RPC call failed for %s: %s", address, saw_network_err)

        if token_uri_1 and len(candidate_tids) >= 2:
            second_tids = [t for t in candidate_tids if t != matched_tid]
            if second_tids:
                try:
                    calldata_2 = f"{matched_selector}{encode(['uint256'], [second_tids[0]]).hex()}"
                    res_2 = await self.rpc.eth_call(to=address, data=calldata_2)
                    token_uri_2 = _decode_string_or_bytes32(res_2)
                except Exception:
                    pass

        self.last_uri_statuses[address.lower()] = {
            "contract_uri_status": contract_uri_status,
            "contract_uri_error": contract_uri_err,
            "token_uri_status": token_uri_status,
            "token_uri_error": token_uri_err,
        }

        if not token_uri_1 and not contract_uri:
            return None, None, None, "unavailable"

        if not token_uri_1:
            return None, contract_uri, None, "tokenURI unavailable"

        lower_uri = token_uri_1.lower()
        unrevealed_keywords = (
            "unrevealed",
            "prereveal",
            "pre-reveal",
            "hidden",
            "placeholder",
            "notrevealed",
            "mystery",
        )
        if any(kw in lower_uri for kw in unrevealed_keywords):
            return token_uri_1, contract_uri, False, "Placeholder keyword in URI"

        if token_uri_1.startswith("data:application/json"):
            return token_uri_1, contract_uri, True, "On-chain JSON"

        if token_uri_2 and token_uri_1 == token_uri_2 and "{id}" not in lower_uri:
            return token_uri_1, contract_uri, False, "Identical static URI across tokens"

        return token_uri_1, contract_uri, True, "Revealed"


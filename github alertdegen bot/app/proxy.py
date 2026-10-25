"""Proxy detection for EVM smart contracts via EIP-1967, EIP-1822, and OpenZeppelin storage slots."""

import logging
from typing import Optional, Tuple
from eth_utils import to_checksum_address
from app.rpc import EvmRpcClient, RPCError

logger = logging.getLogger(__name__)

# Standard Storage Slots
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1822_PROXIABLE_SLOT = "0xc5f1683af66d29d8d582456ec0e677484ee6acaee5132045cff87325828f06a0"
OPENZEPPELIN_LEGACY_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"

BEACON_IMPLEMENTATION_CALLDATA = "0x5c60da1b"  # implementation() selector on beacon


def parse_address_from_slot(slot_hex: str) -> Optional[str]:
    """Extract 20-byte address from a 32-byte storage slot hex string."""
    if not slot_hex or slot_hex == "0x":
        return None
    raw = slot_hex.replace("0x", "").lower().zfill(64)
    addr_part = raw[-40:]
    if addr_part == "0" * 40:
        return None
    try:
        return to_checksum_address("0x" + addr_part)
    except Exception:
        return None


class ProxyDetector:
    """Detects whether a contract is an upgradeable proxy and identifies implementation address."""

    def __init__(self, rpc_client: EvmRpcClient):
        self.rpc = rpc_client

    async def detect_proxy(self, address: str) -> Tuple[Optional[bool], Optional[str], Optional[str]]:
        """
        Check whether the given address is a proxy.
        Returns:
            (is_proxy: Optional[bool], implementation_address: Optional[str], proxy_type: Optional[str])
            Returns (None, None, None) if all storage slot lookups fail.
        """
        any_slot_read = False

        # 1. EIP-1967 Implementation Slot
        try:
            val = await self.rpc.eth_get_storage_at(address, EIP1967_IMPLEMENTATION_SLOT)
            if isinstance(val, str):
                any_slot_read = True
                impl = parse_address_from_slot(val)
                if impl:
                    return True, impl, "EIP-1967"
        except (RPCError, Exception) as e:
            logger.debug("Failed reading EIP-1967 slot for %s: %s", address, e)

        # 2. EIP-1967 Beacon Slot
        try:
            val = await self.rpc.eth_get_storage_at(address, EIP1967_BEACON_SLOT)
            if isinstance(val, str):
                any_slot_read = True
                beacon = parse_address_from_slot(val)
                if beacon:
                    try:
                        res = await self.rpc.eth_call(to=beacon, data=BEACON_IMPLEMENTATION_CALLDATA)
                        beacon_impl = parse_address_from_slot(res)
                        if beacon_impl:
                            return True, beacon_impl, "EIP-1967 Beacon"
                    except Exception:
                        pass
                    return True, beacon, "EIP-1967 Beacon"
        except Exception as e:
            logger.debug("Failed reading EIP-1967 beacon slot for %s: %s", address, e)

        # 3. EIP-1822 UUPS Slot
        try:
            val = await self.rpc.eth_get_storage_at(address, EIP1822_PROXIABLE_SLOT)
            if isinstance(val, str):
                any_slot_read = True
                impl = parse_address_from_slot(val)
                if impl:
                    return True, impl, "EIP-1822 UUPS"
        except Exception as e:
            logger.debug("Failed reading EIP-1822 slot for %s: %s", address, e)

        # 4. OpenZeppelin Legacy Slot
        try:
            val = await self.rpc.eth_get_storage_at(address, OPENZEPPELIN_LEGACY_SLOT)
            if isinstance(val, str):
                any_slot_read = True
                impl = parse_address_from_slot(val)
                if impl:
                    return True, impl, "OpenZeppelin Legacy"
        except Exception as e:
            logger.debug("Failed reading OpenZeppelin legacy slot for %s: %s", address, e)

        if not any_slot_read:
            return None, None, None

        return False, None, None

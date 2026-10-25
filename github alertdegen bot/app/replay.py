"""Historical block replay engine for verifying mint detection, thresholds, and alerts."""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional
from app.pipeline import (
    AlertPipeline,
    TRANSFER_TOPIC,
    TRANSFER_SINGLE_TOPIC,
    TRANSFER_BATCH_TOPIC,
)
from app.rpc import EvmRpcClient

logger = logging.getLogger(__name__)


class BlockReplayer:
    """Replays a block range to simulate or backtest live streaming."""

    def __init__(self, pipeline: AlertPipeline, rpc: EvmRpcClient):
        self.pipeline = pipeline
        self.rpc = rpc

    async def replay_range(
        self,
        start_block: int,
        end_block: int,
        batch_size: int = 10,
        delay_between_batches: float = 0.2,
    ) -> Dict[str, Any]:
        """
        Replay blocks from start_block to end_block inclusive.
        Returns execution statistics summary.
        """
        logger.info("🎬 Starting block replay from block %d to %d...", start_block, end_block)
        total_blocks = end_block - start_block + 1
        blocks_processed = 0
        deployments_found = 0
        mints_processed = 0

        # Pre-initialize pipeline database
        await self.pipeline.initialize()

        # Target topics for mint transfers from 0 address
        mint_topics = [[TRANSFER_TOPIC, TRANSFER_SINGLE_TOPIC, TRANSFER_BATCH_TOPIC]]

        for blk_num in range(start_block, end_block + 1):
            try:
                # 1. Fetch block header only (never fetch full blocks)
                block = await self.rpc.eth_get_block_by_number(blk_num, full_txs=False)
                if not block:
                    continue
                blocks_processed += 1
                block_ts = int(block.get("timestamp", "0"), 16) if isinstance(block.get("timestamp"), str) else block.get("timestamp", int(time.time()))

                # 2. Check contract deployments in block
                detected = await self.pipeline.process_block_deployments(block)
                deployments_found += len(detected)

                # 3. Fetch receipts and logs for this block
                receipts = None
                try:
                    receipts = await self.rpc.eth_get_block_receipts(blk_num)
                except Exception:
                    pass

                if isinstance(receipts, list) and len(receipts) > 0:
                    for r in receipts:
                        if isinstance(r, dict):
                            # Extract logs
                            for log in r.get("logs", []):
                                mint = await self.pipeline.parse_log_as_mint(log, block_timestamp=block_ts)
                                if mint:
                                    await self.pipeline.process_mint(mint)
                                    mints_processed += 1
                else:
                    # Fallback to eth_getLogs for the block
                    try:
                        logs_filter = {
                            "fromBlock": hex(blk_num),
                            "toBlock": hex(blk_num),
                            "topics": mint_topics,
                        }
                        logs = await self.rpc.eth_get_logs(logs_filter)
                        for log in logs:
                            mint = await self.pipeline.parse_log_as_mint(log, block_timestamp=block_ts)
                            if mint:
                                await self.pipeline.process_mint(mint)
                                mints_processed += 1
                    except Exception as e:
                        logger.warning("Could not fetch logs for block %d: %s", blk_num, e)

                if hasattr(self.pipeline, "db") and hasattr(self.pipeline.db, "set_last_processed_block"):
                    await self.pipeline.db.set_last_processed_block(self.pipeline.chain_key, blk_num)

            except Exception as e:
                logger.warning("Error processing block %d during replay: %s", blk_num, e)

            if delay_between_batches > 0:
                await asyncio.sleep(delay_between_batches)

        logger.info(
            "🏁 Block replay finished! Processed %d blocks, %d new deployments, %d mints.",
            blocks_processed, deployments_found, mints_processed
        )

        return {
            "start_block": start_block,
            "end_block": end_block,
            "blocks_processed": blocks_processed,
            "deployments_found": deployments_found,
            "mints_processed": mints_processed,
        }

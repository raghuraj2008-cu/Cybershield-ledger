import hashlib
from typing import Dict, Any

class BlockchainAnchorService:
    def __init__(self):
        self.anchored_batches = []

    def anchor_merkle_root(self, merkle_root: str, total_events: int) -> Dict[str, Any]:
        """Anchors the calculated Merkle root to the simulated/connected immutable ledger."""
        tx_hash = "0x" + hashlib.sha256(f"{merkle_root}{total_events}".encode()).hexdigest()
        record = {
            "batch_id": len(self.anchored_batches) + 1,
            "merkle_root": merkle_root,
            "total_events": total_events,
            "tx_hash": tx_hash,
            "status": "COMMITTED_ON_CHAIN"
        }
        self.anchored_batches.append(record)
        return record

blockchain_service = BlockchainAnchorService()

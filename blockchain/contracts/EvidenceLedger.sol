// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EvidenceLedger {
    struct BatchRecord {
        bytes32 merkleRoot;
        uint256 timestamp;
        uint256 totalEvents;
        address recordedBy;
    }

    mapping(uint256 => BatchRecord) public batches;
    uint256 public batchCount;

    event BatchCommitted(uint256 indexed batchId, bytes32 indexed merkleRoot, uint256 totalEvents);

    function commitBatch(bytes32 _merkleRoot, uint256 _totalEvents) external returns (uint256) {
        batchCount++;
        batches[batchCount] = BatchRecord({
            merkleRoot: _merkleRoot,
            timestamp: block.timestamp,
            totalEvents: _totalEvents,
            recordedBy: msg.sender
        });

        emit BatchCommitted(batchCount, _merkleRoot, _totalEvents);
        return batchCount;
    }

    function verifyProof(
        bytes32 leafHash,
        bytes32[] calldata proof,
        bool[] calldata positions,
        uint256 batchId
    ) external view returns (bool) {
        bytes32 computed = leafHash;
        for (uint256 i = 0; i < proof.length; i++) {
            if (positions[i]) {
                computed = keccak256(abi.encodePacked(computed, proof[i]));
            } else {
                computed = keccak256(abi.encodePacked(proof[i], computed));
            }
        }
        return computed == batches[batchId].merkleRoot;
    }
}

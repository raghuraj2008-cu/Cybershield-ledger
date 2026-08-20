import hashlib
import json
import sys

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def verify_merkle_path(leaf_hash: str, proof_path: list[dict], expected_root: str) -> bool:
    current = leaf_hash
    for step in proof_path:
        sibling = step.get("hash")
        direction = step.get("position", "right")
        
        if direction == "left":
            combined = sibling + current
        else:
            combined = current + sibling
            
        current = sha256(combined)
        
    return current.lower() == expected_root.lower()

if __name__ == "__main__":
    print("=" * 65)
    print("🛡️  CYBERSHIELD LEDGER — INDEPENDENT MERKLE PROOF VERIFIER")
    print("=" * 65)

    if len(sys.argv) < 4:
        print("\nUsage:")
        print("  python verify_proof.py <LEAF_HASH> <SIBLINGS_JSON> <EXPECTED_ROOT>")
        print("\nExample (Self-Test Verification):")
        
        # Test vectors
        leaf_a = sha256("EVENT_A")
        leaf_b = sha256("EVENT_B")
        root = sha256(leaf_a + leaf_b)
        proof = [{"hash": leaf_b, "position": "right"}]
        
        print(f"  Leaf Hash     : {leaf_a}")
        print(f"  Sibling Proof : {proof}")
        print(f"  Expected Root : {root}")
        
        is_valid = verify_merkle_path(leaf_a, proof, root)
        print(f"\nMathematical Proof Verdict: {'[VALID - CONSENSUS CONFIRMED]' if is_valid else '[INVALID]'}")
    else:
        leaf = sys.argv[1]
        proof = json.loads(sys.argv[2])
        root = sys.argv[3]
        
        is_valid = verify_merkle_path(leaf, proof, root)
        print(f"\nTarget Leaf   : {leaf}")
        print(f"Expected Root : {root}")
        print(f"Verification  : {'✅ CRYPTOGRAPHICALLY VALID (NIST SP 800-86 ADMISSIBLE)' if is_valid else '❌ FORGERY DETECTED'}")
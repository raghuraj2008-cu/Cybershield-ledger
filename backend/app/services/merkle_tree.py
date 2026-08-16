import hashlib
from typing import List, Tuple

class MerkleTree:
    @staticmethod
    def hash_str(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def build_tree(leaves: List[str]) -> Tuple[str, List[List[str]]]:
        if not leaves:
            return "", []
        current = [MerkleTree.hash_str(x) for x in leaves]
        levels = [current]
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                l = current[i]
                r = current[i + 1] if i + 1 < len(current) else l
                nxt.append(MerkleTree.hash_str(l + r))
            levels.append(nxt)
            current = nxt
        return current[0], levels

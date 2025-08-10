import math
import subprocess
import binascii

def sm3_hash(msg):
    with open("input.bin", "wb") as f:
        f.write(msg)
    subprocess.run(["./sm3_test", "input.bin"], capture_output=True)
    with open("output.bin", "rb") as f:
        return f.read()

class MerkleTree:
    def __init__(self, leaves):
        self.leaves = [sm3_hash(leaf) for leaf in leaves]
        self.tree = self.build_tree(self.leaves)
    
    def build_tree(self, leaves):
        tree = [leaves]
        while len(tree[-1]) > 1:
            level = []
            for i in range(0, len(tree[-1]), 2):
                left = tree[-1][i]
                right = tree[-1][i+1] if i+1 < len(tree[-1]) else left
                parent = sm3_hash(left + right)
                level.append(parent)
            tree.append(level)
        return tree
    
    def get_root(self):
        return self.tree[-1][0]
    
    def get_existence_proof(self, leaf):
        leaf_hash = sm3_hash(leaf)
        if leaf_hash not in self.leaves:
            return None
        index = self.leaves.index(leaf_hash)
        proof = []
        for level in self.tree[:-1]:
            sibling_index = index ^ 1
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            index //= 2
        return proof
    
    def verify_existence_proof(self, leaf, proof, root):
        current = sm3_hash(leaf)
        index = self.leaves.index(current) if current in self.leaves else 0
        for sibling in proof:
            if index % 2 == 0:
                current = sm3_hash(current + sibling)
            else:
                current = sm3_hash(sibling + current)
            index //= 2
        return current == root
    
    def get_non_existence_proof(self, leaf):
        leaf_hash = sm3_hash(leaf)
        if leaf_hash in self.leaves:
            return None
        sorted_leaves = sorted(self.leaves)
        for i, h in enumerate(sorted_leaves):
            if h > leaf_hash:
                return self.get_existence_proof(self.leaves[i-1]) if i > 0 else []
        return self.get_existence_proof(self.leaves[-1])

if __name__ == "__main__":
    leaves = [f"data_{i}".encode() for i in range(100000)]
    tree = MerkleTree(leaves)
    root = tree.get_root()
    print(f"Merkle Root: {binascii.hexlify(root).decode()}")
    
    proof = tree.get_existence_proof(b"data_42")
    print(f"Existence Proof for data_42: {[binascii.hexlify(p).decode() for p in proof]}")
    print(f"Verified: {tree.verify_existence_proof(b'data_42', proof, root)}")
    
    proof = tree.get_non_existence_proof(b"non_existent")
    print(f"Non-existence Proof: {[binascii.hexlify(p).decode() for p in proof]}")
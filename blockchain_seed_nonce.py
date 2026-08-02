"""
Blockchain Nonce Determinism via 512-Bit Master Seed.

Concept:
In standard blockchains (Proof-of-Work):
- Miners must spend massive computational power guessing billions of nonces blindly 
  to satisfy a hash condition.

In this Secret-Seed Blockchain Identity Scheme:
- The Public Network sees blocks linked by SHA-512 hashes. To guess the next 
  valid nonce, an attacker would need to brute-force a 512-bit search space (2^512).
- The Secret Seed Holder ALWAYS knows the exact winning nonce N_i for block i instantly.
  They generate N_i directly from their PRNG engine derived from the 512-bit secret seed!
"""

import hashlib
import secrets
import time
from prng512 import CryptoPRNG512


def sha512_int(val: int) -> bytes:
    """SHA-512 hash of a 512-bit integer."""
    return hashlib.sha512(val.to_bytes(64, byteorder='big')).digest()


def sha512_bytes(data: bytes) -> bytes:
    """SHA-512 hash of bytes."""
    return hashlib.sha512(data).digest()


class SeedBlockchain:
    def __init__(self, secret_seed: int):
        self.secret_seed = secret_seed
        # Seed holder's deterministic nonce generator
        self.prng = CryptoPRNG512(secret_seed)
        
        # Pre-generate nonces for the chain
        self.blocks = []

    def mint_block(self, block_index: int, data: str) -> dict:
        """
        The seed holder instantly produces the valid nonces N_i and N_{i+1} 
        without any brute-force search!
        """
        start_time = time.perf_counter()
        
        # Seed holder retrieves the exact deterministic nonces for this block
        nonce_curr = self.prng.next_int()
        
        # Lookahead nonce for chain link
        # We peek or generate the next nonce in sequence
        h_curr = sha512_int(nonce_curr)
        
        # For demonstration of chain link:
        # Block Hash combines Previous Block Hash + Data + Nonce Commitment
        prev_hash = self.blocks[-1]["block_hash"] if self.blocks else "0" * 128
        block_content = (prev_hash + data + h_curr.hex()).encode('utf-8')
        block_hash = sha512_bytes(block_content).hex()
        
        elapsed_us = (time.perf_counter() - start_time) * 1_000_000
        
        block = {
            "index": block_index,
            "data": data,
            "nonce_N_i": hex(nonce_curr),           # The winning 512-bit nonce known instantly
            "nonce_hash_H_Ni": h_curr.hex(),        # Public commitment of nonce
            "prev_hash": prev_hash,
            "block_hash": block_hash,
            "time_to_know_nonce": f"{elapsed_us:.2f} µs (INSTANT)"
        }
        self.blocks.append(block)
        return block


def simulate_attacker_brute_force(target_hash_hex: str, max_attempts: int = 100_000):
    """
    Simulate an outsider/attacker without the secret seed trying to guess 
    the valid 512-bit nonce that produces target_hash_hex.
    """
    print(f"\n[ATTACKER WITHOUT SEED] Attempting to brute-force 512-bit nonce for target hash:")
    print(f"Target H(N_i): {target_hash_hex[:32]}...")
    
    start_time = time.perf_counter()
    attempts = 0
    
    target_bytes = bytes.fromhex(target_hash_hex)
    
    for _ in range(max_attempts):
        attempts += 1
        guess = secrets.randbits(512)
        if sha512_int(guess) == target_bytes:
            print(f"SUCCESS after {attempts} attempts!")
            return True
            
    elapsed = time.perf_counter() - start_time
    print(f"FAILED after {attempts:,} attempts ({elapsed:.3f}s).")
    print(f"Estimated time to guess 2^512 nonces without seed: ~10^138 universe lifetimes!\n")
    return False


def run_demo():
    print("=" * 80)
    print("BLOCKCHAIN DEMO: INSTANT NONCE KNOWLEDGE VIA SECRET SEED")
    print("=" * 80 + "\n")
    
    # 1. Generate 512-bit Secret Seed (Private Key)
    seed = secrets.randbits(512)
    print("1. MASTER SECRET SEED (Held ONLY by signature owner):")
    print(f"{hex(seed)}\n")
    
    # 2. Initialize Blockchain
    chain = SeedBlockchain(secret_seed=seed)
    
    print("-" * 80)
    print("2. SEED HOLDER MINTS BLOCKS (Zero Computational Delay)")
    print("-" * 80)
    
    transactions = [
        "Genesis Block - Identity Registration",
        "Block #1: Transfer 100 Tokens to Alice",
        "Block #2: Execute Smart Contract #4092"
    ]
    
    for i, tx_data in enumerate(transactions):
        block = chain.mint_block(block_index=i, data=tx_data)
        print(f"Block #{block['index']}: '{block['data']}'")
        print(f"  Winning Nonce N_{i} (512-bit Hex):")
        print(f"    {block['nonce_N_i'][:40]}...")
        print(f"  Nonce Commitment H(N_{i}):")
        print(f"    {block['nonce_hash_H_Ni'][:40]}...")
        print(f"  Block Hash:")
        print(f"    {block['block_hash'][:40]}...")
        print(f"  Time taken by Seed Holder: {block['time_to_know_nonce']}\n")
        
    print("-" * 80)
    print("3. COMPARISON: OUTSIDER / NETWORK VALIDATOR WITHOUT SEED")
    print("-" * 80)
    
    # Try to guess Block #1's nonce without the seed
    target_block = chain.blocks[1]
    simulate_attacker_brute_force(target_block["nonce_hash_H_Ni"], max_attempts=100_000)


if __name__ == "__main__":
    run_demo()

"""
Blockchain Nonce Determinism & 2-Level Pre-Image Revelation Scheme via 512-Bit Master Seed.

Security Model:
- Raw PRNG numbers (N_k) are NEVER revealed publicly!
- Level 1 Hash: H1(N_k) = SHA-512(N_k)
  Revealed in Block k+1 as `previous_nonce` (a hash!).
- Level 2 Hash: H2(N_k) = SHA-512(H1(N_k))
  Committed in Block k as `nonce_hash`.
- Block Hash: block_hash = SHA-512(current_data + nonce_hash)

Verification of Block k+1 against Block k:
  SHA-512(Block_{k+1}.previous_nonce) == Block_k.nonce_hash
  i.e. SHA-512( H1(N_k) ) == H2(N_k)
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


def prng_level1_hash(prng_number: int) -> str:
    """Level 1 Hash: H1(N_k) = SHA-512(N_k). Revealed in next block."""
    return sha512_int(prng_number).hex()


def prng_level2_hash(level1_hex: str) -> str:
    """Level 2 Hash: H2(N_k) = SHA-512(H1(N_k)). Committed in current block as nonce_hash."""
    return sha512_bytes(level1_hex.encode('utf-8')).hex()


def save_block_to_txt(block: dict, filepath: str):
    """Save a block dictionary into a clean, human-readable & easily parsable .txt file."""
    lines = [
        "================================================================================",
        f"BLOCK_INDEX        : {block['index']}",
        f"DATA               : {block['data']}",
        f"NONCE_HASH         : {block['nonce_hash']}",
        f"BLOCK_HASH         : {block['block_hash']}",
        f"PREVIOUS_NONCE     : {block['previous_nonce']}",
        f"TIME_TO_KNOW_NONCE : {block['time_to_know_nonce']}",
        "================================================================================"
    ]
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def parse_block_txt(filepath: str) -> dict:
    """Parse a block data .txt file into a Python dictionary."""
    block = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("="):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                if key == "block_index":
                    block["index"] = int(val)
                elif key == "data":
                    block["data"] = val
                elif key == "nonce_hash" or key == "nonce_hash_h_ni":
                    block["nonce_hash"] = val
                elif key == "block_hash":
                    block["block_hash"] = val
                elif key == "previous_nonce" or key == "prev_nonce":
                    block["previous_nonce"] = val
                elif key == "time_to_know_nonce":
                    block["time_to_know_nonce"] = val
    return block

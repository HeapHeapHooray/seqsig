"""
Blockchain Nonce Determinism & Pre-Image Revelation Scheme via 512-Bit Master Seed.

Concept:
- For Block k:
  - Publishes `nonce_hash`: H(N_k), committing to secret nonce N_k for the current block.
  - Publishes `prev_nonce`: N_{k-1}, revealing the secret pre-image nonce of the PREVIOUS block!
- Anyone can verify SHA-512(prev_nonce) == previous_block.nonce_hash to confirm the creator 
  possessed the secret seed that generated the previous commitment.
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


def save_block_to_txt(block: dict, filepath: str):
    """Save a block dictionary into a clean, human-readable & easily parsable .txt file."""
    lines = [
        "================================================================================",
        f"BLOCK_INDEX        : {block['index']}",
        f"DATA               : {block['data']}",
        f"PREV_NONCE         : {block['prev_nonce']}",
        f"PREV_NONCE_HASH    : {block['prev_nonce_hash']}",
        f"NONCE_HASH         : {block['nonce_hash']}",
        f"BLOCK_HASH         : {block['block_hash']}",
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
                elif key == "prev_nonce":
                    block["prev_nonce"] = val
                elif key == "prev_nonce_hash":
                    block["prev_nonce_hash"] = val
                elif key == "nonce_hash" or key == "nonce_hash_h_ni":
                    block["nonce_hash"] = val
                elif key == "block_hash":
                    block["block_hash"] = val
                elif key == "time_to_know_nonce":
                    block["time_to_know_nonce"] = val
    return block

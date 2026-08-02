"""
Single-Hash Deterministic Blockchain Identity Scheme.

Model:
- PRNG number N_k is PRIVATE.
- Single Hash: nonce_hash = SHA-512(N_k)
- block_hash = SHA-512(current_data + nonce_hash)
- `nonce_hash` is NOT written in Block k! It only appears in Block k+1 as `previous_nonce`.
- Block k contains only: index, data, previous_nonce, block_hash.
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


def compute_nonce_hash(prng_number: int) -> str:
    """Single hash: SHA-512(N_k)."""
    return sha512_int(prng_number).hex()


def compute_block_hash(data: str, nonce_hash: str) -> str:
    """block_hash = SHA-512(current_data + nonce_hash)"""
    return sha512_bytes((data + nonce_hash).encode('utf-8')).hex()


def save_block_to_txt(block: dict, filepath: str):
    """Save a block dictionary into a clean, human-readable & easily parsable .txt file."""
    lines = [
        "================================================================================",
        f"BLOCK_INDEX        : {block['index']}",
        f"DATA               : {block['data']}",
        f"PREVIOUS_NONCE     : {block['previous_nonce']}",
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
                elif key == "previous_nonce" or key == "prev_nonce":
                    block["previous_nonce"] = val
                elif key == "block_hash":
                    block["block_hash"] = val
                elif key == "time_to_know_nonce":
                    block["time_to_know_nonce"] = val
    return block

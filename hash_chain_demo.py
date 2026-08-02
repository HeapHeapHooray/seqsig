"""
Sequential 512-bit PRNG Hash Chain Script.

For each step:
1. Generates 512-bit pseudo-random numbers N_i and N_{i+1} using a 512-bit seed.
2. Computes SHA-512 hash of N_i -> H(N_i).
3. Computes SHA-512 hash of N_{i+1} -> H(N_{i+1}).
4. Computes SHA-512 hash of the concatenated pair H(N_i) + H(N_{i+1}) -> H(H(N_i) || H(N_{i+1})).
5. Displays formatted output for each step.
"""

import hashlib
import secrets
from prng512 import CryptoPRNG512, FastPRNG512


def sha512_int(val: int) -> bytes:
    """Compute SHA-512 hash of a 512-bit integer."""
    val_bytes = val.to_bytes(64, byteorder='big')
    return hashlib.sha512(val_bytes).digest()


def sha512_bytes(data: bytes) -> bytes:
    """Compute SHA-512 hash of arbitrary byte data."""
    return hashlib.sha512(data).digest()


def run_hash_chain(seed_int: int, steps: int = 5, use_crypto: bool = True):
    print("=" * 80)
    prng_type = "CryptoPRNG512 (SHAKE-256)" if use_crypto else "FastPRNG512 (xoshiro512**)"
    print(f"512-BIT HASH CHAIN DEMO - Engine: {prng_type}")
    print(f"Seed (512-bit int):\n{hex(seed_int)}")
    print("=" * 80 + "\n")

    # Initialize PRNG
    prng = CryptoPRNG512(seed_int) if use_crypto else FastPRNG512(seed_int)

    # Generate sequence of 512-bit numbers for the requested steps (+1 extra for the last pair)
    numbers = [prng.next_int() for _ in range(steps + 1)]
    hashes = [sha512_int(n) for n in numbers]

    for i in range(steps):
        n_curr = numbers[i]
        n_next = numbers[i + 1]

        h_curr = hashes[i]
        h_next = hashes[i + 1]

        # Combine H(N_i) and H(N_{i+1}) and hash them together
        h_pair = sha512_bytes((str(h_curr) + str(h_next)).encode())

        print(f"--- STEP {i + 1} ---")
        print(f"Number N_{i+1} (512-bit hex):")
        print(f"  {hex(n_curr)}")
        print(f"SHA-512(N_{i+1}) [H(N_{i+1})]:")
        print(f"  {h_curr.hex()}")
        print(f"SHA-512(N_{i+2}) [H(N_{i+2})]:")
        print(f"  {h_next.hex()}")
        print(f"Combined Hash [SHA-512( H(N_{i+1}) || H(N_{i+2}) )]:")
        print(f"  {h_pair.hex()}\n")


if __name__ == "__main__":
    # Generate random 512-bit seed
    seed = secrets.randbits(512)
    
    # Run 4 steps of the hash chain
    run_hash_chain(seed_int=seed, steps=4, use_crypto=True)

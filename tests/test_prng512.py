#!/usr/bin/env python3
"""
Unit tests for 512-bit PRNG cryptographic engines.
"""

import sys
import os

src_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from sequential_signature.prng512 import CryptoPRNG512, FastPRNG512, Random512


def test_crypto_prng():
    seed = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
    prng1 = CryptoPRNG512(seed)
    prng2 = CryptoPRNG512(seed)
    
    val1_a = prng1.next_int()
    val1_b = prng1.next_int()
    
    val2_a = prng2.next_int()
    val2_b = prng2.next_int()
    
    assert val1_a == val2_a
    assert val1_b == val2_b
    assert val1_a != val1_b
    print("CryptoPRNG512 determinism & uniqueness test passed! ✅")


def test_fast_prng():
    seed = 0xFEEDFACEDEADBEEFFEEDFACEDEADBEEFFEEDFACEDEADBEEFFEEDFACEDEADBEEFFEEDFACEDEADBEEFFEEDFACEDEADBEEFFEEDFACEDEADBEEFFEEDFACEDEADBEEF
    prng1 = FastPRNG512(seed)
    prng2 = FastPRNG512(seed)
    
    assert prng1.next_int() == prng2.next_int()
    assert prng1.next_int() == prng2.next_int()
    print("FastPRNG512 determinism test passed! ✅")


def test_random_adapter():
    seed = 0x99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
    rnd = Random512(seed)
    num = rnd.randint(1, 100)
    assert 1 <= num <= 100
    print("Random512 adapter test passed! ✅")


if __name__ == "__main__":
    test_crypto_prng()
    test_fast_prng()
    test_random_adapter()
    print("\nAll unit tests passed successfully! ✅")

"""
512-bit Pseudo-Random Number Generators in Python.

Provides three implementations:
1. `CryptoPRNG512`: Cryptographically secure 512-bit PRNG based on SHAKE-256 (XOF)
   with key ratcheting for forward secrecy.
2. `FastPRNG512`: High-speed 512-bit PRNG based on the Xoshiro512** algorithm.
3. `Random512`: Subclass of Python's standard `random.Random` utilizing a 512-bit seed.
"""

import hashlib
import random
import secrets


class CryptoPRNG512:
    """
    Cryptographically secure 512-bit Pseudo-Random Number Generator.
    
    Uses SHAKE-256 extendable-output function with key ratcheting.
    - Seed: 512-bit integer (0 <= seed < 2^512)
    - Output: 512-bit integer (0 <= output < 2^512)
    """
    
    def __init__(self, seed: int):
        if not isinstance(seed, int):
            raise TypeError("Seed must be an integer.")
        if not (0 <= seed < (1 << 512)):
            raise ValueError("Seed must be a 512-bit unsigned integer (0 <= seed < 2^512).")
            
        self._state = seed.to_bytes(64, byteorder='big')
        self._counter = 0

    def next_bytes(self) -> bytes:
        """Generate 64 random bytes (512 bits) and ratchet internal state."""
        # Derive output block
        ctx_out = hashlib.shake_256(self._state + b"\x00" + self._counter.to_bytes(8, 'big'))
        output_bytes = ctx_out.digest(64)
        
        # Ratchet state forward for forward secrecy
        ctx_state = hashlib.shake_256(self._state + b"\x01" + self._counter.to_bytes(8, 'big'))
        self._state = ctx_state.digest(64)
        
        self._counter += 1
        return output_bytes

    def next_int(self) -> int:
        """Generate next 512-bit random integer."""
        return int.from_bytes(self.next_bytes(), byteorder='big')

    def __iter__(self):
        return self

    def __next__(self) -> int:
        return self.next_int()


class FastPRNG512:
    """
    Fast 512-bit PRNG based on xoshiro512** (8 x 64-bit state words).
    
    - Seed: 512-bit integer (0 <= seed < 2^512)
    - Output: 512-bit integer (0 <= output < 2^512)
    - Period: 2^512 - 1
    """
    
    MASK64 = (1 << 64) - 1

    def __init__(self, seed: int):
        if not isinstance(seed, int):
            raise TypeError("Seed must be an integer.")
        if not (0 <= seed < (1 << 512)):
            raise ValueError("Seed must be a 512-bit unsigned integer (0 <= seed < 2^512).")

        # Extract 8 64-bit words from 512-bit seed
        self.s = [(seed >> (64 * i)) & self.MASK64 for i in range(8)]
        
        # If all state words are 0, use SplitMix64 initialization to avoid zero state
        if all(x == 0 for x in self.s):
            self.s = self._splitmix64_init(seed)

    @staticmethod
    def _rotl(x: int, k: int) -> int:
        return ((x << k) & FastPRNG512.MASK64) | (x >> (64 - k))

    def _splitmix64_init(self, seed_val: int) -> list[int]:
        state = seed_val & self.MASK64
        words = []
        for _ in range(8):
            state = (state + 0x9E3779B97F4A7C15) & self.MASK64
            z = state
            z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & self.MASK64
            z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & self.MASK64
            words.append(z ^ (z >> 31))
        return words

    def _next64(self) -> int:
        """xoshiro512** generator step returning one 64-bit word."""
        res = (self._rotl((self.s[1] * 5) & self.MASK64, 7) * 9) & self.MASK64
        
        t = (self.s[1] << 11) & self.MASK64

        self.s[2] ^= self.s[0]
        self.s[5] ^= self.s[1]
        self.s[1] ^= self.s[7]
        self.s[7] ^= self.s[3]
        self.s[3] ^= self.s[4]
        self.s[4] ^= self.s[6]
        self.s[0] ^= self.s[2]
        self.s[6] ^= self.s[5]

        self.s[6] ^= t
        self.s[7] = self._rotl(self.s[7], 21)

        return res

    def next_int(self) -> int:
        """Generate next 512-bit random integer by combining eight 64-bit outputs."""
        val = 0
        for i in range(8):
            val |= (self._next64() << (64 * i))
        return val

    def __iter__(self):
        return self

    def __next__(self) -> int:
        return self.next_int()


class Random512(random.Random):
    """
    Adapter subclassing Python's standard `random.Random`.
    
    Allows standard Python random functions (`randint`, `choice`, `shuffle`, etc.)
    to operate on top of a 512-bit PRNG engine.
    """
    
    def __init__(self, seed: int, use_crypto: bool = True):
        self._use_crypto = use_crypto
        self._prng = CryptoPRNG512(seed) if use_crypto else FastPRNG512(seed)
        super().__init__(seed)

    def seed(self, a=None, version=2):
        if a is None:
            a = secrets.randbits(512)
        elif not isinstance(a, int):
            a = int.from_bytes(hashlib.sha512(str(a).encode()).digest(), 'big')
        seed_val = a % (1 << 512)
        self._prng = CryptoPRNG512(seed_val) if getattr(self, '_use_crypto', True) else FastPRNG512(seed_val)

    def getrandbits(self, k: int) -> int:
        """Generate integer with k random bits."""
        if k <= 0:
            raise ValueError("number of bits must be > 0")
        res = 0
        bits_fetched = 0
        while bits_fetched < k:
            block = self._prng.next_int()
            res = (res << 512) | block
            bits_fetched += 512
        return res >> (bits_fetched - k)

    def random(self) -> float:
        """Generate random float in [0.0, 1.0) with 53 bits of precision."""
        return self.getrandbits(53) / (1 << 53)


if __name__ == "__main__":
    # Example 512-bit seed
    seed = secrets.randbits(512)
    print(f"Seed (512-bit int):\n{hex(seed)}\n")

    print("--- Cryptographic PRNG (CryptoPRNG512) ---")
    crypto_gen = CryptoPRNG512(seed)
    for i in range(2):
        val = crypto_gen.next_int()
        print(f"Sample {i+1} ({val.bit_length()} bits):\n{hex(val)}")

    print("\n--- Fast PRNG (FastPRNG512 - xoshiro512**) ---")
    fast_gen = FastPRNG512(seed)
    for i in range(2):
        val = fast_gen.next_int()
        print(f"Sample {i+1} ({val.bit_length()} bits):\n{hex(val)}")

    print("\n--- Python random.Random Adapter (Random512) ---")
    rnd = Random512(seed)
    print(f"Random 512-bit int : {hex(rnd.getrandbits(512))}")
    print(f"Random choice [1..10]: {rnd.choice(list(range(1, 11)))}")
    print(f"Random float [0, 1)  : {rnd.random()}")

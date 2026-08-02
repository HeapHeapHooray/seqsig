import unittest
import secrets
import random
from prng512 import CryptoPRNG512, FastPRNG512, Random512

class TestPRNG512(unittest.TestCase):
    def setUp(self):
        self.seed = secrets.randbits(512)

    def test_seed_validation(self):
        with self.assertRaises(ValueError):
            CryptoPRNG512(-1)
        with self.assertRaises(ValueError):
            CryptoPRNG512(1 << 512)
        with self.assertRaises(TypeError):
            CryptoPRNG512("invalid_seed")

        with self.assertRaises(ValueError):
            FastPRNG512(-1)
        with self.assertRaises(ValueError):
            FastPRNG512(1 << 512)
        with self.assertRaises(TypeError):
            FastPRNG512(12.34)

    def test_crypto_prng_determinism(self):
        gen1 = CryptoPRNG512(self.seed)
        gen2 = CryptoPRNG512(self.seed)
        for _ in range(10):
            self.assertEqual(gen1.next_int(), gen2.next_int())

    def test_fast_prng_determinism(self):
        gen1 = FastPRNG512(self.seed)
        gen2 = FastPRNG512(self.seed)
        for _ in range(10):
            self.assertEqual(gen1.next_int(), gen2.next_int())

    def test_zero_seed(self):
        crypto_gen = CryptoPRNG512(0)
        fast_gen = FastPRNG512(0)
        
        c_val = crypto_gen.next_int()
        f_val = fast_gen.next_int()
        
        self.assertTrue(0 <= c_val < (1 << 512))
        self.assertTrue(0 <= f_val < (1 << 512))

    def test_output_bounds(self):
        crypto_gen = CryptoPRNG512(self.seed)
        fast_gen = FastPRNG512(self.seed)
        
        for _ in range(100):
            c_val = crypto_gen.next_int()
            f_val = fast_gen.next_int()
            self.assertTrue(0 <= c_val < (1 << 512))
            self.assertTrue(0 <= f_val < (1 << 512))

    def test_iteration(self):
        crypto_gen = CryptoPRNG512(self.seed)
        fast_gen = FastPRNG512(self.seed)
        
        c_vals = [next(crypto_gen) for _ in range(5)]
        f_vals = [next(fast_gen) for _ in range(5)]
        
        self.assertEqual(len(c_vals), 5)
        self.assertEqual(len(f_vals), 5)

    def test_random512_adapter(self):
        rnd = Random512(self.seed)
        
        # Test 512-bit output
        val = rnd.getrandbits(512)
        self.assertTrue(0 <= val < (1 << 512))
        
        # Test random float
        flt = rnd.random()
        self.assertTrue(0.0 <= flt < 1.0)
        
        # Test choice
        chosen = rnd.choice(['a', 'b', 'c'])
        self.assertIn(chosen, ['a', 'b', 'c'])

if __name__ == "__main__":
    unittest.main()

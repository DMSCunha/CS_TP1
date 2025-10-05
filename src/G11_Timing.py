import unittest
import time
from G11_DSA import get_DSAparameters, get_skeys
from G11_Attacks import get_private_key


class TestBruteForceTiming(unittest.TestCase):
    """
    Brute-force Discrete Logarithm Attack Timing Analysis

    This test measures the time required to recover the DSA private key x from the public key y
    using a brute-force search for various key sizes (n). The results demonstrate the exponential
    growth in computation time as the key size increases, illustrating the impracticality of brute-force
    attacks for realistic key sizes.

    Test environment:
    - CPU: Intel Core i7-1185G7 (4 cores, 8 threads, up to 4.8 GHz)
    - RAM: 32GB

    Observed timings:
        n=4 bits:    ~0.0006 seconds
        n=8 bits:    ~0.0003 seconds (probably just lucky)
        n=16 bits:   ~0.0609 seconds
        n=20 bits:   ~0.5116 seconds
        n=25 bits:   ~5.1821 seconds
        n=30 bits:   ~8452.8021 seconds (140 minutes, over 2 hours)

    As shown, the time required increases rapidly with key size, confirming the exponential complexity
    of the discrete logarithm problem and the security of DSA against brute-force attacks for large enough keys.
    """

    def test_brute_force_timing(self):
        key_sizes = [4, 8, 16, 20, 25, 30]
        times = []
        for n in key_sizes:
            p, q, g = get_DSAparameters(n)
            x, y = get_skeys(p, q, g)
            start = time.time()
            x_found = get_private_key(y, g, p)
            elapsed = time.time() - start
            times.append((n, elapsed))
            self.assertEqual(x, x_found)
            print(f"[DEBUG] Brute-force for n={n} bits: {elapsed:.4f} seconds")


if __name__ == '__main__':
    unittest.main()

import unittest
#----------------------
from src.G11_DSA import *
from src.G11_Attacks import *


class TestCases(unittest.TestCase):

    # helper tests
    def test_get_DSAparamenters(self):
        n = 8
        p, q, g = get_DSAparamenters(n)
        self.assertTrue(p > q > 1)
        self.assertTrue((p - 1) % q == 0)
        self.assertTrue(1 < g < p)
        self.assertTrue(g != 1)

    def test_get_skeys(self):
        n = 8
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        self.assertTrue(1 <= x < q)
        self.assertTrue(1 <= y < p)

    def test_get_private_key(self):
        n = 8
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        x_found = get_private_key_brute_force(y, g, p)
        self.assertEqual(x, x_found)


    # brute force tests
    def test_get_private_keys(self):
        
        message_size = 10
        
        (p, q, g) = get_DSAparamenters(message_size)
        
        (x, y) = get_skeys(p, q, g)
        
        x_discovered = get_private_key_brute_force(y, g, p)
        
        self.assertEqual(x, x_discovered, f"Message not discovered x={x} and x_discovered={x_discovered}")

    def test_brute_force_key_recovery_various_sizes(self):
        for n in [4, 8, 12]:
            p, q, g = get_DSAparamenters(n)
            x, y = get_skeys(p, q, g)
            x_found = get_private_key_brute_force(y, g, p)
            self.assertEqual(x, x_found)

    # dsa tests
    def test_dsa_sign_and_verify(self):
        n = 8
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        message = 42
        signature = dsa_sign(message, p, q, g, x)
        self.assertIsInstance(signature, tuple)
        self.assertEqual(len(signature), 2)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))
        # Negative test: wrong message
        self.assertFalse(dsa_verify(message + 1, signature, p, q, g, y))

    def test_dsa_with_small_key(self):
        n = 4
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        message = 7
        signature = dsa_sign(message, p, q, g, x)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))

    def test_dsa_with_medium_key(self):
        n = 16
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        message = 123
        signature = dsa_sign(message, p, q, g, x)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))

    def test_dsa_with_larger_key(self):
        n = 64
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        message = 999
        signature = dsa_sign(message, p, q, g, x)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))

    # negative tests
    def test_invalid_signature(self):
        n = 8
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        message = 42
        signature = dsa_sign(message, p, q, g, x)
        # affect signature
        bad_signature = (signature[0], (signature[1] + 1) % q)
        self.assertFalse(dsa_verify(message, bad_signature, p, q, g, y))

    def test_signature_with_boundary_values(self):
        n = 8
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        # r or s = 0 should fail
        self.assertFalse(dsa_verify(1, (0, 1), p, q, g, y))
        self.assertFalse(dsa_verify(1, (1, 0), p, q, g, y))
        # r or s >= q should fail
        self.assertFalse(dsa_verify(1, (q, 1), p, q, g, y))
        self.assertFalse(dsa_verify(1, (1, q), p, q, g, y))

    # rigged k attack tests
    def attack_recover_x(self, n, m1, m2):
        p, q, g = get_DSAparamenters(n)
        x, y = get_skeys(p, q, g)
        # Sign two different messages with the same k
        sig1 = dsa_sign_k_rigged(m1, p, q, g, x)
        sig2 = dsa_sign_k_rigged(m2, p, q, g, x)
        # Both signatures must have the same r
        self.assertEqual(sig1[0], sig2[0])
        # Recover x
        x_recovered = get_private_key_k_rigged(sig1, sig2, q, m1, m2)
        self.assertEqual(x, x_recovered)

    def test_attack_small_key(self):
        self.attack_recover_x(8, 42, 99)

    def test_attack_medium_key(self):
        self.attack_recover_x(12, 123, 456)

    def test_attack_large_key(self):
        self.attack_recover_x(16, 789, 321)

    def test_attack_various_messages(self):
        for m1, m2 in [(1, 2), (100, 200), (555, 777)]:
            self.attack_recover_x(8, m1, m2)

    def test_attack_various_key_sizes(self):
        for n in [4, 8, 16, 32, 99]:
            self.attack_recover_x(n, 11, 22)

if __name__ == '__main__':
    unittest.main()

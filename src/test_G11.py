#
#   Modulo de testes dos metodos desenvolvidos
#

import unittest
import time

#----------------------
from G11_DSA import *
from G11_Attacks import *

#----------------------
class TestCases(unittest.TestCase):

    # helper tests
    def test_get_DSAparameters(self):
        """
        Os objetivos deste teste são verificar que:
        - q é um número entre 1 e p
        - (p - 1) é multiplo de q
        - g é:
            - diferente de 1
            - um número entre 1 e p
        """
        print("------TEST CASE: get_DSAparemeters")
        n = 8
        p, q, g = get_DSAparameters(n)
        print(f"[DEBUG] Generated p = {p}")
        print(f"[DEBUG] Generated q = {q}")
        print(f"[DEBUG] Generated g = {g}")
        self.assertTrue(p > q > 1)
        self.assertTrue((p - 1) % q == 0)
        self.assertTrue(1 < g < p)
        self.assertTrue(g != 1)
        
        print("------TEST CASE FINISHED\n")

    def test_get_skeys(self):
        """
        Os objetivos deste teste são verificar que:
        - a chave privada da sessão x é um número inteiro entre 1 e q-1
        - a chave pública é um número inteiro entre entre 1 e p
        """
        print("------TEST CASE: get_skeys")
        n = 8
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        print(f"[DEBUG] Randomize private session key x = {x}")
        print(f"[DEBUG] Generated public session key y = {y}")
        self.assertTrue(1 < x < q - 1)
        self.assertTrue(1 < y < p)
        
        print("------TEST CASE FINISHED\n")

    # brute force tests
    def test_get_private_keys_nominal(self):
        """
        O objetivo deste teste é verificar que o método de ataque por força bruta consegue descobrir o valor da chave privada da sessão (x)
        """
        print("------TEST CASE: get_private_keys")
        
        start_time = time.perf_counter()
        
        n = 8
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)        
        x_discovered = get_private_key(y, g, p)

        end_time = time.perf_counter()
        print(f"[DEBUG] Randomize private session key x = {x}")
        print(f"[DEBUG] Private session key x found = {x_discovered}")
        
        self.assertEqual(x, x_discovered, f"Message not discovered x={x} and x_discovered={x_discovered}")
        print(f"[DEBUG] It took {end_time - start_time:.8f} seconds to find the private key session")
        
        print("------TEST CASE FINISHED\n")

    def test_brute_force_key_recovery_various_sizes(self):
        print("------TEST CASE: brute_force_key_recovery_various_sizes")
        
        for n in [4, 10, 12]:
            p, q, g = get_DSAparameters(n)
            x, y = get_skeys(p, q, g)
            x_found = get_private_key(y, g, p)
            self.assertEqual(x, x_found)

        print("------TEST CASE FINISHED\n")

    # dsa tests
    def test_dsa_sign_and_verify(self):
        print("------TEST CASE: get_private_keys")
        
        n = 8
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        message = 42
        signature = dsa_sign(message, p, q, g, x)
        print(f"[DEBUG] Generated r = {signature[0]}")
        print(f"[DEBUG] Generated s = {signature[1]}")
        self.assertIsInstance(signature, tuple)
        self.assertEqual(len(signature), 2)
        
        v = dsa_verify(message, signature, p, q, g, y)
        print(f"[DEBUG] Computed v = {v}")
        self.assertTrue(v)
        # Negative test: wrong message
        v = dsa_verify(message + 1, signature, p, q, g, y)
        print(f"[DEBUG] Computed v = {v}")
        self.assertFalse(v)
        
        print("------TEST CASE FINISHED\n")

    def test_dsa_with_small_key(self):
        print("------TEST CASE: dsa_with_small_key")
        n = 4
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        message = 7
        signature = dsa_sign(message, p, q, g, x)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))
        
        print("------TEST CASE FINISHED\n")

    def test_dsa_with_medium_key(self):
        print("------TEST CASE: dsa_with_medium_key")
        
        n = 16
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        message = 123
        signature = dsa_sign(message, p, q, g, x)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))
        
        print("------TEST CASE FINISHED\n")

    def test_dsa_with_larger_key(self):
        print("------TEST CASE: dsa_with_larger_key")
        
        n = 64
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        message = 999
        signature = dsa_sign(message, p, q, g, x)
        self.assertTrue(dsa_verify(message, signature, p, q, g, y))
        
        print("------TEST CASE FINISHED\n")

    # negative tests
    def test_invalid_signature(self):
        print("------TEST CASE: invalid_signature")
        
        n = 8
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        message = 42
        signature = dsa_sign(message, p, q, g, x)
        # affect signature
        bad_signature = (signature[0], (signature[1] + 1) % q)
        self.assertFalse(dsa_verify(message, bad_signature, p, q, g, y))
        
        print("------TEST CASE FINISHED\n")

    def test_signature_with_boundary_values(self):
        print("------TEST CASE: signature_with_boundary_values")
        
        n = 8
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        # r or s = 0 should fail
        self.assertFalse(dsa_verify(1, (0, 1), p, q, g, y))
        self.assertFalse(dsa_verify(1, (1, 0), p, q, g, y))
        # r or s >= q should fail
        self.assertFalse(dsa_verify(1, (q, 1), p, q, g, y))
        self.assertFalse(dsa_verify(1, (1, q), p, q, g, y))
        
        print("------TEST CASE FINISHED\n")

    # rigged k attack tests
    def attack_recover_x(self, n, m1, m2, debug_flag = True):
        p, q, g = get_DSAparameters(n)
        x, y = get_skeys(p, q, g)
        # Sign two different messages with the same k
        sig1 = dsa_sign_k_rigged(m1, p, q, g, x)
        if debug_flag:
            print(f"[DEBUG] Generated r = {sig1[0]}")
            print(f"[DEBUG] Generated s = {sig1[1]}")
        sig2 = dsa_sign_k_rigged(m2, p, q, g, x)
        if debug_flag:
            print(f"[DEBUG] Generated r = {sig2[0]}")
            print(f"[DEBUG] Generated s = {sig2[1]}")
        # Both signatures must have the same r
        self.assertEqual(sig1[0], sig2[0])
        # Recover x
        x_recovered = get_private_key_k_rigged(sig1, sig2, q, m1, m2)
        self.assertEqual(x, x_recovered)

    def test_attack_small_key(self):
        print("------TEST CASE: attack_small_key")
        self.attack_recover_x(8, 42, 99)
        print("------TEST CASE FINISHED\n")

    def test_attack_medium_key(self):
        print("------TEST CASE: attack_medium_key")
        self.attack_recover_x(12, 123, 456)
        print("------TEST CASE FINISHED\n")

    def test_attack_large_key(self):
        print("------TEST CASE: attack_large_key")
        self.attack_recover_x(16, 789, 321)
        print("------TEST CASE FINISHED\n")

    def test_attack_various_messages(self):
        print("------TEST CASE: attack_various_key")
        
        for m1, m2 in [(1, 2), (100, 200), (555, 777)]:
            self.attack_recover_x(8, m1, m2, False)
            
        print("------TEST CASE FINISHED\n")

    def test_attack_various_key_sizes(self):
        print("------TEST CASE: attack_various_key_sizes")
        
        for n in [4, 8, 16, 32, 99]:
            self.attack_recover_x(n, 11, 22, False)
        
        print("------TEST CASE FINISHED\n")

if __name__ == '__main__':
    unittest.main()

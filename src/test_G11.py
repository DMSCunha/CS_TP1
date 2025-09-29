import unittest
#----------------------
from G11_DSA import *
from G11_H import *


class TestCases(unittest.TestCase):
    def test_get_private_keys(self):
        
        message_size = 10
        
        p, q, g = get_DSAparamenters(message_size)
        
        x, y = get_skeys(p, q, g)
        
        x_discovered = get_private_key(y, g, p)
        
        self.assertEqual(x, x_discovered, f"Message not discovered x={x} and x_discovered={x_discovered}")

if __name__ == '__main__':
    unittest.main()

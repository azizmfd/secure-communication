import unittest

from algorithms.asymmetric import dh, rsa


class TestDH(unittest.TestCase):
    def test_parameters(self):
        self.assertEqual(dh.P.bit_length(), 1024)
        self.assertTrue(rsa.is_prime(dh.P))
        self.assertTrue(rsa.is_prime(dh.Q))   # p est un nombre premier "sûr"
        self.assertEqual(pow(dh.G, dh.Q, dh.P), 1)

    def test_both_sides_get_same_secret(self):
        a = dh.generate_private()
        b = dh.generate_private()
        A = dh.public_value(a)
        B = dh.public_value(b)
        self.assertEqual(dh.shared_secret(a, B), dh.shared_secret(b, A))

    def test_different_each_time(self):
        self.assertNotEqual(dh.generate_private(), dh.generate_private())

    def test_invalid_public_values(self):
        a = dh.generate_private()
        for bad in (0, 1, dh.P - 1, dh.P, dh.P + 5):
            with self.assertRaises(ValueError):
                dh.shared_secret(a, bad)
        # un nombre qui n'est pas dans le bon sous-groupe est refusé aussi
        outsider = next(v for v in range(3, 100) if pow(v, dh.Q, dh.P) != 1)
        with self.assertRaises(ValueError):
            dh.shared_secret(a, outsider)

    def test_derive_key(self):
        s = dh.shared_secret(dh.generate_private(), dh.public_value(dh.generate_private()))
        self.assertEqual(len(dh.derive_key(s, 16)), 16)
        self.assertEqual(len(dh.derive_key(s, 32)), 32)
        self.assertEqual(dh.derive_key(s, 32), dh.derive_key(s, 32))
        self.assertNotEqual(dh.derive_key(s, 32), dh.derive_key(s + 1, 32))
        with self.assertRaises(ValueError):
            dh.derive_key(s, 20)


if __name__ == "__main__":
    unittest.main()

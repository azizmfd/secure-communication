import os
import tempfile
import unittest

from algorithms.asymmetric import rsa


class TestPrimes(unittest.TestCase):
    def test_is_prime(self):
        for p in (2, 3, 97, 7919, 1000000007):
            self.assertTrue(rsa.is_prime(p), p)
        # 561 = 3*11*17 est un nombre de Carmichael : il trompe des tests naïfs
        for c in (0, 1, 4, 91, 561, 1000000007 * 3):
            self.assertFalse(rsa.is_prime(c), c)

    def test_generate_prime(self):
        p = rsa.generate_prime(64)
        self.assertEqual(p.bit_length(), 64)
        self.assertTrue(rsa.is_prime(p))


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub, cls.priv = rsa.generate_keypair(512)
        cls.pub2, cls.priv2 = rsa.generate_keypair(512)

    def test_keypair(self):
        e, n = self.pub
        d, n2 = self.priv
        self.assertEqual(n, n2)
        self.assertEqual(n.bit_length(), 512)
        self.assertEqual(pow(pow(42, e, n), d, n), 42)

    def test_roundtrip(self):
        for msg in ("", "Bonjour Serveur", "ça va très bien ! 😀", "x" * 500):
            with self.subTest(msg=msg[:20]):
                cipher = rsa.encrypt(msg, self.pub)
                self.assertEqual(rsa.decrypt(cipher, self.priv), msg)

    def test_block_size_and_determinism(self):
        _, block_len = rsa._block_sizes(self.pub[1])
        cipher = rsa.encrypt("x" * 500, self.pub)
        self.assertEqual((len(cipher) // 2) % block_len, 0)
        # RSA "livre" sans padding : même message = même chiffré (faiblesse !)
        self.assertEqual(rsa.encrypt("abc", self.pub), rsa.encrypt("abc", self.pub))

    def test_wrong_private_key(self):
        cipher = rsa.encrypt("secret", self.pub)
        try:
            result = rsa.decrypt(cipher, self.priv2)
        except Exception:
            return  # une erreur est un bon résultat
        self.assertNotEqual(result, "secret")

    def test_sign_verify(self):
        sig = rsa.sign("Message authentique", self.priv)
        self.assertTrue(rsa.verify("Message authentique", sig, self.pub))
        self.assertFalse(rsa.verify("Message modifié", sig, self.pub))
        self.assertFalse(rsa.verify("Message authentique", sig, self.pub2))
        self.assertFalse(rsa.verify("Message authentique", "zz", self.pub))

    def test_sign_short_key(self):
        _, priv_short = rsa.generate_keypair(128)
        with self.assertRaises(ValueError):
            rsa.sign("Hello", priv_short)

    def test_key_files(self):
        self.assertEqual(rsa.key_from_str(rsa.key_to_str(self.pub)), self.pub)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pub.txt")
            rsa.save_key(path, self.pub)
            self.assertEqual(rsa.load_key(path), self.pub)


if __name__ == "__main__":
    unittest.main()

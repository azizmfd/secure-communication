import unittest
from algorithms.classical import hill


class TestHill(unittest.TestCase):
    def test_known_encrypt(self):
        self.assertEqual(hill.encrypt("HELP", "DDCF"), "HIAT")

    def test_known_decrypt(self):
        self.assertEqual(hill.decrypt("HIAT", "DDCF"), "HELP")

    def test_roundtrip(self):
        cipher = hill.encrypt("Bonjour Serveur", "DDCF")
        self.assertEqual(hill.decrypt(cipher, "DDCF"), "BONJOURSERVEUR")

    def test_odd_length(self):
        cipher = hill.encrypt("ABC", "DDCF")
        self.assertEqual(hill.decrypt(cipher, "DDCF"), "ABCX")

    def test_lowercase_key(self):
        self.assertEqual(hill.encrypt("HELP", "ddcf"), "HIAT")

    def test_invalid_keys(self):
        with self.assertRaises(ValueError):
            hill.encrypt("HELP", "AAAA")  # déterminant 0
        with self.assertRaises(ValueError):
            hill.encrypt("HELP", "CAAB")  # déterminant 2 (pair)
        with self.assertRaises(ValueError):
            hill.encrypt("HELP", "ABC")   # il faut 4 lettres


if __name__ == "__main__":
    unittest.main()

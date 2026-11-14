import unittest
from algorithms.classical import caesar


class TestCaesar(unittest.TestCase):
    def test_encrypt_simple(self):
        self.assertEqual(caesar.encrypt("ABC", 3), "DEF")

    def test_wraparound(self):
        self.assertEqual(caesar.encrypt("XYZ", 3), "ABC")

    def test_keeps_case_and_punctuation(self):
        self.assertEqual(caesar.encrypt("Hello, World!", 3), "Khoor, Zruog!")

    def test_roundtrip(self):
        msg = "Bonjour Serveur"
        self.assertEqual(caesar.decrypt(caesar.encrypt(msg, 7), 7), msg)


if __name__ == "__main__":
    unittest.main()

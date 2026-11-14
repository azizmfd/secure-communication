import unittest
from algorithms.classical import substitution

KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"


class TestSubstitution(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(substitution.encrypt("ABC", KEY), "QWE")
        self.assertEqual(substitution.encrypt("Hello", KEY), "Itssg")

    def test_roundtrip_random_key(self):
        key = substitution.generate_key()
        msg = "Bonjour Serveur, ça va ?"
        self.assertEqual(substitution.decrypt(substitution.encrypt(msg, key), key), msg)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            substitution.encrypt("ABC", "ABC")


if __name__ == "__main__":
    unittest.main()

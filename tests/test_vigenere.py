import unittest
from algorithms.classical import vigenere


class TestVigenere(unittest.TestCase):
    def test_known_value(self):
        # Exemple classique de Wikipédia
        self.assertEqual(vigenere.encrypt("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")

    def test_keeps_case_and_spaces(self):
        self.assertEqual(vigenere.encrypt("Attack at dawn", "LEMON"), "Lxfopv ef rnhr")

    def test_roundtrip(self):
        msg = "Bonjour Serveur, ça va ?"
        self.assertEqual(vigenere.decrypt(vigenere.encrypt(msg, "kali"), "kali"), msg)

    def test_key_a_changes_nothing(self):
        self.assertEqual(vigenere.encrypt("Hello", "A"), "Hello")

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            vigenere.encrypt("Hello", "123")


if __name__ == "__main__":
    unittest.main()

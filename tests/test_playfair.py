import unittest
from algorithms.classical import playfair


class TestPlayfair(unittest.TestCase):
    def test_matrix(self):
        matrix = playfair.build_matrix("PLAYFAIR EXAMPLE")
        self.assertEqual("".join("".join(row) for row in matrix),
                         "PLAYFIREXMBCDGHKNOQSTUVWZ")

    def test_known_encrypt(self):
        # Exemple classique de Wikipédia
        self.assertEqual(
            playfair.encrypt("hide the gold in the tree stump", "PLAYFAIR EXAMPLE"),
            "BMODZBXDNABEKUDMUIXMMOUVIF")

    def test_known_decrypt(self):
        self.assertEqual(
            playfair.decrypt("BMODZBXDNABEKUDMUIXMMOUVIF", "PLAYFAIR EXAMPLE"),
            "HIDETHEGOLDINTHETREXESTUMP")

    def test_double_letters(self):
        # BALLOON -> BA LX LO ON (un X est inséré entre les deux L)
        cipher = playfair.encrypt("Balloon", "KEY")
        self.assertEqual(playfair.decrypt(cipher, "KEY"), "BALXLOON")

    def test_odd_length(self):
        # ABC -> AB CX
        cipher = playfair.encrypt("ABC", "KEY")
        self.assertEqual(playfair.decrypt(cipher, "KEY"), "ABCX")

    def test_j_becomes_i(self):
        cipher = playfair.encrypt("JUMP", "KEY")
        self.assertEqual(playfair.decrypt(cipher, "KEY"), "IUMP")

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            playfair.encrypt("Hello", "123")


if __name__ == "__main__":
    unittest.main()

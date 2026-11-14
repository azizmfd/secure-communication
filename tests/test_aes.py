import unittest
from algorithms.symmetric import aes


class TestAES(unittest.TestCase):
    def test_roundtrip_all_modes_and_sizes(self):
        msg = "Bonjour Serveur, ça va ?"
        for bits in (128, 256):
            key = aes.generate_key(bits)
            for mode in ("ECB", "CBC", "CTR"):
                with self.subTest(bits=bits, mode=mode):
                    ct, iv = aes.encrypt(msg, key, mode)
                    self.assertEqual(aes.decrypt(ct, key, mode, iv), msg)

    def test_ecb_same_blocks_same_ciphertext(self):
        # 32 fois "A" = 2 blocs identiques : ECB les chiffre pareil (fuite !)
        key = aes.generate_key(128)
        ct, _ = aes.encrypt("A" * 32, key, "ECB")
        self.assertEqual(ct[:16], ct[16:32])

    def test_cbc_hides_patterns(self):
        key = aes.generate_key(128)
        ct, _ = aes.encrypt("A" * 32, key, "CBC")
        self.assertNotEqual(ct[:16], ct[16:32])

    def test_cbc_random_iv(self):
        key = aes.generate_key(128)
        ct1, iv1 = aes.encrypt("Bonjour", key, "CBC")
        ct2, iv2 = aes.encrypt("Bonjour", key, "CBC")
        self.assertNotEqual(iv1, iv2)
        self.assertNotEqual(ct1, ct2)

    def test_lengths(self):
        key = aes.generate_key(128)
        self.assertEqual(len(aes.encrypt("Bonjour", key, "ECB")[0]), 16)  # 7 octets + padding
        self.assertEqual(len(aes.encrypt("Bonjour", key, "CBC")[0]), 16)
        self.assertEqual(len(aes.encrypt("Bonjour", key, "CTR")[0]), 7)   # pas de padding

    def test_invalid_key_size(self):
        with self.assertRaises(ValueError):
            aes.encrypt("Hello", b"trop-court", "CBC")

    def test_invalid_mode(self):
        with self.assertRaises(ValueError):
            aes.encrypt("Hello", aes.generate_key(128), "XYZ")


if __name__ == "__main__":
    unittest.main()

import hashlib
import hmac
import unittest

from algorithms.hash import sha256, hmac_sha256


class TestSHA256(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(
            sha256.sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(
            sha256.sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(
            sha256.sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

    def test_matches_hashlib_all_lengths(self):
        # Les longueurs autour de 55, 56, 63, 64 testent le padding
        for n in range(0, 200):
            data = bytes(i % 251 for i in range(n))
            self.assertEqual(sha256.sha256(data), hashlib.sha256(data).digest(), n)

    def test_avalanche(self):
        # Changer 1 caractère change environ la moitié des 256 bits
        a = int(sha256.sha256_hex("abc"), 16)
        b = int(sha256.sha256_hex("abd"), 16)
        diff = bin(a ^ b).count("1")
        self.assertTrue(80 < diff < 176, diff)

    def test_output_length(self):
        self.assertEqual(len(sha256.sha256(b"x" * 1000)), 32)


class TestHMAC(unittest.TestCase):
    def test_rfc4231_case2(self):
        self.assertEqual(
            hmac_sha256.hmac_hex("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    def test_matches_stdlib_all_key_sizes(self):
        for key_len in (1, 10, 64, 65, 100):
            key = b"k" * key_len
            msg = b"Bonjour Serveur"
            self.assertEqual(hmac_sha256.hmac_sha256(key, msg),
                             hmac.new(key, msg, hashlib.sha256).digest(), key_len)

    def test_verify(self):
        tag = hmac_sha256.hmac_hex("secret", "message")
        self.assertTrue(hmac_sha256.verify("secret", "message", tag))
        self.assertFalse(hmac_sha256.verify("autre", "message", tag))
        self.assertFalse(hmac_sha256.verify("secret", "message modifié", tag))


if __name__ == "__main__":
    unittest.main()

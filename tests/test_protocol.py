import os
import tempfile
import unittest

from algorithms.asymmetric import dh, rsa
from network import protocol

MESSAGE = "Bonjour Serveur"


def normalize(text):
    """Playfair et Hill rendent des majuscules sans espaces (J devient I) : on compare à ça."""
    return "".join(c for c in text.upper().replace("J", "I") if "A" <= c <= "Z")


def roundtrip(algorithm, mode="CBC", **kwargs):
    key = protocol.default_key(algorithm)
    payload = protocol.make_payload(algorithm, key, MESSAGE, mode, **kwargs)
    return protocol.parse_message(payload)


class TestProtocol(unittest.TestCase):
    def test_classical_roundtrip(self):
        for algorithm in ("caesar", "substitution", "vigenere", "playfair", "hill"):
            with self.subTest(algorithm=algorithm):
                msg = roundtrip(algorithm)
                self.assertEqual(msg["algorithm"], algorithm)
                self.assertEqual(normalize(protocol.decrypt_message(msg)), normalize(MESSAGE))

    def test_aes_modes(self):
        for mode in ("ECB", "CBC", "CTR"):
            with self.subTest(mode=mode):
                msg = roundtrip("aes", mode)
                self.assertEqual(msg["mode"], mode)
                self.assertEqual(protocol.decrypt_message(msg), MESSAGE)

    def test_rsa_and_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            server_pub, server_priv = rsa.generate_keypair(512)
            client_pub, client_priv = rsa.generate_keypair(512)
            other_pub, _ = rsa.generate_keypair(512)
            server_pub_path = os.path.join(tmp, "server_pub.txt")
            client_priv_path = os.path.join(tmp, "client_priv.txt")
            rsa.save_key(server_pub_path, server_pub)
            rsa.save_key(client_priv_path, client_priv)

            payload = protocol.make_payload("rsa", server_pub_path, MESSAGE, sign_key=client_priv_path)
            msg = protocol.parse_message(payload)
            self.assertEqual(protocol.decrypt_message(msg, private_key=server_priv), MESSAGE)
            self.assertTrue(protocol.check_signature(msg, MESSAGE, client_pub))
            self.assertFalse(protocol.check_signature(msg, MESSAGE, other_pub))
            self.assertFalse(protocol.check_signature(msg, "Message modifié", client_pub))

    def test_rsa_needs_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            pub, _ = rsa.generate_keypair(512)
            path = os.path.join(tmp, "pub.txt")
            rsa.save_key(path, pub)
            msg = protocol.parse_message(protocol.make_payload("rsa", path, MESSAGE))
            with self.assertRaises(ValueError):
                protocol.decrypt_message(msg)

    def test_diffie_hellman_session(self):
        # Le client et le serveur calculent la même clé, qui n'apparaît jamais dans le JSON
        client_private = dh.generate_private()
        client_public = f"{dh.public_value(client_private):x}"
        server_private = dh.generate_private()
        server_public = dh.public_value(server_private)

        session_keys = {client_public: dh.derive_key(dh.shared_secret(server_private, int(client_public, 16)), 16)}
        client_key = dh.derive_key(dh.shared_secret(client_private, server_public), 16)

        payload = protocol.make_payload("aes", client_key.hex(), MESSAGE, "CTR", dh_public=client_public)
        msg = protocol.parse_message(payload)
        self.assertNotIn("key", msg)
        self.assertNotIn(client_key.hex(), payload)
        self.assertEqual(protocol.decrypt_message(msg, session_keys=session_keys), MESSAGE)
        with self.assertRaises(ValueError):  # session inconnue
            protocol.decrypt_message(msg, session_keys={})

    def test_hash_and_hmac(self):
        msg = roundtrip("caesar", secret="monsecret")
        self.assertTrue(protocol.verify_hmac(msg, "monsecret"))
        self.assertFalse(protocol.verify_hmac(msg, "autre"))
        self.assertTrue(protocol.check_hash(msg, MESSAGE))
        self.assertFalse(protocol.check_hash(msg, "Message modifié"))
        msg["ciphertext"] = msg["ciphertext"] + "A"  # un pirate modifie le chiffré
        self.assertFalse(protocol.verify_hmac(msg, "monsecret"))
        self.assertIsNone(protocol.check_hash({"algorithm": "caesar"}, MESSAGE))

    def test_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            protocol.default_key("xyz")
        with self.assertRaises(ValueError):
            protocol.make_payload("xyz", "k", MESSAGE)
        with self.assertRaises(ValueError):
            protocol.decrypt_message({"algorithm": "xyz", "ciphertext": "a"})


if __name__ == "__main__":
    unittest.main()

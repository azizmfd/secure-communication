import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")


def free_port():
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


def run_scenario(server_args, clients, expected):
    """Lance un vrai serveur, lance chaque client, retourne (sortie du serveur, sorties des clients)."""
    port = free_port()
    server = subprocess.Popen(
        [sys.executable, "-u", "network/server.py", "--port", str(port), *server_args],
        cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8")
    lines = []
    reader = threading.Thread(target=lambda: lines.extend(server.stdout), daemon=True)
    reader.start()
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not any("En écoute" in line for line in lines):
            time.sleep(0.05)
        outputs = []
        for client_args in clients:
            result = subprocess.run(
                [sys.executable, "network/client.py", "--port", str(port), *client_args],
                cwd=ROOT, env=ENV, capture_output=True, text=True, encoding="utf-8", timeout=30)
            outputs.append(result.stdout)
        deadline = time.time() + 5  # on laisse le serveur finir d'afficher
        while time.time() < deadline and not all(e in "".join(lines) for e in expected):
            time.sleep(0.05)
    finally:
        server.terminate()
        server.wait(timeout=5)
        reader.join(timeout=2)
        server.stdout.close()
    return "".join(lines), outputs


class TestNetwork(unittest.TestCase):
    def test_caesar(self):
        out, _ = run_scenario([], [["--algorithm", "caesar", "--key", "5", "--message", "Test réseau"]],
                              ["SHA-256"])
        self.assertIn("Message déchiffré : Test réseau", out)
        self.assertIn("SHA-256 : OK", out)

    def test_aes_cbc(self):
        out, _ = run_scenario([], [["--algorithm", "aes", "--mode", "CBC", "--message", "Test AES"]],
                              ["SHA-256"])
        self.assertIn("Message déchiffré : Test AES", out)

    def test_diffie_hellman_same_key_both_sides(self):
        out, clients = run_scenario(
            [], [["--algorithm", "dh", "--bits", "256", "--message", "Test DH"]], ["SHA-256"])
        fingerprint = re.search(r"Empreinte de la clé : ([0-9a-f]{16})", clients[0]).group(1)
        self.assertIn(f"Empreinte de la clé : {fingerprint}", out)  # même empreinte côté serveur
        self.assertIn("Message déchiffré : Test DH", out)

    def test_hmac_rejects_wrong_secret(self):
        out, _ = run_scenario(
            ["--secret", "bon"],
            [["--secret", "bon", "--message", "Message légitime"],
             ["--secret", "mauvais", "--message", "Message du pirate"]],
            ["HMAC invalide"])
        self.assertIn("Message déchiffré : Message légitime", out)
        self.assertIn("HMAC invalide", out)
        self.assertNotIn("Message déchiffré : Message du pirate", out)


if __name__ == "__main__":
    unittest.main()

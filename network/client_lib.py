import json
import socket

from algorithms.asymmetric import dh
from algorithms.hash import sha256
from network.protocol import make_payload, default_key, key_path

ALGORITHMS = ["caesar", "substitution", "vigenere", "playfair", "hill", "aes", "rsa", "dh"]


def _send(host, port, text, expect_reply=False):
    """Envoie un texte au serveur. Si expect_reply, attend et retourne sa réponse."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(text.encode())
    if not expect_reply:
        s.close()
        return None
    s.shutdown(socket.SHUT_WR)  # "j'ai fini d'envoyer", mais j'écoute encore la réponse
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode()


def send_message(host, port, algorithm, message, key=None, mode="CBC", bits=128,
                 secret=None, sign=False):
    """Chiffre le message avec l'algorithme choisi et l'envoie. Retourne le JSON envoyé."""
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Algorithme inconnu : {algorithm} (choix : {', '.join(ALGORITHMS)})")
    sign_key = key_path("client_priv.txt") if sign else None

    if algorithm == "dh":
        # 1. Échange Diffie-Hellman : on envoie A, le serveur répond B
        my_private = dh.generate_private()
        my_public = f"{dh.public_value(my_private):x}"
        init = json.dumps({"type": "dh_init", "public": my_public, "bits": bits})
        reply = json.loads(_send(host, port, init, expect_reply=True))
        shared = dh.shared_secret(my_private, int(reply["public"], 16))
        session_key = dh.derive_key(shared, bits // 8)
        fingerprint = sha256.sha256_hex(session_key)[:16]
        print(f"[CLIENT] Échange Diffie-Hellman terminé. Empreinte de la clé : {fingerprint}")
        # 2. On chiffre en AES avec la clé obtenue (elle n'est pas envoyée)
        payload = make_payload("aes", session_key.hex(), message, mode,
                               secret, sign_key, dh_public=my_public)
    else:
        key = key if key else default_key(algorithm, bits)
        payload = make_payload(algorithm, key, message, mode, secret, sign_key)

    _send(host, port, payload)
    return payload

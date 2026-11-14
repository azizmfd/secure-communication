import argparse
import json
import os
import socket
import sys

# Permet d'importer "algorithms" et "network" depuis la racine du projet
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.asymmetric import rsa, dh
from algorithms.hash import sha256
from network.protocol import (parse_message, decrypt_message, verify_hmac,
                              check_hash, check_signature, key_path)

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="localhost")
parser.add_argument("--port", type=int, default=5000)
parser.add_argument("--secret", default=None)  # secret partagé pour vérifier le HMAC
parser.add_argument("--privkey", default=key_path("server_priv.txt"))  # clé privée RSA du serveur
parser.add_argument("--clientpub", default=key_path("client_pub.txt"))  # clé publique RSA du client


def load_if_exists(path):
    return rsa.load_key(path) if os.path.exists(path) else None


args = parser.parse_args()
private_key = load_if_exists(args.privkey)
client_pub = load_if_exists(args.clientpub)
session_keys = {}  # clés AES négociées par Diffie-Hellman : {valeur publique du client: clé}

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # relancer vite sur le même port
server.bind((args.host, args.port))  # "j'écoute sur ce port"
server.listen(5)
print(f"[SERVEUR] En écoute sur {args.host}:{args.port} ...")
print(f"[SERVEUR] Clé privée RSA : {'chargée' if private_key else 'absente'} | "
      f"clé publique du client : {'chargée' if client_pub else 'absente'}")

while True:
    conn, addr = server.accept()  # attend qu'un client se connecte
    with conn:
        # On lit jusqu'à la fin de l'envoi du client
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        raw = data.decode()
        print(f"\n[SERVEUR] Reçu de {addr} : {raw}")
        try:
            msg = parse_message(raw)

            # 0. Échange de clés Diffie-Hellman : on répond avec notre valeur publique
            if msg.get("type") == "dh_init":
                nbytes = int(msg.get("bits", 128)) // 8
                my_private = dh.generate_private()
                my_public = dh.public_value(my_private)
                secret = dh.shared_secret(my_private, int(msg["public"], 16))
                session_keys[msg["public"]] = dh.derive_key(secret, nbytes)
                conn.sendall(json.dumps({"type": "dh_reply", "public": f"{my_public:x}"}).encode())
                fingerprint = sha256.sha256_hex(session_keys[msg["public"]])[:16]
                print(f"[SERVEUR] Échange Diffie-Hellman terminé. Empreinte de la clé : {fingerprint}")
                continue

            # 1. Authenticité : on vérifie le HMAC AVANT de déchiffrer
            if args.secret:
                if not verify_hmac(msg, args.secret):
                    print("[SERVEUR] HMAC invalide -> message rejeté")
                    continue
                print("[SERVEUR] HMAC : OK")

            # 2. Déchiffrement
            plaintext = decrypt_message(msg, private_key, session_keys)
            print(f"[SERVEUR] Message déchiffré : {plaintext}")

            # 3. Intégrité : l'empreinte SHA-256 correspond-elle ?
            result = check_hash(msg, plaintext)
            if result is not None:
                print(f"[SERVEUR] SHA-256 : {'OK' if result else 'ÉCHEC (message modifié ?)'}")

            # 4. Signature RSA de l'expéditeur
            if "signature" in msg:
                if client_pub is None:
                    print("[SERVEUR] Signature RSA : non vérifiable (clé publique du client absente)")
                else:
                    ok = check_signature(msg, plaintext, client_pub)
                    print(f"[SERVEUR] Signature RSA : {'VALIDE' if ok else 'INVALIDE'}")
        except Exception as e:
            print(f"[SERVEUR] Erreur : {e}")

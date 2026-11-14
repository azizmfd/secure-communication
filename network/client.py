import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.client_lib import send_message

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="localhost")
parser.add_argument("--port", type=int, default=5000)
parser.add_argument("--algorithm", default="caesar")  # caesar, substitution, vigenere, playfair, hill, aes, rsa, dh
parser.add_argument("--key", default=None)  # si absent, une clé par défaut est choisie
parser.add_argument("--message", default="Bonjour Serveur")
parser.add_argument("--mode", default="CBC")  # pour AES : ECB, CBC ou CTR
parser.add_argument("--bits", type=int, default=128, choices=[128, 256])  # pour AES
parser.add_argument("--secret", default=None)  # secret partagé : ajoute un HMAC
parser.add_argument("--sign", action="store_true")  # signe le message avec la clé privée du client
args = parser.parse_args()

try:
    payload = send_message(args.host, args.port, args.algorithm, args.message, args.key,
                           args.mode, args.bits, args.secret, args.sign)
    print(f"[CLIENT] Envoyé : {payload}")
except ConnectionRefusedError:
    print(f"[CLIENT] Impossible de se connecter à {args.host}:{args.port} : le serveur est-il lancé ?")
    sys.exit(1)
except FileNotFoundError as e:
    print(f"[CLIENT] Fichier introuvable : {e.filename} (as-tu lancé network/keygen.py ?)")
    sys.exit(1)
except ValueError as e:
    print(f"[CLIENT] Erreur : {e}")
    sys.exit(1)

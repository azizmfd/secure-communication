import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from network.client_lib import send_message

CHOICES = {
    "1": ("caesar", "Caesar (décalage)"),
    "2": ("substitution", "Substitution (alphabet mélangé)"),
    "3": ("vigenere", "Vigenère (mot-clé répété)"),
    "4": ("playfair", "Playfair (grille 5x5)"),
    "5": ("hill", "Hill (matrices)"),
    "6": ("aes", "AES (clé envoyée dans le JSON)"),
    "7": ("rsa", "RSA (clé publique du serveur)"),
    "8": ("dh", "Diffie-Hellman + AES (clé jamais envoyée)"),
}


def ask(question, default=""):
    suffix = f" [{default}]" if default else ""
    return input(f"{question}{suffix} : ").strip() or default


print("=== Client de communication sécurisée ===")
for number, (_, label) in CHOICES.items():
    print(f"  {number}. {label}")

choice = ask("Ton choix (1-8)", "1")
if choice not in CHOICES:
    print("Choix invalide.")
    sys.exit(1)
algorithm = CHOICES[choice][0]

try:
    message = ask("Message à envoyer", "Bonjour Serveur")
    port = int(ask("Port du serveur", "5000"))
    mode, bits, key = "CBC", 128, None
    if algorithm in ("aes", "dh"):
        mode = ask("Mode (ECB/CBC/CTR)", "CBC").upper()
        bits = int(ask("Taille de clé (128/256)", "128"))
    if algorithm in ("caesar", "substitution", "vigenere", "playfair", "hill", "aes"):
        key = ask("Clé (vide = clé par défaut ; en hexadécimal pour AES)") or None
    secret = ask("Secret partagé pour le HMAC (vide = pas de HMAC)") or None
    sign = ask("Signer avec RSA ? (o/N)", "n").lower() in ("o", "oui", "y")

    payload = send_message("localhost", port, algorithm, message, key, mode, bits, secret, sign)
    print(f"[CLIENT] Envoyé : {payload}")
except ConnectionRefusedError:
    print("[CLIENT] Impossible de se connecter : le serveur est-il lancé ?")
except FileNotFoundError as e:
    print(f"[CLIENT] Fichier introuvable : {e.filename} (as-tu lancé network/keygen.py ?)")
except ValueError as e:
    print(f"[CLIENT] Erreur : {e}")

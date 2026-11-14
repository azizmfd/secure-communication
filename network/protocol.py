import json
import os
from algorithms.classical import caesar, substitution, vigenere, playfair, hill
from algorithms.symmetric import aes
from algorithms.asymmetric import rsa
from algorithms.hash import sha256, hmac_sha256

# Dossier des clés RSA : ~/secure-communication/keys
KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys")


def key_path(filename):
    return os.path.join(KEYS_DIR, filename)


def default_key(algorithm, bits=128):
    """Clé utilisée si le client n'en donne pas."""
    if algorithm == "caesar":
        return "3"
    if algorithm == "substitution":
        return substitution.generate_key()
    if algorithm == "vigenere":
        return "SECRET"
    if algorithm == "playfair":
        return "MONARCHY"
    if algorithm == "hill":
        return "DDCF"
    if algorithm == "aes":
        return aes.generate_key(bits).hex()  # clé aléatoire, en hexadécimal
    if algorithm == "rsa":
        return key_path("server_pub.txt")  # chemin de la clé publique du serveur
    raise ValueError(f"Algorithme inconnu : {algorithm}")


def encrypt_message(algorithm, key, plaintext):
    """Algorithmes classiques uniquement."""
    if algorithm == "caesar":
        return caesar.encrypt(plaintext, int(key))
    if algorithm == "substitution":
        return substitution.encrypt(plaintext, key)
    if algorithm == "vigenere":
        return vigenere.encrypt(plaintext, key)
    if algorithm == "playfair":
        return playfair.encrypt(plaintext, key)
    if algorithm == "hill":
        return hill.encrypt(plaintext, key)
    raise ValueError(f"Algorithme inconnu : {algorithm}")


def make_payload(algorithm, key, plaintext, mode="CBC", secret=None, sign_key=None, dh_public=None):
    """Côté client : chiffre le message et retourne le JSON à envoyer."""
    msg = {"algorithm": algorithm, "key": key}
    if algorithm == "aes":
        if dh_public:
            # Clé issue de Diffie-Hellman : elle ne voyage plus, on envoie seulement
            # notre valeur publique pour que le serveur retrouve la bonne session
            msg.pop("key")
            msg["dh_public"] = dh_public
        mode = mode.upper()
        ciphertext, iv = aes.encrypt(plaintext, bytes.fromhex(key), mode)
        msg["mode"] = mode
        if iv is not None:
            msg["iv"] = iv.hex()
        msg["ciphertext"] = ciphertext.hex()
    elif algorithm == "rsa":
        public_key = rsa.load_key(key)  # ici, key = chemin du fichier de clé publique
        msg["key"] = rsa.key_to_str(public_key)  # la clé publique peut voyager en clair
        msg["ciphertext"] = rsa.encrypt(plaintext, public_key)
    else:
        msg["ciphertext"] = encrypt_message(algorithm, key, plaintext)
    # Empreinte du message en clair : permet de détecter une modification
    msg["sha256"] = sha256.sha256_hex(plaintext)
    # Étiquette HMAC (si un secret partagé est donné) : prouve l'origine du message
    if secret:
        msg["hmac"] = hmac_sha256.hmac_hex(secret, msg["ciphertext"])
    # Signature RSA (si une clé privée d'expéditeur est donnée) : preuve d'origine, sans secret partagé
    if sign_key:
        msg["signature"] = rsa.sign(plaintext, rsa.load_key(sign_key))
    return json.dumps(msg)


def parse_message(raw):
    return json.loads(raw)


def verify_hmac(msg, secret):
    """Côté serveur : True si l'étiquette HMAC reçue est correcte."""
    return "hmac" in msg and hmac_sha256.verify(secret, msg["ciphertext"], msg["hmac"])


def check_hash(msg, plaintext):
    """Côté serveur : True/False selon l'empreinte, None si le message n'en contient pas."""
    if "sha256" not in msg:
        return None
    return sha256.sha256_hex(plaintext) == msg["sha256"]


def check_signature(msg, plaintext, public_key):
    """Côté serveur : True si la signature RSA de l'expéditeur est valide."""
    return rsa.verify(plaintext, msg["signature"], public_key)


def decrypt_message(msg, private_key=None, session_keys=None):
    """Côté serveur : déchiffre selon l'algorithme indiqué dans le JSON."""
    algo = msg["algorithm"]
    if algo == "caesar":
        return caesar.decrypt(msg["ciphertext"], int(msg["key"]))
    if algo == "substitution":
        return substitution.decrypt(msg["ciphertext"], msg["key"])
    if algo == "vigenere":
        return vigenere.decrypt(msg["ciphertext"], msg["key"])
    if algo == "playfair":
        return playfair.decrypt(msg["ciphertext"], msg["key"])
    if algo == "hill":
        return hill.decrypt(msg["ciphertext"], msg["key"])
    if algo == "aes":
        iv = bytes.fromhex(msg["iv"]) if "iv" in msg else None
        if "dh_public" in msg:  # clé négociée par Diffie-Hellman
            key = (session_keys or {}).get(msg["dh_public"])
            if key is None:
                raise ValueError("Session Diffie-Hellman inconnue (fais d'abord l'échange)")
        else:
            key = bytes.fromhex(msg["key"])
        return aes.decrypt(bytes.fromhex(msg["ciphertext"]), key, msg["mode"], iv)
    if algo == "rsa":
        if private_key is None:
            raise ValueError("Clé privée du serveur introuvable (lance keygen.py)")
        return rsa.decrypt(msg["ciphertext"], private_key)
    raise ValueError(f"Algorithme inconnu : {algo}")

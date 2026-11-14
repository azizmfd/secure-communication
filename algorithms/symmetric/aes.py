from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK = 16  # AES travaille par blocs de 16 octets


def generate_key(bits=128):
    """Clé aléatoire : 16 octets (AES-128) ou 32 octets (AES-256)."""
    if bits not in (128, 256):
        raise ValueError("bits doit valoir 128 ou 256")
    return get_random_bytes(bits // 8)


def _check_key(key):
    if len(key) not in (16, 32):
        raise ValueError("Clé invalide : 16 octets (AES-128) ou 32 octets (AES-256)")


def encrypt(plaintext, key, mode):
    """Retourne (message_chiffré, iv). iv vaut None en mode ECB."""
    _check_key(key)
    mode = mode.upper()
    data = plaintext.encode("utf-8")  # AES travaille sur des octets, pas du texte

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(data, BLOCK)), None
    if mode == "CBC":
        iv = get_random_bytes(16)  # nouvel IV aléatoire à chaque message
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(data, BLOCK)), iv
    if mode == "CTR":
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(data), nonce  # pas de padding en CTR
    raise ValueError(f"Mode inconnu : {mode} (ECB, CBC ou CTR)")


def decrypt(ciphertext, key, mode, iv=None):
    _check_key(key)
    mode = mode.upper()

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), BLOCK).decode("utf-8")
    if mode == "CBC":
        if iv is None:
            raise ValueError("Le mode CBC nécessite un IV")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), BLOCK).decode("utf-8")
    if mode == "CTR":
        if iv is None:
            raise ValueError("Le mode CTR nécessite un nonce")
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
        return cipher.decrypt(ciphertext).decode("utf-8")
    raise ValueError(f"Mode inconnu : {mode} (ECB, CBC ou CTR)")

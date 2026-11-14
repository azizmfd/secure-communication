import hmac as _stdlib_hmac  # uniquement pour compare_digest

from algorithms.hash import sha256

BLOCK_SIZE = 64


def hmac_sha256(key, message):
    """HMAC-SHA256 (octets -> octets)."""
    if len(key) > BLOCK_SIZE:
        key = sha256.sha256(key)  # clé trop longue : on la hache d'abord
    key = key.ljust(BLOCK_SIZE, b"\x00")  # on complète avec des zéros
    inner_key = bytes(b ^ 0x36 for b in key)
    outer_key = bytes(b ^ 0x5C for b in key)
    return sha256.sha256(outer_key + sha256.sha256(inner_key + message))


def hmac_hex(secret, text):
    """Pratique : secret et message en texte, retourne l'hexadécimal."""
    return hmac_sha256(secret.encode("utf-8"), text.encode("utf-8")).hex()


def verify(secret, text, received_hex):
    """Compare en temps constant, pour ne pas donner d'indice par le temps de calcul."""
    return _stdlib_hmac.compare_digest(hmac_hex(secret, text), received_hex)

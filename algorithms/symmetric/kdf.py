from algorithms.hash import sha256


def password_to_key(password, bits=128):
    """Transforme un mot de passe en clé AES (16 ou 32 octets) avec SHA-256.
       C'est volontairement simple : dans un vrai système on utiliserait PBKDF2/Argon2
       pour ralentir les essais, ce qui est justement ce qui manque ici."""
    return sha256.sha256(password.encode("utf-8"))[: bits // 8]

import random
import string

ALPHABET = string.ascii_uppercase


def generate_key():
    """Mélange l'alphabet pour fabriquer une clé de 26 lettres."""
    letters = list(ALPHABET)
    random.shuffle(letters)
    return "".join(letters)


def _check_key(key):
    # Une clé valide contient exactement les 26 lettres, chacune une seule fois
    if sorted(key) != list(ALPHABET):
        raise ValueError("Clé invalide : il faut les 26 lettres, sans doublon")


def encrypt(text, key):
    key = key.upper()
    _check_key(key)
    table = {}
    for plain, cipher in zip(ALPHABET, key):
        table[plain] = cipher                  # A -> Q
        table[plain.lower()] = cipher.lower()  # a -> q (on garde la casse)
    # table.get(c, c) : si ce n'est pas une lettre, on la laisse telle quelle
    return "".join(table.get(c, c) for c in text)


def decrypt(text, key):
    key = key.upper()
    _check_key(key)
    table = {}
    for plain, cipher in zip(ALPHABET, key):
        table[cipher] = plain                  # Q -> A (table inversée)
        table[cipher.lower()] = plain.lower()
    return "".join(table.get(c, c) for c in text)

from math import gcd


def _key_matrix(key):
    """Transforme une clé de 4 lettres en matrice [[a, b], [c, d]]."""
    key = "".join(c for c in key.upper() if "A" <= c <= "Z")
    if len(key) != 4:
        raise ValueError("Clé invalide : il faut 4 lettres (ex: DDCF)")
    a, b, c, d = [ord(ch) - ord("A") for ch in key]  # A=0 ... Z=25
    det = (a * d - b * c) % 26
    if gcd(det, 26) != 1:
        raise ValueError("Clé non inversible modulo 26, choisis-en une autre")
    return a, b, c, d


def _inverse(a, b, c, d):
    """Matrice inverse modulo 26 : inverse(det) × [[d, -b], [-c, a]]."""
    det = (a * d - b * c) % 26
    det_inv = pow(det, -1, 26)  # inverse de det modulo 26
    return (d * det_inv) % 26, (-b * det_inv) % 26, (-c * det_inv) % 26, (a * det_inv) % 26


def _clean(text):
    """Majuscules, seulement les lettres A-Z."""
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def _apply(text, matrix):
    """Multiplie chaque paire de lettres par la matrice (mod 26)."""
    a, b, c, d = matrix
    result = []
    for i in range(0, len(text), 2):
        x = ord(text[i]) - ord("A")
        y = ord(text[i + 1]) - ord("A")
        result.append(chr((a * x + b * y) % 26 + ord("A")))
        result.append(chr((c * x + d * y) % 26 + ord("A")))
    return "".join(result)


def encrypt(text, key):
    matrix = _key_matrix(key)
    text = _clean(text)
    if len(text) % 2 != 0:
        text += "X"  # on complète pour avoir des paires entières
    return _apply(text, matrix)


def decrypt(text, key):
    matrix = _key_matrix(key)
    text = _clean(text)
    if len(text) % 2 != 0:
        raise ValueError("Texte chiffré invalide : nombre de lettres impair")
    return _apply(text, _inverse(*matrix))

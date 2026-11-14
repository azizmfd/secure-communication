import argparse
import os
import sys
from math import gcd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.classical import hill
from attacks.common import get_ciphertext

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def letters_to_numbers(text):
    return [ALPHABET.index(c) for c in text]


def mat2_inverse_mod26(a, b, c, d):
    det = (a * d - b * c) % 26
    if gcd(det, 26) != 1:
        return None
    inv_det = pow(det, -1, 26)
    return (d * inv_det) % 26, (-b * inv_det) % 26, (-c * inv_det) % 26, (a * inv_det) % 26


def mat2_mul(m1, m2):
    a, b, c, d = m1
    e, f, g, h = m2
    return (a * e + b * g) % 26, (a * f + b * h) % 26, (c * e + d * g) % 26, (c * f + d * h) % 26


def recover_key(known_plain, known_cipher):
    """A partir d'au moins 4 lettres de clair ET du chiffré correspondant, retrouve la clé K telle que C = K.P (mod 26).
       On prend 2 paires de colonnes (P1,P2) inversible, et K = C . P^-1."""
    p = letters_to_numbers(known_plain)
    c = letters_to_numbers(known_cipher)
    p_matrix = (p[0], p[2], p[1], p[3])   # matrice P = [[p0, p2], [p1, p3]]
    c_matrix = (c[0], c[2], c[1], c[3])
    p_inv = mat2_inverse_mod26(*p_matrix)
    if p_inv is None:
        raise ValueError("Ce couple de lettres claires ne permet pas de retrouver la clé (matrice non inversible). "
                         "Essaie un autre morceau de texte clair connu.")
    return mat2_mul(c_matrix, p_inv)


def key_to_letters(key):
    a, b, c, d = key
    return "".join(ALPHABET[x] for x in (a, b, c, d))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attaque known plaintext sur Hill : il faut connaitre 4 lettres de texte clair ET le chiffre qui leur correspond, au début du message.")
    parser.add_argument("--capture", default="capture.txt")
    parser.add_argument("--text", default=None)
    parser.add_argument("--known", required=True, help="les 4 premières lettres claires que l'on devine (ex: HELP)")
    args = parser.parse_args()

    ciphertext = get_ciphertext("hill", args.capture, args.text)
    known_plain = args.known.upper()
    if len(known_plain) != 4:
        raise SystemExit("--known doit faire exactement 4 lettres (2 blocs de Hill)")
    known_cipher = ciphertext[:4]

    print(f"Texte clair connu (hypothèse de l'attaquant) : {known_plain}")
    print(f"Texte chiffré correspondant (les 4 premières lettres interceptées) : {known_cipher}\n")

    key = recover_key(known_plain, known_cipher)
    key_str = key_to_letters(key)
    print(f"Clé retrouvée (matrice) : {key}")
    print(f"Clé retrouvée (4 lettres, comme dans notre format Hill) : {key_str}")

    plaintext = hill.decrypt(ciphertext, key_str)
    print(f"\nTexte déchiffré avec cette clé :\n{plaintext}")

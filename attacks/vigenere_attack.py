import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.classical import vigenere
from attacks.common import chi_squared, get_ciphertext, letters_only, load_messages
from attacks.substitution_attack import score  # même "juge" que pour la Substitution

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def index_of_coincidence(text):
    """Probabilité que 2 lettres tirées au hasard dans le texte soient identiques."""
    n = len(text)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in Counter(text).values()) / (n * (n - 1))


def average_ic(letters, length):
    """IC moyen des 'colonnes' : lettres 0, L, 2L... puis 1, L+1... etc."""
    columns = [letters[i::length] for i in range(length)]
    return sum(index_of_coincidence(c) for c in columns) / length


def find_key_length(letters, max_length=16):
    """Plus petite longueur dont l'IC moyen est proche du meilleur."""
    table = {length: average_ic(letters, length) for length in range(1, max_length + 1)}
    best = max(table.values())
    for length in range(1, max_length + 1):
        if table[length] >= 0.93 * best:
            return length, table
    return 1, table


def best_shift(column):
    """Décalage (0-25) pour lequel cette colonne ressemble le plus au français."""
    best, best_score = 0, float("inf")
    for shift in range(26):
        shifted = "".join(chr((ord(c) - 65 - shift) % 26 + 65) for c in column)
        s = chi_squared(shifted)
        if s < best_score:
            best, best_score = shift, s
    return best


def crack(ciphertext, length):
    letters = letters_only(ciphertext)
    # 1. Chaque colonne est un Caesar : on trouve son décalage par fréquences
    key = [ALPHABET[best_shift(letters[i::length])] for i in range(length)]
    # 2. Affinage : pour chaque lettre de la clé, on garde celle qui rend le texte le plus français
    for _ in range(2):
        for i in range(length):
            best_letter, best_score = key[i], float("-inf")
            for letter in ALPHABET:
                key[i] = letter
                s = score(vigenere.decrypt(ciphertext, "".join(key)))
                if s > best_score:
                    best_letter, best_score = letter, s
            key[i] = best_letter
    return "".join(key)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", default="capture.txt")
    parser.add_argument("--text", default=None)
    parser.add_argument("--length", type=int, default=None)  # forcer la longueur de clé
    args = parser.parse_args()

    real_key = None
    if args.text:
        ciphertext = args.text
    else:
        messages = [m for m in load_messages(args.capture) if m["algorithm"] == "vigenere"]
        if not messages:
            raise SystemExit(f"Aucun message 'vigenere' trouvé dans {args.capture}")
        ciphertext = messages[-1]["ciphertext"]
        real_key = messages[-1].get("key")  # visible dans la capture : on s'en sert SEULEMENT pour vérifier

    letters = letters_only(ciphertext)
    print(f"Texte chiffré : {len(letters)} lettres\n")

    length, table = find_key_length(letters)
    print("Etape 1 : longueur de la clé (indice de coïncidence moyen)")
    print("  français ~ 0.075 | texte aléatoire ~ 0.039")
    for l, ic in table.items():
        print(f"  longueur {l:2d} : IC = {ic:.3f} {'#' * round(ic * 400)}")
    if args.length:
        length = args.length
    print(f"\nLongueur de clé retenue : {length}")

    key = crack(ciphertext, length)
    print(f"\nEtape 2 : clé trouvée (fréquences par colonne, puis affinage) : {key}")
    print(f"\nTexte déchiffré :\n{vigenere.decrypt(ciphertext, key)}")
    if real_key:
        print(f"\nVérification avec la vraie clé de la capture : {'CORRECTE' if key == real_key.upper() else 'différente (' + real_key + ')'}")

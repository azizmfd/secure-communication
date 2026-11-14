import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.classical import caesar
from attacks.common import get_ciphertext, chi_squared, is_valid_text

parser = argparse.ArgumentParser()
parser.add_argument("--capture", default="capture.txt")
parser.add_argument("--text", default=None)  # texte chiffré donné directement
args = parser.parse_args()

ciphertext = get_ciphertext("caesar", args.capture, args.text)
print(f"Texte chiffré ({len(ciphertext)} caractères) : {ciphertext[:60]}...\n")

best_key, best_score = 0, float("inf")
for key in range(26):  # on teste TOUTES les clés possibles
    plaintext = caesar.decrypt(ciphertext, key)
    score = chi_squared(plaintext)
    flag = "   <-- ressemble à du français" if is_valid_text(plaintext) else ""
    print(f"Clé {key:2d} (chi² = {score:8.1f}) : {plaintext[:45]}{flag}")
    if score < best_score:
        best_key, best_score = key, score

print(f"\nClé la plus probable : {best_key}")
print(f"Texte déchiffré :\n{caesar.decrypt(ciphertext, best_key)}")

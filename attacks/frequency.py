import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.classical import caesar
from attacks.common import FRENCH_FREQ, get_ciphertext, letters_only

parser = argparse.ArgumentParser()
parser.add_argument("--algorithm", default="caesar")
parser.add_argument("--capture", default="capture.txt")
parser.add_argument("--text", default=None)
args = parser.parse_args()

ciphertext = get_ciphertext(args.algorithm, args.capture, args.text)
letters = letters_only(ciphertext)
counts = Counter(letters)
print(f"{len(letters)} lettres dans le texte chiffré\n")

# 1. Histogramme des fréquences du texte chiffré
print("Lettre  Fréquence")
for letter, count in counts.most_common():
    percent = 100 * count / len(letters)
    print(f"  {letter}     {percent:5.1f} %  {'#' * round(percent * 2)}")

# 2. Comparaison avec le français
french_ranking = sorted(FRENCH_FREQ, key=FRENCH_FREQ.get, reverse=True)
print("\n5 lettres les plus fréquentes :")
print("  texte chiffré :", " ".join(f"{l} ({100 * c / len(letters):.1f}%)" for l, c in counts.most_common(5)))
print("  français      :", " ".join(f"{l} ({FRENCH_FREQ[l]:.1f}%)" for l in french_ranking[:5]))

# 3. Hypothèse pour Caesar : la lettre la plus fréquente correspond au E
if args.algorithm == "caesar":
    top = counts.most_common(1)[0][0]
    key = (ord(top) - ord("E")) % 26
    print(f"\nHypothèse : {top} correspond à E, donc décalage = {key}")
    print(f"Texte déchiffré :\n{caesar.decrypt(ciphertext, key)}")

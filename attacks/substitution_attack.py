import argparse
import os
import random
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.common import FRENCH_FREQ, letters_only, load_messages
from attacks.french_data import BIGRAM_LOG, WORDS, normalized_letters

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
WORD_BONUS = 3.0  # points gagnés par lettre d'un mot français reconnu


def decrypt_with(ciphertext, key):
    """key[i] = lettre chiffrée qui remplace la lettre claire ALPHABET[i]."""
    table = {}
    for plain, cipher in zip(ALPHABET, key):
        table[ord(cipher)] = plain
        table[ord(cipher.lower())] = plain.lower()
    return ciphertext.translate(table)


def score(text):
    """Plus le score est haut, plus le texte ressemble à du français."""
    letters = normalized_letters(text)
    total = sum(BIGRAM_LOG[a + b] for a, b in zip(letters, letters[1:]))
    for word in re.findall(r"[a-zàâçéèêëîïôûù]+", text.lower()):
        if word in WORDS and len(word) >= 2:
            total += WORD_BONUS * len(word)
    return total


def initial_key(ciphertext):
    """Point de départ : la lettre chiffrée la plus fréquente remplace la lettre la plus fréquente du français, etc."""
    cipher_rank = [l for l, _ in Counter(letters_only(ciphertext)).most_common()]
    cipher_rank += [l for l in ALPHABET if l not in cipher_rank]  # lettres absentes du texte
    french_rank = sorted(FRENCH_FREQ, key=FRENCH_FREQ.get, reverse=True)
    key = [None] * 26
    for plain, cipher in zip(french_rank, cipher_rank):
        key[ALPHABET.index(plain)] = cipher
    return key


def climb(ciphertext, key):
    """Escalade : on échange 2 lettres de la clé tant que ça améliore le score."""
    best = score(decrypt_with(ciphertext, key))
    improved = True
    while improved:
        improved = False
        for i in range(25):
            for j in range(i + 1, 26):
                key[i], key[j] = key[j], key[i]
                s = score(decrypt_with(ciphertext, key))
                if s > best:
                    best, improved = s, True
                else:
                    key[i], key[j] = key[j], key[i]  # pas mieux : on annule
    return key, best


def attack(ciphertext, restarts=15, verbose=False):
    key, best = climb(ciphertext, initial_key(ciphertext))
    best_key = list(key)
    for n in range(restarts):
        candidate = list(best_key)
        for _ in range(4):  # on secoue la meilleure clé avec 4 échanges au hasard
            i, j = random.sample(range(26), 2)
            candidate[i], candidate[j] = candidate[j], candidate[i]
        candidate, s = climb(ciphertext, candidate)
        if verbose:
            print(f"  essai {n + 1:2d}/{restarts} : score {s:8.1f}")
        if s > best:
            best, best_key = s, candidate
    return "".join(best_key), best


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", default="capture.txt")
    parser.add_argument("--text", default=None)  # texte chiffré donné directement
    parser.add_argument("--restarts", type=int, default=15)
    parser.add_argument("--seed", type=int, default=1)  # même graine = même résultat à chaque lancement
    parser.add_argument("--swap", action="append", default=[])  # correction à la main, ex : --swap VG
    args = parser.parse_args()
    random.seed(args.seed)

    real_key = None
    if args.text:
        ciphertext = args.text
    else:
        messages = [m for m in load_messages(args.capture) if m["algorithm"] == "substitution"]
        if not messages:
            raise SystemExit(f"Aucun message 'substitution' trouvé dans {args.capture}")
        ciphertext = messages[-1]["ciphertext"]
        real_key = messages[-1].get("key")  # visible dans la capture : on s'en sert SEULEMENT pour vérifier

    print(f"Texte chiffré ({len(letters_only(ciphertext))} lettres) : {ciphertext[:60]}...\n")
    print("Recherche de la clé (escalade + redémarrages)...")
    found_key, found_score = attack(ciphertext, args.restarts, verbose=True)

    key = list(found_key)
    for pair in args.swap:  # corrections à la main : on échange 2 lettres CLAIRES dans le résultat
        a, b = pair.upper()
        i, j = ALPHABET.index(a), ALPHABET.index(b)
        key[i], key[j] = key[j], key[i]
        print(f"Correction à la main : {a} <-> {b}")

    print("\nClé trouvée :")
    print(f"  lettre claire   : {ALPHABET}")
    print(f"  lettre chiffrée : {''.join(key)}")
    print(f"\nTexte déchiffré :\n{decrypt_with(ciphertext, key)}")
    if real_key:
        good = sum(1 for a, b in zip(key, real_key.upper()) if a == b)
        print(f"\nVérification avec la vraie clé de la capture : {good}/26 lettres correctes")

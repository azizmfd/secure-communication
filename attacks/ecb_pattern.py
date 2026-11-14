import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.common import get_ciphertext

BLOCK_HEX = 32  # 16 octets = 32 caractères hexadécimaux


def split_blocks(ciphertext_hex):
    return [ciphertext_hex[i:i + BLOCK_HEX] for i in range(0, len(ciphertext_hex), BLOCK_HEX)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Repere les blocs identiques dans un chiffre AES-ECB : la preuve de la fuite d'information.")
    parser.add_argument("--capture", default="capture.txt")
    parser.add_argument("--text", default=None)
    args = parser.parse_args()

    ciphertext = get_ciphertext("aes", args.capture, args.text)
    blocks = split_blocks(ciphertext)
    counts = Counter(blocks)
    repeated = {b: n for b, n in counts.items() if n > 1}

    print(f"{len(blocks)} blocs de 16 octets dans le texte chiffré\n")
    for i, block in enumerate(blocks):
        marker = "   <-- répété" if counts[block] > 1 else ""
        print(f"  bloc {i:2d} : {block}{marker}")

    print()
    if repeated:
        print(f"ATTAQUE REUSSIE : {len(repeated)} bloc(s) répété(s) trouvé(s).")
        print("Cela prouve que le mode est ECB (ou qu'il n'y a pas d'IV) : deux blocs de texte clair")
        print("identiques donnent toujours le même bloc chiffré, donc un motif est visible SANS déchiffrer.")
    else:
        print("Aucun bloc répété : soit le message est trop court ou sans répétition,")
        print("soit le mode est CBC/CTR, qui rendent les blocs différents même si le clair se répète.")

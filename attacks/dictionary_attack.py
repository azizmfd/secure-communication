import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.symmetric import aes, kdf
from attacks.common import load_messages

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Essaie une liste de mots de passe courants sur un message AES chiffré avec une clé faible.")
    parser.add_argument("--capture", default="capture.txt")
    parser.add_argument("--wordlist", default="examples/wordlist.txt")
    args = parser.parse_args()

    messages = [m for m in load_messages(args.capture) if m["algorithm"] == "aes"]
    if not messages:
        raise SystemExit(f"Aucun message 'aes' trouvé dans {args.capture}")
    msg = messages[-1]
    ciphertext = bytes.fromhex(msg["ciphertext"])
    mode = msg["mode"]
    iv = bytes.fromhex(msg["iv"]) if "iv" in msg else None
    bits = len(bytes.fromhex(msg["key"])) * 8 if "key" in msg else 128

    with open(args.wordlist, encoding="utf-8") as f:
        words = [w.strip() for w in f if w.strip()]
    print(f"{len(words)} mots de passe à tester, chiffré en AES-{bits} {mode}\n")

    for word in words:
        key = kdf.password_to_key(word, bits)
        try:
            plaintext = aes.decrypt(ciphertext, key, mode, iv)
        except (ValueError, UnicodeDecodeError):
            continue  # mauvais padding ou texte non UTF-8 : ce mot n'est pas la clé
        print(f"MOT DE PASSE TROUVE : « {word} »")
        print(f"Message déchiffré : {plaintext}")
        break
    else:
        print("Aucun mot de la liste ne fonctionne.")

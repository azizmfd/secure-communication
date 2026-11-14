import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.asymmetric import rsa
from network.protocol import KEYS_DIR, key_path

parser = argparse.ArgumentParser()
parser.add_argument("--bits", type=int, default=1024)  # taille de la clé RSA
args = parser.parse_args()

os.makedirs(KEYS_DIR, exist_ok=True)
for name in ("server", "client"):
    print(f"Génération de la paire de clés {name} ({args.bits} bits)...")
    public_key, private_key = rsa.generate_keypair(args.bits)
    rsa.save_key(key_path(f"{name}_pub.txt"), public_key)
    rsa.save_key(key_path(f"{name}_priv.txt"), private_key)
print(f"Terminé. Clés enregistrées dans : {KEYS_DIR}")

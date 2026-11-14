import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.common import load_messages

parser = argparse.ArgumentParser()
parser.add_argument("--capture", default="capture.txt")
args = parser.parse_args()

messages = load_messages(args.capture)
print(f"{len(messages)} message(s) trouvé(s) dans {args.capture}")
for i, msg in enumerate(messages, 1):
    print(f"\n--- Message {i} ---")
    for field in ("algorithm", "key", "mode", "iv", "ciphertext"):
        if field in msg:
            value = str(msg[field])
            print(f"{field:<10}: {value if len(value) <= 70 else value[:70] + '...'}")

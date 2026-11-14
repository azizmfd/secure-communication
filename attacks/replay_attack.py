import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from attacks.common import load_messages

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Renvoie tel quel un message intercepte au serveur : s'il l'accepte une 2e fois, il n'y a pas de protection contre le rejeu.")
    parser.add_argument("--capture", default="capture.txt")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--times", type=int, default=3)  # combien de fois renvoyer le message
    args = parser.parse_args()

    messages = load_messages(args.capture)
    if not messages:
        raise SystemExit(f"Aucun message trouvé dans {args.capture}")
    captured = messages[-1]  # le dernier message intercepté (dict Python)
    import json
    raw = json.dumps(captured)

    print(f"Message intercepté rejoué {args.times} fois, sans le déchiffrer ni le modifier :")
    print(f"  {raw[:100]}...\n")

    for i in range(args.times):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((args.host, args.port))
        s.sendall(raw.encode())
        s.close()
        print(f"  envoi {i + 1}/{args.times} terminé")

    print("\nRegarde le terminal du serveur : si 'Message déchiffré' apparaît plusieurs fois")
    print("pour ce même message, le serveur n'a aucune protection contre le rejeu.")

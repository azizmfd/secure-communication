import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algorithms.asymmetric import rsa
from network.protocol import make_payload, default_key

# Le pirate fabrique sa propre paire de clés et signe avec
_, fake_private = rsa.generate_keypair(1024)
rsa.save_key("/tmp/fake_priv.txt", fake_private)

payload = make_payload("rsa", default_key("rsa"), "Je suis le vrai client (faux !)",
                       sign_key="/tmp/fake_priv.txt")
s = socket.socket()
s.connect(("localhost", 5000))
s.sendall(payload.encode())
s.close()
print("Message avec fausse signature envoyé")

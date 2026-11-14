# Communication Sécurisée Client-Serveur

Projet éducatif : un client chiffre un message avec l'algorithme de son choix et
l'envoie à un serveur (sockets Python, TCP) qui le déchiffre. Le trafic est ensuite
intercepté avec Wireshark et analysé (cryptanalyse).

> Projet pédagogique : les algorithmes écrits à la main ne doivent PAS être utilisés
> en production. Utilisez des bibliothèques éprouvées et des protocoles standards (TLS).

## Structure

```
secure-communication/
├── algorithms/
│   ├── classical/     caesar, substitution, vigenere, playfair, hill
│   ├── symmetric/     aes (ECB, CBC, CTR)
│   ├── asymmetric/    rsa (chiffrement + signatures), dh (Diffie-Hellman)
│   └── hash/          sha256, hmac_sha256
├── network/           server.py, client.py, interactive.py, client_lib.py, protocol.py, keygen.py
├── tests/             tests unitaires, de protocole et réseau
└── examples/
```

## Installation

Python 3 et pycryptodome (utilisé uniquement pour AES) :

```bash
sudo apt install python3-pycryptodome
python3 network/keygen.py        # génère les clés RSA du serveur et du client (dossier keys/)
```

## Utilisation (deux terminaux sur la même machine)

```bash
# Terminal 1
python3 network/server.py --port 5000

# Terminal 2 : menu interactif
python3 network/interactive.py

# ou en ligne de commande
python3 network/client.py --algorithm caesar --key 5 --message "Bonjour"
python3 network/client.py --algorithm aes --mode CBC --bits 256
python3 network/client.py --algorithm rsa --sign
python3 network/client.py --algorithm dh --bits 256
python3 network/client.py --algorithm vigenere --secret monsecret   # + --secret au serveur
```

## Algorithmes

| Famille | Algorithmes | Remarques |
|---|---|---|
| Classique | Caesar, Substitution, Vigenère, Playfair, Hill | écrits à la main |
| Symétrique | AES-128 / AES-256, modes ECB, CBC, CTR | pycryptodome |
| Asymétrique | RSA (chiffrement, signature), Diffie-Hellman | écrits à la main |
| Hachage | SHA-256, HMAC-SHA256 | écrits à la main, comparés à hashlib |

## Format des messages (JSON)

```json
{"algorithm": "aes", "key": "<hex>", "mode": "CBC", "iv": "<hex>",
 "ciphertext": "<hex>", "sha256": "<hash du clair>", "hmac": "...", "signature": "..."}
```

Avec Diffie-Hellman (`--algorithm dh`), le champ `key` disparaît : le client envoie
`dh_public`, et la clé AES est calculée des deux côtés sans jamais circuler.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

## Limites connues (volontaires, étudiées en cryptanalyse)

- Pour les algorithmes classiques et AES « simple », la clé est envoyée dans le JSON.
- RSA « livre » sans padding : le même message donne toujours le même chiffré.
- Diffie-Hellman n'est pas authentifié : vulnérable au man-in-the-middle.
- Le SHA-256 du message en clair est envoyé tel quel : il permet de tester des devinettes.
- Aucune protection contre le rejeu (replay) des messages.

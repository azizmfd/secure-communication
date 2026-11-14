# Secure Client-Server Communication

An educational project implementing a secure communication system between a client and a server in Python, using TCP sockets. The client chooses an encryption algorithm, encrypts a message, and sends it to the server, which decrypts it. The project also includes a full cryptanalysis module: traffic interception and several attacks against each algorithm.

> **Educational project.** The hand-written algorithms here must NOT be used in production. Always use well-tested libraries and standard protocols (TLS, etc.).

## Project structure

## Installation

Requires Python 3 and pycryptodome (used only for AES):

```bash
sudo apt install python3-pycryptodome
python3 network/keygen.py        # generates the server's and client's RSA key pairs (keys/ folder)
```

## Usage (two terminals on the same machine)

```bash
# Terminal 1: start the server
python3 network/server.py --port 5000

# Terminal 2: interactive menu
python3 network/interactive.py

# or from the command line
python3 network/client.py --algorithm caesar --key 5 --message "Hello"
python3 network/client.py --algorithm aes --mode CBC --bits 256
python3 network/client.py --algorithm rsa --sign
python3 network/client.py --algorithm dh --bits 256
python3 network/client.py --algorithm vigenere --secret mysecret   # server must also use --secret
```

A guided demo script that walks through every algorithm is available:
```bash
bash examples/demo.sh
```

## Algorithms implemented

| Family | Algorithms | Notes |
|---|---|---|
| Classical | Caesar, Substitution, Vigenère, Playfair, Hill | hand-written |
| Symmetric | AES-128 / AES-256, modes ECB, CBC, CTR | pycryptodome |
| Asymmetric | RSA (encryption, signature), Diffie-Hellman | hand-written |
| Hashing | SHA-256, HMAC-SHA256 | hand-written, verified against `hashlib` |

## Message format (JSON)

```json
{"algorithm": "aes", "key": "<hex>", "mode": "CBC", "iv": "<hex>",
 "ciphertext": "<hex>", "sha256": "<hash of the plaintext>", "hmac": "...", "signature": "..."}
```

With Diffie-Hellman (`--algorithm dh`), the `key` field disappears: the client sends `dh_public`, and the AES key is computed independently on both sides, never transmitted.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

64 tests covering every algorithm, the protocol, and real client/server network exchanges.

## Cryptanalysis (attacks/)

Traffic is captured locally with `tcpdump` or `Wireshark` (`tcp.port == 5000` on the `lo` interface), then analyzed:

| Script | Attack | Target |
|---|---|---|
| `brute_force.py` | Brute force (26 keys) | Caesar |
| `frequency.py` | Letter frequency analysis | Caesar |
| `substitution_attack.py` | Frequency analysis + hill-climbing | Substitution |
| `vigenere_attack.py` | Index of coincidence + per-column frequency | Vigenère |
| `hill_known_plaintext.py` | Known-plaintext attack | Hill |
| `ecb_pattern.py` | Detection of repeated ciphertext blocks | AES-ECB |
| `dictionary_attack.py` | Dictionary attack against a password-derived key | AES (weak key) |
| `replay_attack.py` | Replays a captured message | Any algorithm |

Example:
```bash
sudo tcpdump -i lo -A -s 0 'tcp port 5000' > capture.txt
python3 network/client.py --algorithm caesar --key 7 --message "$(cat examples/message.txt)"
python3 attacks/brute_force.py --capture capture.txt
```

## Known limitations (intentional, studied through cryptanalysis)

- For classical algorithms and plain AES, the key is sent inside the JSON message.
- RSA is "textbook" RSA (no padding): the same message always produces the same ciphertext.
- Diffie-Hellman alone is not authenticated: vulnerable to man-in-the-middle attacks.
- The SHA-256 hash of the plaintext is sent as-is: it can be used to test guesses.
- No protection against message replay.

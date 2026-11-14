import secrets
from math import gcd

from algorithms.hash import sha256

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n, rounds=40):
    """Test de Miller-Rabin : répond 'premier' avec une erreur négligeable."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    # On écrit n - 1 = d * 2^r avec d impair
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # témoin aléatoire entre 2 et n-2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # a prouve que n est composé
    return True


def generate_prime(bits):
    """Nombre premier aléatoire de 'bits' bits."""
    while True:
        # On force les 2 bits de poids fort (taille exacte) et le dernier bit (impair)
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_prime(candidate):
            return candidate


def generate_keypair(bits=1024, e=65537):
    """Retourne (clé_publique, clé_privée) = ((e, n), (d, n))."""
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:  # e doit être inversible modulo phi
            break
    n = p * q
    d = pow(e, -1, phi)  # inverse de e modulo phi
    return (e, n), (d, n)


# ---------- Sauvegarde / lecture des clés ----------

def key_to_str(key):
    """(e, n) -> 'e:n' en hexadécimal."""
    return f"{key[0]:x}:{key[1]:x}"


def key_from_str(text):
    a, b = text.strip().split(":")
    return int(a, 16), int(b, 16)


def save_key(path, key):
    with open(path, "w") as f:
        f.write(key_to_str(key))


def load_key(path):
    with open(path) as f:
        return key_from_str(f.read())


# ---------- Chiffrement ----------

def _block_sizes(n):
    """(octets de message par bloc, octets d'un bloc chiffré)."""
    k = (n.bit_length() - 1) // 8
    if k < 2:
        raise ValueError("Clé trop courte")
    return k - 1, (n.bit_length() + 7) // 8


def encrypt(text, public_key):
    """Chiffre un texte, retourne l'hexadécimal."""
    e, n = public_key
    chunk_size, block_len = _block_sizes(n)
    data = text.encode("utf-8")
    result = b""
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        # Le 0x01 devant garde les zéros du début et reste plus petit que n
        m = int.from_bytes(b"\x01" + chunk, "big")
        c = pow(m, e, n)  # c = m^e mod n
        result += c.to_bytes(block_len, "big")
    return result.hex()


def decrypt(cipher_hex, private_key):
    d, n = private_key
    _, block_len = _block_sizes(n)
    raw = bytes.fromhex(cipher_hex)
    if len(raw) % block_len != 0:
        raise ValueError("Message chiffré invalide (taille)")
    data = b""
    for i in range(0, len(raw), block_len):
        c = int.from_bytes(raw[i:i + block_len], "big")
        m = pow(c, d, n)  # m = c^d mod n
        block = m.to_bytes((m.bit_length() + 7) // 8, "big")
        if not block or block[0] != 1:
            raise ValueError("Déchiffrement invalide (mauvaise clé ?)")
        data += block[1:]
    return data.decode("utf-8")


# ---------- Signature ----------

def sign(text, private_key):
    """Signature = (SHA-256 du message) élevé à la puissance d, modulo n."""
    d, n = private_key
    if n.bit_length() <= 256:
        raise ValueError("Clé trop courte pour signer un SHA-256 (il faut > 256 bits)")
    h = int(sha256.sha256_hex(text), 16)
    return f"{pow(h, d, n):x}"


def verify(text, signature_hex, public_key):
    """Vrai si la signature correspond bien au message."""
    e, n = public_key
    h = int(sha256.sha256_hex(text), 16)
    try:
        return pow(int(signature_hex, 16), e, n) == h  # signature^e mod n doit redonner le hash
    except ValueError:
        return False

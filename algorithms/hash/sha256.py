import struct
from math import isqrt

MASK = 0xFFFFFFFF  # on travaille sur 32 bits


def _first_primes(n):
    """Les n premiers nombres premiers (2, 3, 5, 7, ...)."""
    primes = []
    candidate = 2
    while len(primes) < n:
        if all(candidate % p != 0 for p in primes):
            primes.append(candidate)
        candidate += 1
    return primes


def _icbrt(n):
    """Racine cubique entière (par dichotomie)."""
    low, high = 0, 1 << (n.bit_length() // 3 + 1)
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** 3 <= n:
            low = mid
        else:
            high = mid - 1
    return low


_PRIMES = _first_primes(64)
# Valeurs de départ : 32 premiers bits de la partie décimale de la racine carrée
# des 8 premiers nombres premiers.
_H0 = [isqrt(p << 64) & MASK for p in _PRIMES[:8]]
# Constantes : idem avec la racine cubique des 64 premiers nombres premiers.
_K = [_icbrt(p << 96) & MASK for p in _PRIMES]


def _rotr(x, n):
    """Rotation de x de n bits vers la droite (sur 32 bits)."""
    return ((x >> n) | (x << (32 - n))) & MASK


def _pad(data):
    """Ajoute 0x80, des zéros, puis la longueur du message en bits (8 octets)."""
    length_bits = len(data) * 8
    data += b"\x80"
    while len(data) % 64 != 56:
        data += b"\x00"
    return data + length_bits.to_bytes(8, "big")


def sha256(data):
    """Prend des octets, retourne le hash (32 octets)."""
    h = list(_H0)
    data = _pad(data)
    for start in range(0, len(data), 64):  # un bloc de 64 octets à la fois
        chunk = data[start:start + 64]
        w = list(struct.unpack(">16I", chunk))
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)

        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + S1 + ch + _K[i] + w[i]) & MASK
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & MASK
            hh, g, f = g, f, e
            e = (d + temp1) & MASK
            d, c, b = c, b, a
            a = (temp1 + temp2) & MASK

        h = [(x + y) & MASK for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def sha256_hex(text):
    """Pratique : accepte un texte (str) ou des octets, retourne l'hexadécimal."""
    if isinstance(text, str):
        text = text.encode("utf-8")
    return sha256(text).hex()

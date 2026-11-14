import secrets

from algorithms.hash import sha256

# Module p : nombre premier "sûr" de 1024 bits (p = 2q + 1 avec q aussi premier).
# En vrai on utilise au moins 2048 bits (groupes standardisés RFC 3526 / RFC 7919).
P = int(
    "ea7b7198f61108c21b72e0b76c02b8242eaed9e5b27257a39ab6369886320f41"
    "5d55ff511382e0de4ad25511912976ccbc7a72037a9dc642eff848ec531d575a"
    "7080aaf39364d3159c9bbc1f0dc55706bbfcbb28e0db9a4196bd68e3973f6795"
    "09539083a41a610e95303d775427581a7a0b5e828825d2e8566445b097e1ae4f",
    16,
)
Q = (P - 1) // 2  # ordre du sous-groupe utilisé
G = 2             # générateur (2 est un résidu quadratique pour ce p)


def generate_private():
    """Exposant secret aléatoire (a ou b)."""
    return secrets.randbelow(Q - 2) + 2


def public_value(private):
    """Valeur publique A = g^a mod p (ou B = g^b mod p)."""
    return pow(G, private, P)


def shared_secret(private, other_public):
    """Secret partagé = (valeur publique de l'autre)^(mon secret) mod p."""
    # On refuse les valeurs dangereuses (1, p-1, hors du sous-groupe...)
    if not 2 <= other_public <= P - 2 or pow(other_public, Q, P) != 1:
        raise ValueError("Valeur publique Diffie-Hellman invalide")
    return pow(other_public, private, P)


def derive_key(secret, nbytes=16):
    """Transforme le grand secret partagé en clé AES (16 octets = AES-128, 32 = AES-256)."""
    if nbytes not in (16, 32):
        raise ValueError("nbytes doit valoir 16 ou 32")
    secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
    return sha256.sha256(secret_bytes)[:nbytes]

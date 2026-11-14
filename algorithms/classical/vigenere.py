def _clean_key(key):
    key = key.upper()
    # La clé doit être un mot : seulement des lettres A-Z, non vide
    if not key or not all("A" <= c <= "Z" for c in key):
        raise ValueError("Clé invalide : uniquement des lettres A-Z (ex: LEMON)")
    return key


def _process(text, key, sign):
    """sign = +1 pour chiffrer, -1 pour déchiffrer."""
    key = _clean_key(key)
    result = []
    i = 0  # position dans la clé : n'avance que sur les lettres
    for c in text:
        if "A" <= c <= "Z":
            base = ord("A")
        elif "a" <= c <= "z":
            base = ord("a")
        else:
            result.append(c)  # espace, ponctuation... : inchangé, la clé n'avance pas
            continue
        # Décalage = position de la lettre de la clé (A=0, B=1 ... Z=25)
        shift = (ord(key[i % len(key)]) - ord("A")) * sign
        result.append(chr((ord(c) - base + shift) % 26 + base))
        i += 1
    return "".join(result)


def encrypt(text, key):
    return _process(text, key, +1)


def decrypt(text, key):
    return _process(text, key, -1)

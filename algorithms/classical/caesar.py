def _shift_char(c, shift):
    """Décale un seul caractère. Ce qui n'est pas une lettre reste inchangé."""
    if "A" <= c <= "Z":
        base = ord("A")
    elif "a" <= c <= "z":
        base = ord("a")
    else:
        return c  # espaces, chiffres, ponctuation, accents : on ne touche pas
    # ord(c) - base : position de la lettre (A=0 ... Z=25)
    # + shift       : on décale
    # % 26          : si on dépasse Z, on revient à A
    return chr((ord(c) - base + shift) % 26 + base)


def encrypt(text, shift):
    return "".join(_shift_char(c, shift) for c in text)


def decrypt(text, shift):
    # Déchiffrer = décaler dans l'autre sens
    return encrypt(text, -shift)

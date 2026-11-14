ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 lettres, pas de J


def _clean(text):
    """Majuscules, J devient I, on garde seulement les lettres A-Z."""
    text = text.upper().replace("J", "I")
    return "".join(c for c in text if "A" <= c <= "Z")


def build_matrix(key):
    key = _clean(key)
    if not key:
        raise ValueError("Clé invalide : il faut au moins une lettre")
    letters = []
    for c in key + ALPHABET:  # d'abord la clé, puis le reste de l'alphabet
        if c not in letters:  # sans doublon
            letters.append(c)
    # On découpe la liste de 25 lettres en 5 lignes de 5
    return [letters[i:i + 5] for i in range(0, 25, 5)]


def _find(matrix, c):
    """Retourne (ligne, colonne) d'une lettre dans la grille."""
    for r, row in enumerate(matrix):
        if c in row:
            return r, row.index(c)


def _make_pairs(text):
    """Coupe le texte en paires, en insérant X entre deux lettres identiques."""
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        filler = "X" if a != "X" else "Q"
        b = text[i + 1] if i + 1 < len(text) else filler
        if a == b:
            pairs.append((a, filler))  # lettres doubles : on insère le filler
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def _convert_pair(matrix, a, b, step):
    """step = +1 pour chiffrer (droite/bas), -1 pour déchiffrer (gauche/haut)."""
    ra, ca = _find(matrix, a)
    rb, cb = _find(matrix, b)
    if ra == rb:  # même ligne
        return matrix[ra][(ca + step) % 5], matrix[rb][(cb + step) % 5]
    if ca == cb:  # même colonne
        return matrix[(ra + step) % 5][ca], matrix[(rb + step) % 5][cb]
    # rectangle : on échange les colonnes
    return matrix[ra][cb], matrix[rb][ca]


def encrypt(text, key):
    matrix = build_matrix(key)
    pairs = _make_pairs(_clean(text))
    return "".join("".join(_convert_pair(matrix, a, b, +1)) for a, b in pairs)


def decrypt(text, key):
    matrix = build_matrix(key)
    text = _clean(text)
    if len(text) % 2 != 0:
        raise ValueError("Texte chiffré invalide : nombre de lettres impair")
    pairs = [(text[i], text[i + 1]) for i in range(0, len(text), 2)]
    return "".join("".join(_convert_pair(matrix, a, b, -1)) for a, b in pairs)

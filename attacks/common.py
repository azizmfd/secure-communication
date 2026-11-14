import json
import re

# Fréquence (en %) de chaque lettre dans un texte français
FRENCH_FREQ = {
    "A": 7.636, "B": 0.901, "C": 3.260, "D": 3.669, "E": 14.715, "F": 1.066,
    "G": 0.866, "H": 0.737, "I": 7.529, "J": 0.613, "K": 0.049, "L": 5.456,
    "M": 2.968, "N": 7.095, "O": 5.796, "P": 2.521, "Q": 1.362, "R": 6.693,
    "S": 7.948, "T": 7.244, "U": 6.311, "V": 1.838, "W": 0.074, "X": 0.427,
    "Y": 0.128, "Z": 0.326,
}

# Mots très courants : s'ils apparaissent, le texte déchiffré est probablement du français
COMMON_WORDS = {
    "le", "la", "les", "de", "des", "du", "un", "une", "et", "est", "que", "qui",
    "dans", "pour", "pas", "sur", "au", "aux", "ce", "se", "en", "ne", "nous",
    "vous", "il", "elle", "ont", "par", "mais", "ou", "donc", "plus", "cette", "comme",
}


def load_messages(path):
    """Extrait les messages JSON d'une capture (tcpdump -A, ou 'Follow TCP Stream' de Wireshark)."""
    with open(path, "rb") as f:
        content = f.read().decode("latin-1")  # latin-1 accepte n'importe quel octet
    messages = []
    for match in re.finditer(r'\{"algorithm"[^{}]*\}', content):
        try:
            messages.append(json.loads(match.group(0)))
        except json.JSONDecodeError:
            pass  # JSON coupé ou abîmé : on l'ignore
    return messages


def get_ciphertext(algorithm, capture=None, text=None):
    """Retourne le texte chiffré : soit donné directement, soit le dernier de la capture."""
    if text:
        return text
    messages = [m for m in load_messages(capture) if m["algorithm"] == algorithm]
    if not messages:
        raise SystemExit(f"Aucun message '{algorithm}' trouvé dans {capture}")
    return messages[-1]["ciphertext"]


def letters_only(text):
    """Garde seulement les lettres A-Z, en majuscules."""
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def chi_squared(text):
    """Distance entre les fréquences du texte et celles du français (petit = ressemble au français)."""
    letters = letters_only(text)
    if not letters:
        return float("inf")
    total = 0.0
    for letter, freq in FRENCH_FREQ.items():
        expected = len(letters) * freq / 100
        observed = letters.count(letter)
        total += (observed - expected) ** 2 / expected
    return total


def is_valid_text(text):
    """Vrai si le texte contient au moins 3 mots courants du français."""
    words = re.findall(r"[a-zàâçéèêëîïôûù]+", text.lower())
    return sum(1 for w in words if w in COMMON_WORDS) >= 3

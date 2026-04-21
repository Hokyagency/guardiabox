"""
Module password — vérification de la robustesse des mots de passe.

Évalue la solidité d'un mot de passe en contrôlant :
- Sa longueur minimale.
- La présence de majuscules, minuscules, chiffres et caractères spéciaux.
- Son entropie estimée en bits (résistance aux attaques par force brute).
"""

import math
import re
import string

# --- Seuils de sécurité ---
MIN_LENGTH: int = 12
MIN_ENTROPY_BITS: float = 50.0


def calculate_entropy(password: str) -> float:
    """Calcule l'entropie estimée d'un mot de passe en bits.

    L'entropie est calculée selon la formule :
    ``H = len(password) * log2(taille_alphabet)``
    où l'alphabet est estimé d'après les catégories de caractères présentes.

    Args:
        password: Le mot de passe à évaluer.

    Returns:
        L'entropie en bits (``float``). Vaut ``0.0`` si le mot de passe est vide.
    """
    if not password:
        return 0.0

    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[^\w\s]", password):
        charset_size += len(string.punctuation)

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)


def check_password_strength(password: str) -> tuple[bool, list[str]]:
    """Vérifie si un mot de passe respecte les critères de sécurité.

    Critères vérifiés :
    - Longueur minimale (:data:`MIN_LENGTH` caractères).
    - Présence d'au moins une lettre minuscule.
    - Présence d'au moins une lettre majuscule.
    - Présence d'au moins un chiffre.
    - Présence d'au moins un caractère spécial.
    - Entropie minimale (:data:`MIN_ENTROPY_BITS` bits).

    Args:
        password: Le mot de passe à évaluer.

    Returns:
        Un tuple ``(is_strong, issues)`` où ``is_strong`` est ``True``
        si tous les critères sont satisfaits, et ``issues`` est la liste
        des problèmes détectés (vide si le mot de passe est robuste).
    """
    issues: list[str] = []

    if len(password) < MIN_LENGTH:
        issues.append(
            f"Le mot de passe doit contenir au moins {MIN_LENGTH} caractères."
        )

    if not re.search(r"[a-z]", password):
        issues.append("Le mot de passe doit contenir au moins une lettre minuscule.")

    if not re.search(r"[A-Z]", password):
        issues.append("Le mot de passe doit contenir au moins une lettre majuscule.")

    if not re.search(r"\d", password):
        issues.append("Le mot de passe doit contenir au moins un chiffre.")

    if not re.search(r"[^\w\s]", password):
        issues.append(
            "Le mot de passe doit contenir au moins un caractère spécial "
            "(ex. : ! @ # $ % ^ & *)."
        )

    entropy = calculate_entropy(password)
    if entropy < MIN_ENTROPY_BITS:
        issues.append(
            f"Entropie insuffisante ({entropy:.1f} bits, minimum requis : "
            f"{MIN_ENTROPY_BITS} bits). Allongez ou diversifiez votre mot de passe."
        )

    return len(issues) == 0, issues

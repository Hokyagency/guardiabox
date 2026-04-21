"""
Module crypto — chiffrement et déchiffrement AES-256-GCM.

Implémente :
- La dérivation de clé via PBKDF2-HMAC-SHA256.
- Le chiffrement authentifié AES-256-GCM.
- Le déchiffrement avec vérification d'intégrité (tag GCM).

Format du fichier chiffré (concaténation binaire) :
    [16 octets salt][12 octets nonce][N octets ciphertext + 16 octets tag]
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Constantes cryptographiques ---
SALT_SIZE: int = 16          # Taille du sel en octets
NONCE_SIZE: int = 12         # Taille du nonce GCM recommandée (96 bits)
KEY_SIZE: int = 32           # Clé AES-256 (256 bits)
TAG_SIZE: int = 16           # Tag d'authentification GCM (128 bits)
PBKDF2_ITERATIONS: int = 600_000  # NIST SP 800-132 recommande ≥ 210 000 pour SHA-256

# Taille minimale d'un fichier chiffré valide
MIN_ENCRYPTED_SIZE: int = SALT_SIZE + NONCE_SIZE + TAG_SIZE


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Dérive une clé AES-256 depuis un mot de passe via PBKDF2-HMAC-SHA256.

    Args:
        password: Le mot de passe en clair fourni par l'utilisateur.
        salt: Un sel aléatoire de :data:`SALT_SIZE` octets.
        iterations: Nombre d'itérations PBKDF2 (par défaut :data:`PBKDF2_ITERATIONS`).

    Returns:
        Une clé de :data:`KEY_SIZE` octets prête à être utilisée avec AES.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, password: str) -> bytes:
    """Chiffre des données avec AES-256-GCM.

    Génère un sel et un nonce aléatoires à chaque appel, garantissant
    que deux chiffrements du même texte produisent des résultats différents.

    Args:
        data: Les données en clair à chiffrer.
        password: Le mot de passe fourni par l'utilisateur.

    Returns:
        Les données chiffrées au format :
        ``salt (16B) + nonce (12B) + ciphertext + tag (16B)``.
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    # encrypt() retourne ciphertext + tag (16 octets) concaténés
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)

    return salt + nonce + ciphertext_with_tag


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """Déchiffre des données chiffrées avec :func:`encrypt_data`.

    Vérifie l'intégrité via le tag GCM : toute altération ou mauvais mot
    de passe lève une exception.

    Args:
        encrypted_data: Les données au format
            ``salt + nonce + ciphertext + tag``.
        password: Le mot de passe fourni par l'utilisateur.

    Returns:
        Les données déchiffrées en clair.

    Raises:
        ValueError: Si les données sont trop courtes pour être valides.
        InvalidTag: Si le mot de passe est incorrect ou les données corrompues.
    """
    if len(encrypted_data) < MIN_ENCRYPTED_SIZE:
        raise ValueError(
            "Données chiffrées trop courtes ou corrompues "
            f"(minimum {MIN_ENCRYPTED_SIZE} octets requis)."
        )

    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext_with_tag = encrypted_data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # Lève InvalidTag si le mot de passe est erroné ou les données altérées
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

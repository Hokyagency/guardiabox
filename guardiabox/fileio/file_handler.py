"""
Module file_handler — manipulation sécurisée des fichiers.

Fournit des fonctions de lecture/écriture avec validation des chemins
afin de prévenir les attaques de type Path Traversal.
"""

import os
import sys
from pathlib import Path


def validate_path(file_path: str) -> Path:
    """Valide un chemin de fichier et prévient les injections de chemin.

    Vérifie l'absence de séquences ``..`` (path traversal) et de
    caractères nuls dans le chemin fourni.

    Args:
        file_path: Le chemin à valider (relatif ou absolu).

    Returns:
        Un objet :class:`pathlib.Path` normalisé.

    Raises:
        ValueError: Si le chemin contient ``..`` ou un octet nul.
    """
    if "\x00" in file_path:
        raise ValueError("Le chemin contient des caractères invalides (octet nul).")

    normalized = Path(os.path.normpath(file_path))

    if ".." in normalized.parts:
        raise ValueError(
            f"Chemin invalide (tentative de traversal détectée) : '{file_path}'"
        )

    return normalized


def read_file_bytes(file_path: str) -> bytes:
    """Lit et retourne le contenu binaire d'un fichier.

    Args:
        file_path: Le chemin vers le fichier à lire.

    Returns:
        Le contenu du fichier sous forme de ``bytes``.

    Raises:
        ValueError: Si le chemin est invalide.
        FileNotFoundError: Si le fichier est introuvable.
        IsADirectoryError: Si le chemin désigne un répertoire.
    """
    path = validate_path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Le fichier '{path}' est introuvable.")

    if not path.is_file():
        raise IsADirectoryError(f"'{path}' est un répertoire, pas un fichier.")

    with open(path, "rb") as file_obj:
        return file_obj.read()


def write_file_bytes(file_path: str, data: bytes) -> None:
    """Écrit des données binaires dans un fichier.

    Crée les répertoires parents si nécessaire.

    Args:
        file_path: Le chemin de destination.
        data: Les données binaires à écrire.

    Raises:
        ValueError: Si le chemin est invalide.
    """
    path = validate_path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform != "win32":
        old_mask = os.umask(0o077)
    try:
        with open(path, "wb") as file_obj:
            file_obj.write(data)
    finally:
        if sys.platform != "win32":
            os.umask(old_mask)


def write_text_file(file_path: str, content: str) -> None:
    """Écrit une chaîne de caractères dans un fichier texte (UTF-8).

    Crée les répertoires parents si nécessaire.

    Args:
        file_path: Le chemin de destination.
        content: Le contenu textuel à écrire.

    Raises:
        ValueError: Si le chemin est invalide.
    """
    path = validate_path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform != "win32":
        old_mask = os.umask(0o077)
    try:
        with open(path, "w", encoding="utf-8") as file_obj:
            file_obj.write(content)
    finally:
        if sys.platform != "win32":
            os.umask(old_mask)

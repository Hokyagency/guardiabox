"""
Module console — interface utilisateur en mode console pour GuardiaBox.

Gère l'affichage des menus, la saisie utilisateur et orchestre les
flux de chiffrement et de déchiffrement.
"""

import getpass
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag

from fileio.file_handler import (
    read_file_bytes,
    validate_path,
    write_file_bytes,
    write_text_file,
)
from security.crypto import decrypt_data, encrypt_data
from security.password import check_password_strength
from storage.history import record_operation, sha256_of

# Extensions utilisées pour les fichiers chiffrés et déchiffrés
ENCRYPTED_EXT: str = ".crypt"
DECRYPTED_EXT: str = ".decrypt"


# ---------------------------------------------------------------------------
# Affichage
# ---------------------------------------------------------------------------

def clear_screen() -> None:
    """Efface l'écran du terminal (Windows et Unix)."""
    os.system("cls" if os.name == "nt" else "clear")


def display_banner() -> None:
    """Affiche la bannière de l'application."""
    print("=" * 52)
    print("       GUARDIABOX — Coffre-Fort Numérique")
    print("=" * 52)
    print()


def display_menu() -> None:
    """Affiche le menu principal."""
    print("  1. Chiffrer un fichier ou un message")
    print("  2. Déchiffrer un fichier (.crypt)")
    print("  3. Quitter")
    print()


# ---------------------------------------------------------------------------
# Saisie et validation
# ---------------------------------------------------------------------------

def get_user_choice(
    prompt: str = "Votre choix : ",
    valid_choices: tuple[str, ...] = ("1", "2", "3"),
) -> str:
    """Invite l'utilisateur à choisir une option et valide la saisie.

    Args:
        prompt: Message affiché avant la saisie.
        valid_choices: Tuple des valeurs acceptées.

    Returns:
        Le choix validé de l'utilisateur.
    """
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        print(f"Choix invalide. Options disponibles : {', '.join(valid_choices)}\n")


def _prompt_password(confirm: bool = False) -> str | None:
    """Invite l'utilisateur à saisir un mot de passe.

    En mode ``confirm=True``, vérifie la robustesse du mot de passe et
    demande une confirmation.

    Args:
        confirm: Si ``True``, applique les vérifications de robustesse
                 et demande une saisie de confirmation.

    Returns:
        Le mot de passe saisi, ou ``None`` si l'utilisateur abandonne.
    """
    while True:
        password = getpass.getpass("Mot de passe : ")

        if not password:
            print("Le mot de passe ne peut pas être vide.\n")
            continue

        if confirm:
            is_strong, issues = check_password_strength(password)
            if not is_strong:
                print("\nMot de passe insuffisamment robuste :")
                for issue in issues:
                    print(f"  • {issue}")
                print()
                continue

            confirm_pwd = getpass.getpass("Confirmez le mot de passe : ")
            if password != confirm_pwd:
                print("Les mots de passe ne correspondent pas. Réessayez.\n")
                continue

        return password


def _choose_source() -> str:
    """Demande à l'utilisateur ce qu'il souhaite chiffrer.

    Returns:
        ``"1"`` pour un message texte, ``"2"`` pour un fichier existant.
    """
    print("\nQue souhaitez-vous chiffrer ?")
    print("  1. Un message texte")
    print("  2. Un fichier existant")
    return get_user_choice(valid_choices=("1", "2"))


# ---------------------------------------------------------------------------
# Flux de chiffrement
# ---------------------------------------------------------------------------

def encrypt_flow() -> None:
    """Orchestre le flux complet de chiffrement.

    Selon le choix de l'utilisateur :
    - Saisie d'un message → sauvegarde dans un ``.txt`` → chiffrement.
    - Sélection d'un fichier existant → chiffrement direct.

    Le fichier chiffré est sauvegardé avec l'extension ``.crypt``.
    """
    print("\n--- CHIFFREMENT ---\n")

    source_choice = _choose_source()
    data: bytes
    source_file: str

    if source_choice == "1":
        # --- Chiffrement d'un message texte ---
        message = input("\nSaisissez votre message : ").strip()
        if not message:
            print("Le message ne peut pas être vide.")
            return

        output_name = input(
            "Nom du fichier de sortie (sans extension) : "
        ).strip()
        if not output_name:
            print("Le nom ne peut pas être vide.")
            return

        try:
            validate_path(output_name)
        except ValueError as exc:
            print(f"Nom de fichier invalide : {exc}")
            return

        source_file = f"{output_name}.txt"
        try:
            write_text_file(source_file, message)
        except (ValueError, OSError) as exc:
            print(f"Impossible de créer le fichier texte : {exc}")
            return

        print(f"Message sauvegardé dans '{source_file}'.")
        data = message.encode("utf-8")

    else:
        # --- Chiffrement d'un fichier existant ---
        file_path = input("\nChemin du fichier à chiffrer : ").strip()
        try:
            data = read_file_bytes(file_path)
            source_file = file_path
        except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
            print(f"Erreur : {exc}")
            return

    # --- Saisie et vérification du mot de passe ---
    password = _prompt_password(confirm=True)
    if password is None:
        return

    # --- Chiffrement ---
    try:
        encrypted = encrypt_data(data, password)
    except Exception as exc:
        print(f"Erreur lors du chiffrement : {exc}")
        try:
            record_operation("CHIFFREMENT", source_file, "", sha256_of(data), "ERREUR", str(exc))
        except Exception:
            pass
        return

    output_path = source_file + ENCRYPTED_EXT
    try:
        write_file_bytes(output_path, encrypted)
    except (ValueError, OSError) as exc:
        print(f"Impossible d'écrire le fichier chiffré : {exc}")
        try:
            record_operation("CHIFFREMENT", source_file, output_path, sha256_of(data), "ERREUR", str(exc))
        except Exception:
            pass
        return

    print(f"\n✓ Fichier chiffré avec succès : '{output_path}'")
    try:
        record_operation("CHIFFREMENT", source_file, output_path, sha256_of(data), "SUCCES")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Flux de déchiffrement
# ---------------------------------------------------------------------------

def decrypt_flow() -> None:
    """Orchestre le flux complet de déchiffrement.

    Lit un fichier ``.crypt``, dérive la clé depuis le mot de passe et
    le sel stocké, vérifie l'intégrité via le tag AES-GCM, puis :
    - Affiche le contenu si c'est du texte UTF-8.
    - Ou sauvegarde le fichier déchiffré avec l'extension ``.decrypt``.
    """
    print("\n--- DÉCHIFFREMENT ---\n")

    file_path = input("Chemin du fichier chiffré (.crypt) : ").strip()
    try:
        encrypted_data = read_file_bytes(file_path)
    except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
        print(f"Erreur : {exc}")
        return

    password = _prompt_password(confirm=False)
    if password is None:
        return

    # --- Déchiffrement ---
    try:
        decrypted = decrypt_data(encrypted_data, password)
    except InvalidTag:
        print(
            "\n✗ Échec du déchiffrement : mot de passe incorrect ou fichier corrompu."
        )
        try:
            record_operation("DECHIFFREMENT", file_path, "", sha256_of(encrypted_data), "ERREUR", "InvalidTag : mot de passe incorrect ou fichier corrompu")
        except Exception:
            pass
        return
    except ValueError as exc:
        print(f"\n✗ Données invalides : {exc}")
        try:
            record_operation("DECHIFFREMENT", file_path, "", sha256_of(encrypted_data), "ERREUR", str(exc))
        except Exception:
            pass
        return
    except Exception as exc:
        print(f"\n✗ Erreur inattendue lors du déchiffrement : {exc}")
        try:
            record_operation("DECHIFFREMENT", file_path, "", sha256_of(encrypted_data), "ERREUR", str(exc))
        except Exception:
            pass
        return

    # --- Détermination du chemin de sortie ---
    path_obj = Path(file_path)
    base = str(path_obj.with_suffix("")) if path_obj.suffix == ENCRYPTED_EXT else file_path

    # Tentative d'affichage en texte clair
    try:
        text = decrypted.decode("utf-8")
        print(f"\n✓ Contenu déchiffré :\n{'─' * 40}")
        print(text)
        print("─" * 40)
    except UnicodeDecodeError:
        text = None

    # Sauvegarde du fichier déchiffré dans tous les cas
    output_path = base + DECRYPTED_EXT
    try:
        write_file_bytes(output_path, decrypted)
        print(f"\n✓ Fichier déchiffré sauvegardé : '{output_path}'")
        try:
            record_operation("DECHIFFREMENT", file_path, output_path, sha256_of(encrypted_data), "SUCCES")
        except Exception:
            pass
    except (ValueError, OSError) as exc:
        print(f"Impossible de sauvegarder le fichier déchiffré : {exc}")
        try:
            record_operation("DECHIFFREMENT", file_path, output_path, sha256_of(encrypted_data), "ERREUR", str(exc))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Boucle principale
# ---------------------------------------------------------------------------

def run_menu() -> None:
    """Lance la boucle principale du menu console de GuardiaBox."""
    while True:
        clear_screen()
        display_banner()
        display_menu()

        choice = get_user_choice()

        if choice == "1":
            encrypt_flow()
        elif choice == "2":
            decrypt_flow()
        elif choice == "3":
            print("\nAu revoir !\n")
            break

        input("\nAppuyez sur Entrée pour continuer...")

"""
setup_launcher.py — Script de packaging GuardiaBox avec PyInstaller.

Génère un exécutable Windows autonome (.exe) qui inclut :
- L'application GuardiaBox (GUI PyQt6).
- Toutes les dépendances (cryptography, PyQt6, etc.).
- Les ressources nécessaires.

Usage :
    pip install pyinstaller
    python setup_launcher.py

L'exécutable sera généré dans : guardiabox/dist/GuardiaBox/GuardiaBox.exe
"""

import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_NAME = "GuardiaBox"
MAIN_SCRIPT = "main.py"
ICON_PATH = None          # Remplacez par "assets/icon.ico" si vous avez une icône

# Répertoires à inclure comme données (source, destination_dans_exe)
DATAS: list[tuple[str, str]] = []

# Modules cachés que PyInstaller peut manquer
HIDDEN_IMPORTS: list[str] = [
    "cryptography",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.primitives.hashes",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
]

# ---------------------------------------------------------------------------
# Construction de la commande PyInstaller
# ---------------------------------------------------------------------------

def build_command() -> list[str]:
    """Construit la liste d'arguments pour PyInstaller."""
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", APP_NAME,
        "--onedir",          # Dossier unique (plus rapide au démarrage que --onefile)
        "--windowed",        # Pas de fenêtre console (mode GUI)
        "--noconfirm",       # Écrase sans demander
        "--clean",           # Nettoie le cache avant build
    ]

    if ICON_PATH and Path(ICON_PATH).exists():
        cmd += ["--icon", ICON_PATH]

    for src, dst in DATAS:
        cmd += ["--add-data", f"{src};{dst}"]

    for module in HIDDEN_IMPORTS:
        cmd += ["--hidden-import", module]

    cmd.append(MAIN_SCRIPT)
    return cmd


def main() -> None:
    """Lance le build PyInstaller."""
    root = Path(__file__).parent
    print(f"[GuardiaBox] Répertoire de travail : {root}")
    print(f"[GuardiaBox] Script principal      : {MAIN_SCRIPT}")
    print(f"[GuardiaBox] Nom de l'exécutable   : {APP_NAME}.exe")
    print("[GuardiaBox] Démarrage du packaging…\n")

    cmd = build_command()

    try:
        result = subprocess.run(cmd, cwd=str(root), check=True)
    except subprocess.CalledProcessError as exc:
        print(f"\n[ERREUR] PyInstaller a échoué (code {exc.returncode}).")
        print("Vérifiez que PyInstaller est installé : pip install pyinstaller")
        sys.exit(exc.returncode)
    except FileNotFoundError:
        print("\n[ERREUR] Python ou PyInstaller introuvable.")
        print("Installez PyInstaller : pip install pyinstaller")
        sys.exit(1)

    exe_path = root / "dist" / APP_NAME / f"{APP_NAME}.exe"
    if exe_path.exists():
        print(f"\n[OK] Exécutable généré avec succès :\n     {exe_path}")
        print(
            "\nVous pouvez distribuer le dossier entier :\n"
            f"  dist/{APP_NAME}/\n"
        )
    else:
        print("\n[ATTENTION] Build terminé mais l'exécutable est introuvable.")
        print(f"  Chemin attendu : {exe_path}")


if __name__ == "__main__":
    main()

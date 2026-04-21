"""
GuardiaBox — Point d'entrée principal de l'application.

Comportement par défaut : lance l'interface graphique (PyQt6).
Option ``--console`` : lance l'interface texte en mode terminal.

Usage :
    python main.py           # GUI (défaut)
    python main.py --console # Console
    python main.py --gui     # GUI (explicite)
"""

import sys


def main() -> None:
    """Lance GuardiaBox en mode GUI (défaut) ou console (--console)."""
    args = [a.lower() for a in sys.argv[1:]]

    if "--console" in args:
        from ui.console import run_menu
        run_menu()
    else:
        # Mode GUI par défaut (--gui ou aucun argument)
        try:
            from ui.gui import run_gui
            run_gui()
        except ImportError as exc:
            print(
                f"[ERREUR] Impossible de lancer l'interface graphique : {exc}\n"
                "Assurez-vous que PyQt6 est installé : pip install PyQt6\n"
                "Ou lancez en mode console : python main.py --console"
            )
            sys.exit(1)


if __name__ == "__main__":
    main()

"""
conftest.py — Configuration Pytest pour GuardiaBox.

Ajoute la racine du projet au sys.path afin que les imports
(fileio, security, ui) fonctionnent correctement lors des tests.
"""

import sys
from pathlib import Path

# Racine du projet (répertoire contenant ce fichier)
PROJECT_ROOT = Path(__file__).parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

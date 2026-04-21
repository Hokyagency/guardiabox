# EXPLICATIONS_PROJET — GuardiaBox

## Table des matières

1. [Structure du projet](#1-structure-du-projet)
2. [Rôle de chaque module](#2-rôle-de-chaque-module)
3. [Choix techniques](#3-choix-techniques)
4. [Lancer l'application](#4-lancer-lapplication)
5. [Lancer les tests](#5-lancer-les-tests)
6. [Interface graphique (GUI)](#6-interface-graphique-gui)
7. [Générer un exécutable (.exe)](#7-générer-un-exécutable-exe)

---

## 1. Structure du projet

```
guardiabox/
├── fileio/
│   ├── __init__.py
│   └── file_handler.py       ← Lecture / écriture sécurisée de fichiers
├── security/
│   ├── __init__.py
│   ├── crypto.py             ← Chiffrement AES-256-GCM + dérivation PBKDF2
│   └── password.py           ← Vérification robustesse / entropie du mot de passe
├── tests/
│   ├── __init__.py
│   └── test_guardiabox.py    ← Tests unitaires Pytest
├── ui/
│   ├── __init__.py
│   ├── console.py            ← Interface utilisateur en mode console
│   └── gui.py                ← Interface graphique PyQt6 (version étendue)
├── conftest.py               ← Configuration Pytest (sys.path)
├── main.py                   ← Point d'entrée (GUI par défaut, --console disponible)
├── setup_launcher.py         ← Script de packaging PyInstaller
├── requirements.txt          ← Dépendances Python
app/
└── run_guardiabox.bat        ← Lanceur double-clic Windows (à la racine de app/)
```

---

## 2. Rôle de chaque module

### `fileio/file_handler.py`

Fournit trois fonctions de bas niveau pour manipuler les fichiers de manière
sécurisée :

| Fonction | Rôle |
|---|---|
| `validate_path(path)` | Normalise le chemin et rejette toute séquence `..` (Path Traversal) ou octet nul. |
| `read_file_bytes(path)` | Lit le contenu binaire d'un fichier après validation du chemin. |
| `write_file_bytes(path, data)` | Écrit des octets dans un fichier (crée les dossiers parents si besoin). |
| `write_text_file(path, content)` | Écrit une chaîne UTF-8 dans un fichier texte. |

Toutes les fonctions appellent `validate_path` avant toute opération, ce qui
constitue la première ligne de défense contre les injections de chemin.

---

### `security/crypto.py`

Cœur cryptographique de l'application.

**Constantes clés :**

| Constante | Valeur | Justification |
|---|---|---|
| `SALT_SIZE` | 16 octets | Sel aléatoire pour PBKDF2, empêche les attaques par table de correspondance (rainbow tables). |
| `NONCE_SIZE` | 12 octets | Taille standard recommandée pour AES-GCM (96 bits). |
| `KEY_SIZE` | 32 octets | AES-256 bits, référence industrielle pour la sécurité à long terme. |
| `PBKDF2_ITERATIONS` | 600 000 | Au-dessus de la recommandation NIST SP 800-132 (≥ 210 000 pour SHA-256). Ralentit les attaques par dictionnaire. |

**Format du fichier `.crypt` :**

```
┌──────────────┬─────────────┬──────────────────────────────┐
│  salt (16 B) │ nonce (12 B)│  ciphertext + tag GCM (16 B) │
└──────────────┴─────────────┴──────────────────────────────┘
```

Le tag GCM est généré automatiquement par la bibliothèque `cryptography` lors du
chiffrement et vérifié lors du déchiffrement : toute altération des données ou
utilisation d'un mauvais mot de passe lève `cryptography.exceptions.InvalidTag`.

---

### `security/password.py`

Évalue la robustesse d'un mot de passe selon deux axes :

1. **Critères qualitatifs** : longueur minimale (12 caractères), présence de
   minuscules, majuscules, chiffres et caractères spéciaux.
2. **Entropie estimée** (bits) : calculée selon `H = len(pwd) × log₂(alphabet)`.
   Le seuil minimal est fixé à **50 bits**, ce qui correspond à une résistance
   raisonnable contre les attaques par force brute modernes.

---

### `ui/console.py`

Interface utilisateur en mode console organisée autour de trois flux :

- **`run_menu()`** : boucle principale affichant le menu et dirigeant vers le
  flux approprié.
- **`encrypt_flow()`** : guide l'utilisateur pour chiffrer un message ou un
  fichier, vérifie le mot de passe avant chiffrement.
- **`decrypt_flow()`** : guide l'utilisateur pour déchiffrer un fichier `.crypt`,
  affiche le contenu si UTF-8, sinon sauvegarde en `.decrypt`.

Le module importe `cryptography.exceptions.InvalidTag` pour afficher un message
d'erreur explicite sans révéler d'information exploitable à un attaquant.

---

### `main.py`

Point d'entrée minimal : appelle `run_menu()` depuis `ui.console`.

```python
if __name__ == "__main__":
    main()
```

---

### `conftest.py`

Fichier de configuration Pytest qui ajoute la racine du projet à `sys.path`,
permettant aux tests d'importer `fileio`, `security` et `ui` sans installation
préalable du package.

---

## 3. Choix techniques

### Pourquoi AES-GCM ?

AES-GCM (Galois/Counter Mode) est un mode de chiffrement **authentifié** (AEAD —
Authenticated Encryption with Associated Data). Par rapport à AES-CBC ou AES-CTR,
il offre :

- **Confidentialité** : les données sont chiffrées avec AES-256.
- **Intégrité & Authenticité** : le tag de 128 bits détecte toute modification
  du fichier chiffré ou utilisation d'un mauvais mot de passe.
- **Standard industriel** : recommandé par le NIST, utilisé dans TLS 1.3.

### Pourquoi PBKDF2 ?

Un mot de passe ne peut pas être utilisé directement comme clé AES. PBKDF2
(Password-Based Key Derivation Function 2) :

- Étire le mot de passe sur une clé de 256 bits de manière déterministe.
- Incorpore un **sel aléatoire** (stocké dans le fichier `.crypt`) pour éviter
  que deux utilisateurs avec le même mot de passe produisent la même clé.
- Rend les attaques par dictionnaire très coûteuses grâce au nombre d'itérations
  élevé (600 000 tours = calcul lent intentionnellement).

### Prévention des vulnérabilités OWASP

| Risque | Mesure mise en œuvre |
|---|---|
| **Path Traversal (A01)** | `validate_path()` rejette tout chemin contenant `..` ou un octet nul. |
| **Cryptographie faible (A02)** | AES-256-GCM + PBKDF2 SHA-256 avec 600 000 itérations. |
| **Mot de passe faible** | Vérification longueur, complexité et entropie avant chiffrement. |
| **Integrity failure (A08)** | Tag GCM 128 bits vérifié à chaque déchiffrement. |
| **Crash applicatif** | Blocs `try/except` ciblés dans tous les flux critiques. |

---

## 4. Lancer l'application

### Prérequis

- Python 3.12 ou supérieur
- pip

### Installation des dépendances

Depuis le dossier `guardiabox/` :

```bash
pip install -r requirements.txt
```

### Démarrage

```bash
cd guardiabox
python main.py            # Interface graphique (GUI) — par défaut
python main.py --console  # Interface console (terminal)
python main.py --gui      # Interface graphique (explicite)
```

Ou depuis la racine du projet, double-cliquer sur :

```
run_guardiabox.bat
```

---

## 5. Lancer les tests

Depuis le dossier `guardiabox/` :

```bash
pytest tests/ -v
```

Option avec rapport de couverture (nécessite `pytest-cov`) :

```bash
pip install pytest-cov
pytest tests/ -v --cov=. --cov-report=term-missing
```

### Tests couverts

| Classe de tests | Ce qui est vérifié |
|---|---|
| `TestEncryptDecrypt` | Cycle chiffrement/déchiffrement, mauvais mot de passe, données vides, corrompues, unicode, grandes tailles. |
| `TestPasswordStrength` | Mot de passe fort, trop court, sans majuscule, sans chiffre, sans caractère spécial, entropie. |
| `TestFileHandler` | Chemin valide, path traversal (`../`), octet nul. |

---

## 6. Interface graphique (GUI)

### Framework et thème

L'interface graphique utilise **PyQt6** avec un thème sombre inspiré cybersécurité.

| Couleur | Usage |
|---|---|
| `#1a1d23` | Fond principal |
| `#22262e` | Panneaux, en-tête, onglets |
| `#00b4d8` | Accent (bleu cyan) — boutons, sélection active |
| `#52b788` | Succès (vert) |
| `#e63946` | Erreur (rouge) |
| `#f4a261` | Avertissement (orange) |

### Architecture GUI

```
MainWindow (QMainWindow)
├── Header (titre + badge algorithme)
├── QTabWidget
│   ├── EncryptTab (QWidget)
│   │   ├── EncryptWorker (QThread) ← chiffrement non bloquant
│   │   └── Indicateur de robustesse du mot de passe
│   └── DecryptTab (QWidget)
│       ├── DecryptWorker (QThread) ← déchiffrement non bloquant
│       └── Zone d'affichage du contenu textuel
└── QStatusBar ← retour visuel coloré (succès/erreur/info)
```

### Fonctionnalités clés

| Fonctionnalité | Détail |
|---|---|
| **QFileDialog** | Bouton « Parcourir » sur chaque champ chemin : ouvre une pop-up d'exploration native. |
| **Champ mot de passe masqué** | `QLineEdit.EchoMode.Password` par défaut ; bouton 👁 pour basculer la visibilité. |
| **Indicateur de robustesse** | `QProgressBar` colorée (rouge → orange → vert) mise à jour en temps réel pendant la saisie. |
| **Traitement asynchrone** | `QThread` dédié pour chaque opération cryptographique : l'UI reste réactive pendant la dérivation PBKDF2. |
| **Barre de statut** | Affiche le résultat de chaque opération avec un code couleur. |
| **Mode console conservé** | `python main.py --console` lance toujours l'interface texte. |

### Améliorations UX v2.1

| Fonctionnalité | Implémentation |
|---|---|
| **Fade-in + Slide-up** | À l'ouverture, `QPropertyAnimation` sur `windowOpacity` (0→1) et `geometry` (+30px→0) jouées en parallèle sur 400 ms avec easing `OutCubic`. |
| **Toast slide-down** | Classe `ToastNotification(QWidget)` : apparaît sous l'en-tête avec `QPropertyAnimation` sur `geometry` (280 ms `OutCubic`), se referme après 3 s (220 ms `InCubic`). |
| **Pulsation du bouton** | Classe `PulseButton(QPushButton)` : quand tous les champs requis sont remplis, un `QTimer` à 700 ms alterne la couleur de bordure pour signaler que le formulaire est prêt. |
| **Tooltips ⓘ** | Labels `QLabel("ⓘ")` placés à côté des termes techniques (AES-256-GCM, PBKDF2-SHA256, mot de passe). Le survol affiche un `QToolTip` pédagogique multi-lignes. |
| **Drop-shadow** | `QGraphicsDropShadowEffect` appliqué au `QTabWidget` (rayon 24 px) et aux boutons d'action (rayon 16 px). |
| **QSS enrichi** | `border-radius: 7–10px` sur inputs et boutons, classe CSS `#action_ready` pour les boutons prêts, classe `#toast` pour la bannière verte. |

### Sécurité GUI

- Le mot de passe n'est jamais affiché dans les logs ou la barre de statut.
- La vérification de robustesse (`check_password_strength`) est appelée avant tout chiffrement.
- `validate_path()` est appelé sur tous les chemins saisis manuellement.
- En cas de mauvais mot de passe, le message d'erreur ne révèle pas d'information cryptographique exploitable.

---

## 7. Générer un exécutable (.exe)

### Prérequis

```bash
pip install pyinstaller
```

### Méthode 1 — Script automatisé

```bash
cd guardiabox
python setup_launcher.py
```

L'exécutable est généré dans :

```
guardiabox/dist/GuardiaBox/GuardiaBox.exe
```

### Méthode 2 — Commande manuelle

```bash
cd guardiabox
pyinstaller --name GuardiaBox --onedir --windowed --noconfirm --clean \
  --hidden-import cryptography \
  --hidden-import cryptography.hazmat.primitives.ciphers.aead \
  --hidden-import cryptography.hazmat.primitives.kdf.pbkdf2 \
  --hidden-import PyQt6.QtCore \
  --hidden-import PyQt6.QtGui \
  --hidden-import PyQt6.QtWidgets \
  main.py
```

### Distribution

Le dossier `dist/GuardiaBox/` est autonome et peut être copié/zippé pour distribution.
Il contient l'exécutable et toutes ses dépendances — Python n'est pas requis sur la machine cible.

> **Note :** L'option `--onedir` (dossier unique) est préférée à `--onefile` car elle
> évite l'extraction lente au démarrage et est plus compatible avec certains antivirus.


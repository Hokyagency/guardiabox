"""
Module history — historique SQLite des opérations GuardiaBox.

Stocke chaque opération de chiffrement ou déchiffrement dans une base
SQLite légère située dans ``~/.guardiabox/history.db``.

Schéma de la table ``operations`` :

    id          : identifiant auto-incrémenté
    timestamp   : date/heure UTC ISO-8601
    operation   : 'CHIFFREMENT' ou 'DECHIFFREMENT'
    source_path : chemin du fichier source (ou '(message direct)')
    output_path : chemin du fichier produit
    file_sha256 : empreinte SHA-256 du fichier source
    status      : 'SUCCES' ou 'ERREUR'
    error_msg   : message d'erreur (vide si succès)
"""

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Chemin de la base de données (répertoire caché dans le home utilisateur)
# ---------------------------------------------------------------------------

_DB_DIR: Path = Path.home() / ".guardiabox"
DB_PATH: Path = _DB_DIR / "history.db"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS operations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    operation   TEXT    NOT NULL,
    source_path TEXT    NOT NULL,
    output_path TEXT    NOT NULL,
    file_sha256 TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    error_msg   TEXT    NOT NULL DEFAULT ''
);
"""

# ---------------------------------------------------------------------------
# Fonctions internes
# ---------------------------------------------------------------------------

def _get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Ouvre (ou crée) la connexion à la base de données."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

def init_db(db_path: Path = DB_PATH) -> None:
    """Crée la table ``operations`` si elle n'existe pas encore.

    Appelée automatiquement par :func:`record_operation` et
    :func:`get_history` ; peut aussi être appelée manuellement au
    démarrage de l'application.

    Args:
        db_path: Chemin de la base de données (paramètre de test).
    """
    with _get_connection(db_path) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()


def record_operation(
    operation: str,
    source_path: str,
    output_path: str,
    file_sha256: str,
    status: str,
    error_msg: str = "",
    db_path: Path = DB_PATH,
) -> None:
    """Enregistre une opération dans l'historique.

    Args:
        operation:   ``'CHIFFREMENT'`` ou ``'DECHIFFREMENT'``.
        source_path: Chemin du fichier source (ou ``'(message direct)'``).
        output_path: Chemin du fichier produit.
        file_sha256: Empreinte SHA-256 du contenu source.
        status:      ``'SUCCES'`` ou ``'ERREUR'``.
        error_msg:   Message d'erreur si ``status == 'ERREUR'``.
        db_path:     Chemin de la base de données (paramètre de test).
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    init_db(db_path)
    with _get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO operations "
            "(timestamp, operation, source_path, output_path, "
            " file_sha256, status, error_msg) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, operation, source_path, output_path,
             file_sha256, status, error_msg),
        )
        conn.commit()


def get_history(limit: int = 100, db_path: Path = DB_PATH) -> list[dict]:
    """Retourne les dernières opérations enregistrées (ordre anti-chronologique).

    Args:
        limit:   Nombre maximum d'entrées à retourner.
        db_path: Chemin de la base de données (paramètre de test).

    Returns:
        Liste de dictionnaires avec les colonnes de la table.
    """
    init_db(db_path)
    with _get_connection(db_path) as conn:
        cursor = conn.execute(
            "SELECT * FROM operations ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]


def sha256_of(data: bytes) -> str:
    """Calcule l'empreinte SHA-256 d'un bloc de données.

    Args:
        data: Données à hacher.

    Returns:
        Empreinte hexadécimale de 64 caractères.
    """
    return hashlib.sha256(data).hexdigest()

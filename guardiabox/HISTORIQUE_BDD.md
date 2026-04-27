# HISTORIQUE_BDD — Base de données SQLite de GuardiaBox

## Objectif

GuardiaBox enregistre chaque opération de chiffrement et de déchiffrement dans une base de données SQLite locale. Cela constitue un **journal d'audit** qui permet de :

- Tracer l'historique des fichiers traités (critères CDC n° 13 et 14).
- Conserver une empreinte SHA-256 du fichier source pour détecter ultérieurement toute altération.
- Distinguer les opérations réussies des opérations en erreur.

---

## Emplacement du fichier

```
~/.guardiabox/history.db
```

| Système | Chemin réel |
|---|---|
| Windows | `C:\Users\<utilisateur>\.guardiabox\history.db` |
| Linux / macOS | `/home/<utilisateur>/.guardiabox/history.db` |

Le répertoire `.guardiabox/` est créé automatiquement au premier lancement si il n'existe pas.

---

## Module concerné

| Fichier | Rôle |
|---|---|
| `guardiabox/storage/__init__.py` | Package, exporte `init_db`, `record_operation`, `get_history`, `sha256_of`. |
| `guardiabox/storage/history.py` | Toute la logique SQLite (connexion, création table, insertions, requêtes). |

---

## Schéma de la table `operations`

```sql
CREATE TABLE IF NOT EXISTS operations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,   -- Date/heure UTC (ISO-8601)
    operation   TEXT    NOT NULL,   -- 'CHIFFREMENT' ou 'DECHIFFREMENT'
    source_path TEXT    NOT NULL,   -- Chemin du fichier source
    output_path TEXT    NOT NULL,   -- Chemin du fichier produit
    file_sha256 TEXT    NOT NULL,   -- Empreinte SHA-256 du fichier source
    status      TEXT    NOT NULL,   -- 'SUCCES' ou 'ERREUR'
    error_msg   TEXT    NOT NULL DEFAULT ''  -- Message d'erreur (vide si succès)
);
```

### Exemple de lignes

| id | timestamp | operation | source_path | output_path | file_sha256 | status | error_msg |
|---|---|---|---|---|---|---|---|
| 1 | 2026-04-24T10:15:00+00:00 | CHIFFREMENT | /docs/rapport.pdf | /docs/rapport.pdf.crypt | `a3f1…` | SUCCES | |
| 2 | 2026-04-24T10:17:32+00:00 | DECHIFFREMENT | /docs/rapport.pdf.crypt | /docs/rapport.pdf.decrypt | `b9c2…` | ERREUR | Mot de passe incorrect |

---

## API publique (`storage/history.py`)

### `init_db(db_path)`
Crée la table `operations` si elle n'existe pas. Appelée automatiquement par les deux fonctions suivantes.

### `record_operation(operation, source_path, output_path, file_sha256, status, error_msg, db_path)`
Insère une ligne dans la table. Appelée depuis `ui/gui.py` :
- Dans `EncryptTab._on_encrypt_ok` → status `'SUCCES'`
- Dans `EncryptTab._on_encrypt_error` → status `'ERREUR'`
- Dans `DecryptTab._on_decrypt_ok` → status `'SUCCES'`
- Dans `DecryptTab._on_decrypt_error` → status `'ERREUR'`

### `get_history(limit, db_path)`
Retourne les `limit` dernières opérations (ordre anti-chronologique) sous forme de liste de dictionnaires.

### `sha256_of(data) -> str`
Calcule l'empreinte SHA-256 d'un `bytes`. Retourne une chaîne hexadécimale de 64 caractères.

---

## Intégration dans le flux GUI

```
_run_encrypt()
    │
    ├─ Lit le fichier source → data (bytes)
    ├─ Calcule self._pending_hash = sha256_of(data)
    ├─ Stocke self._pending_src, self._pending_dest
    └─ Lance EncryptWorker (QThread)
              │
              ├─ [succès] → _on_encrypt_ok()
              │               └─ record_operation(..., "SUCCES")
              │
              └─ [erreur] → _on_encrypt_error()
                              └─ record_operation(..., "ERREUR", message)
```

Le même schéma s'applique pour `_run_decrypt`.

---

## Sécurité

| Point | Mesure |
|---|---|
| **Mot de passe absent** | Le mot de passe n'est jamais stocké dans la BDD (ni en clair, ni haché). |
| **Empreinte SHA-256** | Sert uniquement à identifier le fichier source, pas à reconstituer son contenu. |
| **Injection SQL** | Toutes les insertions utilisent des paramètres liés (`?`) — jamais de concaténation de chaînes. |
| **Accès concurrent** | SQLite gère les verrous au niveau fichier ; adapté à un usage mono-utilisateur. |

---

## Tests

8 nouveaux tests dans `TestHistory` (`tests/test_guardiabox.py`) couvrent :

| Test | Ce qui est vérifié |
|---|---|
| `test_init_creates_table` | La table est créée et le fichier `.db` existe. |
| `test_record_and_retrieve` | Une opération insérée est lisible avec tous ses champs. |
| `test_record_error_stores_message` | Le message d'erreur est bien persisté. |
| `test_get_history_order` | Les entrées sont retournées en ordre anti-chronologique. |
| `test_get_history_limit` | Le paramètre `limit` est respecté. |
| `test_sha256_of_known_value` | Hash de `b""` correspond à la valeur de référence RFC. |
| `test_sha256_of_deterministic` | Même entrée → même hash. |
| `test_sha256_of_length` | Le hash fait toujours 64 caractères. |

Tous les tests utilisent une base temporaire (`tmp_path` pytest) — la BDD de production n'est jamais touchée.

---

## Satisfaire les critères CDC 13 et 14

| Critère | Couverture |
|---|---|
| **13 — Persistance des données** | Chaque opération est stockée de manière persistante dans `~/.guardiabox/history.db`, indépendamment des fichiers traités. |
| **14 — Traçabilité / Audit** | Chaque entrée contient : horodatage UTC, type d'opération, chemins source/sortie, empreinte SHA-256, statut et message d'erreur éventuel. |

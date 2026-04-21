"""
Module gui — Interface graphique PyQt6 pour GuardiaBox.

Implémente une fenêtre principale à onglets avec :
- Onglet « Chiffrer »  : sélection source (message ou fichier), mot de passe,
  dérivation PBKDF2 exécutée dans un QThread pour ne pas bloquer l'UI.
- Onglet « Déchiffrer » : sélection fichier .crypt, mot de passe, résultat.

Thème : sombre, sobre, inspiré cybersécurité.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from cryptography.exceptions import InvalidTag

from fileio.file_handler import (
    read_file_bytes,
    validate_path,
    write_file_bytes,
    write_text_file,
)
from security.crypto import decrypt_data, encrypt_data
from security.password import check_password_strength

# ---------------------------------------------------------------------------
# Constantes d'interface
# ---------------------------------------------------------------------------

APP_TITLE = "GuardiaBox — Coffre-Fort Numérique"
APP_VERSION = "2.0"
ENCRYPTED_EXT = ".crypt"
DECRYPTED_EXT = ".decrypt"

# Palette de couleurs
C_BG = "#1a1d23"
C_PANEL = "#22262e"
C_BORDER = "#2e3440"
C_ACCENT = "#00b4d8"
C_ACCENT_HOVER = "#0096c7"
C_SUCCESS = "#52b788"
C_ERROR = "#e63946"
C_WARNING = "#f4a261"
C_TEXT = "#e0e0e0"
C_TEXT_MUTED = "#8b949e"
C_INPUT_BG = "#2a2f3a"

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {C_BG};
    color: {C_TEXT};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 13px;
}}

QTabWidget::pane {{
    border: 1px solid {C_BORDER};
    background-color: {C_PANEL};
    border-radius: 6px;
}}

QTabBar::tab {{
    background-color: {C_BG};
    color: {C_TEXT_MUTED};
    padding: 10px 28px;
    border: 1px solid {C_BORDER};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background-color: {C_PANEL};
    color: {C_ACCENT};
    border-bottom: 2px solid {C_ACCENT};
    font-weight: 700;
}}

QTabBar::tab:hover:!selected {{
    color: {C_TEXT};
    background-color: {C_PANEL};
}}

QLabel {{
    color: {C_TEXT};
}}

QLabel#section_title {{
    font-size: 11px;
    font-weight: 600;
    color: {C_TEXT_MUTED};
    text-transform: uppercase;
    letter-spacing: 1px;
}}

QLineEdit, QTextEdit {{
    background-color: {C_INPUT_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    border-radius: 5px;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: {C_ACCENT};
}}

QLineEdit:focus, QTextEdit:focus {{
    border: 1px solid {C_ACCENT};
    outline: none;
}}

QLineEdit:read-only {{
    color: {C_TEXT_MUTED};
    background-color: {C_BG};
}}

QPushButton {{
    background-color: {C_ACCENT};
    color: #ffffff;
    border: none;
    border-radius: 5px;
    padding: 9px 20px;
    font-size: 13px;
    font-weight: 600;
    min-width: 100px;
}}

QPushButton:hover {{
    background-color: {C_ACCENT_HOVER};
}}

QPushButton:pressed {{
    background-color: #0077a6;
}}

QPushButton:disabled {{
    background-color: {C_BORDER};
    color: {C_TEXT_MUTED};
}}

QPushButton#browse_btn {{
    background-color: {C_PANEL};
    color: {C_ACCENT};
    border: 1px solid {C_ACCENT};
    min-width: 90px;
    padding: 8px 16px;
}}

QPushButton#browse_btn:hover {{
    background-color: {C_ACCENT};
    color: #ffffff;
}}

QPushButton#toggle_pwd_btn {{
    background-color: transparent;
    color: {C_TEXT_MUTED};
    border: none;
    min-width: 30px;
    padding: 4px 8px;
    font-size: 15px;
}}

QPushButton#toggle_pwd_btn:hover {{
    color: {C_ACCENT};
}}

QRadioButton {{
    color: {C_TEXT};
    spacing: 8px;
}}

QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 8px;
    border: 2px solid {C_BORDER};
    background-color: {C_INPUT_BG};
}}

QRadioButton::indicator:checked {{
    background-color: {C_ACCENT};
    border: 2px solid {C_ACCENT};
}}

QProgressBar {{
    background-color: {C_INPUT_BG};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    height: 8px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {C_ACCENT};
    border-radius: 4px;
}}

QStatusBar {{
    background-color: {C_BG};
    color: {C_TEXT_MUTED};
    border-top: 1px solid {C_BORDER};
    font-size: 12px;
}}

QMessageBox {{
    background-color: {C_PANEL};
    color: {C_TEXT};
}}

QMessageBox QLabel {{
    color: {C_TEXT};
}}

QMessageBox QPushButton {{
    min-width: 80px;
}}
"""


# ---------------------------------------------------------------------------
# Workers QThread
# ---------------------------------------------------------------------------

class EncryptWorker(QThread):
    """Exécute le chiffrement dans un thread séparé pour ne pas bloquer l'UI."""

    finished = pyqtSignal(str)       # chemin du fichier produit
    error = pyqtSignal(str)          # message d'erreur

    def __init__(
        self,
        data: bytes,
        password: str,
        output_path: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._data = data
        self._password = password
        self._output_path = output_path

    def run(self) -> None:
        try:
            encrypted = encrypt_data(self._data, self._password)
            write_file_bytes(self._output_path, encrypted)
            self.finished.emit(self._output_path)
        except Exception as exc:
            self.error.emit(str(exc))


class DecryptWorker(QThread):
    """Exécute le déchiffrement dans un thread séparé pour ne pas bloquer l'UI."""

    finished = pyqtSignal(bytes, str)   # données déchiffrées + chemin sortie
    error = pyqtSignal(str)

    def __init__(
        self,
        encrypted_data: bytes,
        password: str,
        output_path: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._encrypted_data = encrypted_data
        self._password = password
        self._output_path = output_path

    def run(self) -> None:
        try:
            decrypted = decrypt_data(self._encrypted_data, self._password)
            write_file_bytes(self._output_path, decrypted)
            self.finished.emit(decrypted, self._output_path)
        except InvalidTag:
            self.error.emit(
                "Mot de passe incorrect ou fichier corrompu.\n"
                "Le tag d'authenticité AES-GCM n'est pas valide."
            )
        except ValueError as exc:
            self.error.emit(str(exc))
        except Exception as exc:
            self.error.emit(f"Erreur inattendue : {exc}")


# ---------------------------------------------------------------------------
# Widgets utilitaires
# ---------------------------------------------------------------------------

def _section_label(text: str) -> QLabel:
    """Retourne un label stylisé pour les titres de section."""
    lbl = QLabel(text.upper())
    lbl.setObjectName("section_title")
    return lbl


def _make_file_row(
    placeholder: str,
    dialog_title: str,
    file_filter: str,
    mode: str = "open",
) -> tuple[QLineEdit, QPushButton]:
    """Crée une paire (QLineEdit chemin, QPushButton Parcourir).

    Args:
        placeholder: Texte indicatif dans le champ de saisie.
        dialog_title: Titre de la boîte de dialogue fichier.
        file_filter: Filtre de fichiers pour QFileDialog.
        mode: ``"open"`` ou ``"save"``.

    Returns:
        Un tuple ``(line_edit, browse_button)``.
    """
    line_edit = QLineEdit()
    line_edit.setPlaceholderText(placeholder)

    browse_btn = QPushButton("Parcourir")
    browse_btn.setObjectName("browse_btn")
    browse_btn.setFocusPolicy(Qt.FocusPolicy.TabFocus)

    def _open_dialog() -> None:
        if mode == "open":
            path, _ = QFileDialog.getOpenFileName(
                None, dialog_title, "", file_filter
            )
        else:
            path, _ = QFileDialog.getSaveFileName(
                None, dialog_title, "", file_filter
            )
        if path:
            line_edit.setText(path)

    browse_btn.clicked.connect(_open_dialog)
    return line_edit, browse_btn


def _make_password_row() -> tuple[QLineEdit, QPushButton]:
    """Crée un champ mot de passe avec bouton bascule visibilité.

    Returns:
        Un tuple ``(password_line_edit, toggle_button)``.
    """
    pwd_field = QLineEdit()
    pwd_field.setPlaceholderText("Mot de passe")
    pwd_field.setEchoMode(QLineEdit.EchoMode.Password)

    toggle_btn = QPushButton("👁")
    toggle_btn.setObjectName("toggle_pwd_btn")
    toggle_btn.setCheckable(True)
    toggle_btn.setToolTip("Afficher / masquer le mot de passe")

    def _toggle(checked: bool) -> None:
        if checked:
            pwd_field.setEchoMode(QLineEdit.EchoMode.Normal)
            toggle_btn.setText("🙈")
        else:
            pwd_field.setEchoMode(QLineEdit.EchoMode.Password)
            toggle_btn.setText("👁")

    toggle_btn.clicked.connect(_toggle)
    return pwd_field, toggle_btn


def _password_strength_color(password: str) -> str:
    """Retourne une couleur CSS en fonction de la robustesse du mot de passe."""
    if not password:
        return C_BORDER
    is_strong, issues = check_password_strength(password)
    if is_strong:
        return C_SUCCESS
    if len(issues) <= 2:
        return C_WARNING
    return C_ERROR


# ---------------------------------------------------------------------------
# Onglet Chiffrement
# ---------------------------------------------------------------------------

class EncryptTab(QWidget):
    """Onglet dédié au chiffrement de fichier ou de message."""

    status_message = pyqtSignal(str, str)   # (message, niveau: info|ok|error)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: EncryptWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)

        # --- Source ---
        root.addWidget(_section_label("Source"))

        radio_row = QHBoxLayout()
        self._radio_message = QRadioButton("Message texte")
        self._radio_message.setChecked(True)
        self._radio_file = QRadioButton("Fichier existant")
        radio_row.addWidget(self._radio_message)
        radio_row.addWidget(self._radio_file)
        radio_row.addStretch()
        root.addLayout(radio_row)

        # Message texte
        self._message_edit = QTextEdit()
        self._message_edit.setPlaceholderText("Saisissez votre message ici…")
        self._message_edit.setMaximumHeight(110)
        root.addWidget(self._message_edit)

        # Fichier source
        self._source_path, browse_src = _make_file_row(
            "Chemin du fichier à chiffrer",
            "Sélectionner un fichier à chiffrer",
            "Tous les fichiers (*.*)",
        )
        file_row = QHBoxLayout()
        file_row.addWidget(self._source_path)
        file_row.addWidget(browse_src)
        self._file_row_widget = QWidget()
        self._file_row_widget.setLayout(file_row)
        self._file_row_widget.setVisible(False)
        root.addWidget(self._file_row_widget)

        # --- Destination ---
        root.addWidget(_section_label("Fichier de sortie"))

        self._dest_path, browse_dest = _make_file_row(
            "Chemin du fichier chiffré (.crypt)",
            "Enregistrer le fichier chiffré",
            f"Fichiers chiffrés (*{ENCRYPTED_EXT});;Tous (*.*)",
            mode="save",
        )
        dest_row = QHBoxLayout()
        dest_row.addWidget(self._dest_path)
        dest_row.addWidget(browse_dest)
        root.addLayout(dest_row)

        # --- Mot de passe ---
        root.addWidget(_section_label("Mot de passe"))

        self._pwd_field, pwd_toggle = _make_password_row()
        self._pwd_confirm, pwd_confirm_toggle = _make_password_row()
        self._pwd_confirm.setPlaceholderText("Confirmer le mot de passe")

        pwd_row1 = QHBoxLayout()
        pwd_row1.addWidget(self._pwd_field)
        pwd_row1.addWidget(pwd_toggle)
        root.addLayout(pwd_row1)

        pwd_row2 = QHBoxLayout()
        pwd_row2.addWidget(self._pwd_confirm)
        pwd_row2.addWidget(pwd_confirm_toggle)
        root.addLayout(pwd_row2)

        # Indicateur de robustesse
        self._strength_bar = QProgressBar()
        self._strength_bar.setRange(0, 100)
        self._strength_bar.setValue(0)
        self._strength_bar.setTextVisible(False)
        self._strength_bar.setMaximumHeight(6)
        root.addWidget(self._strength_bar)

        self._strength_label = QLabel("")
        self._strength_label.setStyleSheet(f"color: {C_TEXT_MUTED}; font-size: 11px;")
        root.addWidget(self._strength_label)

        # --- Bouton action ---
        root.addStretch()
        self._encrypt_btn = QPushButton("  Chiffrer le fichier")
        self._encrypt_btn.setMinimumHeight(42)
        root.addWidget(self._encrypt_btn)

        # --- Connexions ---
        self._radio_message.toggled.connect(self._on_source_toggle)
        self._radio_file.toggled.connect(self._on_source_toggle)
        self._message_edit.textChanged.connect(self._auto_fill_dest_from_message)
        self._source_path.textChanged.connect(self._auto_fill_dest_from_file)
        self._pwd_field.textChanged.connect(self._update_strength)
        self._encrypt_btn.clicked.connect(self._run_encrypt)

    # --- Gestion affichage ---

    def _on_source_toggle(self) -> None:
        is_message = self._radio_message.isChecked()
        self._message_edit.setVisible(is_message)
        self._file_row_widget.setVisible(not is_message)

    def _auto_fill_dest_from_message(self) -> None:
        if self._radio_message.isChecked() and not self._dest_path.text():
            self._dest_path.setPlaceholderText("message.txt.crypt")

    def _auto_fill_dest_from_file(self, path: str) -> None:
        if path and not self._dest_path.text():
            suggested = path + ENCRYPTED_EXT
            self._dest_path.setPlaceholderText(suggested)

    def _update_strength(self, password: str) -> None:
        if not password:
            self._strength_bar.setValue(0)
            self._strength_bar.setStyleSheet("")
            self._strength_label.setText("")
            return

        is_strong, issues = check_password_strength(password)
        total_criteria = 6
        passed = total_criteria - len(issues)
        pct = int((passed / total_criteria) * 100)

        self._strength_bar.setValue(pct)
        color = _password_strength_color(password)
        self._strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}"
        )

        if is_strong:
            self._strength_label.setText("Mot de passe robuste ✓")
            self._strength_label.setStyleSheet(f"color: {C_SUCCESS}; font-size: 11px;")
        else:
            first_issue = issues[0] if issues else ""
            self._strength_label.setText(f"⚠ {first_issue}")
            self._strength_label.setStyleSheet(f"color: {C_WARNING}; font-size: 11px;")

    # --- Logique chiffrement ---

    def _run_encrypt(self) -> None:
        """Valide les entrées puis lance le worker de chiffrement."""
        password = self._pwd_field.text()
        confirm = self._pwd_confirm.text()
        dest = self._dest_path.text().strip()

        # Validation mot de passe
        if not password:
            self._show_error("Veuillez saisir un mot de passe.")
            return

        is_strong, issues = check_password_strength(password)
        if not is_strong:
            self._show_error(
                "Mot de passe insuffisamment robuste :\n• " + "\n• ".join(issues)
            )
            return

        if password != confirm:
            self._show_error("Les mots de passe ne correspondent pas.")
            return

        # Récupération des données
        if self._radio_message.isChecked():
            text = self._message_edit.toPlainText().strip()
            if not text:
                self._show_error("Le message ne peut pas être vide.")
                return
            data = text.encode("utf-8")
            auto_dest = dest or "message.txt" + ENCRYPTED_EXT
        else:
            src = self._source_path.text().strip()
            if not src:
                self._show_error("Veuillez sélectionner un fichier source.")
                return
            try:
                data = read_file_bytes(src)
            except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
                self._show_error(str(exc))
                return
            auto_dest = dest or src + ENCRYPTED_EXT

        # Validation chemin destination
        final_dest = dest or auto_dest
        try:
            validate_path(final_dest)
        except ValueError as exc:
            self._show_error(f"Chemin de destination invalide : {exc}")
            return

        # Lancement worker
        self._set_busy(True)
        self.status_message.emit("Chiffrement en cours…", "info")

        self._worker = EncryptWorker(data, password, final_dest, self)
        self._worker.finished.connect(self._on_encrypt_ok)
        self._worker.error.connect(self._on_encrypt_error)
        self._worker.start()

    def _on_encrypt_ok(self, output_path: str) -> None:
        self._set_busy(False)
        self.status_message.emit(f"Fichier chiffré : {output_path}", "ok")
        QMessageBox.information(
            self,
            "Succès",
            f"Fichier chiffré avec succès !\n\n{output_path}",
        )

    def _on_encrypt_error(self, message: str) -> None:
        self._set_busy(False)
        self.status_message.emit(f"Erreur : {message}", "error")
        self._show_error(message)

    def _set_busy(self, busy: bool) -> None:
        self._encrypt_btn.setEnabled(not busy)
        self._encrypt_btn.setText(
            "  Chiffrement en cours…" if busy else "  Chiffrer le fichier"
        )

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Erreur", message)


# ---------------------------------------------------------------------------
# Onglet Déchiffrement
# ---------------------------------------------------------------------------

class DecryptTab(QWidget):
    """Onglet dédié au déchiffrement d'un fichier .crypt."""

    status_message = pyqtSignal(str, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: DecryptWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)

        # --- Fichier chiffré ---
        root.addWidget(_section_label("Fichier chiffré"))

        self._src_path, browse_src = _make_file_row(
            "Chemin du fichier .crypt",
            "Sélectionner un fichier chiffré",
            f"Fichiers chiffrés (*{ENCRYPTED_EXT});;Tous (*.*)",
        )
        src_row = QHBoxLayout()
        src_row.addWidget(self._src_path)
        src_row.addWidget(browse_src)
        root.addLayout(src_row)

        # --- Destination ---
        root.addWidget(_section_label("Fichier de sortie"))

        self._dest_path, browse_dest = _make_file_row(
            "Laisser vide pour utiliser le nom automatique (.decrypt)",
            "Enregistrer le fichier déchiffré",
            "Tous les fichiers (*.*)",
            mode="save",
        )
        dest_row = QHBoxLayout()
        dest_row.addWidget(self._dest_path)
        dest_row.addWidget(browse_dest)
        root.addLayout(dest_row)

        # --- Mot de passe ---
        root.addWidget(_section_label("Mot de passe"))

        self._pwd_field, pwd_toggle = _make_password_row()
        pwd_row = QHBoxLayout()
        pwd_row.addWidget(self._pwd_field)
        pwd_row.addWidget(pwd_toggle)
        root.addLayout(pwd_row)

        # --- Résultat texte ---
        root.addWidget(_section_label("Contenu déchiffré (si texte)"))

        self._result_edit = QTextEdit()
        self._result_edit.setReadOnly(True)
        self._result_edit.setPlaceholderText(
            "Le contenu textuel apparaîtra ici après déchiffrement…"
        )
        self._result_edit.setMinimumHeight(120)
        root.addWidget(self._result_edit)

        # --- Bouton ---
        root.addStretch()
        self._decrypt_btn = QPushButton("  Déchiffrer le fichier")
        self._decrypt_btn.setMinimumHeight(42)
        root.addWidget(self._decrypt_btn)

        # --- Connexions ---
        self._src_path.textChanged.connect(self._auto_fill_dest)
        self._decrypt_btn.clicked.connect(self._run_decrypt)

    def _auto_fill_dest(self, path: str) -> None:
        if path and not self._dest_path.text():
            p = Path(path)
            base = str(p.with_suffix("")) if p.suffix == ENCRYPTED_EXT else path
            self._dest_path.setPlaceholderText(base + DECRYPTED_EXT)

    def _run_decrypt(self) -> None:
        src = self._src_path.text().strip()
        password = self._pwd_field.text()
        dest = self._dest_path.text().strip()

        if not src:
            self._show_error("Veuillez sélectionner un fichier chiffré.")
            return

        if not password:
            self._show_error("Veuillez saisir le mot de passe.")
            return

        try:
            encrypted_data = read_file_bytes(src)
        except (FileNotFoundError, IsADirectoryError, ValueError) as exc:
            self._show_error(str(exc))
            return

        # Chemin de sortie automatique si non renseigné
        if not dest:
            p = Path(src)
            base = str(p.with_suffix("")) if p.suffix == ENCRYPTED_EXT else src
            dest = base + DECRYPTED_EXT

        try:
            validate_path(dest)
        except ValueError as exc:
            self._show_error(f"Chemin de destination invalide : {exc}")
            return

        self._set_busy(True)
        self._result_edit.clear()
        self.status_message.emit("Déchiffrement en cours…", "info")

        self._worker = DecryptWorker(encrypted_data, password, dest, self)
        self._worker.finished.connect(self._on_decrypt_ok)
        self._worker.error.connect(self._on_decrypt_error)
        self._worker.start()

    def _on_decrypt_ok(self, decrypted: bytes, output_path: str) -> None:
        self._set_busy(False)
        self.status_message.emit(f"Fichier déchiffré : {output_path}", "ok")

        try:
            text = decrypted.decode("utf-8")
            self._result_edit.setPlainText(text)
        except UnicodeDecodeError:
            self._result_edit.setPlainText(
                "(Contenu binaire — non affichable. "
                f"Fichier sauvegardé : {output_path})"
            )

        QMessageBox.information(
            self,
            "Succès",
            f"Fichier déchiffré avec succès !\n\n{output_path}",
        )

    def _on_decrypt_error(self, message: str) -> None:
        self._set_busy(False)
        self.status_message.emit(f"Erreur : {message}", "error")
        self._show_error(message)

    def _set_busy(self, busy: bool) -> None:
        self._decrypt_btn.setEnabled(not busy)
        self._decrypt_btn.setText(
            "  Déchiffrement en cours…" if busy else "  Déchiffrer le fichier"
        )

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Erreur", message)


# ---------------------------------------------------------------------------
# Fenêtre principale
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    """Fenêtre principale de GuardiaBox."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE}  v{APP_VERSION}")
        self.setMinimumSize(680, 620)
        self.resize(760, 680)
        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- En-tête ---
        header = QWidget()
        header.setStyleSheet(f"background-color: {C_PANEL}; border-bottom: 1px solid {C_BORDER};")
        header.setFixedHeight(64)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(28, 0, 28, 0)

        title_lbl = QLabel("GUARDIA<span style='color:" + C_ACCENT + ";'>BOX</span>")
        title_lbl.setTextFormat(Qt.TextFormat.RichText)
        title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; letter-spacing: 2px;")
        subtitle_lbl = QLabel("Coffre-Fort Numérique Sécurisé")
        subtitle_lbl.setStyleSheet(f"color: {C_TEXT_MUTED}; font-size: 11px; margin-left: 12px;")

        header_layout.addWidget(title_lbl)
        header_layout.addWidget(subtitle_lbl)
        header_layout.addStretch()

        algo_lbl = QLabel("AES-256-GCM · PBKDF2-SHA256")
        algo_lbl.setStyleSheet(
            f"color: {C_ACCENT}; font-size: 10px; font-weight: 600; "
            f"border: 1px solid {C_ACCENT}; border-radius: 3px; padding: 3px 8px;"
        )
        header_layout.addWidget(algo_lbl)

        layout.addWidget(header)

        # --- Onglets ---
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(False)
        self._tabs.setContentsMargins(16, 16, 16, 16)

        self._encrypt_tab = EncryptTab()
        self._decrypt_tab = DecryptTab()

        self._tabs.addTab(self._encrypt_tab, "🔒  Chiffrer")
        self._tabs.addTab(self._decrypt_tab, "🔓  Déchiffrer")

        layout.addWidget(self._tabs)

        # --- Barre de statut ---
        self._status_bar = QStatusBar()
        self._status_bar.showMessage("Prêt")
        self.setStatusBar(self._status_bar)

        # --- Connexions ---
        self._encrypt_tab.status_message.connect(self._update_status)
        self._decrypt_tab.status_message.connect(self._update_status)

    def _update_status(self, message: str, level: str) -> None:
        """Met à jour la barre de statut avec un code couleur."""
        color_map = {
            "ok": C_SUCCESS,
            "error": C_ERROR,
            "info": C_ACCENT,
        }
        color = color_map.get(level, C_TEXT_MUTED)
        self._status_bar.setStyleSheet(
            f"QStatusBar {{ color: {color}; background-color: {C_BG}; "
            f"border-top: 1px solid {C_BORDER}; font-size: 12px; }}"
        )
        self._status_bar.showMessage(message)


# ---------------------------------------------------------------------------
# Point d'entrée GUI
# ---------------------------------------------------------------------------

def run_gui() -> None:
    """Initialise et lance l'application PyQt6."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)

    # Palette Fusion sombre
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(C_BG))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(C_TEXT))
    palette.setColor(QPalette.ColorRole.Base, QColor(C_INPUT_BG))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(C_PANEL))
    palette.setColor(QPalette.ColorRole.Text, QColor(C_TEXT))
    palette.setColor(QPalette.ColorRole.Button, QColor(C_PANEL))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(C_TEXT))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(C_ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

"""
Module gui — Interface graphique PyQt6 pour GuardiaBox (v2.2).

Améliorations UX v2.1 :
- Fade-in + slide-up à l'ouverture (QPropertyAnimation sur windowOpacity / geometry).
- Notification « toast » slide-down en cas de succès.
- Pulsation du bouton principal quand tous les champs sont remplis.
- Tooltips informatifs sur les termes cryptographiques (ⓘ).
- QSS enrichi : border-radius, drop-shadow, transitions CSS sur les boutons.
- Logique de chiffrement inchangée (security/ non modifié).
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QRect,
    QSequentialAnimationGroup,
    Qt,
    QThread,
    QTimer,
    pyqtSignal,
)
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QGraphicsDropShadowEffect,
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
)
from security.crypto import decrypt_data, encrypt_data
from security.password import check_password_strength
from storage.history import record_operation, sha256_of

# ---------------------------------------------------------------------------
# Constantes d'interface
# ---------------------------------------------------------------------------

APP_TITLE = "GuardiaBox — Coffre-Fort Numérique"
APP_VERSION = "2.2"
ENCRYPTED_EXT = ".crypt"
DECRYPTED_EXT = ".decrypt"

# Palette de couleurs
C_BG = "#1a1d23"
C_PANEL = "#22262e"
C_BORDER = "#2e3440"
C_ACCENT = "#00b4d8"
C_ACCENT_HOVER = "#0096c7"
C_ACCENT_GLOW = "#00d4ff"
C_SUCCESS = "#52b788"
C_ERROR = "#e63946"
C_WARNING = "#f4a261"
C_TEXT = "#e0e0e0"
C_TEXT_MUTED = "#8b949e"
C_INPUT_BG = "#2a2f3a"
C_TOAST_BG = "#1e3a2e"

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {C_BG};
    color: {C_TEXT};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 13px;
}}

/* ── Onglets ── */
QTabWidget::pane {{
    border: 1px solid {C_BORDER};
    background-color: {C_PANEL};
    border-radius: 10px;
    margin-top: -1px;
}}

QTabBar::tab {{
    background-color: {C_BG};
    color: {C_TEXT_MUTED};
    padding: 10px 28px;
    border: 1px solid {C_BORDER};
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 3px;
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

/* ── Labels ── */
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

QLabel#info_icon {{
    color: {C_ACCENT};
    font-size: 13px;
    padding: 0 4px;
}}

QLabel#info_icon:hover {{
    color: {C_ACCENT_GLOW};
}}

/* ── Inputs ── */
QLineEdit, QTextEdit {{
    background-color: {C_INPUT_BG};
    color: {C_TEXT};
    border: 1px solid {C_BORDER};
    border-radius: 7px;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: {C_ACCENT};
}}

QLineEdit:focus, QTextEdit:focus {{
    border: 1px solid {C_ACCENT};
}}

QLineEdit:read-only {{
    color: {C_TEXT_MUTED};
    background-color: {C_BG};
}}

/* ── Boutons principaux ── */
QPushButton {{
    background-color: {C_ACCENT};
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 9px 20px;
    font-size: 13px;
    font-weight: 600;
    min-width: 100px;
}}

QPushButton:hover {{
    background-color: {C_ACCENT_HOVER};
    border: 1px solid {C_ACCENT_GLOW};
}}

QPushButton:pressed {{
    background-color: #0077a6;
}}

QPushButton:disabled {{
    background-color: {C_BORDER};
    color: {C_TEXT_MUTED};
    border: none;
}}

/* ── Bouton Parcourir ── */
QPushButton#browse_btn {{
    background-color: {C_PANEL};
    color: {C_ACCENT};
    border: 1px solid {C_ACCENT};
    border-radius: 7px;
    min-width: 90px;
    padding: 8px 16px;
}}

QPushButton#browse_btn:hover {{
    background-color: {C_ACCENT};
    color: #ffffff;
    border: 1px solid {C_ACCENT_GLOW};
}}

/* ── Bouton toggle mot de passe ── */
QPushButton#toggle_pwd_btn {{
    background-color: transparent;
    color: {C_TEXT_MUTED};
    border: none;
    min-width: 30px;
    padding: 4px 8px;
    font-size: 15px;
    border-radius: 5px;
}}

QPushButton#toggle_pwd_btn:hover {{
    color: {C_ACCENT};
    background-color: {C_INPUT_BG};
}}

/* ── Bouton principal "ready" (pulsation gérée par code) ── */
QPushButton#action_ready {{
    background-color: {C_ACCENT};
    border: 2px solid {C_ACCENT_GLOW};
    border-radius: 7px;
    color: #ffffff;
    font-weight: 700;
}}

/* ── Radio ── */
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

/* ── Progress bar ── */
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

/* ── Status bar ── */
QStatusBar {{
    background-color: {C_BG};
    color: {C_TEXT_MUTED};
    border-top: 1px solid {C_BORDER};
    font-size: 12px;
}}

/* ── Toast notification ── */
QWidget#toast_success {{
    background-color: {C_TOAST_BG};
    border: 1px solid {C_SUCCESS};
    border-radius: 8px;
    padding: 4px;
}}

QWidget#toast_error {{
    background-color: #3a1e1e;
    border: 1px solid {C_ERROR};
    border-radius: 8px;
    padding: 4px;
}}

QLabel#toast_label_success {{
    color: {C_SUCCESS};
    font-size: 13px;
    font-weight: 600;
    padding: 8px 16px;
}}

QLabel#toast_label_error {{
    color: {C_ERROR};
    font-size: 13px;
    font-weight: 600;
    padding: 8px 16px;
}}

/* ── Bouton Terminal Expert ── */
QPushButton#terminal_btn {{
    background-color: transparent;
    color: {C_TEXT_MUTED};
    border: 1px solid {C_BORDER};
    border-radius: 6px;
    padding: 5px 12px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    font-weight: 600;
}}

QPushButton#terminal_btn:hover {{
    background-color: {C_PANEL};
    color: {C_ACCENT};
    border-color: {C_ACCENT};
}}

QPushButton#terminal_btn:pressed {{
    background-color: {C_INPUT_BG};
}}

/* ── Bouton Infos Terminal ── */
QPushButton#info_terminal_btn {{
    background-color: transparent;
    color: {C_TEXT_MUTED};
    border: 1px solid {C_BORDER};
    border-radius: 6px;
    padding: 5px 12px;
    font-size: 12px;
}}

QPushButton#info_terminal_btn:hover {{
    background-color: {C_PANEL};
    color: {C_ACCENT};
    border-color: {C_ACCENT};
}}

QPushButton#info_terminal_btn:pressed {{
    background-color: {C_INPUT_BG};
}}

/* ── Bouton Ouvrir le dossier ── */
QPushButton#open_folder_btn {{
    background-color: {C_PANEL};
    color: {C_SUCCESS};
    border: 1px solid {C_SUCCESS};
    border-radius: 7px;
    min-width: 160px;
    padding: 8px 16px;
    font-size: 13px;
    font-weight: 600;
}}

QPushButton#open_folder_btn:hover {{
    background-color: {C_SUCCESS};
    color: #ffffff;
}}

QPushButton#open_folder_btn:pressed {{
    background-color: #3a8a62;
}}

/* ── Message boxes ── */
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


def _info_icon(tooltip_text: str) -> QLabel:
    """Retourne un label ⓘ avec tooltip au survol.

    Args:
        tooltip_text: Texte affiché au survol de l'icône.
    """
    lbl = QLabel("ⓘ")
    lbl.setObjectName("info_icon")
    lbl.setToolTip(tooltip_text)
    lbl.setCursor(Qt.CursorShape.WhatsThisCursor)
    return lbl


def _open_file_location(path: str) -> None:
    """Ouvre dans l'explorateur le dossier contenant le fichier *path*."""
    folder = str(Path(path).parent)
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", f"/select,{path}"])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", folder])
    except Exception:
        pass


def _add_drop_shadow(widget: QWidget, radius: int = 18, opacity: float = 0.35) -> None:
    """Ajoute un effet de drop-shadow à un widget.

    Args:
        widget: Widget cible.
        radius: Rayon du flou en pixels.
        opacity: Opacité de l'ombre (0.0 – 1.0).
    """
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(radius)
    shadow.setOffset(0, 4)
    shadow.setColor(QColor(0, 0, 0, int(255 * opacity)))
    widget.setGraphicsEffect(shadow)


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
# Widget glisser-déposer de fichier
# ---------------------------------------------------------------------------

class DropLineEdit(QLineEdit):
    """QLineEdit qui accepte le glisser-déposer d'un fichier unique.

    Args:
        placeholder: Texte indicatif dans le champ.
        accept_ext:  Extension autorisée (ex. ``.crypt``). ``None`` = tous.
    """

    def __init__(
        self,
        placeholder: str = "",
        accept_ext: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self._accept_ext = accept_ext.lower() if accept_ext else None
        self.setAcceptDrops(True)

    def _is_accepted(self, path: str) -> bool:
        return self._accept_ext is None or path.lower().endswith(self._accept_ext)

    def dragEnterEvent(self, event) -> None:  # type: ignore[override]
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls and self._is_accepted(urls[0].toLocalFile()):
                self.setStyleSheet(
                    f"QLineEdit {{ border: 2px dashed {C_ACCENT_GLOW}; "
                    f"background-color: #1a2a35; }}"
                )
                event.acceptProposedAction()
                return
        event.ignore()

    def dragLeaveEvent(self, event) -> None:  # type: ignore[override]
        self.setStyleSheet("")

    def dropEvent(self, event) -> None:  # type: ignore[override]
        self.setStyleSheet("")
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if self._is_accepted(path):
                self.setText(path)
                event.acceptProposedAction()
                return
        event.ignore()


# ---------------------------------------------------------------------------
# Toast notification (slide-down)
# ---------------------------------------------------------------------------

class ToastNotification(QWidget):
    """Bannière de notification slide-down (succès ou erreur).

    Args:
        parent: Widget parent (nécessaire pour le positionnement).
        message: Texte à afficher.
        kind: ``'success'`` (fond vert) ou ``'error'`` (fond rouge).
        duration_ms: Durée d'affichage avant disparition automatique.
    """

    def __init__(
        self,
        parent: QWidget,
        message: str,
        kind: str = "success",
        duration_ms: int = 3000,
    ) -> None:
        super().__init__(parent)
        self.setObjectName(f"toast_{kind}")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        icon = "✓" if kind == "success" else "✗"
        lbl = QLabel(f"{icon}  {message}")
        lbl.setObjectName(f"toast_label_{kind}")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl)

        self._setup_geometry(parent)
        self._animate_in(duration_ms)

    def _setup_geometry(self, parent: QWidget) -> None:
        w = parent.width() - 80
        h = 48
        x = 40
        self._final_y = 70          # position finale sous l'en-tête
        self._start_y = self._final_y - h - 10
        self.setGeometry(x, self._start_y, w, h)
        self.raise_()
        self.show()

    def _animate_in(self, duration_ms: int) -> None:
        w = self.width()
        h = self.height()
        x = self.x()

        self._anim_in = QPropertyAnimation(self, b"geometry")
        self._anim_in.setDuration(280)
        self._anim_in.setStartValue(QRect(x, self._start_y, w, h))
        self._anim_in.setEndValue(QRect(x, self._final_y, w, h))
        self._anim_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim_in.start()

        QTimer.singleShot(duration_ms, self._animate_out)

    def _animate_out(self) -> None:
        w = self.width()
        h = self.height()
        x = self.x()
        current_y = self.y()

        self._anim_out = QPropertyAnimation(self, b"geometry")
        self._anim_out.setDuration(220)
        self._anim_out.setStartValue(QRect(x, current_y, w, h))
        self._anim_out.setEndValue(QRect(x, self._start_y, w, h))
        self._anim_out.setEasingCurve(QEasingCurve.Type.InCubic)
        self._anim_out.finished.connect(self.deleteLater)
        self._anim_out.start()


# ---------------------------------------------------------------------------
# Pulsation du bouton principal
# ---------------------------------------------------------------------------

class PulseButton(QPushButton):
    """QPushButton avec effet de pulsation (scale simulé via bordure/couleur)
    quand le bouton est dans l'état "prêt".

    La pulsation alterne la couleur de la bordure toutes les 700 ms.
    """

    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._pulse_timer = QTimer(self)
        self._pulse_state = False
        self._pulse_timer.timeout.connect(self._toggle_pulse)

    def start_pulse(self) -> None:
        """Active la pulsation visuelle."""
        self.setObjectName("action_ready")
        self._pulse_timer.start(700)
        self._refresh_style()

    def stop_pulse(self) -> None:
        """Arrête la pulsation et revient au style normal."""
        self._pulse_timer.stop()
        self.setObjectName("")
        self._refresh_style()

    def _toggle_pulse(self) -> None:
        self._pulse_state = not self._pulse_state
        if self._pulse_state:
            self.setStyleSheet(
                f"QPushButton {{ background-color: {C_ACCENT_GLOW}; "
                f"border: 2px solid #ffffff; border-radius: 7px; "
                f"color: #ffffff; font-weight: 700; }}"
            )
        else:
            self.setStyleSheet("")
            self.setObjectName("action_ready")
            self._refresh_style()

    def _refresh_style(self) -> None:
        self.style().unpolish(self)
        self.style().polish(self)


# ---------------------------------------------------------------------------
# Onglet Chiffrement
# ---------------------------------------------------------------------------

class EncryptTab(QWidget):
    """Onglet dédié au chiffrement de fichier ou de message."""

    status_message = pyqtSignal(str, str)   # (message, niveau: info|ok|error)
    request_toast = pyqtSignal(str, str)     # (message, kind: success|error)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: EncryptWorker | None = None
        self._last_output_path: str = ""
        self._pending_src: str = ""
        self._pending_dest: str = ""
        self._pending_hash: str = ""
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
        self._source_path = DropLineEdit(
            "Chemin du fichier à chiffrer (ou glissez-déposez un fichier ici)",
        )
        browse_src = QPushButton("Parcourir")
        browse_src.setObjectName("browse_btn")
        browse_src.setFocusPolicy(Qt.FocusPolicy.TabFocus)

        def _open_src_dialog() -> None:
            path, _ = QFileDialog.getOpenFileName(
                None, "Sélectionner un fichier à chiffrer", "", "Tous les fichiers (*.*)"
            )
            if path:
                self._source_path.setText(path)

        browse_src.clicked.connect(_open_src_dialog)
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
        pwd_title_row = QHBoxLayout()
        pwd_title_row.addWidget(_section_label("Mot de passe"))
        pwd_title_row.addWidget(
            _info_icon(
                "Le mot de passe est transformé en clé AES-256 via PBKDF2-HMAC-SHA256 "
                "(600 000 itérations + sel aléatoire). Il n'est jamais stocké."
            )
        )
        pwd_title_row.addStretch()
        root.addLayout(pwd_title_row)

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

        # --- Bouton action (PulseButton) ---
        root.addStretch()
        action_row = QHBoxLayout()
        self._encrypt_btn = PulseButton("  Chiffrer le fichier")
        self._encrypt_btn.setMinimumHeight(42)
        _add_drop_shadow(self._encrypt_btn, radius=16, opacity=0.4)
        action_row.addWidget(self._encrypt_btn)

        self._open_folder_btn = QPushButton("📂  Ouvrir le dossier")
        self._open_folder_btn.setObjectName("open_folder_btn")
        self._open_folder_btn.setMinimumHeight(42)
        self._open_folder_btn.setMaximumWidth(190)
        self._open_folder_btn.setVisible(False)
        self._open_folder_btn.clicked.connect(self._open_last_folder)
        action_row.addWidget(self._open_folder_btn)
        root.addLayout(action_row)

        # --- Connexions ---
        self._radio_message.toggled.connect(self._on_source_toggle)
        self._radio_file.toggled.connect(self._on_source_toggle)
        self._message_edit.textChanged.connect(self._auto_fill_dest_from_message)
        self._message_edit.textChanged.connect(self._check_ready)
        self._source_path.textChanged.connect(self._auto_fill_dest_from_file)
        self._source_path.textChanged.connect(self._check_ready)
        self._pwd_field.textChanged.connect(self._update_strength)
        self._pwd_field.textChanged.connect(self._check_ready)
        self._pwd_confirm.textChanged.connect(self._check_ready)
        self._encrypt_btn.clicked.connect(self._run_encrypt)

    # --- Gestion affichage ---

    def _on_source_toggle(self) -> None:
        is_message = self._radio_message.isChecked()
        self._message_edit.setVisible(is_message)
        self._file_row_widget.setVisible(not is_message)
        self._check_ready()

    def _auto_fill_dest_from_message(self) -> None:
        if self._radio_message.isChecked() and not self._dest_path.text():
            self._dest_path.setPlaceholderText("message.txt.crypt")

    def _auto_fill_dest_from_file(self, path: str) -> None:
        if path and not self._dest_path.text():
            self._dest_path.setPlaceholderText(path + ENCRYPTED_EXT)

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

    def _check_ready(self) -> None:
        """Active la pulsation du bouton quand tous les champs requis sont remplis."""
        pwd = self._pwd_field.text()
        confirm = self._pwd_confirm.text()

        if self._radio_message.isChecked():
            source_ok = bool(self._message_edit.toPlainText().strip())
        else:
            source_ok = bool(self._source_path.text().strip())

        is_strong, _ = check_password_strength(pwd) if pwd else (False, [])
        all_ready = source_ok and is_strong and pwd == confirm and bool(confirm)

        if all_ready:
            self._encrypt_btn.start_pulse()
        else:
            self._encrypt_btn.stop_pulse()

    # --- Logique chiffrement ---

    def _run_encrypt(self) -> None:
        """Valide les entrées puis lance le worker de chiffrement."""
        password = self._pwd_field.text()
        confirm = self._pwd_confirm.text()
        dest = self._dest_path.text().strip()

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

        final_dest = dest or auto_dest
        try:
            validate_path(final_dest)
        except ValueError as exc:
            self._show_error(f"Chemin de destination invalide : {exc}")
            return

        # Capture des métadonnées pour l'historique
        self._pending_src = "(message direct)" if self._radio_message.isChecked() else src
        self._pending_dest = final_dest
        self._pending_hash = sha256_of(data)

        self._set_busy(True)
        self._open_folder_btn.setVisible(False)
        self.status_message.emit("Chiffrement en cours…", "info")

        self._worker = EncryptWorker(data, password, final_dest, self)
        self._worker.finished.connect(self._on_encrypt_ok)
        self._worker.error.connect(self._on_encrypt_error)
        self._worker.start()

    def _on_encrypt_ok(self, output_path: str) -> None:
        self._set_busy(False)
        self._encrypt_btn.stop_pulse()
        self.status_message.emit(f"Fichier chiffré : {output_path}", "ok")

        src = getattr(self, "_pending_src", "")
        record_operation(
            "CHIFFREMENT",
            src or "?",
            output_path,
            getattr(self, "_pending_hash", ""),
            "SUCCES",
        )

        # Supprimer le fichier source pour ne laisser que le .crypt
        if src and src != "(message direct)":
            try:
                Path(src).unlink()
            except Exception:
                pass  # Suppression optionnelle — on ne bloque pas si échec

        self._last_output_path = output_path
        self._open_folder_btn.setVisible(True)
        self.request_toast.emit("Fichier chiffré avec succès !", "success")

    def _open_last_folder(self) -> None:
        if self._last_output_path:
            _open_file_location(self._last_output_path)

    def _on_encrypt_error(self, message: str) -> None:
        self._set_busy(False)
        self.status_message.emit(f"Erreur : {message}", "error")
        record_operation(
            "CHIFFREMENT",
            getattr(self, "_pending_src", "?"),
            getattr(self, "_pending_dest", "?"),
            getattr(self, "_pending_hash", ""),
            "ERREUR",
            message,
        )
        self.request_toast.emit(message, "error")
        # _show_error délègue au toast, pas d'appel supplémentaire

    def _set_busy(self, busy: bool) -> None:
        self._encrypt_btn.setEnabled(not busy)
        self._encrypt_btn.setText(
            "  Chiffrement en cours…" if busy else "  Chiffrer le fichier"
        )

    def _show_error(self, message: str) -> None:
        self.request_toast.emit(message, "error")


# ---------------------------------------------------------------------------
# Onglet Déchiffrement
# ---------------------------------------------------------------------------

class DecryptTab(QWidget):
    """Onglet dédié au déchiffrement d'un fichier .crypt."""

    status_message = pyqtSignal(str, str)
    request_toast = pyqtSignal(str, str)  # (message, kind)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: DecryptWorker | None = None
        self._last_output_path: str = ""
        self._pending_src: str = ""
        self._pending_dest: str = ""
        self._pending_hash: str = ""
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)

        # --- Fichier chiffré ---
        algo_row = QHBoxLayout()
        algo_row.addWidget(_section_label("Fichier chiffré"))
        algo_row.addWidget(
            _info_icon(
                "AES-256-GCM : chiffrement authentifié.\n"
                "Le tag GCM (128 bits) garantit qu'aucune altération n'a eu lieu.\n"
                "Un mauvais mot de passe ou un fichier modifié sera immédiatement rejeté."
            )
        )
        algo_row.addStretch()
        root.addLayout(algo_row)

        self._src_path = DropLineEdit(
            "Chemin du fichier .crypt (ou glissez-déposez un fichier ici)",
            accept_ext=ENCRYPTED_EXT,
        )
        browse_src = QPushButton("Parcourir")
        browse_src.setObjectName("browse_btn")
        browse_src.setFocusPolicy(Qt.FocusPolicy.TabFocus)

        def _open_src_dialog() -> None:
            path, _ = QFileDialog.getOpenFileName(
                None, "Sélectionner un fichier chiffré", "",
                f"Fichiers chiffrés (*{ENCRYPTED_EXT});;Tous (*.*)"
            )
            if path:
                self._src_path.setText(path)

        browse_src.clicked.connect(_open_src_dialog)
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
        pwd_title_row = QHBoxLayout()
        pwd_title_row.addWidget(_section_label("Mot de passe"))
        pwd_title_row.addWidget(
            _info_icon(
                "Saisissez le même mot de passe qu'au moment du chiffrement.\n"
                "Le sel (stocké dans le fichier .crypt) permet de reconstituer\n"
                "la clé via PBKDF2-HMAC-SHA256."
            )
        )
        pwd_title_row.addStretch()
        root.addLayout(pwd_title_row)

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
        action_row = QHBoxLayout()
        self._decrypt_btn = PulseButton("  Déchiffrer le fichier")
        self._decrypt_btn.setMinimumHeight(42)
        _add_drop_shadow(self._decrypt_btn, radius=16, opacity=0.4)
        action_row.addWidget(self._decrypt_btn)

        self._open_folder_btn = QPushButton("📂  Ouvrir le dossier")
        self._open_folder_btn.setObjectName("open_folder_btn")
        self._open_folder_btn.setMinimumHeight(42)
        self._open_folder_btn.setMaximumWidth(190)
        self._open_folder_btn.setVisible(False)
        self._open_folder_btn.clicked.connect(self._open_last_folder)
        action_row.addWidget(self._open_folder_btn)
        root.addLayout(action_row)

        # --- Connexions ---
        self._src_path.textChanged.connect(self._auto_fill_dest)
        self._src_path.textChanged.connect(self._check_ready)
        self._pwd_field.textChanged.connect(self._check_ready)
        self._decrypt_btn.clicked.connect(self._run_decrypt)

    def _auto_fill_dest(self, path: str) -> None:
        if path and not self._dest_path.text():
            p = Path(path)
            base = str(p.with_suffix("")) if p.suffix == ENCRYPTED_EXT else path
            self._dest_path.setPlaceholderText(base + DECRYPTED_EXT)

    def _check_ready(self) -> None:
        """Active la pulsation quand le fichier source et le mot de passe sont renseignés."""
        src_ok = bool(self._src_path.text().strip())
        pwd_ok = bool(self._pwd_field.text())
        if src_ok and pwd_ok:
            self._decrypt_btn.start_pulse()
        else:
            self._decrypt_btn.stop_pulse()

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

        if not dest:
            p = Path(src)
            base = str(p.with_suffix("")) if p.suffix == ENCRYPTED_EXT else src
            dest = base + DECRYPTED_EXT

        try:
            validate_path(dest)
        except ValueError as exc:
            self._show_error(f"Chemin de destination invalide : {exc}")
            return

        # Capture des métadonnées pour l'historique
        self._pending_src = src
        self._pending_dest = dest
        self._pending_hash = sha256_of(encrypted_data)

        self._set_busy(True)
        self._open_folder_btn.setVisible(False)
        self._result_edit.clear()
        self.status_message.emit("Déchiffrement en cours…", "info")

        self._worker = DecryptWorker(encrypted_data, password, dest, self)
        self._worker.finished.connect(self._on_decrypt_ok)
        self._worker.error.connect(self._on_decrypt_error)
        self._worker.start()

    def _on_decrypt_ok(self, decrypted: bytes, output_path: str) -> None:
        self._set_busy(False)
        self._decrypt_btn.stop_pulse()
        self.status_message.emit(f"Fichier déchiffré : {output_path}", "ok")

        try:
            text = decrypted.decode("utf-8")
            self._result_edit.setPlainText(text)
        except UnicodeDecodeError:
            self._result_edit.setPlainText(
                f"(Contenu binaire — non affichable. Fichier sauvegardé : {output_path})"
            )

        self.request_toast.emit("Fichier déchiffré avec succès !", "success")
        self._last_output_path = output_path
        self._open_folder_btn.setVisible(True)
        record_operation(
            "DECHIFFREMENT",
            getattr(self, "_pending_src", "?"),
            output_path,
            getattr(self, "_pending_hash", ""),
            "SUCCES",
        )

    def _open_last_folder(self) -> None:
        if self._last_output_path:
            _open_file_location(self._last_output_path)

    def _on_decrypt_error(self, message: str) -> None:
        self._set_busy(False)
        self.status_message.emit(f"Erreur : {message}", "error")
        record_operation(
            "DECHIFFREMENT",
            getattr(self, "_pending_src", "?"),
            getattr(self, "_pending_dest", "?"),
            getattr(self, "_pending_hash", ""),
            "ERREUR",
            message,
        )
        self.request_toast.emit(message, "error")

    def _set_busy(self, busy: bool) -> None:
        self._decrypt_btn.setEnabled(not busy)
        self._decrypt_btn.setText(
            "  Déchiffrement en cours…" if busy else "  Déchiffrer le fichier"
        )

    def _show_error(self, message: str) -> None:
        self.request_toast.emit(message, "error")


# ---------------------------------------------------------------------------
# Dialogue Infos Terminal
# ---------------------------------------------------------------------------

class TerminalTab(QWidget):
    """Onglet affichant les commandes utiles à copier-coller dans le terminal."""

    COMMANDS = [
        ("Mode console",          "python main.py --console"),
        ("Lancer les tests",      "pytest tests/ -v"),
        ("Historique SQLite",     'python -c "from storage.history import get_history; [print(r) for r in get_history(10)]"'),
        ("Installer dépendances", "pip install -r requirements.txt"),
        ("Git status",            "git status"),
        ("Git log",               "git log --oneline -10"),
        ("Git push",              "git push origin Gab"),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Commandes à utiliser dans le terminal")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #00b4d8; padding-bottom: 6px;")
        layout.addWidget(title)

        hint = QLabel("Ouvrez d'abord le terminal (bouton >_ Terminal), puis collez la commande souhaitée.")
        hint.setStyleSheet("color: #7a8694; font-size: 12px; padding-bottom: 10px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        for description, command in self.COMMANDS:
            row = QWidget()
            row.setStyleSheet("background: #22262e; border-radius: 6px;")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(10, 8, 10, 8)
            row_layout.setSpacing(10)

            desc_lbl = QLabel(description)
            desc_lbl.setFixedWidth(155)
            desc_lbl.setStyleSheet("color: #a0aab4; font-size: 12px; background: transparent;")

            cmd_lbl = QLabel(command)
            cmd_lbl.setStyleSheet(
                "font-family: Consolas, monospace; font-size: 12px; "
                "color: #c9d1d9; background: #12151a; "
                "padding: 4px 8px; border-radius: 4px; border: 1px solid #2d3240;"
            )
            cmd_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            cmd_lbl.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

            copy_btn = QPushButton("Copier")
            copy_btn.setFixedSize(72, 28)
            copy_btn.setStyleSheet(
                "QPushButton { background: #00b4d8; color: #fff; border-radius: 5px; font-size: 12px; border: none; }"
                "QPushButton:hover { background: #0096b5; }"
                "QPushButton:pressed { background: #007a96; }"
            )
            copy_btn.clicked.connect(
                lambda _checked, cmd=command, btn=copy_btn: self._copy(cmd, btn)
            )

            row_layout.addWidget(desc_lbl)
            row_layout.addWidget(cmd_lbl)
            row_layout.addWidget(copy_btn)
            layout.addWidget(row)

        layout.addStretch()

    def _copy(self, command: str, btn: QPushButton) -> None:
        QApplication.clipboard().setText(command)
        btn.setText("✓ Copié !")
        btn.setStyleSheet(
            "QPushButton { background: #52b788; color: #fff; border-radius: 5px; font-size: 12px; border: none; }"
        )
        QTimer.singleShot(1500, lambda: (
            btn.setText("Copier"),
            btn.setStyleSheet(
                "QPushButton { background: #00b4d8; color: #fff; border-radius: 5px; font-size: 12px; border: none; }"
                "QPushButton:hover { background: #0096b5; }"
                "QPushButton:pressed { background: #007a96; }"
            )
        ))


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
        self._animate_open()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # --- En-tête ---
        header = QWidget()
        header.setStyleSheet(
            f"background-color: {C_PANEL}; border-bottom: 1px solid {C_BORDER};"
        )
        header.setFixedHeight(64)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(28, 0, 28, 0)

        title_lbl = QLabel(
            "GUARDIA<span style='color:" + C_ACCENT + ";'>BOX</span>"
        )
        title_lbl.setTextFormat(Qt.TextFormat.RichText)
        title_lbl.setStyleSheet(
            "font-size: 20px; font-weight: 800; letter-spacing: 2px;"
        )
        subtitle_lbl = QLabel("Coffre-Fort Numérique Sécurisé")
        subtitle_lbl.setStyleSheet(
            f"color: {C_TEXT_MUTED}; font-size: 11px; margin-left: 12px;"
        )

        header_layout.addWidget(title_lbl)
        header_layout.addWidget(subtitle_lbl)
        header_layout.addStretch()

        # Badge algo avec tooltips ⓘ
        algo_badge = QWidget()
        algo_badge_layout = QHBoxLayout(algo_badge)
        algo_badge_layout.setContentsMargins(0, 0, 0, 0)
        algo_badge_layout.setSpacing(4)

        algo_lbl = QLabel("AES-256-GCM · PBKDF2-SHA256")
        algo_lbl.setStyleSheet(
            f"color: {C_ACCENT}; font-size: 10px; font-weight: 600; "
            f"border: 1px solid {C_ACCENT}; border-radius: 4px; padding: 3px 8px;"
        )
        aes_info = _info_icon(
            "AES-256-GCM (Advanced Encryption Standard — Galois/Counter Mode)\n"
            "• Chiffrement symétrique 256 bits — standard NIST.\n"
            "• Mode GCM : chiffrement authentifié (AEAD).\n"
            "• Le tag de 128 bits garantit confidentialité ET intégrité."
        )
        pbkdf2_info = _info_icon(
            "PBKDF2-HMAC-SHA256 (Password-Based Key Derivation Function 2)\n"
            "• Transforme votre mot de passe en clé AES-256.\n"
            "• 600 000 itérations + sel aléatoire de 16 octets.\n"
            "• Résiste aux attaques par dictionnaire et force brute."
        )

        algo_badge_layout.addWidget(algo_lbl)
        algo_badge_layout.addWidget(aes_info)
        algo_badge_layout.addWidget(pbkdf2_info)
        header_layout.addWidget(algo_badge)

        # Bouton Terminal Expert
        terminal_btn = QPushButton(">_  Terminal")
        terminal_btn.setObjectName("terminal_btn")
        terminal_btn.setToolTip(
            "Ouvre un terminal système dans le répertoire du projet.\n"
            "Utile pour exécuter des scripts Python, des commandes Git, etc."
        )
        terminal_btn.setFixedHeight(32)
        terminal_btn.clicked.connect(self._open_terminal)
        header_layout.addSpacing(12)
        header_layout.addWidget(terminal_btn)

        layout.addWidget(header)

        # --- Onglets ---
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(False)
        self._tabs.setContentsMargins(16, 16, 16, 16)
        _add_drop_shadow(self._tabs, radius=24, opacity=0.3)

        self._encrypt_tab = EncryptTab()
        self._decrypt_tab = DecryptTab()
        self._terminal_tab = TerminalTab()

        self._tabs.addTab(self._encrypt_tab, "🔒  Chiffrer")
        self._tabs.addTab(self._decrypt_tab, "🔓  Déchiffrer")
        self._tabs.addTab(self._terminal_tab, ">_  Terminal")

        layout.addWidget(self._tabs)

        # --- Barre de statut ---
        self._status_bar = QStatusBar()
        self._status_bar.showMessage("Prêt")
        self.setStatusBar(self._status_bar)

        # --- Connexions ---
        self._encrypt_tab.status_message.connect(self._update_status)
        self._decrypt_tab.status_message.connect(self._update_status)
        self._encrypt_tab.request_toast.connect(self._show_toast)
        self._decrypt_tab.request_toast.connect(self._show_toast)

    # --- Terminal Expert ---

    def _open_terminal(self) -> None:
        """Ouvre un terminal dans le répertoire source guardiabox/ et lance le mode console."""
        if getattr(sys, "frozen", False):
            # Exe = dist/GuardiaBox/GuardiaBox.exe → remonter 3 niveaux pour atteindre guardiabox/
            project_dir = str(Path(sys.executable).parent.parent.parent)
            # Venv python : app/.venv/Scripts/python.exe
            venv_python = (
                Path(sys.executable).parent.parent.parent.parent
                / ".venv" / "Scripts" / "python.exe"
            )
            python_cmd = f'"{venv_python}"' if venv_python.exists() else "python"
        else:
            project_dir = str(Path(__file__).parent.parent)
            # sys.executable est déjà le python du venv qui a lancé l'app
            python_cmd = f'"{sys.executable}"'

        pip_cmd = f"{python_cmd} -m pip install -r requirements.txt"
        console_cmd = f"{python_cmd} main.py --console"

        try:
            if sys.platform == "win32":
                full_cmd = f'{pip_cmd} && {console_cmd}'
                subprocess.Popen(
                    ["cmd.exe", "/K", full_cmd],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=project_dir,
                )
            elif sys.platform == "darwin":
                mac_script = f"cd {shlex.quote(project_dir)} && {pip_cmd} && {console_cmd}"
                script = f'tell application "Terminal" to do script {shlex.quote(mac_script)}'
                subprocess.Popen(["osascript", "-e", script])
            else:
                run_part = f"{pip_cmd} && {console_cmd}; exec bash"
                for emulator in ("x-terminal-emulator", "gnome-terminal", "xterm"):
                    try:
                        if emulator == "gnome-terminal":
                            subprocess.Popen(
                                [emulator, f"--working-directory={project_dir}",
                                 "--", "bash", "-c", run_part]
                            )
                        else:
                            subprocess.Popen([emulator, "-e", "bash", "-c", run_part],
                                             cwd=project_dir)
                        break
                    except FileNotFoundError:
                        continue
        except Exception as exc:
            self._show_toast(f"Impossible d'ouvrir le terminal : {exc}", "error")

    # --- Animations ---

    def _animate_open(self) -> None:
        """Fade-in + slide-up à l'ouverture de la fenêtre."""
        # Fade-in via windowOpacity
        self.setWindowOpacity(0.0)
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self._fade_anim.setDuration(400)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Slide-up via geometry
        geo = self.geometry()
        start_geo = QRect(geo.x(), geo.y() + 30, geo.width(), geo.height())
        end_geo = QRect(geo.x(), geo.y(), geo.width(), geo.height())

        self._slide_anim = QPropertyAnimation(self, b"geometry")
        self._slide_anim.setDuration(400)
        self._slide_anim.setStartValue(start_geo)
        self._slide_anim.setEndValue(end_geo)
        self._slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._open_group = QSequentialAnimationGroup()
        # Les deux animations jouées en parallèle via start() direct
        self._fade_anim.start()
        self._slide_anim.start()

    # --- Toast ---

    def _show_toast(self, message: str, kind: str = "success") -> None:
        """Affiche une notification slide-down (succès ou erreur)."""
        ToastNotification(self.centralWidget(), message, kind)

    # --- Status bar ---

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

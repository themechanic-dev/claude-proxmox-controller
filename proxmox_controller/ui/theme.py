"""Look and feel: Qt's Fusion style with our own light and dark palettes and a small stylesheet, so the app
looks the same on Linux and Windows and follows the system's light/dark choice."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication


@dataclass(frozen=True)
class Colors:
    window: str
    view: str
    card: str
    card_hover: str
    border: str
    text: str
    dim: str
    accent: str
    accent_text: str
    danger: str
    success: str
    warning: str


ICONS = Path(__file__).resolve().parents[2] / "data" / "icons"

DARK = Colors(window="#222226", view="#1d1d20", card="#2e2e32", card_hover="#38383d", border="#3d3d42",
              text="#f2f2f2", dim="#a0a0a8", accent="#3584e4", accent_text="#ffffff", danger="#e5484d",
              success="#3fb950", warning="#e5a50a")
LIGHT = Colors(window="#fafafb", view="#ffffff", card="#ffffff", card_hover="#f0f0f3", border="#dcdce0",
               text="#1d1d20", dim="#5e5e66", accent="#1c71d8", accent_text="#ffffff", danger="#c01c28",
               success="#26a269", warning="#9c6e03")


def is_dark() -> bool:
    scheme = QGuiApplication.styleHints().colorScheme()
    if scheme == Qt.ColorScheme.Dark:
        return True
    if scheme == Qt.ColorScheme.Light:
        return False
    return QGuiApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128


def colors() -> Colors:
    return DARK if is_dark() else LIGHT


def apply(app: QApplication, dark: bool | None = None) -> Colors:
    c = (DARK if dark else LIGHT) if dark is not None else colors()
    app.setStyle("Fusion")
    pal = QPalette()
    for role, value in ((QPalette.ColorRole.Window, c.window), (QPalette.ColorRole.Base, c.view),
                        (QPalette.ColorRole.AlternateBase, c.card), (QPalette.ColorRole.Button, c.card),
                        (QPalette.ColorRole.Text, c.text), (QPalette.ColorRole.WindowText, c.text),
                        (QPalette.ColorRole.ButtonText, c.text), (QPalette.ColorRole.ToolTipBase, c.card),
                        (QPalette.ColorRole.ToolTipText, c.text), (QPalette.ColorRole.PlaceholderText, c.dim),
                        (QPalette.ColorRole.Highlight, c.accent), (QPalette.ColorRole.HighlightedText, c.accent_text),
                        (QPalette.ColorRole.Accent, c.accent), (QPalette.ColorRole.Link, c.accent)):
        pal.setColor(role, QColor(value))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.WindowText, QPalette.ColorRole.ButtonText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(c.dim))
    app.setPalette(pal)
    app.setStyleSheet(stylesheet(c))
    return c


def stylesheet(c: Colors) -> str:
    return f"""
    QWidget {{ font-size: 10.5pt; }}
    QFrame#card {{ background: {c.card}; border: 1px solid {c.border}; border-radius: 12px; }}
    QLabel#title {{ font-size: 17pt; font-weight: 700; }}
    QLabel#heading {{ font-size: 11.5pt; font-weight: 700; }}
    QLabel#confirmTitle {{ font-size: 12.5pt; font-weight: 700; }}
    QFrame#guestCard {{ background: {c.card}; border: 1px solid {c.border}; border-radius: 8px; }}
    QLabel#dim, QLabel#caption {{ color: {c.dim}; }}
    QLabel#caption {{ font-size: 9pt; }}
    QLabel#grant {{ color: {c.warning}; font-size: 9pt; }}
    QLabel#big {{ font-size: 19pt; font-weight: 700; }}
    QLabel[pill="true"] {{ border-radius: 10px; padding: 2px 10px; font-weight: 700; font-size: 9.5pt; }}
    QLabel[pill="true"][state="online"] {{ background: {_alpha(c.success, 0.18)}; color: {c.success}; }}
    QLabel[pill="true"][state="offline"] {{ background: {_alpha(c.dim, 0.18)}; color: {c.dim}; }}
    QLabel[pill="true"][state="unknown"] {{ background: {_alpha(c.warning, 0.18)}; color: {c.warning}; }}
    QLabel[pill="true"][state="error"] {{ background: {_alpha(c.danger, 0.18)}; color: {c.danger}; }}
    QPushButton, QToolButton {{ background: {c.card_hover}; border: 1px solid {c.border}; border-radius: 8px;
                                padding: 6px 12px; }}
    QPushButton:hover, QToolButton:hover {{ border-color: {c.dim}; }}
    QPushButton:disabled, QToolButton:disabled {{ color: {c.dim}; background: {c.card}; }}
    QPushButton[kind="suggested"] {{ background: {c.accent}; color: {c.accent_text}; border-color: {c.accent}; }}
    QPushButton[kind="destructive"] {{ background: {c.danger}; color: #ffffff; border-color: {c.danger}; }}
    QPushButton[kind="flat"], QToolButton[kind="flat"] {{ background: transparent; border-color: transparent; }}
    QPushButton[kind="suggested"]:disabled, QPushButton[kind="destructive"]:disabled {{
        background: {c.card}; color: {c.dim}; border-color: {c.border}; }}
    QPushButton:checked {{ background: {_alpha(c.accent, 0.28)}; border-color: {c.accent}; font-weight: 700; }}
    QToolButton[popupMode="1"] {{ padding-right: 26px; }}
    QToolButton::menu-button {{ border: none; border-left: 1px solid {c.border}; width: 20px;
                               border-top-right-radius: 8px; border-bottom-right-radius: 8px; }}
    QToolButton::menu-button:hover {{ background: {c.card}; }}
    QToolButton::menu-arrow {{ image: url("{_icon('chevron-down', c)}"); width: 10px; height: 6px; }}
    QWidget#consoleBar {{ background: {c.window}; border-bottom: 1px solid {c.border}; }}
    QToolButton#menuButton {{ background: transparent; border-color: transparent; padding: 0; }}
    QToolButton#menuButton:hover, QToolButton#menuButton:pressed {{ background: {c.card_hover};
                                                                     border-color: {c.border}; }}
    QToolButton#menuButton::menu-indicator {{ image: none; width: 0; }}
    QMenu {{ background: {c.card}; border: 1px solid {c.border}; padding: 4px; }}
    QMenu::item {{ padding: 6px 18px 6px 10px; border-radius: 6px; }}
    QMenu::item:selected {{ background: {c.card_hover}; }}
    QMenu::item:disabled {{ color: {c.dim}; }}
    QMenu::separator {{ height: 1px; background: {c.border}; margin: 4px 6px; }}
    QMenu::icon {{ padding-left: 6px; }}
    QListWidget {{ background: {c.view}; border: 1px solid {c.border}; border-radius: 8px; outline: none; }}
    QListWidget::item {{ padding: 6px 8px; border-radius: 6px; }}
    QListWidget::item:selected {{ background: {_alpha(c.accent, 0.30)}; color: {c.text}; }}
    QTableView {{ background: {c.card}; border: 1px solid {c.border}; border-radius: 12px; gridline-color: transparent;
                  selection-background-color: {_alpha(c.accent, 0.30)}; selection-color: {c.text}; }}
    QTableView::item {{ padding: 0 7px; }}
    QHeaderView::section {{ background: {c.card}; color: {c.dim}; border: none; border-bottom: 1px solid {c.border};
                            padding: 6px 8px; font-weight: 600; }}
    QTabWidget::pane {{ border: none; }}
    QTabBar::tab {{ background: transparent; padding: 8px 16px; border-radius: 8px; margin-right: 4px; }}
    QTabBar::tab:selected {{ background: {c.card_hover}; font-weight: 700; }}
    QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {{ background: {c.view}; border: 1px solid {c.border};
                                                     border-radius: 8px; padding: 5px 8px; }}
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{ border-color: {c.accent}; }}
    QCheckBox::indicator, QListView::indicator, QTableView::indicator {{ width: 14px; height: 14px;
        border: 1px solid {c.dim}; border-radius: 4px; background: {c.view}; }}
    QCheckBox::indicator:hover, QListView::indicator:hover, QTableView::indicator:hover {{ border-color: {c.accent}; }}
    QCheckBox::indicator:checked, QListView::indicator:checked, QTableView::indicator:checked {{
        background: {c.accent}; border-color: {c.accent}; image: url("{(ICONS / 'check.svg').as_posix()}"); }}
    QRadioButton::indicator {{ width: 14px; height: 14px; border: 1px solid {c.dim}; border-radius: 8px;
                              background: {c.view}; }}
    QRadioButton::indicator:hover {{ border-color: {c.accent}; }}
    QRadioButton::indicator:checked {{ border-color: {c.accent}; background: qradialgradient(cx:0.5, cy:0.5,
        radius:0.5, fx:0.5, fy:0.5, stop:0 #ffffff, stop:0.38 #ffffff, stop:0.48 {c.accent}, stop:1 {c.accent}); }}
    QRadioButton::indicator:disabled {{ border-color: {c.border}; background: {c.card}; }}
    QCheckBox::indicator:disabled {{ border-color: {c.border}; background: {c.card}; }}
    QCheckBox::indicator:checked:disabled {{ background: {c.border}; border-color: {c.border}; }}
    QTextBrowser {{ background: {c.view}; border: 1px solid {c.border}; border-radius: 8px; padding: 4px 8px; }}
    QLineEdit, QSpinBox, QComboBox {{ min-height: 22px; }}
    QSpinBox {{ padding-right: 22px; }}
    QSpinBox::up-button, QSpinBox::down-button {{ subcontrol-origin: border; width: 20px; border: none;
                                                  background: transparent; }}
    QSpinBox::up-button {{ subcontrol-position: top right; }}
    QSpinBox::down-button {{ subcontrol-position: bottom right; }}
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {{ background: {c.card_hover}; }}
    QSpinBox::up-arrow {{ image: url("{_icon('chevron-up', c)}"); width: 10px; height: 6px; }}
    QSpinBox::down-arrow {{ image: url("{_icon('chevron-down', c)}"); width: 10px; height: 6px; }}
    QComboBox {{ padding-right: 26px; }}
    QComboBox::drop-down {{ subcontrol-origin: padding; subcontrol-position: center right; width: 24px;
                            border: none; background: transparent; }}
    QComboBox::down-arrow {{ image: url("{_icon('chevron-down', c)}"); width: 10px; height: 6px; }}
    QComboBox QAbstractItemView {{ background: {c.card}; border: 1px solid {c.border}; outline: none;
                                   selection-background-color: {_alpha(c.accent, 0.30)}; selection-color: {c.text}; }}
    QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
    QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px; }}
    QScrollBar::handle {{ background: {_alpha(c.text, 0.22)}; border-radius: 4px; }}
    QScrollBar::handle:hover {{ background: {_alpha(c.text, 0.38)}; }}
    QScrollBar::handle:vertical {{ min-height: 32px; }}
    QScrollBar::handle:horizontal {{ min-width: 32px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; border: none; background: none; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
    QProgressBar {{ background: {c.card_hover}; border: none; border-radius: 4px; height: 8px; text-align: center; }}
    QProgressBar::chunk {{ background: {c.accent}; border-radius: 4px; }}
    QProgressBar[level="warning"]::chunk {{ background: {c.warning}; }}
    QProgressBar[level="critical"]::chunk {{ background: {c.danger}; }}
    QScrollArea {{ border: none; background: transparent; }}
    QLabel#signatureMark {{ border: 1px solid {_alpha(c.text, 0.35)}; border-radius: 4px; padding: 2px 10px;
                            letter-spacing: 3px; font-size: 9pt; color: {_alpha(c.text, 0.75)}; }}
    QLabel#signatureLine {{ font-size: 8.5pt; color: {_alpha(c.text, 0.55)}; }}
    QFrame#signatureRule {{ background: {c.border}; border: none; }}
    """


def _icon(name: str, c: Colors) -> str:
    return (ICONS / f"{name}-{'dark' if c is DARK else 'light'}.svg").as_posix()


def icon_file(name: str) -> str:
    """One of the small drawn icons (chevron-down, chevron-right…) in the current theme's colour."""
    return _icon(name, colors())


def _alpha(hexcolor: str, alpha: float) -> str:
    col = QColor(hexcolor)
    return f"rgba({col.red()}, {col.green()}, {col.blue()}, {alpha})"


def refresh_widget_style(widget) -> None:
    """Re-apply the stylesheet after changing a dynamic property (pill state, button kind…)."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)

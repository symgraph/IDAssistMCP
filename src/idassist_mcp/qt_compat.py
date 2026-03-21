"""
Qt5/Qt6 compatibility shim.

PySide6 (IDA >= 9.2) is tried first; falls back to PyQt5 (IDA <= 9.1).
Consumer files should use explicit imports:
    from ..qt_compat import QWidget, Signal, exec_dialog, ...
"""

try:
    from PySide6.QtCore import QObject, Qt, QTimeZone, Signal
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPlainTextEdit,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
    QT_BINDING = "PySide6"
except ImportError:
    from PyQt5.QtCore import QObject, Qt, QTimeZone, pyqtSignal as Signal
    from PyQt5.QtWidgets import (
        QAction,
        QCheckBox,
        QComboBox,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPlainTextEdit,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
    QT_BINDING = "PyQt5"

QT_AVAILABLE = QT_BINDING is not None

__all__ = [
    "QAction",
    "QCheckBox",
    "QComboBox",
    "QGroupBox",
    "QHBoxLayout",
    "QHeaderView",
    "QLabel",
    "QLineEdit",
    "QObject",
    "QPlainTextEdit",
    "QPushButton",
    "QScrollArea",
    "QSpinBox",
    "QTableWidget",
    "QTableWidgetItem",
    "QTabWidget",
    "QTimeZone",
    "QVBoxLayout",
    "QWidget",
    "QT_AVAILABLE",
    "QT_BINDING",
    "Qt",
    "Signal",
    "exec_dialog",
    "utc_timezone",
]


def exec_dialog(obj, *args):
    """Cross-binding .exec() wrapper (PyQt5 uses .exec_())."""
    if hasattr(obj, "exec"):
        return obj.exec(*args)
    return obj.exec_(*args)


def utc_timezone():
    """Cross-binding UTC QTimeZone."""
    if hasattr(QTimeZone, "utc"):
        return QTimeZone.utc()
    return QTimeZone(0)

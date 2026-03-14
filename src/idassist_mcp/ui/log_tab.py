"""
Log tab widget for IDAssistMCP configuration panel.

Provides a read-only log viewer with real-time updates and a
QLogHandler that bridges Python logging to Qt signals.
"""

import logging
from datetime import datetime

from ..qt_compat import (
    QObject, Signal,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class LogSignalEmitter(QObject):
    """Bridge between Python logging and Qt signal/slot system.

    Emits log_message signal from any thread; Qt's queued connections
    ensure the slot runs on the UI thread.
    """
    log_message = Signal(str)


class QLogHandler(logging.Handler):
    """Python logging.Handler that emits to a Qt signal."""

    def __init__(self, emitter: LogSignalEmitter):
        super().__init__()
        self._emitter = emitter

    def emit(self, record):
        try:
            msg = self.format(record)
            self._emitter.log_message.emit(msg)
        except Exception:
            self.handleError(record)


class LogTab(QWidget):
    """Log viewer tab with status indicator and clear button."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()
        self._init_log_handler()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Top bar: status + clear button
        top_bar = QHBoxLayout()

        self._status_label = QLabel("Server: Stopped")
        self._status_label.setStyleSheet("font-weight: bold; color: #888;")
        top_bar.addWidget(self._status_label)

        top_bar.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(60)
        clear_btn.clicked.connect(self._clear_log)
        top_bar.addWidget(clear_btn)

        layout.addLayout(top_bar)

        # Log text area
        self._log_text = QPlainTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setMaximumBlockCount(5000)
        self._log_text.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        layout.addWidget(self._log_text)

    def _init_log_handler(self):
        """Create the signal emitter and log handler."""
        self._emitter = LogSignalEmitter()
        self._emitter.log_message.connect(self._append_message)
        self._handler = QLogHandler(self._emitter)
        self._handler.setFormatter(logging.Formatter("%(message)s"))

    def get_handler(self) -> QLogHandler:
        """Return the QLogHandler for installation on loggers."""
        return self._handler

    def get_emitter(self) -> LogSignalEmitter:
        """Return the signal emitter for direct message emission."""
        return self._emitter

    def _append_message(self, msg: str):
        """Append a log message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_text.appendPlainText(f"[{timestamp}] {msg}")

    def _clear_log(self):
        """Clear the log display."""
        self._log_text.clear()

    def set_server_status(self, running: bool):
        """Update the server status indicator."""
        if running:
            self._status_label.setText("Server: Running")
            self._status_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
        else:
            self._status_label.setText("Server: Stopped")
            self._status_label.setStyleSheet("font-weight: bold; color: #888;")

    def append_direct(self, msg: str):
        """Append a message directly (not via logging)."""
        self._emitter.log_message.emit(msg)

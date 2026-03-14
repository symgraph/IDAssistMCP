"""
Configuration tab widget for IDAssistMCP.

Provides server settings, analysis settings, plugin settings,
and per-tool enable/disable via a table widget.
"""

from ..qt_compat import (
    Qt, Signal,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .tool_registry import TOOL_CATALOG


class ConfigTab(QWidget):
    """Configuration tab with sections for all IDAssistMCP settings."""

    save_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        # Scrollable area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        # Server Settings
        layout.addWidget(self._create_server_group())

        # Analysis Settings
        layout.addWidget(self._create_analysis_group())

        # Plugin Settings
        layout.addWidget(self._create_plugin_group())

        # MCP Tools
        layout.addWidget(self._create_tools_group())

        # Save button
        save_btn = QPushButton("Save Configuration")
        save_btn.setMinimumHeight(32)
        save_btn.clicked.connect(self.save_requested.emit)
        layout.addWidget(save_btn)

        layout.addStretch()

        scroll.setWidget(container)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ----------------------------------------------------------------- #
    # Server Settings
    # ----------------------------------------------------------------- #

    def _create_server_group(self) -> QGroupBox:
        group = QGroupBox("Server Settings")
        layout = QVBoxLayout(group)

        # Host
        row = QHBoxLayout()
        row.addWidget(QLabel("Host:"))
        self._host_edit = QLineEdit("localhost")
        self._host_edit.setPlaceholderText("localhost")
        row.addWidget(self._host_edit)
        layout.addLayout(row)

        # Port
        row = QHBoxLayout()
        row.addWidget(QLabel("Port:"))
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1024, 65535)
        self._port_spin.setValue(9080)
        row.addWidget(self._port_spin)
        layout.addLayout(row)

        # Transport
        row = QHBoxLayout()
        row.addWidget(QLabel("Transport:"))
        self._transport_combo = QComboBox()
        self._transport_combo.addItems(["streamablehttp", "sse"])
        row.addWidget(self._transport_combo)
        layout.addLayout(row)

        return group

    # ----------------------------------------------------------------- #
    # Analysis Settings
    # ----------------------------------------------------------------- #

    def _create_analysis_group(self) -> QGroupBox:
        group = QGroupBox("Analysis Settings")
        layout = QVBoxLayout(group)

        self._auto_analysis_cb = QCheckBox("Wait for IDA auto-analysis to complete")
        self._auto_analysis_cb.setChecked(True)
        layout.addWidget(self._auto_analysis_cb)

        row = QHBoxLayout()
        row.addWidget(QLabel("Analysis Timeout (s):"))
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(30, 3600)
        self._timeout_spin.setValue(300)
        row.addWidget(self._timeout_spin)
        layout.addLayout(row)

        self._cache_results_cb = QCheckBox("Cache analysis results")
        self._cache_results_cb.setChecked(True)
        layout.addWidget(self._cache_results_cb)

        return group

    # ----------------------------------------------------------------- #
    # Plugin Settings
    # ----------------------------------------------------------------- #

    def _create_plugin_group(self) -> QGroupBox:
        group = QGroupBox("Plugin Settings")
        layout = QVBoxLayout(group)

        self._auto_startup_cb = QCheckBox("Auto-start server on plugin load")
        self._auto_startup_cb.setChecked(False)
        layout.addWidget(self._auto_startup_cb)

        self._show_notifications_cb = QCheckBox("Show status notifications in IDA output")
        self._show_notifications_cb.setChecked(True)
        layout.addWidget(self._show_notifications_cb)

        return group

    # ----------------------------------------------------------------- #
    # MCP Tools
    # ----------------------------------------------------------------- #

    def _create_tools_group(self) -> QGroupBox:
        group = QGroupBox("MCP Tools")
        layout = QVBoxLayout(group)

        # Quick-action buttons
        btn_row = QHBoxLayout()

        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self._select_all_tools)
        btn_row.addWidget(select_all_btn)

        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(self._deselect_all_tools)
        btn_row.addWidget(deselect_all_btn)

        readonly_btn = QPushButton("Read-Only Only")
        readonly_btn.clicked.connect(self._select_readonly_only)
        btn_row.addWidget(readonly_btn)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Tools table
        self._tools_table = QTableWidget()
        self._tools_table.setColumnCount(4)
        self._tools_table.setHorizontalHeaderLabels(["Enabled", "Name", "Category", "Type"])
        self._tools_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._tools_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._tools_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._tools_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._tools_table.setColumnWidth(0, 60)
        self._tools_table.verticalHeader().setVisible(False)
        self._tools_table.setSelectionMode(QTableWidget.NoSelection)

        self._populate_tools_table()

        layout.addWidget(self._tools_table)

        return group

    def _populate_tools_table(self):
        """Fill the tools table from the tool catalog."""
        self._tools_table.setRowCount(len(TOOL_CATALOG))
        self._tool_checkboxes = {}

        for row, tool in enumerate(TOOL_CATALOG):
            # Enabled checkbox
            cb = QCheckBox()
            cb.setChecked(True)
            cb_widget = QWidget()
            cb_layout = QHBoxLayout(cb_widget)
            cb_layout.addWidget(cb)
            cb_layout.setAlignment(Qt.AlignCenter)
            cb_layout.setContentsMargins(0, 0, 0, 0)
            self._tools_table.setCellWidget(row, 0, cb_widget)
            self._tool_checkboxes[tool.name] = cb

            # Name
            name_item = QTableWidgetItem(tool.display_name)
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            name_item.setToolTip(f"{tool.name}\n{tool.description}")
            self._tools_table.setItem(row, 1, name_item)

            # Category
            cat_item = QTableWidgetItem(tool.category)
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemIsEditable)
            self._tools_table.setItem(row, 2, cat_item)

            # Type (annotation)
            type_label = {"read_only": "Read", "modify": "Modify", "non_idempotent": "Write"}.get(
                tool.annotation, tool.annotation
            )
            type_item = QTableWidgetItem(type_label)
            type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            self._tools_table.setItem(row, 3, type_item)

    def _select_all_tools(self):
        for cb in self._tool_checkboxes.values():
            cb.setChecked(True)

    def _deselect_all_tools(self):
        for cb in self._tool_checkboxes.values():
            cb.setChecked(False)

    def _select_readonly_only(self):
        for tool in TOOL_CATALOG:
            cb = self._tool_checkboxes.get(tool.name)
            if cb:
                cb.setChecked(tool.annotation == "read_only")

    # ----------------------------------------------------------------- #
    # Config load/save
    # ----------------------------------------------------------------- #

    def load_from_config(self, config):
        """Load values from an IDAssistMCPConfig instance."""
        # Server
        self._host_edit.setText(config.server.host)
        self._port_spin.setValue(config.server.port)
        idx = self._transport_combo.findText(config.server.transport.value)
        if idx >= 0:
            self._transport_combo.setCurrentIndex(idx)

        # Analysis
        self._auto_analysis_cb.setChecked(config.analysis.auto_analysis_wait)
        self._timeout_spin.setValue(config.analysis.analysis_timeout)
        self._cache_results_cb.setChecked(config.analysis.cache_results)

        # Plugin
        self._auto_startup_cb.setChecked(config.plugin.auto_startup)
        self._show_notifications_cb.setChecked(config.plugin.show_notifications)

        # Disabled tools
        disabled = set(config.disabled_tools)
        for name, cb in self._tool_checkboxes.items():
            cb.setChecked(name not in disabled)

    def get_config_dict(self) -> dict:
        """Collect current widget values into a config-compatible dict."""
        return {
            "server": {
                "host": self._host_edit.text().strip() or "localhost",
                "port": self._port_spin.value(),
                "transport": self._transport_combo.currentText(),
            },
            "analysis": {
                "auto_analysis_wait": self._auto_analysis_cb.isChecked(),
                "analysis_timeout": self._timeout_spin.value(),
                "cache_results": self._cache_results_cb.isChecked(),
            },
            "plugin": {
                "auto_startup": self._auto_startup_cb.isChecked(),
                "show_notifications": self._show_notifications_cb.isChecked(),
            },
            "disabled_tools": self.get_disabled_tools(),
        }

    def get_disabled_tools(self) -> list:
        """Return list of tool names that are unchecked (disabled)."""
        disabled = []
        for tool in TOOL_CATALOG:
            cb = self._tool_checkboxes.get(tool.name)
            if cb and not cb.isChecked():
                disabled.append(tool.name)
        return disabled

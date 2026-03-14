"""
Dockable configuration panel for IDAssistMCP.

Follows the same PluginForm + FormToPyQtWidget pattern as IDAssist.
"""

import idaapi
import ida_kernwin


class IDAssistMCPPanel(idaapi.PluginForm):
    """Singleton dockable form hosting the IDAssistMCP config and log tabs."""

    _instance = None

    @classmethod
    def open(cls, plugin):
        """Open (or focus) the singleton panel.

        Args:
            plugin: IDAssistMCPPlugin instance
        """
        if cls._instance is None:
            cls._instance = IDAssistMCPPanel(plugin)
        cls._instance.Show(
            "IDAssistMCP",
            options=(
                idaapi.PluginForm.WOPN_TAB
                | idaapi.PluginForm.WOPN_RESTORE
                | idaapi.PluginForm.WOPN_PERSIST
            ),
        )

    def __init__(self, plugin):
        super().__init__()
        self._plugin = plugin
        self._config_tab = None
        self._log_tab = None

    def OnCreate(self, form):
        """Called by IDA when the form is first created."""
        try:
            from PySide6.QtWidgets import (
                QHBoxLayout,
                QPushButton,
                QTabWidget,
                QVBoxLayout,
            )

            from .config_tab import ConfigTab
            from .log_tab import LogTab
            from ..logging import install_qt_handler, log

            parent = self.FormToPyQtWidget(form)

            layout = QVBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)

            # Server start/stop button bar
            btn_bar = QHBoxLayout()
            btn_bar.setContentsMargins(8, 4, 8, 0)

            self._toggle_btn = QPushButton("Start Server")
            self._toggle_btn.setMinimumHeight(28)
            self._toggle_btn.clicked.connect(self._on_toggle_server)
            btn_bar.addWidget(self._toggle_btn)

            btn_bar.addStretch()
            layout.addLayout(btn_bar)

            # Tab widget
            tabs = QTabWidget()

            # Configuration tab
            self._config_tab = ConfigTab()
            self._config_tab.save_requested.connect(self._on_save)
            tabs.addTab(self._config_tab, "Configuration")

            # Log tab
            self._log_tab = LogTab()
            tabs.addTab(self._log_tab, "Log")

            layout.addWidget(tabs)
            parent.setLayout(layout)

            # Install Qt log handler so log messages appear in the Log tab
            install_qt_handler(self._log_tab.get_handler())

            # Load current config into widgets
            if self._plugin._config is not None:
                self._config_tab.load_from_config(self._plugin._config)

            # Update button/status based on server state
            self._update_server_ui()

            log.log_info("IDAssistMCP config panel created")

        except Exception as e:
            ida_kernwin.msg(f"[IDAssistMCP] Failed to create config panel: {e}\n")
            import traceback
            ida_kernwin.msg(f"[IDAssistMCP] {traceback.format_exc()}\n")

    def OnClose(self, form):
        """Called by IDA when the form is closed."""
        from ..logging import install_qt_handler
        install_qt_handler(None)
        IDAssistMCPPanel._instance = None

    def _on_save(self):
        """Handle save button click."""
        from ..config import IDAssistMCPConfig, DEFAULT_CONFIG_PATH
        from ..logging import log

        try:
            config_dict = self._config_tab.get_config_dict()
            new_config = IDAssistMCPConfig(**config_dict)

            errors = new_config.validate()
            if errors:
                ida_kernwin.msg(f"[IDAssistMCP] Config validation errors: {errors}\n")
                return

            new_config.save_to_file(DEFAULT_CONFIG_PATH)
            self._plugin._config = new_config
            log.log_info("Configuration saved and applied")

        except Exception as e:
            ida_kernwin.msg(f"[IDAssistMCP] Failed to save config: {e}\n")

    def _on_toggle_server(self):
        """Handle start/stop server button."""
        if self._plugin._server and self._plugin._server.is_running():
            self._plugin._stop_server()
        else:
            self._plugin._start_server()

        self._update_server_ui()

    def _update_server_ui(self):
        """Sync button text and log tab status with server state."""
        running = self._plugin._server is not None and self._plugin._server.is_running()

        if self._toggle_btn is not None:
            self._toggle_btn.setText("Stop Server" if running else "Start Server")

        if self._log_tab is not None:
            self._log_tab.set_server_status(running)

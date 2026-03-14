"""
Qt environment validation for IDAssistMCP.

Duplicated from IDAssist's ida_compat.py to keep the two plugins
independently deployable (no cross-plugin import dependency).
"""

import os


def check_qt_platform_plugins():
    """Lightweight file-existence check for Qt platform plugins.

    Does NOT import PySide6 — checks the filesystem to detect whether
    the platform plugins directory exists. Call before importing PySide6
    in OnCreate to prevent the fatal abort() that Qt triggers when
    platform plugins are missing (which Python cannot catch).

    Returns:
        (ok: bool, error_msg: str or None)
    """
    try:
        import importlib.util
        spec = importlib.util.find_spec("PySide6")
        if spec is None or spec.origin is None:
            return False, "PySide6 is not installed or not importable"

        pyside6_dir = os.path.dirname(spec.origin)
        plugins_dir = os.path.join(pyside6_dir, "Qt", "plugins", "platforms")
        if not os.path.isdir(plugins_dir):
            return False, (
                f"Qt platform plugins directory not found at {plugins_dir}. "
                "This usually means PySide6 is incomplete or corrupted. "
                "Try: pip install --force-reinstall PySide6"
            )
        return True, None
    except Exception as e:
        return False, f"Qt platform plugin check failed: {e}"


def check_qt_environment():
    """Validate the Qt/PySide6 environment for use in IDA plugins.

    Performs import tests, version logging, conflict detection, and
    platform plugin checks.

    Returns:
        (ok: bool, diagnostics: str)
    """
    diag_lines = []

    # 1. Import test
    try:
        import PySide6
        import PySide6.QtCore
    except ImportError as e:
        return False, f"PySide6 import failed: {e}"

    # 2. Version logging
    pyside_ver = PySide6.__version__
    qt_ver = PySide6.QtCore.qVersion()
    diag_lines.append(f"PySide6 {pyside_ver}, Qt {qt_ver}")

    # 3. Conflicting install detection
    pyside_path = os.path.realpath(PySide6.__file__)
    if "site-packages" in pyside_path:
        try:
            import idaapi
            ida_dir = os.path.dirname(idaapi.get_ida_directory() or "")
            if ida_dir and not pyside_path.startswith(ida_dir):
                diag_lines.append(
                    f"WARNING: PySide6 loaded from pip site-packages ({pyside_path}) "
                    "which may shadow IDA's bundled Qt and cause crashes. "
                    "Consider: pip uninstall PySide6"
                )
        except Exception:
            pass

    # 4. Platform plugin check
    ok, err = check_qt_platform_plugins()
    if not ok:
        diag_lines.append(f"FATAL: {err}")
        return False, "; ".join(diag_lines)

    # 5. QApplication check
    try:
        from PySide6.QtWidgets import QApplication
        if QApplication.instance() is None:
            diag_lines.append("Note: QApplication not yet created (may be normal during early init)")
    except Exception:
        pass

    return True, "; ".join(diag_lines)

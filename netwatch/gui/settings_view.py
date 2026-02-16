"""
NetWatch - Settings View
Provides configuration controls including baseline management,
scan preferences, and dependency status.
"""

import logging
import os

from PyQt5.QtCore    import Qt
from PyQt5.QtWidgets import (
    QFrame, QGroupBox, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

logger = logging.getLogger("netwatch.settings_view")

_BASELINE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "baseline.json"
)


class SettingsView(QWidget):
    """
    Settings screen with:
    - Baseline management (reset)
    - Dependency health check
    - Application information
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(30, 30, 30, 30)
        outer.setSpacing(20)

        # ---- Page title ----
        title = QLabel("Settings")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #00d4ff;")
        outer.addWidget(title)

        # ---- Baseline section ----
        baseline_box = self._section("Anomaly Detection Baseline")
        b_layout = QVBoxLayout(baseline_box)
        b_layout.setSpacing(10)

        self._baseline_info = QLabel(self._baseline_status())
        self._baseline_info.setStyleSheet("color: #aaa; font-size: 12px;")
        b_layout.addWidget(self._baseline_info)

        btn_row = QHBoxLayout()

        reset_btn = self._make_btn("🔄  Reset Baseline", "#ffaa00", "#000")
        reset_btn.setToolTip(
            "Delete the saved baseline so the next scan creates a fresh one."
        )
        reset_btn.clicked.connect(self._reset_baseline)
        btn_row.addWidget(reset_btn)
        btn_row.addStretch()
        b_layout.addLayout(btn_row)

        outer.addWidget(baseline_box)

        # ---- Dependency check section ----
        dep_box = self._section("Dependency Health Check")
        d_layout = QVBoxLayout(dep_box)

        check_btn = self._make_btn("🔍  Check Dependencies", "#00d4ff", "#000")
        check_btn.clicked.connect(self._check_deps)
        d_layout.addWidget(check_btn)

        self._dep_label = QLabel("Click above to check installed dependencies.")
        self._dep_label.setStyleSheet("color: #888; font-size: 12px;")
        self._dep_label.setWordWrap(True)
        d_layout.addWidget(self._dep_label)

        outer.addWidget(dep_box)

        # ---- About section ----
        about_box = self._section("About NetWatch")
        a_layout = QVBoxLayout(about_box)
        about_text = QLabel(
            "<b>NetWatch v1.0.0</b><br>"
            "Defensive network security monitor for Windows.<br><br>"
            "<b>Security Policy:</b><br>"
            "• Only scans localhost (127.0.0.1)<br>"
            "• No aggressive scan techniques<br>"
            "• No vulnerability exploitation<br>"
            "• All firewall changes require confirmation<br><br>"
            "<b>Logs:</b>  netwatch/logs/netwatch.log"
        )
        about_text.setStyleSheet("color: #aaa; font-size: 12px; line-height: 160%;")
        about_text.setTextFormat(Qt.RichText)
        about_text.setWordWrap(True)
        a_layout.addWidget(about_text)
        outer.addWidget(about_box)

        outer.addStretch()
        self.setStyleSheet("background-color: #010409;")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _section(title: str) -> QGroupBox:
        box = QGroupBox(title)
        box.setStyleSheet("""
            QGroupBox {
                color: #00d4ff;
                border: 1px solid #1e2d3d;
                border-radius: 8px;
                margin-top: 10px;
                font-size: 13px;
                font-weight: bold;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
            }
        """)
        return box

    @staticmethod
    def _make_btn(label: str, bg: str, fg: str) -> QPushButton:
        btn = QPushButton(label)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg}; color: {fg};
                border: none; padding: 9px 22px;
                font-size: 13px; font-weight: bold; border-radius: 6px;
            }}
            QPushButton:hover {{ opacity: 0.85; }}
        """)
        return btn

    def _baseline_status(self) -> str:
        if os.path.exists(_BASELINE_PATH) and os.path.getsize(_BASELINE_PATH) > 5:
            size = os.path.getsize(_BASELINE_PATH)
            mtime = os.path.getmtime(_BASELINE_PATH)
            from datetime import datetime
            ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            return f"Baseline file found  ({size} bytes, last updated: {ts})"
        return "No baseline file found.  Run a scan to create one."

    def _reset_baseline(self):
        reply = QMessageBox.question(
            self, "Reset Baseline",
            "Delete the saved baseline?\n\n"
            "The next scan will create a new baseline and anomaly detection "
            "will not flag anything until the scan after that.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            from core.anomaly_detector import AnomalyDetector
            AnomalyDetector().reset_baseline()
            self._baseline_info.setText("Baseline reset.  Run a new scan to create a fresh baseline.")
            QMessageBox.information(self, "Done", "Baseline has been reset.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _check_deps(self):
        """Check which required packages are available."""
        packages = {
            "PyQt5":        "PyQt5",
            "nmap":         "python-nmap",
            "networkx":     "networkx",
            "matplotlib":   "matplotlib",
            "reportlab":    "reportlab (optional - PDF export)",
            "sklearn":      "scikit-learn (optional - ML anomaly detection)",
            "numpy":        "numpy",
        }

        lines = []
        for module, desc in packages.items():
            try:
                __import__(module)
                lines.append(f"✅  {desc}")
            except ImportError:
                lines.append(f"❌  {desc}  — pip install {module}")

        self._dep_label.setText("\n".join(lines))
        self._dep_label.setStyleSheet(
            "color: #ccc; font-size: 12px; line-height: 160%;"
        )

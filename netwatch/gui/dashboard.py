"""
NetWatch - Dashboard View
Displays risk summary, key statistics, and quick-action buttons.
"""

import logging
from datetime import datetime
from typing import Dict

from PyQt5.QtCore    import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget,
)

logger = logging.getLogger("netwatch.dashboard")


# ---------------------------------------------------------------------------
# Risk Gauge Widget
# ---------------------------------------------------------------------------

class RiskGauge(QFrame):
    """
    Large centered widget displaying the numeric risk percentage
    and a color-coded status label.

    Color thresholds:
      0–30  → Green  (SECURE)
      31–70 → Yellow (WARNING)
      71–100→ Red    (CRITICAL)
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(6)

        self._pct_label = QLabel("—")
        self._pct_label.setAlignment(Qt.AlignCenter)

        self._status_label = QLabel("NO DATA")
        self._status_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(self._pct_label)
        layout.addWidget(self._status_label)

        self.setMinimumSize(220, 220)
        self._apply_color("#888888", "NO DATA")

    def _apply_color(self, color: str, status: str):
        self._pct_label.setStyleSheet(
            f"font-size: 68px; font-weight: bold; color: {color};"
        )
        self._status_label.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {color}; letter-spacing: 3px;"
        )
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #0d1117;
                border-radius: 18px;
                border: 3px solid {color};
            }}
        """)
        self._status_label.setText(status)

    def update_risk(self, percent: int):
        """
        Refresh the display for the given risk percentage.

        Args:
            percent: Integer 0–100.
        """
        self._pct_label.setText(f"{percent}%")

        if percent <= 30:
            self._apply_color("#00ff88", "SECURE")
        elif percent <= 70:
            self._apply_color("#ffaa00", "WARNING")
        else:
            self._apply_color("#ff4444", "CRITICAL")


# ---------------------------------------------------------------------------
# Stat Card Widget
# ---------------------------------------------------------------------------

class StatCard(QFrame):
    """
    Compact card widget showing a single KPI with an icon, value, and label.
    """

    def __init__(self, title: str, icon: str = "", value: str = "—", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(4)

        icon_lbl = QLabel(icon)
        icon_lbl.setAlignment(Qt.AlignCenter)
        icon_lbl.setStyleSheet("font-size: 28px;")

        self._value_lbl = QLabel(str(value))
        self._value_lbl.setAlignment(Qt.AlignCenter)
        self._value_lbl.setStyleSheet(
            "font-size: 26px; font-weight: bold; color: #00d4ff;"
        )

        title_lbl = QLabel(title)
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet("font-size: 11px; color: #888;")

        layout.addWidget(icon_lbl)
        layout.addWidget(self._value_lbl)
        layout.addWidget(title_lbl)

        self.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border-radius: 10px;
                border: 1px solid #1e2d3d;
                padding: 8px;
                min-width: 140px;
                min-height: 110px;
            }
        """)

    def update_value(self, value):
        """Update the displayed KPI value."""
        self._value_lbl.setText(str(value))


# ---------------------------------------------------------------------------
# Dashboard View
# ---------------------------------------------------------------------------

class DashboardView(QWidget):
    """
    Main dashboard screen showing risk gauge, statistics, and action buttons.

    Signals:
        run_scan_requested:    Emitted when user clicks "Run Scan".
        apply_fixes_requested: Emitted when user clicks "Apply Suggested Fixes".
    """

    run_scan_requested    = pyqtSignal()
    apply_fixes_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scan_data: Dict = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # ---- Page title ----
        title = QLabel("Security Dashboard")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #00d4ff;")
        layout.addWidget(title)

        # ---- Top content row: gauge + stat cards ----
        content_row = QHBoxLayout()
        content_row.setSpacing(30)

        self.risk_gauge = RiskGauge()
        content_row.addWidget(self.risk_gauge)

        # Stat card grid
        stats_frame  = QFrame()
        stats_layout = QGridLayout(stats_frame)
        stats_layout.setSpacing(15)
        stats_layout.setContentsMargins(0, 0, 0, 0)

        self.card_ports     = StatCard("Open Ports",       "🔌")
        self.card_firewall  = StatCard("Firewall Issues",  "🔥")
        self.card_anomalies = StatCard("Anomalies",        "⚠️")
        self.card_timestamp = StatCard("Last Scan",        "🕐", "Never")

        stats_layout.addWidget(self.card_ports,     0, 0)
        stats_layout.addWidget(self.card_firewall,  0, 1)
        stats_layout.addWidget(self.card_anomalies, 1, 0)
        stats_layout.addWidget(self.card_timestamp, 1, 1)

        content_row.addWidget(stats_frame)
        content_row.addStretch()
        layout.addLayout(content_row)

        # ---- Action buttons ----
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self._run_btn = self._make_button("▶  Run Scan",              "#00d4ff", "#000000")
        self._fix_btn = self._make_button("🔧  Apply Suggested Fixes","#ff6b35", "#ffffff")
        self._pdf_btn = self._make_button("📄  Export PDF Report",    "#6c5ce7", "#ffffff")

        self._run_btn.clicked.connect(self.run_scan_requested)
        self._fix_btn.clicked.connect(self.apply_fixes_requested)
        self._pdf_btn.clicked.connect(self._export_pdf)

        btn_row.addWidget(self._run_btn)
        btn_row.addWidget(self._fix_btn)
        btn_row.addWidget(self._pdf_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # ---- Info / last scan summary bar ----
        self._info_label = QLabel(
            "Welcome to NetWatch.  Click  'Run Scan'  to begin analysis."
        )
        self._info_label.setWordWrap(True)
        self._info_label.setStyleSheet("""
            QLabel {
                color: #aaa;
                background-color: #0d1117;
                border: 1px solid #1e2d3d;
                border-radius: 6px;
                padding: 14px;
                font-size: 13px;
            }
        """)
        layout.addWidget(self._info_label)
        layout.addStretch()

        self.setStyleSheet("background-color: #010409;")

    @staticmethod
    def _make_button(label: str, bg: str, fg: str) -> QPushButton:
        btn = QPushButton(label)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {fg};
                border: none;
                padding: 11px 28px;
                font-size: 13px;
                font-weight: bold;
                border-radius: 6px;
            }}
            QPushButton:hover   {{ opacity: 0.85; }}
            QPushButton:disabled {{ background-color: #555; color: #888; }}
        """)
        return btn

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def update_stats(self, scan_data: Dict):
        """
        Refresh all dashboard widgets from new scan data.

        Args:
            scan_data: Combined dict from ScanWorker containing
                       risk_percent, open_ports_count, etc.
        """
        logger.info("Updating dashboard statistics")
        self._scan_data = scan_data

        risk_pct   = scan_data.get("risk_percent", 0)
        ports      = scan_data.get("open_ports_count", 0)
        fw_issues  = scan_data.get("firewall_issues_count", 0)
        anomalies  = scan_data.get("anomaly_count", 0)
        timestamp  = scan_data.get("timestamp", datetime.now().strftime("%H:%M:%S"))

        self.risk_gauge.update_risk(risk_pct)
        self.card_ports.update_value(ports)
        self.card_firewall.update_value(fw_issues)
        self.card_anomalies.update_value(anomalies)
        self.card_timestamp.update_value(timestamp)

        self._info_label.setText(
            f"Scan completed at {timestamp}.  "
            f"{ports} open port(s) found,  "
            f"{fw_issues} firewall issue(s),  "
            f"{anomalies} anomaly(ies) detected.  "
            f"Overall risk: {risk_pct}%"
        )

    def _export_pdf(self):
        """Handle PDF export button click."""
        try:
            if not self._scan_data:
                QMessageBox.warning(
                    self, "No Scan Data",
                    "Please run a scan before exporting a report."
                )
                return

            path, _ = QFileDialog.getSaveFileName(
                self, "Save PDF Report",
                f"netwatch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "PDF Files (*.pdf)",
            )
            if not path:
                return

            from core.pdf_exporter import PDFExporter
            exporter = PDFExporter()
            exporter.export(path, self._scan_data)
            QMessageBox.information(self, "Export Successful", f"Report saved to:\n{path}")

        except ImportError:
            QMessageBox.warning(
                self, "Missing Dependency",
                "PDF export requires reportlab.\n\nFix: pip install reportlab",
            )
        except Exception as exc:
            logger.error(f"PDF export failed: {exc}", exc_info=True)
            QMessageBox.critical(self, "Export Failed", str(exc))

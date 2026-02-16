"""
NetWatch - Scan Network View
Runs a localhost nmap scan in a background QThread and displays port results.
"""

import logging
from datetime import datetime

from PyQt5.QtCore    import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui     import QColor
from PyQt5.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QProgressBar, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

logger = logging.getLogger("netwatch.scan_view")


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    """
    Runs the full scan pipeline in a background thread:
      NetworkScanner → FirewallAnalyzer → RiskEngine → AnomalyDetector

    Signals:
        scan_complete(dict): Combined results dict on success.
        scan_error(str):     Error message on failure.
        progress(str):       Status message updates.
    """

    scan_complete = pyqtSignal(dict)
    scan_error    = pyqtSignal(str)
    progress      = pyqtSignal(str)

    def run(self):
        """Execute the full scan pipeline."""
        try:
            # ---- 1. Port scan ----
            self.progress.emit("Initializing nmap scanner…")
            from core.scanner import NetworkScanner
            scanner = NetworkScanner()

            self.progress.emit("Scanning localhost (ports 1–10000)…")
            scan_results = scanner.scan_localhost()

            # ---- 2. Firewall analysis ----
            self.progress.emit("Querying Windows Firewall rules via PowerShell…")
            from core.firewall import FirewallAnalyzer
            fw_analyzer  = FirewallAnalyzer()
            fw_results   = fw_analyzer.analyze()

            # ---- 3. Risk scoring ----
            self.progress.emit("Calculating risk score…")
            from core.risk_engine import RiskEngine
            risk_engine  = RiskEngine()
            risk_percent = risk_engine.calculate_risk(scan_results, fw_results)
            hints        = risk_engine.get_remediation_hints(scan_results, fw_results)

            # ---- 4. Anomaly detection ----
            self.progress.emit("Checking for anomalies against baseline…")
            from core.anomaly_detector import AnomalyDetector
            detector  = AnomalyDetector()
            anomalies = detector.detect(scan_results)

            # ---- 5. Combine ----
            open_ports = [
                p for p in scan_results.get("ports", [])
                if p.get("state") == "open"
            ]

            combined = {
                "scan_results":           scan_results,
                "firewall_results":       fw_results,
                "risk_percent":           risk_percent,
                "open_ports_count":       len(open_ports),
                "firewall_issues_count":  len(fw_results.get("issues", [])),
                "anomaly_count":          len(anomalies),
                "anomalies":              anomalies,
                "remediation_hints":      hints,
                "timestamp":              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            self.scan_complete.emit(combined)

        except Exception as exc:
            logger.error(f"ScanWorker failed: {exc}", exc_info=True)
            self.scan_error.emit(str(exc))


# ---------------------------------------------------------------------------
# Scan View
# ---------------------------------------------------------------------------

class ScanView(QWidget):
    """
    Displays scan controls and a table of discovered open ports/services.

    Signals:
        scan_completed(dict): Emitted with combined results after a successful scan.
    """

    scan_completed = pyqtSignal(dict)

    # Risk-level color mapping
    _RISK_COLORS = {
        "Critical": QColor("#ff4444"),
        "Risky":    QColor("#ffaa00"),
        "Low":      QColor("#00ff88"),
        "Closed":   QColor("#666666"),
    }

    CRITICAL_PORTS = frozenset({21, 22, 23, 445, 3389})
    RISKY_PORTS    = frozenset({25, 80, 110, 143, 443, 3306, 5432, 5900, 8080, 8443})

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: ScanWorker | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(14)

        # ---- Header row ----
        header = QHBoxLayout()
        title  = QLabel("Network Scan")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #00d4ff;")
        header.addWidget(title)
        header.addStretch()

        self._scan_btn = QPushButton("▶  Run Scan")
        self._scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4ff; color: #000;
                border: none; padding: 10px 26px;
                font-size: 13px; font-weight: bold; border-radius: 6px;
            }
            QPushButton:hover    { background-color: #00bcd4; }
            QPushButton:disabled { background-color: #555; color: #888; }
        """)
        self._scan_btn.clicked.connect(self.run_scan)
        header.addWidget(self._scan_btn)
        layout.addLayout(header)

        # ---- Progress / status ----
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)   # Indeterminate spinner
        self._progress_bar.setVisible(False)
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setStyleSheet("""
            QProgressBar         { border: none; background: #0d1117; border-radius: 3px; }
            QProgressBar::chunk  { background-color: #00d4ff; border-radius: 3px; }
        """)
        layout.addWidget(self._progress_bar)

        self._status_label = QLabel("Ready.  Click 'Run Scan' to start.")
        self._status_label.setStyleSheet("color: #888; font-size: 12px;")
        layout.addWidget(self._status_label)

        # ---- Results table ----
        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Port", "Service", "State", "Risk Level"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                alternate-background-color: #111820;
                color: #ccc;
                border: 1px solid #1e2d3d;
                gridline-color: #1e2d3d;
                font-size: 13px;
            }
            QHeaderView::section {
                background-color: #161b22;
                color: #00d4ff;
                border: 1px solid #1e2d3d;
                padding: 8px;
                font-weight: bold;
            }
            QTableWidget::item:selected { background-color: #1e2d3d; }
        """)
        layout.addWidget(self._table)

        self.setStyleSheet("background-color: #010409;")

    # ------------------------------------------------------------------
    # Public method - can be called externally (e.g. from main_window)
    # ------------------------------------------------------------------

    def run_scan(self):
        """Start a scan. Safe to call from the main thread."""
        if self._worker and self._worker.isRunning():
            return   # Prevent double-start

        self._scan_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._status_label.setText("Starting scan…")
        self._table.setRowCount(0)

        self._worker = ScanWorker()
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_error.connect(self._on_scan_error)
        self._worker.progress.connect(self._status_label.setText)
        self._worker.start()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @pyqtSlot(dict)
    def _on_scan_complete(self, data: dict):
        """Handle successful scan completion."""
        self._scan_btn.setEnabled(True)
        self._progress_bar.setVisible(False)
        self._status_label.setText(f"Scan complete — {data['timestamp']}")

        # Populate table with open ports
        ports = data.get("scan_results", {}).get("ports", [])
        self._populate_table(ports)

        # Show anomaly popup if any were detected
        anomalies = data.get("anomalies", [])
        if anomalies:
            msg = "\n".join(f"• {a}" for a in anomalies)
            QMessageBox.warning(
                self,
                "⚠️ Anomaly Detected",
                f"The following network anomalies were detected:\n\n{msg}",
            )

        self.scan_completed.emit(data)

    @pyqtSlot(str)
    def _on_scan_error(self, error_msg: str):
        """Handle scan failure."""
        self._scan_btn.setEnabled(True)
        self._progress_bar.setVisible(False)
        self._status_label.setText(f"Scan failed: {error_msg}")
        QMessageBox.critical(
            self,
            "Scan Error",
            f"The scan encountered an error:\n\n{error_msg}\n\n"
            "Ensure:\n"
            "• nmap is installed and on your PATH\n"
            "• The application is run as Administrator",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _populate_table(self, ports: list):
        """Fill the results table with port data."""
        self._table.setRowCount(len(ports))

        for row, p in enumerate(ports):
            port_num = p.get("port", 0)
            service  = p.get("service", "unknown") or "unknown"
            state    = p.get("state", "unknown")

            if p.get("is_critical"):
                risk  = "Critical"
            elif p.get("is_risky"):
                risk  = "Risky"
            elif state == "open":
                risk  = "Low"
            else:
                risk  = "Closed"

            color = self._RISK_COLORS.get(risk, QColor("#888888"))

            for col, text in enumerate([str(port_num), service, state, risk]):
                item = QTableWidgetItem(text)
                item.setForeground(color)
                item.setTextAlignment(Qt.AlignCenter)
                self._table.setItem(row, col, item)

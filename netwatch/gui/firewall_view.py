"""
NetWatch - Firewall Analysis View
Queries Windows Firewall rules via PowerShell and displays detected issues.
Provides Disable / Remove actions for selected rules.
"""

import logging

from PyQt5.QtCore    import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui     import QColor
from PyQt5.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QProgressBar, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

logger = logging.getLogger("netwatch.firewall_view")


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

class FirewallWorker(QThread):
    """
    Runs FirewallAnalyzer.analyze() in a background thread.

    Signals:
        complete(dict): Analysis results on success.
        error(str):     Error message on failure.
        progress(str):  Status text updates.
    """

    complete = pyqtSignal(dict)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)

    def run(self):
        try:
            self.progress.emit("Querying Windows Firewall via PowerShell…")
            from core.firewall import FirewallAnalyzer
            results = FirewallAnalyzer().analyze()
            self.complete.emit(results)
        except Exception as exc:
            logger.error(f"FirewallWorker failed: {exc}", exc_info=True)
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# Firewall View
# ---------------------------------------------------------------------------

class FirewallView(QWidget):
    """
    Displays Windows Firewall misconfiguration analysis in a table.
    Allows the user to disable or remove selected rules.
    """

    _SEVERITY_COLORS = {
        "Critical": QColor("#ff4444"),
        "High":     QColor("#ff6b35"),
        "Medium":   QColor("#ffaa00"),
        "Low":      QColor("#00ff88"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._issues: list = []
        self._worker: FirewallWorker | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(14)

        # ---- Header row ----
        header = QHBoxLayout()
        title  = QLabel("Firewall Analysis")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #00d4ff;")
        header.addWidget(title)
        header.addStretch()

        self._analyze_btn = QPushButton("🔍  Analyze Firewall")
        self._analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #00d4ff; color: #000;
                border: none; padding: 10px 26px;
                font-size: 13px; font-weight: bold; border-radius: 6px;
            }
            QPushButton:hover    { background-color: #00bcd4; }
            QPushButton:disabled { background-color: #555; color: #888; }
        """)
        self._analyze_btn.clicked.connect(self._run_analysis)
        header.addWidget(self._analyze_btn)
        layout.addLayout(header)

        # ---- Progress / status ----
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setVisible(False)
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setStyleSheet("""
            QProgressBar         { border: none; background: #0d1117; border-radius: 3px; }
            QProgressBar::chunk  { background-color: #00d4ff; border-radius: 3px; }
        """)
        layout.addWidget(self._progress_bar)

        self._status_label = QLabel(
            "Click 'Analyze Firewall' to scan Windows Firewall rules."
        )
        self._status_label.setStyleSheet("color: #888; font-size: 12px;")
        layout.addWidget(self._status_label)

        # ---- Issues table ----
        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(
            ["Rule Name", "Issue Type", "Severity", "Suggested Fix"]
        )
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setWordWrap(True)
        self._table.setStyleSheet("""
            QTableWidget {
                background-color: #0d1117;
                alternate-background-color: #111820;
                color: #ccc;
                border: 1px solid #1e2d3d;
                gridline-color: #1e2d3d;
                font-size: 12px;
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

        # ---- Action buttons ----
        action_row = QHBoxLayout()

        self._disable_btn = QPushButton("⏸  Disable Rule")
        self._disable_btn.setStyleSheet("""
            QPushButton {
                background-color: #ffaa00; color: #000;
                border: none; padding: 10px 22px;
                font-weight: bold; border-radius: 6px; font-size: 13px;
            }
            QPushButton:hover { background-color: #e09900; }
        """)
        self._disable_btn.clicked.connect(self._disable_selected)

        self._remove_btn = QPushButton("🗑  Remove Rule")
        self._remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff4444; color: #fff;
                border: none; padding: 10px 22px;
                font-weight: bold; border-radius: 6px; font-size: 13px;
            }
            QPushButton:hover { background-color: #dd3333; }
        """)
        self._remove_btn.clicked.connect(self._remove_selected)

        action_row.addWidget(self._disable_btn)
        action_row.addWidget(self._remove_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        self.setStyleSheet("background-color: #010409;")

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _run_analysis(self):
        """Start firewall analysis worker."""
        if self._worker and self._worker.isRunning():
            return

        self._analyze_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._table.setRowCount(0)
        self._issues = []

        self._worker = FirewallWorker()
        self._worker.complete.connect(self._on_complete)
        self._worker.error.connect(self._on_error)
        self._worker.progress.connect(self._status_label.setText)
        self._worker.start()

    @pyqtSlot(dict)
    def _on_complete(self, data: dict):
        self._analyze_btn.setEnabled(True)
        self._progress_bar.setVisible(False)
        self._issues = data.get("issues", [])
        count = len(self._issues)
        total = data.get("total_rules", 0)
        self._status_label.setText(
            f"Analysis complete.  {count} issue(s) found across {total} rule(s)."
        )
        self._populate_table(self._issues)

    @pyqtSlot(str)
    def _on_error(self, error_msg: str):
        self._analyze_btn.setEnabled(True)
        self._progress_bar.setVisible(False)
        self._status_label.setText(f"Analysis failed: {error_msg}")
        QMessageBox.critical(
            self,
            "Firewall Analysis Error",
            f"Error:\n{error_msg}\n\n"
            "Ensure the application is run as Administrator.",
        )

    def _populate_table(self, issues: list):
        """Fill the table with issue data."""
        self._table.setRowCount(len(issues))
        for row, issue in enumerate(issues):
            severity = issue.get("severity", "Low")
            color    = self._SEVERITY_COLORS.get(severity, QColor("#888888"))

            cells = [
                issue.get("rule_name",     "Unknown"),
                issue.get("issue_type",    "Unknown"),
                severity,
                issue.get("suggested_fix", "Review this rule"),
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(str(text))
                item.setForeground(color)
                self._table.setItem(row, col, item)

        self._table.resizeRowsToContents()

    # ------------------------------------------------------------------
    # Rule actions
    # ------------------------------------------------------------------

    def _get_selected_rule_name(self) -> str | None:
        """Return the rule name for the currently selected row, or None."""
        row = self._table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection",
                                "Please select a rule from the table first.")
            return None
        if row < len(self._issues):
            return self._issues[row].get("rule_name")
        return None

    def _disable_selected(self):
        name = self._get_selected_rule_name()
        if not name:
            return

        reply = QMessageBox.question(
            self, "Confirm Disable",
            f"Disable firewall rule:\n\n  '{name}'\n\n"
            "This may affect network connectivity.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            from core.firewall import FirewallAnalyzer
            ok = FirewallAnalyzer().disable_rule(name)
            if ok:
                QMessageBox.information(self, "Done", f"Rule '{name}' disabled.")
                self._run_analysis()   # Refresh list
            else:
                QMessageBox.warning(self, "Failed",
                                    f"Could not disable '{name}'.\n"
                                    "Ensure you are running as Administrator.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _remove_selected(self):
        name = self._get_selected_rule_name()
        if not name:
            return

        reply = QMessageBox.question(
            self, "Confirm Remove",
            f"PERMANENTLY REMOVE firewall rule:\n\n  '{name}'\n\n"
            "This action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            from core.firewall import FirewallAnalyzer
            ok = FirewallAnalyzer().remove_rule(name)
            if ok:
                QMessageBox.information(self, "Done", f"Rule '{name}' removed.")
                self._run_analysis()   # Refresh list
            else:
                QMessageBox.warning(self, "Failed",
                                    f"Could not remove '{name}'.\n"
                                    "Ensure you are running as Administrator.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

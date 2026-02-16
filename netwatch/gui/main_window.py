"""
NetWatch - Main Application Window
Provides the outer shell with a left-sidebar navigation and a stacked content area.
"""

import logging

from PyQt5.QtCore    import Qt
from PyQt5.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QMainWindow,
    QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

from gui.dashboard     import DashboardView
from gui.scan_view     import ScanView
from gui.firewall_view import FirewallView
from gui.attack_view   import AttackView
from gui.settings_view import SettingsView

logger = logging.getLogger("netwatch.main_window")


class MainWindow(QMainWindow):
    """
    Main application window.

    Layout:
    ┌────────────┬──────────────────────────────┐
    │  Sidebar   │   Stacked content area        │
    │  (nav)     │   (Dashboard / Scan /          │
    │            │    Firewall / Attack / Settings)│
    └────────────┴──────────────────────────────┘
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetWatch — Network Security Monitor")
        self.setMinimumSize(1200, 760)
        self._setup_ui()
        self._connect_signals()
        # Select Dashboard on startup
        self._navigate(0)
        logger.info("MainWindow initialized")

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build and lay out all UI components."""
        root  = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)

        # Sidebar
        self._sidebar = self._build_sidebar()
        root_layout.addWidget(self._sidebar)

        # Stacked content
        self._stack = QStackedWidget()
        root_layout.addWidget(self._stack)

        # Instantiate views
        self.dashboard     = DashboardView()
        self.scan_view     = ScanView()
        self.firewall_view = FirewallView()
        self.attack_view   = AttackView()
        self.settings_view = SettingsView()

        for view in (
            self.dashboard,
            self.scan_view,
            self.firewall_view,
            self.attack_view,
            self.settings_view,
        ):
            self._stack.addWidget(view)

    def _build_sidebar(self) -> QFrame:
        """Create the left navigation sidebar."""
        sidebar = QFrame()
        sidebar.setFixedWidth(210)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #0d1117;
                border-right: 1px solid #1e2d3d;
            }
        """)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ---- Logo / title ----
        logo = QLabel("🛡 NetWatch")
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("""
            QLabel {
                color: #00d4ff;
                font-size: 19px;
                font-weight: bold;
                padding: 22px 10px;
                border-bottom: 1px solid #1e2d3d;
            }
        """)
        layout.addWidget(logo)

        # ---- Navigation buttons ----
        self._nav_buttons: list[QPushButton] = []
        nav_items = [
            ("🏠  Dashboard",              0),
            ("🔍  Scan Network",           1),
            ("🔥  Firewall Analysis",      2),
            ("🕸  Attack Visualization",   3),
            ("⚙️  Settings",              4),
        ]
        for label, index in nav_items:
            btn = self._make_nav_button(label, index)
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addStretch()

        # ---- Version footer ----
        version = QLabel("v1.0.0  ·  Defensive Only")
        version.setAlignment(Qt.AlignCenter)
        version.setStyleSheet("color: #444; font-size: 10px; padding: 12px;")
        layout.addWidget(version)

        return sidebar

    def _make_nav_button(self, label: str, index: int) -> QPushButton:
        """Create a single sidebar navigation button."""
        btn = QPushButton(label)
        btn.setCheckable(True)
        btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #888;
                border: none;
                border-left: 3px solid transparent;
                padding: 14px 18px;
                text-align: left;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #161b22;
                color: #ccc;
            }
            QPushButton:checked {
                background-color: #161b22;
                color: #00d4ff;
                border-left: 3px solid #00d4ff;
                font-weight: bold;
            }
        """)
        btn.clicked.connect(lambda _checked, i=index: self._navigate(i))
        return btn

    # ------------------------------------------------------------------
    # Signal wiring
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect cross-view signals."""
        # Dashboard "Run Scan" button → navigate to Scan view + trigger scan
        self.dashboard.run_scan_requested.connect(self._trigger_scan_from_dashboard)

        # "Apply Suggested Fixes" → navigate to Firewall view and run analysis
        self.dashboard.apply_fixes_requested.connect(self._trigger_firewall_from_dashboard)

        # When scan finishes → update dashboard stats and attack graph
        self.scan_view.scan_completed.connect(self.dashboard.update_stats)
        self.scan_view.scan_completed.connect(self.attack_view.update_graph)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _navigate(self, index: int):
        """Switch to the view at the given stack index."""
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        logger.debug(f"Navigated to view index {index}")

    # ------------------------------------------------------------------
    # Cross-view triggers
    # ------------------------------------------------------------------

    def _trigger_scan_from_dashboard(self):
        """Navigate to Scan view and start a scan automatically."""
        self._navigate(1)
        self.scan_view.run_scan()

    def _trigger_firewall_from_dashboard(self):
        """Navigate to Firewall view and start analysis automatically."""
        self._navigate(2)
        self.firewall_view._run_analysis()

"""
NetWatch - Attack Visualization View
Renders a NetworkX attack-path graph using matplotlib embedded in PyQt5.
"""

import logging

from PyQt5.QtCore    import Qt
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

logger = logging.getLogger("netwatch.attack_view")

# Set backend BEFORE any other matplotlib import
try:
    import matplotlib
    matplotlib.use("Qt5Agg")
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure                  import Figure
    from matplotlib.patches                 import Patch
    _MATPLOTLIB_OK = True
except Exception as _mpl_err:
    logger.warning(f"matplotlib not available: {_mpl_err}")
    _MATPLOTLIB_OK = False


# ---------------------------------------------------------------------------
# Matplotlib canvas wrapper
# ---------------------------------------------------------------------------

class AttackGraphCanvas(FigureCanvas if _MATPLOTLIB_OK else QWidget):
    """
    Embeddable matplotlib canvas that draws the attack-path graph.
    Falls back to a plain QLabel if matplotlib is unavailable.
    """

    def __init__(self, parent=None):
        if _MATPLOTLIB_OK:
            self._fig = Figure(figsize=(11, 6), facecolor="#010409", tight_layout=True)
            super().__init__(self._fig)
            self._ax = self._fig.add_subplot(111)
            self._draw_placeholder()
        else:
            super().__init__(parent)
            lbl = QLabel("matplotlib is not installed.\nRun: pip install matplotlib", self)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("color:#888; font-size:14px;")

    def _draw_placeholder(self):
        """Show a placeholder message before any scan data is loaded."""
        self._ax.clear()
        self._ax.set_facecolor("#0d1117")
        self._ax.text(
            0.5, 0.5,
            "Run a scan to generate the attack graph",
            ha="center", va="center",
            fontsize=14, color="#555",
            transform=self._ax.transAxes,
        )
        self._ax.set_xticks([])
        self._ax.set_yticks([])
        for spine in self._ax.spines.values():
            spine.set_edgecolor("#1e2d3d")
        self.draw()

    def update_graph(self, scan_data: dict):
        """
        Rebuild and render the attack graph from scan data.

        Args:
            scan_data: Combined scan dict from ScanWorker.
        """
        if not _MATPLOTLIB_OK:
            return

        try:
            import networkx as nx
        except ImportError:
            logger.warning("networkx not installed — cannot draw graph.")
            self._ax.clear()
            self._ax.text(0.5, 0.5, "networkx not installed.\npip install networkx",
                          ha="center", va="center", fontsize=13, color="#ff4444",
                          transform=self._ax.transAxes)
            self.draw()
            return

        try:
            from core.attack_graph import AttackGraphBuilder

            G, node_colors, edge_colors, labels = AttackGraphBuilder().build(scan_data)

            if G.number_of_nodes() == 0:
                self._draw_placeholder()
                return

            self._ax.clear()
            self._ax.set_facecolor("#0d1117")
            self._fig.set_facecolor("#010409")

            # Layout
            pos = nx.spring_layout(G, seed=42, k=2.2)

            # Draw
            nx.draw_networkx_nodes(
                G, pos,
                node_color=node_colors,
                node_size=1600,
                ax=self._ax,
                alpha=0.92,
            )
            nx.draw_networkx_edges(
                G, pos,
                edge_color=edge_colors,
                ax=self._ax,
                arrows=True,
                arrowsize=22,
                width=2,
                alpha=0.85,
            )
            nx.draw_networkx_labels(
                G, pos,
                labels=labels,
                ax=self._ax,
                font_size=8,
                font_color="white",
                font_weight="bold",
            )

            # Title
            self._ax.set_title(
                "Attack Path Visualization  (red = critical risk)",
                color="#00d4ff",
                fontsize=13,
                pad=14,
            )
            self._ax.set_xticks([])
            self._ax.set_yticks([])
            for spine in self._ax.spines.values():
                spine.set_edgecolor("#1e2d3d")

            # Legend
            legend_elements = [
                Patch(facecolor="#4466ff", edgecolor="none", label="Localhost"),
                Patch(facecolor="#ff4444", edgecolor="none", label="Critical Port/Service"),
                Patch(facecolor="#ffaa00", edgecolor="none", label="Medium Risk"),
                Patch(facecolor="#00ff88", edgecolor="none", label="Low Risk"),
            ]
            self._ax.legend(
                handles=legend_elements,
                loc="upper left",
                facecolor="#161b22",
                edgecolor="#1e2d3d",
                labelcolor="white",
                fontsize=9,
            )

            self.draw()

        except Exception as exc:
            logger.error(f"Graph rendering failed: {exc}", exc_info=True)
            self._draw_placeholder()


# ---------------------------------------------------------------------------
# Attack View widget
# ---------------------------------------------------------------------------

class AttackView(QWidget):
    """
    Screen containing the attack-path graph canvas and a legend/info bar.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(12)

        # ---- Header ----
        header = QHBoxLayout()
        title  = QLabel("Attack Path Visualization")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #00d4ff;")
        header.addWidget(title)
        header.addStretch()

        info = QLabel("Red paths = critical attack vectors  |  Blue node = localhost")
        info.setStyleSheet("color: #666; font-size: 11px;")
        header.addWidget(info)
        layout.addLayout(header)

        # ---- Canvas ----
        self._canvas = AttackGraphCanvas()
        layout.addWidget(self._canvas)

        self.setStyleSheet("background-color: #010409;")

    def update_graph(self, scan_data: dict):
        """
        Update the graph with new scan data.

        Args:
            scan_data: Combined scan results dict from ScanWorker.
        """
        self._canvas.update_graph(scan_data)

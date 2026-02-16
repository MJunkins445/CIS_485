"""
NetWatch - Attack Graph Builder
Constructs a directed NetworkX graph representing potential attack paths
from the local network scan results.
"""

import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("netwatch.attack_graph")


class AttackGraphBuilder:
    """
    Builds a NetworkX DiGraph showing attack paths from open ports to localhost.

    Node types:
    - Localhost node (blue)
    - Port nodes (color-coded by risk level)
    - Service nodes (color-coded by risk level)

    Edge direction: port → service → localhost
    Critical path edges are colored red.
    """

    CRITICAL_PORTS    = frozenset({21, 22, 23, 445, 3389})
    MEDIUM_RISK_PORTS = frozenset({25, 80, 110, 143, 443, 3306, 5432, 5900, 8080, 8443})

    # (port_color, service_color, edge_color) by risk level
    _COLORS = {
        "critical": ("#ff4444", "#ff6b6b", "#ff0000"),
        "medium":   ("#ffaa00", "#ffc857", "#ffaa00"),
        "low":      ("#00ff88", "#00d4aa", "#00cc66"),
    }

    def build(self, scan_data: Dict) -> Tuple:
        """
        Build the attack graph from combined scan data.

        Args:
            scan_data: The combined scan dict emitted by the ScanWorker,
                       containing 'scan_results' key.

        Returns:
            Tuple of (G, node_colors, edge_colors, labels) where:
            - G is a networkx.DiGraph
            - node_colors is a list of hex color strings matching G.nodes()
            - edge_colors is a list of hex color strings matching G.edges()
            - labels is a dict {node_id: display_label}
        """
        try:
            import networkx as nx
        except ImportError:
            raise RuntimeError("networkx not installed. Run: pip install networkx")

        G = nx.DiGraph()
        node_color_map: Dict[str, str] = {}
        edge_colors: List[str] = []
        labels: Dict[str, str] = {}

        ports = scan_data.get("scan_results", {}).get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]

        if not open_ports:
            logger.info("No open ports - attack graph will be empty.")
            return G, [], [], {}

        # --- Add localhost node ---
        G.add_node("localhost")
        node_color_map["localhost"] = "#4466ff"
        labels["localhost"] = "localhost\n(target)"

        # --- Add port and service nodes ---
        for port_info in open_ports:
            port_num  = port_info.get("port", 0)
            service   = port_info.get("service", "unknown") or "unknown"

            # Determine risk tier
            if port_num in self.CRITICAL_PORTS:
                tier = "critical"
            elif port_num in self.MEDIUM_RISK_PORTS or port_info.get("is_risky", False):
                tier = "medium"
            else:
                tier = "low"

            port_color, svc_color, edge_color = self._COLORS[tier]

            # Node IDs
            port_node = f"port_{port_num}"
            svc_node  = f"svc_{port_num}"

            # Truncate service label for readability
            svc_label = service[:14] if service else "unknown"

            # Add nodes
            G.add_node(port_node)
            G.add_node(svc_node)
            node_color_map[port_node] = port_color
            node_color_map[svc_node]  = svc_color
            labels[port_node] = f":{port_num}"
            labels[svc_node]  = svc_label

            # Add edges: port → service → localhost
            G.add_edge(port_node, svc_node)
            edge_colors.append(edge_color)

            G.add_edge(svc_node, "localhost")
            edge_colors.append(edge_color)

        # Build ordered node color list (must match G.nodes() iteration order)
        node_colors = [node_color_map.get(node, "#888888") for node in G.nodes()]

        logger.info(
            f"Attack graph: {G.number_of_nodes()} nodes, "
            f"{G.number_of_edges()} edges"
        )
        return G, node_colors, edge_colors, labels

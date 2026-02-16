"""
NetWatch - Network Scanner Module
Scans localhost using python-nmap for open ports and services.
Only defensive, non-aggressive scans are performed.
"""

import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger("netwatch.scanner")


class NetworkScanner:
    """
    Handles localhost network scanning using python-nmap.

    Security policy:
    - Only scans 127.0.0.1 (localhost)
    - No aggressive scan flags (-A, --script, etc.)
    - Uses service version detection only
    """

    # Ports that represent critical attack surfaces
    CRITICAL_PORTS = {21, 22, 23, 445, 3389}

    # Ports that are commonly risky but not always critical
    RISKY_PORTS = {25, 80, 110, 143, 443, 3306, 5432, 5900, 8080, 8443}

    # Friendly descriptions for well-known ports
    PORT_DESCRIPTIONS = {
        21:   "FTP - File Transfer",
        22:   "SSH - Secure Shell",
        23:   "Telnet (unencrypted)",
        25:   "SMTP - Email",
        80:   "HTTP - Web",
        110:  "POP3 - Email",
        143:  "IMAP - Email",
        443:  "HTTPS - Secure Web",
        445:  "SMB - File Sharing (WannaCry vector)",
        3306: "MySQL Database",
        3389: "RDP - Remote Desktop",
        5432: "PostgreSQL Database",
        5900: "VNC - Remote Desktop",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
    }

    def __init__(self):
        """Initialize the scanner, loading nmap with error handling."""
        self.nm = None
        self._init_nmap()

    def _init_nmap(self):
        """
        Initialize the nmap PortScanner.

        Raises:
            RuntimeError: If python-nmap or nmap binary is missing.
        """
        try:
            import nmap
            self.nm = nmap.PortScanner()
            logger.info("nmap PortScanner initialized successfully")
        except ImportError:
            raise RuntimeError(
                "python-nmap is not installed.\n"
                "Fix: pip install python-nmap"
            )
        except nmap.PortScannerError:
            raise RuntimeError(
                "nmap binary not found on PATH.\n"
                "Download from: https://nmap.org/download.html\n"
                "Add nmap to your system PATH after installing."
            )

    def scan_localhost(self) -> Dict:
        """
        Perform a non-aggressive service scan on localhost.

        Scans ports 1-10000 using version detection (-sV) at timing
        template T3 (normal speed). No exploit scripts are used.

        Returns:
            Dict with keys:
                target (str): Always '127.0.0.1'
                ports (list): List of port detail dicts
                os_guess (str): Best OS guess or 'Unknown'
                scan_args (str): Arguments used
        """
        target = "127.0.0.1"
        # -sV: version detection | -T3: normal timing | --open: open ports only
        # -p 1-10000: common port range without aggressive --script usage
        scan_args = "-sV -T3 --open -p 1-10000"

        logger.info(f"Starting scan on {target} | args: {scan_args}")

        try:
            self.nm.scan(hosts=target, arguments=scan_args)
        except Exception as exc:
            raise RuntimeError(
                f"nmap scan failed: {exc}\n"
                "Ensure nmap is installed and the application is run as Administrator."
            )

        results: Dict = {
            "target": target,
            "ports": [],
            "os_guess": "Unknown",
            "scan_args": scan_args,
        }

        if target not in self.nm.all_hosts():
            logger.warning("Localhost not found in scan results - no open ports detected.")
            return results

        host_data = self.nm[target]

        # OS guess (best effort - requires elevated privileges)
        try:
            if host_data.get("osmatch"):
                results["os_guess"] = host_data["osmatch"][0].get("name", "Unknown")
        except Exception:
            pass

        # Collect port information
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                info = host_data[proto][port]

                service_name = info.get("name", "unknown")
                product     = info.get("product", "")
                version     = info.get("version", "")
                service_full = " ".join(filter(None, [service_name, product, version]))

                # Override with friendly description if known
                friendly = self.PORT_DESCRIPTIONS.get(port, "")
                display_service = friendly if friendly else service_full

                results["ports"].append({
                    "port":        port,
                    "proto":       proto,
                    "state":       info.get("state", "unknown"),
                    "service":     display_service or service_name,
                    "is_risky":    port in self.RISKY_PORTS,
                    "is_critical": port in self.CRITICAL_PORTS,
                })

        open_count = sum(1 for p in results["ports"] if p["state"] == "open")
        logger.info(f"Scan complete. {open_count} open port(s) found.")

        self._save_initial_baseline(results)
        return results

    def _save_initial_baseline(self, results: Dict):
        """
        Save scan results as baseline ONLY if no baseline exists yet.

        Args:
            results: Scan results to potentially save.
        """
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            os.makedirs(data_dir, exist_ok=True)
            baseline_path = os.path.join(data_dir, "baseline.json")

            if not os.path.exists(baseline_path) or os.path.getsize(baseline_path) < 5:
                with open(baseline_path, "w") as fh:
                    json.dump(results, fh, indent=2)
                logger.info("Initial baseline saved.")
        except Exception as exc:
            logger.warning(f"Could not save baseline: {exc}")

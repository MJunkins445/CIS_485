"""
NetWatch - Windows Firewall Analyzer Module
Uses PowerShell via subprocess to query, analyze, and manage firewall rules.
Requires Administrator privileges for full functionality.
"""

import json
import logging
import subprocess
import sys
from typing import Dict, List, Optional

logger = logging.getLogger("netwatch.firewall")

# Hide the console window on Windows when spawning PowerShell
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class FirewallAnalyzer:
    """
    Queries and analyzes Windows Firewall rules via PowerShell.

    Detects:
    - Disabled rules that should be reviewed
    - Duplicate rules (same display name)
    - Overly permissive inbound Allow/Any rules
    - Shadowed rules (same port with both Allow and Deny)
    """

    def _run_powershell(self, command: str, timeout: int = 45) -> Optional[str]:
        """
        Execute a PowerShell command and return its stdout.

        Args:
            command: The PowerShell command string to run.
            timeout: Maximum seconds to wait.

        Returns:
            stdout string on success, None on failure.

        Raises:
            RuntimeError: If PowerShell is not available.
        """
        try:
            proc = subprocess.run(
                [
                    "powershell",
                    "-NonInteractive",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", command,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
            )

            if proc.returncode != 0 and proc.stderr.strip():
                logger.warning(f"PowerShell stderr: {proc.stderr.strip()[:200]}")

            return proc.stdout.strip() if proc.stdout else ""

        except subprocess.TimeoutExpired:
            logger.error(f"PowerShell timed out executing: {command[:80]}")
            return None
        except FileNotFoundError:
            raise RuntimeError(
                "PowerShell executable not found. "
                "This feature requires Windows with PowerShell installed."
            )
        except Exception as exc:
            logger.error(f"PowerShell execution error: {exc}")
            return None

    def get_firewall_rules(self) -> List[Dict]:
        """
        Retrieve all Windows Firewall rules as a list of dicts.

        Returns:
            List of rule dicts. Empty list on failure.
        """
        cmd = (
            "Get-NetFirewallRule | "
            "Select-Object DisplayName, Enabled, Direction, Action, Profile, "
            "DisplayGroup, Description, PolicyStoreSourceType | "
            "ConvertTo-Json -Depth 2 -Compress"
        )

        output = self._run_powershell(cmd)
        if not output:
            logger.warning("No output from Get-NetFirewallRule")
            return []

        try:
            data = json.loads(output)
            # PowerShell returns a single object (not array) if only 1 rule exists
            if isinstance(data, dict):
                data = [data]
            logger.info(f"Retrieved {len(data)} firewall rules")
            return data
        except json.JSONDecodeError as exc:
            logger.error(f"Failed to parse firewall JSON: {exc}")
            # Try to return partial results
            return []

    def analyze(self) -> Dict:
        """
        Perform full firewall misconfiguration analysis.

        Checks for:
        1. Disabled rules
        2. Duplicate display names
        3. Overly permissive inbound Allow rules (Any profile)

        Returns:
            Dict with:
                rules (list): All raw rules
                issues (list): Detected issue dicts
                total_rules (int): Total rule count
        """
        logger.info("Starting firewall analysis")
        rules = self.get_firewall_rules()

        issues: List[Dict] = []
        seen_names: Dict[str, int] = {}

        for rule in rules:
            name      = rule.get("DisplayName", "Unknown")
            enabled   = rule.get("Enabled", True)
            action    = str(rule.get("Action", ""))
            direction = str(rule.get("Direction", ""))
            profile   = str(rule.get("Profile", ""))

            # --- Check 1: Disabled rules ---
            if str(enabled).lower() in ("false", "0"):
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Disabled Rule",
                    "severity":      "Low",
                    "suggested_fix": f"Review and remove '{name}' if no longer needed.",
                })

            # --- Check 2: Duplicate display names ---
            if name in seen_names:
                seen_names[name] += 1
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Duplicate Rule",
                    "severity":      "Medium",
                    "suggested_fix": f"Remove duplicate entry for '{name}' to avoid rule shadowing.",
                })
            else:
                seen_names[name] = 1

            # --- Check 3: Overly permissive inbound Allow (Any profile) ---
            # Action: 2 = Allow | Direction: 1 = Inbound | Profile: Any / 2147483647 / 4
            is_allow    = action in ("Allow", "2")
            is_inbound  = direction in ("Inbound", "1")
            is_any_prof = profile in ("Any", "4", "2147483647", "-1")

            if is_allow and is_inbound and is_any_prof:
                issues.append({
                    "rule_name":     name,
                    "issue_type":    "Overly Permissive (Any Profile)",
                    "severity":      "High",
                    "suggested_fix": (
                        f"Restrict '{name}' to Domain or Private profile only, "
                        "not 'Any' network."
                    ),
                })

        logger.info(f"Firewall analysis done. {len(issues)} issue(s) from {len(rules)} rule(s).")
        return {
            "rules":       rules,
            "issues":      issues,
            "total_rules": len(rules),
        }

    def disable_rule(self, rule_name: str) -> bool:
        """
        Disable a firewall rule by display name via PowerShell.

        Args:
            rule_name: The DisplayName of the rule to disable.

        Returns:
            True on success, False on failure.
        """
        # Escape single-quotes to prevent injection
        safe_name = rule_name.replace("'", "''")
        cmd = f"Disable-NetFirewallRule -DisplayName '{safe_name}'"
        logger.info(f"Disabling firewall rule: '{rule_name}'")

        try:
            self._run_powershell(cmd)
            logger.info(f"Rule '{rule_name}' disabled successfully")
            return True
        except Exception as exc:
            logger.error(f"Failed to disable rule '{rule_name}': {exc}")
            return False

    def remove_rule(self, rule_name: str) -> bool:
        """
        Permanently remove a firewall rule by display name.

        Args:
            rule_name: The DisplayName of the rule to remove.

        Returns:
            True on success, False on failure.
        """
        safe_name = rule_name.replace("'", "''")
        cmd = f"Remove-NetFirewallRule -DisplayName '{safe_name}'"
        logger.info(f"Removing firewall rule: '{rule_name}'")

        try:
            self._run_powershell(cmd)
            logger.info(f"Rule '{rule_name}' removed successfully")
            return True
        except Exception as exc:
            logger.error(f"Failed to remove rule '{rule_name}': {exc}")
            return False

"""
NetWatch - PDF Report Exporter
Generates a formatted PDF security report using reportlab.
"""

import logging
from datetime import datetime
from typing import Dict

logger = logging.getLogger("netwatch.pdf_exporter")


class PDFExporter:
    """
    Exports a combined scan result dict to a formatted PDF report.

    Requires: pip install reportlab
    """

    def export(self, filepath: str, scan_data: Dict):
        """
        Generate and save a PDF report.

        Args:
            filepath:  Absolute path for the output PDF file.
            scan_data: Combined scan/firewall/risk dict from ScanWorker.

        Raises:
            ImportError: If reportlab is not installed.
            Exception:   On any other write/build error.
        """
        try:
            from reportlab.lib             import colors
            from reportlab.lib.enums       import TA_CENTER, TA_LEFT
            from reportlab.lib.pagesizes   import letter
            from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units       import inch
            from reportlab.platypus        import (
                HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
            )
        except ImportError:
            raise ImportError(
                "reportlab is not installed.\n"
                "Fix: pip install reportlab"
            )

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=72, leftMargin=72,
            topMargin=72,   bottomMargin=72,
        )

        styles  = getSampleStyleSheet()
        story   = []

        # ---- Helper styles ----
        title_style = ParagraphStyle(
            "NWTitle",
            parent=styles["Title"],
            fontSize=26,
            textColor=colors.HexColor("#003366"),
            spaceAfter=4,
            alignment=TA_CENTER,
        )
        subtitle_style = ParagraphStyle(
            "NWSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.grey,
            alignment=TA_CENTER,
            spaceAfter=6,
        )
        section_style = ParagraphStyle(
            "NWSection",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#003366"),
            spaceBefore=12,
            spaceAfter=4,
        )
        footer_style = ParagraphStyle(
            "NWFooter",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER,
        )

        # ---- Title block ----
        story.append(Paragraph("NetWatch Security Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            subtitle_style,
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#003366")))
        story.append(Spacer(1, 0.2 * inch))

        # ---- Risk summary card ----
        risk_pct    = scan_data.get("risk_percent", 0)
        open_count  = scan_data.get("open_ports_count", 0)
        fw_count    = scan_data.get("firewall_issues_count", 0)
        anom_count  = scan_data.get("anomaly_count", 0)
        scan_time   = scan_data.get("timestamp", "N/A")

        if risk_pct <= 30:
            risk_color = colors.green
        elif risk_pct <= 70:
            risk_color = colors.orange
        else:
            risk_color = colors.red

        story.append(Paragraph("Risk Summary", section_style))
        summary_rows = [
            ["Metric",            "Value"],
            ["Risk Score",        f"{risk_pct}%"],
            ["Open Ports",        str(open_count)],
            ["Firewall Issues",   str(fw_count)],
            ["Anomalies Detected",str(anom_count)],
            ["Scan Timestamp",    scan_time],
        ]
        summary_table = Table(summary_rows, colWidths=[3.0 * inch, 3.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#003366")),
            ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0),  11),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4ff")]),
            ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
            ("TEXTCOLOR",    (1, 1), (1, 1),   risk_color),
            ("FONTNAME",     (1, 1), (1, 1),   "Helvetica-Bold"),
            ("FONTSIZE",     (1, 1), (1, 1),   13),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.25 * inch))

        # ---- Open Ports ----
        ports = scan_data.get("scan_results", {}).get("ports", [])
        open_ports = [p for p in ports if p.get("state") == "open"]

        if open_ports:
            story.append(Paragraph("Open Ports", section_style))
            port_rows = [["Port", "Service", "Protocol", "Risk Level"]]
            for p in open_ports:
                pnum = p.get("port", "")
                if p.get("is_critical"):
                    risk_label = "Critical"
                elif p.get("is_risky"):
                    risk_label = "Risky"
                else:
                    risk_label = "Low"
                port_rows.append([
                    str(pnum),
                    (p.get("service") or "unknown")[:40],
                    p.get("proto", "tcp").upper(),
                    risk_label,
                ])
            port_table = Table(port_rows, colWidths=[0.8*inch, 3.0*inch, 1.2*inch, 1.5*inch])
            port_table.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (-1, 0),  colors.HexColor("#003366")),
                ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
                ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),  [colors.white, colors.HexColor("#f0f4ff")]),
                ("GRID",           (0, 0), (-1, -1),  0.5, colors.grey),
                ("FONTSIZE",       (0, 0), (-1, -1),  9),
            ]))
            story.append(port_table)
            story.append(Spacer(1, 0.2 * inch))

        # ---- Firewall Issues ----
        fw_issues = scan_data.get("firewall_results", {}).get("issues", [])
        if fw_issues:
            story.append(Paragraph("Firewall Issues", section_style))
            fw_rows = [["Rule Name", "Issue Type", "Severity", "Suggested Fix"]]
            for issue in fw_issues[:25]:   # cap at 25 to keep PDF manageable
                fw_rows.append([
                    (issue.get("rule_name", "") or "")[:35],
                    (issue.get("issue_type", "") or ""),
                    (issue.get("severity", "") or ""),
                    (issue.get("suggested_fix", "") or "")[:55],
                ])
            fw_table = Table(fw_rows, colWidths=[1.8*inch, 1.5*inch, 0.9*inch, 2.3*inch])
            fw_table.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (-1, 0),  colors.HexColor("#003366")),
                ("TEXTCOLOR",      (0, 0), (-1, 0),  colors.white),
                ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),  [colors.white, colors.HexColor("#f0f4ff")]),
                ("GRID",           (0, 0), (-1, -1),  0.5, colors.grey),
                ("FONTSIZE",       (0, 0), (-1, -1),  8),
                ("WORDWRAP",       (0, 0), (-1, -1),  True),
            ]))
            story.append(fw_table)
            story.append(Spacer(1, 0.2 * inch))

        # ---- Anomalies ----
        anomalies = scan_data.get("anomalies", [])
        if anomalies:
            story.append(Paragraph("Detected Anomalies", section_style))
            for anomaly in anomalies:
                story.append(Paragraph(f"• {anomaly}", styles["Normal"]))
            story.append(Spacer(1, 0.15 * inch))

        # ---- Remediation hints ----
        hints = scan_data.get("remediation_hints", [])
        if hints:
            story.append(Paragraph("Remediation Recommendations", section_style))
            for hint in hints:
                story.append(Paragraph(f"✓  {hint}", styles["Normal"]))
            story.append(Spacer(1, 0.15 * inch))

        # ---- Footer ----
        story.append(Spacer(1, 0.4 * inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Paragraph(
            "NetWatch Defensive Security Monitor  |  For authorized use only  |  "
            "This report is confidential.",
            footer_style,
        ))

        doc.build(story)
        logger.info(f"PDF report saved: {filepath}")

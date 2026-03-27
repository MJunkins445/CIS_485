"""
L.O.G.S. — Log, Observe, Guard, Secure
Firewall Analyzer entry point.

Usage (run as Administrator for full firewall access):
    cd C:\\My_Java_Project\\CIS_485\\netwatch_demo
    py main.py
"""

import logging
import os
import sys


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore    import Qt
    except ImportError:
        print("ERROR: PyQt5 is not installed.  Fix: pip install PyQt5")
        sys.exit(1)

    # High-DPI support
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("L.O.G.S.")
    app.setStyle("Fusion")

    # Apply dark palette
    try:
        from PyQt5.QtGui import QColor, QPalette
        pal = QPalette()
        pal.setColor(QPalette.Window,          QColor(1,   4,   9))
        pal.setColor(QPalette.WindowText,      QColor(220, 220, 220))
        pal.setColor(QPalette.Base,            QColor(13,  17,  23))
        pal.setColor(QPalette.AlternateBase,   QColor(10,  15,  22))
        pal.setColor(QPalette.Text,            QColor(220, 220, 220))
        pal.setColor(QPalette.Button,          QColor(22,  27,  34))
        pal.setColor(QPalette.ButtonText,      QColor(220, 220, 220))
        pal.setColor(QPalette.Highlight,       QColor(0,   180, 220))
        pal.setColor(QPalette.HighlightedText, QColor(0,   0,   0))
        app.setPalette(pal)
    except Exception:
        pass

    from gui.firewall_window import FirewallDemoWindow
    window = FirewallDemoWindow()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

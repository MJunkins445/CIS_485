"""
NetWatch - Entry Point
Defensive network security monitor for Windows.

Usage:
    python main.py

Requirements:
    - Windows 10/11
    - Python 3.11+
    - Run as Administrator for full functionality (nmap + firewall changes)
    - See requirements.txt for Python package dependencies
    - nmap binary must be installed: https://nmap.org/download.html
"""

import logging
import os
import sys


def setup_logging() -> logging.Logger:
    """
    Configure application-wide logging to both file and console.

    Log files are stored in netwatch/logs/netwatch.log.

    Returns:
        Root 'netwatch' logger instance.
    """
    log_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "netwatch.log")

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  —  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler    = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)

    root_logger = logging.getLogger("netwatch")
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    return root_logger


def main():
    """Application entry point."""
    logger = setup_logging()
    logger.info("=" * 60)
    logger.info("NetWatch starting")
    logger.info("=" * 60)

    # Ensure the data directory exists
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    os.makedirs(data_dir, exist_ok=True)

    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore    import Qt
    except ImportError:
        print("ERROR: PyQt5 is not installed.")
        print("Fix:   pip install PyQt5")
        sys.exit(1)

    # Enable High-DPI support
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("NetWatch")
    app.setApplicationVersion("1.0.0")
    app.setStyle("Fusion")

    # Dark palette for the Fusion style
    try:
        from PyQt5.QtGui import QColor, QPalette

        palette = QPalette()
        dark    = QColor(15, 15, 20)
        mid     = QColor(30, 30, 40)
        text    = QColor(220, 220, 220)
        hilite  = QColor(0, 180, 220)

        palette.setColor(QPalette.Window,          dark)
        palette.setColor(QPalette.WindowText,      text)
        palette.setColor(QPalette.Base,            QColor(13, 17, 23))
        palette.setColor(QPalette.AlternateBase,   mid)
        palette.setColor(QPalette.ToolTipBase,     dark)
        palette.setColor(QPalette.ToolTipText,     text)
        palette.setColor(QPalette.Text,            text)
        palette.setColor(QPalette.Button,          mid)
        palette.setColor(QPalette.ButtonText,      text)
        palette.setColor(QPalette.BrightText,      QColor(255, 100, 100))
        palette.setColor(QPalette.Highlight,       hilite)
        palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
        app.setPalette(palette)
    except Exception as pal_err:
        logger.warning(f"Could not apply dark palette: {pal_err}")

    try:
        from gui.main_window import MainWindow
    except Exception as import_err:
        logger.critical(f"Failed to import MainWindow: {import_err}", exc_info=True)
        try:
            from PyQt5.QtWidgets import QMessageBox
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Startup Error")
            msg.setText(f"NetWatch failed to start:\n\n{import_err}")
            msg.exec_()
        except Exception:
            print(f"FATAL: {import_err}")
        sys.exit(1)

    window = MainWindow()
    window.show()

    logger.info("MainWindow displayed — entering event loop")
    exit_code = app.exec_()
    logger.info(f"NetWatch exiting with code {exit_code}")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

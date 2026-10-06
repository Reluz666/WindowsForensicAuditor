import sys
from PySide6.QtWidgets import QApplication
from app.gui.v3_main_window import MainWindow

def main():
    app=QApplication(sys.argv)
    app.setApplicationName("Windows Forensic Auditor")
    app.setStyle("Fusion")
    w=MainWindow(); w.show()
    return app.exec()

if __name__=="__main__":
    raise SystemExit(main())

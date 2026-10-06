import sys
from PySide6.QtWidgets import QApplication
from app.gui.main_window import MainWindow as BaseMainWindow
from app.gui.enhancements import build_enhanced_class

MainWindow = build_enhanced_class(BaseMainWindow)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Windows Forensic Auditor")
    w = MainWindow()
    w.show()
    return app.exec()

if __name__ == "__main__":
    raise SystemExit(main())

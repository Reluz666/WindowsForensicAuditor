import sys
import traceback
from PySide6.QtWidgets import QApplication, QMessageBox
from app.gui.v3_main_window import MainWindow

def _excepthook(exc_type, exc, tb):
    msg=''.join(traceback.format_exception(exc_type,exc,tb))
    try:
        QMessageBox.critical(None,'Error inesperado',msg[-5000:])
    except Exception:
        pass
    sys.__excepthook__(exc_type,exc,tb)

def main():
    sys.excepthook=_excepthook
    app=QApplication(sys.argv)
    app.setApplicationName("Windows Forensic Auditor")
    app.setStyle("Fusion")
    w=MainWindow(); w.show()
    return app.exec()

if __name__=="__main__":
    raise SystemExit(main())

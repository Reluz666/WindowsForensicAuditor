from __future__ import annotations
import json, os
from pathlib import Path
from PySide6.QtCore import QThread,Signal
from PySide6.QtWidgets import QMessageBox,QFileDialog
from app.engine import AuditEngine,COLLECTORS
from app.utils.platform import safe_output_root
from app.gui.v2_main_window import MainWindow as V2MainWindow
from app.gui.v3_enhancements import apply_v3,ProfileDialog,PROFILE_MAP,correlate,make_full_package
from app.gui.v3_report import generate_professional_pdf, generate_professional_html

class ProfileWorker(QThread):
    progress=Signal(str,int,int); done=Signal(str,dict); failed=Signal(str)
    def __init__(self,root:Path,selected:set[str],demo:bool):
        super().__init__(); self.engine=AuditEngine(root,lambda n,i,t:self.progress.emit(n,i,t)); self.selected=selected; self.demo=demo
    def run(self):
        try:
            out,summary=self.engine.run(self.selected,self.demo); self.done.emit(str(out),summary)
        except Exception as exc:
            self.failed.emit(f'{type(exc).__name__}: {exc}')

class MainWindow(V2MainWindow):
    def __init__(self):
        super().__init__(); apply_v3(self); self.current_profile='Completa'

    def start_audit(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self,'Auditoría en curso','Ya existe una auditoría en ejecución.'); return
        dlg=ProfileDialog(self)
        if dlg.exec()!=dlg.Accepted:return
        profile,demo=dlg.selection(); self.current_profile=profile
        selected=PROFILE_MAP.get(profile)
        if selected is None: selected={c.name for c in COLLECTORS}
        self.worker=ProfileWorker(Path(safe_output_root()),set(selected),demo)
        self.worker.progress.connect(self._progress); self.worker.done.connect(self._finished); self.worker.failed.connect(self._failed)
        from PySide6.QtWidgets import QMessageBox as MB
        self.progress_box=MB(self); self.progress_box.setWindowTitle('Auditoría en curso'); self.progress_box.setText(f'Perfil: {profile}\nPreparando auditoría...'); self.progress_box.setStandardButtons(MB.Cancel); self.progress_box.buttonClicked.connect(lambda _:self.worker.engine.cancel()); self.progress_box.show()
        self.v3_status.setText(f'Estado: AUDITANDO — {profile.upper()}'); self.worker.start()

    def _progress(self,name,i,total):
        super()._progress(name,i,total)
        self.v3_status.setText(f'Estado: AUDITANDO {i}/{total}')

    def _failed(self,msg):
        self.v3_status.setText('Estado: ERROR'); super()._failed(msg)

    def _finished(self,out,summary):
        if self.progress_box:self.progress_box.close()
        self.output_dir=Path(out)
        try:self.data=json.loads((self.output_dir/'reports'/'audit.json').read_text(encoding='utf-8'))
        except Exception:self.data={'results':[],'findings':[],'risk_score':summary.get('risk_score',0)}
        self.data['audit_id']=summary.get('audit_id'); self.data['risk_score']=summary.get('risk_score',self.data.get('risk_score',0))
        existing=self.data.get('findings') or []
        extra=correlate(self.data)
        seen={(str(x.get('title')),str(x.get('module'))) for x in existing}
        for f in extra:
            if (str(f.get('title')),str(f.get('module'))) not in seen: existing.append(f)
        self.data['findings']=existing
        try:
            generate_professional_pdf(self.data,self.output_dir,self.current_profile)
            generate_professional_html(self.data,self.output_dir,self.current_profile)
        except Exception:
            pass
        self._populate_all(); self.show_page('dashboard'); self.v3_status.setText(f'Estado: COMPLETADA — {self.current_profile.upper()}')
        QMessageBox.information(self,'Auditoría finalizada','La auditoría terminó correctamente.\n\nLos resultados están disponibles en pantalla. Puede usar “Exportar reporte completo” para obtener un único paquete con todos los reportes y evidencias.')

    def export_full_report(self):
        if not self.output_dir:
            QMessageBox.information(self,'Sin auditoría','Primero ejecute una auditoría.'); return
        default=Path.home()/'Desktop'/f'WindowsForensicAuditor_{self.data.get("audit_id","auditoria")}_REPORTE_COMPLETO.zip'
        dst,_=QFileDialog.getSaveFileName(self,'Exportar reporte completo',str(default),'ZIP (*.zip)')
        if not dst:return
        if not dst.lower().endswith('.zip'):dst+='.zip'
        try:
            h,sha=make_full_package(self.output_dir,Path(dst))
            QMessageBox.information(self,'Reporte completo exportado',f'Se exportó el paquete completo:\n{dst}\n\nSHA-256:\n{h}\n\nArchivo de hash:\n{sha}')
        except Exception as exc:
            QMessageBox.critical(self,'Error al exportar',f'{type(exc).__name__}: {exc}')

from __future__ import annotations

import csv
import json
import os
import shutil
from pathlib import Path
from PySide6.QtWidgets import (
    QWidget,QVBoxLayout,QHBoxLayout,QFrame,QLabel,QPushButton,QLineEdit,QTableWidget,
    QTableWidgetItem,QHeaderView,QAbstractItemView,QTextEdit,QFileDialog,QMessageBox,QCheckBox,QApplication
)
from app.utils.platform import relaunch_as_admin,is_admin,safe_output_root
from app.engine import COLLECTORS

MAP={
 'Resumen del sistema':'system','Cuentas de usuario':'accounts','Actividad de procesos':'processes',
 'Red':'network','Network':'network','Servicios':'services','Tareas':'tasks','USB':'usb','Software':'software',
 'Defender':'defender','Persistencia':'persistence','PowerShell':'powershell','Evidence':'evidence','Evidencia':'evidence',
 'Reports':'reports','Reportes':'reports','Settings':'settings','Configuración':'settings','Timeline':'timeline','Línea de tiempo':'timeline',
 'Findings':'findings','Hallazgos':'findings','Remote Access':'remote','Acceso remoto e inicios de sesión':'remote','Logons':'remote',
}
ES={'system':'Resumen del sistema','accounts':'Cuentas de usuario','processes':'Actividad de procesos','network':'Actividad de red','services':'Servicios','tasks':'Tareas programadas','usb':'Dispositivos USB','software':'Software','defender':'Microsoft Defender','persistence':'Persistencia y autoarranque','powershell':'PowerShell','windows_update':'Windows Update','events':'Eventos de Windows','firewall':'Firewall','recent_files':'Archivos recientes'}
STATUS={'SUCCESS':'CORRECTO','PARTIAL':'PARCIAL','FAILED':'FALLÓ','NOT_AVAILABLE':'NO DISPONIBLE','PERMISSION_DENIED':'PERMISO DENEGADO'}

class ModulePage(QWidget):
    def __init__(self,title,owner):
        super().__init__(); self.owner=owner; self.records=[]; root=QVBoxLayout(self); root.setContentsMargins(20,18,20,18); root.setSpacing(12)
        top=QHBoxLayout(); box=QVBoxLayout(); h=QLabel(title); h.setObjectName('pt'); s=QLabel('Resultados recopilados por este módulo. Seleccione una fila para ver el registro completo.'); s.setObjectName('sub'); box.addWidget(h); box.addWidget(s); top.addLayout(box); top.addStretch(); run=QPushButton('＋  Nueva auditoría'); run.setObjectName('primary'); run.clicked.connect(owner.audit); top.addWidget(run); exp=QPushButton('Exportar CSV'); exp.clicked.connect(self.export_csv); top.addWidget(exp); root.addLayout(top)
        f=QFrame(); f.setObjectName('panel'); fl=QHBoxLayout(f); fl.addWidget(QLabel('Buscar / filtrar:')); self.search=QLineEdit(); self.search.setPlaceholderText('Usuario, IP, proceso, ruta, evento, servicio...'); self.search.textChanged.connect(self.filter); fl.addWidget(self.search,1); clear=QPushButton('Limpiar'); clear.clicked.connect(self.search.clear); fl.addWidget(clear); root.addWidget(f)
        split=QHBoxLayout(); a=QFrame(); a.setObjectName('panel'); al=QVBoxLayout(a); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(['Fecha / hora','Elemento','Detalle','Fuente','Estado']); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.table.verticalHeader().hide(); self.table.setSelectionBehavior(QAbstractItemView.SelectRows); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.setAlternatingRowColors(True); self.table.setShowGrid(False); self.table.cellClicked.connect(self.show_row); al.addWidget(self.table); split.addWidget(a,3)
        b=QFrame(); b.setObjectName('panel'); bl=QVBoxLayout(b); t=QLabel('Detalle del registro'); t.setObjectName('sect'); bl.addWidget(t); self.detail=QTextEdit(); self.detail.setReadOnly(True); self.detail.setPlainText('Ejecute una auditoría y seleccione una fila.'); bl.addWidget(self.detail); split.addWidget(b,2); root.addLayout(split,1)
    def load(self,result):
        self.result=result or {}; self.records=list(self.result.get('records') or []); self.table.setRowCount(0)
        if not result: self.add(['—','—','Módulo no ejecutado.','—','NO DISPONIBLE']); return
        st=STATUS.get(result.get('status'),result.get('status','—')); src=result.get('source') or result.get('name') or '—'
        if not self.records: self.add(['—',ES.get(result.get('name'),result.get('name','Módulo')),result.get('error') or 'No se obtuvieron registros disponibles.',src,st]); return
        for rec in self.records[:2000]:
            tm=str(rec.get('time') or rec.get('timestamp') or rec.get('date') or rec.get('created') or '—').replace('T',' ').replace('Z','')
            el=str(rec.get('name') or rec.get('user') or rec.get('display_name') or rec.get('DisplayName') or rec.get('process') or rec.get('event_id') or rec.get('ip') or rec.get('path') or 'Registro')
            detail=self.summary(rec); self.add([tm,el,detail,src,st])
    def summary(self,r):
        keys=['description','command_line','command','path','remote','local','state','reason','action','task','service','ip','username','domain','manufacturer','display_name','version']
        parts=[f'{k}: {r.get(k)}' for k in keys if r.get(k) not in (None,'',[])]; d=r.get('data')
        if not parts and isinstance(d,dict): parts=[f'{k}: {v}' for k,v in list(d.items())[:7] if v not in (None,'')]
        return (' | '.join(parts) or json.dumps(r,ensure_ascii=False,default=str))[:900]
    def add(self,vals):
        r=self.table.rowCount(); self.table.insertRow(r)
        for c,v in enumerate(vals): self.table.setItem(r,c,QTableWidgetItem(str(v)))
    def show_row(self,row,_):
        if row<len(self.records): self.detail.setPlainText(json.dumps(self.records[row],ensure_ascii=False,indent=2,default=str))
    def filter(self,text):
        q=(text or '').lower().strip()
        for r in range(self.table.rowCount()):
            hay=' '.join(self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())).lower(); self.table.setRowHidden(r,bool(q) and q not in hay)
    def export_csv(self):
        path,_=QFileDialog.getSaveFileName(self,'Guardar CSV',str(Path.home()/'Desktop'/f'{self.result.get("name","resultados")}.csv'),'CSV (*.csv)')
        if not path:return
        with open(path,'w',newline='',encoding='utf-8-sig') as f:
            w=csv.writer(f); w.writerow([self.table.horizontalHeaderItem(c).text() for c in range(self.table.columnCount())])
            for r in range(self.table.rowCount()):
                if not self.table.isRowHidden(r): w.writerow([self.table.item(r,c).text() if self.table.item(r,c) else '' for c in range(self.table.columnCount())])
        QMessageBox.information(self,'Exportación completa',f'Archivo guardado en:\n{path}')

class EvidencePage(QWidget):
    def __init__(self,owner):
        super().__init__(); self.owner=owner; l=QVBoxLayout(self); l.setContentsMargins(20,18,20,18); h=QLabel('Evidencia'); h.setObjectName('pt'); l.addWidget(h); s=QLabel('Cobertura y disponibilidad de las fuentes consultadas. Un módulo sin datos no equivale a ausencia de actividad.'); s.setObjectName('sub'); s.setWordWrap(True); l.addWidget(s); top=QHBoxLayout(); top.addStretch(); b=QPushButton('Abrir carpeta de evidencia'); b.clicked.connect(owner.openOut); top.addWidget(b); l.addLayout(top); self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(['Fuente / módulo','Estado','Registros','Origen','Observación']); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.table.verticalHeader().hide(); self.table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.table.setAlternatingRowColors(True); l.addWidget(self.table,1)
    def load(self,results):
        self.table.setRowCount(0)
        for r in results:
            st=STATUS.get(r.get('status'),r.get('status','—')); n=len(r.get('records') or []); obs=r.get('error') or ('Fuente consultada.' if st=='CORRECTO' else 'Revise permisos o disponibilidad de la fuente.'); row=[ES.get(r.get('name'),r.get('name')),st,n,r.get('source') or r.get('name'),obs]; rr=self.table.rowCount(); self.table.insertRow(rr); [self.table.setItem(rr,c,QTableWidgetItem(str(v))) for c,v in enumerate(row)]

class ReportsPage(QWidget):
    def __init__(self,owner):
        super().__init__(); self.owner=owner; l=QVBoxLayout(self); l.setContentsMargins(20,18,20,18); h=QLabel('Reportes'); h.setObjectName('pt'); l.addWidget(h); self.info=QLabel('Ejecute una auditoría para generar los reportes.'); self.info.setWordWrap(True); l.addWidget(self.info); panel=QFrame(); panel.setObjectName('panel'); g=QVBoxLayout(panel)
        for key,label in [('csv','Guardar CSV'),('json','Guardar JSON'),('html','Abrir / guardar HTML'),('pdf','Abrir / guardar PDF'),('zip','Guardar paquete de evidencia ZIP'),('folder','Abrir carpeta de auditoría')]:
            b=QPushButton(label); b.clicked.connect(lambda _,k=key:self.action(k)); g.addWidget(b)
        l.addWidget(panel); l.addStretch()
    def action(self,key):
        out=self.owner.out
        if not out: QMessageBox.information(self,'Sin reportes','Primero ejecute una auditoría.'); return
        if key=='folder': self.owner.openOut(); return
        src={'csv':out/'reports'/'audit.csv','json':out/'reports'/'audit.json','html':out/'reports'/'report.html','pdf':out/'reports'/'report.pdf','zip':out/'reports'/'evidence_package.zip'}[key]
        if not src.exists(): QMessageBox.warning(self,'Archivo no disponible',str(src)); return
        if key in ('html','pdf'):
            try: os.startfile(str(src)); return
            except Exception: pass
        dst,_=QFileDialog.getSaveFileName(self,'Guardar archivo',str(Path.home()/'Desktop'/src.name),'Todos los archivos (*)')
        if dst: shutil.copy2(src,dst); QMessageBox.information(self,'Archivo guardado',dst)

class SettingsPage(QWidget):
    def __init__(self,owner):
        super().__init__(); self.owner=owner; l=QVBoxLayout(self); l.setContentsMargins(20,18,20,18); h=QLabel('Configuración'); h.setObjectName('pt'); l.addWidget(h); p=QFrame(); p.setObjectName('panel'); pl=QVBoxLayout(p); self.demo=QCheckBox('DEMO / TEST MODE (datos ficticios claramente identificados)'); pl.addWidget(self.demo); pl.addWidget(QLabel(f'Directorio de salida predeterminado:\n{safe_output_root()}')); adm=QPushButton('Reiniciar como administrador'); adm.setEnabled(not is_admin()); adm.clicked.connect(self.admin); pl.addWidget(adm); l.addWidget(p); l.addStretch()
    def admin(self):
        if relaunch_as_admin(): QApplication.instance().quit()
        else: QMessageBox.warning(self,'No disponible','Windows no permitió iniciar la aplicación con elevación.')

def build_enhanced_class(Base):
    class EnhancedMainWindow(Base):
        def __init__(self):
            super().__init__(); self.extra_pages={}; self.results_by_name={}; self._install_pages(); self._rewire_nav(); self._translate_existing()
        def _translate_existing(self):
            trans={'Dashboard':'Panel principal','New Audit':'Nueva auditoría','Remote Access':'Acceso remoto e inicios de sesión','Logons':'Acceso remoto e inicios de sesión','Accounts':'Cuentas de usuario','Processes':'Actividad de procesos','Network':'Actividad de red','Services':'Servicios','Tasks':'Tareas programadas','USB':'Dispositivos USB','Software':'Software','Defender':'Microsoft Defender','Persistence':'Persistencia y autoarranque','Timeline':'Línea de tiempo','Findings':'Hallazgos','Evidence':'Evidencia','Reports':'Reportes','Settings':'Configuración'}
            for b,_ in self.nav:
                if b.text() in trans: b.setText(trans[b.text()])
        def _install_pages(self):
            for key in ['system','accounts','processes','network','services','tasks','usb','software','defender','persistence','powershell','events','firewall','recent_files']:
                p=ModulePage(ES[key],self); self.pages.addWidget(p); self.extra_pages[key]=p
            self.evidence_page=EvidencePage(self); self.pages.addWidget(self.evidence_page); self.extra_pages['evidence']=self.evidence_page
            self.reports_page=ReportsPage(self); self.pages.addWidget(self.reports_page); self.extra_pages['reports']=self.reports_page
            self.settings_page=SettingsPage(self); self.pages.addWidget(self.settings_page); self.extra_pages['settings']=self.settings_page
        def _rewire_nav(self):
            by_label={'Panel principal':0,'Dashboard':0,'Acceso remoto e inicios de sesión':1,'Remote Access':1,'Logons':1,'Hallazgos':2,'Findings':2}
            fallback=['dashboard','dashboard','accounts','remote','processes','network','services','tasks','usb','software','defender','persistence','timeline','findings','evidence','reports','settings']
            for idx,(b,old) in enumerate(self.nav):
                try: b.clicked.disconnect()
                except Exception: pass
                text=b.text(); key=MAP.get(text)
                if text in ('New Audit','Nueva auditoría'):
                    b.clicked.connect(self.audit); continue
                if text in by_label: page=by_label[text]
                elif key in self.extra_pages: page=self.pages.indexOf(self.extra_pages[key])
                else:
                    fk=fallback[idx] if idx<len(fallback) else 'dashboard'; page=by_label.get(text, self.pages.indexOf(self.extra_pages[fk]) if fk in self.extra_pages else 0)
                b.clicked.connect(lambda _,p=page:self.pages.setCurrentIndex(p))
        def audit(self):
            if self.worker and self.worker.isRunning(): QMessageBox.information(self,'Auditoría en curso','Ya existe una auditoría en ejecución.'); return
            m=QMessageBox.question(self,'Nueva auditoría','La auditoría puede recopilar información sensible del sistema, incluidos usuarios, IP, procesos y eventos de seguridad.\n\n¿Desea iniciar la auditoría completa?',QMessageBox.Yes|QMessageBox.No)
            if m!=QMessageBox.Yes:return
            demo=getattr(self,'settings_page',None) and self.settings_page.demo.isChecked()
            from app.gui.main_window import Worker
            self.pg=QMessageBox(self); self.pg.setWindowTitle('Auditoría en curso'); self.pg.setText('Preparando auditoría...'); self.pg.setStandardButtons(QMessageBox.Cancel)
            root=Path(safe_output_root()); self.worker=Worker(root); self.worker.e.cancelled=False
            if demo:
                from PySide6.QtCore import QThread,Signal
                class DW(QThread):
                    progress=Signal(str,int,int); ok=Signal(str,dict); fail=Signal(str)
                    def __init__(self,root): super().__init__(); from app.engine import AuditEngine; self.e=AuditEngine(root,lambda n,i,t:self.progress.emit(n,i,t))
                    def run(self):
                        try: out,s=self.e.run({c.name for c in COLLECTORS},True); self.ok.emit(str(out),s)
                        except Exception as x:self.fail.emit(f'{type(x).__name__}: {x}')
                self.worker=DW(root)
            self.worker.progress.connect(lambda n,i,t:self.pg.setText(f'Analizando: {ES.get(n,n)}\nProgreso: {i} de {t} módulos')); self.worker.ok.connect(self.done); self.worker.fail.connect(self.fail); self.pg.buttonClicked.connect(lambda _:self.worker.e.cancel()); self.worker.start(); self.pg.show()
        def done(self,out,s):
            super().done(out,s); self.results_by_name={r.get('name'):r for r in self.data.get('results',[]) or s.get('results',[])}
            for key,p in self.extra_pages.items():
                if isinstance(p,ModulePage): p.load(self.results_by_name.get(key))
            self.evidence_page.load(list(self.results_by_name.values())); self.reports_page.info.setText(f'Auditoría: {s.get("audit_id","—")}\nEstado: {s.get("status","—")}\nCarpeta: {out}')
        def openOut(self):
            return super().openOut()
    return EnhancedMainWindow

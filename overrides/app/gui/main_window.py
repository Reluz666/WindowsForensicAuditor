import json, os
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import QThread,Signal,Qt,QRectF
from PySide6.QtGui import QColor,QPainter,QPen,QBrush
from PySide6.QtWidgets import *
from app.engine import AuditEngine,COLLECTORS
from app.utils.platform import is_admin,safe_output_root

MOD={'system':'Sistema','accounts':'Cuentas','logons':'Inicios de sesión','rdp':'Acceso remoto / RDP','powershell':'PowerShell','processes':'Procesos','network':'Red','services':'Servicios','tasks':'Tareas programadas','usb':'USB','software':'Software','defender':'Microsoft Defender','persistence':'Persistencia','windows_update':'Windows Update','events':'Eventos','firewall':'Firewall','recent_files':'Archivos recientes'}

def card(title,value='—',sub='',color='#2d8cff'):
    f=QFrame(); f.setObjectName('card'); l=QVBoxLayout(f); l.setContentsMargins(15,12,15,12); t=QLabel(title); t.setObjectName('ct'); v=QLabel(value); v.setObjectName('cv'); v.setStyleSheet(f'color:{color}'); s=QLabel(sub); s.setObjectName('cs'); s.setWordWrap(True); l.addWidget(t); l.addWidget(v); l.addWidget(s); f.v=v; f.s=s; return f

class Timeline(QWidget):
    def __init__(self): super().__init__(); self.ev=[]; self.setMinimumHeight(170)
    def setEvents(self,e): self.ev=e[:250]; self.update()
    def paintEvent(self,_):
        p=QPainter(self); p.setRenderHint(QPainter.Antialiasing); w,h=self.width(),self.height(); y=h//2+15; p.setPen(QPen(QColor('#35506c'),1)); p.drawLine(22,y,w-22,y)
        if not self.ev: p.setPen(QColor('#8096aa')); p.drawText(QRectF(0,0,w,h),Qt.AlignCenter,'Sin eventos disponibles'); return
        cs={'ok':'#2494ff','bad':'#ff4d4f','off':'#ff9e32','rdp':'#23c7e8'}; n=max(1,len(self.ev)-1)
        for i,e in enumerate(self.ev):
            x=22+(w-44)*i/n; c=QColor(cs.get(e[0],'#2494ff')); p.setPen(QPen(c,2)); p.drawLine(int(x),y,int(x),y-35-(i%3)*8); p.setBrush(QBrush(c)); p.setPen(Qt.NoPen); p.drawEllipse(QRectF(x-5,y-46-(i%3)*8,10,10))
        p.setPen(QColor('#8096aa')); p.drawText(22,h-10,'Más antiguo'); p.drawText(w-90,h-10,'Más reciente')

class Worker(QThread):
    progress=Signal(str,int,int); ok=Signal(str,dict); fail=Signal(str)
    def __init__(self,root): super().__init__(); self.e=AuditEngine(root,lambda n,i,t:self.progress.emit(n,i,t))
    def run(self):
        try: out,s=self.e.run({c.name for c in COLLECTORS},False); self.ok.emit(str(out),s)
        except Exception as x: self.fail.emit(f'{type(x).__name__}: {x}')

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle('WINDOWS FORENSIC AUDITOR'); self.resize(1500,900); self.setMinimumSize(1150,700); self.worker=None; self.out=None; self.data={}; self._ui(); self._style()
    def _ui(self):
        r=QWidget(); self.setCentralWidget(r); o=QVBoxLayout(r); o.setContentsMargins(0,0,0,0); o.setSpacing(0)
        h=QFrame(); h.setObjectName('head'); x=QHBoxLayout(h); brand=QVBoxLayout(); a=QLabel('▣  WINDOWS FORENSIC AUDITOR'); a.setObjectName('brand'); b=QLabel('Creado por el Equipo Forense de Alejandro'); b.setObjectName('by'); brand.addWidget(a); brand.addWidget(b); x.addLayout(brand); x.addStretch(); self.meta=QLabel('Equipo: —   |   Perfil: Auditoría completa'); x.addWidget(self.meta); o.addWidget(h)
        body=QHBoxLayout(); body.setSpacing(0); o.addLayout(body,1); side=QFrame(); side.setObjectName('side'); side.setFixedWidth(235); sl=QVBoxLayout(side); self.nav=[]
        for text,page in [('Panel principal',0),('Resumen del sistema',0),('Cuentas de usuario',0),('Acceso remoto e inicios de sesión',1),('Actividad de procesos',0),('Actividad de red',0),('Servicios',0),('Tareas programadas',0),('Dispositivos USB',0),('Microsoft Defender',0),('Persistencia',0),('Línea de tiempo',1),('Hallazgos',2),('Evidencia',0),('Reportes',0)]:
            q=QPushButton(text); q.setObjectName('nav'); q.setCheckable(True); q.clicked.connect(lambda _,p=page:self.go(p)); sl.addWidget(q); self.nav.append((q,page))
        sl.addStretch(); self.target=QLabel('🖥  Objetivo actual\n\nSin auditoría ejecutada'); self.target.setObjectName('target'); self.target.setWordWrap(True); sl.addWidget(self.target); body.addWidget(side)
        self.pages=QStackedWidget(); body.addWidget(self.pages,1); self.pages.addWidget(self.dashboard()); self.pages.addWidget(self.remote()); self.pages.addWidget(self.findings()); self.go(0)
    def shell(self,title,sub):
        p=QWidget(); l=QVBoxLayout(p); l.setContentsMargins(20,18,20,18); top=QHBoxLayout(); z=QVBoxLayout(); t=QLabel(title); t.setObjectName('pt'); s=QLabel(sub); s.setObjectName('sub'); z.addWidget(t); z.addWidget(s); top.addLayout(z); top.addStretch(); n=QPushButton('＋  Nueva auditoría'); n.setObjectName('primary'); n.clicked.connect(self.audit); top.addWidget(n); l.addLayout(top); return p,l
    def dashboard(self):
        p,l=self.shell('Panel principal','Resumen comprensible de la auditoría y de la evidencia disponible.'); g=QGridLayout(); self.host=card('Equipo'); self.user=card('Usuario'); self.win=card('Windows'); self.admin=card('Privilegios','ADMINISTRADOR ✓' if is_admin() else 'LIMITADOS ⚠','', '#34d399' if is_admin() else '#f59e0b'); self.events=card('Eventos analizados','0'); self.rdp=card('Eventos RDP','0'); self.failed=card('Inicios fallidos','0','', '#ff5c65'); self.nfind=card('Hallazgos','0','', '#f5b942'); self.risk=card('Nivel de riesgo','0 / 100','Puntaje heurístico, no conclusión absoluta','#f5b942'); cs=[self.host,self.user,self.win,self.admin,self.events,self.rdp,self.failed,self.nfind,self.risk]
        for i,c in enumerate(cs): g.addWidget(c,i//5,i%5); l.addLayout(g)
        q=QFrame(); q.setObjectName('panel'); ql=QVBoxLayout(q); hh=QHBoxLayout(); st=QLabel('Resultados recientes de la auditoría'); st.setObjectName('sect'); hh.addWidget(st); hh.addStretch(); op=QPushButton('Abrir carpeta de evidencia'); op.clicked.connect(self.openOut); hh.addWidget(op); ql.addLayout(hh); self.mainTable=self.table(['Fecha / hora','Categoría','Evento / detalle','Severidad','Fuente']); ql.addWidget(self.mainTable); l.addWidget(q,1); return p
    def remote(self):
        p,l=self.shell('Acceso remoto e inicios de sesión','Analice accesos remotos, eventos de inicio de sesión y sesiones interactivas.'); row=QHBoxLayout(); self.rs=card('Sesiones / eventos remotos','0'); self.rip=card('IPs de origen únicas','0'); self.rr=card('Eventos RDP','0'); self.rf=card('Inicios fallidos','0','', '#ff5c65'); self.rl=card('Nivel de riesgo','SIN DATOS','', '#f5b942'); [row.addWidget(c) for c in [self.rs,self.rip,self.rr,self.rf,self.rl]]; l.addLayout(row)
        filt=QFrame(); filt.setObjectName('panel'); fl=QHBoxLayout(filt); self.u=QLineEdit(); self.u.setPlaceholderText('Filtrar por usuario...'); self.ip=QLineEdit(); self.ip.setPlaceholderText('Filtrar por IP...'); fl.addWidget(QLabel('Usuario')); fl.addWidget(self.u); fl.addWidget(QLabel('IP de origen')); fl.addWidget(self.ip); l.addWidget(filt)
        mid=QHBoxLayout(); q=QFrame(); q.setObjectName('panel'); ql=QVBoxLayout(q); z=QLabel('Línea de tiempo de acceso remoto'); z.setObjectName('sect'); ql.addWidget(z); self.tl=Timeline(); ql.addWidget(self.tl); mid.addWidget(q,3); d=QFrame(); d.setObjectName('panel'); dl=QVBoxLayout(d); z=QLabel('Detalles de la sesión'); z.setObjectName('sect'); dl.addWidget(z); self.detail=QTextEdit(); self.detail.setReadOnly(True); self.detail.setPlainText('Seleccione una sesión o ejecute una auditoría.'); dl.addWidget(self.detail); mid.addWidget(d,1); l.addLayout(mid,1)
        tabs=QHBoxLayout(); a=QFrame(); a.setObjectName('panel'); al=QVBoxLayout(a); z=QLabel('✓  Inicios remotos exitosos'); z.setObjectName('sect'); al.addWidget(z); self.oktab=self.table(['Fecha y hora','Usuario','IP de origen','Tipo de inicio','ID de sesión','Duración']); al.addWidget(self.oktab); tabs.addWidget(a); b=QFrame(); b.setObjectName('panel'); bl=QVBoxLayout(b); z=QLabel('✕  Intentos fallidos'); z.setObjectName('sect'); bl.addWidget(z); self.badtab=self.table(['Fecha y hora','IP de origen','Usuario','Motivo']); bl.addWidget(self.badtab); tabs.addWidget(b); l.addLayout(tabs,2); self.oktab.cellClicked.connect(lambda r,c:self.showSession(r,False)); self.badtab.cellClicked.connect(lambda r,c:self.showSession(r,True)); return p
    def findings(self):
        p,l=self.shell('Hallazgos','Hallazgos explicados con su clasificación, evidencia y limitaciones.'); h=QHBoxLayout(); a=QFrame(); a.setObjectName('panel'); al=QVBoxLayout(a); self.ft=self.table(['Severidad','Módulo','Hallazgo','Clasificación']); al.addWidget(self.ft); h.addWidget(a,2); b=QFrame(); b.setObjectName('panel'); bl=QVBoxLayout(b); z=QLabel('Detalle del hallazgo'); z.setObjectName('sect'); bl.addWidget(z); self.fd=QTextEdit(); self.fd.setReadOnly(True); bl.addWidget(self.fd); h.addWidget(b,1); l.addLayout(h,1); self.ft.cellClicked.connect(self.showFinding); return p
    def table(self,heads):
        t=QTableWidget(0,len(heads)); t.setHorizontalHeaderLabels(heads); t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); t.verticalHeader().hide(); t.setSelectionBehavior(QAbstractItemView.SelectRows); t.setEditTriggers(QAbstractItemView.NoEditTriggers); t.setAlternatingRowColors(True); t.setShowGrid(False); return t
    def go(self,i): self.pages.setCurrentIndex(i); [b.setChecked(p==i) for b,p in self.nav]
    def audit(self):
        m=QMessageBox.question(self,'Nueva auditoría','La auditoría puede recopilar información sensible del sistema, incluidos usuarios, IP, procesos y eventos de seguridad.\n\n¿Desea iniciar la auditoría completa?',QMessageBox.Yes|QMessageBox.No)
        if m!=QMessageBox.Yes:return
        self.pg=QMessageBox(self); self.pg.setWindowTitle('Auditoría en curso'); self.pg.setText('Preparando auditoría...'); self.pg.setStandardButtons(QMessageBox.Cancel); self.worker=Worker(Path(safe_output_root())); self.worker.progress.connect(lambda n,i,t:self.pg.setText(f'Analizando: {MOD.get(n,n)}\nProgreso: {i} de {t} módulos')); self.worker.ok.connect(self.done); self.worker.fail.connect(self.fail); self.pg.buttonClicked.connect(lambda _:self.worker.e.cancel()); self.worker.start(); self.pg.show()
    def fail(self,e): self.pg.close(); QMessageBox.critical(self,'Error de auditoría',e)
    def done(self,out,s):
        self.pg.close(); self.out=Path(out)
        try:self.data=json.loads((self.out/'reports'/'audit.json').read_text(encoding='utf-8'))
        except Exception:self.data={}
        self.populate(); self.go(0); QMessageBox.information(self,'Auditoría finalizada','La auditoría finalizó. Los resultados ya están disponibles en pantalla.\n\nEl paquete de evidencia también fue guardado para preservar trazabilidad e integridad.')
    def d(self,e): return e.get('data',{}) if isinstance(e.get('data',{}),dict) else {}
    def ipx(self,e): d=self.d(e); return str(d.get('IpAddress') or d.get('SourceNetworkAddress') or d.get('Param3') or '')
    def usr(self,e): d=self.d(e); u=d.get('TargetUserName') or d.get('SubjectUserName') or d.get('Param1') or '—'; dom=d.get('TargetDomainName') or d.get('SubjectDomainName') or ''; return f'{dom}\\{u}' if dom and dom not in ('-','.') else str(u)
    def tm(self,e): return str(e.get('time') or e.get('timestamp') or '—').replace('T',' ').replace('Z','')
    def add(self,t,row):
        r=t.rowCount(); t.insertRow(r)
        for c,v in enumerate(row): t.setItem(r,c,QTableWidgetItem(str(v)))
    def populate(self):
        rs=self.data.get('results',[]); fs=self.data.get('findings',[]); score=int(self.data.get('risk_score',0) or 0); by={r.get('name'):r for r in rs}; sy=(by.get('system',{}).get('records') or [{}])[0]; host=str(sy.get('hostname') or os.environ.get('COMPUTERNAME') or '—'); user=str(sy.get('user') or os.environ.get('USERNAME') or '—'); win=str(sy.get('windows') or sy.get('os') or 'Windows'); log=by.get('logons',{}).get('records',[]); rdp=by.get('rdp',{}).get('records',[]); bad=[e for e in log if int(e.get('event_id',0) or 0)==4625]
        self.host.v.setText(host); self.user.v.setText(user); self.win.v.setText(win); self.events.v.setText(str(sum(len(r.get('records',[])) for r in rs))); self.rdp.v.setText(str(len(rdp))); self.failed.v.setText(str(len(bad))); self.nfind.v.setText(str(len(fs))); self.risk.v.setText(f'{score} / 100'); self.meta.setText(f'Equipo: {host}   |   Perfil: Auditoría completa'); self.target.setText(f'🖥  Objetivo actual\n\n{host}\n{win}\nÚltima auditoría: {datetime.now():%d/%m/%Y %H:%M}')
        level='BAJO' if score<25 else 'MEDIO' if score<60 else 'ALTO' if score<85 else 'CRÍTICO'; ips={self.ipx(e) for e in log+rdp if self.ipx(e) not in ('','-','127.0.0.1','::1')}; self.rs.v.setText(str(len(log)+len(rdp))); self.rip.v.setText(str(len(ips))); self.rr.v.setText(str(len(rdp))); self.rf.v.setText(str(len(bad))); self.rl.v.setText(level)
        self.mainTable.setRowCount(0); [self.add(self.mainTable,['—',MOD.get(f.get('module'),f.get('module','Análisis')),f.get('title','Hallazgo'),f.get('severity','INFO'),f.get('classification','')]) for f in fs];
        for r in rs:
            for e in (r.get('records') or [])[:5]: self.add(self.mainTable,[self.tm(e),MOD.get(r.get('name'),r.get('name')),f"Evento {e.get('event_id','')}" if e.get('event_id') else json.dumps(e,ensure_ascii=False,default=str)[:100],'INFORMACIÓN',r.get('source') or r.get('name')])
        self.oktab.setRowCount(0); self.badtab.setRowCount(0); tev=[]
        for e in log:
            eid=int(e.get('event_id',0) or 0); d=self.d(e); lt=str(d.get('LogonType') or '—')
            if eid==4624:self.add(self.oktab,[self.tm(e),self.usr(e),self.ipx(e) or '—',self.lt(lt),d.get('TargetLogonId') or '—','No determinable']); tev.append(('ok',e))
            elif eid==4625:self.add(self.badtab,[self.tm(e),self.ipx(e) or '—',self.usr(e),d.get('FailureReason') or d.get('Status') or 'Intento fallido']); tev.append(('bad',e))
            elif eid in (4634,4647): tev.append(('off',e))
        tev += [('rdp',e) for e in rdp]; self.tl.setEvents(tev); self.F=fs; self.ft.setRowCount(0); [self.add(self.ft,[f.get('severity','INFO'),MOD.get(f.get('module'),f.get('module')),f.get('title','Hallazgo'),f.get('classification','INFORMACIÓN')]) for f in fs]
    def lt(self,x): return {'2':'2 — Interactivo','3':'3 — Red','5':'5 — Servicio','7':'7 — Desbloqueo','10':'10 — Remoto interactivo (RDP)','11':'11 — Interactivo en caché'}.get(str(x),str(x))
    def showSession(self,r,bad):
        t=self.badtab if bad else self.oktab; v=[t.item(r,c).text() if t.item(r,c) else '—' for c in range(t.columnCount())]; self.detail.setPlainText((f'Evento: Intento de inicio fallido\n\nFecha y hora: {v[0]}\nIP de origen: {v[1]}\nUsuario: {v[2]}\nMotivo: {v[3]}\n\nLa existencia de un evento 4625 acredita un intento fallido registrado. No confirma por sí sola un ataque.' if bad else f'Evento: Inicio de sesión\n\nFecha y hora: {v[0]}\nUsuario: {v[1]}\nIP de origen: {v[2]}\nTipo de inicio: {v[3]}\nID de sesión: {v[4]}\nDuración: {v[5]}\n\nUna IP identifica un origen de red; no atribuye por sí sola la actividad a una persona.'))
    def showFinding(self,r,c):
        if r>=len(getattr(self,'F',[])):return
        f=self.F[r]; self.fd.setPlainText(f"{f.get('title')}\n\nSeveridad: {f.get('severity')}\nClasificación: {f.get('classification')}\n\nPOR QUÉ\n{f.get('reason')}\n\nEVIDENCIA\n{json.dumps(f.get('evidence',[]),ensure_ascii=False,indent=2)}\n\nLIMITACIÓN\nLa interpretación se limita a la evidencia disponible y al período conservado por Windows. La ausencia de un evento no demuestra que la actividad nunca haya ocurrido.")
    def openOut(self):
        if not self.out:return
        try:os.startfile(str(self.out))
        except Exception:QMessageBox.information(self,'Carpeta de evidencia',str(self.out))
    def _style(self):
        self.setStyleSheet("""*{font-family:'Segoe UI';font-size:12px}QMainWindow,QWidget{background:#081521;color:#dce8f5}#head{background:#0a1d2e;border-bottom:1px solid #19344d}#brand{font-size:21px;font-weight:700;color:#fff}#by{color:#a8bed3;font-size:11px;margin-left:32px}#side{background:#0a1a28;border-right:1px solid #17324a}#nav{text-align:left;border:0;border-radius:6px;padding:10px;color:#c6d7e7;background:transparent}#nav:hover{background:#102b42}#nav:checked{background:#0e5fae;color:white;font-weight:600;border-left:3px solid #39a7ff}#target,#card,#panel{background:#0d2132;border:1px solid #1c3a53;border-radius:8px;padding:8px}#pt{font-size:24px;font-weight:700;color:#f4f8fd}#sub,#cs{color:#9eb4c8}#ct{color:#b8cadd}#cv{font-size:24px;font-weight:700}#sect{font-size:16px;font-weight:700;color:#eef6ff}QPushButton{background:#102b42;border:1px solid #27516f;border-radius:6px;padding:8px 12px;color:#e8f4ff}#primary{background:#0f79df;border-color:#218ff0;font-weight:700}QLineEdit,QTextEdit{background:#091927;border:1px solid #23445e;border-radius:5px;padding:7px;color:#dce8f5}QTableWidget{background:#0a1b29;alternate-background-color:#0c2233;border:0;selection-background-color:#105a9f}QHeaderView::section{background:#10283b;color:#d7e6f4;border:0;border-right:1px solid #1d3d56;padding:7px;font-weight:600}""")

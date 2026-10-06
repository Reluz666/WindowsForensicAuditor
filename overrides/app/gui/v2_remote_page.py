from __future__ import annotations
import json
from PySide6.QtCore import Qt,QRectF
from PySide6.QtGui import QColor,QPainter,QPen,QBrush
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QFrame,QLabel,QPushButton,QLineEdit,QComboBox,QTableWidget,QTableWidgetItem,QHeaderView,QAbstractItemView,QTextEdit

def _data(rec):
    d=rec.get('data')
    return d if isinstance(d,dict) else {}

def _time(rec):
    return str(rec.get('time') or rec.get('timestamp') or '—').replace('T',' ').replace('Z','')

def _ip(rec):
    d=_data(rec)
    return str(d.get('IpAddress') or d.get('SourceNetworkAddress') or d.get('Param3') or '—')

def _user(rec):
    d=_data(rec)
    u=d.get('TargetUserName') or d.get('SubjectUserName') or d.get('Param1') or '—'
    dom=d.get('TargetDomainName') or d.get('SubjectDomainName') or ''
    return f'{dom}\\{u}' if dom and dom not in ('-','.') else str(u)

def _panel():
    f=QFrame(); f.setObjectName('panel'); return f

def _metric(title,value='0',subtitle='',accent='#37a2ff'):
    f=QFrame(); f.setObjectName('metric'); l=QVBoxLayout(f); l.setContentsMargins(16,12,16,12); l.setSpacing(2)
    t=QLabel(title); t.setObjectName('metricTitle'); v=QLabel(value); v.setObjectName('metricValue'); v.setStyleSheet(f'color:{accent};'); s=QLabel(subtitle); s.setObjectName('metricSub'); s.setWordWrap(True)
    l.addWidget(t); l.addWidget(v); l.addWidget(s); l.addStretch(); f.value_label=v; return f

class Table(QTableWidget):
    def __init__(self,headers):
        super().__init__(0,len(headers)); self.setHorizontalHeaderLabels(headers); self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); self.verticalHeader().hide(); self.setSelectionBehavior(QAbstractItemView.SelectRows); self.setEditTriggers(QAbstractItemView.NoEditTriggers); self.setAlternatingRowColors(True); self.setShowGrid(False)
    def add(self,vals):
        r=self.rowCount(); self.insertRow(r)
        for c,v in enumerate(vals): self.setItem(r,c,QTableWidgetItem(str(v)))
    def filter(self,user_q,ip_q):
        u=(user_q or '').lower().strip(); ip=(ip_q or '').lower().strip()
        for r in range(self.rowCount()):
            hay=' '.join(self.item(r,c).text() if self.item(r,c) else '' for c in range(self.columnCount())).lower()
            self.setRowHidden(r,bool((u and u not in hay) or (ip and ip not in hay)))

class Timeline(QWidget):
    def __init__(self):
        super().__init__(); self.events=[]; self.setMinimumHeight(185)
    def load(self,events):
        self.events=list(events or [])[:120]; self.update()
    def paintEvent(self,_):
        p=QPainter(self); p.setRenderHint(QPainter.Antialiasing); w,h=self.width(),self.height(); left,right=28,w-28; y=int(h*.58)
        p.setPen(QPen(QColor('#36536a'),1)); p.drawLine(left,y,right,y)
        if not self.events:
            p.setPen(QColor('#8199ab')); p.drawText(QRectF(0,0,w,h),Qt.AlignCenter,'Sin eventos disponibles para la línea de tiempo'); return
        colors={'ok':'#2d93ff','bad':'#ff525d','rdp':'#25c8e6','off':'#ff9f35'}
        n=max(1,len(self.events)-1)
        for i,e in enumerate(self.events):
            x=left+(right-left)*(i/n); kind=e.get('_kind','rdp'); c=QColor(colors.get(kind,'#2d93ff')); top=y-42-(i%3)*11
            p.setPen(QPen(c,2)); p.drawLine(int(x),y,int(x),top+9); p.setBrush(QBrush(c)); p.setPen(Qt.NoPen); p.drawEllipse(QRectF(x-6,top-6,12,12))
        p.setPen(QColor('#91a8b9')); p.drawText(left,h-12,'Más antiguo'); p.drawText(right-80,h-12,'Más reciente')

class RemotePageModern(QWidget):
    def __init__(self,owner):
        super().__init__(); self.owner=owner; self.ok_raw=[]; self.bad_raw=[]; self.rdp_raw=[]
        root=QVBoxLayout(self); root.setContentsMargins(22,18,22,18); root.setSpacing(11)
        top=QHBoxLayout(); titles=QVBoxLayout(); h=QLabel('Acceso remoto e inicios de sesión'); h.setObjectName('pageTitle'); s=QLabel('Analice accesos remotos, inicios exitosos, intentos fallidos y sesiones registradas en el sistema.'); s.setObjectName('pageSub'); titles.addWidget(h); titles.addWidget(s); top.addLayout(titles); top.addStretch(); run=QPushButton('＋  Nueva auditoría'); run.setObjectName('primary'); run.clicked.connect(owner.start_audit); top.addWidget(run); root.addLayout(top)
        cards=QHBoxLayout(); self.total=_metric('Sesiones / eventos','0','Interactivos y remotos'); self.ips=_metric('IPs de origen únicas','0','Orígenes distintos'); self.rdp=_metric('Eventos RDP','0','Terminal Services'); self.failed=_metric('Inicios fallidos','0','Intentos no exitosos','#ff626b'); self.level=_metric('Nivel de riesgo','SIN DATOS','Según hallazgos del análisis','#f2b84b')
        for c in (self.total,self.ips,self.rdp,self.failed,self.level): cards.addWidget(c)
        root.addLayout(cards)
        filt=_panel(); fl=QHBoxLayout(filt); self.user=QLineEdit(); self.user.setPlaceholderText('Todos los usuarios'); self.ip=QLineEdit(); self.ip.setPlaceholderText('Todas las IP'); self.scope=QComboBox(); self.scope.addItems(['Todos los eventos','Últimas sesiones registradas']); fl.addWidget(QLabel('Usuario')); fl.addWidget(self.user,1); fl.addWidget(QLabel('IP de origen')); fl.addWidget(self.ip,1); fl.addWidget(QLabel('Vista')); fl.addWidget(self.scope); clear=QPushButton('Limpiar filtros'); clear.clicked.connect(self.clear_filters); fl.addWidget(clear); root.addWidget(filt)
        mid=QHBoxLayout(); tl=_panel(); tll=QVBoxLayout(tl); th=QLabel('Línea de tiempo de acceso remoto'); th.setObjectName('sectionTitle'); legend=QLabel('● Inicio    ● RDP    ● Cierre    ● Intento fallido'); legend.setStyleSheet('color:#91a8b9;'); tll.addWidget(th); tll.addWidget(legend); self.timeline=Timeline(); tll.addWidget(self.timeline); mid.addWidget(tl,3)
        det=_panel(); dl=QVBoxLayout(det); dh=QLabel('Detalles de la sesión'); dh.setObjectName('sectionTitle'); dl.addWidget(dh); self.detail=QTextEdit(); self.detail.setReadOnly(True); self.detail.setPlainText('Seleccione una sesión o un intento fallido para ver los datos del evento y su interpretación.'); dl.addWidget(self.detail); mid.addWidget(det,2); root.addLayout(mid,2)
        bottom=QHBoxLayout(); okp=_panel(); ol=QVBoxLayout(okp); oh=QLabel('✓  Inicios remotos exitosos'); oh.setObjectName('sectionTitle'); ol.addWidget(oh); self.ok=Table(['Fecha y hora','Usuario','IP de origen','Tipo','ID']); ol.addWidget(self.ok); bottom.addWidget(okp,1)
        badp=_panel(); bl=QVBoxLayout(badp); bh=QLabel('✕  Intentos fallidos'); bh.setObjectName('sectionTitle'); bl.addWidget(bh); self.bad=Table(['Fecha y hora','IP de origen','Usuario','Motivo']); bl.addWidget(self.bad); bottom.addWidget(badp,1); root.addLayout(bottom,2)
        self.ok.cellClicked.connect(lambda r,c:self.show_event(self.ok_raw,r,'success')); self.bad.cellClicked.connect(lambda r,c:self.show_event(self.bad_raw,r,'failed')); self.user.textChanged.connect(self.apply_filters); self.ip.textChanged.connect(self.apply_filters)
    def clear_filters(self):
        self.user.clear(); self.ip.clear(); self.scope.setCurrentIndex(0)
    def apply_filters(self,*_):
        self.ok.filter(self.user.text(),self.ip.text()); self.bad.filter(self.user.text(),self.ip.text())
    def load(self,data):
        by={r.get('name'):r for r in data.get('results',[])}; logons=by.get('logons',{}).get('records') or []; rdp=by.get('rdp',{}).get('records') or []
        self.ok.setRowCount(0); self.bad.setRowCount(0); self.ok_raw=[]; self.bad_raw=[]; self.rdp_raw=rdp; events=[]; ips=set()
        for e in logons:
            eid=int(e.get('event_id',0) or 0); d=_data(e); ip=_ip(e); user=_user(e)
            if ip not in ('—','-','127.0.0.1','::1'): ips.add(ip)
            if eid==4624:
                lt=str(d.get('LogonType') or '—'); label={'2':'Interactivo','3':'Red','5':'Servicio','7':'Desbloqueo','10':'RDP / remoto interactivo','11':'Interactivo en caché'}.get(lt,lt); self.ok.add([_time(e),user,ip,label,d.get('TargetLogonId') or '—']); self.ok_raw.append(e); x=dict(e); x['_kind']='ok'; events.append(x)
            elif eid==4625:
                reason=d.get('FailureReason') or d.get('Status') or 'Intento fallido'; self.bad.add([_time(e),ip,user,reason]); self.bad_raw.append(e); x=dict(e); x['_kind']='bad'; events.append(x)
            elif eid in (4634,4647):
                x=dict(e); x['_kind']='off'; events.append(x)
        for e in rdp:
            ip=_ip(e)
            if ip not in ('—','-','127.0.0.1','::1'): ips.add(ip)
            x=dict(e); x['_kind']='rdp'; events.append(x)
        events.sort(key=_time); self.timeline.load(events)
        score=int(data.get('risk_score',0) or 0); lvl='BAJO' if score<25 else 'MEDIO' if score<60 else 'ALTO' if score<85 else 'CRÍTICO'
        self.total.value_label.setText(str(len(logons)+len(rdp))); self.ips.value_label.setText(str(len(ips))); self.rdp.value_label.setText(str(len(rdp))); self.failed.value_label.setText(str(len(self.bad_raw))); self.level.value_label.setText(lvl); self.apply_filters()
    def show_event(self,rows,row,kind):
        if row>=len(rows): return
        e=rows[row]; d=_data(e); heading='Inicio de sesión exitoso' if kind=='success' else 'Intento de inicio fallido'
        self.detail.setPlainText(f'{heading}\n\nFecha y hora: {_time(e)}\nUsuario: {_user(e)}\nIP de origen: {_ip(e)}\nEvento: {e.get("event_id","—")}\nProveedor: {e.get("provider","Security")}\n\nEVIDENCIA\n{json.dumps(d,ensure_ascii=False,indent=2,default=str)}\n\nINTERPRETACIÓN\nLa IP identifica un origen de red y no necesariamente a una persona. La ausencia de eventos no demuestra ausencia de actividad.')

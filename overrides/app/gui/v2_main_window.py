from __future__ import annotations

import csv
import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from app.engine import AuditEngine, COLLECTORS
from app.utils.platform import is_admin, relaunch_as_admin, safe_output_root\nfrom app.gui.v2_remote_page import RemotePageModern

COLLECTOR_LABELS = {
    'system': 'Sistema', 'accounts': 'Cuentas', 'logons': 'Inicios de sesión',
    'rdp': 'Acceso remoto / RDP', 'powershell': 'PowerShell', 'processes': 'Procesos',
    'network': 'Red', 'services': 'Servicios', 'tasks': 'Tareas programadas',
    'usb': 'USB', 'software': 'Software', 'defender': 'Microsoft Defender',
    'persistence': 'Persistencia', 'windows_update': 'Windows Update',
    'events': 'Eventos', 'firewall': 'Firewall', 'recent_files': 'Archivos recientes',
}
STATUS_ES = {
    'SUCCESS': 'CORRECTO', 'PARTIAL': 'PARCIAL', 'FAILED': 'FALLÓ',
    'NOT_AVAILABLE': 'NO DISPONIBLE', 'PERMISSION_DENIED': 'PERMISO DENEGADO',
}
SEVERITY_ES = {
    'INFO': 'INFORMACIÓN', 'LOW': 'BAJO', 'MEDIUM': 'MEDIO',
    'HIGH': 'ALTO', 'CRITICAL': 'CRÍTICO',
}


def qtext(v: Any) -> str:
    if v is None:
        return '—'
    if isinstance(v, bool):
        return 'Sí' if v else 'No'
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False, default=str)
    return str(v)


def event_time(rec: dict) -> str:
    v = rec.get('time') or rec.get('timestamp') or rec.get('created') or rec.get('modified') or rec.get('InstalledOn') or '—'
    return str(v).replace('T', ' ').replace('Z', '')


def event_data(rec: dict) -> dict:
    d = rec.get('data')
    return d if isinstance(d, dict) else {}


def event_ip(rec: dict) -> str:
    d = event_data(rec)
    return str(d.get('IpAddress') or d.get('SourceNetworkAddress') or d.get('Param3') or rec.get('remote') or rec.get('ip') or '—')


def event_user(rec: dict) -> str:
    d = event_data(rec)
    user = d.get('TargetUserName') or d.get('SubjectUserName') or d.get('Param1') or rec.get('user') or rec.get('username') or '—'
    dom = d.get('TargetDomainName') or d.get('SubjectDomainName') or rec.get('domain') or ''
    if dom and dom not in ('-', '.') and '\\' not in str(user):
        return f'{dom}\\{user}'
    return str(user)


def panel() -> QFrame:
    f = QFrame()
    f.setObjectName('panel')
    return f


def metric(title: str, value: str = '—', subtitle: str = '', accent: str = '#37a2ff') -> QFrame:
    f = QFrame()
    f.setObjectName('metric')
    l = QVBoxLayout(f)
    l.setContentsMargins(16, 13, 16, 13)
    l.setSpacing(3)
    t = QLabel(title)
    t.setObjectName('metricTitle')
    v = QLabel(value)
    v.setObjectName('metricValue')
    v.setStyleSheet(f'color:{accent};')
    s = QLabel(subtitle)
    s.setObjectName('metricSub')
    s.setWordWrap(True)
    l.addWidget(t)
    l.addWidget(v)
    l.addWidget(s)
    l.addStretch()
    f.value_label = v
    f.subtitle_label = s
    return f


class AuditWorker(QThread):
    progress = Signal(str, int, int)
    done = Signal(str, dict)
    failed = Signal(str)

    def __init__(self, root: Path, demo: bool):
        super().__init__()
        self.engine = AuditEngine(root, lambda n, i, t: self.progress.emit(n, i, t))
        self.demo = demo

    def run(self):
        try:
            out, summary = self.engine.run({c.name for c in COLLECTORS}, self.demo)
            self.done.emit(str(out), summary)
        except Exception as exc:
            self.failed.emit(f'{type(exc).__name__}: {exc}')


class DataTable(QTableWidget):
    def __init__(self, headers: list[str]):
        super().__init__(0, len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)

    def add_row(self, values: list[Any]):
        r = self.rowCount()
        self.insertRow(r)
        for c, v in enumerate(values):
            self.setItem(r, c, QTableWidgetItem(qtext(v)))

    def filter_text(self, text: str):
        q = (text or '').strip().lower()
        for r in range(self.rowCount()):
            hay = ' '.join(self.item(r, c).text() if self.item(r, c) else '' for c in range(self.columnCount())).lower()
            self.setRowHidden(r, bool(q) and q not in hay)

    def export_csv(self, parent, default_name='resultados.csv'):
        path, _ = QFileDialog.getSaveFileName(parent, 'Guardar CSV', str(Path.home() / 'Desktop' / default_name), 'CSV (*.csv)')
        if not path:
            return
        with open(path, 'w', newline='', encoding='utf-8-sig') as fh:
            wr = csv.writer(fh)
            wr.writerow([self.horizontalHeaderItem(i).text() for i in range(self.columnCount())])
            for r in range(self.rowCount()):
                if self.isRowHidden(r):
                    continue
                wr.writerow([self.item(r, c).text() if self.item(r, c) else '' for c in range(self.columnCount())])
        QMessageBox.information(parent, 'Exportación completada', f'Archivo guardado en:\n{path}')


class PageBase(QWidget):
    def __init__(self, owner, title: str, subtitle: str):
        super().__init__()
        self.owner = owner
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(22, 18, 22, 18)
        self.root.setSpacing(12)
        top = QHBoxLayout()
        titles = QVBoxLayout()
        h = QLabel(title)
        h.setObjectName('pageTitle')
        s = QLabel(subtitle)
        s.setObjectName('pageSub')
        s.setWordWrap(True)
        titles.addWidget(h)
        titles.addWidget(s)
        top.addLayout(titles)
        top.addStretch()
        run = QPushButton('＋  Nueva auditoría')
        run.setObjectName('primary')
        run.clicked.connect(owner.start_audit)
        top.addWidget(run)
        self.root.addLayout(top)


class DashboardPage(PageBase):
    def __init__(self, owner):
        super().__init__(owner, 'Panel principal', 'Resumen comprensible del equipo, cobertura de evidencia, actividad relevante y hallazgos.')
        g = QGridLayout()
        g.setHorizontalSpacing(10)
        g.setVerticalSpacing(10)
        self.host = metric('Equipo')
        self.user = metric('Usuario')
        self.windows = metric('Windows')
        self.admin = metric('Privilegios', 'ADMINISTRADOR' if is_admin() else 'LIMITADOS', 'Ejecute como administrador para mayor cobertura', '#34d399' if is_admin() else '#f2b84b')
        self.events = metric('Registros recopilados', '0')
        self.rdp = metric('Eventos RDP', '0')
        self.failed = metric('Inicios fallidos', '0', '', '#ff626b')
        self.findings = metric('Hallazgos', '0', '', '#f2b84b')
        self.risk = metric('Nivel de riesgo', '0 / 100', 'Puntaje heurístico; no es una conclusión pericial automática', '#f2b84b')
        cards = [self.host,self.user,self.windows,self.admin,self.events,self.rdp,self.failed,self.findings,self.risk]
        for i, c in enumerate(cards):
            g.addWidget(c, i//5, i%5)
        self.root.addLayout(g)
        body = QHBoxLayout()
        left = panel()
        ll = QVBoxLayout(left)
        st = QLabel('Hallazgos principales')
        st.setObjectName('sectionTitle')
        ll.addWidget(st)
        self.finding_table = DataTable(['Severidad','Módulo','Hallazgo','Clasificación'])
        self.finding_table.cellClicked.connect(self._select_find)
        ll.addWidget(self.finding_table)
        body.addWidget(left,3)
        right = panel()
        rl = QVBoxLayout(right)
        st2 = QLabel('Detalle seleccionado')
        st2.setObjectName('sectionTitle')
        rl.addWidget(st2)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlainText('Seleccione un hallazgo para ver su interpretación, evidencia y limitaciones.')
        rl.addWidget(self.detail)
        body.addWidget(right,2)
        self.root.addLayout(body,1)
        self.finding_rows=[]

    def load(self, data: dict):
        results = data.get('results',[])
        by={r.get('name'):r for r in results}
        system=(by.get('system',{}).get('records') or [{}])[0]
        self.host.value_label.setText(qtext(system.get('hostname')))
        self.user.value_label.setText(qtext(system.get('user')))
        self.windows.value_label.setText(qtext(system.get('os') or system.get('release') or 'Windows'))
        total=sum(len(r.get('records') or []) for r in results)
        rdp=len(by.get('rdp',{}).get('records') or [])
        logons=by.get('logons',{}).get('records') or []
        bad=sum(1 for e in logons if int(e.get('event_id',0) or 0)==4625)
        findings=data.get('findings',[])
        score=int(data.get('risk_score',0) or 0)
        level='BAJO' if score<25 else 'MEDIO' if score<60 else 'ALTO' if score<85 else 'CRÍTICO'
        self.events.value_label.setText(str(total))
        self.rdp.value_label.setText(str(rdp))
        self.failed.value_label.setText(str(bad))
        self.findings.value_label.setText(str(len(findings)))
        self.risk.value_label.setText(f'{score} / 100 — {level}')
        self.finding_table.setRowCount(0)
        self.finding_rows=findings
        for f in findings:
            self.finding_table.add_row([SEVERITY_ES.get(str(f.get('severity')),f.get('severity')),COLLECTOR_LABELS.get(f.get('module'),f.get('module')),f.get('title','Hallazgo'),f.get('classification','—')])
        if not findings:
            self.finding_table.add_row(['INFORMACIÓN','Análisis','No se generaron hallazgos automáticos.','INFORMACIÓN'])

    def _select_find(self,row,_):
        if row>=len(self.finding_rows):
            return
        f=self.finding_rows[row]
        self.detail.setPlainText(
            f"{f.get('title','Hallazgo')}\n\n"
            f"SEVERIDAD\n{SEVERITY_ES.get(str(f.get('severity')),f.get('severity','—'))}\n\n"
            f"CLASIFICACIÓN\n{f.get('classification','—')}\n\n"
            f"POR QUÉ SE MARCÓ\n{f.get('reason','No especificado')}\n\n"
            f"EVIDENCIA\n{json.dumps(f.get('evidence',[]),ensure_ascii=False,indent=2,default=str)}\n\n"
            "LIMITACIONES\nLa interpretación depende de la evidencia disponible y del período conservado por Windows. "
            "La ausencia de un evento no demuestra que la actividad nunca haya ocurrido."
        )


class RemotePage(PageBase):
    def __init__(self, owner):
        super().__init__(owner, 'Acceso remoto e inicios de sesión', 'Analice RDP, inicios exitosos, intentos fallidos y sesiones registradas sin atribuir automáticamente una IP a una persona.')
        cards=QHBoxLayout()
        self.total=metric('Eventos de sesión','0')
        self.ips=metric('IPs de origen únicas','0')
        self.rdp=metric('Eventos RDP','0')
        self.failed=metric('Inicios fallidos','0','', '#ff626b')
        self.level=metric('Nivel de riesgo','SIN DATOS','', '#f2b84b')
        [cards.addWidget(x) for x in (self.total,self.ips,self.rdp,self.failed,self.level)]
        self.root.addLayout(cards)
        filters=panel()
        fl=QHBoxLayout(filters)
        self.user_filter=QLineEdit()
        self.user_filter.setPlaceholderText('Usuario...')
        self.ip_filter=QLineEdit()
        self.ip_filter.setPlaceholderText('IP de origen...')
        self.kind_filter=QComboBox()
        self.kind_filter.addItems(['Todos','Exitosos','Fallidos','RDP'])
        fl.addWidget(QLabel('Usuario'))
        fl.addWidget(self.user_filter)
        fl.addWidget(QLabel('IP'))
        fl.addWidget(self.ip_filter)
        fl.addWidget(QLabel('Tipo'))
        fl.addWidget(self.kind_filter)
        clear=QPushButton('Limpiar filtros')
        clear.clicked.connect(self._clear)
        fl.addWidget(clear)
        self.root.addWidget(filters)
        self.tabs=QTabWidget()
        ok=QWidget()
        ol=QVBoxLayout(ok)
        self.ok=DataTable(['Fecha y hora','Usuario','IP de origen','Tipo de inicio','ID de sesión','Fuente'])
        ol.addWidget(self.ok)
        bad=QWidget()
        bl=QVBoxLayout(bad)
        self.bad=DataTable(['Fecha y hora','Usuario','IP de origen','Motivo','Código','Fuente'])
        bl.addWidget(self.bad)
        rdp=QWidget()
        rl=QVBoxLayout(rdp)
        self.rdp_table=DataTable(['Fecha y hora','Evento','Usuario','IP de origen','Proveedor','Detalle'])
        rl.addWidget(self.rdp_table)
        self.tabs.addTab(ok,'Inicios exitosos')
        self.tabs.addTab(bad,'Intentos fallidos')
        self.tabs.addTab(rdp,'RDP / Terminal Services')
        self.root.addWidget(self.tabs,2)
        d=panel()
        dl=QHBoxLayout(d)
        self.detail=QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(180)
        self.detail.setPlainText('Seleccione una fila para ver una explicación del evento.')
        dl.addWidget(self.detail)
        self.root.addWidget(d)
        self.ok.cellClicked.connect(lambda r,c:self._show(self.ok,r,'success'))
        self.bad.cellClicked.connect(lambda r,c:self._show(self.bad,r,'failed'))
        self.rdp_table.cellClicked.connect(lambda r,c:self._show(self.rdp_table,r,'rdp'))
        self.user_filter.textChanged.connect(self.apply_filters)
        self.ip_filter.textChanged.connect(self.apply_filters)
        self.kind_filter.currentTextChanged.connect(self.apply_filters)
        self.raw_ok=[]
        self.raw_bad=[]
        self.raw_rdp=[]

    def _clear(self):
        self.user_filter.clear()
        self.ip_filter.clear()
        self.kind_filter.setCurrentIndex(0)

    def apply_filters(self,*_):
        uq=self.user_filter.text().lower().strip()
        iq=self.ip_filter.text().lower().strip()
        kind=self.kind_filter.currentText()
        for table,name in [(self.ok,'Exitosos'),(self.bad,'Fallidos'),(self.rdp_table,'RDP')]:
            for r in range(table.rowCount()):
                hay=' '.join(table.item(r,c).text() if table.item(r,c) else '' for c in range(table.columnCount())).lower()
                hide=(uq and uq not in hay) or (iq and iq not in hay) or (kind!='Todos' and kind!=name)
                table.setRowHidden(r,bool(hide))

    def load(self,data:dict):
        by={r.get('name'):r for r in data.get('results',[])}
        logons=by.get('logons',{}).get('records') or []
        rdp=by.get('rdp',{}).get('records') or []
        self.ok.setRowCount(0)
        self.bad.setRowCount(0)
        self.rdp_table.setRowCount(0)
        self.raw_ok=[]
        self.raw_bad=[]
        self.raw_rdp=[]
        ips=set()
        for e in logons:
            eid=int(e.get('event_id',0) or 0)
            d=event_data(e)
            ip=event_ip(e)
            user=event_user(e)
            if ip not in ('—','-','127.0.0.1','::1'):
                ips.add(ip)
            if eid==4624:
                lt=str(d.get('LogonType') or '—')
                label={'2':'2 — Interactivo','3':'3 — Red','5':'5 — Servicio','7':'7 — Desbloqueo','10':'10 — Remoto interactivo (RDP)','11':'11 — Interactivo en caché'}.get(lt,lt)
                self.ok.add_row([event_time(e),user,ip,label,d.get('TargetLogonId') or '—','Security 4624'])
                self.raw_ok.append(e)
            elif eid==4625:
                reason=d.get('FailureReason') or d.get('Status') or 'Intento fallido'
                self.bad.add_row([event_time(e),user,ip,reason,d.get('Status') or '4625','Security 4625'])
                self.raw_bad.append(e)
        for e in rdp:
            d=event_data(e)
            ip=event_ip(e)
            if ip not in ('—','-','127.0.0.1','::1'):
                ips.add(ip)
            self.rdp_table.add_row([event_time(e),e.get('event_id','—'),event_user(e),ip,e.get('provider') or 'TerminalServices',json.dumps(d,ensure_ascii=False,default=str)[:260]])
            self.raw_rdp.append(e)
        score=int(data.get('risk_score',0) or 0)
        lvl='BAJO' if score<25 else 'MEDIO' if score<60 else 'ALTO' if score<85 else 'CRÍTICO'
        self.total.value_label.setText(str(len(logons)+len(rdp)))
        self.ips.value_label.setText(str(len(ips)))
        self.rdp.value_label.setText(str(len(rdp)))
        self.failed.value_label.setText(str(len(self.raw_bad)))
        self.level.value_label.setText(lvl)
        self.apply_filters()

    def _show(self,table,row,kind):
        raw={'success':self.raw_ok,'failed':self.raw_bad,'rdp':self.raw_rdp}[kind]
        if row>=len(raw):
            return
        e=raw[row]
        d=event_data(e)
        base=(
            f"Fecha y hora: {event_time(e)}\nUsuario: {event_user(e)}\nIP de origen: {event_ip(e)}\n"
            f"Evento: {e.get('event_id','—')}\nProveedor: {e.get('provider','—')}\n\n"
            f"DATOS DEL EVENTO\n{json.dumps(d,ensure_ascii=False,indent=2,default=str)}"
        )
        caution='\n\nINTERPRETACIÓN\nUna dirección IP identifica un origen de red y no necesariamente a una persona. La existencia de un evento acredita que Windows registró ese evento; su ausencia no prueba que la actividad no ocurrió.'
        self.detail.setPlainText(base+caution)


class ModulePage(PageBase):
    def __init__(self,owner,title,collector_names):
        super().__init__(owner,title,'Información recopilada por los módulos asociados. Use el buscador y seleccione una fila para ver los datos completos.')
        self.collector_names=collector_names
        f=panel()
        fl=QHBoxLayout(f)
        fl.addWidget(QLabel('Buscar'))
        self.search=QLineEdit()
        self.search.setPlaceholderText('Usuario, IP, proceso, archivo, servicio, evento...')
        fl.addWidget(self.search,1)
        exp=QPushButton('Exportar CSV')
        exp.clicked.connect(lambda:self.table.export_csv(self,f'{collector_names[0]}.csv'))
        fl.addWidget(exp)
        self.root.addWidget(f)
        body=QHBoxLayout()
        a=panel()
        al=QVBoxLayout(a)
        self.table=DataTable(['Fecha / hora','Módulo','Elemento','Detalle','Estado'])
        al.addWidget(self.table)
        body.addWidget(a,3)
        b=panel()
        bl=QVBoxLayout(b)
        st=QLabel('Detalle del registro')
        st.setObjectName('sectionTitle')
        bl.addWidget(st)
        self.detail=QTextEdit()
        self.detail.setReadOnly(True)
        bl.addWidget(self.detail)
        body.addWidget(b,2)
        self.root.addLayout(body,1)
        self.search.textChanged.connect(self.table.filter_text)
        self.rows=[]
        self.table.cellClicked.connect(self.show)

    def load(self,data):
        by={r.get('name'):r for r in data.get('results',[])}
        self.table.setRowCount(0)
        self.rows=[]
        for name in self.collector_names:
            result=by.get(name)
            if not result:
                self.table.add_row(['—',COLLECTOR_LABELS.get(name,name),'—','Módulo no ejecutado','NO DISPONIBLE'])
                continue
            status=STATUS_ES.get(result.get('status'),result.get('status','—'))
            records=result.get('records') or []
            if not records:
                self.table.add_row(['—',COLLECTOR_LABELS.get(name,name),'—',result.get('error') or 'Sin registros disponibles',status])
                continue
            for rec in records[:2500]:
                element=rec.get('name') or rec.get('DisplayName') or rec.get('TaskName') or rec.get('process') or rec.get('path') or rec.get('event_id') or rec.get('HotFixID') or rec.get('local') or 'Registro'
                detail=self._summary(rec)
                self.table.add_row([event_time(rec),COLLECTOR_LABELS.get(name,name),element,detail,status])
                self.rows.append((name,rec))

    def _summary(self,rec):
        preferred=['user','username','remote','local','status','state','path','command_line','command','publisher','DisplayVersion','Manufacturer','Description','Enabled','DefaultInboundAction','HotFixID']
        parts=[f'{k}: {rec.get(k)}' for k in preferred if rec.get(k) not in (None,'',[])]
        d=event_data(rec)
        if not parts and d:
            parts=[f'{k}: {v}' for k,v in list(d.items())[:8] if v not in (None,'')]
        return (' | '.join(parts) or json.dumps(rec,ensure_ascii=False,default=str))[:900]

    def show(self,row,_):
        visible_index=-1
        for r in range(self.table.rowCount()):
            if self.table.item(r,2) and self.table.item(r,2).text()!='—':
                visible_index += 1
            if r==row:
                break
        if 0<=visible_index<len(self.rows):
            name,rec=self.rows[visible_index]
            self.detail.setPlainText(
                f"MÓDULO\n{COLLECTOR_LABELS.get(name,name)}\n\nREGISTRO COMPLETO\n"
                f"{json.dumps(rec,ensure_ascii=False,indent=2,default=str)}\n\n"
                "NOTA\nLos campos se muestran como fueron recopilados. Su significado debe interpretarse junto con la fuente, "
                "la configuración de auditoría y el período conservado."
            )


class TimelinePage(PageBase):
    def __init__(self,owner):
        super().__init__(owner,'Línea de tiempo','Vista cronológica unificada de eventos con fecha/hora disponible.')
        f=panel()
        fl=QHBoxLayout(f)
        fl.addWidget(QLabel('Buscar'))
        self.search=QLineEdit()
        self.search.setPlaceholderText('Filtrar la línea de tiempo...')
        fl.addWidget(self.search,1)
        self.root.addWidget(f)
        self.table=DataTable(['Fecha / hora','Módulo','Evento / elemento','Detalle'])
        self.root.addWidget(self.table,1)
        self.search.textChanged.connect(self.table.filter_text)

    def load(self,data):
        events=[]
        for res in data.get('results',[]):
            for rec in res.get('records') or []:
                tm=event_time(rec)
                if tm!='—':
                    events.append((tm,res.get('name'),rec))
        events.sort(key=lambda x:x[0],reverse=True)
        self.table.setRowCount(0)
        for tm,name,rec in events[:5000]:
            self.table.add_row([tm,COLLECTOR_LABELS.get(name,name),rec.get('event_id') or rec.get('name') or rec.get('process') or rec.get('path') or 'Registro',json.dumps(event_data(rec) or rec,ensure_ascii=False,default=str)[:450]])


class FindingsPage(PageBase):
    def __init__(self,owner):
        super().__init__(owner,'Hallazgos','Clasificación y explicación de los hallazgos generados por el motor de análisis.')
        body=QHBoxLayout()
        a=panel()
        al=QVBoxLayout(a)
        self.table=DataTable(['Severidad','Módulo','Hallazgo','Clasificación'])
        al.addWidget(self.table)
        body.addWidget(a,3)
        b=panel()
        bl=QVBoxLayout(b)
        self.detail=QTextEdit()
        self.detail.setReadOnly(True)
        bl.addWidget(self.detail)
        body.addWidget(b,2)
        self.root.addLayout(body,1)
        self.rows=[]
        self.table.cellClicked.connect(self.show)

    def load(self,data):
        self.rows=data.get('findings',[])
        self.table.setRowCount(0)
        for f in self.rows:
            self.table.add_row([SEVERITY_ES.get(str(f.get('severity')),f.get('severity')),COLLECTOR_LABELS.get(f.get('module'),f.get('module')),f.get('title'),f.get('classification')])
        if not self.rows:
            self.table.add_row(['INFORMACIÓN','Análisis','No se generaron hallazgos automáticos.','INFORMACIÓN'])

    def show(self,row,_):
        if row>=len(self.rows):
            return
        f=self.rows[row]
        self.detail.setPlainText(
            f"{f.get('title')}\n\nSeveridad: {SEVERITY_ES.get(str(f.get('severity')),f.get('severity'))}\n"
            f"Clasificación: {f.get('classification')}\n\nPOR QUÉ\n{f.get('reason','—')}\n\n"
            f"EVIDENCIA\n{json.dumps(f.get('evidence',[]),ensure_ascii=False,indent=2,default=str)}\n\n"
            "LIMITACIÓN\nEste hallazgo es una ayuda de análisis. Debe contrastarse con la evidencia original y el contexto técnico."
        )


class EvidencePage(PageBase):
    def __init__(self,owner):
        super().__init__(owner,'Evidencia','Muestra qué fuentes fueron consultadas y si la evidencia estuvo disponible.')
        top=QHBoxLayout()
        b=QPushButton('Abrir carpeta de evidencia')
        b.clicked.connect(owner.open_output)
        top.addWidget(b)
        top.addStretch()
        self.root.addLayout(top)
        self.table=DataTable(['Módulo','Estado','Registros','Fuente','Observación'])
        self.root.addWidget(self.table,1)

    def load(self,data):
        self.table.setRowCount(0)
        for r in data.get('results',[]):
            st=STATUS_ES.get(r.get('status'),r.get('status'))
            n=len(r.get('records') or [])
            obs=r.get('error') or ('Fuente consultada correctamente.' if st=='CORRECTO' else 'Revise disponibilidad, permisos o configuración de auditoría.')
            self.table.add_row([COLLECTOR_LABELS.get(r.get('name'),r.get('name')),st,n,r.get('source') or r.get('name'),obs])


class ReportsPage(PageBase):
    def __init__(self,owner):
        super().__init__(owner,'Reportes','Abra o guarde los productos generados por la auditoría.')
        self.info=QLabel('Todavía no hay una auditoría cargada.')
        self.info.setWordWrap(True)
        self.root.addWidget(self.info)
        box=panel()
        l=QVBoxLayout(box)
        for key,label in [('pdf','Abrir reporte PDF'),('html','Abrir reporte HTML'),('csv','Guardar CSV'),('json','Guardar JSON'),('zip','Guardar paquete de evidencia ZIP'),('folder','Abrir carpeta de la auditoría')]:
            b=QPushButton(label)
            b.clicked.connect(lambda _,k=key:self.action(k))
            l.addWidget(b)
        self.root.addWidget(box)
        self.root.addStretch()

    def load(self,data):
        self.info.setText(f"Auditoría: {data.get('audit_id','—')}\nPuntaje de riesgo: {data.get('risk_score','—')}\nCarpeta: {self.owner.output_dir or '—'}")

    def action(self,key):
        out=self.owner.output_dir
        if not out:
            QMessageBox.information(self,'Sin reportes','Primero ejecute una auditoría.')
            return
        if key=='folder':
            self.owner.open_output()
            return
        src={'pdf':out/'reports'/'report.pdf','html':out/'reports'/'report.html','csv':out/'reports'/'audit.csv','json':out/'reports'/'audit.json','zip':out/'reports'/'evidence_package.zip'}[key]
        if not src.exists():
            QMessageBox.warning(self,'No disponible',f'No se encontró:\n{src}')
            return
        if key in ('pdf','html'):
            try:
                os.startfile(str(src))
                return
            except Exception:
                pass
        dst,_=QFileDialog.getSaveFileName(self,'Guardar archivo',str(Path.home()/'Desktop'/src.name),'Todos los archivos (*)')
        if dst:
            shutil.copy2(src,dst)
            QMessageBox.information(self,'Archivo guardado',dst)


class SettingsPage(PageBase):
    def __init__(self,owner):
        super().__init__(owner,'Configuración','Opciones de ejecución y diagnóstico.')
        box=panel()
        l=QVBoxLayout(box)
        self.demo=QCheckBox('Modo DEMO / TEST — usar datos ficticios identificados como DEMO DATA')
        l.addWidget(self.demo)
        l.addWidget(QLabel(f'Directorio de salida predeterminado:\n{safe_output_root()}'))
        self.admin_btn=QPushButton('Reiniciar como administrador')
        self.admin_btn.setEnabled(not is_admin())
        self.admin_btn.clicked.connect(self.admin)
        l.addWidget(self.admin_btn)
        self.root.addWidget(box)
        self.root.addStretch()

    def admin(self):
        if relaunch_as_admin():
            QApplication.instance().quit()
        else:
            QMessageBox.warning(self,'No disponible','Windows no permitió iniciar la aplicación con elevación.')


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('WINDOWS FORENSIC AUDITOR')
        self.resize(1580,930)
        self.setMinimumSize(1220,760)
        self.worker=None
        self.progress_box=None
        self.output_dir:Path|None=None
        self.data={}
        self.pages={}
        self.nav=[]
        self._build()
        self._style()

    def _build(self):
        root=QWidget()
        self.setCentralWidget(root)
        outer=QVBoxLayout(root)
        outer.setContentsMargins(0,0,0,0)
        outer.setSpacing(0)
        head=QFrame()
        head.setObjectName('header')
        hl=QHBoxLayout(head)
        hl.setContentsMargins(22,10,18,10)
        brand=QVBoxLayout()
        title=QLabel('▣  WINDOWS FORENSIC AUDITOR')
        title.setObjectName('brandTitle')
        by=QLabel('Creado por el Equipo Forense de Alejandro')
        by.setObjectName('brandBy')
        brand.addWidget(title)
        brand.addWidget(by)
        hl.addLayout(brand)
        hl.addStretch()
        self.header_meta=QLabel('Equipo: —   |   Perfil: Auditoría completa')
        self.header_meta.setObjectName('headerMeta')
        hl.addWidget(self.header_meta)
        outer.addWidget(head)
        body=QHBoxLayout()
        body.setSpacing(0)
        outer.addLayout(body,1)
        side=QFrame()
        side.setObjectName('sidebar')
        side.setFixedWidth(252)
        sl=QVBoxLayout(side)
        sl.setContentsMargins(10,16,10,12)
        sl.setSpacing(5)
        menu=[
            ('Panel principal','dashboard'),('Resumen del sistema','system'),('Cuentas de usuario','accounts'),
            ('Acceso remoto e inicios de sesión','remote'),('Actividad de procesos','processes'),
            ('Actividad de red','network'),('Persistencia y autoarranque','persistence'),
            ('Dispositivos USB','usb'),('Seguridad y eventos','security'),('Línea de tiempo','timeline'),
            ('Hallazgos','findings'),('Evidencia','evidence'),('Reportes','reports'),('Configuración','settings')
        ]
        for label,key in menu:
            b=QPushButton(label)
            b.setObjectName('navButton')
            b.setCheckable(True)
            b.clicked.connect(lambda _,k=key:self.show_page(k))
            sl.addWidget(b)
            self.nav.append((key,b))
        sl.addStretch()
        self.target=QLabel('🖥  OBJETIVO ACTUAL\n\nSin auditoría ejecutada')
        self.target.setObjectName('targetBox')
        self.target.setWordWrap(True)
        sl.addWidget(self.target)
        body.addWidget(side)
        self.stack=QStackedWidget()
        body.addWidget(self.stack,1)
        self.pages['dashboard']=DashboardPage(self)
        self.pages['system']=ModulePage(self,'Resumen del sistema',['system','software','windows_update','recent_files'])
        self.pages['accounts']=ModulePage(self,'Cuentas de usuario',['accounts'])
        self.pages['remote']=RemotePageModern(self)
        self.pages['processes']=ModulePage(self,'Actividad de procesos',['processes','powershell'])
        self.pages['network']=ModulePage(self,'Actividad de red',['network','firewall'])
        self.pages['persistence']=ModulePage(self,'Persistencia y autoarranque',['persistence','services','tasks'])
        self.pages['usb']=ModulePage(self,'Dispositivos USB',['usb'])
        self.pages['security']=ModulePage(self,'Seguridad y eventos',['defender','events','firewall','windows_update'])
        self.pages['timeline']=TimelinePage(self)
        self.pages['findings']=FindingsPage(self)
        self.pages['evidence']=EvidencePage(self)
        self.pages['reports']=ReportsPage(self)
        self.pages['settings']=SettingsPage(self)
        for p in self.pages.values():
            self.stack.addWidget(p)
        self.show_page('dashboard')

    def show_page(self,key):
        self.stack.setCurrentWidget(self.pages[key])
        for k,b in self.nav:
            b.setChecked(k==key)

    def start_audit(self):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self,'Auditoría en curso','Ya existe una auditoría en ejecución.')
            return
        answer=QMessageBox.question(self,'Nueva auditoría','La auditoría recopilará información del sistema, cuentas, procesos, red y registros de seguridad.\n\n¿Desea iniciar la auditoría completa?',QMessageBox.Yes|QMessageBox.No)
        if answer!=QMessageBox.Yes:
            return
        demo=self.pages['settings'].demo.isChecked()
        self.worker=AuditWorker(Path(safe_output_root()),demo)
        self.worker.progress.connect(self._progress)
        self.worker.done.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.progress_box=QMessageBox(self)
        self.progress_box.setWindowTitle('Auditoría en curso')
        self.progress_box.setText('Preparando auditoría...')
        self.progress_box.setStandardButtons(QMessageBox.Cancel)
        self.progress_box.buttonClicked.connect(lambda _:self.worker.engine.cancel())
        self.progress_box.show()
        self.worker.start()

    def _progress(self,name,i,total):
        if self.progress_box:
            self.progress_box.setText(f'Analizando: {COLLECTOR_LABELS.get(name,name)}\nProgreso: {i} de {total} módulos')

    def _failed(self,msg):
        if self.progress_box:
            self.progress_box.close()
        QMessageBox.critical(self,'Error de auditoría',msg)

    def _finished(self,out,summary):
        if self.progress_box:
            self.progress_box.close()
        self.output_dir=Path(out)
        try:
            self.data=json.loads((self.output_dir/'reports'/'audit.json').read_text(encoding='utf-8'))
        except Exception:
            self.data={'results':[],'findings':[],'risk_score':summary.get('risk_score',0)}
        self.data['audit_id']=summary.get('audit_id')
        self.data['risk_score']=summary.get('risk_score',self.data.get('risk_score',0))
        self._populate_all()
        self.show_page('dashboard')
        QMessageBox.information(self,'Auditoría finalizada','La auditoría terminó. Los resultados ya están disponibles en pantalla.\n\nLos archivos de evidencia y reportes quedaron guardados como respaldo técnico.')

    def _populate_all(self):
        for p in self.pages.values():
            if hasattr(p,'load'):
                p.load(self.data)
        by={r.get('name'):r for r in self.data.get('results',[])}
        sys=(by.get('system',{}).get('records') or [{}])[0]
        host=sys.get('hostname') or os.environ.get('COMPUTERNAME') or '—'
        win=sys.get('os') or sys.get('release') or 'Windows'
        self.header_meta.setText(f'Equipo: {host}   |   Perfil: Auditoría completa   |   {datetime.now():%d/%m/%Y %H:%M}')
        self.target.setText(f'🖥  OBJETIVO ACTUAL\n\n{host}\n{win}\nÚltima auditoría: {datetime.now():%d/%m/%Y %H:%M}')

    def open_output(self):
        if not self.output_dir:
            QMessageBox.information(self,'Sin auditoría','Primero ejecute una auditoría.')
            return
        try:
            os.startfile(str(self.output_dir))
        except Exception:
            QMessageBox.information(self,'Carpeta de auditoría',str(self.output_dir))

    def _style(self):
        self.setStyleSheet('''
        *{font-family:"Segoe UI";font-size:12px;color:#dce8f3}
        QMainWindow,QWidget{background:#07131f}
        #header{background:#0a1c2b;border-bottom:1px solid #1a3952}
        #brandTitle{font-size:20px;font-weight:700;color:#f4f9ff}
        #brandBy{font-size:11px;color:#9eb7cc;margin-left:31px}
        #headerMeta{color:#aec1d2}
        #sidebar{background:#091927;border-right:1px solid #18364e}
        #navButton{text-align:left;background:transparent;border:0;border-radius:7px;padding:10px 12px;color:#c3d4e3}
        #navButton:hover{background:#102a3e}
        #navButton:checked{background:#0d5798;border-left:3px solid #38a7ff;color:#fff;font-weight:600}
        #targetBox{background:#0c2232;border:1px solid #1b3a52;border-radius:8px;padding:12px;color:#aac0d4}
        #pageTitle{font-size:24px;font-weight:700;color:#f2f7fc}
        #pageSub{color:#94adbf}
        #panel,#metric{background:#0b2030;border:1px solid #1a3a52;border-radius:9px}
        #metricTitle{color:#a9bfd2;font-weight:600}
        #metricValue{font-size:23px;font-weight:700}
        #metricSub{color:#7f99ad;font-size:11px}
        #sectionTitle{font-size:15px;font-weight:700;color:#eef7ff}
        QPushButton{background:#10293d;border:1px solid #27506d;border-radius:6px;padding:8px 12px;color:#e6f2fb}
        QPushButton:hover{background:#153750;border-color:#3376a3}
        #primary{background:#0d75d5;border-color:#1a8bf0;font-weight:700;color:white}
        QLineEdit,QTextEdit,QComboBox{background:#081a28;border:1px solid #24465e;border-radius:6px;padding:7px;color:#e3edf5}
        QTableWidget{background:#081925;alternate-background-color:#0b2030;border:0;selection-background-color:#0d5b9e;selection-color:white}
        QHeaderView::section{background:#10283a;color:#dce9f3;border:0;border-right:1px solid #1d3c53;padding:8px;font-weight:600}
        QTabWidget::pane{border:1px solid #1a3a52;background:#081925;border-radius:7px}
        QTabBar::tab{background:#0c2131;border:1px solid #1a3a52;padding:8px 16px;color:#a9bfd2}
        QTabBar::tab:selected{background:#0d5798;color:white}
        ''')
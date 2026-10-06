from __future__ import annotations
import json, os, shutil, zipfile, hashlib
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,QRadioButton,QButtonGroup,
    QGroupBox,QCheckBox,QMessageBox,QFileDialog,QProgressBar,QFrame,QGridLayout,QTextEdit
)

PROFILE_MAP={
    'Rápida':{'system','accounts','processes','network','defender'},
    'Completa':None,
    'Acceso remoto':{'system','accounts','logons','rdp','network','firewall','events'},
    'Seguridad':{'system','accounts','events','defender','firewall','windows_update','powershell'},
    'Persistencia':{'system','services','tasks','persistence','powershell','recent_files'},
}

def correlate(data:dict)->list[dict]:
    findings=[]
    by={r.get('name'):r for r in data.get('results',[])}
    logons=by.get('logons',{}).get('records') or []
    failed=[e for e in logons if int(e.get('event_id',0) or 0)==4625]
    success=[e for e in logons if int(e.get('event_id',0) or 0)==4624]
    def d(e):
        x=e.get('data'); return x if isinstance(x,dict) else {}
    def ip(e):
        x=d(e); return str(x.get('IpAddress') or x.get('SourceNetworkAddress') or x.get('Param3') or '')
    def user(e):
        x=d(e); return str(x.get('TargetUserName') or x.get('SubjectUserName') or x.get('Param1') or '')
    grouped={}
    for e in failed:
        k=(ip(e),user(e)); grouped.setdefault(k,0); grouped[k]+=1
    for (src,u),count in grouped.items():
        if count>=5:
            has_success=any((not src or ip(s)==src) and (not u or user(s)==u) for s in success)
            findings.append({
                'severity':'HIGH' if has_success else 'MEDIUM','module':'logons',
                'title':'Múltiples intentos fallidos'+(' seguidos de acceso exitoso' if has_success else ''),
                'classification':'INDICADOR',
                'reason':f'Se registraron {count} eventos 4625 para el mismo origen/usuario. '+('También existe al menos un 4624 compatible.' if has_success else 'No se infiere por sí solo un ataque.'),
                'evidence':[{'source_ip':src or 'No disponible','user':u or 'No disponible','failed_count':count,'success_after_pattern':has_success}]
            })
    ps=by.get('powershell',{}).get('records') or []
    suspicious=[]
    for e in ps:
        blob=json.dumps(e,ensure_ascii=False).lower()
        if 'encodedcommand' in blob or '-enc ' in blob or 'frombase64string' in blob:
            suspicious.append(e)
    if suspicious:
        findings.append({'severity':'HIGH','module':'powershell','title':'PowerShell con indicadores de ofuscación o contenido codificado','classification':'INDICADOR','reason':f'Se detectaron {len(suspicious)} registros con patrones como EncodedCommand o Base64.','evidence':suspicious[:5]})
    services=by.get('services',{}).get('records') or []
    svc=[]
    for e in services:
        blob=json.dumps(e,ensure_ascii=False).lower()
        if any(x in blob for x in ('\\appdata\\','\\temp\\','\\users\\public\\')):
            svc.append(e)
    if svc:
        findings.append({'severity':'HIGH','module':'services','title':'Servicio con binario en ruta atípica','classification':'INDICADOR','reason':'Se observaron servicios asociados a rutas de usuario, AppData, Temp o Public. Requiere verificación contextual.','evidence':svc[:5]})
    proc=by.get('processes',{}).get('records') or []
    odd=[]
    for e in proc:
        blob=json.dumps(e,ensure_ascii=False).lower()
        if any(x in blob for x in ('\\appdata\\local\\temp\\','\\temp\\')) or 'encodedcommand' in blob:
            odd.append(e)
    if odd:
        findings.append({'severity':'MEDIUM','module':'processes','title':'Procesos ejecutados desde rutas temporales o con comandos atípicos','classification':'INDICADOR','reason':'Se detectaron procesos en ubicaciones o con parámetros que merecen revisión. No implica por sí solo actividad maliciosa.','evidence':odd[:8]})
    events=by.get('events',{}).get('records') or []
    cleared=[e for e in events if int(e.get('event_id',0) or 0) in (104,1102)]
    if cleared:
        findings.append({'severity':'HIGH','module':'events','title':'Evidencia de limpieza de registros de eventos','classification':'EVIDENCIA DIRECTA','reason':'Se encontraron eventos 104 y/o 1102 compatibles con limpieza de registros.','evidence':cleared[:10]})
    return findings

class ProfileDialog(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent); self.setWindowTitle('Nueva auditoría'); self.setMinimumWidth(520)
        l=QVBoxLayout(self); h=QLabel('Seleccione el perfil de auditoría'); h.setStyleSheet('font-size:20px;font-weight:700;'); l.addWidget(h)
        s=QLabel('El perfil define qué módulos se recopilan. Puede ejecutar la auditoría completa para máxima cobertura.'); s.setWordWrap(True); l.addWidget(s)
        self.group=QButtonGroup(self)
        for i,(name,desc) in enumerate([
            ('Rápida','Sistema, cuentas, procesos, red y Defender.'),
            ('Completa','Todos los módulos disponibles.'),
            ('Acceso remoto','Security, RDP, red, firewall y eventos.'),
            ('Seguridad','Eventos, Defender, firewall, PowerShell y actualizaciones.'),
            ('Persistencia','Servicios, tareas, persistencia, PowerShell y archivos recientes.'),
        ]):
            r=QRadioButton(f'{name} — {desc}'); self.group.addButton(r,i); l.addWidget(r)
            if name=='Completa': r.setChecked(True)
        self.demo=QCheckBox('Modo DEMO / TEST (datos ficticios claramente identificados)'); l.addWidget(self.demo)
        row=QHBoxLayout(); row.addStretch(); cancel=QPushButton('Cancelar'); cancel.clicked.connect(self.reject); ok=QPushButton('Iniciar auditoría'); ok.setObjectName('primary'); ok.clicked.connect(self.accept); row.addWidget(cancel); row.addWidget(ok); l.addLayout(row)
    def selection(self):
        b=self.group.checkedButton(); txt=b.text().split(' — ')[0] if b else 'Completa'; return txt,self.demo.isChecked()

def make_full_package(output_dir:Path, destination:Path):
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'w',zipfile.ZIP_DEFLATED) as z:
        for p in output_dir.rglob('*'):
            if p.is_file():
                z.write(p,p.relative_to(output_dir))
    h=hashlib.sha256(destination.read_bytes()).hexdigest()
    sha=destination.with_suffix(destination.suffix+'.sha256.txt'); sha.write_text(h,encoding='ascii')
    return h,sha

def apply_v3(window):
    window.setWindowTitle('WINDOWS FORENSIC AUDITOR — V3 Professional')
    window.resize(1660,960)
    # Professional action strip under header
    central=window.centralWidget()
    outer=central.layout()
    bar=QFrame(); bar.setObjectName('actionBar'); lay=QHBoxLayout(bar); lay.setContentsMargins(16,8,16,8)
    status=QLabel('Estado: LISTO'); status.setObjectName('statusPill'); lay.addWidget(status); lay.addStretch()
    new=QPushButton('＋ Nueva auditoría'); new.setObjectName('primary'); new.clicked.connect(window.start_audit); lay.addWidget(new)
    exp=QPushButton('Exportar reporte completo'); exp.setObjectName('reportButton'); exp.clicked.connect(lambda:window.export_full_report()); lay.addWidget(exp)
    helpb=QPushButton('Ayuda'); helpb.clicked.connect(lambda:QMessageBox.information(window,'Ayuda','Ejecute la auditoría como administrador para maximizar cobertura.\n\nLos resultados se muestran en pantalla y el reporte completo puede exportarse como paquete ZIP.')); lay.addWidget(helpb)
    outer.insertWidget(1,bar)
    window.v3_status=status
    # Add prominent export button on report page
    reports=window.pages.get('reports')
    if reports:
        b=QPushButton('⬇  EXPORTAR REPORTE COMPLETO'); b.setObjectName('primary'); b.setMinimumHeight(44); b.clicked.connect(lambda:window.export_full_report()); reports.root.insertWidget(2,b)
    # Polish stylesheet
    window.setStyleSheet(window.styleSheet()+'''
    #actionBar{background:#0a1825;border-bottom:1px solid #17364e}
    #statusPill{background:#0d2a3d;border:1px solid #235776;border-radius:12px;padding:6px 12px;color:#a9d8ff;font-weight:600}
    #reportButton{background:#12324a;border:1px solid #2b698e;font-weight:600}
    #reportButton:hover{background:#174663}
    QToolTip{background:#10283a;color:white;border:1px solid #2d5876;padding:6px}
    QScrollBar:vertical{background:#07131f;width:10px;margin:0}
    QScrollBar::handle:vertical{background:#23445e;border-radius:5px;min-height:24px}
    QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}
    ''')
    return window

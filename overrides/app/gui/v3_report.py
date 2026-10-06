from __future__ import annotations
from pathlib import Path
from html import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak

def _txt(v):
    if v is None:return '—'
    return str(v)

def generate_professional_pdf(data:dict,out:Path,profile='Completa'):
    reports=out/'reports'; reports.mkdir(parents=True,exist_ok=True)
    pdf=reports/'reporte_forense_profesional.pdf'
    styles=getSampleStyleSheet()
    title=ParagraphStyle('TitleX',parent=styles['Title'],fontSize=22,leading=26,alignment=TA_CENTER,textColor=colors.HexColor('#17365D'),spaceAfter=10)
    h1=ParagraphStyle('H1X',parent=styles['Heading1'],fontSize=15,leading=18,textColor=colors.HexColor('#17365D'),spaceBefore=9,spaceAfter=7)
    body=ParagraphStyle('BodyX',parent=styles['BodyText'],fontSize=9.5,leading=13,spaceAfter=5)
    small=ParagraphStyle('SmallX',parent=body,fontSize=8,leading=10)
    doc=SimpleDocTemplate(str(pdf),pagesize=A4,rightMargin=16*mm,leftMargin=16*mm,topMargin=14*mm,bottomMargin=14*mm,title='Windows Forensic Auditor - Reporte Forense')
    story=[Paragraph('WINDOWS FORENSIC AUDITOR',title),Paragraph('Creado por el Equipo Forense de Alejandro',ParagraphStyle('sub',parent=body,alignment=TA_CENTER,textColor=colors.grey)),Spacer(1,5*mm)]
    by={r.get('name'):r for r in data.get('results',[])}
    sys=(by.get('system',{}).get('records') or [{}])[0]
    findings=data.get('findings',[]) or []
    risk=data.get('risk_score',0)
    meta=[
        ['Auditoría',_txt(data.get('audit_id'))],['Perfil',profile],['Equipo',_txt(sys.get('hostname'))],
        ['Usuario',_txt(sys.get('user'))],['Sistema operativo',_txt(sys.get('os') or sys.get('release'))],['Puntaje de riesgo',f'{risk} / 100'],
    ]
    t=Table(meta,colWidths=[45*mm,125*mm])
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#EAF2F8')),('GRID',(0,0),(-1,-1),0.25,colors.HexColor('#AAB7B8')),('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),9),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6)]))
    story += [t,Spacer(1,5*mm),Paragraph('1. Resumen ejecutivo',h1)]
    total=sum(len(r.get('records') or []) for r in data.get('results',[]))
    critical=sum(1 for f in findings if str(f.get('severity')).upper()=='CRITICAL')
    high=sum(1 for f in findings if str(f.get('severity')).upper()=='HIGH')
    story.append(Paragraph(f'Se recopilaron <b>{total}</b> registros de las fuentes disponibles y se generaron <b>{len(findings)}</b> hallazgos automáticos. Hallazgos críticos: <b>{critical}</b>; altos: <b>{high}</b>. El puntaje de riesgo es heurístico y no constituye por sí solo una conclusión pericial.',body))
    story += [Paragraph('2. Cobertura de evidencia',h1)]
    rows=[['Módulo','Estado','Registros','Fuente / observación']]
    for r in data.get('results',[]):
        rows.append([_txt(r.get('name')),_txt(r.get('status')),_txt(len(r.get('records') or [])),_txt(r.get('error') or r.get('source') or r.get('name'))[:90]])
    tab=Table(rows,colWidths=[35*mm,28*mm,22*mm,85*mm],repeatRows=1)
    tab.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#17365D')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),7.5),('GRID',(0,0),(-1,-1),0.25,colors.HexColor('#BDC3C7')),('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#F8F9F9')])]))
    story += [tab,PageBreak(),Paragraph('3. Hallazgos',h1)]
    if not findings:
        story.append(Paragraph('No se generaron hallazgos automáticos con la evidencia disponible.',body))
    for i,f in enumerate(findings,1):
        story.append(Paragraph(f'{i}. {escape(_txt(f.get("title")))}',ParagraphStyle('fh',parent=h1,fontSize=11,leading=14)))
        story.append(Paragraph(f'<b>Severidad:</b> {escape(_txt(f.get("severity")))} &nbsp;&nbsp; <b>Clasificación:</b> {escape(_txt(f.get("classification")))} &nbsp;&nbsp; <b>Módulo:</b> {escape(_txt(f.get("module")))}',body))
        story.append(Paragraph(f'<b>Interpretación:</b> {escape(_txt(f.get("reason")))}',body))
        ev=f.get('evidence') or []
        if ev: story.append(Paragraph('<b>Evidencia resumida:</b> '+escape(_txt(ev[:3]))[:1800],small))
        story.append(Paragraph('<b>Limitación:</b> El hallazgo debe contrastarse con la evidencia original, la configuración de auditoría y el período de retención. La ausencia de un evento no demuestra que la actividad no haya ocurrido.',small))
        story.append(Spacer(1,2*mm))
    story += [PageBreak(),Paragraph('4. Acceso remoto e inicios de sesión',h1)]
    logons=by.get('logons',{}).get('records') or []; rdp=by.get('rdp',{}).get('records') or []
    failed=sum(1 for e in logons if int(e.get('event_id',0) or 0)==4625); success=sum(1 for e in logons if int(e.get('event_id',0) or 0)==4624)
    story.append(Paragraph(f'Eventos 4624 registrados: <b>{success}</b>. Eventos 4625 registrados: <b>{failed}</b>. Registros RDP/Terminal Services: <b>{len(rdp)}</b>. Estos conteos reflejan únicamente la evidencia conservada y accesible.',body))
    story += [Paragraph('5. Módulos técnicos relevantes',h1)]
    for name in ('processes','powershell','network','services','tasks','persistence','usb','defender','events','firewall'):
        r=by.get(name)
        if not r: continue
        story.append(Paragraph(f'<b>{escape(name)}</b>: {len(r.get("records") or [])} registros — estado {escape(_txt(r.get("status")))}.',body))
    story += [Paragraph('6. Consideraciones y limitaciones',h1),Paragraph('Este reporte diferencia evidencia disponible, indicadores y conclusiones inferenciales. Un registro ausente puede deberse a retención, configuración, permisos, canal no habilitado o falta de cobertura. No debe afirmarse que un evento no ocurrió únicamente porque no exista un registro conservado.',body)]
    story += [Paragraph('7. Integridad y trazabilidad',h1),Paragraph('El paquete exportado por la aplicación incorpora los productos de auditoría y genera un SHA-256 del archivo ZIP completo. Conserve dicho hash junto con el paquete para controles posteriores de integridad.',body)]
    doc.build(story)
    return pdf

def generate_professional_html(data:dict,out:Path,profile='Completa'):
    p=out/'reports'/'reporte_forense_profesional.html'
    findings=''.join(f"<article><h3>{escape(str(f.get('title','Hallazgo')))}</h3><p><b>Severidad:</b> {escape(str(f.get('severity','—')))} · <b>Clasificación:</b> {escape(str(f.get('classification','—')))}</p><p>{escape(str(f.get('reason','—')))}</p></article>" for f in data.get('findings',[]))
    coverage=''.join(f"<tr><td>{escape(str(r.get('name','—')))}</td><td>{escape(str(r.get('status','—')))}</td><td>{len(r.get('records') or [])}</td><td>{escape(str(r.get('error') or r.get('source') or '—'))}</td></tr>" for r in data.get('results',[]))
    html=f"""<!doctype html><html lang='es'><meta charset='utf-8'><title>Reporte Forense</title><style>body{{font-family:Segoe UI,Arial;background:#f4f6f8;color:#17202a;margin:0}}header{{background:#0b1f33;color:white;padding:28px 40px}}main{{max-width:1100px;margin:auto;padding:30px}}section,article{{background:white;border:1px solid #dfe6e9;border-radius:10px;padding:18px;margin:14px 0}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid #e5e8e8;text-align:left}}th{{background:#17365d;color:white}}.badge{{display:inline-block;background:#eaf2f8;padding:6px 10px;border-radius:14px}}</style><header><h1>WINDOWS FORENSIC AUDITOR</h1><div>Creado por el Equipo Forense de Alejandro</div></header><main><section><h2>Resumen ejecutivo</h2><p class='badge'>Perfil: {escape(profile)}</p><p>Puntaje de riesgo: <b>{escape(str(data.get('risk_score','—')))} / 100</b></p><p>Hallazgos: <b>{len(data.get('findings',[]))}</b></p></section><section><h2>Cobertura</h2><table><tr><th>Módulo</th><th>Estado</th><th>Registros</th><th>Fuente</th></tr>{coverage}</table></section><section><h2>Hallazgos</h2>{findings or '<p>No se generaron hallazgos automáticos.</p>'}</section><section><h2>Limitaciones</h2><p>La ausencia de un evento no demuestra que la actividad no haya ocurrido. Deben considerarse permisos, retención, canales habilitados y cobertura disponible.</p></section></main></html>"""
    p.write_text(html,encoding='utf-8'); return p

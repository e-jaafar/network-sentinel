#!/usr/bin/env python3
"""
PDF Report Generator for Network Sentinel
"""

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT


def generate_pdf_report(scan_data: dict, ai_analysis: str = None) -> bytes:
    """
    Generate a PDF security report from scan data
    Returns PDF as bytes
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=1.5*cm, bottomMargin=1.5*cm)
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#00ff88')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#00d4ff')
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    elements = []
    
    # Title
    elements.append(Paragraph("🛡️ Network Sentinel", title_style))
    elements.append(Paragraph("Security Assessment Report", styles['Heading2']))
    elements.append(Spacer(1, 20))
    
    # Report metadata
    scan_time = scan_data.get("scan_time", datetime.now().isoformat())
    elements.append(Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Paragraph(f"<b>Scan Time:</b> {scan_time}", normal_style))
    elements.append(Paragraph(f"<b>Network:</b> {scan_data.get('network', 'Unknown')}", normal_style))
    elements.append(Spacer(1, 20))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    
    devices = scan_data.get("devices", [])
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    total_ports = 0
    
    for device in devices:
        level = device.get("risk", {}).get("level", "MINIMAL")
        risk_counts[level] = risk_counts.get(level, 0) + 1
        total_ports += len(device.get("ports", []))
    
    summary_data = [
        ["Metric", "Value"],
        ["Total Devices", str(len(devices))],
        ["Open Ports", str(total_ports)],
        ["High Risk Devices", str(risk_counts["HIGH"])],
        ["Medium Risk Devices", str(risk_counts["MEDIUM"])],
        ["Low Risk Devices", str(risk_counts["LOW"])],
        ["Minimal Risk Devices", str(risk_counts["MINIMAL"])],
    ]
    
    summary_table = Table(summary_data, colWidths=[8*cm, 4*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e1e2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    # Device Details
    elements.append(Paragraph("Device Inventory", heading_style))
    
    device_data = [["IP Address", "MAC Address", "Vendor", "Open Ports", "Risk"]]
    
    for device in devices:
        ports = device.get("ports", [])
        ports_str = ", ".join([f"{p['port']}" for p in ports[:3]])
        if len(ports) > 3:
            ports_str += f" (+{len(ports)-3})"
        
        risk_level = device.get("risk", {}).get("level", "MINIMAL")
        
        device_data.append([
            device.get("ip", "N/A"),
            device.get("mac", "N/A"),
            device.get("vendor", "Unknown")[:15],
            ports_str or "None",
            risk_level
        ])
    
    device_table = Table(device_data, colWidths=[3*cm, 4*cm, 3*cm, 3*cm, 2*cm])
    device_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e1e2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
    ]))
    
    elements.append(device_table)
    elements.append(Spacer(1, 20))
    
    # Security Findings
    elements.append(Paragraph("Security Findings", heading_style))
    
    findings_found = False
    for device in devices:
        reasons = device.get("risk", {}).get("reasons", [])
        if reasons:
            findings_found = True
            elements.append(Paragraph(f"<b>{device.get('ip', 'Unknown')}</b> ({device.get('vendor', 'Unknown')})", normal_style))
            for reason in reasons:
                elements.append(Paragraph(f"  • {reason}", normal_style))
            elements.append(Spacer(1, 10))
    
    if not findings_found:
        elements.append(Paragraph("No significant security issues detected.", normal_style))
    
    elements.append(Spacer(1, 20))
    
    # AI Analysis (if provided)
    if ai_analysis:
        elements.append(Paragraph("AI Security Analysis", heading_style))
        
        # Split AI analysis into paragraphs
        for para in ai_analysis.split('\n\n'):
            if para.strip():
                # Handle markdown-style headers
                if para.startswith('**') or para.startswith('###'):
                    clean_para = para.replace('**', '').replace('###', '').replace('#', '').strip()
                    elements.append(Paragraph(f"<b>{clean_para}</b>", normal_style))
                else:
                    elements.append(Paragraph(para.strip(), normal_style))
        
        elements.append(Spacer(1, 20))
    
    # Footer
    elements.append(Spacer(1, 30))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.gray)
    elements.append(Paragraph("Generated by Network Sentinel | AI-Powered Network Security", footer_style))
    elements.append(Paragraph("Running on Raspberry Pi 5 with Llama 3.2", footer_style))
    
    # Build PDF
    doc.build(elements)
    
    buffer.seek(0)
    return buffer.getvalue()

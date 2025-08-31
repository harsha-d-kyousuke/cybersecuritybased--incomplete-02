# backend/reports/report_generator.py
import os
import json
from datetime import datetime
from typing import Dict, List, Any
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.colors import HexColor, black, white, red, orange, yellow, green
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Severity color mapping
        self.severity_colors = {
            'critical': HexColor('#d32f2f'),
            'high': HexColor('#f57c00'),
            'medium': HexColor('#fbc02d'),
            'low': HexColor('#689f38'),
            'info': HexColor('#1976d2')
        }

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1976d2'),
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=HexColor('#424242'),
            borderWidth=0,
            borderColor=HexColor('#e0e0e0'),
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceBefore=15,
            spaceAfter=5,
            textColor=HexColor('#d32f2f')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Code'],
            fontSize=10,
            backgroundColor=HexColor('#f5f5f5'),
            borderWidth=1,
            borderColor=HexColor('#e0e0e0'),
            borderPadding=8,
            fontName='Courier'
        ))

    async def generate_pdf_report(self, attack_data: Dict[str, Any]) -> str:
        """Generate comprehensive PDF security report"""
        try:
            # Create filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{attack_data['id']}_{timestamp}.pdf"
            filepath = os.path.join(self.report_dir, filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page(attack_data))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(attack_data))
            story.append(PageBreak())
            
            # Vulnerability details
            story.extend(self._create_vulnerability_details(attack_data))
            
            # Recommendations
            story.extend(self._create_recommendations(attack_data))
            
            # Appendices
            story.extend(self._create_appendices(attack_data))
            
            # Build PDF
            doc.build(story)
            
            logger.info(f"PDF report generated: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
            raise

    def _create_title_page(self, attack_data: Dict[str, Any]) -> List:
        """Create report title page"""
        story = []
        
        # Title
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("CYBERSECURITY ASSESSMENT REPORT", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        attack_type_display = attack_data['attack_type'].replace('_', ' ').title()
        story.append(Paragraph(f"{attack_type_display} Security Assessment", self.styles['Heading2']))
        story.append(Spacer(1, 1*inch))
        
        # Report details table
        report_details = [
            ['Target URL:', attack_data.get('target_url', 'N/A')],
            ['Assessment Type:', attack_type_display],
            ['Assessment Date:', datetime.fromisoformat(attack_data['timestamp'].replace('Z', '+00:00')).strftime('%B %d, %Y at %H:%M UTC')],
            ['Report Generated:', datetime.now().strftime('%B %d, %Y at %H:%M UTC')],
            ['Severity Score:', f"{attack_data.get('severity_score', 0)}/10"],
            ['Vulnerabilities Found:', str(len(attack_data.get('vulnerabilities_found', [])))]
        ]
        
        table = Table(report_details, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#495057')),
            ('TEXTCOLOR', (1, 0), (1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [HexColor('#ffffff'), HexColor('#f8f9fa')])
        ]))
        
        story.append(table)
        story.append(Spacer(1, 1*inch))
        
        # Disclaimer
        disclaimer = """
        <b>CONFIDENTIAL</b><br/>
        This report contains confidential security assessment information. 
        Distribution should be limited to authorized personnel only. 
        The vulnerabilities identified in this report should be addressed 
        with appropriate urgency based on their severity levels.
        """
        story.append(Paragraph(disclaimer, self.styles['Normal']))
        
        return story

    def _create_executive_summary(self, attack_data: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        vulnerabilities = attack_data.get('vulnerabilities_found', [])
        if isinstance(vulnerabilities, str):
            try:
                vulnerabilities = json.loads(vulnerabilities)
            except:
                vulnerabilities = []
        
        # Summary statistics
        total_vulns = len(vulnerabilities)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Summary text
        if total_vulns == 0:
            summary_text = """
            The security assessment completed successfully with no vulnerabilities identified. 
            The target application appears to have adequate security controls in place for 
            the tested attack vectors. However, this assessment covers only specific attack 
            scenarios and should not be considered a comprehensive security
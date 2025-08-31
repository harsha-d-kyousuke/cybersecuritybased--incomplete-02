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
            scenarios and should not be considered a comprehensive security evaluation.
            """
        else:
            critical_high = severity_counts['critical'] + severity_counts['high']
            if critical_high > 0:
                risk_level = "HIGH RISK"
                summary_text = f"""
                The security assessment identified <b>{total_vulns}</b> vulnerabilities, including 
                <b>{critical_high}</b> critical/high severity issues that require immediate attention. 
                These vulnerabilities pose significant security risks and should be remediated as 
                soon as possible to prevent potential security breaches.
                """
            elif severity_counts['medium'] > 0:
                risk_level = "MEDIUM RISK"
                summary_text = f"""
                The security assessment identified <b>{total_vulns}</b> vulnerabilities of medium 
                to low severity. While these issues may not pose immediate critical risks, they 
                should be addressed in upcoming security maintenance cycles to strengthen the 
                overall security posture.
                """
            else:
                risk_level = "LOW RISK"
                summary_text = f"""
                The security assessment identified <b>{total_vulns}</b> low-severity vulnerabilities. 
                These issues represent minor security concerns that should be addressed during 
                regular maintenance cycles.
                """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Vulnerability summary table
        if total_vulns > 0:
            story.append(Paragraph("Vulnerability Summary", self.styles['Heading3']))
            story.append(Spacer(1, 10))
            
            summary_data = [['Severity Level', 'Count', 'Percentage']]
            for severity, count in severity_counts.items():
                if count > 0:
                    percentage = (count / total_vulns) * 100
                    summary_data.append([
                        severity.title(),
                        str(count),
                        f"{percentage:.1f}%"
                    ])
            
            table = Table(summary_data, colWidths=[2*inch, 1*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e3f2fd')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#1565c0')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#bbdefb')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Color-code severity rows
            for i, (severity, count) in enumerate(severity_counts.items(), 1):
                if count > 0:
                    severity_color = self.severity_colors.get(severity, black)
                    table.setStyle(TableStyle([
                        ('TEXTCOLOR', (0, i), (0, i), severity_color)
                    ]))
            
            story.append(table)
        
        return story

    def _create_vulnerability_details(self, attack_data: Dict[str, Any]) -> List:
        """Create detailed vulnerability descriptions"""
        story = []
        
        story.append(Paragraph("Vulnerability Details", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        vulnerabilities = attack_data.get('vulnerabilities_found', [])
        if isinstance(vulnerabilities, str):
            try:
                vulnerabilities = json.loads(vulnerabilities)
            except:
                vulnerabilities = []
        
        if not vulnerabilities:
            story.append(Paragraph("No vulnerabilities were identified during this assessment.", self.styles['Normal']))
            return story
        
        for i, vuln in enumerate(vulnerabilities, 1):
            story.append(Paragraph(f"Vulnerability #{i}: {vuln.get('type', 'Unknown')}", self.styles['VulnTitle']))
            
            # Vulnerability details table
            vuln_details = [
                ['Severity:', vuln.get('severity', 'Unknown').title()],
                ['Parameter:', vuln.get('parameter', 'N/A')],
                ['Evidence:', vuln.get('evidence', 'N/A')],
                ['Description:', vuln.get('description', 'No description available')]
            ]
            
            table = Table(vuln_details, colWidths=[1.2*inch, 4.8*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#495057')),
                ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6)
            ]))
            
            story.append(table)
            
            # Payload information
            if vuln.get('payload'):
                story.append(Spacer(1, 10))
                story.append(Paragraph("Payload Used:", self.styles['Heading4']))
                payload_text = f"<font name='Courier'>{vuln['payload']}</font>"
                story.append(Paragraph(payload_text, self.styles['CodeBlock']))
            
            story.append(Spacer(1, 20))
        
        return story

    def _create_recommendations(self, attack_data: Dict[str, Any]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Remediation Recommendations", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        recommendations = attack_data.get('recommendations', [])
        if isinstance(recommendations, str):
            try:
                recommendations = json.loads(recommendations)
            except:
                recommendations = []
        
        if recommendations:
            story.append(Paragraph("AI-Generated Recommendations:", self.styles['Heading3']))
            story.append(Spacer(1, 10))
            
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
                story.append(Spacer(1, 8))
        
        # General security recommendations based on attack type
        attack_type = attack_data.get('attack_type', '')
        general_recs = self._get_general_recommendations(attack_type)
        
        if general_recs:
            story.append(Spacer(1, 15))
            story.append(Paragraph("General Security Best Practices:", self.styles['Heading3']))
            story.append(Spacer(1, 10))
            
            for i, rec in enumerate(general_recs, 1):
                story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
                story.append(Spacer(1, 8))
        
        return story

    def _create_appendices(self, attack_data: Dict[str, Any]) -> List:
        """Create appendices section"""
        story = []
        
        story.append(PageBreak())
        story.append(Paragraph("Appendices", self.styles['SectionHeader']))
        story.append(Spacer(1, 12))
        
        # Appendix A: Technical Details
        story.append(Paragraph("Appendix A: Technical Assessment Details", self.styles['Heading3']))
        story.append(Spacer(1, 10))
        
        tech_details = [
            ['Assessment Method:', attack_data.get('attack_type', 'N/A').replace('_', ' ').title()],
            ['Target URL:', attack_data.get('target_url', 'N/A')],
            ['Assessment Duration:', 'Automated scan'],
            ['Tools Used:', 'CyberAttack Simulator v1.0'],
            ['Timestamp:', datetime.fromisoformat(attack_data['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')]
        ]
        
        table = Table(tech_details, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#495057')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Appendix B: Risk Matrix
        story.append(Paragraph("Appendix B: Risk Assessment Matrix", self.styles['Heading3']))
        story.append(Spacer(1, 10))
        
        risk_matrix_text = """
        <b>Critical:</b> Immediate action required. Vulnerabilities that can be easily exploited 
        and may lead to complete system compromise.<br/><br/>
        
        <b>High:</b> Prompt attention needed. Significant security risks that should be addressed 
        within days or weeks.<br/><br/>
        
        <b>Medium:</b> Important but not urgent. Should be addressed in the next maintenance cycle.<br/><br/>
        
        <b>Low:</b> Minor issues that can be addressed during routine maintenance.<br/><br/>
        
        <b>Info:</b> Informational findings that may be useful for security awareness.
        """
        story.append(Paragraph(risk_matrix_text, self.styles['Normal']))
        
        return story

    def _get_general_recommendations(self, attack_type: str) -> List[str]:
        """Get general recommendations based on attack type"""
        recommendations = {
            'sql_injection': [
                'Implement parameterized queries (prepared statements) for all database operations',
                'Apply input validation and sanitization on all user inputs',
                'Use stored procedures with proper parameter handling',
                'Implement least-privilege database access controls',
                'Enable database query logging and monitoring',
                'Regular security code reviews and static analysis'
            ],
            'xss': [
                'Implement proper output encoding/escaping for all user data',
                'Use Content Security Policy (CSP) headers',
                'Validate and sanitize all input data',
                'Use framework-provided XSS protection mechanisms',
                'Implement HTTP security headers (X-XSS-Protection, X-Content-Type-Options)',
                'Regular penetration testing for XSS vulnerabilities'
            ],
            'csrf': [
                'Implement CSRF tokens for all state-changing operations',
                'Verify HTTP Referer headers where appropriate',
                'Use SameSite cookie attributes',
                'Implement proper session management',
                'Use double-submit cookie patterns',
                'Educate users about CSRF attack vectors'
            ],
            'directory_traversal': [
                'Implement proper input validation and path sanitization',
                'Use whitelisting for allowed file paths and names',
                'Apply principle of least privilege for file system access',
                'Use secure file handling APIs and libraries',
                'Implement proper access controls and authentication',
                'Regular security assessments of file handling functionality'
            ],
            'brute_force': [
                'Implement account lockout policies',
                'Use strong password requirements',
                'Implement CAPTCHA after multiple failed attempts',
                'Add rate limiting and throttling mechanisms',
                'Monitor and log authentication attempts',
                'Consider multi-factor authentication (MFA)'
            ]
        }
        
        return recommendations.get(attack_type, [
            'Implement comprehensive input validation',
            'Apply security best practices in code development',
            'Regular security assessments and penetration testing',
            'Keep all systems and dependencies updated',
            'Implement proper logging and monitoring',
            'Provide security awareness training to development teams'
        ])

    def generate_json_report(self, attack_data: Dict[str, Any]) -> str:
        """Generate JSON format report"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_report_{attack_data['id']}_{timestamp}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            # Enhanced report data
            report_data = {
                'report_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'report_version': '1.0',
                    'tool_version': 'CyberAttack Simulator v1.0'
                },
                'assessment_details': attack_data,
                'summary': {
                    'total_vulnerabilities': len(attack_data.get('vulnerabilities_found', [])),
                    'severity_distribution': self._calculate_severity_distribution(attack_data),
                    'risk_level': self._calculate_risk_level(attack_data)
                }
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"JSON report generated: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"JSON report generation failed: {str(e)}")
            raise

    def _calculate_severity_distribution(self, attack_data: Dict[str, Any]) -> Dict[str, int]:
        """Calculate distribution of vulnerability severities"""
        vulnerabilities = attack_data.get('vulnerabilities_found', [])
        if isinstance(vulnerabilities, str):
            try:
                vulnerabilities = json.loads(vulnerabilities)
            except:
                vulnerabilities = []
        
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution

    def _calculate_risk_level(self, attack_data: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        distribution = self._calculate_severity_distribution(attack_data)
        
        if distribution['critical'] > 0:
            return 'CRITICAL'
        elif distribution['high'] > 0:
            return 'HIGH'
        elif distribution['medium'] > 0:
            return 'MEDIUM'
        elif distribution['low'] > 0:
            return 'LOW'
        else:
            return 'NONE'
# backend/ai/fix_recommender.py
import os
import asyncio
import logging
from typing import List, Dict, Any, Optional
import openai
import json

logger = logging.getLogger(__name__)

class FixRecommender:
    def __init__(self):
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
        
        if self.openai_api_key:
            openai.api_key = self.openai_api_key
            self.ai_enabled = True
        else:
            self.ai_enabled = False
            logger.warning("OpenAI API key not provided. Using fallback recommendations.")

    async def generate_recommendations(self, attack_type: str, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate AI-powered vulnerability fix recommendations"""
        
        if not vulnerabilities:
            return ["No vulnerabilities found. Continue regular security assessments."]
        
        if self.ai_enabled:
            try:
                return await self._generate_ai_recommendations(attack_type, vulnerabilities)
            except Exception as e:
                logger.error(f"AI recommendation generation failed: {str(e)}")
                return self._generate_fallback_recommendations(attack_type, vulnerabilities)
        else:
            return self._generate_fallback_recommendations(attack_type, vulnerabilities)

    async def _generate_ai_recommendations(self, attack_type: str, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations using OpenAI API"""
        
        # Prepare context for AI
        vulnerability_summary = self._prepare_vulnerability_context(vulnerabilities)
        
        system_prompt = """You are a senior cybersecurity consultant specializing in web application security. 
        Your task is to provide actionable, technical remediation recommendations for identified vulnerabilities.
        
        Guidelines:
        1. Provide specific, actionable steps
        2. Include code examples where appropriate
        3. Prioritize by risk level
        4. Consider both immediate fixes and long-term security improvements
        5. Be concise but comprehensive
        6. Focus on root cause remediation, not just symptoms"""

        user_prompt = f"""
        Attack Type: {attack_type.replace('_', ' ').title()}
        
        Vulnerability Details:
        {vulnerability_summary}
        
        Please provide specific remediation recommendations for these vulnerabilities. Include:
        1. Immediate fixes required
        2. Code-level changes needed
        3. Security controls to implement
        4. Best practices to prevent similar issues
        
        Format as a numbered list of actionable recommendations.
        """

        try:
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=1500,
                temperature=0.3,
                timeout=30
            )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Parse recommendations from AI response
            recommendations = self._parse_ai_response(ai_response)
            
            # Enhance with technical details
            enhanced_recommendations = self._enhance_recommendations(attack_type, recommendations)
            
            return enhanced_recommendations
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {str(e)}")
            raise

    def _prepare_vulnerability_context(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Prepare vulnerability context for AI processing"""
        
        context_parts = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_context = f"""
            Vulnerability #{i}:
            - Type: {vuln.get('type', 'Unknown')}
            - Severity: {vuln.get('severity', 'Unknown')}
            - Parameter: {vuln.get('parameter', 'N/A')}
            - Evidence: {vuln.get('evidence', 'N/A')}
            - Description: {vuln.get('description', 'N/A')}
            """
            if vuln.get('payload'):
                vuln_context += f"- Payload: {vuln['payload'][:100]}{'...' if len(vuln['payload']) > 100 else ''}"
            
            context_parts.append(vuln_context.strip())
        
        return "\n\n".join(context_parts)

    def _parse_ai_response(self, ai_response: str) -> List[str]:
        """Parse AI response into structured recommendations"""
        
        recommendations = []
        lines = ai_response.split('\n')
        
        current_rec = ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Check if this is a numbered item
            if line.match(r'^\d+\.\s'):
                if current_rec:
                    recommendations.append(current_rec.strip())
                current_rec = line
            elif line.startswith('- ') or line.startswith('* '):
                # Sub-item
                current_rec += f" {line}"
            else:
                # Continuation of current item
                if current_rec:
                    current_rec += f" {line}"
                else:
                    current_rec = line
        
        # Add the last recommendation
        if current_rec:
            recommendations.append(current_rec.strip())
        
        # Clean up recommendations
        cleaned_recommendations = []
        for rec in recommendations:
            # Remove numbering if present
            cleaned_rec = rec.strip()
            if cleaned_rec.match(r'^\d+\.\s'):
                cleaned_rec = cleaned_rec.split('.', 1)[1].strip()
            
            if len(cleaned_rec) > 10:  # Filter out very short items
                cleaned_recommendations.append(cleaned_rec)
        
        return cleaned_recommendations[:10]  # Limit to top 10 recommendations

    def _enhance_recommendations(self, attack_type: str, recommendations: List[str]) -> List[str]:
        """Enhance AI recommendations with technical details"""
        
        enhanced = []
        
        # Add attack-specific enhancements
        enhancements = self._get_attack_specific_enhancements(attack_type)
        
        for rec in recommendations:
            enhanced_rec = rec
            
            # Add relevant code snippets or specific guidance
            for keyword, enhancement in enhancements.items():
                if keyword.lower() in rec.lower():
                    enhanced_rec += f" {enhancement}"
                    break
            
            enhanced.append(enhanced_rec)
        
        return enhanced

    def _get_attack_specific_enhancements(self, attack_type: str) -> Dict[str, str]:
        """Get attack-specific technical enhancements"""
        
        enhancements = {
            'sql_injection': {
                'parameterized': "Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                'prepared': "Use prepared statements like mysqli_prepare() in PHP or PreparedStatement in Java.",
                'validation': "Implement strict input validation: allow only alphanumeric characters for IDs, limit string lengths, and validate against expected formats.",
                'escape': "Use database-specific escaping functions like mysql_real_escape_string() only as a secondary defense.",
                'privilege': "Create database users with minimal privileges needed for the application functionality."
            },
            'xss': {
                'encoding': "Use context-appropriate encoding: HTML entity encoding for HTML context, JavaScript encoding for JS context, URL encoding for URLs.",
                'csp': "Implement Content Security Policy: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'",
                'sanitize': "Use libraries like DOMPurify for client-side sanitization or OWASP Java HTML Sanitizer for server-side.",
                'validate': "Validate input against whitelists: only allow expected characters and formats.",
                'headers': "Set security headers: X-XSS-Protection: 1; mode=block, X-Content-Type-Options: nosniff"
            },
            'csrf': {
                'token': "Generate unique CSRF tokens per session: token = hash(session_id + secret + timestamp)",
                'samesite': "Set SameSite cookie attribute: Set-Cookie: sessionid=abc123; SameSite=Strict; Secure",
                'referer': "Validate Referer header: check if request originates from your domain.",
                'double submit': "Use double-submit cookie pattern: include CSRF token in both cookie and request parameter."
            },
            'directory_traversal': {
                'sanitize': "Remove directory traversal sequences: path = path.replace('..', '').replace('\\', '/')",
                'whitelist': "Use whitelist of allowed files: if filename not in ALLOWED_FILES: return error",
                'resolve': "Resolve absolute paths: os.path.abspath(os.path.join(base_dir, filename))",
                'chroot': "Use chroot jail or containerization to limit file system access."
            },
            'brute_force': {
                'lockout': "Implement progressive delays: delay = min(300, 2 ** attempt_count) seconds",
                'captcha': "Add CAPTCHA after 3 failed attempts using libraries like reCAPTCHA.",
                'rate limit': "Use rate limiting: allow max 5 login attempts per IP per minute.",
                'monitoring': "Log and monitor failed attempts: alert on suspicious patterns."
            }
        }
        
        return enhancements.get(attack_type, {})

    def _generate_fallback_recommendations(self, attack_type: str, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate fallback recommendations when AI is not available"""
        
        base_recommendations = {
            'sql_injection': [
                "Implement parameterized queries (prepared statements) for all database operations",
                "Apply strict input validation and sanitization on all user inputs",
                "Use stored procedures with proper parameter validation",
                "Implement least-privilege database access controls",
                "Enable comprehensive database query logging and monitoring",
                "Conduct regular code reviews focusing on database interaction points",
                "Use ORM frameworks that provide built-in SQL injection protection",
                "Implement database connection pooling with proper configuration",
                "Add automated security testing to your CI/CD pipeline"
            ],
            'xss': [
                "Implement proper output encoding/escaping for all dynamic content",
                "Deploy Content Security Policy (CSP) headers to prevent script execution",
                "Validate and sanitize all user inputs on both client and server side",
                "Use framework-provided XSS protection mechanisms",
                "Set appropriate HTTP security headers (X-XSS-Protection, X-Content-Type-Options)",
                "Implement input validation using whitelist approach",
                "Use template engines that automatically escape output",
                "Regular penetration testing specifically for XSS vulnerabilities",
                "Train developers on secure coding practices for XSS prevention"
            ],
            'csrf': [
                "Implement anti-CSRF tokens for all state-changing operations",
                "Use SameSite cookie attributes to prevent cross-site requests",
                "Verify HTTP Referer headers for additional validation",
                "Implement proper session management with secure cookies",
                "Use double-submit cookie pattern for enhanced protection",
                "Add CSRF protection middleware to your web framework",
                "Educate users about CSRF attack vectors and prevention",
                "Regular security assessments of state-changing endpoints"
            ],
            'directory_traversal': [
                "Implement strict input validation and path sanitization",
                "Use whitelist approach for allowed file paths and names",
                "Apply principle of least privilege for file system access",
                "Use secure file handling APIs and avoid direct path manipulation",
                "Implement proper access controls and authentication",
                "Use chroot jails or containerization to limit file access",
                "Regular security assessments of file handling functionality",
                "Log and monitor all file access attempts"
            ],
            'brute_force': [
                "Implement progressive account lockout policies",
                "Enforce strong password requirements and complexity",
                "Add CAPTCHA verification after multiple failed attempts",
                "Implement rate limiting and request throttling",
                "Deploy multi-factor authentication (MFA) for sensitive accounts",
                "Monitor and log all authentication attempts",
                "Use geographic and behavioral anomaly detection",
                "Implement IP-based blocking for suspicious activity"
            ]
        }
        
        recommendations = base_recommendations.get(attack_type, [
            "Implement comprehensive input validation for all user inputs",
            "Apply security best practices in application development",
            "Conduct regular security assessments and penetration testing",
            "Keep all systems and dependencies updated with latest security patches",
            "Implement comprehensive logging and monitoring systems",
            "Provide security awareness training to development teams",
            "Use automated security scanning tools in development pipeline",
            "Establish incident response procedures for security breaches"
        ])
        
        # Add severity-specific recommendations
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        if critical_vulns:
            recommendations.insert(0, "IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected - implement emergency patches")
        
        high_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'high']
        if high_vulns:
            recommendations.insert(0, "HIGH PRIORITY: Address high-severity vulnerabilities within 24-48 hours")
        
        return recommendations[:8]  # Return top 8 recommendations

    async def generate_executive_summary(self, attack_data: Dict[str, Any]) -> str:
        """Generate executive summary for reports"""
        
        vulnerabilities = attack_data.get('vulnerabilities_found', [])
        if isinstance(vulnerabilities, str):
            try:
                vulnerabilities = json.loads(vulnerabilities)
            except:
                vulnerabilities = []
        
        vuln_count = len(vulnerabilities)
        severity_counts = self._count_by_severity(vulnerabilities)
        
        if self.ai_enabled:
            try:
                return await self._generate_ai_executive_summary(attack_data, vuln_count, severity_counts)
            except Exception as e:
                logger.error(f"AI executive summary generation failed: {str(e)}")
        
        return self._generate_fallback_executive_summary(attack_data, vuln_count, severity_counts)

    async def _generate_ai_executive_summary(self, attack_data: Dict[str, Any], vuln_count: int, severity_counts: Dict[str, int]) -> str:
        """Generate AI-powered executive summary"""
        
        prompt = f"""
        Generate a professional executive summary for a cybersecurity assessment report with the following details:
        
        - Attack Type: {attack_data.get('attack_type', 'N/A').replace('_', ' ').title()}
        - Target: {attack_data.get('target_url', 'N/A')}
        - Total Vulnerabilities: {vuln_count}
        - Critical: {severity_counts.get('critical', 0)}
        - High: {severity_counts.get('high', 0)}
        - Medium: {severity_counts.get('medium', 0)}
        - Low: {severity_counts.get('low', 0)}
        - Overall Severity Score: {attack_data.get('severity_score', 0)}/10
        
        Write a concise executive summary (2-3 paragraphs) that:
        1. Summarizes the assessment results
        2. Highlights the risk level
        3. Provides high-level recommendations
        4. Is appropriate for C-level executives
        """
        
        try:
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model=self.openai_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.2,
                timeout=30
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.error(f"AI executive summary failed: {str(e)}")
            raise

    def _generate_fallback_executive_summary(self, attack_data: Dict[str, Any], vuln_count: int, severity_counts: Dict[str, int]) -> str:
        """Generate fallback executive summary"""
        
        attack_type = attack_data.get('attack_type', 'Unknown').replace('_', ' ').title()
        severity_score = attack_data.get('severity_score', 0)
        
        if vuln_count == 0:
            return f"""
            The {attack_type} security assessment completed successfully with no vulnerabilities identified. 
            The target application demonstrates adequate security controls for the tested attack vectors. 
            However, continued vigilance and regular security assessments are recommended to maintain 
            this security posture as the application evolves.
            """
        
        critical_high = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
        
        if critical_high > 0:
            risk_level = "HIGH"
            urgency = "immediate attention"
        elif severity_counts.get('medium', 0) > 0:
            risk_level = "MODERATE"
            urgency = "prompt remediation"
        else:
            risk_level = "LOW"
            urgency = "planned maintenance"
        
        return f"""
        The {attack_type} security assessment identified {vuln_count} vulnerabilities with an overall 
        severity score of {severity_score}/10, indicating {risk_level} risk level. {critical_high} 
        critical/high severity issues require {urgency}, while {severity_counts.get('medium', 0)} 
        medium and {severity_counts.get('low', 0)} low severity issues should be addressed in upcoming 
        development cycles.
        
        Immediate focus should be placed on implementing proper input validation, secure coding practices, 
        and automated security testing to prevent similar vulnerabilities. Regular security assessments 
        and developer training are recommended to maintain a strong security posture.
        """

    def _count_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts
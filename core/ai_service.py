"""
AI Service - Vanchin StreamLake Integration
Provides AI-powered analysis and decision making for attack operations
"""

import os
import json
import aiohttp
from typing import List, Dict, Any, Optional
from loguru import logger


class AIService:
    """AI Service using Vanchin StreamLake API"""
    
    def __init__(self):
        self.api_key = os.getenv("VC_API_KEY", "8-WmOAVImJdRrqBybLj55n-QDu1Y-WYnQNRb280wLhU")
        self.base_url = "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/chat/completions"
        self.model = "ep-zz4e7f-1761510002100745438"
        
    async def chat(
        self,
        messages: List[Dict[str, str]],
        system_prompt: Optional[str] = None
    ) -> str:
        """Send chat request to AI"""
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages
            
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": messages
            }
            
            try:
                async with session.post(
                    self.base_url,
                    headers=headers,
                    json=payload
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["choices"][0]["message"]["content"]
                    else:
                        error_text = await response.text()
                        logger.error(f"AI API error: {error_text}")
                        return None
            except Exception as e:
                logger.error(f"AI Service error: {e}")
                return None
    
    async def analyze_target(self, target_url: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze target and provide attack recommendations"""
        system_prompt = """You are an expert penetration testing AI assistant.
Analyze the target and provide detailed attack recommendations in JSON format."""
        
        user_message = f"""Target: {target_url}
Scan Results: {json.dumps(scan_results, indent=2)}

Provide analysis in this JSON format:
{{
    "technology_stack": ["list of detected technologies"],
    "attack_surface": ["list of attack vectors"],
    "recommended_attacks": ["list of recommended attack types"],
    "priority_targets": ["list of high-value targets"],
    "estimated_difficulty": "low/medium/high",
    "recommended_approach": "description of attack strategy"
}}"""
        
        messages = [{"role": "user", "content": user_message}]
        response = await self.chat(messages, system_prompt)
        
        if response:
            try:
                # Extract JSON from response
                start = response.find("{")
                end = response.rfind("}") + 1
                if start >= 0 and end > start:
                    json_str = response[start:end]
                    return json.loads(json_str)
            except Exception as e:
                logger.error(f"Failed to parse AI response: {e}")
        
        return {
            "technology_stack": [],
            "attack_surface": [],
            "recommended_attacks": [],
            "priority_targets": [],
            "estimated_difficulty": "unknown",
            "recommended_approach": "Standard automated approach"
        }
    
    async def generate_payload(
        self,
        vulnerability_type: str,
        target_info: Dict[str, Any]
    ) -> List[str]:
        """Generate attack payloads for specific vulnerability"""
        system_prompt = """You are an expert exploit developer.
Generate effective attack payloads for the given vulnerability type."""
        
        user_message = f"""Vulnerability Type: {vulnerability_type}
Target Info: {json.dumps(target_info, indent=2)}

Generate 5-10 attack payloads that are most likely to succeed.
Return ONLY the payloads, one per line, no explanations."""
        
        messages = [{"role": "user", "content": user_message}]
        response = await self.chat(messages, system_prompt)
        
        if response:
            payloads = [line.strip() for line in response.split("\n") if line.strip()]
            return [p for p in payloads if p and not p.startswith("#")]
        
        return []
    
    async def analyze_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        target_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze vulnerability and provide exploitation guidance"""
        system_prompt = """You are an expert vulnerability analyst.
Analyze the vulnerability and provide detailed exploitation guidance."""
        
        user_message = f"""Vulnerability: {json.dumps(vulnerability, indent=2)}
Target Context: {json.dumps(target_context, indent=2)}

Provide analysis in JSON format:
{{
    "exploitability": "low/medium/high/critical",
    "attack_complexity": "low/medium/high",
    "recommended_tools": ["list of tools"],
    "exploitation_steps": ["step-by-step guide"],
    "success_probability": "percentage",
    "potential_impact": "description"
}}"""
        
        messages = [{"role": "user", "content": user_message}]
        response = await self.chat(messages, system_prompt)
        
        if response:
            try:
                start = response.find("{")
                end = response.rfind("}") + 1
                if start >= 0 and end > start:
                    json_str = response[start:end]
                    return json.loads(json_str)
            except Exception as e:
                logger.error(f"Failed to parse AI response: {e}")
        
        return {
            "exploitability": "unknown",
            "attack_complexity": "unknown",
            "recommended_tools": [],
            "exploitation_steps": [],
            "success_probability": "0%",
            "potential_impact": "Unknown"
        }
    
    async def plan_attack_strategy(
        self,
        target_url: str,
        attack_mode: str,
        discovered_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Plan comprehensive attack strategy"""
        system_prompt = """You are an expert attack strategist.
Create a detailed attack plan based on the discovered information."""
        
        user_message = f"""Target: {target_url}
Attack Mode: {attack_mode}
Discovered Info: {json.dumps(discovered_info, indent=2)}

Create attack plan in JSON format:
{{
    "phases": [
        {{
            "name": "phase name",
            "objectives": ["list of objectives"],
            "techniques": ["list of techniques"],
            "tools": ["list of tools"],
            "estimated_duration": "duration"
        }}
    ],
    "critical_paths": ["list of critical attack paths"],
    "fallback_strategies": ["list of alternative approaches"],
    "success_criteria": ["list of success indicators"]
}}"""
        
        messages = [{"role": "user", "content": user_message}]
        response = await self.chat(messages, system_prompt)
        
        if response:
            try:
                start = response.find("{")
                end = response.rfind("}") + 1
                if start >= 0 and end > start:
                    json_str = response[start:end]
                    return json.loads(json_str)
            except Exception as e:
                logger.error(f"Failed to parse AI response: {e}")
        
        return {
            "phases": [],
            "critical_paths": [],
            "fallback_strategies": [],
            "success_criteria": []
        }
    
    async def optimize_attack(
        self,
        current_results: Dict[str, Any],
        remaining_targets: List[str]
    ) -> Dict[str, Any]:
        """Optimize attack based on current results"""
        system_prompt = """You are an expert attack optimizer.
Analyze current results and optimize the attack strategy."""
        
        user_message = f"""Current Results: {json.dumps(current_results, indent=2)}
Remaining Targets: {json.dumps(remaining_targets, indent=2)}

Provide optimization recommendations in JSON format:
{{
    "continue_current_approach": true/false,
    "recommended_changes": ["list of recommended changes"],
    "priority_targets": ["reordered target list"],
    "new_techniques": ["list of new techniques to try"],
    "abandon_techniques": ["list of techniques to abandon"]
}}"""
        
        messages = [{"role": "user", "content": user_message}]
        response = await self.chat(messages, system_prompt)
        
        if response:
            try:
                start = response.find("{")
                end = response.rfind("}") + 1
                if start >= 0 and end > start:
                    json_str = response[start:end]
                    return json.loads(json_str)
            except Exception as e:
                logger.error(f"Failed to parse AI response: {e}")
        
        return {
            "continue_current_approach": True,
            "recommended_changes": [],
            "priority_targets": remaining_targets,
            "new_techniques": [],
            "abandon_techniques": []
        }


# Global AI service instance
ai_service = AIService()


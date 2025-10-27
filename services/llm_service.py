"""
LLM Service - AI Integration using Vanchin API
Provides AI-powered analysis for security testing
"""

import os
import sys
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

from typing import List, Dict, Any, Optional
from core.vanchin_multi_client import vanchin_multi_client
from loguru import logger
import json


class LLMService:
    """AI-powered analysis service using Vanchin API"""
    
    def __init__(self):
        self.client = vanchin_multi_client
        logger.info("[LLMService] Initialized with Vanchin Multi-Client")
    
    async def analyze_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerability scan results using AI"""
        
        prompt = f"""
You are a cybersecurity expert analyzing vulnerability scan results.

Scan Results:
{json.dumps(scan_results, indent=2)}

Please provide:
1. Summary of findings
2. Risk assessment (Critical/High/Medium/Low)
3. Prioritized list of vulnerabilities to address
4. Recommended remediation steps
5. Overall security score (0-100)

Respond in JSON format:
{{
    "summary": "...",
    "risk_level": "...",
    "vulnerabilities": [
        {{
            "name": "...",
            "severity": "...",
            "description": "...",
            "remediation": "..."
        }}
    ],
    "recommendations": ["..."],
    "security_score": 0-100
}}
"""
        
        try:
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert specializing in vulnerability analysis."},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.chat(messages, temperature=0.3)
            
            # Try to parse JSON response
            try:
                # Extract JSON from response (may have markdown code blocks)
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                else:
                    json_str = response.strip()
                
                analysis = json.loads(json_str)
                return {
                    "success": True,
                    "analysis": analysis,
                    "raw_response": response
                }
            except json.JSONDecodeError:
                # Return raw response if JSON parsing fails
                return {
                    "success": True,
                    "analysis": {
                        "summary": response,
                        "risk_level": "unknown",
                        "vulnerabilities": [],
                        "recommendations": [],
                        "security_score": 0
                    },
                    "raw_response": response
                }
        
        except Exception as e:
            logger.error(f"[LLMService] Error analyzing scan results: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def optimize_attack_strategy(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate optimized attack strategy using AI"""
        
        prompt = f"""
You are a penetration testing expert planning an attack strategy.

Target Information:
{json.dumps(target_info, indent=2)}

Please provide an optimized attack strategy including:
1. Reconnaissance approach
2. Priority targets and attack vectors
3. Recommended tools and techniques
4. Timing and stealth considerations
5. Expected success rate

Respond in JSON format:
{{
    "strategy": "...",
    "phases": [
        {{
            "name": "...",
            "description": "...",
            "tools": ["..."],
            "duration_estimate": "..."
        }}
    ],
    "attack_vectors": [
        {{
            "vector": "...",
            "priority": "high/medium/low",
            "success_probability": 0-100
        }}
    ],
    "recommendations": ["..."]
}}
"""
        
        try:
            messages = [
                {"role": "system", "content": "You are a penetration testing expert with deep knowledge of attack methodologies."},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.chat(messages, temperature=0.5)
            
            # Parse JSON response
            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                else:
                    json_str = response.strip()
                
                strategy = json.loads(json_str)
                return {
                    "success": True,
                    "strategy": strategy,
                    "raw_response": response
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "strategy": {
                        "strategy": response,
                        "phases": [],
                        "attack_vectors": [],
                        "recommendations": []
                    },
                    "raw_response": response
                }
        
        except Exception as e:
            logger.error(f"[LLMService] Error optimizing attack strategy: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def analyze_exploit_code(self, code: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze exploit code and suggest improvements"""
        
        prompt = f"""
You are a security researcher analyzing exploit code.

Exploit Code:
```
{code}
```

Target Information:
{json.dumps(target_info, indent=2)}

Please analyze:
1. Code effectiveness and reliability
2. Potential issues or bugs
3. Suggested improvements
4. Success probability
5. Detection risk

Respond in JSON format:
{{
    "effectiveness": "high/medium/low",
    "issues": ["..."],
    "improvements": ["..."],
    "success_probability": 0-100,
    "detection_risk": "high/medium/low",
    "recommendations": ["..."]
}}
"""
        
        try:
            messages = [
                {"role": "system", "content": "You are a security researcher specializing in exploit development."},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.chat(messages, temperature=0.3)
            
            # Parse JSON response
            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0].strip()
                else:
                    json_str = response.strip()
                
                analysis = json.loads(json_str)
                return {
                    "success": True,
                    "analysis": analysis,
                    "raw_response": response
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "analysis": {
                        "effectiveness": "unknown",
                        "issues": [],
                        "improvements": [],
                        "success_probability": 0,
                        "detection_risk": "unknown",
                        "recommendations": []
                    },
                    "raw_response": response
                }
        
        except Exception as e:
            logger.error(f"[LLMService] Error analyzing exploit code: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def generate_report(self, campaign_data: Dict[str, Any]) -> str:
        """Generate comprehensive security report"""
        
        prompt = f"""
You are a security consultant writing a professional penetration testing report.

Campaign Data:
{json.dumps(campaign_data, indent=2)}

Please generate a comprehensive report including:
1. Executive Summary
2. Methodology
3. Findings (organized by severity)
4. Detailed vulnerability descriptions
5. Remediation recommendations
6. Conclusion

Format the report in Markdown.
"""
        
        try:
            messages = [
                {"role": "system", "content": "You are a professional security consultant writing penetration testing reports."},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.chat(messages, temperature=0.4, max_tokens=4000)
            
            return {
                "success": True,
                "report": response
            }
        
        except Exception as e:
            logger.error(f"[LLMService] Error generating report: {e}")
            return {
                "success": False,
                "error": str(e)
            }


# Singleton instance
llm_service = LLMService()


# Example usage
async def main():
    service = LLMService()
    
    # Test scan analysis
    scan_results = {
        "target": "https://example.com",
        "open_ports": [80, 443, 22],
        "vulnerabilities": [
            {
                "type": "exposed_file",
                "severity": "medium",
                "path": "/.git/config"
            }
        ]
    }
    
    print("Analyzing scan results...")
    analysis = await service.analyze_scan_results(scan_results)
    print(json.dumps(analysis, indent=2))


if __name__ == '__main__':
    import asyncio
    asyncio.run(main())


#!/usr/bin/env python3
"""
AI Integration for dLNk dLNk Framework
Integrates LLM capabilities into the framework
"""
from datetime import datetime

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from core.llm_provider import VanchinProvider, OllamaProvider
from loguru import logger


@dataclass
class AITask:
    """AI task definition"""
    task_id: str
    task_type: str  # recon, vuln_analysis, exploit, post_exploit, report
    input_data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


@dataclass
class AIResult:
    """AI task result"""
    task_id: str
    success: bool
    content: str
    confidence: float
    recommendations: List[str]
    warnings: List[str]
    error: Optional[str] = None


class AIOrchestrator:
    """
    AI Orchestrator for dLNk dLNk Framework
    Manages AI-powered decision making and planning
    """
    
    def __init__(self, model: str = None, api_key: Optional[str] = None):
        """Initialize AI Orchestrator"""
        self.provider_type = os.getenv("LLM_PROVIDER", "vanchin")
        self.model = model

        if self.provider_type == "vanchin":
            # Use Vanchin provider
            vanchin_api_url = os.getenv("VANCHIN_API_URL")
            vanchin_model = os.getenv("VANCHIN_MODEL")
            vanchin_api_keys = os.getenv("VANCHIN_API_KEYS")

            if vanchin_api_keys:
                self.provider = VanchinProvider(
                    logger=logger,
                    knowledge_base_path="knowledge_base.json",
                    api_url=vanchin_api_url,
                    model=vanchin_model,
                    api_keys=vanchin_api_keys
                )
            else:
                logger.warning("Vanchin API keys not configured, falling back to local model")
                self.provider_type = "ollama"
                self.provider = OllamaProvider(
                    logger=logger,
                    knowledge_base_path="knowledge_base.json"
                )
        else:
            # Use Ollama provider
            self.provider = OllamaProvider(
                logger=logger,
                knowledge_base_path="knowledge_base.json"
            )

        self.task_history: List[AITask] = []
        self.result_history: List[AIResult] = []
        
    def get_system_prompt(self, task_type: str) -> str:
        """Get optimized system prompt for task type"""
        
        base = """คุณเป็น AI ผู้เชี่ยวชาญด้าน Offensive Security สำหรับ dLNk dLNk Framework
คุณมีความรู้ลึกซึ้งเกี่ยวกับ MITRE ATT&CK®, OWASP, และเทคนิคการโจมตีทุกประเภท

**หลักการตอบ:**
1. ตรงประเด็นและครอบคลุม
2. ใช้โครงสร้างชัดเจน
3. ให้ตัวอย่างที่ใช้ได้จริง
4. ระบุความเสี่ยง
"""
        
        prompts = {
            "recon": "\n**โครงสร้าง:** Phase 1-3, Tools, Commands, Expected Results",
            "vuln_analysis": "\n**โครงสร้าง:** Type, Exploitation, Payloads, Mitigation",
            "exploit": "\n**โครงสร้าง:** Initial Access, Privilege Escalation, Persistence, Lateral Movement",
            "post_exploit": "\n**โครงสร้าง:** Privilege Escalation, Persistence, Lateral Movement, Exfiltration, Cleanup",
            "report": "\n**โครงสร้าง:** Executive Summary, Technical Details, Impact, Recommendations"
        }
        
        return base + prompts.get(task_type, "")
    
    async def execute_task(self, task: AITask) -> AIResult:
        """Execute AI task"""

        try:
            # Build prompt based on task type
            prompt = self._build_prompt(task)

            # Call LLM with timeout
            timeout = int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))
            logger.info(f"Executing AI task {task.task_id} with timeout={timeout}s")

            messages = [
                {"role": "system", "content": self.get_system_prompt(task.task_type)},
                {"role": "user", "content": prompt}
            ]

            # Call LLM through provider
            content = await self.provider._call_vanchin_api(messages, max_tokens=2500, temperature=0.7)

            logger.success(f"AI task {task.task_id} completed successfully")
            
            # Extract metadata
            recommendations = self._extract_recommendations(content)
            warnings = self._extract_warnings(content)
            confidence = self._calculate_confidence(content, task)
            
            result = AIResult(
                task_id=task.task_id,
                success=True,
                content=content,
                confidence=confidence,
                recommendations=recommendations,
                warnings=warnings
            )
            
        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            logger.error(f"AI task {task.task_id} failed: {error_type}: {error_msg}")
            
            result = AIResult(
                task_id=task.task_id,
                success=False,
                content="",
                confidence=0.0,
                recommendations=[],
                warnings=[f"Task failed: {error_type}"],
                error=f"{error_type}: {error_msg}"
            )
        
        # Store history
        self.task_history.append(task)
        self.result_history.append(result)
        
        return result
    
    def _build_prompt(self, task: AITask) -> str:
        """Build prompt from task"""
        
        if task.task_type == "recon":
            return f"""วางแผน Reconnaissance สำหรับ:
Target: {task.input_data.get('target', 'Unknown')}
Type: {task.input_data.get('type', 'Unknown')}
Technology: {task.input_data.get('technology', 'Unknown')}

วางแผนอย่างละเอียดพร้อมคำสั่ง"""
            
        elif task.task_type == "vuln_analysis":
            return f"""วิเคราะห์ช่องโหว่:
Type: {task.input_data.get('vuln_type', 'Unknown')}
Location: {task.input_data.get('location', 'Unknown')}
Details: {task.input_data.get('details', 'N/A')}

วิเคราะห์และแนะนำการ exploit"""
            
        elif task.task_type == "exploit":
            return f"""สร้างกลยุทธ์การโจมตี:
Target: {task.input_data.get('target', 'Unknown')}
Vulnerabilities: {', '.join(task.input_data.get('vulnerabilities', []))}
Goal: {task.input_data.get('goal', 'Full compromise')}

สร้างแผนการโจมตีแบบครบวงจร"""
            
        elif task.input_type == "post_exploit":
            return f"""วางแผน Post-Exploitation:
Access Level: {task.input_data.get('access_level', 'User')}
System: {task.input_data.get('system', 'Unknown')}
Goals: {', '.join(task.input_data.get('goals', []))}

วางแผนอย่างละเอียด"""
            
        elif task.task_type == "report":
            findings = task.input_data.get('findings', [])
            findings_text = '\n'.join([f"- {f}" for f in findings])
            return f"""สร้างรายงาน Penetration Testing:

Findings:
{findings_text}

สร้างรายงานที่สมบูรณ์"""
            
        return json.dumps(task.input_data, ensure_ascii=False)
    
    def _extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations"""
        recommendations = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            if 'แนะนำ' in line or 'recommendation' in line.lower():
                # Get next few lines that start with -
                for j in range(i+1, min(i+6, len(lines))):
                    if lines[j].strip().startswith('-'):
                        recommendations.append(lines[j].strip()[1:].strip())
        
        return recommendations[:5]
    
    def _extract_warnings(self, content: str) -> List[str]:
        """Extract warnings"""
        warnings = []
        lines = content.split('\n')
        
        for line in lines:
            if 'ระวัง' in line or 'warning' in line.lower() or 'caution' in line.lower():
                warnings.append(line.strip())
        
        return warnings[:3]
    
    def _calculate_confidence(self, content: str, task: AITask) -> float:
        """Calculate confidence score"""
        # Simple heuristic
        score = 0.7  # Base score
        
        # Bonus for length
        if len(content) > 500:
            score += 0.1
        
        # Bonus for structure
        if '##' in content or '###' in content:
            score += 0.1
        
        # Bonus for examples
        if '```' in content or 'ตัวอย่าง' in content:
            score += 0.1
        
        return min(score, 1.0)
    
    def plan_attack_workflow(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Plan complete attack workflow using AI"""
        
        # Phase 1: Reconnaissance
        recon_task = AITask(
            task_id="recon_001",
            task_type="recon",
            input_data=target_info
        )
        recon_result = self.execute_task(recon_task)
        
        # Phase 2: Vulnerability Analysis (simulated)
        vuln_task = AITask(
            task_id="vuln_001",
            task_type="vuln_analysis",
            input_data={
                "vuln_type": "SQL Injection",
                "location": "/api/users",
                "details": "Found in user_id parameter"
            }
        )
        vuln_result = self.execute_task(vuln_task)
        
        # Phase 3: Exploit Strategy
        exploit_task = AITask(
            task_id="exploit_001",
            task_type="exploit",
            input_data={
                "target": target_info.get('target', 'Unknown'),
                "vulnerabilities": ["SQL Injection", "XSS"],
                "goal": "Database access"
            }
        )
        exploit_result = self.execute_task(exploit_task)
        
        return {
            "phases": [
                {"name": "Reconnaissance", "result": asdict(recon_result)},
                {"name": "Vulnerability Analysis", "result": asdict(vuln_result)},
                {"name": "Exploitation", "result": asdict(exploit_result)}
            ],
            "overall_confidence": sum([r.confidence for r in [recon_result, vuln_result, exploit_result]]) / 3
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get AI usage statistics"""
        
        total_tasks = len(self.task_history)
        successful = sum(1 for r in self.result_history if r.success)
        
        avg_confidence = sum(r.confidence for r in self.result_history) / total_tasks if total_tasks > 0 else 0
        
        by_type = {}
        for task in self.task_history:
            if task.task_type not in by_type:
                by_type[task.task_type] = 0
            by_type[task.task_type] += 1
        
        return {
            "total_tasks": total_tasks,
            "successful": successful,
            "failed": total_tasks - successful,
            "avg_confidence": avg_confidence,
            "by_type": by_type
        }


# Example usage
if __name__ == "__main__":
    # Initialize AI Orchestrator
    ai = AIOrchestrator()
    
    # Example: Plan attack workflow
    target = {
        "target": "http://localhost:8000",
        "type": "Web Application",
        "technology": "PHP + MySQL"
    }
    
    print("Planning attack workflow...")
    workflow = ai.plan_attack_workflow(target)
    
    print(f"\nWorkflow planned with {len(workflow['phases'])} phases")
    print(f"Overall confidence: {workflow['overall_confidence']:.2%}")
    
    for phase in workflow['phases']:
        print(f"\n{phase['name']}:")
        print(f"  Success: {phase['result']['success']}")
        print(f"  Confidence: {phase['result']['confidence']:.2%}")
        print(f"  Recommendations: {len(phase['result']['recommendations'])}")
    
    # Statistics
    stats = ai.get_statistics()
    print(f"\nStatistics:")
    print(f"  Total tasks: {stats['total_tasks']}")
    print(f"  Success rate: {stats['successful']}/{stats['total_tasks']}")
    print(f"  Avg confidence: {stats['avg_confidence']:.2%}")




class AIIntegration:
    """
    AI Integration Class - ครอบคลุมการใช้ AI ทั้งหมด
    
    Features:
    - Attack planning
    - Vulnerability analysis
    - Exploit generation
    - Report generation
    - Learning from results
    """
    
    def __init__(self, model: str = "gpt-4.1-mini", api_key: Optional[str] = None):
        """Initialize AI Integration"""
        self.orchestrator = AIOrchestrator(model, api_key)
        self.attack_history = []
        self.learning_data = []
        
    async def analyze_target(self, target: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        วิเคราะห์ target ด้วย AI
        
        Args:
            target: target URL/IP
            context: ข้อมูลเพิ่มเติม
        """
        logger.info(f"[AIIntegration] Analyzing target: {target}")
        
        task = AITask(
            task_id=f"analyze_{len(self.attack_history)}",
            task_type="recon",
            input_data={
                "target": target,
                "type": context.get("type", "Unknown") if context else "Unknown",
                "technology": context.get("technology", "Unknown") if context else "Unknown"
            },
            context=context
        )
        
        result = await self.orchestrator.execute_task(task)
        
        return {
            "success": result.success,
            "analysis": result.content,
            "confidence": result.confidence,
            "recommendations": result.recommendations,
            "warnings": result.warnings
        }
    
    async def suggest_attack_vector(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        แนะนำ attack vector ที่เหมาะสม
        
        Args:
            vulnerabilities: รายการช่องโหว่ที่พบ
            target_info: ข้อมูล target
        """
        logger.info(f"[AIIntegration] Suggesting attack vectors for {len(vulnerabilities)} vulnerabilities")
        
        vuln_list = [v.get("type", "Unknown") for v in vulnerabilities]
        
        task = AITask(
            task_id=f"attack_vector_{len(self.attack_history)}",
            task_type="exploit",
            input_data={
                "target": target_info.get("target", "Unknown"),
                "vulnerabilities": vuln_list,
                "goal": target_info.get("goal", "Full compromise")
            }
        )
        
        result = await self.orchestrator.execute_task(task)
        
        return {
            "success": result.success,
            "attack_plan": result.content,
            "confidence": result.confidence,
            "recommendations": result.recommendations,
            "warnings": result.warnings
        }
    
    async def generate_exploit_code(
        self,
        vulnerability: Dict[str, Any],
        target: str
    ) -> Dict[str, Any]:
        """
        สร้าง exploit code ด้วย AI
        
        Args:
            vulnerability: ข้อมูลช่องโหว่
            target: target URL/IP
        """
        logger.info(f"[AIIntegration] Generating exploit for {vulnerability.get('type', 'Unknown')}")
        
        task = AITask(
            task_id=f"exploit_gen_{len(self.attack_history)}",
            task_type="exploit",
            input_data={
                "target": target,
                "vuln_type": vulnerability.get("type", "Unknown"),
                "location": vulnerability.get("location", "Unknown"),
                "details": vulnerability.get("details", "N/A")
            }
        )
        
        result = await self.orchestrator.execute_task(task)
        
        return {
            "success": result.success,
            "exploit_code": result.content,
            "confidence": result.confidence,
            "recommendations": result.recommendations,
            "warnings": result.warnings
        }
    
    async def analyze_response(
        self,
        response: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        วิเคราะห์ response จาก target
        
        Args:
            response: HTTP response หรือ output
            context: ข้อมูลบริบท
        """
        logger.info(f"[AIIntegration] Analyzing response")
        
        task = AITask(
            task_id=f"response_analysis_{len(self.attack_history)}",
            task_type="vuln_analysis",
            input_data={
                "response": response[:1000],  # Limit size
                "context": context
            }
        )
        
        result = await self.orchestrator.execute_task(task)
        
        return {
            "success": result.success,
            "analysis": result.content,
            "confidence": result.confidence,
            "findings": result.recommendations,
            "warnings": result.warnings
        }
    
    async def generate_report(
        self,
        findings: List[Dict[str, Any]],
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        สร้างรายงานด้วย AI
        
        Args:
            findings: รายการช่องโหว่ที่พบ
            target_info: ข้อมูล target
        """
        logger.info(f"[AIIntegration] Generating report for {len(findings)} findings")
        
        findings_text = [
            f"{f.get('type', 'Unknown')} at {f.get('location', 'Unknown')}"
            for f in findings
        ]
        
        task = AITask(
            task_id=f"report_{len(self.attack_history)}",
            task_type="report",
            input_data={
                "target": target_info.get("target", "Unknown"),
                "findings": findings_text,
                "severity": target_info.get("severity", "Medium")
            }
        )
        
        result = await self.orchestrator.execute_task(task)
        
        return {
            "success": result.success,
            "report": result.content,
            "confidence": result.confidence,
            "recommendations": result.recommendations
        }
    
    async def learn_from_attack(
        self,
        attack_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        เรียนรู้จากผลการโจมตี
        
        Args:
            attack_data: ข้อมูลการโจมตี
        """
        logger.info(f"[AIIntegration] Learning from attack")
        
        # บันทึกข้อมูล
        self.learning_data.append({
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_data.get("type", "Unknown"),
            "success": attack_data.get("success", False),
            "target": attack_data.get("target", "Unknown"),
            "techniques": attack_data.get("techniques", []),
            "results": attack_data.get("results", {})
        })
        
        # วิเคราะห์ pattern
        successful_attacks = [a for a in self.learning_data if a["success"]]
        
        return {
            "total_attacks": len(self.learning_data),
            "successful_attacks": len(successful_attacks),
            "success_rate": len(successful_attacks) / len(self.learning_data) if self.learning_data else 0,
            "learned_patterns": len(set([a["attack_type"] for a in successful_attacks]))
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """ดึงสถิติการใช้งาน AI"""
        orchestrator_stats = self.orchestrator.get_statistics()
        
        return {
            **orchestrator_stats,
            "attack_history": len(self.attack_history),
            "learning_data": len(self.learning_data)
        }
    
    def export_learning_data(self, filepath: str):
        """Export learning data ออกเป็นไฟล์"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.learning_data, f, indent=2, ensure_ascii=False)
            logger.success(f"[AIIntegration] Learning data exported to {filepath}")
        except Exception as e:
            logger.error(f"[AIIntegration] Export failed: {e}")


# Singleton instance
ai_integration = AIIntegration()


# Helper functions
async def analyze_target(target: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """Analyze target wrapper"""
    return await ai_integration.analyze_target(target, context)


async def suggest_attack_vector(
    vulnerabilities: List[Dict[str, Any]],
    target_info: Dict[str, Any]
) -> Dict[str, Any]:
    """Suggest attack vector wrapper"""
    return await ai_integration.suggest_attack_vector(vulnerabilities, target_info)


async def generate_exploit_code(
    vulnerability: Dict[str, Any],
    target: str
) -> Dict[str, Any]:
    """Generate exploit code wrapper"""
    return await ai_integration.generate_exploit_code(vulnerability, target)


async def generate_report(
    findings: List[Dict[str, Any]],
    target_info: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate report wrapper"""
    return await ai_integration.generate_report(findings, target_info)


class AIIntegration:
    """
    AI Integration Class - ครอบคลุมการใช้ AI ทั้งหมด

    Features:
    - Attack planning
    - Vulnerability analysis
    - Exploit generation
    - Report generation
    - Learning from results
    """

    def __init__(self, model: str = "gpt-4.1-mini", api_key: Optional[str] = None):
        """Initialize AI Integration"""
        self.orchestrator = AIOrchestrator(model, api_key)
        self.attack_history = []
        self.learning_data = []

    def get_model_status(self) -> Dict[str, Any]:
        """
        Get current model status and capabilities
        """
        try:
            # Get model info from orchestrator
            model_info = {
                "model": self.orchestrator.model,
                "status": "ready",
                "capabilities": [
                    "target_analysis",
                    "vulnerability_identification",
                    "attack_planning",
                    "exploit_generation",
                    "report_generation",
                    "learning_from_results"
                ],
                "provider": "OpenAI" if hasattr(self.orchestrator.client, 'api_key') else "Unknown"
            }

            return model_info

        except Exception as e:
            return {
                "model": "unknown",
                "status": "error",
                "capabilities": [],
                "error": str(e),
                "provider": "Unknown"
            }


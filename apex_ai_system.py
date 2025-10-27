#!/usr/bin/env python3
"""
dLNk dLNk AI System - Production-Ready
Improved prompts, validation, and response handling
"""

import os
import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from openai import OpenAI

client = OpenAI()


@dataclass
class AIRequest:
    """AI request with context"""
    task_type: str  # recon, vuln_analysis, exploit, post_exploit, report
    target_info: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None
    

@dataclass
class AIResponse:
    """AI response with metadata"""
    content: str
    confidence: float
    reasoning: str
    recommendations: List[str]
    warnings: List[str]


class dLNkAISystem:
    """Production-ready AI system for dLNk dLNk Framework"""
    
    def __init__(self, model: str = "gpt-4.1-mini"):
        self.model = model
        self.client = client
        
    def get_system_prompt(self, task_type: str) -> str:
        """Get optimized system prompt for each task type"""
        
        base_prompt = """คุณเป็น AI ผู้เชี่ยวชาญด้าน Offensive Security และ Penetration Testing ระดับสูง
คุณมีความรู้ลึกซึ้งเกี่ยวกับ:
- MITRE ATT&CK® Framework
- OWASP Top 10 และ API Security
- Advanced Exploitation Techniques
- Evasion และ Anti-Forensics
- Cloud Security (AWS, Azure, GCP)
- Network Penetration Testing
- Database Security

**หลักการตอบคำถาม:**
1. ตอบตรงประเด็นและครอบคลุม
2. ใช้โครงสร้างที่ชัดเจนตามที่กำหนด
3. ให้ตัวอย่างคำสั่งหรือ code ที่ใช้ได้จริง
4. ระบุความเสี่ยงและข้อควรระวัง
5. ใช้ภาษาไทยผสมศัพท์เทคนิคภาษาอังกฤษ
"""
        
        task_prompts = {
            "recon": """
**สำหรับ Reconnaissance:**
ตอบตามโครงสร้างนี้:
1. **Phase 1: Information Gathering** - เครื่องมือและคำสั่ง
2. **Phase 2: Network Enumeration** - port scanning, service detection
3. **Phase 3: Vulnerability Identification** - vulnerability scanners
4. **Expected Results** - ผลลัพธ์ที่คาดหวังและการวิเคราะห์
""",
            
            "vuln_analysis": """
**สำหรับ Vulnerability Analysis:**
ตอบตามโครงสร้างนี้:
1. **Vulnerability Type** - ประเภทและรายละเอียดช่องโหว่
2. **Exploitation Method** - วิธีการ exploit แบบละเอียด
3. **Payloads** - payload ตัวอย่างที่ใช้ได้จริง
4. **Mitigation** - วิธีป้องกันและแก้ไข
""",
            
            "exploit": """
**สำหรับ Exploit Strategy:**
ตอบตามโครงสร้างนี้:
1. **Initial Access** - วิธีการเข้าถึงเป้าหมายครั้งแรก
2. **Privilege Escalation** - การยกระดับสิทธิ์
3. **Persistence** - การสร้างช่องทางกลับเข้ามาถาวร
4. **Lateral Movement** - การเคลื่อนย้ายในระบบ
""",
            
            "post_exploit": """
**สำหรับ Post-Exploitation:**
ตอบตามโครงสร้างนี้:
1. **Privilege Escalation** - ขั้นตอนยกระดับสิทธิ์
2. **Persistence** - วิธีสร้าง backdoor
3. **Lateral Movement** - การเคลื่อนย้ายไปยังระบบอื่น
4. **Data Exfiltration** - การขโมยข้อมูล
5. **Cleanup** - การลบร่องรอย
""",
            
            "report": """
**สำหรับ Report Generation:**
ตอบตามโครงสร้างนี้:
1. **Executive Summary** - สรุปสำหรับผู้บริหาร
2. **Technical Details** - รายละเอียดทางเทคนิค
3. **Impact Assessment** - ผลกระทบและความเสี่ยง
4. **Recommendations** - คำแนะนำการแก้ไข
"""
        }
        
        return base_prompt + task_prompts.get(task_type, "")
    
    def plan_reconnaissance(self, target_info: Dict[str, Any]) -> AIResponse:
        """Plan reconnaissance for target"""
        
        prompt = f"""วางแผนการ Reconnaissance สำหรับเป้าหมายต่อไปนี้:

**Target Information:**
- URL/IP: {target_info.get('url', 'N/A')}
- Technology: {target_info.get('technology', 'Unknown')}
- Type: {target_info.get('type', 'Web Application')}

วางแผนอย่างละเอียดครอบคลุมทุกขั้นตอน พร้อมคำสั่งที่ใช้ได้จริง
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.get_system_prompt("recon")},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        ,
                timeout=120)
        
        content = response.choices[0].message.content
        
        return AIResponse(
            content=content,
            confidence=0.9,
            reasoning="Comprehensive reconnaissance plan based on target technology",
            recommendations=self.extract_recommendations(content),
            warnings=self.extract_warnings(content)
        )
    
    def analyze_vulnerability(self, vuln_info: Dict[str, Any]) -> AIResponse:
        """Analyze vulnerability and suggest exploitation"""
        
        prompt = f"""วิเคราะห์ช่องโหว่ต่อไปนี้และแนะนำวิธีการ exploit:

**Vulnerability Information:**
- Type: {vuln_info.get('type', 'Unknown')}
- Location: {vuln_info.get('location', 'N/A')}
- Parameter: {vuln_info.get('parameter', 'N/A')}
- Context: {vuln_info.get('context', 'N/A')}

วิเคราะห์อย่างละเอียดและให้ payload ที่ใช้ได้จริง
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.get_system_prompt("vuln_analysis")},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        ,
                timeout=120)
        
        content = response.choices[0].message.content
        
        return AIResponse(
            content=content,
            confidence=0.85,
            reasoning="Detailed vulnerability analysis with exploitation methods",
            recommendations=self.extract_recommendations(content),
            warnings=self.extract_warnings(content)
        )
    
    def create_exploit_strategy(self, target_info: Dict[str, Any], context: Dict[str, Any]) -> AIResponse:
        """Create comprehensive exploit strategy"""
        
        prompt = f"""สร้างกลยุทธ์การโจมตีแบบครบวงจรสำหรับ:

**Target:**
- Type: {target_info.get('type', 'Unknown')}
- Technology: {target_info.get('technology', 'Unknown')}
- Known Vulnerabilities: {', '.join(target_info.get('vulnerabilities', []))}

**Context:**
- Current Access: {context.get('access_level', 'None')}
- Goal: {context.get('goal', 'Full compromise')}

สร้างแผนการโจมตีที่ละเอียดและเป็นขั้นตอน
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.get_system_prompt("exploit")},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2500
        ,
                timeout=120)
        
        content = response.choices[0].message.content
        
        return AIResponse(
            content=content,
            confidence=0.88,
            reasoning="Multi-stage exploit strategy based on MITRE ATT&CK",
            recommendations=self.extract_recommendations(content),
            warnings=self.extract_warnings(content)
        )
    
    def plan_post_exploitation(self, context: Dict[str, Any]) -> AIResponse:
        """Plan post-exploitation activities"""
        
        prompt = f"""วางแผนการดำเนินการหลังจากได้ access แล้ว:

**Current Status:**
- Access Level: {context.get('access_level', 'User')}
- System: {context.get('system', 'Unknown')}
- Shell Type: {context.get('shell_type', 'Unknown')}

**Goals:**
- {', '.join(context.get('goals', ['Privilege Escalation', 'Persistence', 'Data Exfiltration']))}

วางแผนอย่างละเอียดพร้อมคำสั่งที่ใช้ได้จริง
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.get_system_prompt("post_exploit")},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=2000
        ,
                timeout=120)
        
        content = response.choices[0].message.content
        
        return AIResponse(
            content=content,
            confidence=0.87,
            reasoning="Comprehensive post-exploitation plan",
            recommendations=self.extract_recommendations(content),
            warnings=self.extract_warnings(content)
        )
    
    def generate_report(self, findings: List[Dict[str, Any]]) -> AIResponse:
        """Generate penetration testing report"""
        
        findings_text = "\n".join([
            f"- {f.get('title', 'Unknown')}: {f.get('severity', 'Unknown')} severity"
            for f in findings
        ])
        
        prompt = f"""สร้างรายงานการทดสอบเจาะระบบสำหรับช่องโหว่ที่พบ:

**Findings:**
{findings_text}

**Report Requirements:**
- Executive Summary สำหรับผู้บริหาร
- Technical Details สำหรับทีมเทคนิค
- Impact Assessment
- Remediation Recommendations

สร้างรายงานที่สมบูรณ์และเป็นมืออาชีพ
"""
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": self.get_system_prompt("report")},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=3000
        ,
                timeout=120)
        
        content = response.choices[0].message.content
        
        return AIResponse(
            content=content,
            confidence=0.92,
            reasoning="Professional penetration testing report",
            recommendations=self.extract_recommendations(content),
            warnings=[]
        )
    
    def extract_recommendations(self, content: str) -> List[str]:
        """Extract recommendations from AI response"""
        recommendations = []
        
        # Simple extraction based on common patterns
        lines = content.split('\n')
        in_recommendations = False
        
        for line in lines:
            if 'แนะนำ' in line or 'recommendation' in line.lower() or 'mitigation' in line.lower():
                in_recommendations = True
                continue
            
            if in_recommendations and line.strip().startswith('-'):
                recommendations.append(line.strip()[1:].strip())
        
        return recommendations[:5]  # Top 5
    
    def extract_warnings(self, content: str) -> List[str]:
        """Extract warnings from AI response"""
        warnings = []
        
        lines = content.split('\n')
        for line in lines:
            if 'ระวัง' in line or 'warning' in line.lower() or 'caution' in line.lower():
                warnings.append(line.strip())
        
        return warnings[:3]  # Top 3


def demo():
    """Demo the improved AI system"""
    
    print("="*80)
    print("dLNk DLNK AI SYSTEM - DEMO")
    print("="*80)
    
    ai = dLNkAISystem()
    
    # Test 1: Reconnaissance Planning
    print("\n" + "="*80)
    print("TEST 1: Reconnaissance Planning")
    print("="*80)
    
    target = {
        'url': 'https://example-ecommerce.com',
        'technology': 'PHP + MySQL',
        'type': 'E-commerce Website'
    }
    
    response = ai.plan_reconnaissance(target)
    print(f"\nResponse:\n{response.content[:500]}...")
    print(f"\nConfidence: {response.confidence:.2%}")
    print(f"Recommendations: {len(response.recommendations)}")
    
    # Test 2: Vulnerability Analysis
    print("\n" + "="*80)
    print("TEST 2: Vulnerability Analysis")
    print("="*80)
    
    vuln = {
        'type': 'SQL Injection',
        'location': '/product.php',
        'parameter': 'id',
        'context': 'GET parameter, no input validation'
    }
    
    response = ai.analyze_vulnerability(vuln)
    print(f"\nResponse:\n{response.content[:500]}...")
    print(f"\nConfidence: {response.confidence:.2%}")
    print(f"Warnings: {len(response.warnings)}")
    
    # Test 3: Exploit Strategy
    print("\n" + "="*80)
    print("TEST 3: Exploit Strategy")
    print("="*80)
    
    target = {
        'type': 'Active Directory Domain Controller',
        'technology': 'Windows Server 2019 + Kerberos',
        'vulnerabilities': ['Kerberoasting', 'AS-REP Roasting']
    }
    
    context = {
        'access_level': 'Domain User',
        'goal': 'Domain Admin'
    }
    
    response = ai.create_exploit_strategy(target, context)
    print(f"\nResponse:\n{response.content[:500]}...")
    print(f"\nConfidence: {response.confidence:.2%}")
    
    print("\n" + "="*80)
    print("✅ DEMO COMPLETE")
    print("="*80)


if __name__ == "__main__":
    demo()


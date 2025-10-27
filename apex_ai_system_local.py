"""
dLNk dLNk AI System with Local LLM Support
Supports: OpenAI, Ollama (Mixtral), LM Studio, LocalAI
"""

import time
from openai import OpenAI
from llm_config import get_llm_config, print_config

class dLNkAISystem:
    """AI System for dLNk dLNk Framework with Local LLM Support"""
    
    def __init__(self):
        """Initialize AI system with configured LLM"""
        config = get_llm_config()
        
        self.client = OpenAI(
            base_url=config['base_url'],
            api_key=config['api_key'],
            timeout=config['timeout']
        )
        
        self.model = config['model']
        self.temperature = config['temperature']
        self.max_tokens = config['max_tokens']
        
        print("✅ dLNk dLNk AI System initialized")
        print_config()
        print()
    
    def generate_attack_plan(self, target_info: dict) -> dict:
        """Generate attack plan using LLM"""
        
        prompt = f"""คุณเป็น Offensive Security Expert ที่เชี่ยวชาญการโจมตีระบบ

เป้าหมาย:
- URL: {target_info.get('target', 'N/A')}
- ประเภท: {target_info.get('type', 'N/A')}
- เทคโนโลยี: {target_info.get('technology', 'N/A')}

วางแผนการโจมตีแบบครบวงจร 3 เฟส:

## Phase 1: Reconnaissance
- เครื่องมือที่ใช้
- คำสั่งที่รัน
- ข้อมูลที่ต้องหา

## Phase 2: Exploitation
- ช่องโหว่ที่น่าสนใจ
- วิธีการ exploit
- Payload ที่ใช้

## Phase 3: Post-Exploitation
- การยกระดับสิทธิ์
- การขโมยข้อมูล
- การซ่อนร่องรอย

ตอบเป็นภาษาไทย แบบละเอียด มีตัวอย่างคำสั่งจริง"""

        start_time = time.time()
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "คุณเป็น Offensive Security Expert ที่เชี่ยวชาญการโจมตีระบบ"},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            ,
                timeout=120)
            
            elapsed = time.time() - start_time
            content = response.choices[0].message.content
            
            return {
                "success": True,
                "content": content,
                "model": self.model,
                "response_time": elapsed,
                "tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model": self.model,
                "response_time": time.time() - start_time
            }
    
    def analyze_vulnerability(self, vuln_info: dict) -> dict:
        """Analyze vulnerability and suggest exploitation"""
        
        prompt = f"""วิเคราะห์ช่องโหว่และแนะนำวิธีการ exploit:

ช่องโหว่:
- ประเภท: {vuln_info.get('type', 'N/A')}
- รายละเอียด: {vuln_info.get('details', 'N/A')}
- Severity: {vuln_info.get('severity', 'N/A')}

วิเคราะห์:
1. ความรุนแรงและผลกระทบ
2. วิธีการ exploit ที่เป็นไปได้
3. Payload ตัวอย่าง
4. วิธีการป้องกัน

ตอบเป็นภาษาไทย แบบละเอียด"""

        start_time = time.time()
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "คุณเป็น Vulnerability Analysis Expert"},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            ,
                timeout=120)
            
            elapsed = time.time() - start_time
            content = response.choices[0].message.content
            
            return {
                "success": True,
                "content": content,
                "model": self.model,
                "response_time": elapsed,
                "tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model": self.model,
                "response_time": time.time() - start_time
            }
    
    def generate_report(self, findings: dict) -> dict:
        """Generate penetration testing report"""
        
        prompt = f"""สร้างรายงาน Penetration Testing จากผลการทดสอบ:

ผลการทดสอบ:
{findings}

สร้างรายงานที่ประกอบด้วย:
1. Executive Summary
2. ช่องโหว่ที่พบ (แยกตาม severity)
3. วิธีการ exploit
4. ผลกระทบ
5. คำแนะนำการแก้ไข

ตอบเป็นภาษาไทย รูปแบบ Markdown"""

        start_time = time.time()
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "คุณเป็น Security Report Writer Expert"},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            ,
                timeout=120)
            
            elapsed = time.time() - start_time
            content = response.choices[0].message.content
            
            return {
                "success": True,
                "content": content,
                "model": self.model,
                "response_time": elapsed,
                "tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model": self.model,
                "response_time": time.time() - start_time
            }


def demo():
    """Demo AI system with local LLM"""
    
    print("=" * 80)
    print("🦅 dLNk dLNk AI System - Local LLM Demo")
    print("=" * 80)
    print()
    
    # Initialize
    ai = dLNkAISystem()
    
    # Test 1: Attack Planning
    print("=" * 80)
    print("📋 Test 1: Attack Planning")
    print("=" * 80)
    print()
    
    target = {
        "target": "http://localhost:8000",
        "type": "Web Application",
        "technology": "PHP + MySQL"
    }
    
    print(f"🎯 Target: {target['target']}")
    print(f"📦 Type: {target['type']}")
    print(f"🔧 Tech: {target['technology']}")
    print()
    print("⏳ Generating attack plan...")
    print()
    
    result = ai.generate_attack_plan(target)
    
    if result['success']:
        print("✅ Attack plan generated!")
        print(f"⏱️  Response time: {result['response_time']:.2f}s")
        print(f"🎯 Model: {result['model']}")
        if result['tokens'] > 0:
            print(f"📊 Tokens: {result['tokens']}")
        print()
        print("-" * 80)
        print(result['content'])
        print("-" * 80)
    else:
        print(f"❌ Error: {result['error']}")
    
    print()
    
    # Test 2: Vulnerability Analysis
    print("=" * 80)
    print("🔍 Test 2: Vulnerability Analysis")
    print("=" * 80)
    print()
    
    vuln = {
        "type": "SQL Injection",
        "details": "Parameter 'id' in /user.php is vulnerable to SQL injection",
        "severity": "Critical"
    }
    
    print(f"🐛 Type: {vuln['type']}")
    print(f"📝 Details: {vuln['details']}")
    print(f"⚠️  Severity: {vuln['severity']}")
    print()
    print("⏳ Analyzing vulnerability...")
    print()
    
    result = ai.analyze_vulnerability(vuln)
    
    if result['success']:
        print("✅ Analysis complete!")
        print(f"⏱️  Response time: {result['response_time']:.2f}s")
        print(f"🎯 Model: {result['model']}")
        if result['tokens'] > 0:
            print(f"📊 Tokens: {result['tokens']}")
        print()
        print("-" * 80)
        print(result['content'])
        print("-" * 80)
    else:
        print(f"❌ Error: {result['error']}")
    
    print()
    print("=" * 80)
    print("✅ Demo complete!")
    print("=" * 80)


if __name__ == "__main__":
    demo()


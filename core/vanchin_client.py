#!/usr/bin/env python3
"""
Vanchin AI Client
Client สำหรับเชื่อมต่อกับ Vanchin AI API
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional
from loguru import logger


class VanchinClient:
    """Client สำหรับ Vanchin AI"""
    
    def __init__(self):
        self.api_key = os.getenv("VC_API_KEY", "jjMoD5XYaClAwYlfMUzllfWucvd3NPZy67F3Ax4IT-c")
        self.base_url = os.getenv("VC_API_BASE", "https://vanchin.streamlake.ai/api/gateway/v1/endpoints")
        self.model = os.getenv("VC_MODEL", "ep-rtt0hh-1761571039145129553")
        self.temperature = float(os.getenv("VC_TEMPERATURE", "0.7"))
        self.max_tokens = int(os.getenv("VC_MAX_TOKENS", "2000"))
        
        if not self.api_key or self.api_key == "${VC_API_KEY}":
            raise ValueError("VC_API_KEY not set properly")
        
        logger.info(f"[VanchinClient] Initialized with model: {self.model}")
    
    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> str:
        """
        ส่งคำถามไปยัง Vanchin AI
        
        Args:
            messages: รายการข้อความ [{"role": "user", "content": "..."}]
            temperature: ความสร้างสรรค์ (0.0-1.0)
            max_tokens: จำนวน tokens สูงสุด
        
        Returns:
            คำตอบจาก AI
        """
        url = f"{self.base_url}/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature or self.temperature,
            "max_tokens": max_tokens or self.max_tokens
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0]["message"]["content"]
                logger.debug(f"[VanchinClient] Response: {content[:100]}...")
                return content
            else:
                logger.error(f"[VanchinClient] Invalid response format: {data}")
                return ""
                
        except requests.exceptions.RequestException as e:
            logger.error(f"[VanchinClient] Request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"[VanchinClient] Error: {e}")
            raise
    
    def ask(self, question: str, system_prompt: Optional[str] = None) -> str:
        """
        ถามคำถามแบบง่าย
        
        Args:
            question: คำถาม
            system_prompt: System prompt (optional)
        
        Returns:
            คำตอบ
        """
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": question})
        
        return self.chat(messages)
    
    def analyze_shell_output(self, command: str, output: str) -> Dict[str, Any]:
        """
        วิเคราะห์ผลลัพธ์จาก shell command ด้วย AI
        
        Args:
            command: คำสั่งที่รัน
            output: ผลลัพธ์
        
        Returns:
            การวิเคราะห์
        """
        prompt = f"""วิเคราะห์ผลลัพธ์จากคำสั่ง shell:

คำสั่ง: {command}

ผลลัพธ์:
{output}

กรุณาวิเคราะห์และตอบในรูปแบบ JSON:
{{
    "summary": "สรุปผลลัพธ์",
    "important_findings": ["ข้อค้นพบสำคัญ"],
    "next_commands": ["คำสั่งที่ควรรันต่อไป"],
    "security_issues": ["ปัญหาความปลอดภัยที่พบ"]
}}
"""
        
        response = self.ask(prompt)
        
        try:
            # พยายาม extract JSON จาก response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()
            else:
                json_str = response.strip()
            
            analysis = json.loads(json_str)
            return analysis
        except:
            return {
                "summary": response,
                "important_findings": [],
                "next_commands": [],
                "security_issues": []
            }
    
    def decide_next_action(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        ให้ AI ตัดสินใจว่าควรทำอะไรต่อไป
        
        Args:
            context: บริบทปัจจุบัน
        
        Returns:
            การตัดสินใจ
        """
        prompt = f"""คุณเป็น AI Security Expert ที่กำลังควบคุม shell session

บริบทปัจจุบัน:
{json.dumps(context, indent=2, ensure_ascii=False)}

กรุณาตัดสินใจว่าควรทำอะไรต่อไป และตอบในรูปแบบ JSON:
{{
    "action": "command|exfiltrate|escalate|persist|exit",
    "command": "คำสั่งที่ควรรัน (ถ้า action = command)",
    "reason": "เหตุผล",
    "priority": "high|medium|low"
}}
"""
        
        response = self.ask(prompt, system_prompt="You are an expert penetration tester and security researcher.")
        
        try:
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()
            else:
                json_str = response.strip()
            
            decision = json.loads(json_str)
            return decision
        except:
            return {
                "action": "exit",
                "command": "",
                "reason": "Failed to parse AI decision",
                "priority": "low"
            }
    
    def generate_report(self, attack_data: Dict[str, Any]) -> str:
        """
        สร้างรายงานการโจมตี
        
        Args:
            attack_data: ข้อมูลการโจมตี
        
        Returns:
            รายงานในรูปแบบ Markdown
        """
        prompt = f"""สร้างรายงานการโจมตีจากข้อมูลต่อไปนี้:

{json.dumps(attack_data, indent=2, ensure_ascii=False)}

กรุณาสร้างรายงานในรูปแบบ Markdown ที่มี:
1. สรุปผลการโจมตี
2. รายละเอียดช่องโหว่ที่พบ
3. ข้อมูลที่เก็บได้
4. ข้อเสนอแนะ
5. Timeline ของการโจมตี
"""
        
        return self.ask(prompt, system_prompt="You are a professional security report writer.")


# Global instance
vanchin_client = VanchinClient()


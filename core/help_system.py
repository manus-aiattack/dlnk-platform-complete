import asyncio
from typing import Dict, List, Any, Optional
from core.logger import log


class HelpSystem:
    """ระบบช่วยเหลือสำหรับผู้ใช้"""

    def __init__(self):
        self.help_topics = {}
        self.tutorials = {}
        self.faq = {}

    async def initialize(self):
        """เริ่มต้น Help System"""
        try:
            # โหลด help topics
            await self._load_help_topics()

            # โหลด tutorials
            await self._load_tutorials()

            # โหลด FAQ
            await self._load_faq()

            log.info("✅ Help System เริ่มต้นสำเร็จ")
            return True

        except Exception as e:
            log.error(f"❌ Help System เริ่มต้นล้มเหลว: {e}")
            return False

    async def _load_help_topics(self):
        """โหลด help topics"""
        self.help_topics = {
            "getting_started": {
                "title": "Getting Started",
                "description": "เริ่มต้นใช้งาน dLNk dLNk v5 LLM",
                "content": """
# Getting Started

## การเริ่มต้นใช้งาน

1. **เริ่มต้นระบบ**
   ```bash
   python main.py
   ```

2. **โหมด Interactive**
   - ใช้คำสั่ง `help` เพื่อดูคำสั่งที่ใช้ได้
   - ใช้คำสั่ง `target <URL>` เพื่อตั้งค่าเป้าหมาย
   - ใช้คำสั่ง `run` เพื่อเริ่มการทดสอบ

3. **โหมด Automated**
   ```bash
   python main.py --target <URL> --objective <OBJECTIVE>
   ```

## คำสั่งพื้นฐาน

- `help` - แสดงคำสั่งที่ใช้ได้
- `target <URL>` - ตั้งค่าเป้าหมาย
- `run` - เริ่มการทดสอบ
- `status` - แสดงสถานะ
- `results` - แสดงผลลัพธ์
- `quit` - ออกจากระบบ
                """
            },
            "commands": {
                "title": "Commands",
                "description": "คำสั่งที่ใช้ได้ในระบบ",
                "content": """
# Commands

## คำสั่งพื้นฐาน

### การตั้งค่า
- `target <URL>` - ตั้งค่าเป้าหมาย
- `objective <TEXT>` - ตั้งค่าจุดประสงค์
- `config` - แสดงการตั้งค่า

### การทดสอบ
- `run` - เริ่มการทดสอบ
- `pause` - หยุดการทดสอบ
- `resume` - ดำเนินการต่อ
- `stop` - หยุดการทดสอบ

### การดูผลลัพธ์
- `status` - แสดงสถานะ
- `results` - แสดงผลลัพธ์
- `findings` - แสดงการค้นพบ
- `vulnerabilities` - แสดงช่องโหว่
- `exploits` - แสดงการแสวงหาประโยชน์

### การจัดการ
- `agents` - แสดง agents ที่ใช้ได้
- `phases` - แสดง phases ที่ใช้ได้
- `workflows` - แสดง workflows ที่ใช้ได้

### ระบบ
- `help` - แสดงคำสั่งที่ใช้ได้
- `version` - แสดงเวอร์ชัน
- `quit` - ออกจากระบบ
                """
            },
            "agents": {
                "title": "Agents",
                "description": "Agents ที่ใช้ได้ในระบบ",
                "content": """
# Agents

## Reconnaissance Agents
- **ReconnaissanceMaster** - สำรวจเป้าหมาย
- **TriageAgent** - ประเมินและจัดลำดับ
- **NmapScanAgent** - สแกนพอร์ต
- **TechnologyProfilerAgent** - วิเคราะห์เทคโนโลยี

## Vulnerability Assessment Agents
- **NucleiAgent** - สแกนช่องโหว่
- **FuzzingAgent** - ทดสอบ input validation
- **WafDetectorAgent** - ตรวจสอบ WAF

## Exploitation Agents
- **ExploitAgent** - แสวงหาประโยชน์
- **XSS_Agent** - ทดสอบ XSS
- **SQLInjectionExploiter** - ทดสอบ SQL Injection
- **CommandInjectionExploiter** - ทดสอบ Command Injection

## Post-Exploitation Agents
- **PostExAgent** - หลังการแสวงหาประโยชน์
- **PrivilegeEscalationAgent** - เพิ่มสิทธิ์
- **LateralMovementAgent** - เคลื่อนที่ในเครือข่าย
- **DataDumperAgent** - ดึงข้อมูล

## Reporting Agents
- **ReportingAgent** - สร้างรายงาน
                """
            },
            "workflows": {
                "title": "Workflows",
                "description": "Workflows ที่ใช้ได้ในระบบ",
                "content": """
# Workflows

## Full Attack Workflow
- **reconnaissance** - สำรวจเป้าหมาย
- **vulnerability_assessment** - ประเมินช่องโหว่
- **exploitation** - แสวงหาประโยชน์
- **post_exploitation** - หลังการแสวงหาประโยชน์
- **reporting** - สร้างรายงาน

## Reconnaissance Only
- **reconnaissance** - สำรวจเป้าหมายเท่านั้น

## Vulnerability Assessment
- **reconnaissance** - สำรวจเป้าหมาย
- **vulnerability_assessment** - ประเมินช่องโหว่

## Exploitation
- **reconnaissance** - สำรวจเป้าหมาย
- **vulnerability_assessment** - ประเมินช่องโหว่
- **exploitation** - แสวงหาประโยชน์

## Post-Exploitation
- **reconnaissance** - สำรวจเป้าหมาย
- **vulnerability_assessment** - ประเมินช่องโหว่
- **exploitation** - แสวงหาประโยชน์
- **post_exploitation** - หลังการแสวงหาประโยชน์
                """
            },
            "troubleshooting": {
                "title": "Troubleshooting",
                "description": "การแก้ไขปัญหาที่พบบ่อย",
                "content": """
# Troubleshooting

## ปัญหาที่พบบ่อย

### 1. ระบบไม่เริ่มต้น
- ตรวจสอบการติดตั้ง dependencies
- ตรวจสอบการตั้งค่า LLM
- ตรวจสอบ log files

### 2. Agents ไม่ทำงาน
- ตรวจสอบการตั้งค่า agents
- ตรวจสอบการเชื่อมต่อ
- ตรวจสอบ permissions

### 3. LLM ไม่ตอบสนอง
- ตรวจสอบ API key
- ตรวจสอบการเชื่อมต่อ
- ตรวจสอบ rate limits

### 4. การทดสอบล้มเหลว
- ตรวจสอบเป้าหมาย
- ตรวจสอบการตั้งค่า
- ตรวจสอบ log files

## การแก้ไขปัญหา

### ตรวจสอบ Logs
```bash
tail -f logs/dlnk.log
```

### ตรวจสอบ Configuration
```bash
python main.py --config
```

### ตรวจสอบ Status
```bash
python main.py --status
```
                """
            }
        }

    async def _load_tutorials(self):
        """โหลด tutorials"""
        self.tutorials = {
            "basic_usage": {
                "title": "Basic Usage Tutorial",
                "description": "สอนการใช้งานพื้นฐาน",
                "steps": [
                    "เริ่มต้นระบบ",
                    "ตั้งค่าเป้าหมาย",
                    "เริ่มการทดสอบ",
                    "ดูผลลัพธ์"
                ]
            },
            "advanced_usage": {
                "title": "Advanced Usage Tutorial",
                "description": "สอนการใช้งานขั้นสูง",
                "steps": [
                    "การตั้งค่าขั้นสูง",
                    "การใช้ workflows",
                    "การจัดการ agents",
                    "การสร้างรายงาน"
                ]
            }
        }

    async def _load_faq(self):
        """โหลด FAQ"""
        self.faq = {
            "what_is_dlnk": {
                "question": "dLNk dLNk v5 LLM คืออะไร?",
                "answer": "dLNk dLNk v5 LLM เป็นระบบทดสอบความปลอดภัยแบบอัตโนมัติที่ใช้ AI และ LLM เพื่อทำการทดสอบความปลอดภัยแบบครอบคลุม"
            },
            "how_to_use": {
                "question": "วิธีใช้งานระบบ?",
                "answer": "สามารถใช้งานได้ 2 โหมด: Interactive mode (python main.py) และ Automated mode (python main.py --target <URL> --objective <OBJECTIVE>)"
            },
            "what_agents_available": {
                "question": "Agents ที่ใช้ได้มีอะไรบ้าง?",
                "answer": "มี agents หลายประเภท: Reconnaissance, Vulnerability Assessment, Exploitation, Post-Exploitation, และ Reporting"
            },
            "what_workflows_available": {
                "question": "Workflows ที่ใช้ได้มีอะไรบ้าง?",
                "answer": "มี workflows: Full Attack, Reconnaissance Only, Vulnerability Assessment, Exploitation, และ Post-Exploitation"
            },
            "how_to_troubleshoot": {
                "question": "วิธีแก้ไขปัญหา?",
                "answer": "ตรวจสอบ logs, configuration, และ status ของระบบ หรือใช้คำสั่ง help เพื่อดูคำแนะนำ"
            }
        }

    async def get_help(self, topic: str = None) -> Dict[str, Any]:
        """รับความช่วยเหลือ"""
        try:
            if topic:
                if topic in self.help_topics:
                    return self.help_topics[topic]
                else:
                    return {"error": f"Topic '{topic}' ไม่พบ"}
            else:
                return {
                    "available_topics": list(self.help_topics.keys()),
                    "topics": self.help_topics
                }

        except Exception as e:
            log.error(f"❌ รับความช่วยเหลือล้มเหลว: {e}")
            return {"error": str(e)}

    async def get_tutorial(self, tutorial_id: str = None) -> Dict[str, Any]:
        """รับ tutorial"""
        try:
            if tutorial_id:
                if tutorial_id in self.tutorials:
                    return self.tutorials[tutorial_id]
                else:
                    return {"error": f"Tutorial '{tutorial_id}' ไม่พบ"}
            else:
                return {
                    "available_tutorials": list(self.tutorials.keys()),
                    "tutorials": self.tutorials
                }

        except Exception as e:
            log.error(f"❌ รับ tutorial ล้มเหลว: {e}")
            return {"error": str(e)}

    async def get_faq(self, question_id: str = None) -> Dict[str, Any]:
        """รับ FAQ"""
        try:
            if question_id:
                if question_id in self.faq:
                    return self.faq[question_id]
                else:
                    return {"error": f"FAQ '{question_id}' ไม่พบ"}
            else:
                return {
                    "available_faqs": list(self.faq.keys()),
                    "faqs": self.faq
                }

        except Exception as e:
            log.error(f"❌ รับ FAQ ล้มเหลว: {e}")
            return {"error": str(e)}

    async def search_help(self, query: str) -> List[Dict[str, Any]]:
        """ค้นหาความช่วยเหลือ"""
        try:
            results = []
            query_lower = query.lower()

            # ค้นหาใน help topics
            for topic_id, topic_data in self.help_topics.items():
                if (query_lower in topic_data.get("title", "").lower() or
                    query_lower in topic_data.get("description", "").lower() or
                        query_lower in topic_data.get("content", "").lower()):
                    results.append({
                        "type": "help_topic",
                        "id": topic_id,
                        "title": topic_data.get("title", ""),
                        "description": topic_data.get("description", ""),
                        "content": topic_data.get("content", "")
                    })

            # ค้นหาใน tutorials
            for tutorial_id, tutorial_data in self.tutorials.items():
                if (query_lower in tutorial_data.get("title", "").lower() or
                        query_lower in tutorial_data.get("description", "").lower()):
                    results.append({
                        "type": "tutorial",
                        "id": tutorial_id,
                        "title": tutorial_data.get("title", ""),
                        "description": tutorial_data.get("description", ""),
                        "steps": tutorial_data.get("steps", [])
                    })

            # ค้นหาใน FAQ
            for faq_id, faq_data in self.faq.items():
                if (query_lower in faq_data.get("question", "").lower() or
                        query_lower in faq_data.get("answer", "").lower()):
                    results.append({
                        "type": "faq",
                        "id": faq_id,
                        "question": faq_data.get("question", ""),
                        "answer": faq_data.get("answer", "")
                    })

            return results

        except Exception as e:
            log.error(f"❌ ค้นหาความช่วยเหลือล้มเหลว: {e}")
            return []

    async def get_quick_help(self) -> Dict[str, Any]:
        """รับความช่วยเหลือแบบด่วน"""
        try:
            return {
                "basic_commands": [
                    "help - แสดงความช่วยเหลือ",
                    "target <URL> - ตั้งค่าเป้าหมาย",
                    "run - เริ่มการทดสอบ",
                    "status - แสดงสถานะ",
                    "quit - ออกจากระบบ"
                ],
                "common_workflows": [
                    "full_attack - การโจมตีแบบเต็มรูปแบบ",
                    "reconnaissance_only - สำรวจเท่านั้น",
                    "vulnerability_assessment - ประเมินช่องโหว่"
                ],
                "troubleshooting": [
                    "ตรวจสอบ logs",
                    "ตรวจสอบ configuration",
                    "ตรวจสอบ status"
                ]
            }

        except Exception as e:
            log.error(f"❌ รับความช่วยเหลือแบบด่วนล้มเหลว: {e}")
            return {"error": str(e)}

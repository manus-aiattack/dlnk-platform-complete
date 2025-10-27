import asyncio
from typing import Dict, List, Any, Optional
from core.logger import log
from core.result_aggregator import ResultAggregator
from datetime import datetime
import json
import os


class ReportGenerator:
    """สร้างรายงาน Loot และข้อมูลที่ขโมยได้"""

    def __init__(self, result_aggregator: ResultAggregator):
        self.result_aggregator = result_aggregator
        self.report_templates = {}
        self.generated_reports = {}

    async def initialize(self):
        """เริ่มต้น Report Generator"""
        try:
            # โหลด report templates
            await self._load_report_templates()

            log.info("✅ Report Generator เริ่มต้นสำเร็จ")
            return True

        except Exception as e:
            log.error(f"❌ Report Generator เริ่มต้นล้มเหลว: {e}")
            return False

    async def _load_report_templates(self):
        """โหลด report templates"""
        try:
            self.report_templates = {
                "loot_report": self._generate_loot_report,
                "technical_details": self._generate_technical_details,
                "exploit_report": self._generate_exploit_report,
                "full_report": self._generate_full_report
            }

        except Exception as e:
            log.error(f"❌ โหลด report templates ล้มเหลว: {e}")

    async def generate_report(self, session_id: str, results: Dict[str, Any] = None,
                              report_type: str = "full_report", output_format: str = "json") -> Dict[str, Any]:
        """สร้างรายงาน"""
        try:
            log.info(f"📝 สร้างรายงานสำหรับ session: {session_id}")

            # รับข้อมูลที่รวมแล้ว
            if results is None:
                results = self.result_aggregator.get_aggregated_data(
                    session_id)

            if not results:
                return {"error": f"ไม่พบข้อมูลสำหรับ session {session_id}"}

            # สร้างรายงานตามประเภท
            if report_type not in self.report_templates:
                return {"error": f"ประเภทรายงาน '{report_type}' ไม่พบ"}

            report_data = await self.report_templates[report_type](results)

            # บันทึกรายงาน
            report_id = f"{session_id}_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.generated_reports[report_id] = {
                "session_id": session_id,
                "report_type": report_type,
                "output_format": output_format,
                "timestamp": datetime.now().isoformat(),
                "data": report_data
            }

            # บันทึกลงไฟล์
            if output_format == "json":
                await self._save_json_report(report_id, report_data)
            elif output_format == "html":
                await self._save_html_report(report_id, report_data)
            elif output_format == "pdf":
                await self._save_pdf_report(report_id, report_data)

            log.success(f"✅ สร้างรายงาน {report_type} เสร็จสิ้น")
            return {
                "success": True,
                "report_id": report_id,
                "report_type": report_type,
                "output_format": output_format,
                "data": report_data
            }

        except Exception as e:
            log.error(f"❌ สร้างรายงานล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_loot_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงาน Loot - ข้อมูลที่ขโมยได้"""
        try:
            loot_report = {
                "title": "Loot Report - Stolen Data",
                "timestamp": datetime.now().isoformat(),
                "attack_id": results.get("session_id", "unknown"),
                "target": results.get("target", "unknown"),
                "status": "exploited" if results.get("exploits", []) else "scanning",
                "summary": {
                    "total_databases_dumped": 0,
                    "total_credentials_stolen": 0,
                    "total_files_stolen": 0,
                    "total_sessions_stolen": 0,
                    "active_webshells": 0,
                    "active_c2_agents": 0
                },
                "loot": {
                    "database_dumps": [],
                    "credentials": [],
                    "session_tokens": [],
                    "files": [],
                    "webshells": [],
                    "c2_agents": []
                }
            }

            # วิเคราะห์ข้อมูลที่ขโมยได้จาก exploits
            exploits = results.get("exploits", [])
            for exploit in exploits:
                if not exploit.get("success", False):
                    continue

                exploit_type = exploit.get("type", "").lower()
                exploit_data = exploit.get("data", {})

                # SQL Injection - Database dumps
                if "sql" in exploit_type or "database" in exploit_type:
                    db_dump = {
                        "type": "database_dump",
                        "database": exploit_data.get("database", "unknown"),
                        "tables": exploit_data.get("tables", []),
                        "file_path": exploit_data.get("dump_file", ""),
                        "size": exploit_data.get("size", 0),
                        "timestamp": exploit.get("timestamp", "")
                    }
                    loot_report["loot"]["database_dumps"].append(db_dump)
                    loot_report["summary"]["total_databases_dumped"] += 1

                # XSS - Session tokens
                if "xss" in exploit_type or "session" in exploit_type:
                    sessions = exploit_data.get("sessions", [])
                    for session in sessions:
                        loot_report["loot"]["session_tokens"].append({
                            "type": "session_token",
                            "token": session.get("token", ""),
                            "cookie_name": session.get("name", ""),
                            "domain": session.get("domain", ""),
                            "timestamp": exploit.get("timestamp", "")
                        })
                        loot_report["summary"]["total_sessions_stolen"] += 1

                # File Upload - Webshells
                if "upload" in exploit_type or "shell" in exploit_type:
                    webshell = {
                        "type": "webshell",
                        "url": exploit_data.get("shell_url", ""),
                        "password": exploit_data.get("password", ""),
                        "shell_type": exploit_data.get("shell_type", "php"),
                        "access_command": exploit_data.get("access_command", ""),
                        "status": "active",
                        "timestamp": exploit.get("timestamp", "")
                    }
                    loot_report["loot"]["webshells"].append(webshell)
                    loot_report["summary"]["active_webshells"] += 1

                # Credentials
                if "auth" in exploit_type or "credential" in exploit_type or "password" in exploit_type:
                    credentials = exploit_data.get("credentials", [])
                    for cred in credentials:
                        loot_report["loot"]["credentials"].append({
                            "type": "credential",
                            "username": cred.get("username", ""),
                            "password": cred.get("password", ""),
                            "hash": cred.get("hash", ""),
                            "source": cred.get("source", ""),
                            "timestamp": exploit.get("timestamp", "")
                        })
                        loot_report["summary"]["total_credentials_stolen"] += 1

            # วิเคราะห์ไฟล์ที่ขโมยได้
            findings = results.get("findings", [])
            for finding in findings:
                if finding.get("type", "") == "file" or "file" in finding.get("description", "").lower():
                    loot_report["loot"]["files"].append({
                        "type": "file",
                        "file_path": finding.get("location", ""),
                        "file_name": finding.get("name", ""),
                        "content": finding.get("content", ""),
                        "size": finding.get("size", 0),
                        "timestamp": finding.get("timestamp", "")
                    })
                    loot_report["summary"]["total_files_stolen"] += 1

            # วิเคราะห์ C2 agents
            agents = results.get("c2_agents", [])
            for agent in agents:
                if agent.get("status", "") == "active":
                    loot_report["loot"]["c2_agents"].append({
                        "type": "c2_agent",
                        "agent_id": agent.get("agent_id", ""),
                        "callback_url": agent.get("callback_url", ""),
                        "status": agent.get("status", ""),
                        "last_seen": agent.get("last_seen", ""),
                        "capabilities": agent.get("capabilities", [])
                    })
                    loot_report["summary"]["active_c2_agents"] += 1

            return loot_report

        except Exception as e:
            log.error(f"❌ สร้าง loot report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_technical_details(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายละเอียดทางเทคนิค"""
        try:
            technical_details = {
                "title": "Technical Details",
                "timestamp": datetime.now().isoformat(),
                "phases": {},
                "agents": {},
                "statistics": results.get("statistics", {}),
                "timeline": []
            }

            # รายละเอียด phases
            for phase_name, phase_data in results.get("phases", {}).items():
                technical_details["phases"][phase_name] = {
                    "name": phase_data.get("name", ""),
                    "status": phase_data.get("status", ""),
                    "success": phase_data.get("success", False),
                    "start_time": phase_data.get("start_time", ""),
                    "end_time": phase_data.get("end_time", ""),
                    "duration": phase_data.get("duration", 0),
                    "agents_used": phase_data.get("agents_used", []),
                    "results": phase_data.get("results", {}),
                    "errors": phase_data.get("errors", []),
                    "exploits": phase_data.get("exploits", [])
                }

            # รายละเอียด agents
            for agent_name, agent_data in results.get("agents", {}).items():
                technical_details["agents"][agent_name] = {
                    "name": agent_data.get("name", ""),
                    "status": agent_data.get("status", ""),
                    "success": agent_data.get("success", False),
                    "start_time": agent_data.get("start_time", ""),
                    "end_time": agent_data.get("end_time", ""),
                    "duration": agent_data.get("duration", 0),
                    "results": agent_data.get("results", {}),
                    "errors": agent_data.get("errors", []),
                    "exploits": agent_data.get("exploits", [])
                }

            # สร้าง timeline
            timeline = []
            for phase_name, phase_data in results.get("phases", {}).items():
                timeline.append({
                    "timestamp": phase_data.get("start_time", ""),
                    "event": f"Phase {phase_name} started",
                    "type": "phase_start",
                    "data": phase_data
                })

                timeline.append({
                    "timestamp": phase_data.get("end_time", ""),
                    "event": f"Phase {phase_name} completed",
                    "type": "phase_end",
                    "data": phase_data
                })

            # เรียง timeline ตาม timestamp
            timeline.sort(key=lambda x: x["timestamp"])
            technical_details["timeline"] = timeline

            return technical_details

        except Exception as e:
            log.error(f"❌ สร้าง technical details ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_exploit_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงานการโจมตี"""
        try:
            exploit_report = {
                "title": "Exploit Report",
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_exploits": len(results.get("exploits", [])),
                    "successful_exploits": 0,
                    "failed_exploits": 0,
                    "by_type": {}
                },
                "exploits": results.get("exploits", [])
            }

            # วิเคราะห์ exploits
            exploits = results.get("exploits", [])
            for exploit in exploits:
                if exploit.get("success", False):
                    exploit_report["summary"]["successful_exploits"] += 1
                else:
                    exploit_report["summary"]["failed_exploits"] += 1

                exploit_type = exploit.get("type", "unknown")
                if exploit_type not in exploit_report["summary"]["by_type"]:
                    exploit_report["summary"]["by_type"][exploit_type] = 0
                exploit_report["summary"]["by_type"][exploit_type] += 1

            return exploit_report

        except Exception as e:
            log.error(f"❌ สร้าง exploit report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_full_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างรายงานแบบเต็ม"""
        try:
            full_report = {
                "title": "Full Attack Report",
                "timestamp": datetime.now().isoformat(),
                "loot_report": await self._generate_loot_report(results),
                "technical_details": await self._generate_technical_details(results),
                "exploit_report": await self._generate_exploit_report(results)
            }

            return full_report

        except Exception as e:
            log.error(f"❌ สร้าง full report ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _save_json_report(self, report_id: str, report_data: Dict[str, Any]):
        """บันทึกรายงานเป็น JSON"""
        try:
            os.makedirs("workspace/loot", exist_ok=True)
            report_file = f"workspace/loot/{report_id}.json"

            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            log.info(f"📄 บันทึกรายงาน JSON: {report_file}")

        except Exception as e:
            log.error(f"❌ บันทึกรายงาน JSON ล้มเหลว: {e}")

    async def _save_html_report(self, report_id: str, report_data: Dict[str, Any]):
        """บันทึกรายงานเป็น HTML"""
        try:
            # สร้าง HTML template
            html_content = await self._generate_html_content(report_data)

            os.makedirs("workspace/loot", exist_ok=True)
            report_file = f"workspace/loot/{report_id}.html"

            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            log.info(f"📄 บันทึกรายงาน HTML: {report_file}")

        except Exception as e:
            log.error(f"❌ บันทึกรายงาน HTML ล้มเหลว: {e}")

    async def _save_pdf_report(self, report_id: str, report_data: Dict[str, Any]):
        """บันทึกรายงานเป็น PDF"""
        try:
            # สร้าง HTML ก่อน
            html_content = await self._generate_html_content(report_data)

            os.makedirs("workspace/loot", exist_ok=True)
            report_file = f"workspace/loot/{report_id}.pdf"

            # แปลง HTML เป็น PDF (ต้องติดตั้ง weasyprint หรือ wkhtmltopdf)
            # ตัวอย่างนี้ใช้ weasyprint
            try:
                from weasyprint import HTML
                HTML(string=html_content).write_pdf(report_file)
            except ImportError:
                log.warning("⚠️ weasyprint ไม่พร้อมใช้งาน บันทึกเป็น HTML แทน")
                html_file = f"workspace/loot/{report_id}.html"
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                return

            log.info(f"📄 บันทึกรายงาน PDF: {report_file}")

        except Exception as e:
            log.error(f"❌ บันทึกรายงาน PDF ล้มเหลว: {e}")

    async def _generate_html_content(self, report_data: Dict[str, Any]) -> str:
        """สร้างเนื้อหา HTML สำหรับรายงาน"""
        try:
            html = f"""
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data.get('title', 'Attack Report')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #0a0a0a;
            color: #00ff00;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #1a1a1a;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }}
        h1 {{
            color: #00ff00;
            border-bottom: 2px solid #00ff00;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #00cc00;
            margin-top: 30px;
        }}
        .section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #0d0d0d;
            border-left: 3px solid #00ff00;
        }}
        .loot-item {{
            margin: 10px 0;
            padding: 10px;
            background-color: #1a1a1a;
            border: 1px solid #00ff00;
            border-radius: 5px;
        }}
        .credential {{
            color: #ff0000;
            font-weight: bold;
        }}
        .success {{
            color: #00ff00;
        }}
        .warning {{
            color: #ffaa00;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border: 1px solid #00ff00;
        }}
        th {{
            background-color: #0d0d0d;
            color: #00ff00;
        }}
        pre {{
            background-color: #0d0d0d;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report_data.get('title', 'Attack Report')}</h1>
        <p><strong>Timestamp:</strong> {report_data.get('timestamp', '')}</p>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <pre>{json.dumps(report_data.get('summary', {}), indent=2, ensure_ascii=False)}</pre>
        </div>
        
        <div class="section">
            <h2>💰 Loot Collected</h2>
            <pre>{json.dumps(report_data.get('loot', {}), indent=2, ensure_ascii=False)}</pre>
        </div>
        
        <div class="section">
            <h2>🔧 Technical Details</h2>
            <pre>{json.dumps(report_data, indent=2, ensure_ascii=False)}</pre>
        </div>
    </div>
</body>
</html>
"""
            return html

        except Exception as e:
            log.error(f"❌ สร้าง HTML content ล้มเหลว: {e}")
            return f"<html><body><h1>Error generating report</h1><p>{str(e)}</p></body></html>"

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """ดึงรายงานที่สร้างแล้ว"""
        return self.generated_reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        """แสดงรายการรายงานทั้งหมด"""
        return [
            {
                "report_id": report_id,
                "session_id": report_data["session_id"],
                "report_type": report_data["report_type"],
                "timestamp": report_data["timestamp"]
            }
            for report_id, report_data in self.generated_reports.items()
        ]


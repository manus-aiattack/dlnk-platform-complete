import asyncio
from typing import Dict, List, Any, Optional
from core.logger import log
from datetime import datetime


class StatusDisplay:
    """แสดงสถานะของระบบ"""

    def __init__(self):
        self.status_data = {}
        self.display_format = "table"

    async def show_system_status(self, status_data: Dict[str, Any]):
        """แสดงสถานะของระบบ"""
        try:
            if self.display_format == "table":
                await self._show_table_status(status_data)
            elif self.display_format == "json":
                await self._show_json_status(status_data)
            elif self.display_format == "simple":
                await self._show_simple_status(status_data)
            else:
                await self._show_default_status(status_data)

        except Exception as e:
            log.error(f"❌ แสดงสถานะระบบล้มเหลว: {e}")

    async def _show_table_status(self, status_data: Dict[str, Any]):
        """แสดงสถานะแบบตาราง"""
        try:
            print("\n" + "="*80)
            print("dLNk DLNK v5 LLM - SYSTEM STATUS")
            print("="*80)

            # System Info
            print(f"{'System Status':<20}: {status_data.get('status', 'Unknown')}")
            print(f"{'Uptime':<20}: {status_data.get('uptime', 'Unknown')}")
            print(f"{'Version':<20}: {status_data.get('version', 'Unknown')}")
            print(
                f"{'Timestamp':<20}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            # Sessions
            sessions = status_data.get('sessions', {})
            print(f"\n{'SESSIONS':<20}")
            print("-" * 40)
            print(f"{'Active Sessions':<20}: {sessions.get('active', 0)}")
            print(f"{'Total Sessions':<20}: {sessions.get('total', 0)}")
            print(f"{'Completed':<20}: {sessions.get('completed', 0)}")
            print(f"{'Failed':<20}: {sessions.get('failed', 0)}")

            # Agents
            agents = status_data.get('agents', {})
            print(f"\n{'AGENTS':<20}")
            print("-" * 40)
            print(f"{'Total Agents':<20}: {agents.get('total', 0)}")
            print(f"{'Active Agents':<20}: {agents.get('active', 0)}")
            print(f"{'Successful':<20}: {agents.get('successful', 0)}")
            print(f"{'Failed':<20}: {agents.get('failed', 0)}")

            # Workflows
            workflows = status_data.get('workflows', {})
            print(f"\n{'WORKFLOWS':<20}")
            print("-" * 40)
            print(f"{'Active Workflows':<20}: {workflows.get('active', 0)}")
            print(f"{'Completed':<20}: {workflows.get('completed', 0)}")
            print(f"{'Failed':<20}: {workflows.get('failed', 0)}")

            # Results
            results = status_data.get('results', {})
            print(f"\n{'RESULTS':<20}")
            print("-" * 40)
            print(f"{'Vulnerabilities':<20}: {results.get('vulnerabilities', 0)}")
            print(f"{'Exploits':<20}: {results.get('exploits', 0)}")
            print(f"{'Findings':<20}: {results.get('findings', 0)}")

            # Performance
            performance = status_data.get('performance', {})
            print(f"\n{'PERFORMANCE':<20}")
            print("-" * 40)
            print(f"{'CPU Usage':<20}: {performance.get('cpu_usage', 0)}%")
            print(f"{'Memory Usage':<20}: {performance.get('memory_usage', 0)}%")
            print(f"{'Disk Usage':<20}: {performance.get('disk_usage', 0)}%")

            print("="*80)

        except Exception as e:
            log.error(f"❌ แสดงสถานะแบบตารางล้มเหลว: {e}")

    async def _show_json_status(self, status_data: Dict[str, Any]):
        """แสดงสถานะแบบ JSON"""
        try:
            import json
            print(json.dumps(status_data, indent=2, ensure_ascii=False))

        except Exception as e:
            log.error(f"❌ แสดงสถานะแบบ JSON ล้มเหลว: {e}")

    async def _show_simple_status(self, status_data: Dict[str, Any]):
        """แสดงสถานะแบบง่าย"""
        try:
            print(f"Status: {status_data.get('status', 'Unknown')}")
            print(
                f"Active Sessions: {status_data.get('sessions', {}).get('active', 0)}")
            print(
                f"Active Agents: {status_data.get('agents', {}).get('active', 0)}")
            print(
                f"Vulnerabilities: {status_data.get('results', {}).get('vulnerabilities', 0)}")
            print(
                f"Exploits: {status_data.get('results', {}).get('exploits', 0)}")

        except Exception as e:
            log.error(f"❌ แสดงสถานะแบบง่ายล้มเหลว: {e}")

    async def _show_default_status(self, status_data: Dict[str, Any]):
        """แสดงสถานะแบบเริ่มต้น"""
        try:
            print(f"\n🔍 dLNk dLNk v5 LLM Status")
            print(f"Status: {status_data.get('status', 'Unknown')}")
            print(
                f"Active Sessions: {status_data.get('sessions', {}).get('active', 0)}")
            print(
                f"Active Agents: {status_data.get('agents', {}).get('active', 0)}")
            print(
                f"Vulnerabilities Found: {status_data.get('results', {}).get('vulnerabilities', 0)}")
            print(
                f"Exploits Generated: {status_data.get('results', {}).get('exploits', 0)}")
            print(
                f"Findings: {status_data.get('results', {}).get('findings', 0)}")

        except Exception as e:
            log.error(f"❌ แสดงสถานะแบบเริ่มต้นล้มเหลว: {e}")

    async def show_session_status(self, session_data: Dict[str, Any]):
        """แสดงสถานะของ session"""
        try:
            print(f"\n📝 Session Status")
            print(f"Session ID: {session_data.get('session_id', 'Unknown')}")
            print(f"Target: {session_data.get('target_url', 'Unknown')}")
            print(f"Objective: {session_data.get('objective', 'Unknown')}")
            print(f"Status: {session_data.get('status', 'Unknown')}")
            print(
                f"Current Phase: {session_data.get('current_phase', 'Unknown')}")
            print(f"Progress: {session_data.get('progress', 0)}%")
            print(f"Risk Score: {session_data.get('risk_score', 0)}")
            print(f"Agents Used: {session_data.get('agents_used', 0)}")
            print(
                f"Vulnerabilities: {session_data.get('vulnerabilities_found', 0)}")
            print(f"Exploits: {session_data.get('exploits_generated', 0)}")

        except Exception as e:
            log.error(f"❌ แสดงสถานะ session ล้มเหลว: {e}")

    async def show_agent_status(self, agent_data: Dict[str, Any]):
        """แสดงสถานะของ agent"""
        try:
            print(f"\n🤖 Agent Status")
            print(f"Agent: {agent_data.get('name', 'Unknown')}")
            print(f"Status: {agent_data.get('status', 'Unknown')}")
            print(f"Success: {agent_data.get('success', False)}")
            print(f"Duration: {agent_data.get('duration', 0)}s")
            print(f"Results: {len(agent_data.get('results', {}))}")
            print(f"Errors: {len(agent_data.get('errors', []))}")
            print(f"Findings: {len(agent_data.get('findings', []))}")
            print(
                f"Vulnerabilities: {len(agent_data.get('vulnerabilities', []))}")
            print(f"Exploits: {len(agent_data.get('exploits', []))}")

        except Exception as e:
            log.error(f"❌ แสดงสถานะ agent ล้มเหลว: {e}")

    async def show_workflow_status(self, workflow_data: Dict[str, Any]):
        """แสดงสถานะของ workflow"""
        try:
            print(f"\n🔄 Workflow Status")
            print(f"Workflow: {workflow_data.get('name', 'Unknown')}")
            print(f"Status: {workflow_data.get('status', 'Unknown')}")
            print(f"Target: {workflow_data.get('target_url', 'Unknown')}")
            print(f"Objective: {workflow_data.get('objective', 'Unknown')}")
            print(f"Start Time: {workflow_data.get('start_time', 'Unknown')}")
            print(f"End Time: {workflow_data.get('end_time', 'Unknown')}")
            print(f"Duration: {workflow_data.get('duration', 0)}s")
            print(f"Results: {len(workflow_data.get('results', {}))}")

        except Exception as e:
            log.error(f"❌ แสดงสถานะ workflow ล้มเหลว: {e}")

    async def show_results_summary(self, results_data: Dict[str, Any]):
        """แสดงสรุปผลลัพธ์"""
        try:
            print(f"\n📊 Results Summary")
            print(
                f"Total Vulnerabilities: {results_data.get('vulnerabilities', 0)}")
            print(f"Total Exploits: {results_data.get('exploits', 0)}")
            print(f"Total Findings: {results_data.get('findings', 0)}")
            print(f"Success Rate: {results_data.get('success_rate', 0)}%")
            print(f"Total Duration: {results_data.get('total_duration', 0)}s")

            # แสดง vulnerabilities
            vulnerabilities = results_data.get('vulnerability_details', [])
            if vulnerabilities:
                print(f"\n🔍 Vulnerabilities:")
                for vuln in vulnerabilities[:5]:  # แสดง 5 อันแรก
                    print(
                        f"  - {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")

            # แสดง exploits
            exploits = results_data.get('exploit_details', [])
            if exploits:
                print(f"\n💥 Exploits:")
                for exploit in exploits[:5]:  # แสดง 5 อันแรก
                    print(
                        f"  - {exploit.get('type', 'Unknown')}: {exploit.get('description', 'No description')}")

            # แสดง findings
            findings = results_data.get('finding_details', [])
            if findings:
                print(f"\n🔍 Findings:")
                for finding in findings[:5]:  # แสดง 5 อันแรก
                    print(
                        f"  - {finding.get('type', 'Unknown')}: {finding.get('description', 'No description')}")

        except Exception as e:
            log.error(f"❌ แสดงสรุปผลลัพธ์ล้มเหลว: {e}")

    async def show_progress(self, progress_data: Dict[str, Any]):
        """แสดงความคืบหน้า"""
        try:
            current_phase = progress_data.get('current_phase', 'Unknown')
            progress = progress_data.get('progress', 0)
            total_phases = progress_data.get('total_phases', 0)
            current_phase_index = progress_data.get('current_phase_index', 0)

            print(f"\n⏳ Progress: {progress}%")
            print(
                f"Current Phase: {current_phase} ({current_phase_index + 1}/{total_phases})")

            # แสดง progress bar
            bar_length = 50
            filled_length = int(bar_length * progress / 100)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            print(f"Progress Bar: [{bar}] {progress}%")

        except Exception as e:
            log.error(f"❌ แสดงความคืบหน้าล้มเหลว: {e}")

    async def show_alerts(self, alerts_data: List[Dict[str, Any]]):
        """แสดง alerts"""
        try:
            if not alerts_data:
                print("\n✅ No alerts")
                return

            print(f"\n🚨 Alerts ({len(alerts_data)})")
            for alert in alerts_data:
                severity = alert.get('severity', 'unknown')
                message = alert.get('message', 'No message')
                timestamp = alert.get('timestamp', 'Unknown')

                severity_icon = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🟢'
                }.get(severity, '⚪')

                print(
                    f"  {severity_icon} [{severity.upper()}] {message} ({timestamp})")

        except Exception as e:
            log.error(f"❌ แสดง alerts ล้มเหลว: {e}")

    def set_display_format(self, format_type: str):
        """ตั้งค่ารูปแบบการแสดงผล"""
        if format_type in ["table", "json", "simple", "default"]:
            self.display_format = format_type
        else:
            log.warning(f"⚠️ รูปแบบการแสดงผล '{format_type}' ไม่รองรับ")

    def get_display_format(self) -> str:
        """รับรูปแบบการแสดงผลปัจจุบัน"""
        return self.display_format

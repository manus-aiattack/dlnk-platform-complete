import asyncio
from typing import Dict, List, Any, Optional
from core.logger import log
from datetime import datetime


class ResultAggregator:
    """รวมผลลัพธ์จากทุก phase และ agents"""

    def __init__(self):
        self.results = {}
        self.aggregated_data = {}

    async def aggregate_results(self, session_id: str) -> Dict[str, Any]:
        """รวมผลลัพธ์จาก session"""
        try:
            log.info(f"📊 รวมผลลัพธ์สำหรับ session: {session_id}")

            # เริ่มต้น aggregated data
            aggregated_data = {
                "session_id": session_id,
                "timestamp": datetime.now().isoformat(),
                "phases": {},
                "agents": {},
                "vulnerabilities": [],
                "exploits": [],
                "findings": [],
                "statistics": {},
                "summary": {}
            }

            # รวมผลลัพธ์จาก phases
            if session_id in self.results:
                session_results = self.results[session_id]

                # รวมผลลัพธ์จาก phases
                for phase_name, phase_data in session_results.get("phases", {}).items():
                    aggregated_data["phases"][phase_name] = await self._aggregate_phase_results(phase_data)

                # รวมผลลัพธ์จาก agents
                for agent_name, agent_data in session_results.get("agents", {}).items():
                    aggregated_data["agents"][agent_name] = await self._aggregate_agent_results(agent_data)

                # รวม vulnerabilities
                aggregated_data["vulnerabilities"] = await self._aggregate_vulnerabilities(session_results)

                # รวม exploits
                aggregated_data["exploits"] = await self._aggregate_exploits(session_results)

                # รวม findings
                aggregated_data["findings"] = await self._aggregate_findings(session_results)

                # คำนวณสถิติ
                aggregated_data["statistics"] = await self._calculate_statistics(session_results)

                # สร้างสรุป
                aggregated_data["summary"] = await self._create_summary(aggregated_data)

            # บันทึก aggregated data
            self.aggregated_data[session_id] = aggregated_data

            log.success(f"✅ รวมผลลัพธ์สำหรับ session {session_id} เสร็จสิ้น")
            return aggregated_data

        except Exception as e:
            log.error(f"❌ รวมผลลัพธ์ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _aggregate_phase_results(self, phase_data: Dict[str, Any]) -> Dict[str, Any]:
        """รวมผลลัพธ์จาก phase"""
        try:
            aggregated_phase = {
                "name": phase_data.get("name", ""),
                "status": phase_data.get("status", "unknown"),
                "success": phase_data.get("success", False),
                "start_time": phase_data.get("start_time", ""),
                "end_time": phase_data.get("end_time", ""),
                "duration": phase_data.get("duration", 0),
                "agents_used": phase_data.get("agents_used", []),
                "results": phase_data.get("results", {}),
                "errors": phase_data.get("errors", []),
                "findings": phase_data.get("findings", []),
                "vulnerabilities": phase_data.get("vulnerabilities", []),
                "exploits": phase_data.get("exploits", [])
            }

            return aggregated_phase

        except Exception as e:
            log.error(f"❌ รวมผลลัพธ์ phase ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _aggregate_agent_results(self, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """รวมผลลัพธ์จาก agent"""
        try:
            aggregated_agent = {
                "name": agent_data.get("name", ""),
                "status": agent_data.get("status", "unknown"),
                "success": agent_data.get("success", False),
                "start_time": agent_data.get("start_time", ""),
                "end_time": agent_data.get("end_time", ""),
                "duration": agent_data.get("duration", 0),
                "results": agent_data.get("results", {}),
                "errors": agent_data.get("errors", []),
                "findings": agent_data.get("findings", []),
                "vulnerabilities": agent_data.get("vulnerabilities", []),
                "exploits": agent_data.get("exploits", [])
            }

            return aggregated_agent

        except Exception as e:
            log.error(f"❌ รวมผลลัพธ์ agent ล้มเหลว: {e}")
            return {"error": str(e)}

    async def _aggregate_vulnerabilities(self, session_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """รวม vulnerabilities"""
        try:
            vulnerabilities = []

            # รวม vulnerabilities จาก phases
            for phase_data in session_results.get("phases", {}).values():
                phase_vulns = phase_data.get("vulnerabilities", [])
                vulnerabilities.extend(phase_vulns)

            # รวม vulnerabilities จาก agents
            for agent_data in session_results.get("agents", {}).values():
                agent_vulns = agent_data.get("vulnerabilities", [])
                vulnerabilities.extend(agent_vulns)

            # ลบ duplicates
            unique_vulnerabilities = []
            seen_vulns = set()

            for vuln in vulnerabilities:
                vuln_key = f"{vuln.get('type', '')}_{vuln.get('location', '')}"
                if vuln_key not in seen_vulns:
                    unique_vulnerabilities.append(vuln)
                    seen_vulns.add(vuln_key)

            return unique_vulnerabilities

        except Exception as e:
            log.error(f"❌ รวม vulnerabilities ล้มเหลว: {e}")
            return []

    async def _aggregate_exploits(self, session_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """รวม exploits"""
        try:
            exploits = []

            # รวม exploits จาก phases
            for phase_data in session_results.get("phases", {}).values():
                phase_exploits = phase_data.get("exploits", [])
                exploits.extend(phase_exploits)

            # รวม exploits จาก agents
            for agent_data in session_results.get("agents", {}).values():
                agent_exploits = agent_data.get("exploits", [])
                exploits.extend(agent_exploits)

            # ลบ duplicates
            unique_exploits = []
            seen_exploits = set()

            for exploit in exploits:
                exploit_key = f"{exploit.get('type', '')}_{exploit.get('target', '')}"
                if exploit_key not in seen_exploits:
                    unique_exploits.append(exploit)
                    seen_exploits.add(exploit_key)

            return unique_exploits

        except Exception as e:
            log.error(f"❌ รวม exploits ล้มเหลว: {e}")
            return []

    async def _aggregate_findings(self, session_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """รวม findings"""
        try:
            findings = []

            # รวม findings จาก phases
            for phase_data in session_results.get("phases", {}).values():
                phase_findings = phase_data.get("findings", [])
                findings.extend(phase_findings)

            # รวม findings จาก agents
            for agent_data in session_results.get("agents", {}).values():
                agent_findings = agent_data.get("findings", [])
                findings.extend(agent_findings)

            # ลบ duplicates
            unique_findings = []
            seen_findings = set()

            for finding in findings:
                finding_key = f"{finding.get('type', '')}_{finding.get('description', '')}"
                if finding_key not in seen_findings:
                    unique_findings.append(finding)
                    seen_findings.add(finding_key)

            return unique_findings

        except Exception as e:
            log.error(f"❌ รวม findings ล้มเหลว: {e}")
            return []

    async def _calculate_statistics(self, session_results: Dict[str, Any]) -> Dict[str, Any]:
        """คำนวณสถิติ"""
        try:
            statistics = {
                "total_phases": len(session_results.get("phases", {})),
                "total_agents": len(session_results.get("agents", {})),
                "total_vulnerabilities": 0,
                "total_exploits": 0,
                "total_findings": 0,
                "successful_phases": 0,
                "successful_agents": 0,
                "failed_phases": 0,
                "failed_agents": 0,
                "total_duration": 0,
                "average_phase_duration": 0,
                "average_agent_duration": 0
            }

            # คำนวณสถิติ phases
            phases = session_results.get("phases", {})
            for phase_data in phases.values():
                if phase_data.get("success", False):
                    statistics["successful_phases"] += 1
                else:
                    statistics["failed_phases"] += 1

                duration = phase_data.get("duration", 0)
                statistics["total_duration"] += duration

            # คำนวณสถิติ agents
            agents = session_results.get("agents", {})
            for agent_data in agents.values():
                if agent_data.get("success", False):
                    statistics["successful_agents"] += 1
                else:
                    statistics["failed_agents"] += 1

                duration = agent_data.get("duration", 0)
                statistics["total_duration"] += duration

            # คำนวณ vulnerabilities
            for phase_data in phases.values():
                statistics["total_vulnerabilities"] += len(
                    phase_data.get("vulnerabilities", []))

            for agent_data in agents.values():
                statistics["total_vulnerabilities"] += len(
                    agent_data.get("vulnerabilities", []))

            # คำนวณ exploits
            for phase_data in phases.values():
                statistics["total_exploits"] += len(
                    phase_data.get("exploits", []))

            for agent_data in agents.values():
                statistics["total_exploits"] += len(
                    agent_data.get("exploits", []))

            # คำนวณ findings
            for phase_data in phases.values():
                statistics["total_findings"] += len(
                    phase_data.get("findings", []))

            for agent_data in agents.values():
                statistics["total_findings"] += len(
                    agent_data.get("findings", []))

            # คำนวณ average duration
            if statistics["total_phases"] > 0:
                statistics["average_phase_duration"] = statistics["total_duration"] / \
                    statistics["total_phases"]

            if statistics["total_agents"] > 0:
                statistics["average_agent_duration"] = statistics["total_duration"] / \
                    statistics["total_agents"]

            return statistics

        except Exception as e:
            log.error(f"❌ คำนวณสถิติล้มเหลว: {e}")
            return {}

    async def _create_summary(self, aggregated_data: Dict[str, Any]) -> Dict[str, Any]:
        """สร้างสรุป"""
        try:
            summary = {
                "overview": {
                    "total_phases": len(aggregated_data.get("phases", {})),
                    "total_agents": len(aggregated_data.get("agents", {})),
                    "total_vulnerabilities": len(aggregated_data.get("vulnerabilities", [])),
                    "total_exploits": len(aggregated_data.get("exploits", [])),
                    "total_findings": len(aggregated_data.get("findings", []))
                },
                "phases_summary": {},
                "agents_summary": {},
                "vulnerabilities_summary": {},
                "exploits_summary": {},
                "findings_summary": {},
                "recommendations": []
            }

            # สรุป phases
            for phase_name, phase_data in aggregated_data.get("phases", {}).items():
                summary["phases_summary"][phase_name] = {
                    "status": phase_data.get("status", "unknown"),
                    "success": phase_data.get("success", False),
                    "duration": phase_data.get("duration", 0),
                    "agents_used": len(phase_data.get("agents_used", [])),
                    "vulnerabilities": len(phase_data.get("vulnerabilities", [])),
                    "exploits": len(phase_data.get("exploits", [])),
                    "findings": len(phase_data.get("findings", []))
                }

            # สรุป agents
            for agent_name, agent_data in aggregated_data.get("agents", {}).items():
                summary["agents_summary"][agent_name] = {
                    "status": agent_data.get("status", "unknown"),
                    "success": agent_data.get("success", False),
                    "duration": agent_data.get("duration", 0),
                    "vulnerabilities": len(agent_data.get("vulnerabilities", [])),
                    "exploits": len(agent_data.get("exploits", [])),
                    "findings": len(agent_data.get("findings", []))
                }

            # สรุป vulnerabilities
            vulnerabilities = aggregated_data.get("vulnerabilities", [])
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "unknown")
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

            summary["vulnerabilities_summary"] = vuln_types

            # สรุป exploits
            exploits = aggregated_data.get("exploits", [])
            exploit_types = {}
            for exploit in exploits:
                exploit_type = exploit.get("type", "unknown")
                exploit_types[exploit_type] = exploit_types.get(
                    exploit_type, 0) + 1

            summary["exploits_summary"] = exploit_types

            # สรุป findings
            findings = aggregated_data.get("findings", [])
            finding_types = {}
            for finding in findings:
                finding_type = finding.get("type", "unknown")
                finding_types[finding_type] = finding_types.get(
                    finding_type, 0) + 1

            summary["findings_summary"] = finding_types

            # สร้างคำแนะนำ
            summary["recommendations"] = await self._generate_recommendations(aggregated_data)

            return summary

        except Exception as e:
            log.error(f"❌ สร้างสรุปล้มเหลว: {e}")
            return {"error": str(e)}

    async def _generate_recommendations(self, aggregated_data: Dict[str, Any]) -> List[str]:
        """สร้างคำแนะนำ"""
        try:
            recommendations = []

            # ตรวจสอบ vulnerabilities
            vulnerabilities = aggregated_data.get("vulnerabilities", [])
            if vulnerabilities:
                high_severity_vulns = [v for v in vulnerabilities if v.get(
                    "severity", "").lower() == "high"]
                if high_severity_vulns:
                    recommendations.append("พบช่องโหว่ระดับสูง ควรแก้ไขทันที")

                critical_vulns = [v for v in vulnerabilities if v.get(
                    "severity", "").lower() == "critical"]
                if critical_vulns:
                    recommendations.append(
                        "พบช่องโหว่ระดับวิกฤต ต้องแก้ไขด่วน")

            # ตรวจสอบ exploits
            exploits = aggregated_data.get("exploits", [])
            if exploits:
                successful_exploits = [
                    e for e in exploits if e.get("success", False)]
                if successful_exploits:
                    recommendations.append(
                        "พบการแสวงหาประโยชน์ที่สำเร็จ ควรตรวจสอบระบบ")

            # ตรวจสอบ findings
            findings = aggregated_data.get("findings", [])
            if findings:
                sensitive_findings = [
                    f for f in findings if "sensitive" in f.get("description", "").lower()]
                if sensitive_findings:
                    recommendations.append(
                        "พบข้อมูลที่ละเอียดอ่อน ควรตรวจสอบการเข้าถึง")

            return recommendations

        except Exception as e:
            log.error(f"❌ สร้างคำแนะนำล้มเหลว: {e}")
            return []

    def get_aggregated_data(self, session_id: str) -> Dict[str, Any]:
        """รับข้อมูลที่รวมแล้ว"""
        return self.aggregated_data.get(session_id, {})

    def get_all_aggregated_data(self) -> Dict[str, Any]:
        """รับข้อมูลที่รวมแล้วทั้งหมด"""
        return self.aggregated_data

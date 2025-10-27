import logging
from typing import Dict, Any, List
from core.logger import log
from core.data_models import (Strategy, AttackPhase,
                              TriageReport, WafReport, VulnerabilityReport,
                              PostExReport, PrivilegeEscalationReport, DataDumpReport,
                              PersistenceReport, ThreatAssessmentReport, ErrorType)
import time

from core.base_agent import BaseAgent


class ThreatAssessorReporter(BaseAgent):
    supported_phases = [AttackPhase.REPORTING]
    required_tools = []
    """
    An agent responsible for assessing the overall threat posture and generating a comprehensive report.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_class = ThreatAssessmentReport

    async def run(self, strategy: Strategy, **kwargs) -> ThreatAssessmentReport:
        start_time = time.time()
        triage_report = strategy.context.get("triage_report")
        waf_report = strategy.context.get("waf_report")
        vulnerability_report = strategy.context.get("vulnerability_report")
        post_ex_report = strategy.context.get("post_ex_report")
        privilege_escalation_report = strategy.context.get(
            "privilege_escalation_report")
        data_dump_report = strategy.context.get("data_dump_report")
        persistence_report = strategy.context.get("persistence_report")

        log.info(
            "[ThreatAssessorReporter] Generating comprehensive threat assessment report.")

        summary = ""
        vulnerabilities_exploited = []
        data_dumped = {}
        persistence_mechanisms = []
        recommendations = []

        if triage_report and triage_report.is_interesting:
            summary += f"Initial triage identified the target as interesting: {triage_report.assessment}.\n"
            summary += f"  Interesting findings: {len(triage_report.interesting_findings)}\n"

        if waf_report and waf_report.detected_waf != "None":
            summary += f"WAF detected: {waf_report.detected_waf}.\n"

        if vulnerability_report and vulnerability_report.findings:
            summary += f"Identified {len(vulnerability_report.findings)} vulnerabilities:\n"
            for vuln in vulnerability_report.findings:
                if isinstance(vuln, dict):
                    vuln_id = vuln.get('id', 'N/A')
                    vuln_name = vuln.get('info', {}).get('name', 'N/A')
                    vuln_severity = vuln.get('info', {}).get('severity', 'N/A')
                    summary += f"  - {vuln_id}: {vuln_name} (Severity: {vuln_severity})\n"
                else:
                    summary += f"  - {vuln}\n"

        if post_ex_report and post_ex_report.shell_id:
            summary += f"Post-exploitation initiated on shell ID: {post_ex_report.shell_id}.\n"
            summary += f"  User: {post_ex_report.user}\n"
            summary += f"  Hostname: {post_ex_report.hostname}\n"
            summary += f"  OS Info: {post_ex_report.os_info}\n"
            summary += f"  Network Info: {post_ex_report.network_info}\n"
            # Truncate for brevity
            summary += f"  Processes: {post_ex_report.processes[:200]}...\n"
            summary += f"  Home Dir Listing: {post_ex_report.home_dir_listing[:200]}...\n"

        if privilege_escalation_report and privilege_escalation_report.script_output:
            summary += f"Privilege escalation attempt initiated on shell ID: {privilege_escalation_report.shell_id}.\n"
            summary += f"  Potential vectors identified: {', '.join(privilege_escalation_report.script_output[:5])}\n"
            recommendations.append(
                "Review privilege escalation script output for actionable insights. Remediate any identified vulnerabilities, such as SUID binaries, weak file permissions, or sudo misconfigurations.")

        if data_dump_report and not data_dump_report.errors:
            summary += f"Data dump successful on shell ID: {data_dump_report.shell_id}.\n"
            summary += f"  Dumped data keys: {list(data_dump_report.dumped_data.keys())}\n"
            recommendations.append(
                "Secure sensitive data identified in dump reports. Encrypt sensitive files, rotate credentials, and restrict access to sensitive data.")

        if persistence_report and not persistence_report.errors:
            summary += f"Persistence established via {persistence_report.persistence_type} on shell ID: {persistence_report.shell_id}.\n"
            persistence_mechanisms.append(persistence_report.persistence_type)
            recommendations.append(
                "Remove persistence mechanisms from compromised hosts. Check for new services, cron jobs, registry keys, and startup items.")

        exploit_result = await self.context_manager.get_context('exploit_result')
        if exploit_result and not exploit_result.get("errors"):
            vulnerabilities_exploited.append(
                f"Exploit successful: {exploit_result.get('summary')}")
            summary += f"Exploit successful: {exploit_result.get('summary')}\n"

        if not recommendations:
            recommendations.append("Continue monitoring and reconnaissance.")

        end_time = time.time()
        report = ThreatAssessmentReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            summary=summary,
            vulnerabilities_found=vulnerabilities_exploited,
            recommendations=recommendations
        )
        log.success(
            "[ThreatAssessorReporter] Threat assessment report generated.")
        return report

import os
from core.data_models import AgentData, Strategy
import subprocess
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from core.data_models import ScannerReport, Strategy, Finding, AttackPhase, ErrorType
from core.logger import log
from config import settings
import asyncio
import time

from core.base_agent import BaseAgent


class SkipfishAgent(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = ["skipfish"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = ScannerReport

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute skipfish agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _parse_report(self, output_dir: str) -> List[Finding]:
        """Parses the Skipfish HTML report to extract vulnerabilities."""
        findings = []
        report_path = os.path.join(output_dir, "index.html")
        if not os.path.exists(report_path):
            log.warning(f"Skipfish report not found at {report_path}")
            return findings

        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                soup = BeautifulSoup(f.read(), 'html.parser')

            # Find the main table with all the issue types
            tables = soup.find_all('table')
            if len(tables) < 4:
                log.warning(
                    "Could not find the main vulnerability table in Skipfish report.")
                return findings

            vuln_table = tables[3]  # The main table is usually the 4th one
            rows = vuln_table.find_all('tr')

            # Skip header rows
            for row in rows[2:]:
                cols = row.find_all('td')
                if len(cols) < 2:
                    continue

                # Extract severity from the CSS class of the first column
                severity_class = cols[0].get('class', [''])[0]
                severity_map = {
                    'sev_high': 'high',
                    'sev_medium': 'medium',
                    'sev_low': 'low',
                    'sev_warn': 'informational',
                    'sev_info': 'informational'}
                severity = severity_map.get(severity_class, 'unknown')

                # Extract vulnerability type
                vuln_type = cols[1].text.strip()

                # Find the link to the detailed samples
                details_link = cols[1].find('a')['href']
                details_path = os.path.join(output_dir, details_link)

                # Parse the details page to get an example URL and description
                affected_url = "N/A"
                description = "N/A"
                if os.path.exists(details_path):
                    with open(details_path, 'r', encoding='utf-8') as df:
                        details_soup = BeautifulSoup(df.read(), 'html.parser')
                        # Find the first sample URL
                        sample_table = details_soup.find('table')
                        if sample_table:
                            first_sample_row = sample_table.find_all('tr')[
                                1]  # Skip header
                            if first_sample_row:
                                affected_url = first_sample_row.find(
                                    'a').text.strip()

                        # Find the description
                        description_elem = details_soup.find('h3')
                        if description_elem:
                            description = description_elem.next_sibling.strip()

                finding = Finding(
                    type="vulnerability",
                    source="Skipfish",
                    severity=severity,
                    description=f"{vuln_type}: {description}",
                    recommendation=f"Review Skipfish report in {output_dir} for details.",
                    data={"vuln_type": vuln_type, "affected_url": affected_url}
                )
                findings.append(finding)

            log.success(
                f"Parsed {len(findings)} findings from Skipfish report.")
            return findings

        except Exception as e:
            log.error(f"Failed to parse Skipfish report: {e}", exc_info=True)
            return []

    async def run(self, strategy: Strategy, **kwargs) -> ScannerReport:
        start_time = time.time()
        target_url = await self.context_manager.get_context('target_url')
        target_host = await self.context_manager.get_context('target_host')
        log.info(f"Running Skipfish against {target_url}...")

        # Sanitize target_host for directory creation
        target_host_sanitized = target_host.replace(
            ':', '_').replace('/', '_')
        output_dir = os.path.join(
            settings.WORKSPACE_DIR, "skipfish_reports", target_host_sanitized)
        os.makedirs(output_dir, exist_ok=True)

        command = ["skipfish", "-S", "-l", "5", "-k",
                   "--ssl-cert-bypass", "-o", output_dir, target_url]

        try:
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            log.info(
                f"Skipfish scan is in progress (PID: {process.pid}. This may take a while...")

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1800)  # 30 minutes timeout
            full_output = stdout.decode(errors='ignore')

            if process.returncode == 0:
                summary = f"Skipfish scan completed. Report saved in {output_dir}. Now parsing..."
                log.success(summary)
                findings = self._parse_report(output_dir)
                if not findings:
                    summary += " No high-impact vulnerabilities were parsed from the report."

                end_time = time.time()
                return ScannerReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    findings=findings,
                    summary=summary,
                    raw_output=full_output
                )
            else:
                error_msg = f"Skipfish scan failed with return code {process.returncode}. Output: {full_output}"
                log.error(error_msg)
                end_time = time.time()
                return ScannerReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    errors=[error_msg],
                    error_type=ErrorType.LOGIC,
                    summary=f"Skipfish scan failed for {target_url}.",
                    raw_output=full_output
                )

        except FileNotFoundError:
            error_msg = "'skipfish' command not found. Please install it and ensure it is in your PATH."
            log.critical(error_msg)
            end_time = time.time()
            return ScannerReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[error_msg],
                error_type=ErrorType.CONFIGURATION,
                summary="Skipfish scan failed: Command not found."
            )
        except asyncio.TimeoutError:
            summary = f"Skipfish scan timed out after 30 minutes. Parsing incomplete report from {output_dir}..."
            log.warning(summary)
            findings = self._parse_report(output_dir)
            if not findings:
                summary += " No high-impact vulnerabilities were parsed from the incomplete report."
            end_time = time.time()
            return ScannerReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                findings=findings,
                summary=summary,
                errors=["Scan timed out after 30 minutes."],
                error_type=ErrorType.TIMEOUT
            )
        except Exception as e:
            error_msg = f"An unexpected error occurred during Skipfish scan: {e}"
            log.error(error_msg, exc_info=True)
            end_time = time.time()
            return ScannerReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[error_msg],
                error_type=ErrorType.LOGIC,
                summary=f"Skipfish scan failed due to an unexpected error: {e}"
            )

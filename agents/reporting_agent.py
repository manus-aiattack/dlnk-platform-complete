import json
from core.data_models import AgentData, Strategy
import os
from datetime import datetime, timezone
from core.logger import log
from core.data_models import Strategy, ReportingReport, AttackPhase, ErrorType
from core.target_model_manager import TargetModel
import time
from typing import Optional
from core.database_manager import DatabaseManager
from core.target_model_manager import TargetModelManager

from core.base_agent import BaseAgent


class ReportingAgent(BaseAgent):
    supported_phases = [AttackPhase.REPORTING]
    required_tools = []
    """
    An agent responsible for generating a comprehensive final attack report
    in markdown format.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.target_model_manager: Optional[TargetModelManager] = None
        self.db_manager: Optional[DatabaseManager] = None
        self.report_class = ReportingReport

    async def setup(self):
        """Asynchronous setup method for ReportingAgent."""
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')
        self.db_manager = await self.context_manager.get_context('db_manager')

    async def run(self, strategy: Strategy, **kwargs) -> ReportingReport:
        start_time = time.time()
        log.phase("ReportingAgent: Generating final attack summary report...")
        try:
            # 1. Gather all data from the source of truth: TargetModelManager
            targets = await self.target_model_manager.get_all_targets()
            if not targets:
                end_time = time.time()
                return ReportingReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    errors=["No targets found to generate a report."],
                    error_type=ErrorType.LOGIC,
                    summary="Report generation failed: No targets found."
                )

            # 2. Get all historical actions for the narrative
            cycle_id = await self.context_manager.get_context('cycle_id')
            action_history = await self.db_manager.get_cycle_history(cycle_id)

            # 3. Use LLM to generate the narrative parts of the report
            prompt = self._build_report_prompt(targets, action_history)
            llm_response = await self.orchestrator.call_llm_func(prompt, context="FinalReportGeneration")
            narrative_sections = llm_response.get("report_sections", {
                "executive_summary": "The LLM failed to generate an executive summary.",
                "attack_narrative": "The LLM failed to generate an attack narrative.",
                "exploitation_recommendations": "The LLM failed to generate exploitation recommendations."
            })
            # 4. Build the markdown report by combining LLM narrative with structured data
            markdown_report = self._build_markdown_report(
                targets, narrative_sections)

            # 5. Save the report to a file
            target_host_summary = targets[0].hostname if targets else "multitarget"
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            report_filename = f"Attack_Report_{target_host_summary}_{timestamp}.md"

            # Ensure the reports directory exists
            reports_dir = os.path.abspath("reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_path = os.path.join(reports_dir, report_filename)

            with open(report_path, "w", encoding="utf-8") as f:
                f.write(markdown_report)

            summary = f"Final report saved to {report_path}"
            log.success(summary)
            end_time = time.time()
            return ReportingReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                report_path=report_path,
                content=markdown_report,
                summary=summary
            )

        except Exception as e:
            error_msg = str(e)
            log.error(f"Failed to generate final report: {error_msg}", exc_info=True)
            end_time = time.time()
            return ReportingReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[error_msg],
                error_type=ErrorType.LOGIC,
                summary=f"Report generation failed due to an unexpected error: {error_msg}"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute reporting agent"""
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

    def _build_markdown_report(self, targets: list[TargetModel], narrative_sections: dict) -> str:
        """Assembles the final markdown report from various data sources."""
        report_parts = []

        # Header
        report_parts.append("# dLNk dLNk - Final Attack Report")
        report_parts.append(
            f"**Generated on:** {datetime.now(timezone.utc).isoformat()}Z")
        report_parts.append("---")

        # Executive Summary (from LLM)
        report_parts.append("## 1. Executive Summary")
        report_parts.append(narrative_sections.get(
            "executive_summary", "No summary available."))
        report_parts.append("---")

        # Attack Narrative (from LLM)
        report_parts.append("## 2. Attack Narrative")
        report_parts.append(narrative_sections.get(
            "attack_narrative", "No narrative available."))
        report_parts.append("---")

        # Technical Details Section
        report_parts.append("## 3. Technical Details")

        # Compromised Hosts
        report_parts.append("### 3.1 Compromised & Targeted Hosts")
        for target in targets:
            report_parts.append(f"- **Hostname:** `{target.hostname}`")
            if target.ip_addresses:
                report_parts.append(
                    f"  - **IP Addresses:** {', '.join(f'`{ip}`' for ip in target.ip_addresses)}")
            if target.technologies:
                report_parts.append(
                    f"  - **Discovered Technologies:** {', '.join(f'`{tech}`' for tech in target.technologies)}")
            report_parts.append("")  # Newline for readability
        report_parts.append("---")

        # Credentials
        report_parts.append("### 3.2 Credentials Discovered")
        all_creds = [cred for target in targets for cred in target.credentials]
        if not all_creds:
            report_parts.append(
                "No credentials were discovered during this operation.")
        else:
            report_parts.append(
                "| Host | Username | Type | Value / Key | Source Agent |")
            report_parts.append(
                "|------|----------|------|-------------|--------------|")
            for cred in all_creds:
                cred_type = "password" if cred.password else "hash" if cred.hash else "key"
                value = cred.password or cred.hash or cred.key
                value_short = (
                    value[:50] + '...') if value and len(value) > 53 else value
                report_parts.append(
                    f"| `{cred.host or 'N/A'}` | `{cred.username or 'N/A'}` | {cred_type} | `{value_short or 'N/A'}` | `{cred.source_agent}` |")
        report_parts.append("---")

        # Confirmed Vulnerabilities
        report_parts.append("### 3.3 Confirmed Vulnerabilities")
        all_vulns = [
            vuln for target in targets for vuln in target.confirmed_vulnerabilities]
        if not all_vulns:
            report_parts.append(
                "No vulnerabilities were confirmed during this operation.")
        else:
            report_parts.append(
                "| Host | Vulnerability | Description | Severity | Source Agent |")
            report_parts.append(
                "|------|-----------------|-------------|----------|--------------|")
            for vuln in all_vulns:
                report_parts.append(
                    f"| `{vuln.host}` | **{vuln.vulnerability_id}** | {vuln.description} | {vuln.severity} | `{vuln.source_agent}` |")
        report_parts.append("---")

        # Exploitation Recommendations (from LLM)
        report_parts.append("## 4. Exploitation Recommendations")
        report_parts.append(narrative_sections.get(
            "exploitation_recommendations", "No recommendations available."))

        return "\n".join(report_parts)

    def _build_report_prompt(self, targets: list[TargetModel], action_history: list) -> str:
        """Builds a rich, structured prompt for the LLM to generate the narrative sections."""

        # Create a serializable summary of the entire operation
        summary = {
            "targets": [t.to_dict() for t in targets],
            "action_history_summary": []}

        # Summarize action history
        # Limit history to avoid huge prompts
        for action in action_history[:30]:
            summary["action_history_summary"].append({
                "agent": action.get("agent_name"),
                "summary": action.get("summary"),
                "success": action.get("report", {}).get("success")
            })

        history_json = json.dumps(summary, indent=2, default=str)

        prompt = f"""
        You are a senior penetration tester AI, tasked with writing the narrative sections of a final report.
        Based on the following JSON data summarizing the entire attack operation, generate a compelling Executive Summary, a chronological Attack Narrative, and a list of actionable Exploitation Recommendations.

        **Operation Data:**
        ```json
        {history_json}
        ```

        **Your Task:**
        Generate an "Executive Summary", an "Attack Narrative", and "Exploitation Recommendations".
        - The **Executive Summary** should be a high-level overview for a non-technical audience, covering objectives, key successes (like shells or critical vulnerabilities), and the overall outcome.
        - The **Attack Narrative** should tell the story of the attack chronologically, explaining what the AI agents did, what worked, and what failed. Mention key agents and their successes or failures.
        - The **Exploitation Recommendations** should provide a prioritized list of actions to take to exploit the identified vulnerabilities and achieve the attack objectives.

        **CRITICAL: Your response MUST be ONLY a raw JSON object with a single key "report_sections", which contains three keys: "executive_summary", "attack_narrative", and "exploitation_recommendations".**
        Example:
        """
        prompt += """{
          "report_sections": {
            "executive_summary": "This is the executive summary...",
            "attack_narrative": "The operation commenced with...",
            "exploitation_recommendations": "1. Exploit the SQL injection vulnerability to extract user credentials...\n2. Use the obtained credentials to access the internal network..."
          }
        }"""
        return prompt

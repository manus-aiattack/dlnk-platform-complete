from typing import List
from core.data_models import AgentData, Strategy
from core.data_models import TriageReport, Strategy, AgentData, AttackPhase, QuerySynthesizerReport, ErrorType
from core.logger import log
import json
import re

from core.base_agent import BaseAgent


class QuerySynthesizerAgent(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = QuerySynthesizerReport

    async def run(self, strategy: Strategy, **kwargs) -> QuerySynthesizerReport:
        triage_report = strategy.context.get("triage_report")
        if not triage_report:
            return self.create_report(
                errors=["Missing triage_report in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Query synthesis failed: Triage report not found."
            )

        log.info("Query Synthesizer: Generating search queries from triage report...")
        prompt = await self._build_prompt(triage_report)
        try:
            response = await self.orchestrator.call_llm_func(
                prompt, context="QuerySynthesizer")
            if response and "queries" in response:
                queries = response['queries']
                summary = f"Synthesized {len(queries)} search queries."
                log.success(summary)
                return self.create_report(queries=queries, summary=summary)
            else:
                log.warning("LLM did not return any search queries.")
                return self.create_report(
                    errors=["LLM did not return any search queries."],
                    error_type=ErrorType.LOGIC,
                    summary="Query synthesis failed: LLM returned no queries."
                )
        except Exception as e:
            error_msg = f"Failed to generate search queries: {e}"
            log.error(error_msg, exc_info=True)
            return self.create_report(
                errors=[error_msg],
                error_type=ErrorType.LOGIC,
                summary="Query synthesis failed due to an unexpected error."
            )

    async def _build_prompt(self, triage_report: TriageReport) -> str:
        """
        Builds a context-rich prompt for the LLM to generate search queries.
        """
        interesting_findings = triage_report.interesting_findings[:5]
        recon_data = await self.context_manager.get_context('recon_data')

        # Summarize key recon data
        tech_summary = []
        if recon_data and recon_data.whatweb_results:
            # A simple way to extract technologies from whatweb output
            for result in recon_data.whatweb_results:
                if "[" in result and "]" in result:
                    tech_summary.extend(re.findall(r'\[(.*?)\]', result))
        tech_summary = list(set(tech_summary))[:10]  # Unique, limited list

        port_summary = []
        if recon_data and recon_data.network_services:
            port_summary = [
                f"{s['port']}/{s['service']}" for s in recon_data.network_services[:10]]

        context_str = f"""
        **Key Technologies Detected:** {json.dumps(tech_summary) if tech_summary else 'N/A'}
        **Open Ports:** {json.dumps(port_summary) if port_summary else 'N/A'}"""

        interesting_findings_dicts = [
            {"finding": f.finding, "reasoning": f.reasoning}
            for f in interesting_findings
        ]

        return f"""
        As a master cybersecurity researcher, your task is to generate a list of effective search queries to find vulnerabilities and exploits based on the following intelligence report.

        --- INTELLIGENCE REPORT ---
        {context_str}
        **Interesting Findings (Priority):**
        ```json
        {json.dumps(interesting_findings_dicts, indent=2)}
        ```

        --- INSTRUCTIONS ---
        1.  Analyze all sections of the intelligence report.
        2.  Generate a list of 5-7 diverse and highly specific search queries.
        3.  Prioritize queries based on the technologies, versions, and specific findings.
        4.  Think creatively. Do not just search for CVEs. Generate queries that could find:
            - **Specific Version Exploits:** (e.g., "Apache 2.4.49 mod_cgi RCE")
            - **Default Credentials:** (e.g., "default password for Jenkins 2.2")
            - **Public Exploit Code:** (e.g., "GitHub PoC for CVE-2023-1234")
            - **Misconfiguration Guides:** (e.g., "how to exploit exposed .git folder")
        5.  Return ONLY a valid JSON object with a single key "queries", which is a list of strings.

        **IMPORTANT: Your response MUST be a valid JSON object and nothing else. Do not include any explanatory text before or after the JSON block.**

        **Example Response:**
        {{
            "queries": [
                "Apache 2.4.29 mod_ssl exploit",
                "CVE-2019-0211 poc",
                "vBulletin 5.x remote code execution",
                "Spring Boot Actuator vulnerability"
            ]
        }}"""

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute query synthesizer agent"""
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

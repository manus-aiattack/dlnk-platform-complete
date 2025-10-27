from core.data_models import Strategy, FuzzingReport, FuzzingFinding, AttackPhase, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import json
import re
from urllib.parse import urlparse, urljoin
import config
import os
import asyncio
import time

from core.base_agent import BaseAgent


class FuzzingAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = ["TriageAndResearch"]
    required_tools = ["curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = FuzzingReport # Set report class

    async def run(self, strategy: Strategy, **kwargs) -> FuzzingReport:
        start_time = time.time()
        log.phase("Fuzzing Agent: Starting Max-Intelligence fuzzing session...")

        target_url = strategy.context.get("target_url")
        if not target_url:
            end_time = time.time()
            return FuzzingReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Target URL not specified in the strategy context.",
                errors=["Agent requires 'target_url' in the context to run."],
                error_type=ErrorType.CONFIGURATION
            )

        generation_prompt = self._build_generation_prompt(target_url)
        llm_response = await self.orchestrator.call_llm_func(generation_prompt, context="FuzzingPayloadGeneration")

        payloads = llm_response.get('payloads', [])
        if not payloads:
            end_time = time.time()
            return FuzzingReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="LLM failed to generate any fuzzing payloads.",
                errors=["LLM did not provide any fuzzing payloads."],
                error_type=ErrorType.LOGIC
            )

        log.info(
            f"LLM generated {len(payloads)} payloads to test concurrently.")

        tasks = []
        for payload in payloads:
            if payload.startswith('?'):
                full_url = f"{target_url.rstrip('/')}{payload}"
            else:
                safe_payload = payload.lstrip('./')
                full_url = f"{target_url.rstrip('/')}/{safe_payload}"

            fuzz_domain = urlparse(full_url).netloc
            if fuzz_domain != urlparse(target_url).netloc:
                log.warning(
                    f"[Fuzzer] LLM generated an OFF-TARGET URL: '{full_url}'. Skipping.")
                continue

            command = f'curl -s -L -m 10 -w "\\nHTTP_STATUS:%{{http_code}}" "{full_url}"'
            tasks.append(self.orchestrator.run_shell_command(
                command, f"Fuzzing with payload: {payload}", use_proxy=True))

        fuzz_results = await asyncio.gather(*tasks)

        processed_results = []
        for i, result in enumerate(fuzz_results):
            response_body = result.get('stdout', '')
            status_code = -1
            match = re.search(r"HTTP_STATUS:(\d{3})$", response_body)
            if match:
                status_code = int(match.group(1))
                response_body = response_body[:match.start()].strip()

            processed_results.append({
                "payload": payloads[i],
                "status_code": status_code,
                "response_body_snippet": response_body[:300]
            })

        analysis_prompt = self._build_analysis_prompt(
            processed_results, target_url)
        llm_analysis = await self.orchestrator.call_llm_func(analysis_prompt, context="FuzzingAnalysis")

        if 'error' in llm_analysis:
            end_time = time.time()
            return FuzzingReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Fuzzing ran, but LLM analysis failed.",
                errors=[llm_analysis['error']],
                error_type=ErrorType.LOGIC
            )

        findings = [FuzzingFinding(**f)
                    for f in llm_analysis.get("findings", [])]
        summary = llm_analysis.get(
            "summary", "LLM analysis provided no summary.")

        log.success(summary)
        end_time = time.time()
        return FuzzingReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            summary=summary
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute fuzzing agent"""
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

    def _build_generation_prompt(self, target_url: str) -> str:
        return f"""
        You are a creative penetration tester specializing in fuzzing. Your task is to generate a diverse list of 15 fuzzing payloads for the target URL: {target_url}

        Generate payloads for a variety of common web vulnerabilities, including:
        - SQL Injection (SQLi)
        - Cross-Site Scripting (XSS)
        - Local File Inclusion (LFI)
        - Remote Code Execution (RCE)
        - Server-Side Template Injection (SSTI)

        Be creative. Think about bypassing simple filters. Use different cases, encodings, and techniques.

        Respond ONLY with a valid JSON object with a single key "payloads" which is a list of 15 strings.
        Example:
        {{
            "payloads": [
                "' OR 1=1--",
                "?page=../../../../etc/passwd",
                "<script>alert('XSS')</script>",
                "; ls -la",
                "{{{{7*7}}}}"
            ]
        }}"""

    def _build_analysis_prompt(self, results: list, target_url: str) -> str:
        results_str = json.dumps(results, indent=2)
        return f"""
        You are a senior security analyst. Your task is to analyze a batch of fuzzing results and identify potential vulnerabilities.

        Target URL: {target_url}

        **Fuzzing Results:**
        ```json
        {results_str}
        ```

        **Analysis Instructions:**
        1.  Review all payload-response pairs.
        2.  Look for anomalies: unexpected HTTP status codes (e.g., 500, 400, 200 when not expected), changes in response body length, error messages (SQL, PHP, etc.), or reflection of payload.
        3.  Group similar results and identify the most promising potential vulnerabilities.

        **Your Task:**
        Respond ONLY with a valid JSON object containing your overall summary and a list of structured findings.

        Response Format:
        {{
            "summary": "<A high-level summary of the findings>",
            "findings": [
                {{
                    "parameter": "<The FUZZed parameter/path>",
                    "payload_type": "<lfi|sqli|xss|rce|ssti|other>",
                    "description": "<Why you think this is a vulnerability>",
                    "raw_response": "<The anomalous response snippet>",
                    "severity": "<Low|Medium|High|Critical>",
                    "exploit_suggestion": "<A concrete next step for the ExploitAgent>"
                }}
            ]
        }}"""

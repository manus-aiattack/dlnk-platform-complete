from typing import List, Dict
from core.data_models import TelemetryReport, Strategy, AttackPhase, ErrorType
from core.logger import log
import re
import json
import asyncio
import time

from core.base_agent import BaseAgent


class TelemetryHunter(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = TelemetryReport

    async def _analyze_with_llm(self, log_content: str) -> List[Dict[str, str]]:
        """Analyzes log content with an LLM to find subtle anomalies."""
        log.info("Analyzing log file with LLM for subtle anomalies...")
        prompt = f"""
        You are a security expert analyzing a log file for suspicious activity.
        Review the following log entries and identify any potential security anomalies, such as:
        - Unusual access patterns (e.g., access at odd hours, repeated failed logins from one IP).
        - Reconnaissance activity (e.g., directory scanning, port scanning).
        - Attempts to access non-existent or sensitive files.
        - Any other behavior that deviates from the norm.

        **Log Entries (sample):**
        ```
        {log_content[:4000]} 
        ```

        **Your Task:**
        Return ONLY a valid JSON object with a single key "anomalies", which is a list of objects.
        Each object should have two keys: "type" (a short category for the anomaly) and "log_entry" (the full log line).

        Example Response:
        {{
            "anomalies": [
                {{
                    "type": "Repeated 404 Errors",
                    "log_entry": "192.168.1.10 - - [17/Oct/2025:10:20:30 +0000] \"GET /admin/config.php HTTP/1.1\" 404 209"
                }}
            ]
        }}"""
        try:
            response = await self.orchestrator.call_llm_func(prompt, context="TelemetryHunter")
            if response and "anomalies" in response and isinstance(response["anomalies"], list):
                log.success(
                    f"LLM analysis found {len(response['anomalies'])} potential anomalies.")
                return response["anomalies"]
        except Exception as e:
            log.error(f"LLM analysis failed during TelemetryHunter run: {e}")
        return []

    async def run(self, strategy: Strategy, **kwargs) -> TelemetryReport:
        start_time = time.time()
        """
        Analyzes log files for suspicious activity.
        """
        log_file_path = strategy.context.get("log_file_path")
        if not log_file_path:
            end_time = time.time()
            return TelemetryReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Log file path not provided.",
                errors=["Log file path not provided in strategy context."],
                error_type=ErrorType.CONFIGURATION
            )

        log.info(f"Telemetry Hunter: Analyzing log file: {log_file_path}")

        try:
            with open(log_file_path, 'r') as f:
                log_content = f.read()
        except FileNotFoundError:
            end_time = time.time()
            return TelemetryReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"Log file not found: {log_file_path}",
                errors=[f"Log file not found: {log_file_path}"],
                error_type=ErrorType.CONFIGURATION
            )
        except Exception as e:
            end_time = time.time()
            return TelemetryReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"Failed to read log file: {e}",
                errors=[f"Failed to read log file: {e}"],
                error_type=ErrorType.LOGIC
            )

        # LLM-based analysis for subtle anomalies
        llm_findings = await self._analyze_with_llm(log_content)

        if llm_findings:
            summary = f"Telemetry Hunter: Found {len(llm_findings)} potential suspicious log entries via LLM."
            log.success(summary)
        else:
            summary = "Telemetry Hunter: No suspicious log entries found via LLM."
            log.info(summary)

        end_time = time.time()
        return TelemetryReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            summary=summary,
            collected_data=llm_findings
        )

from core.data_models import ScannerReport, InterestingFinding, Strategy, AgentData, AttackPhase, ScannerReportAnalyzerReport, ErrorType
from core.logger import log
import json
import time

from core.base_agent import BaseAgent


class ScannerReportAnalyzer(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = ScannerReportAnalyzerReport

    async def run(self, strategy: Strategy, **kwargs) -> ScannerReportAnalyzerReport:
        start_time = time.time()
        scanner_report = strategy.context.get("scanner_report")
        if not scanner_report:
            end_time = time.time()
            return self.create_report(
                errors=["Missing scanner_report in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Scanner report analysis failed: No scanner report provided."
            )

        if not scanner_report.raw_report_path:
            summary = "No scanner report path provided to analyze."
            log.warning(f"[ScannerAnalyzer] {summary}")
            end_time = time.time()
            return self.create_report(
                errors=[summary],
                error_type=ErrorType.CONFIGURATION,
                summary=summary
            )

        report_file_path = scanner_report.raw_report_path
        log.info(
            f"[ScannerAnalyzer] Analyzing scanner report at: {report_file_path}")

        findings = []
        try:
            if "nuclei" in report_file_path:
                findings = await self._analyze_nuclei_report(report_file_path)
            elif "skipfish" in report_file_path:
                findings = self._analyze_skipfish_report(report_file_path)
            elif "burp" in report_file_path:
                findings = self._analyze_burp_report(report_file_path)
            elif "nmap" in report_file_path:
                findings = self._analyze_nmap_report(report_file_path)
            else:
                summary = f"Unknown scanner report type: {report_file_path}"
                log.warning(f"[ScannerAnalyzer] {summary}")
                end_time = time.time()
                return self.create_report(
                    errors=[summary],
                    error_type=ErrorType.LOGIC,
                    summary=summary
                )
        except Exception as e:
            error_msg = f"Error during report analysis: {e}"
            log.error(f"[ScannerAnalyzer] {error_msg}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[error_msg],
                error_type=ErrorType.LOGIC,
                summary=f"Scanner report analysis failed due to an unexpected error: {e}"
            )

        summary = f"Analyzed {report_file_path} and found {len(findings)} findings."
        end_time = time.time()
        return self.create_report(findings=findings, summary=summary)

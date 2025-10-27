import asyncio
import os
import re
from typing import List, Dict, Any, Optional
from core.base_agent import BaseAgent
from core.data_models import AgentData, CrashReport, Strategy, AttackPhase, ErrorType # Added ErrorType
from core.logger import log
from config import settings

class CrashAnalyzerAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.ESCALATION]
    required_tools = ["gdb", "objdump"] # Assuming GDB and objdump are available for analysis

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = CrashReport
        self.crash_analysis_dir = os.path.join(settings.WORKSPACE_DIR, "fuzzing_results", "crashes")
        os.makedirs(self.crash_analysis_dir, exist_ok=True)

    async def run(self, strategy: Strategy = None, **kwargs) -> CrashReport:
        fuzz_output_dir = strategy.context.get("fuzz_output_dir")
        target_binary = strategy.context.get("target_binary")

        if not fuzz_output_dir or not target_binary:
            return self.create_report(
                errors=["Missing 'fuzz_output_dir' or 'target_binary' in strategy context."],
                summary="CrashAnalyzerAgent requires fuzzing output directory and target binary.",
                error_type=ErrorType.CONFIGURATION
            )

        if not os.path.isdir(fuzz_output_dir):
            return self.create_report(
                errors=[f"Fuzz output directory not found: {fuzz_output_dir}"],
                summary=f"CrashAnalyzerAgent failed: Fuzz output directory {fuzz_output_dir} not found.",
                error_type=ErrorType.CONFIGURATION
            )
        if not os.path.exists(target_binary):
            return self.create_report(
                errors=[f"Target binary not found: {target_binary}"],
                summary=f"CrashAnalyzerAgent failed: Target binary {target_binary} not found.",
                error_type=ErrorType.CONFIGURATION
            )

        crashes_found = []
        crash_files = []
        
        # Look for crash files in the fuzzer output directory
        for root, _, files in os.walk(fuzz_output_dir):
            for file in files:
                if "id:" in file and "crash" in root: # AFL++ crash files are typically in 'crashes' subfolder
                    crash_files.append(os.path.join(root, file))
        
        if not crash_files:
            return self.create_report(
                summary=f"No crashes found in {fuzz_output_dir}.",
                target_binary=target_binary
            )

        log.info(f"CrashAnalyzerAgent: Found {len(crash_files)} potential crash files. Analyzing...")

        analysis_summary_lines = []
        for crash_file in crash_files:
            log.debug(f"Analyzing crash file: {crash_file}")
            analysis_output = await self._analyze_single_crash(target_binary, crash_file)
            
            crash_type = "Unknown"
            vulnerability_type = "Unknown"
            classification = "UNKNOWN"
            
            # Simple pattern matching for crash type and vulnerability
            if "Segmentation fault" in analysis_output:
                crash_type = "Segmentation Fault"
                vulnerability_type = "Memory Corruption"
            elif "Buffer overflow" in analysis_output:
                crash_type = "Buffer Overflow"
                vulnerability_type = "Memory Corruption"
            elif "double free" in analysis_output:
                crash_type = "Double Free"
                vulnerability_type = "Memory Corruption (Use-After-Free)"
            elif "heap-buffer-overflow" in analysis_output:
                crash_type = "Heap Buffer Overflow"
                vulnerability_type = "Memory Corruption"
            elif "stack-buffer-overflow" in analysis_output:
                crash_type = "Stack Buffer Overflow"
                vulnerability_type = "Memory Corruption"

            # Parse exploitability classification
            match = re.search(r"Exploitability Classification: (.*)", analysis_output)
            if match:
                classification = match.group(1).strip()
            
            analysis_summary_lines.append(f"Crash in {crash_file}: {crash_type} ({vulnerability_type}) - {classification}")
            analysis_summary_lines.append(analysis_output)

            crashes_found.append({
                "crash_file": crash_file,
                "crash_type": crash_type,
                "vulnerability_type": vulnerability_type,
                "classification": classification,
                "analysis_output": analysis_output
            })

        summary = f"Crash analysis completed for {target_binary}. Found {len(crashes_found)} crashes."
        return self.create_report(
            summary=summary,
            target_binary=target_binary,
            analysis_summary="\n".join(analysis_summary_lines),
            findings=crashes_found
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute crash analyzer agent"""
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

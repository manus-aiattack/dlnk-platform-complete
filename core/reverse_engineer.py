import logging
import re
from typing import List
from core.logger import log
from core.data_models import ReverseEngineeringReport, Strategy, AttackPhase, ErrorType
import r2pipe
import json
import asyncio
import time

from core.base_agent import BaseAgent


class ReverseEngineer(BaseAgent):
    supported_phases = [AttackPhase.TriageAndResearch]
    required_tools = ["radare2"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_class = ReverseEngineeringReport

    async def run(self, strategy: Strategy, **kwargs) -> ReverseEngineeringReport:
        """
        Performs reverse engineering on a binary to find symbolic execution targets.

        Args:
            strategy: The strategy object containing the path to the binary.

        Returns:
            A ReverseEngineeringReport containing the findings.
        """
        start_time = time.time()
        binary_path = strategy.context.get("binary_path")
        if not binary_path:
            end_time = time.time()
            return ReverseEngineeringReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Missing binary_path in context.",
                analysis_results=[],
                errors=["Missing binary_path in context."],
                error_type=ErrorType.CONFIGURATION
            )

        log.info(
            f"[ReverseEngineer] Starting static analysis on {binary_path}.")

        try:
            loop = asyncio.get_running_loop()
            r2 = await loop.run_in_executor(None, lambda: r2pipe.open(binary_path))
            await loop.run_in_executor(None, r2.cmd, 'aaa')  # Analyze all
            functions = await loop.run_in_executor(None, r2.cmdj, 'aflj')  # List functions in JSON

            if not functions:
                end_time = time.time()
                return ReverseEngineeringReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary="No functions found in binary.",
                    analysis_results=[],
                    errors=["No functions found in binary."],
                    error_type=ErrorType.LOGIC
                )

            # Expanded list of dangerous functions to detect a wider range of vulnerabilities
            DANGEROUS_FUNCTIONS = {
                # Buffer Overflows
                'strcpy': 'Buffer Overflow',
                'strcat': 'Buffer Overflow',
                'sprintf': 'Buffer Overflow',
                'gets': 'Buffer Overflow',
                'memcpy': 'Buffer Overflow (if size is not checked)',
                'read': 'Buffer Overflow (if count is not checked)',
                'wcsncpy': 'Buffer Overflow',
                'wcsncat': 'Buffer Overflow',
                'swprintf': 'Buffer Overflow',
                '_getws': 'Buffer Overflow',
                'wmemcpy': 'Buffer Overflow (if size is not checked)',

                # Format String
                'printf': 'Format String',
                'fprintf': 'Format String',
                'sprintf': 'Format String',
                'snprintf': 'Format String',
                'vprintf': 'Format String',
                'vfprintf': 'Format String',
                'vsprintf': 'Format String',
                'vsnprintf': 'Format String',

                # Command Injection
                'system': 'Command Injection',
                'exec': 'Command Injection',
                'popen': 'Command Injection',
                'shellexec': 'Command Injection',
                'ShellExecute': 'Command Injection',
                'CreateProcess': 'Command Injection',

                # Integer Overflow
                'malloc': 'Integer Overflow',
                'calloc': 'Integer Overflow',
                'realloc': 'Integer Overflow',

                # Path Traversal
                'fopen': 'Path Traversal',
                'open': 'Path Traversal',
                'CreateFile': 'Path Traversal'}

            vulnerable_functions = []
            for func in functions:
                # Deeper analysis: check cross-references to the function
                xrefs = await loop.run_in_executor(None, r2.cmdj, f'axtj @ {func["offset"]}')
                # Simple heuristic: more than 2 calls might mean it's a common utility function
                is_interesting = len(xrefs) > 2

                instructions = await loop.run_in_executor(None, r2.cmdj, f'pdfj @ {func["offset"]}')
                if instructions:
                    for ins in instructions.get('ops', []):
                        if ins.get('type') == 'call':
                            called_func_match = re.search(
                                r'sym\.imp\.(\w+)', ins.get('opcode', ''))
                            if called_func_match:
                                called_func_name = called_func_match.group(1)
                                if called_func_name in DANGEROUS_FUNCTIONS:
                                    vulnerability_type = DANGEROUS_FUNCTIONS[called_func_name]
                                    log.warning(
                                        f"[ReverseEngineer] Found potential '{vulnerability_type}' vulnerability in function '{func['name']}' due to call to '{called_func_name}' at {hex(ins['offset'])}")
                                    vulnerable_functions.append({
                                        "function_name": func['name'],
                                        "vulnerable_call": called_func_name,
                                        "vulnerability_type": vulnerability_type,
                                        "address": hex(ins['offset']),
                                        "is_interesting_by_xref": is_interesting
                                    })

            if vulnerable_functions:
                summary = f"Found {len(vulnerable_functions)} potentially vulnerable function calls."
                log.success(f"[ReverseEngineer] {summary}")
                end_time = time.time()
                return ReverseEngineeringReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=summary,
                    analysis_results=vulnerable_functions
                )
            else:
                summary = "No obvious vulnerabilities found."
                end_time = time.time()
                return ReverseEngineeringReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    summary=summary,
                    analysis_results=[]
                )

        except Exception as e:
            error_msg = f"Radare2 analysis failed: {e}"
            log.error(error_msg, exc_info=True)
            end_time = time.time()
            return ReverseEngineeringReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=error_msg,
                analysis_results=[],
                errors=[error_msg],
                error_type=ErrorType.LOGIC
            )

import asyncio
import os
import angr # Assuming angr is installed
import claripy
from typing import List, Dict, Any, Optional
from core.base_agent import BaseAgent
from core.data_models import AgentData, SymbolicExecutionReport, SymbolicExecutionFinding, Strategy, AttackPhase, ErrorType
from core.logger import log
from config import settings
import time

class SymbolicExecutorAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.ESCALATION]
    required_tools = ["angr"] # Requires angr Python library

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = SymbolicExecutionReport
        self.poc_output_dir = os.path.join(settings.WORKSPACE_DIR, "poc")
        os.makedirs(self.poc_output_dir, exist_ok=True)

    async def run(self, strategy: Strategy = None, **kwargs) -> SymbolicExecutionReport:
        start_time = time.time()
        target_binary = strategy.context.get("target_binary")
        vulnerability_type = strategy.context.get("vulnerability_type") # e.g., "Buffer Overflow"
        crash_input_path = strategy.context.get("crash_input_path") # Optional: path to a crashing input

        if not target_binary:
            end_time = time.time()
            return self.create_report(
                errors=["Missing 'target_binary' in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="SymbolicExecutorAgent requires a target binary."
            )

        if not os.path.exists(target_binary):
            end_time = time.time()
            return self.create_report(
                errors=[f"Target binary not found: {target_binary}"],
                error_type=ErrorType.CONFIGURATION,
                summary=f"SymbolicExecutorAgent failed: Target binary {target_binary} not found."
            )

        log.info(f"SymbolicExecutorAgent: Starting symbolic execution for {target_binary} (Vulnerability: {vulnerability_type or 'N/A'}).")

        try:
            loop = asyncio.get_running_loop()
            # Load the binary into Angr
            project = await loop.run_in_executor(None, lambda: angr.Project(target_binary, auto_load_libs=False))
            
            # Create an initial state
            # If a crash input is provided, we might want to start from that state
            if crash_input_path and os.path.exists(crash_input_path):
                with open(crash_input_path, 'rb') as f:
                    initial_input = f.read()
                state = await loop.run_in_executor(None, lambda: project.factory.entry_state(stdin=initial_input))
            else:
                state = await loop.run_in_executor(None, project.factory.entry_state)

            # Create a simulation manager
            simgr = await loop.run_in_executor(None, project.factory.simulation_manager, state)

            # Explore until a crash or a specific vulnerability pattern is found
            # This is a simplified example; real symbolic execution for PoC generation is complex
            # For a buffer overflow, we might look for states where the stack pointer is corrupted
            # or where an instruction pointer is controlled by symbolic input.
            
            # Run the simulation for a limited number of steps or until a specific condition
            await loop.run_in_executor(None, simgr.run, n=100) # Run for 100 steps

            vulnerabilities_found = []
            analysis_summary_lines = []

            if simgr.errored:
                for errored_state in simgr.errored:
                    error_type_str = str(errored_state.error)
                    analysis_summary_lines.append(f"Errored state found: {error_type_str}")
                    vulnerabilities_found.append(SymbolicExecutionFinding(
                        vulnerability_type="Crash/Error",
                        description=f"Symbolic execution led to an error: {error_type_str}",
                        severity="HIGH"
                    ))
            
            if simgr.deadended:
                analysis_summary_lines.append(f"Found {len(simgr.deadended)} deadended paths.")

            if vulnerabilities_found:
                summary = f"Symbolic execution found {len(vulnerabilities_found)} potential vulnerabilities."
                # Attempt to generate a PoC for the first finding
                poc_content = b""
                if crash_input_path: # If we started with a crash, the PoC is the crash input
                    poc_content = initial_input
                elif simgr.errored:
                    # Try to get a concrete input that leads to the error
                    # This is highly simplified; real PoC generation is complex
                    try:
                        concrete_input = errored_state.posix.stdin.load(0, errored_state.posix.stdin.size)
                        poc_content = await loop.run_in_executor(None, errored_state.solver.eval, concrete_input, cast_to=bytes)
                    except Exception as poc_e:
                        log.warning(f"Could not generate concrete PoC input: {poc_e}")
                        poc_content = b"Could not generate PoC."
                else:
                    poc_content = b"No specific PoC generated."

                poc_filename = f"poc_{os.path.basename(target_binary)}_{os.urandom(4).hex()}.bin"
                poc_filepath = os.path.join(self.poc_output_dir, poc_filename)
                with open(poc_filepath, 'wb') as f:
                    f.write(poc_content)
                
                analysis_summary_lines.append(f"Generated PoC at: {poc_filepath}")
                if vulnerabilities_found: # Ensure list is not empty before accessing
                    vulnerabilities_found[0].exploit_payload_hex = poc_content.hex() # Store hex representation
            else:
                summary = "Symbolic execution completed, no immediate vulnerabilities found."

            end_time = time.time()
            return self.create_report(
                summary=summary,
                target_binary=target_binary,
                vulnerabilities=vulnerabilities_found,
                analysis_summary="\n".join(analysis_summary_lines)
            )

        except ImportError:
            end_time = time.time()
            return self.create_report(
                errors=["angr library not found. Please install angr (pip install angr)."],
                error_type=ErrorType.CONFIGURATION,
                summary="SymbolicExecutorAgent failed: angr not installed."
            )
        except Exception as e:
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred during symbolic execution: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"SymbolicExecutorAgent failed due to unexpected error: {e}"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute symbolic executor agent"""
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

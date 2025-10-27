import angr
import logging
import claripy
from core.logger import log
from core.data_models import Strategy, SymbolicExecutionReport, SymbolicExecutionFinding, AttackPhase, ErrorType
import time

from core.base_agent import BaseAgent


class SymbolicExecutorAgent(BaseAgent):
    supported_phases = [AttackPhase.TriageAndResearch]
    required_tools = ["angr"]
    """An agent that performs symbolic execution to find exploitable paths."""

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = SymbolicExecutionReport

    async def run(self, strategy: Strategy, **kwargs) -> SymbolicExecutionReport:
        start_time = time.time()
        target_binary = strategy.context.get("target_binary")
        
        if not target_binary:
            end_time = time.time()
            return SymbolicExecutionReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="Missing target_binary in strategy context.",
                errors=["Missing target_binary in strategy context."],
                error_type=ErrorType.CONFIGURATION
            )

        log.phase(
            f"[SymbolicExecutorAgent] Starting symbolic execution on {target_binary}")

        try:
            project = angr.Project(target_binary, auto_load_libs=False)
            
            # Perform vulnerability analysis
            vulnerabilities = await self._analyze_vulnerabilities(project)
            
            # Generate a report of the findings
            report = self._generate_report(target_binary, vulnerabilities, start_time)
            
            return report

        except Exception as e:
            log.error(
                f"[SymbolicExecutorAgent] angr analysis failed: {e}", exc_info=True)
            end_time = time.time()
            return SymbolicExecutionReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target_binary=target_binary,
                summary=f"angr analysis failed: {e}",
                errors=[f"angr analysis failed: {e}"],
                error_type=ErrorType.LOGIC
            )

    async def _analyze_vulnerabilities(self, project):
        # TODO: Implement more sophisticated vulnerability analysis techniques
        
        # For now, we'll just look for unconstrained states
        simgr = project.factory.simulation_manager()
        simgr.run()
        
        vulnerabilities = []
        
        if simgr.unconstrained:
            log.info(
                f"Found {len(simgr.unconstrained)} unconstrained states. Checking for control of instruction pointer.")
            for state in simgr.unconstrained:
                if state.satisfiable():
                    log.success(
                        "Found a satisfiable state with RIP control!")
                    
                    # We'll assume this is a buffer overflow for now
                    finding = SymbolicExecutionFinding(
                        vulnerability_type="Buffer Overflow",
                        description="Found a path that allows for control of the instruction pointer.",
                        severity="CRITICAL",
                        exploit_payload_hex=None
                    )
                    vulnerabilities.append(finding)
                    
        return vulnerabilities

    def _generate_report(self, target_binary, vulnerabilities, start_time: float):
        end_time = time.time()
        if vulnerabilities:
            summary = f"Found {len(vulnerabilities)} potential vulnerabilities in {target_binary}."
            return SymbolicExecutionReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target_binary=target_binary,
                vulnerabilities=vulnerabilities,
                summary=summary
            )
        else:
            summary = f"No vulnerabilities found in {target_binary}."
            return SymbolicExecutionReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                target_binary=target_binary,
                summary=summary,
                errors=["No vulnerabilities found."],
                error_type=ErrorType.NO_VULNERABILITY_FOUND
            )

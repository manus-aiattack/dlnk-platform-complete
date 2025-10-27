from core.data_models import Strategy, ZeroDayReport, InterestingFinding, AttackPhase, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import time

import asyncio


from core.base_agent import BaseAgent


class ZeroDayHunterAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = ZeroDayReport

    async def run(self, strategy: Strategy, **kwargs) -> ZeroDayReport:
        start_time = time.time()
        log.info(
            "[ZeroDayHunter] Starting concurrent analysis for potential zero-day vulnerabilities...")

        recon_data = await self.context_manager.get_context('recon_data')
        if not recon_data:
            end_time = time.time()
            return ZeroDayReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="No reconnaissance data to analyze.",
                errors=["No reconnaissance data to analyze."],
                error_type=ErrorType.CONFIGURATION
            )

        tasks = []

        # 1. Gather binary analysis tasks
        binary_targets = strategy.context.get("binary_targets", [])
        if binary_targets:
            log.info(
                f"[ZeroDayHunter] Found {len(binary_targets)} potential binary targets. Creating ReverseEngineer tasks.")
            for binary_path in binary_targets:
                rev_eng_strategy = Strategy(
                    next_agent="ReverseEngineer",
                    directive=f"Analyze {binary_path} for potential vulnerabilities.",
                    context={"binary_path": binary_path}
                )
                tasks.append(
                    self.orchestrator.agents["ReverseEngineer"].run(rev_eng_strategy))

        # 2. Gather web fuzzing tasks
        has_web_ports = any(s['port'] in [80, 443, 8080, 8443]
                            for s in recon_data.network_services)
        if has_web_ports:
            log.info(
                "[ZeroDayHunter] Web ports detected. Creating FuzzingAgent task for web applications.")
            fuzzing_strategy = Strategy(
                next_agent="FuzzingAgent",
                directive="Devise and execute a web application fuzzing strategy.",
                context={"target_url": await self.context_manager.get_context('target_url'),
                         "fuzzing_type": "web"}
            )
            tasks.append(
                self.orchestrator.agents["FuzzingAgent"].run(fuzzing_strategy))

        # 3. Gather network service fuzzing tasks
        if recon_data.network_services:
            log.info(
                "[ZeroDayHunter] Creating FuzzingAgent tasks for network services.")
            for service in recon_data.network_services:
                if service['port'] not in [80, 443, 8080, 8443]:  # Don't re-fuzz web ports
                    fuzzing_strategy = Strategy(
                        next_agent="FuzzingAgent",
                        directive=f"Fuzz network service {service['service']} on port {service['port']}.",
                        context={
                            "target_host": await self.context_manager.get_context('target_host'),
                            "target_port": service['port'],
                            "fuzzing_type": "network"}
                    )
                    tasks.append(
                        self.orchestrator.agents["FuzzingAgent"].run(fuzzing_strategy))

        if not tasks:
            summary = "No clear targets for fuzzing or reverse engineering were identified."
            log.info(f"[ZeroDayHunter] {summary}")
            end_time = time.time()
            return ZeroDayReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                errors=[summary],
                error_type=ErrorType.NO_VULNERABILITY_FOUND
            )

        log.info(
            f"[ZeroDayHunter] Executing {len(tasks)} analysis tasks concurrently...")
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        for res in results:
            if isinstance(res, Exception):
                log.error(f"[ZeroDayHunter] A sub-agent task failed: {res}")
                continue
            if hasattr(res, 'findings') and res.findings:
                all_findings.extend(res.findings)

        if all_findings:
            summary = f"Zero-day hunting complete. Found {len(all_findings)} potential leads across all tasks."
            log.success(f"[ZeroDayHunter] {summary}")
            end_time = time.time()
            return ZeroDayReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                findings=all_findings
            )
        else:
            summary = "Concurrent analysis tasks completed, but no new vulnerabilities were found."
            log.info(f"[ZeroDayHunter] {summary}")
            end_time = time.time()
            return ZeroDayReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                errors=[summary],
                error_type=ErrorType.NO_VULNERABILITY_FOUND
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute zero day hunter agent"""
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

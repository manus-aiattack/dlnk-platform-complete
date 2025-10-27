import json
from core.data_models import AgentData, Strategy
import os
import re
import asyncio
from core.data_models import Strategy, HydraSuccessFinding, AgentData, AttackPhase, ErrorType
from core.logger import log
from config import settings
from typing import Optional
from core.database_manager import DatabaseManager

from core.base_agent import BaseAgent


class HydraAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["hydra"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.db_manager: Optional[DatabaseManager] = None
        self.report_class = AgentData # Default report class

    async def setup(self):
        """Asynchronous setup method for HydraAgent."""
        self.db_manager = await self.context_manager.get_context('db_manager')

    async def run(self, strategy: Strategy, **kwargs) -> AgentData:
        log.info("Running Hydra Agent...")

        target = await self.context_manager.get_context('target_host')
        port = strategy.context.get("port", 80)
        service = strategy.context.get("service", "http-get")

        # Try to get credentials from Redis
        usernames = await self.db_manager.redis.smembers(
            f"credentials:{target}:usernames")
        passwords = await self.db_manager.redis.smembers(
            f"credentials:{target}:passwords")

        if not usernames:
            log.info(
                "No usernames found in Redis. Falling back to default list from config.")
            usernames = settings.HYDRA_USERNAMES_LIST

        if not passwords:
            log.info(
                "No passwords found in Redis. Falling back to default list from config.")
            passwords = settings.HYDRA_PASSWORD_LIST

        log.info(
            f"Starting brute-force attack on {target}:{port} ({service} with {len(usernames)} usernames and {len(passwords)} passwords.")

        user_file = f"/tmp/hydra_users_{target}.txt"
        pass_file = f"/tmp/hydra_pass_{target}.txt"
        with open(user_file, "w") as f:
            f.write("\n".join(usernames))
        with open(pass_file, "w") as f:
            f.write("\n".join(passwords))

        hydra_command = f"hydra -L {user_file} -P {pass_file} -s {port} {target} {service}"

        log.info(f"Executing command: {hydra_command}")

        result = await self.orchestrator.run_shell_command(hydra_command, "Run Hydra brute-force attack.")

        os.remove(user_file)
        os.remove(pass_file)

        stdout = result.get("stdout", "")

        success_pattern = re.compile(
            r"host: (.*?) port: (.*?) login: (.*?) password: (.*)")
        successes = success_pattern.findall(stdout)

        if not successes:
            log.info("Hydra agent finished. No credentials found.")
            if self.orchestrator.heuristics_manager:
                self.orchestrator.heuristics_manager.add_failed_heuristic(
                    heuristic_type='bruteforce',
                    key=f"{service}://{target}:{port}",
                    strategy=strategy.model_dump(),
                    report={"errors": ["Hydra found no credentials."]}
                )
            return self.create_report(summary="No credentials found.", errors=["Hydra found no credentials."], error_type=ErrorType.LOGIC)

        findings = []
        for host, port, login, password in successes:
            finding = HydraSuccessFinding(
                host=host,
                port=int(port),
                service=service,
                username=login,
                password=password
            )
            findings.append(finding)

            finding_key = f"finding:hydra_success:{host}:{port}:{login}"
            await self.db_manager.log_agent_action(
                cycle_id=await self.context_manager.get_context('cycle_id'),
                agent_name="HydraAgent",
                action_summary=f"Found credentials: {login}:{password} on {host}:{port}",
                report_data=finding.model_dump(),
                finding_key=finding_key
            )

            if self.orchestrator.heuristics_manager:
                self.orchestrator.heuristics_manager.add_heuristic(
                    heuristic_type='bruteforce',
                    key=f"{service}://{host}:{port}",
                    strategy=strategy.model_dump(),
                    report=finding.model_dump()
                )

            log.success(
                f"Found credentials: {login}:{password} on {host}:{port}")

        log.info("Hydra agent finished.")
        return self.create_report(findings=findings, summary=f"Found {len(findings)} new credentials.")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute hydra agent"""
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

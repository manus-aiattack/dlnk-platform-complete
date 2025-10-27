import os
from core.data_models import AgentData, Strategy
import sys
import shutil
from config import settings
from core.logger import log
from core.redis_client import get_redis_client
from core.data_models import HealthReport, ErrorType, Strategy
from core.base_agent import BaseAgent
import asyncio
import time
from typing import List


class HealthCheckAgent(BaseAgent):
    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.tool_paths = {
            "NUCLEI": settings.NUCLEI_PATH,
            "SUBFINDER": settings.SUBFINDER_PATH,
            "THEHARVESTER": settings.THEHARVESTER_PATH,
            "DIRSEARCH": settings.DIRSEARCH_PATH,
            "NMAP": settings.NMAP_PATH,
            "FFUF": settings.FFUF_PATH,
            "GITLEAKS": settings.GITLEAKS_PATH,
            "TESTSSL": settings.TESTSSL_PATH,
            "HYDRA": settings.HYDRA_PATH,
            "JWTTOOL": settings.JWTTOOL_PATH,
            "DALFOX": settings.DALFOX_PATH,
            "COMMIX": settings.COMMIX_PATH,
            "KATANA": settings.KATANA_PATH,
            "SQLMAP": settings.SQLMAP_PATH,
            "WPSCAN": settings.WPSCAN_PATH,
            "FIREJAIL": "firejail"
        }
        self.report_class = HealthReport

    async def setup(self):
        pass # No specific async setup needed for this agent

    async def _check_tools(self) -> List[str]:
        log.info("HealthCheck: Verifying external tool paths...")
        errors = []
        for tool, path in self.tool_paths.items():
            full_path = shutil.which(path)
            if not full_path:
                error_msg = f"Tool {tool} not found in PATH. Searched for: '{path}'"
                errors.append(error_msg)
                log.error(f"[FAIL] {tool:<25} | NOT FOUND at path {path}")
            elif not os.access(full_path, os.X_OK):
                error_msg = f"Tool {tool} found at {full_path} but is not executable. Please run 'chmod +x {full_path}'"
                errors.append(error_msg)
                log.error(f"[FAIL] {tool:<25} | NOT EXECUTABLE at path {full_path}")
            else:
                log.success(f"[PASS] {tool:<25} | OK")
        return errors

    async def _check_services(self) -> List[str]:
        log.info("HealthCheck: Verifying external service connections...")
        errors = []
        # Check Redis
        try:
            redis_client_instance = await get_redis_client()
            if redis_client_instance and await redis_client_instance.ping():
                log.success(f"[PASS] {'Redis':<25} | OK")
            else:
                raise ConnectionError("Ping failed")
        except ConnectionError as e:
            error_msg = f"Redis connection failed: {e}"
            errors.append(error_msg)
            log.error(f"[FAIL] {'Redis':<25} | UNAVAILABLE")

        # Add other service checks here (e.g., Metasploit, GVM) in the future
        # Check Metasploit
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            client = MsfRpcClient(
                host=settings.MSF_RPC_HOST,
                port=settings.MSF_RPC_PORT,
                user=settings.MSF_RPC_USER,
                password=settings.MSF_RPC_PASS,
                ssl=False
            )
            # The client is authenticated on instantiation, so we can just check the connection
            if client.authenticated:
                log.success(f"[PASS] {'Metasploit':<25} | OK")
            else:
                raise ConnectionError("Authentication failed")
        except Exception as e:
            error_msg = f"Metasploit connection failed: {e}"
            errors.append(error_msg)
            log.error(f"[FAIL] {'Metasploit':<25} | UNAVAILABLE")
        return errors

    async def run(self, strategy: Strategy = None, **kwargs) -> HealthReport:
        log.phase("HealthCheckAgent: Running system health checks...")
        all_errors = []

        tool_errors = await self._check_tools()
        all_errors.extend(tool_errors)

        service_errors = await self._check_services()
        all_errors.extend(service_errors)

        if all_errors:
            summary = "System health check failed. Some dependencies are not met."
            log.critical("--- [PRE-FLIGHT CHECK] RESULT: FAILED ---")
            for err in all_errors:
                log.critical(err)
            return self.create_report(
                errors=all_errors,
                error_type=ErrorType.CONFIGURATION,
                summary=summary
            )
        else:
            summary = "System health check passed. All dependencies are met."
            log.success("--- [PRE-FLIGHT CHECK] RESULT: PASSED ---")
            return self.create_report(
                summary=summary
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute health check agent"""
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

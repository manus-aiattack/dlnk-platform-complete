from core.data_models import Strategy, AuthReport, AuthFinding, AttackPhase, ReconData, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import json
import re
from urllib.parse import urlparse, urljoin
import os
import asyncio
from typing import Optional

from core.base_agent import BaseAgent


class Auth_Agent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["jwt_tool", "hydra"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.recon_data: Optional[ReconData] = None
        self.report_class = AuthReport # Set report class

    async def setup(self):
        """Asynchronous setup method for Auth_Agent."""
        self.recon_data = await self.context_manager.get_context('recon_data')

    async def run(self, strategy: Strategy = None, **kwargs) -> AuthReport:
        log.info("Auth Agent: Starting authentication bypass analysis")
        
        vulnerabilities = []
        errors = []
        
        try:
            # Find login pages
            login_pages = self._find_login_pages()
            
            # Test authentication bypass techniques
            for page in login_pages:
                # Test default credentials
                # Test SQL injection in auth
                # Test authentication bypass
                self.log(f"{self.__class__.__name__} method called")
                            
            return self.create_report(
                summary=f"Auth Agent completed. Found {len(login_pages)} login pages.",
                vulnerabilities=vulnerabilities,
                errors=errors
            )
        except Exception as e:
            log.error(f"Auth Agent error: {e}")
            return self.create_report(
                summary="Auth Agent encountered an error.",
                errors=[str(e)],
                error_type=ErrorType.RUNTIME
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute auth agent"""
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

    def _find_login_pages(self) -> list:
        log.info("Auth Agent: Searching for login pages...")
        login_pages = []
        keywords = ['login', 'signin', 'auth', 'account', 'panel', 'admin']
        if not self.recon_data or not self.recon_data.http_servers:
            return []
        for url in self.recon_data.http_servers:
            if any(keyword in url.lower() for keyword in keywords):
                login_pages.append(url)
        return login_pages

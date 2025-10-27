from core.data_models import Strategy, BOLAReport, BOLAFinding, AttackPhase, ReconData, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import re
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
import asyncio
from typing import Optional
import time

from core.base_agent import BaseAgent


class BOLA_Agent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.recon_data: Optional[ReconData] = None
        self.report_class = BOLAReport # Set report class

    async def setup(self):
        """Asynchronous setup method for BOLA_Agent."""
        self.recon_data = await self.context_manager.get_context('recon_data')

    async def _run_command(self, command: str, description: str) -> dict:
        log.info(f"Executing: {description}")
        result = await self.orchestrator.run_shell_command(command, description)
        if result and result.get('exit_code') == 0:
            log.success(f"{description} completed.")
            return result
        else:
            log.error(
                f"{description} failed. Stderr: {result.get('stderr', 'N/A')}")
            return result

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute bola agent"""
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

    def _find_potential_bola_params(self, url: str) -> list:
        """Analyzes a URL to find parameters that look like object identifiers (integers or UUIDs)."""
        params = []
        uuid_regex = re.compile(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)

        # 1. Check query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for name, values in query_params.items():
            value = values[0]
            if value.isdigit():
                params.append({'type': 'query', 'name': name,
                              'value': value, 'index': None})
            elif uuid_regex.match(value):
                params.append({'type': 'query', 'name': name,
                              'value': value, 'index': None})

        # 2. Check path parameters
        path_parts = parsed_url.path.strip('/').split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit():
                params.append(
                    {'type': 'path', 'name': f'path_{i}', 'value': part, 'index': i})
            elif uuid_regex.match(part):
                params.append(
                    {'type': 'path', 'name': f'path_{i}', 'value': part, 'index': i})

        if params:
            log.info(f"Found {len(params)} potential BOLA parameters in {url}")
        return params

    async def _check_single_param(self, url: str, param: dict):
        original_value = param['value']
        test_value = ""
        if original_value.isdigit():
            test_value = str(int(original_value) + 1)
        else:  # Simple UUID tweak
            test_value = list(original_value)
            if len(test_value) > 0:
                test_value[0] = 'a' if test_value[0] != 'a' else 'b'
                test_value = "".join(test_value)
            else:
                return None

        if not test_value:
            return None

        parsed_url = urlparse(url)
        if param['type'] == 'path':
            path_parts = parsed_url.path.split('/')
            path_parts[param['index']] = test_value
            new_path = '/'.join(path_parts)
            test_url = urlunparse(parsed_url._replace(path=new_path))
        else:  # query
            query_params = parse_qs(parsed_url.query)
            query_params[param['name']] = [test_value]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed_url._replace(query=new_query))

        original_cmd = f"curl -s -o /dev/null -w '%{{http_code}}:%{{size_download}}' \"{url}\""
        test_cmd = f"curl -s -o /dev/null -w '%{{http_code}}:%{{size_download}}' \"{test_url}\""

        original_result_task = self._run_command(
            original_cmd, f"Getting baseline for {url}")
        test_result_task = self._run_command(
            test_cmd, f"Testing BOLA on {test_url}")

        original_result, test_result = await asyncio.gather(original_result_task, test_result_task)

        if not original_result or original_result.get('exit_code') != 0 or not test_result or test_result.get('exit_code') != 0:
            return None

        original_code, original_size_str = original_result.get(
            'stdout', ':').split(':')
        test_code, test_size_str = test_result.get('stdout', ':').split(':')

        try:
            original_size = int(original_size_str)
            test_size = int(test_size_str)
        except ValueError:
            return None  # Could not parse size

        if test_code == original_code and test_code.startswith('2') and abs(original_size - test_size) < 100:
            reason = f"Received status {test_code} with a similar content size ({test_size} bytes) as the original request ({original_size} bytes) when accessing a different object ID."
            log.warning(f"Potential BOLA vulnerability found at {url}")
            return BOLAFinding(
                vulnerable_url=url,
                parameter_type=param['type'],
                parameter_name=param['name'],
                original_value=original_value,
                test_payload=test_value,
                reasoning=reason
            )
        return None

    async def run(self, strategy: Strategy, **kwargs) -> BOLAReport:
        start_time = time.time()
        log.phase("BOLA Agent: Starting Broken Object Level Authorization scan...")
        
        if not self.recon_data or not self.recon_data.http_servers:
            end_time = time.time()
            return BOLAReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="No HTTP servers found in reconnaissance data to test for BOLA.",
                errors=["Reconnaissance data missing or no HTTP servers found."],
                error_type=ErrorType.CONFIGURATION
            )

        targets = self.recon_data.http_servers
        tasks = []

        for url in targets:
            potential_params = self._find_potential_bola_params(url)
            for param in potential_params:
                tasks.append(self._check_single_param(url, param))

        if not tasks:
            end_time = time.time()
            return BOLAReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="No potential BOLA parameters found in any of the target URLs.",
                errors=[],
                error_type=ErrorType.UNKNOWN
            )

        log.info(
            f"Checking {len(tasks)} potential BOLA parameters concurrently...")
        results = await asyncio.gather(*tasks)

        findings = [finding for finding in results if finding]
        
        end_time = time.time()
        if findings:
            summary = f"Found {len(findings)} potential BOLA vulnerabilities."
            log.success(summary)
            return BOLAReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                findings=findings
            )
        else:
            summary = "No obvious BOLA vulnerabilities found."
            log.info(summary)
            return BOLAReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                findings=[]
            )

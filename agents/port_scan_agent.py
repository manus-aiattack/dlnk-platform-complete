import asyncio
import time
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, PortScanReport, ErrorType
from core.logger import log


class PortScanAgent(BaseAgent):
    """
    Performs an asynchronous port scan using the nmap command-line tool.
    """
    required_tools = ["nmap"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubsub_manager = self.orchestrator.pubsub_manager
        self.report_class = PortScanReport

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute port scan agent"""
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

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parses Nmap XML output into a structured list of dictionaries."""
        scan_results = []
        try:
            root = ET.fromstring(xml_output)
            for host in root.findall('host'):
                host_ip = host.find('address').get('addr')
                host_info = {
                    "host": host_ip,
                    "status": host.find('status').get('state'),
                    "open_ports": []
                }
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        if port.find('state').get('state') == 'open':
                            service = port.find('service')
                            port_info = {
                                "port": int(port.get('portid')),
                                "name": service.get('name', '') if service is not None else '',
                                "product": service.get('product', '') if service is not None else '',
                                "version": service.get('version', '') if service is not None else ''
                            }
                            host_info["open_ports"].append(port_info)
                scan_results.append(host_info)
        except ET.ParseError as e:
            log.error(f"PortScanAgent: Failed to parse Nmap XML: {e}")
        return scan_results

    async def run(self, strategy: Strategy) -> PortScanReport:
        start_time = time.time()
        target_host = strategy.context.get("target_host")
        if not target_host:
            end_time = time.time()
            return self.create_report(
                start_time=start_time,
                end_time=end_time,
                errors=["Target host not specified for PortScanAgent."],
                error_type=ErrorType.CONFIGURATION,
                summary="Port scan failed: Target host not specified."
            )

        log.info(f"PortScanAgent: Starting Nmap scan on {target_host}...")

        # -sS: SYN scan, -sV: Version detection, -O: OS detection, -oX -: XML output to stdout
        nmap_command = ["nmap", "-sS", "-sV", "-O", "-p", "1-1000", "-oX", "-", target_host]

        try:
            process = await asyncio.create_subprocess_exec(
                *nmap_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)  # 5-minute timeout

            stdout_str = stdout.decode(errors='ignore')
            stderr_str = stderr.decode(errors='ignore')

            if process.returncode != 0:
                error_message = f"Nmap scan failed with exit code {process.returncode}. Stderr: {stderr_str}"
                log.error(f"PortScanAgent: {error_message}")
                end_time = time.time()
                return self.create_report(
                    start_time=start_time,
                    end_time=end_time,
                    errors=[error_message],
                    error_type=ErrorType.LOGIC,
                    summary=f"Nmap scan failed for {target_host}."
                )

            scan_results = self._parse_nmap_xml(stdout_str)
            open_ports_count = sum(len(host.get("open_ports", [])) for host in scan_results)

            summary = f"Nmap scan on {target_host} completed. Found {open_ports_count} open ports."
            log.success(f"PortScanAgent: {summary}")

            # Publish scan results
            await self.pubsub_manager.publish(
                "port_scan_results",
                {
                    "agent": self.__class__.__name__,
                    "target_host": target_host,
                    "results": scan_results,
                    "timestamp": time.time()
                }
            )

            end_time = time.time()
            return self.create_report(
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                scan_results=scan_results
            )

        except asyncio.TimeoutError:
            log.error(f"PortScanAgent: Nmap scan on {target_host} timed out.")
            end_time = time.time()
            return self.create_report(
                start_time=start_time,
                end_time=end_time,
                errors=["Nmap scan timed out after 5 minutes."],
                error_type=ErrorType.TIMEOUT,
                summary=f"Nmap scan on {target_host} timed out."
            )
        except FileNotFoundError:
            log.error("PortScanAgent: 'nmap' command not found. Is nmap installed and in the system's PATH?")
            end_time = time.time()
            return self.create_report(
                start_time=start_time,
                end_time=end_time,
                errors=["'nmap' command not found."],
                error_type=ErrorType.CONFIGURATION,
                summary="Port scan failed: nmap is not installed."
            )
        except Exception as e:
            log.error(f"PortScanAgent: An unexpected error occurred: {e}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                start_time=start_time,
                end_time=end_time,
                errors=[f"An unexpected error occurred: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Port scan failed due to an unexpected error: {e}"
            )

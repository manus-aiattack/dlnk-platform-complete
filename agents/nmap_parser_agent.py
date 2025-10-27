
from defusedxml import ElementTree as ET
from core.data_models import AgentData, Strategy
from core.data_models import NmapServiceFinding, AgentData, AttackPhase, Strategy, NmapParserReport, ErrorType
from core.logger import log
from typing import Optional
from core.database_manager import DatabaseManager
import time

from core.base_agent import BaseAgent


class NmapParserAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.db_manager: Optional[DatabaseManager] = None
        self.report_class = NmapParserReport # Set report class

    async def setup(self):
        """Asynchronous setup method for NmapParserAgent."""
        self.db_manager = await self.context_manager.get_context('db_manager')

    async def run(self, strategy: Strategy, **kwargs) -> AgentData:
        start_time = time.time()
        xml_file = strategy.context.get("xml_file")
        if not xml_file:
            end_time = time.time()
            return NmapParserReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Missing xml_file in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Nmap parsing failed: XML file not provided."
            )

        log.info(f"Running Nmap Parser Agent on {xml_file}...")

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            log.error(f"Failed to parse Nmap XML file: {e}")
            end_time = time.time()
            return NmapParserReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[f"Failed to parse Nmap XML file: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Nmap parsing failed: {e}"
            )

        findings = []
        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            for port in host.findall('.//port'):
                port_id = int(port.get('portid'))
                protocol = port.get('protocol')
                state = port.find('state').get('state')

                if state == 'open':
                    service_element = port.find('service')
                    service = service_element.get(
                        'name', '') if service_element is not None else ''
                    product = service_element.get(
                        'product', '') if service_element is not None else ''
                    version = service_element.get(
                        'version', '') if service_element is not None else ''

                    finding = NmapServiceFinding(
                        host=ip_address,
                        port=port_id,
                        protocol=protocol,
                        service=service,
                        product=product,
                        version=version
                    )
                    findings.append(finding)

                    finding_key = f"finding:nmap_service:{ip_address}:{port_id}"
                    await self.db_manager.log_agent_action(
                        cycle_id=await self.context_manager.get_context('cycle_id'),
                        agent_name="NmapParserAgent",
                        action_summary=f"Found open port: {ip_address}:{port_id} ({service} {product} {version}",
                        report_data=finding.model_dump(),
                        finding_key=finding_key
                    )
                    log.success(
                        f"Found open port: {ip_address}:{port_id} ({service} {product} {version}")

        log.info("Nmap Parser Agent finished.")
        end_time = time.time()
        return NmapParserReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            summary=f"Parsed {len(findings)} open ports."
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute nmap parser agent"""
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

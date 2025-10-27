"""
AI Network Scanner Agent
AI-driven network reconnaissance and scanning with intelligent target analysis
"""
import asyncio
import nmap
import socket
import subprocess
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy


@dataclass
class NetworkFinding:
    """Network discovery finding"""
    ip: str
    hostname: Optional[str] = None
    open_ports: List[int] = None
    services: List[Dict[str, Any]] = None
    os_fingerprint: Optional[str] = None
    confidence: float = 0.0


class NetworkScannerAgent(BaseAgent):
    """AI Network Scanner Agent for comprehensive network reconnaissance"""

    def __init__(self):
        super().__init__()
        self.nm = nmap.PortScanner()
        self.findings: List[NetworkFinding] = []

    async def setup(self):
        """Initialize network scanner"""
        await super().setup()
        self.logger.info("AI Network Scanner Agent initialized")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute AI-driven network scanning"""
        try:
            target = strategy.context.get('target_host', '127.0.0.1')
            scan_type = strategy.context.get('scan_type', 'intense')

            self.logger.info(f"Starting AI network scan for target: {target}")

            # AI analysis of target for optimal scan strategy
            scan_strategy = await self._analyze_scan_strategy(target, scan_type)

            # Execute intelligent scanning
            results = await self._execute_intelligent_scan(target, scan_strategy)

            # AI analysis of scan results
            analysis = await self._analyze_network_findings(results)

            return AgentData(
                agent_name="NetworkScannerAgent",
                success=True,
                summary=f"Network scan completed for {target}",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={
                    'target': target,
                    'scan_type': scan_type,
                    'findings': analysis,
                    'raw_results': results
                }
            )

        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
            return AgentData(
                agent_name="NetworkScannerAgent",
                success=False,
                summary="Network scan failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'target': strategy.context.get('target_host')}
            )

    async def _analyze_scan_strategy(self, target: str, scan_type: str) -> Dict[str, Any]:
        """AI analysis to determine optimal scan strategy"""
        try:
            # AI analysis of target characteristics
            target_analysis = await self._ai_analyze_target(target)

            # Determine optimal scan parameters based on target analysis
            if scan_type == 'stealth':
                return {
                    'timing': 0,  # Slowest timing
                    'ports': '21,22,23,25,53,80,110,143,443,993,995',
                    'options': ['-sS', '-T0', '-n']
                }
            elif scan_type == 'intense':
                return {
                    'timing': 4,  # Aggressive timing
                    'ports': '1-10000',
                    'options': ['-sS', '-A', '-T4']
                }
            else:  # balanced
                return {
                    'timing': 2,
                    'ports': '1-1000',
                    'options': ['-sS', '-sV', '-O', '-T2']
                }

        except Exception as e:
            self.logger.warning(f"AI scan strategy analysis failed: {e}")
            # Fallback to default strategy
            return {
                'timing': 2,
                'ports': '1-1000',
                'options': ['-sS', '-sV', '-T2']
            }

    async def _ai_analyze_target(self, target: str) -> Dict[str, Any]:
        """AI analysis of target to determine optimal scanning approach"""
        try:
            # Use AI to analyze target characteristics
            # This would typically use an LLM for intelligent analysis
            prompt = f"""
            Analyze target '{target}' for network scanning optimization:

            Provide:
            1. Recommended scan timing (0-5, where 0=slowest, 5=fastest)
            2. Priority ports to scan based on target type
            3. Recommended scan techniques (stealth, aggressive, etc.)
            4. Expected challenges and mitigation

            Focus on maximizing discovery while minimizing detection.
            """

            # Mock AI response for now - would integrate with actual LLM
            return {
                'scan_timing': 2,
                'priority_ports': [22, 80, 443, 3389, 8080],
                'scan_technique': 'balanced',
                'expected_challenges': ['firewall_detection', 'IDS_alerts'],
                'mitigation_strategies': ['timing_control', 'fragmentation']
            }

        except Exception as e:
            self.logger.warning(f"Target analysis failed: {e}")
            return {'scan_timing': 2, 'priority_ports': [80, 443]}

    async def _execute_intelligent_scan(self, target: str, scan_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Execute intelligent network scan with AI optimization"""
        try:
            # Build nmap command
            cmd = ['nmap']
            cmd.extend(scan_strategy['options'])
            cmd.extend(['-p', scan_strategy['ports']])
            cmd.append(target)

            self.logger.info(f"Executing scan: {' '.join(cmd)}")

            # Execute scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                # Parse nmap results
                return self._parse_nmap_output(result.stdout)
            else:
                self.logger.error(f"Scan failed: {result.stderr}")
                return {'error': result.stderr}

        except subprocess.TimeoutExpired:
            self.logger.error("Scan timed out")
            return {'error': 'Scan timeout'}
        except Exception as e:
            self.logger.error(f"Scan execution failed: {e}")
            return {'error': str(e)}

    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output into structured data"""
        try:
            # Parse nmap XML output if available
            # For now, return basic parsing
            return {
                'raw_output': output,
                'parsed': True,
                'hosts_found': self._extract_hosts_from_output(output)
            }
        except Exception as e:
            self.logger.error(f"Output parsing failed: {e}")
            return {'raw_output': output, 'parsed': False}

    def _extract_hosts_from_output(self, output: str) -> List[Dict[str, Any]]:
        """Extract host information from nmap output"""
        hosts = []
        lines = output.split('\n')

        current_host = None
        for line in lines:
            if line.startswith('Nmap scan report for'):
                if current_host:
                    hosts.append(current_host)
                current_host = {'host': line.split()[-1], 'ports': []}
            elif current_host and line.strip().startswith('open'):
                port_info = line.strip().split()
                if len(port_info) >= 3:
                    current_host['ports'].append({
                        'port': port_info[0].split('/')[0],
                        'protocol': port_info[0].split('/')[1] if '/' in port_info[0] else 'tcp',
                        'service': port_info[2] if len(port_info) > 2 else 'unknown'
                    })

        if current_host:
            hosts.append(current_host)

        return hosts

    async def _analyze_network_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI analysis of network scan findings"""
        try:
            findings = []

            if 'hosts_found' in scan_results:
                for host in scan_results['hosts_found']:
                    # AI analysis of each host
                    host_analysis = await self._ai_analyze_host(host)
                    findings.append({
                        'host': host['host'],
                        'analysis': host_analysis,
                        'recommendations': await self._generate_host_recommendations(host)
                    })

            return findings

        except Exception as e:
            self.logger.error(f"Finding analysis failed: {e}")
            return []

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's main functionality"""
        strategy = Strategy(
            phase=AttackPhase.RECONNAISSANCE,
            directive='Network scanning execution',
            next_agent='protocol_fuzzer',
            context=context,
            objectives=['discover_hosts', 'identify_services']
        )
        result = await self.execute(strategy)
        return {
            'success': result.success,
            'summary': result.summary,
            'findings': result.context.get('findings', []),
            'raw_results': result.context.get('raw_results', {})
        }

    async def _ai_analyze_host(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """AI analysis of individual host"""
        try:
            # Mock AI analysis - would use actual LLM integration
            open_ports = len(host.get('ports', []))

            # Analyze services for common vulnerabilities
            common_vulnerable_services = any(
                port.get('service', '').lower() in ['ssh', 'ftp', 'telnet', 'smb', 'http', 'https']
                for port in host.get('ports', [])
            )

            return {
                'open_port_count': open_ports,
                'service_diversity': len(set(p.get('service', '') for p in host.get('ports', []))),
                'risk_level': 'high' if open_ports > 5 else 'medium' if open_ports > 2 else 'low',
                'exploitation_potential': 'high' if common_vulnerable_services else 'medium',
                'recommended_next_steps': ['vulnerability_scan', 'service_analysis']
            }

        except Exception as e:
            self.logger.warning(f"Host analysis failed: {e}")
            return {'error': 'Analysis failed'}

    async def _generate_host_recommendations(self, host: Dict[str, Any]) -> List[str]:
        """Generate AI recommendations for host exploitation"""
        try:
            recommendations = []
            ports = host.get('ports', [])

            # Analyze services for recommendations
            for port in ports:
                service = port.get('service', '').lower()
                port_num = port.get('port', '')

                if service in ['ssh', 'telnet'] and port_num in ['22', '23']:
                    recommendations.append('Attempt credential brute force')
                elif service in ['http', 'https'] and port_num in ['80', '443']:
                    recommendations.append('Web application security testing')
                elif service == 'smb' and port_num == '445':
                    recommendations.append('SMB vulnerability assessment')
                elif service == 'rdp' and port_num == '3389':
                    recommendations.append('RDP security assessment')

            return list(set(recommendations))  # Remove duplicates

        except Exception as e:
            self.logger.warning(f"Recommendation generation failed: {e}")
            return ['Manual analysis required']
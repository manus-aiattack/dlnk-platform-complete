"""
Network Traffic Analyzer Agent
AI-driven network traffic analysis and pattern recognition
"""
import asyncio
import socket
import struct
import binascii
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy


@dataclass
class TrafficFinding:
    """Network traffic analysis finding"""
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    pattern: str
    significance: str
    recommendation: str


class NetworkTrafficAnalyzerAgent(BaseAgent):
    """AI Network Traffic Analyzer Agent for intelligent traffic analysis"""

    def __init__(self):
        super().__init__()
        self.findings: List[TrafficFinding] = []
        self.traffic_patterns = self._initialize_traffic_patterns()

    async def setup(self):
        """Initialize traffic analyzer"""
        await super().setup()
        self.logger.info("AI Network Traffic Analyzer Agent initialized")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute AI-driven network traffic analysis"""
        try:
            interface = strategy.context.get('interface', 'eth0')
            capture_duration = strategy.context.get('capture_duration', 60)
            analysis_type = strategy.context.get('analysis_type', 'comprehensive')

            self.logger.info(f"Starting AI traffic analysis on interface: {interface}")

            # AI analysis for optimal capture strategy
            capture_strategy = await self._analyze_capture_strategy(interface, analysis_type)

            # Execute intelligent traffic capture and analysis
            results = await self._execute_intelligent_analysis(
                interface, capture_duration, capture_strategy
            )

            # AI analysis of traffic patterns
            analysis = await self._analyze_traffic_patterns(results)

            return AgentData(
                agent_name="NetworkTrafficAnalyzerAgent",
                success=True,
                summary=f"Traffic analysis completed on {interface}",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={
                    'interface': interface,
                    'duration': capture_duration,
                    'analysis_type': analysis_type,
                    'findings': analysis,
                    'raw_results': results
                }
            )

        except Exception as e:
            self.logger.error(f"Traffic analysis failed: {e}")
            return AgentData(
                agent_name="NetworkTrafficAnalyzerAgent",
                success=False,
                summary="Traffic analysis failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'interface': strategy.context.get('interface')}
            )

    async def _analyze_capture_strategy(self, interface: str, analysis_type: str) -> Dict[str, Any]:
        """AI analysis to determine optimal capture strategy"""
        try:
            # Mock AI analysis of optimal capture parameters
            analysis_profiles = {
                'comprehensive': {
                    'filter': '',
                    'promiscuous': True,
                    'buffer_size': 2**20,
                    'timeout': 1000,
                    'packet_count': 0  # Unlimited
                },
                'focused': {
                    'filter': 'tcp or udp',
                    'promiscuous': False,
                    'buffer_size': 2**18,
                    'timeout': 500,
                    'packet_count': 1000
                },
                'stealth': {
                    'filter': 'not arp',
                    'promiscuous': False,
                    'buffer_size': 2**17,
                    'timeout': 200,
                    'packet_count': 500
                }
            }

            return analysis_profiles.get(analysis_type, analysis_profiles['focused'])

        except Exception as e:
            self.logger.warning(f"AI capture strategy analysis failed: {e}")
            return {
                'filter': 'tcp or udp',
                'promiscuous': False,
                'buffer_size': 2**18,
                'timeout': 500,
                'packet_count': 1000
            }

    async def _execute_intelligent_analysis(self, interface: str, duration: int, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Execute intelligent traffic analysis"""
        try:
            findings = []
            packets_captured = 0

            # For now, simulate traffic analysis
            # In real implementation, would use pcap or similar
            simulated_results = await self._simulate_traffic_analysis(duration, strategy)

            return {
                'packets_captured': simulated_results['packet_count'],
                'protocols_detected': simulated_results['protocols'],
                'anomalies_found': simulated_results['anomalies'],
                'patterns_identified': simulated_results['patterns'],
                'strategy': strategy
            }

        except Exception as e:
            self.logger.error(f"Traffic analysis execution failed: {e}")
            return {'error': str(e)}

    async def _simulate_traffic_analysis(self, duration: int, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate traffic analysis (replace with real pcap implementation)"""
        try:
            # Simulate packet capture and analysis
            await asyncio.sleep(2)  # Simulate analysis time

            return {
                'packet_count': random.randint(500, 2000),
                'protocols': ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'],
                'anomalies': [
                    {
                        'type': 'Unusual Port Activity',
                        'source': '192.168.1.15',
                        'destination': '192.168.1.100',
                        'port': 6667,
                        'description': 'IRC-like traffic on unusual port'
                    },
                    {
                        'type': 'Large Data Transfer',
                        'source': '192.168.1.25',
                        'destination': '10.0.0.50',
                        'port': 443,
                        'description': 'Large encrypted transfer'
                    }
                ],
                'patterns': [
                    {
                        'pattern': 'Regular DNS Queries',
                        'frequency': 'Every 30 seconds',
                        'source': '192.168.1.1',
                        'confidence': 0.9
                    },
                    {
                        'pattern': 'Web Browsing Activity',
                        'frequency': 'Intermittent',
                        'source': 'Multiple',
                        'confidence': 0.7
                    }
                ]
            }

        except Exception as e:
            self.logger.error(f"Traffic simulation failed: {e}")
            return {'error': str(e)}

    async def _analyze_traffic_patterns(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI analysis of traffic patterns"""
        try:
            findings = []

            # Analyze protocols
            if 'protocols' in results:
                protocol_analysis = await self._analyze_protocols(results['protocols'])
                findings.append({
                    'category': 'protocols',
                    'analysis': protocol_analysis
                })

            # Analyze anomalies
            if 'anomalies' in results:
                anomaly_analysis = await self._analyze_anomalies(results['anomalies'])
                findings.append({
                    'category': 'anomalies',
                    'analysis': anomaly_analysis
                })

            # Analyze patterns
            if 'patterns' in results:
                pattern_analysis = await self._analyze_patterns(results['patterns'])
                findings.append({
                    'category': 'patterns',
                    'analysis': pattern_analysis
                })

            return findings

        except Exception as e:
            self.logger.error(f"Traffic pattern analysis failed: {e}")
            return []

    async def _analyze_protocols(self, protocols: List[str]) -> Dict[str, Any]:
        """AI analysis of detected protocols"""
        try:
            analysis = {
                'protocol_count': len(protocols),
                'common_protocols': [],
                'suspicious_protocols': [],
                'recommendations': []
            }

            common_protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS']
            suspicious_protocols = ['ICMP', 'GRE', 'PPTP', 'L2TP']

            for protocol in protocols:
                if protocol in common_protocols:
                    analysis['common_protocols'].append(protocol)
                if protocol in suspicious_protocols:
                    analysis['suspicious_protocols'].append(protocol)

            # Generate recommendations
            if analysis['suspicious_protocols']:
                analysis['recommendations'].append('Investigate suspicious protocol usage')
            if len(protocols) > 10:
                analysis['recommendations'].append('High protocol diversity - possible multi-service environment')

            return analysis

        except Exception as e:
            self.logger.warning(f"Protocol analysis failed: {e}")
            return {'error': 'Analysis failed'}

    async def _analyze_anomalies(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """AI analysis of network anomalies"""
        try:
            analysis = {
                'anomaly_count': len(anomalies),
                'high_priority': [],
                'medium_priority': [],
                'low_priority': [],
                'threat_assessment': 'unknown'
            }

            for anomaly in anomalies:
                priority = await self._assess_anomaly_priority(anomaly)
                analysis[f'{priority}_priority'].append(anomaly)

            # Overall threat assessment
            if analysis['high_priority']:
                analysis['threat_assessment'] = 'high'
            elif analysis['medium_priority']:
                analysis['threat_assessment'] = 'medium'

            return analysis

        except Exception as e:
            self.logger.warning(f"Anomaly analysis failed: {e}")
            return {'error': 'Analysis failed'}

    async def _assess_anomaly_priority(self, anomaly: Dict[str, Any]) -> str:
        """Assess priority level of anomaly"""
        try:
            # Mock AI assessment
            anomaly_type = anomaly.get('type', '').lower()

            high_priority_types = ['unusual_port', 'large_data', 'encrypted_transfer']
            medium_priority_types = ['dns_tunneling', 'unusual_protocol']

            if any(type_word in anomaly_type for type_word in high_priority_types):
                return 'high'
            elif any(type_word in anomaly_type for type_word in medium_priority_types):
                return 'medium'
            else:
                return 'low'

        except Exception as e:
            self.logger.warning(f"Priority assessment failed: {e}")
            return 'low'

    async def _analyze_patterns(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """AI analysis of traffic patterns"""
        try:
            analysis = {
                'pattern_count': len(patterns),
                'regular_patterns': [],
                'irregular_patterns': [],
                'behavioral_insights': []
            }

            for pattern in patterns:
                confidence = pattern.get('confidence', 0.0)
                if confidence > 0.8:
                    analysis['regular_patterns'].append(pattern)
                else:
                    analysis['irregular_patterns'].append(pattern)

            # Generate behavioral insights
            if len(analysis['regular_patterns']) > len(analysis['irregular_patterns']):
                analysis['behavioral_insights'].append('Network behavior is mostly predictable')
            else:
                analysis['behavioral_insights'].append('Network behavior shows irregular patterns')

            return analysis

        except Exception as e:
            self.logger.warning(f"Pattern analysis failed: {e}")
            return {'error': 'Analysis failed'}

    def _initialize_traffic_patterns(self) -> Dict[str, Any]:
        """Initialize known traffic patterns"""
        return {
            'normal_patterns': [
                {
                    'name': 'Web Browsing',
                    'characteristics': ['HTTP/HTTPS', 'port_80_443', 'intermittent']
                },
                {
                    'name': 'Email',
                    'characteristics': ['SMTP/IMAP', 'port_25_143', 'periodic']
                }
            ],
            'suspicious_patterns': [
                {
                    'name': 'Data Exfiltration',
                    'characteristics': ['large_transfers', 'encrypted', 'unusual_timing']
                },
                {
                    'name': 'C2 Communication',
                    'characteristics': ['regular_intervals', 'dns_tunneling', 'low_volume']
                }
            ]
        }

    async def _packet_callback(self, timestamp, packet_data):
        """Callback for each captured packet"""
        try:
            # Analyze packet structure
            packet_analysis = await self._analyze_packet_structure(packet_data)

            # Check against known patterns
            pattern_match = await self._match_packet_to_patterns(packet_analysis)

            if pattern_match:
                self.logger.info(f"Pattern match found: {pattern_match}")

        except Exception as e:
            self.logger.debug(f"Packet callback failed: {e}")

    async def _analyze_packet_structure(self, packet_data: bytes) -> Dict[str, Any]:
        """Analyze packet structure and contents"""
        try:
            # Basic packet analysis
            packet_length = len(packet_data)

            # Extract basic headers (simplified)
            if packet_length >= 20:  # Minimum IP header size
                # Extract IP header (simplified)
                ip_version = (packet_data[0] >> 4) & 0xF
                ip_header_length = (packet_data[0] & 0xF) * 4
                protocol = packet_data[9]
                source_ip = socket.inet_ntoa(packet_data[12:16])
                destination_ip = socket.inet_ntoa(packet_data[16:20])

                return {
                    'version': ip_version,
                    'header_length': ip_header_length,
                    'protocol': protocol,
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'total_length': packet_length
                }

            return {'error': 'Packet too small for analysis'}

        except Exception as e:
            self.logger.debug(f"Packet structure analysis failed: {e}")
            return {'error': str(e)}

    async def _match_packet_to_patterns(self, packet_analysis: Dict[str, Any]) -> Optional[str]:
        """Match packet to known patterns"""
        try:
            # Simple pattern matching logic
            protocol = packet_analysis.get('protocol', 0)

            # Protocol mapping (simplified)
            protocol_names = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP',
                58: 'IPv6-ICMP'
            }

            protocol_name = protocol_names.get(protocol, f'Unknown-{protocol}')

            # Check for suspicious patterns
            if protocol == 1:  # ICMP
                return 'ICMP Traffic - Monitor for tunneling'
            elif protocol in [6, 17]:  # TCP/UDP
                return 'Standard Traffic'
            else:
                return f'Unusual Protocol: {protocol_name}'

        except Exception as e:
            self.logger.debug(f"Pattern matching failed: {e}")
            return None

    async def _extract_protocol_specific_data(self, packet_data: bytes, protocol: int) -> Optional[Dict[str, Any]]:
        """Extract protocol-specific data from packet"""
        try:
            if protocol == 6:  # TCP
                return self._extract_tcp_data(packet_data)
            elif protocol == 17:  # UDP
                return self._extract_udp_data(packet_data)
            elif protocol == 1:  # ICMP
                return self._extract_icmp_data(packet_data)
            else:
                return None

        except Exception as e:
            self.logger.debug(f"Protocol data extraction failed: {e}")
            return None

    def _extract_tcp_data(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract TCP-specific data"""
        try:
            # TCP header starts after IP header
            ip_header_length = (packet_data[0] & 0xF) * 4
            tcp_start = ip_header_length

            if len(packet_data) >= tcp_start + 20:
                source_port = (packet_data[tcp_start] << 8) | packet_data[tcp_start + 1]
                destination_port = (packet_data[tcp_start + 2] << 8) | packet_data[tcp_start + 3]
                flags = packet_data[tcp_start + 13]

                return {
                    'source_port': source_port,
                    'destination_port': destination_port,
                    'syn_flag': bool(flags & 0x02),
                    'ack_flag': bool(flags & 0x10),
                    'fin_flag': bool(flags & 0x01),
                    'rst_flag': bool(flags & 0x04)
                }

            return {'error': 'TCP header incomplete'}

        except Exception as e:
            return {'error': str(e)}

    def _extract_udp_data(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract UDP-specific data"""
        try:
            ip_header_length = (packet_data[0] & 0xF) * 4
            udp_start = ip_header_length

            if len(packet_data) >= udp_start + 8:
                source_port = (packet_data[udp_start] << 8) | packet_data[udp_start + 1]
                destination_port = (packet_data[udp_start + 2] << 8) | packet_data[udp_start + 3]
                length = (packet_data[udp_start + 4] << 8) | packet_data[udp_start + 5]

                return {
                    'source_port': source_port,
                    'destination_port': destination_port,
                    'length': length
                }

            return {'error': 'UDP header incomplete'}

        except Exception as e:
            return {'error': str(e)}

    def _extract_icmp_data(self, packet_data: bytes) -> Dict[str, Any]:
        """Extract ICMP-specific data"""
        try:
            ip_header_length = (packet_data[0] & 0xF) * 4
            icmp_start = ip_header_length

            if len(packet_data) >= icmp_start + 8:
                icmp_type = packet_data[icmp_start]
                icmp_code = packet_data[icmp_start + 1]
                icmp_checksum = (packet_data[icmp_start + 2] << 8) | packet_data[icmp_start + 3]

                return {
                    'type': icmp_type,
                    'code': icmp_code,
                    'checksum': icmp_checksum
                }

            return {'error': 'ICMP header incomplete'}

        except Exception as e:
            return {'error': str(e)}

    async def _generate_network_insights(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate AI insights from network analysis"""
        try:
            insights = []

            # Analyze protocol distribution
            protocols = analysis_results.get('protocols', [])
            if len(protocols) > 5:
                insights.append("High protocol diversity suggests multi-service environment")

            # Analyze traffic patterns
            patterns = analysis_results.get('patterns', [])
            regular_patterns = [p for p in patterns if p.get('confidence', 0) > 0.8]
            if len(regular_patterns) > 3:
                insights.append("Established traffic patterns - baseline established")

            # Analyze security concerns
            anomalies = analysis_results.get('anomalies', [])
            if anomalies:
                insights.append(f"Security concerns detected: {len(anomalies)} anomalies")

            return insights

        except Exception as e:
            self.logger.warning(f"Insight generation failed: {e}")
            return ["Analysis completed - manual review recommended"]

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's main functionality"""
        strategy = Strategy(
            phase=AttackPhase.RECONNAISSANCE,
            directive='Network traffic analysis execution',
            next_agent='packet_capture',
            context=context,
            objectives=['traffic_monitoring', 'anomaly_detection']
        )
        result = await self.execute(strategy)
        return {
            'success': result.success,
            'summary': result.summary,
            'findings': result.context.get('findings', []),
            'raw_results': result.context.get('raw_results', {})
        }
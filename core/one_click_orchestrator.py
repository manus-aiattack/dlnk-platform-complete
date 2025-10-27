"""
One-Click Attack Orchestrator
Automated end-to-end attack execution with AI-driven decision making
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

log = logging.getLogger(__name__)


class OneClickOrchestrator:
    """
    One-Click Attack Orchestrator
    
    Features:
    - Automated reconnaissance
    - AI-powered vulnerability analysis
    - Intelligent exploit selection
    - Automated exploitation
    - Post-exploitation automation
    - Data exfiltration
    - Self-learning and adaptation
    
    User Input: URL + API Key
    Output: Complete attack results with exfiltrated data
    """
    
    def __init__(self):
        self.attack_history = []
        self.current_phase = None
        
        # Initialize components
        self._init_components()
    
    def _init_components(self):
        """Initialize all attack components"""
        
        try:
            # Import components dynamically
            from agents.reconnaissance.subdomain_scanner import SubdomainScanner
            from agents.reconnaissance.port_scanner import PortScanner
            from agents.reconnaissance.tech_detector import TechDetector
            from agents.vulnerability_scanner import VulnerabilityScanner
            from core.ai_system.vulnerability_analyzer import AIVulnerabilityAnalyzer
            from core.self_learning.pattern_learner import PatternLearner
            
            self.subdomain_scanner = SubdomainScanner()
            self.port_scanner = PortScanner()
            self.tech_detector = TechDetector()
            self.vuln_scanner = VulnerabilityScanner()
            self.ai_analyzer = AIVulnerabilityAnalyzer()
            self.pattern_learner = PatternLearner()
            
        except ImportError as e:
            log.warning(f"[OneClick] Some components not available: {e}")
            # Create mock components for testing
            self.subdomain_scanner = None
            self.port_scanner = None
            self.tech_detector = None
            self.vuln_scanner = None
            self.ai_analyzer = None
            self.pattern_learner = None
    
    async def execute_one_click_attack(self, target_url: str, api_key: str = None) -> Dict:
        """
        Execute complete one-click attack
        
        Args:
            target_url: Target URL to attack
            api_key: API key for authentication (optional)
        
        Returns:
            Dict with complete attack results
        """
        log.info(f"[OneClick] Starting one-click attack on: {target_url}")
        
        attack_id = f"attack_{int(datetime.now().timestamp())}"
        
        results = {
            'attack_id': attack_id,
            'target_url': target_url,
            'start_time': datetime.now().isoformat(),
            'phases': {},
            'vulnerabilities': [],
            'exploits': [],
            'exfiltrated_data': [],
            'backdoors': [],
            'success': False
        }
        
        try:
            # Phase 1: Reconnaissance
            self.current_phase = 'reconnaissance'
            recon_results = await self._phase_reconnaissance(target_url)
            results['phases']['reconnaissance'] = recon_results
            
            # Phase 2: Vulnerability Scanning
            self.current_phase = 'vulnerability_scanning'
            vuln_results = await self._phase_vulnerability_scanning(target_url, recon_results)
            results['phases']['vulnerability_scanning'] = vuln_results
            results['vulnerabilities'] = vuln_results.get('vulnerabilities', [])
            
            # Phase 3: AI Analysis
            self.current_phase = 'ai_analysis'
            ai_results = await self._phase_ai_analysis(target_url, vuln_results)
            results['phases']['ai_analysis'] = ai_results
            
            # Phase 4: Exploitation
            self.current_phase = 'exploitation'
            exploit_results = await self._phase_exploitation(target_url, ai_results)
            results['phases']['exploitation'] = exploit_results
            results['exploits'] = exploit_results.get('successful_exploits', [])
            
            # Phase 5: Post-Exploitation
            self.current_phase = 'post_exploitation'
            post_exploit_results = await self._phase_post_exploitation(exploit_results)
            results['phases']['post_exploitation'] = post_exploit_results
            
            # Phase 6: Data Exfiltration
            self.current_phase = 'data_exfiltration'
            exfil_results = await self._phase_data_exfiltration(post_exploit_results)
            results['phases']['data_exfiltration'] = exfil_results
            results['exfiltrated_data'] = exfil_results.get('exfiltrated_files', [])
            
            # Phase 7: Persistence & Backdoors
            self.current_phase = 'persistence'
            persistence_results = await self._phase_persistence(post_exploit_results)
            results['phases']['persistence'] = persistence_results
            results['backdoors'] = persistence_results.get('backdoors', [])
            
            # Phase 8: Self-Learning
            self.current_phase = 'self_learning'
            await self._phase_self_learning(results)
            
            results['success'] = True
            results['end_time'] = datetime.now().isoformat()
            
            log.info(f"[OneClick] Attack completed successfully: {attack_id}")
            
        except Exception as e:
            log.error(f"[OneClick] Attack failed at phase {self.current_phase}: {e}")
            results['error'] = str(e)
            results['failed_phase'] = self.current_phase
            results['end_time'] = datetime.now().isoformat()
        
        # Store in history
        self.attack_history.append(results)
        
        return results
    
    async def _phase_reconnaissance(self, target_url: str) -> Dict:
        """Phase 1: Reconnaissance"""
        
        log.info("[OneClick] Phase 1: Reconnaissance")
        
        results = {
            'subdomains': [],
            'open_ports': [],
            'technologies': [],
            'endpoints': []
        }
        
        try:
            # Subdomain enumeration
            if self.subdomain_scanner:
                subdomain_result = await self.subdomain_scanner.run({'target': target_url})
                results['subdomains'] = subdomain_result.get('subdomains', [])
            
            # Port scanning
            if self.port_scanner:
                port_result = await self.port_scanner.run({'target': target_url})
                results['open_ports'] = port_result.get('open_ports', [])
            
            # Technology detection
            if self.tech_detector:
                tech_result = await self.tech_detector.run({'target': target_url})
                results['technologies'] = tech_result.get('technologies', [])
            
            log.info(f"[OneClick] Recon found: {len(results['subdomains'])} subdomains, "
                    f"{len(results['open_ports'])} open ports, "
                    f"{len(results['technologies'])} technologies")
        
        except Exception as e:
            log.error(f"[OneClick] Reconnaissance failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _phase_vulnerability_scanning(self, target_url: str, recon_results: Dict) -> Dict:
        """Phase 2: Vulnerability Scanning"""
        
        log.info("[OneClick] Phase 2: Vulnerability Scanning")
        
        results = {
            'vulnerabilities': [],
            'scan_coverage': []
        }
        
        try:
            # Comprehensive vulnerability scanning
            scan_types = [
                'sql_injection',
                'xss',
                'rce',
                'ssrf',
                'lfi',
                'xxe',
                'auth_bypass',
                'idor',
                'csrf'
            ]
            
            for scan_type in scan_types:
                try:
                    if self.vuln_scanner:
                        vuln_result = await self.vuln_scanner.run({
                            'target': target_url,
                            'scan_type': scan_type
                        })
                        
                        if vuln_result.get('vulnerabilities'):
                            results['vulnerabilities'].extend(vuln_result['vulnerabilities'])
                        
                        results['scan_coverage'].append(scan_type)
                
                except Exception as e:
                    log.warning(f"[OneClick] {scan_type} scan failed: {e}")
            
            log.info(f"[OneClick] Found {len(results['vulnerabilities'])} vulnerabilities")
        
        except Exception as e:
            log.error(f"[OneClick] Vulnerability scanning failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _phase_ai_analysis(self, target_url: str, vuln_results: Dict) -> Dict:
        """Phase 3: AI-Powered Analysis"""
        
        log.info("[OneClick] Phase 3: AI Analysis")
        
        results = {
            'ai_vulnerabilities': [],
            'exploit_recommendations': [],
            'attack_path': []
        }
        
        try:
            if self.ai_analyzer:
                ai_result = await self.ai_analyzer.run({
                    'url': target_url,
                    'scan_results': vuln_results
                })
                
                results['ai_vulnerabilities'] = ai_result.get('vulnerabilities', [])
                results['exploit_recommendations'] = ai_result.get('exploits', [])
                
                # Optimize attack path
                all_vulns = vuln_results.get('vulnerabilities', []) + results['ai_vulnerabilities']
                results['attack_path'] = await self.ai_analyzer.optimize_attack_path(all_vulns)
            
            log.info(f"[OneClick] AI found {len(results['ai_vulnerabilities'])} additional vulnerabilities")
        
        except Exception as e:
            log.error(f"[OneClick] AI analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _phase_exploitation(self, target_url: str, ai_results: Dict) -> Dict:
        """Phase 4: Automated Exploitation"""
        
        log.info("[OneClick] Phase 4: Exploitation")
        
        results = {
            'successful_exploits': [],
            'failed_exploits': [],
            'shells': []
        }
        
        try:
            # Get attack path from AI
            attack_path = ai_results.get('attack_path', [])
            
            # Execute exploits in order
            for vuln in attack_path:
                try:
                    exploit_result = await self._execute_exploit(target_url, vuln)
                    
                    if exploit_result.get('success'):
                        results['successful_exploits'].append(exploit_result)
                        
                        # If we got a shell, store it
                        if exploit_result.get('shell_url'):
                            results['shells'].append(exploit_result['shell_url'])
                    else:
                        results['failed_exploits'].append(exploit_result)
                
                except Exception as e:
                    log.warning(f"[OneClick] Exploit failed: {e}")
            
            log.info(f"[OneClick] Successfully exploited {len(results['successful_exploits'])} vulnerabilities")
        
        except Exception as e:
            log.error(f"[OneClick] Exploitation phase failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _execute_exploit(self, target_url: str, vulnerability: Dict) -> Dict:
        """Execute a single exploit"""
        
        vuln_type = vulnerability.get('type', 'unknown')
        
        log.info(f"[OneClick] Executing exploit for: {vuln_type}")
        
        # Mock exploit execution
        # In production, use actual exploit agents
        
        result = {
            'vulnerability': vuln_type,
            'target': target_url,
            'success': True,  # Mock success
            'shell_url': f"{target_url}/shell.php",
            'timestamp': datetime.now().isoformat()
        }
        
        return result
    
    async def _phase_post_exploitation(self, exploit_results: Dict) -> Dict:
        """Phase 5: Post-Exploitation"""
        
        log.info("[OneClick] Phase 5: Post-Exploitation")
        
        results = {
            'credentials': [],
            'privilege_escalation': [],
            'lateral_movement': []
        }
        
        try:
            shells = exploit_results.get('shells', [])
            
            for shell_url in shells:
                # Credential harvesting
                creds = await self._harvest_credentials(shell_url)
                results['credentials'].extend(creds)
                
                # Privilege escalation
                privesc = await self._escalate_privileges(shell_url)
                if privesc:
                    results['privilege_escalation'].append(privesc)
                
                # Lateral movement
                lateral = await self._lateral_movement(shell_url)
                results['lateral_movement'].extend(lateral)
            
            log.info(f"[OneClick] Post-exploitation: {len(results['credentials'])} credentials, "
                    f"{len(results['privilege_escalation'])} privesc, "
                    f"{len(results['lateral_movement'])} lateral moves")
        
        except Exception as e:
            log.error(f"[OneClick] Post-exploitation failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _harvest_credentials(self, shell_url: str) -> List[Dict]:
        """Harvest credentials from compromised system"""
        
        # Mock implementation
        return [
            {'username': 'admin', 'password': 'harvested_password', 'source': shell_url}
        ]
    
    async def _escalate_privileges(self, shell_url: str) -> Optional[Dict]:
        """Attempt privilege escalation"""
        
        # Mock implementation
        return {
            'method': 'sudo_exploit',
            'success': True,
            'new_privileges': 'root'
        }
    
    async def _lateral_movement(self, shell_url: str) -> List[Dict]:
        """Perform lateral movement"""
        
        # Mock implementation
        return [
            {'target': '192.168.1.10', 'method': 'ssh_key', 'success': True}
        ]
    
    async def _phase_data_exfiltration(self, post_exploit_results: Dict) -> Dict:
        """Phase 6: Data Exfiltration"""
        
        log.info("[OneClick] Phase 6: Data Exfiltration")
        
        results = {
            'exfiltrated_files': [],
            'total_size': 0
        }
        
        try:
            # Mock data exfiltration
            sensitive_files = [
                '/etc/passwd',
                '/etc/shadow',
                '~/.ssh/id_rsa',
                '/var/www/html/config.php',
                '/root/.bash_history'
            ]
            
            for file_path in sensitive_files:
                results['exfiltrated_files'].append({
                    'path': file_path,
                    'size': 1024,
                    'timestamp': datetime.now().isoformat()
                })
                results['total_size'] += 1024
            
            log.info(f"[OneClick] Exfiltrated {len(results['exfiltrated_files'])} files")
        
        except Exception as e:
            log.error(f"[OneClick] Data exfiltration failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _phase_persistence(self, post_exploit_results: Dict) -> Dict:
        """Phase 7: Persistence & Backdoors"""
        
        log.info("[OneClick] Phase 7: Persistence")
        
        results = {
            'backdoors': [],
            'persistence_methods': []
        }
        
        try:
            # Mock backdoor installation
            results['backdoors'].append({
                'type': 'webshell',
                'url': 'http://target.com/.system/update.php',
                'password': 'generated_password_123'
            })
            
            results['persistence_methods'].append({
                'type': 'cron_job',
                'command': '/tmp/.update',
                'schedule': '*/5 * * * *'
            })
            
            log.info(f"[OneClick] Installed {len(results['backdoors'])} backdoors")
        
        except Exception as e:
            log.error(f"[OneClick] Persistence failed: {e}")
            results['error'] = str(e)
        
        return results
    
    async def _phase_self_learning(self, attack_results: Dict):
        """Phase 8: Self-Learning"""
        
        log.info("[OneClick] Phase 8: Self-Learning")
        
        try:
            if self.pattern_learner:
                # Learn from attack results
                await self.pattern_learner.run({
                    'attack_result': {
                        'target_url': attack_results['target_url'],
                        'success': attack_results['success'],
                        'vulnerabilities': attack_results['vulnerabilities'],
                        'exploits': attack_results['exploits']
                    },
                    'update_knowledge': True
                })
            
            log.info("[OneClick] Self-learning completed")
        
        except Exception as e:
            log.error(f"[OneClick] Self-learning failed: {e}")


if __name__ == '__main__':
    async def test():
        orchestrator = OneClickOrchestrator()
        
        result = await orchestrator.execute_one_click_attack(
            target_url='http://example.com',
            api_key='test_key'
        )
        
        print("\\n" + "=" * 80)
        print("ONE-CLICK ATTACK RESULTS")
        print("=" * 80)
        print(f"Attack ID: {result['attack_id']}")
        print(f"Target: {result['target_url']}")
        print(f"Success: {result['success']}")
        print(f"Vulnerabilities: {len(result['vulnerabilities'])}")
        print(f"Successful Exploits: {len(result['exploits'])}")
        print(f"Exfiltrated Files: {len(result['exfiltrated_data'])}")
        print(f"Backdoors: {len(result['backdoors'])}")
        print("=" * 80)
    
    asyncio.run(test())


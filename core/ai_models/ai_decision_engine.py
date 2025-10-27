"""
AI Decision Engine for dLNk Attack Platform
Makes intelligent decisions about attack strategies
"""

import asyncio
import numpy as np
from typing import Dict, List, Optional, Tuple
import logging
from datetime import datetime

log = logging.getLogger(__name__)


class AIDecisionEngine:
    """
    AI-powered Decision Engine
    
    Features:
    - Optimal attack path selection
    - Resource allocation optimization
    - Risk assessment and mitigation
    - Adaptive evasion techniques
    - Real-time strategy adjustment
    """
    
    def __init__(self):
        self.attack_history = []
        self.success_rates = {}
        self.technique_effectiveness = {}
        self.target_profiles = {}
        
    async def select_optimal_attack_path(
        self,
        vulnerabilities: List[Dict],
        target_info: Dict,
        constraints: Dict = None
    ) -> List[Dict]:
        """
        Select optimal attack path based on vulnerabilities and target info
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            target_info: Information about the target
            constraints: Attack constraints (time, resources, etc.)
        
        Returns:
            Optimized attack sequence
        """
        log.info("[AIDecision] Selecting optimal attack path...")
        
        if not vulnerabilities:
            return []
        
        # Score each vulnerability
        scored_vulns = []
        for vuln in vulnerabilities:
            score = await self._calculate_attack_score(vuln, target_info, constraints)
            scored_vulns.append((score, vuln))
        
        # Sort by score (highest first)
        scored_vulns.sort(reverse=True, key=lambda x: x[0])
        
        # Build attack sequence
        attack_sequence = []
        for score, vuln in scored_vulns:
            attack_step = {
                'vulnerability': vuln,
                'score': score,
                'priority': self._calculate_priority(score),
                'estimated_time': self._estimate_time(vuln),
                'estimated_success_rate': await self._estimate_success_rate(vuln, target_info),
                'required_resources': self._estimate_resources(vuln),
                'evasion_techniques': await self._select_evasion_techniques(vuln, target_info),
                'fallback_options': await self._generate_fallback_options(vuln)
            }
            attack_sequence.append(attack_step)
        
        log.info(f"[AIDecision] Generated attack sequence with {len(attack_sequence)} steps")
        
        return attack_sequence
    
    async def _calculate_attack_score(
        self,
        vuln: Dict,
        target_info: Dict,
        constraints: Dict = None
    ) -> float:
        """Calculate attack score for a vulnerability"""
        
        score = 0.0
        
        # Severity weight (40%)
        severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 2.0
        }
        severity_score = severity_weights.get(vuln.get('severity', 'LOW'), 2.0)
        score += severity_score * 0.4
        
        # Exploitability weight (30%)
        exploitability = vuln.get('exploitability', 0.5)
        score += exploitability * 10.0 * 0.3
        
        # Confidence weight (20%)
        confidence = vuln.get('confidence', 0.5)
        score += confidence * 10.0 * 0.2
        
        # Historical success rate (10%)
        vuln_type = vuln.get('type', 'unknown')
        historical_rate = self.success_rates.get(vuln_type, 0.5)
        score += historical_rate * 10.0 * 0.1
        
        # Apply constraints
        if constraints:
            # Time constraint
            max_time = constraints.get('max_time', float('inf'))
            estimated_time = self._estimate_time(vuln)
            if estimated_time > max_time:
                score *= 0.5  # Penalize if takes too long
            
            # Stealth constraint
            if constraints.get('stealth_mode', False):
                if vuln.get('type') in ['dos', 'bruteforce']:
                    score *= 0.3  # Heavily penalize noisy attacks
        
        # Target-specific adjustments
        if target_info:
            # WAF detection
            if target_info.get('has_waf', False):
                score *= 0.7  # Reduce score if WAF detected
            
            # Security headers
            security_headers = target_info.get('security_headers', [])
            if len(security_headers) > 5:
                score *= 0.8  # Reduce score if well-protected
            
            # Technology stack
            technologies = target_info.get('technologies', [])
            if self._is_vulnerable_stack(technologies, vuln_type):
                score *= 1.3  # Increase score if known vulnerable stack
        
        return score
    
    def _calculate_priority(self, score: float) -> str:
        """Calculate priority level from score"""
        if score >= 8.0:
            return 'CRITICAL'
        elif score >= 6.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _estimate_time(self, vuln: Dict) -> float:
        """Estimate time required to exploit vulnerability (in seconds)"""
        
        time_estimates = {
            'sql_injection': 30.0,
            'xss': 20.0,
            'rce': 60.0,
            'lfi': 40.0,
            'ssrf': 50.0,
            'xxe': 45.0,
            'deserialization': 90.0,
            'auth_bypass': 30.0,
            'idor': 20.0,
            'csrf': 25.0
        }
        
        vuln_type = vuln.get('type', 'unknown')
        base_time = time_estimates.get(vuln_type, 60.0)
        
        # Adjust based on complexity
        complexity = vuln.get('complexity', 'medium')
        if complexity == 'high':
            base_time *= 2.0
        elif complexity == 'low':
            base_time *= 0.5
        
        return base_time
    
    async def _estimate_success_rate(self, vuln: Dict, target_info: Dict) -> float:
        """Estimate success rate for exploiting vulnerability"""
        
        # Base success rate from exploitability
        success_rate = vuln.get('exploitability', 0.5)
        
        # Adjust based on historical data
        vuln_type = vuln.get('type', 'unknown')
        if vuln_type in self.success_rates:
            historical_rate = self.success_rates[vuln_type]
            success_rate = (success_rate + historical_rate) / 2.0
        
        # Adjust based on target characteristics
        if target_info:
            # WAF
            if target_info.get('has_waf', False):
                success_rate *= 0.6
            
            # Rate limiting
            if target_info.get('has_rate_limiting', False):
                success_rate *= 0.7
            
            # Security headers
            security_headers = target_info.get('security_headers', [])
            if 'X-Frame-Options' in security_headers:
                success_rate *= 0.9
            if 'Content-Security-Policy' in security_headers:
                success_rate *= 0.85
        
        return min(success_rate, 0.95)  # Cap at 95%
    
    def _estimate_resources(self, vuln: Dict) -> Dict:
        """Estimate resources required for exploitation"""
        
        return {
            'cpu': 'low',
            'memory': 'low',
            'network': 'medium',
            'time': self._estimate_time(vuln)
        }
    
    async def _select_evasion_techniques(
        self,
        vuln: Dict,
        target_info: Dict
    ) -> List[str]:
        """Select appropriate evasion techniques"""
        
        evasion_techniques = []
        
        # WAF evasion
        if target_info.get('has_waf', False):
            evasion_techniques.extend([
                'payload_encoding',
                'case_variation',
                'comment_insertion',
                'whitespace_manipulation'
            ])
        
        # IDS/IPS evasion
        if target_info.get('has_ids', False):
            evasion_techniques.extend([
                'fragmentation',
                'timing_variation',
                'protocol_manipulation'
            ])
        
        # Rate limiting evasion
        if target_info.get('has_rate_limiting', False):
            evasion_techniques.extend([
                'request_throttling',
                'ip_rotation',
                'user_agent_rotation'
            ])
        
        # Vulnerability-specific evasion
        vuln_type = vuln.get('type', 'unknown')
        if vuln_type == 'sql_injection':
            evasion_techniques.extend([
                'sql_comment_insertion',
                'sql_case_variation',
                'sql_encoding'
            ])
        elif vuln_type == 'xss':
            evasion_techniques.extend([
                'html_encoding',
                'javascript_obfuscation',
                'event_handler_variation'
            ])
        
        return list(set(evasion_techniques))  # Remove duplicates
    
    async def _generate_fallback_options(self, vuln: Dict) -> List[Dict]:
        """Generate fallback options if primary exploit fails"""
        
        fallback_options = []
        
        vuln_type = vuln.get('type', 'unknown')
        
        # SQL Injection fallbacks
        if vuln_type == 'sql_injection':
            fallback_options = [
                {'technique': 'union_based', 'priority': 1},
                {'technique': 'time_based', 'priority': 2},
                {'technique': 'error_based', 'priority': 3},
                {'technique': 'boolean_based', 'priority': 4}
            ]
        
        # XSS fallbacks
        elif vuln_type == 'xss':
            fallback_options = [
                {'technique': 'reflected', 'priority': 1},
                {'technique': 'stored', 'priority': 2},
                {'technique': 'dom_based', 'priority': 3}
            ]
        
        # RCE fallbacks
        elif vuln_type == 'rce':
            fallback_options = [
                {'technique': 'command_injection', 'priority': 1},
                {'technique': 'code_injection', 'priority': 2},
                {'technique': 'file_upload', 'priority': 3}
            ]
        
        return fallback_options
    
    def _is_vulnerable_stack(self, technologies: List[str], vuln_type: str) -> bool:
        """Check if technology stack is known to be vulnerable"""
        
        vulnerable_stacks = {
            'sql_injection': ['PHP 5.x', 'MySQL 5.0', 'ASP.NET 2.0'],
            'xss': ['jQuery < 3.0', 'AngularJS < 1.6'],
            'rce': ['PHP < 7.0', 'Python 2.x', 'Node.js < 10.0'],
            'deserialization': ['Java < 8', 'PHP < 7.0', 'Python 2.x']
        }
        
        vulnerable_techs = vulnerable_stacks.get(vuln_type, [])
        
        for tech in technologies:
            for vuln_tech in vulnerable_techs:
                if vuln_tech.lower() in tech.lower():
                    return True
        
        return False
    
    async def allocate_resources(
        self,
        attack_sequence: List[Dict],
        available_resources: Dict
    ) -> Dict:
        """
        Allocate resources optimally across attack sequence
        
        Args:
            attack_sequence: Planned attack sequence
            available_resources: Available resources (CPU, memory, network, etc.)
        
        Returns:
            Resource allocation plan
        """
        log.info("[AIDecision] Allocating resources...")
        
        allocation = {
            'parallel_attacks': [],
            'sequential_attacks': [],
            'resource_distribution': {}
        }
        
        # Determine which attacks can run in parallel
        for i, attack in enumerate(attack_sequence):
            required = attack['required_resources']
            
            # Check if can run in parallel
            if self._can_run_parallel(required, available_resources):
                allocation['parallel_attacks'].append(attack)
            else:
                allocation['sequential_attacks'].append(attack)
        
        log.info(f"[AIDecision] Allocated {len(allocation['parallel_attacks'])} parallel, "
                f"{len(allocation['sequential_attacks'])} sequential attacks")
        
        return allocation
    
    def _can_run_parallel(self, required: Dict, available: Dict) -> bool:
        """Check if attack can run in parallel with current resource usage"""
        
        # Simplified check - in production, implement proper resource tracking
        return required.get('cpu', 'low') == 'low' and required.get('memory', 'low') == 'low'
    
    async def assess_risk(
        self,
        attack_plan: List[Dict],
        target_info: Dict
    ) -> Dict:
        """
        Assess risk of attack plan
        
        Returns:
            Risk assessment with mitigation strategies
        """
        log.info("[AIDecision] Assessing attack risk...")
        
        risk_assessment = {
            'overall_risk': 'MEDIUM',
            'detection_probability': 0.3,
            'legal_risk': 'MEDIUM',
            'technical_risk': 'LOW',
            'mitigation_strategies': []
        }
        
        # Calculate detection probability
        detection_prob = 0.0
        for attack in attack_plan:
            vuln_type = attack['vulnerability'].get('type', 'unknown')
            
            # Noisy attacks increase detection probability
            if vuln_type in ['dos', 'bruteforce', 'port_scan']:
                detection_prob += 0.3
            else:
                detection_prob += 0.1
        
        detection_prob = min(detection_prob, 0.9)
        risk_assessment['detection_probability'] = detection_prob
        
        # Determine overall risk
        if detection_prob > 0.7:
            risk_assessment['overall_risk'] = 'HIGH'
        elif detection_prob > 0.4:
            risk_assessment['overall_risk'] = 'MEDIUM'
        else:
            risk_assessment['overall_risk'] = 'LOW'
        
        # Generate mitigation strategies
        if target_info.get('has_waf', False):
            risk_assessment['mitigation_strategies'].append('Use WAF evasion techniques')
        
        if target_info.get('has_ids', False):
            risk_assessment['mitigation_strategies'].append('Implement traffic fragmentation')
        
        if detection_prob > 0.5:
            risk_assessment['mitigation_strategies'].append('Reduce attack frequency')
            risk_assessment['mitigation_strategies'].append('Use IP rotation')
        
        log.info(f"[AIDecision] Risk assessment: {risk_assessment['overall_risk']} "
                f"(detection: {detection_prob:.1%})")
        
        return risk_assessment
    
    async def adapt_strategy(
        self,
        current_results: List[Dict],
        target_info: Dict
    ) -> Dict:
        """
        Adapt attack strategy based on current results
        
        Args:
            current_results: Results from current attacks
            target_info: Updated target information
        
        Returns:
            Adapted strategy
        """
        log.info("[AIDecision] Adapting attack strategy...")
        
        adapted_strategy = {
            'continue_current': True,
            'switch_technique': False,
            'increase_evasion': False,
            'abort_attack': False,
            'new_targets': [],
            'recommendations': []
        }
        
        # Analyze current results
        success_count = sum(1 for r in current_results if r.get('success', False))
        failure_count = len(current_results) - success_count
        
        success_rate = success_count / len(current_results) if current_results else 0.0
        
        # Adapt based on success rate
        if success_rate < 0.2:
            # Low success rate - switch technique
            adapted_strategy['switch_technique'] = True
            adapted_strategy['recommendations'].append('Switch to alternative exploitation technique')
        
        if success_rate < 0.1:
            # Very low success rate - consider aborting
            adapted_strategy['abort_attack'] = True
            adapted_strategy['recommendations'].append('Consider aborting current attack vector')
        
        # Check for detection indicators
        detection_indicators = sum(1 for r in current_results if r.get('blocked', False))
        if detection_indicators > len(current_results) * 0.3:
            # High blocking rate - increase evasion
            adapted_strategy['increase_evasion'] = True
            adapted_strategy['recommendations'].append('Increase evasion techniques')
        
        log.info(f"[AIDecision] Strategy adapted (success rate: {success_rate:.1%})")
        
        return adapted_strategy
    
    async def learn_from_attack(self, attack_result: Dict):
        """Learn from attack results to improve future decisions"""
        
        self.attack_history.append(attack_result)
        
        # Update success rates
        vuln_type = attack_result.get('vulnerability_type')
        success = attack_result.get('success', False)
        
        if vuln_type:
            if vuln_type not in self.success_rates:
                self.success_rates[vuln_type] = 0.5
            
            # Update with exponential moving average
            alpha = 0.3  # Learning rate
            current_rate = self.success_rates[vuln_type]
            new_value = 1.0 if success else 0.0
            self.success_rates[vuln_type] = alpha * new_value + (1 - alpha) * current_rate
        
        # Update technique effectiveness
        technique = attack_result.get('technique')
        if technique:
            if technique not in self.technique_effectiveness:
                self.technique_effectiveness[technique] = {'success': 0, 'total': 0}
            
            self.technique_effectiveness[technique]['total'] += 1
            if success:
                self.technique_effectiveness[technique]['success'] += 1
        
        log.info(f"[AIDecision] Learned from attack: {vuln_type} ({'success' if success else 'failure'})")


if __name__ == '__main__':
    async def test():
        engine = AIDecisionEngine()
        
        # Test vulnerability scoring
        vulnerabilities = [
            {
                'type': 'sql_injection',
                'severity': 'CRITICAL',
                'exploitability': 0.9,
                'confidence': 0.8
            },
            {
                'type': 'xss',
                'severity': 'HIGH',
                'exploitability': 0.7,
                'confidence': 0.6
            }
        ]
        
        target_info = {
            'has_waf': True,
            'technologies': ['PHP 5.6', 'MySQL 5.5'],
            'security_headers': ['X-Frame-Options']
        }
        
        attack_sequence = await engine.select_optimal_attack_path(
            vulnerabilities, target_info
        )
        
        print(f"Generated attack sequence with {len(attack_sequence)} steps:")
        for i, step in enumerate(attack_sequence, 1):
            print(f"  {i}. {step['vulnerability']['type']} "
                  f"(score: {step['score']:.2f}, priority: {step['priority']})")
    
    asyncio.run(test())


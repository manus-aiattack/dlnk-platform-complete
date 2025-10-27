"""
AI-Driven Attack Strategist
Autonomous decision-making for adaptive attack strategies using ML/AI
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from datetime import datetime

from core.logger import get_logger
from core.redis_client import get_redis_client

log = get_logger(__name__)


class AttackStrategy(Enum):
    """Attack strategy types"""
    STEALTH = "stealth"  # Low and slow, evade detection
    AGGRESSIVE = "aggressive"  # Fast and comprehensive
    TARGETED = "targeted"  # Focused on specific vulnerabilities
    ADAPTIVE = "adaptive"  # AI-driven, changes based on feedback
    ZERO_DAY_HUNTING = "zero_day_hunting"  # Focus on unknown vulnerabilities
    APT_SIMULATION = "apt_simulation"  # Advanced persistent threat tactics


class AttackPhase(Enum):
    """Attack execution phases"""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    CLEANUP = "cleanup"


@dataclass
class TargetProfile:
    """AI-generated target profile"""
    url: str
    technologies: List[str] = field(default_factory=list)
    waf_detected: bool = False
    waf_type: Optional[str] = None
    security_posture: str = "unknown"  # low, medium, high, very_high
    attack_surface: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    confidence: float = 0.0
    
    def to_dict(self):
        return {
            "url": self.url,
            "technologies": self.technologies,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "security_posture": self.security_posture,
            "attack_surface": self.attack_surface,
            "vulnerabilities": self.vulnerabilities,
            "risk_score": self.risk_score,
            "confidence": self.confidence
        }


@dataclass
class AttackDecision:
    """AI-driven attack decision"""
    phase: AttackPhase
    agents: List[str]
    payloads: List[Dict[str, Any]]
    strategy: AttackStrategy
    priority: int
    reasoning: str
    success_probability: float
    risk_level: str  # low, medium, high
    estimated_time: int  # seconds
    
    def to_dict(self):
        return {
            "phase": self.phase.value,
            "agents": self.agents,
            "payloads": self.payloads,
            "strategy": self.strategy.value,
            "priority": self.priority,
            "reasoning": self.reasoning,
            "success_probability": self.success_probability,
            "risk_level": self.risk_level,
            "estimated_time": self.estimated_time
        }


class AIAttackStrategist:
    """
    AI-Driven Attack Strategist
    
    Uses machine learning and AI to:
    1. Analyze target characteristics
    2. Select optimal attack vectors
    3. Generate adaptive payloads
    4. Make real-time tactical decisions
    5. Learn from attack outcomes
    """
    
    def __init__(self, llm_provider=None):
        self.llm_provider = llm_provider
        self.redis = None
        self.attack_history = []
        self.success_patterns = {}
        self.failure_patterns = {}
        
    async def initialize(self):
        """Initialize AI strategist"""
        try:
            self.redis = await get_redis_client()
            await self._load_historical_data()
            log.info("AI Attack Strategist initialized")
        except Exception as e:
            log.error(f"Failed to initialize AI strategist: {e}")
            raise
    
    async def analyze_target(self, target_url: str, recon_data: Dict[str, Any]) -> TargetProfile:
        """
        Analyze target using AI to create comprehensive profile
        
        Args:
            target_url: Target URL
            recon_data: Reconnaissance data from agents
            
        Returns:
            TargetProfile with AI-generated insights
        """
        log.info(f"AI analyzing target: {target_url}")
        
        # Extract key information
        technologies = self._extract_technologies(recon_data)
        waf_info = self._detect_waf(recon_data)
        attack_surface = self._map_attack_surface(recon_data)
        
        # AI-driven security posture assessment
        security_posture = await self._assess_security_posture(
            technologies, waf_info, attack_surface
        )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            security_posture, attack_surface, technologies
        )
        
        # Identify potential vulnerabilities
        vulnerabilities = await self._predict_vulnerabilities(
            technologies, attack_surface, recon_data
        )
        
        profile = TargetProfile(
            url=target_url,
            technologies=technologies,
            waf_detected=waf_info["detected"],
            waf_type=waf_info.get("type"),
            security_posture=security_posture,
            attack_surface=attack_surface,
            vulnerabilities=vulnerabilities,
            risk_score=risk_score,
            confidence=0.85
        )
        
        # Store profile for learning
        await self._store_target_profile(profile)
        
        log.info(f"Target analysis complete: {security_posture} security posture, "
                f"risk score: {risk_score:.2f}")
        
        return profile
    
    async def generate_attack_plan(
        self,
        target_profile: TargetProfile,
        strategy: AttackStrategy = AttackStrategy.ADAPTIVE,
        constraints: Optional[Dict[str, Any]] = None
    ) -> List[AttackDecision]:
        """
        Generate AI-driven attack plan
        
        Args:
            target_profile: Target profile from analysis
            strategy: Attack strategy to use
            constraints: Optional constraints (time, stealth, etc.)
            
        Returns:
            List of AttackDecisions in priority order
        """
        log.info(f"Generating attack plan with {strategy.value} strategy")
        
        decisions = []
        
        # Phase 1: Reconnaissance (if needed)
        if not target_profile.attack_surface:
            decisions.append(await self._plan_reconnaissance(target_profile, strategy))
        
        # Phase 2: Vulnerability Discovery
        vuln_decisions = await self._plan_vulnerability_discovery(
            target_profile, strategy, constraints
        )
        decisions.extend(vuln_decisions)
        
        # Phase 3: Exploitation
        exploit_decisions = await self._plan_exploitation(
            target_profile, strategy, constraints
        )
        decisions.extend(exploit_decisions)
        
        # Phase 4: Post-Exploitation (conditional)
        if strategy in [AttackStrategy.AGGRESSIVE, AttackStrategy.APT_SIMULATION]:
            post_ex_decisions = await self._plan_post_exploitation(
                target_profile, strategy, constraints
            )
            decisions.extend(post_ex_decisions)
        
        # Sort by priority and success probability
        decisions.sort(key=lambda d: (d.priority, -d.success_probability))
        
        log.info(f"Generated {len(decisions)} attack decisions")
        
        return decisions
    
    async def adapt_strategy(
        self,
        current_results: Dict[str, Any],
        target_profile: TargetProfile,
        remaining_decisions: List[AttackDecision]
    ) -> List[AttackDecision]:
        """
        Adapt attack strategy based on real-time results
        
        Args:
            current_results: Results from executed attacks
            target_profile: Current target profile
            remaining_decisions: Remaining planned decisions
            
        Returns:
            Updated list of AttackDecisions
        """
        log.info("Adapting attack strategy based on results")
        
        # Analyze what worked and what didn't
        success_rate = self._calculate_success_rate(current_results)
        detected = self._check_detection(current_results)
        
        # Update target profile based on new information
        updated_profile = await self._update_target_profile(
            target_profile, current_results
        )
        
        # If detected, switch to stealth mode
        if detected:
            log.warning("Detection suspected, switching to stealth mode")
            return await self._generate_stealth_strategy(
                updated_profile, remaining_decisions
            )
        
        # If success rate is low, try different approach
        if success_rate < 0.3:
            log.info(f"Low success rate ({success_rate:.2%}), trying alternative approach")
            return await self._generate_alternative_strategy(
                updated_profile, current_results
            )
        
        # If highly successful, become more aggressive
        if success_rate > 0.7:
            log.info(f"High success rate ({success_rate:.2%}), escalating attacks")
            return await self._generate_escalated_strategy(
                updated_profile, remaining_decisions
            )
        
        # Otherwise, continue with minor adjustments
        return await self._adjust_decisions(
            remaining_decisions, current_results, updated_profile
        )
    
    async def generate_adaptive_payload(
        self,
        vuln_type: str,
        target_profile: TargetProfile,
        previous_attempts: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate adaptive payload using AI
        
        Args:
            vuln_type: Type of vulnerability
            target_profile: Target profile
            previous_attempts: Previous payload attempts (for learning)
            
        Returns:
            Optimized payload configuration
        """
        log.info(f"Generating adaptive payload for {vuln_type}")
        
        # Analyze previous attempts to avoid repetition
        if previous_attempts:
            failed_patterns = [p for p in previous_attempts if not p.get("success")]
            successful_patterns = [p for p in previous_attempts if p.get("success")]
        else:
            failed_patterns = []
            successful_patterns = []
        
        # Generate base payload
        base_payload = await self._generate_base_payload(vuln_type, target_profile)
        
        # Apply WAF bypass techniques if needed
        if target_profile.waf_detected:
            base_payload = await self._apply_waf_bypass(
                base_payload, target_profile.waf_type, failed_patterns
            )
        
        # Apply encoding/obfuscation
        payload = await self._apply_obfuscation(
            base_payload, target_profile.technologies
        )
        
        # Add polymorphic elements to evade signature detection
        if target_profile.security_posture in ["high", "very_high"]:
            payload = await self._add_polymorphism(payload)
        
        return payload
    
    async def learn_from_outcome(
        self,
        decision: AttackDecision,
        outcome: Dict[str, Any]
    ):
        """
        Learn from attack outcome to improve future decisions
        
        Args:
            decision: The attack decision that was executed
            outcome: The outcome of the attack
        """
        success = outcome.get("success", False)
        
        # Store in attack history
        self.attack_history.append({
            "decision": decision.to_dict(),
            "outcome": outcome,
            "timestamp": datetime.now().isoformat()
        })
        
        # Update success/failure patterns
        pattern_key = f"{decision.phase.value}_{decision.strategy.value}"
        
        if success:
            if pattern_key not in self.success_patterns:
                self.success_patterns[pattern_key] = []
            self.success_patterns[pattern_key].append({
                "agents": decision.agents,
                "payloads": decision.payloads,
                "outcome": outcome
            })
        else:
            if pattern_key not in self.failure_patterns:
                self.failure_patterns[pattern_key] = []
            self.failure_patterns[pattern_key].append({
                "agents": decision.agents,
                "payloads": decision.payloads,
                "outcome": outcome
            })
        
        # Persist learning data
        await self._persist_learning_data()
        
        log.info(f"Learned from {pattern_key}: {'success' if success else 'failure'}")
    
    # Private helper methods
    
    def _extract_technologies(self, recon_data: Dict[str, Any]) -> List[str]:
        """Extract technologies from reconnaissance data"""
        technologies = set()
        
        # From various recon sources
        if "whatweb" in recon_data:
            technologies.update(recon_data["whatweb"].get("technologies", []))
        
        if "wappalyzer" in recon_data:
            technologies.update(recon_data["wappalyzer"].get("technologies", []))
        
        if "headers" in recon_data:
            headers = recon_data["headers"]
            if "Server" in headers:
                technologies.add(headers["Server"])
            if "X-Powered-By" in headers:
                technologies.add(headers["X-Powered-By"])
        
        return list(technologies)
    
    def _detect_waf(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect WAF from reconnaissance data"""
        waf_info = {"detected": False, "type": None}
        
        if "waf_detector" in recon_data:
            waf_data = recon_data["waf_detector"]
            waf_info["detected"] = waf_data.get("detected", False)
            waf_info["type"] = waf_data.get("type")
        
        return waf_info
    
    def _map_attack_surface(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map attack surface from reconnaissance data"""
        attack_surface = {
            "endpoints": [],
            "parameters": [],
            "forms": [],
            "apis": [],
            "ports": [],
            "subdomains": []
        }
        
        if "crawler" in recon_data:
            attack_surface["endpoints"] = recon_data["crawler"].get("urls", [])
            attack_surface["forms"] = recon_data["crawler"].get("forms", [])
            attack_surface["parameters"] = recon_data["crawler"].get("parameters", [])
        
        if "api_discovery" in recon_data:
            attack_surface["apis"] = recon_data["api_discovery"].get("endpoints", [])
        
        if "nmap" in recon_data:
            attack_surface["ports"] = recon_data["nmap"].get("open_ports", [])
        
        if "subdomain_enum" in recon_data:
            attack_surface["subdomains"] = recon_data["subdomain_enum"].get("subdomains", [])
        
        return attack_surface
    
    async def _assess_security_posture(
        self,
        technologies: List[str],
        waf_info: Dict[str, Any],
        attack_surface: Dict[str, Any]
    ) -> str:
        """AI-driven security posture assessment"""
        score = 0
        
        # WAF presence
        if waf_info["detected"]:
            score += 30
        
        # Modern technologies
        modern_tech = ["nginx", "cloudflare", "aws", "kubernetes"]
        if any(tech.lower() in " ".join(technologies).lower() for tech in modern_tech):
            score += 20
        
        # Attack surface size (smaller is more secure)
        total_surface = sum(len(v) if isinstance(v, list) else 0 
                          for v in attack_surface.values())
        if total_surface < 10:
            score += 20
        elif total_surface < 50:
            score += 10
        
        # Security headers
        # (Would check in actual implementation)
        
        if score >= 70:
            return "very_high"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        else:
            return "low"
    
    def _calculate_risk_score(
        self,
        security_posture: str,
        attack_surface: Dict[str, Any],
        technologies: List[str]
    ) -> float:
        """Calculate risk score (0-10)"""
        base_score = {
            "low": 8.0,
            "medium": 6.0,
            "high": 4.0,
            "very_high": 2.0
        }.get(security_posture, 5.0)
        
        # Adjust based on attack surface
        total_surface = sum(len(v) if isinstance(v, list) else 0 
                          for v in attack_surface.values())
        surface_factor = min(total_surface / 100, 2.0)
        
        # Adjust based on outdated technologies
        # (Would implement version checking in production)
        
        return min(base_score + surface_factor, 10.0)
    
    async def _predict_vulnerabilities(
        self,
        technologies: List[str],
        attack_surface: Dict[str, Any],
        recon_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """AI-driven vulnerability prediction"""
        predicted_vulns = []
        
        # Based on technologies
        tech_vulns = {
            "wordpress": ["sql_injection", "xss", "file_upload", "plugin_vulns"],
            "php": ["lfi", "rfi", "code_injection", "deserialization"],
            "apache": ["path_traversal", "server_misconfiguration"],
            "mysql": ["sql_injection", "default_credentials"],
            "java": ["deserialization", "xxe", "ssti"]
        }
        
        for tech in technologies:
            tech_lower = tech.lower()
            for key, vulns in tech_vulns.items():
                if key in tech_lower:
                    for vuln in vulns:
                        predicted_vulns.append({
                            "type": vuln,
                            "source": f"technology:{tech}",
                            "confidence": 0.7,
                            "priority": "high" if vuln in ["sql_injection", "rce"] else "medium"
                        })
        
        # Based on attack surface
        if attack_surface.get("forms"):
            predicted_vulns.append({
                "type": "xss",
                "source": "forms_detected",
                "confidence": 0.8,
                "priority": "high"
            })
            predicted_vulns.append({
                "type": "csrf",
                "source": "forms_detected",
                "confidence": 0.7,
                "priority": "medium"
            })
        
        if attack_surface.get("apis"):
            predicted_vulns.append({
                "type": "bola",
                "source": "api_detected",
                "confidence": 0.75,
                "priority": "high"
            })
            predicted_vulns.append({
                "type": "idor",
                "source": "api_detected",
                "confidence": 0.7,
                "priority": "high"
            })
        
        return predicted_vulns
    
    async def _plan_reconnaissance(
        self,
        target_profile: TargetProfile,
        strategy: AttackStrategy
    ) -> AttackDecision:
        """Plan reconnaissance phase"""
        agents = ["NmapAgent", "WhatwebAgent", "CrawlerAgent"]
        
        if strategy == AttackStrategy.AGGRESSIVE:
            agents.extend(["DirsearchAgent", "SubdomainEnumeratorAgent", "NucleiAgent"])
        elif strategy == AttackStrategy.STEALTH:
            agents = ["PassiveDNSAgent", "CertificateTransparencyAgent"]
        
        return AttackDecision(
            phase=AttackPhase.RECONNAISSANCE,
            agents=agents,
            payloads=[],
            strategy=strategy,
            priority=1,
            reasoning="Initial reconnaissance to map attack surface",
            success_probability=0.95,
            risk_level="low",
            estimated_time=300
        )
    
    async def _plan_vulnerability_discovery(
        self,
        target_profile: TargetProfile,
        strategy: AttackStrategy,
        constraints: Optional[Dict[str, Any]]
    ) -> List[AttackDecision]:
        """Plan vulnerability discovery phase"""
        decisions = []
        
        # Prioritize based on predicted vulnerabilities
        for vuln in target_profile.vulnerabilities[:5]:  # Top 5
            agents = self._select_agents_for_vuln(vuln["type"])
            
            decisions.append(AttackDecision(
                phase=AttackPhase.VULNERABILITY_DISCOVERY,
                agents=agents,
                payloads=[],
                strategy=strategy,
                priority=2 if vuln["priority"] == "high" else 3,
                reasoning=f"Testing for {vuln['type']} based on {vuln['source']}",
                success_probability=vuln["confidence"],
                risk_level="medium",
                estimated_time=180
            ))
        
        return decisions
    
    async def _plan_exploitation(
        self,
        target_profile: TargetProfile,
        strategy: AttackStrategy,
        constraints: Optional[Dict[str, Any]]
    ) -> List[AttackDecision]:
        """Plan exploitation phase"""
        decisions = []
        
        # Only exploit if vulnerabilities found
        if not target_profile.vulnerabilities:
            return decisions
        
        for vuln in target_profile.vulnerabilities:
            if vuln.get("confirmed"):
                exploit_agents = self._select_exploit_agents(vuln["type"])
                payloads = await self.generate_adaptive_payload(
                    vuln["type"], target_profile
                )
                
                decisions.append(AttackDecision(
                    phase=AttackPhase.EXPLOITATION,
                    agents=exploit_agents,
                    payloads=[payloads],
                    strategy=strategy,
                    priority=4,
                    reasoning=f"Exploiting confirmed {vuln['type']} vulnerability",
                    success_probability=0.8,
                    risk_level="high",
                    estimated_time=240
                ))
        
        return decisions
    
    async def _plan_post_exploitation(
        self,
        target_profile: TargetProfile,
        strategy: AttackStrategy,
        constraints: Optional[Dict[str, Any]]
    ) -> List[AttackDecision]:
        """Plan post-exploitation phase"""
        decisions = []
        
        # Privilege escalation
        decisions.append(AttackDecision(
            phase=AttackPhase.POST_EXPLOITATION,
            agents=["PrivilegeEscalationAgent", "KernelExploitAgent"],
            payloads=[],
            strategy=strategy,
            priority=5,
            reasoning="Escalate privileges for deeper access",
            success_probability=0.6,
            risk_level="high",
            estimated_time=300
        ))
        
        # Persistence
        if strategy == AttackStrategy.APT_SIMULATION:
            decisions.append(AttackDecision(
                phase=AttackPhase.PERSISTENCE,
                agents=["PersistenceAgent", "BackdoorAgent"],
                payloads=[],
                strategy=strategy,
                priority=6,
                reasoning="Establish persistence for long-term access",
                success_probability=0.7,
                risk_level="very_high",
                estimated_time=180
            ))
        
        return decisions
    
    def _select_agents_for_vuln(self, vuln_type: str) -> List[str]:
        """Select appropriate agents for vulnerability type"""
        agent_map = {
            "sql_injection": ["SQLMapAgent", "SQLInjectionAgent"],
            "xss": ["XSSAgent", "DOMXSSAgent"],
            "ssrf": ["SSRFAgent"],
            "idor": ["IDORAgent"],
            "bola": ["BOLAAgent"],
            "file_upload": ["FileUploadAgent"],
            "rce": ["RCEAgent", "CommandInjectionAgent"],
            "lfi": ["LFIAgent"],
            "rfi": ["RFIAgent"],
            "xxe": ["XXEAgent"],
            "deserialization": ["DeserializationAgent"],
            "ssti": ["SSTIAgent"]
        }
        
        return agent_map.get(vuln_type, ["GenericFuzzerAgent"])
    
    def _select_exploit_agents(self, vuln_type: str) -> List[str]:
        """Select exploitation agents"""
        exploit_map = {
            "sql_injection": ["SQLMapAgent"],
            "xss": ["XSSExploitAgent"],
            "rce": ["RCEExploitAgent", "MetasploitAgent"],
            "file_upload": ["WebShellAgent"],
            "deserialization": ["DeserializationExploitAgent"]
        }
        
        return exploit_map.get(vuln_type, ["GenericExploitAgent"])
    
    async def _generate_base_payload(
        self,
        vuln_type: str,
        target_profile: TargetProfile
    ) -> Dict[str, Any]:
        """Generate base payload for vulnerability type"""
        # This would use AI/LLM in production
        payload_templates = {
            "sql_injection": {
                "type": "sql_injection",
                "payload": "' OR '1'='1",
                "method": "GET",
                "parameter": "id"
            },
            "xss": {
                "type": "xss",
                "payload": "<script>alert(document.domain)</script>",
                "context": "html"
            },
            "rce": {
                "type": "rce",
                "payload": "; whoami",
                "method": "POST"
            }
        }
        
        return payload_templates.get(vuln_type, {})
    
    async def _apply_waf_bypass(
        self,
        payload: Dict[str, Any],
        waf_type: Optional[str],
        failed_patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Apply WAF bypass techniques"""
        # Implement WAF-specific bypass techniques
        # This would be much more sophisticated in production
        
        if payload.get("type") == "sql_injection":
            # Example: Use comment-based bypass
            original = payload["payload"]
            payload["payload"] = original.replace(" ", "/**/")
        
        elif payload.get("type") == "xss":
            # Example: Use encoding
            original = payload["payload"]
            payload["payload"] = original.replace("<", "%3C").replace(">", "%3E")
        
        return payload
    
    async def _apply_obfuscation(
        self,
        payload: Dict[str, Any],
        technologies: List[str]
    ) -> Dict[str, Any]:
        """Apply payload obfuscation"""
        # Technology-specific obfuscation
        # Would be more sophisticated in production
        return payload
    
    async def _add_polymorphism(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Add polymorphic elements to payload"""
        # Add random elements to evade signature detection
        # Would use AI to generate variations in production
        return payload
    
    def _calculate_success_rate(self, results: Dict[str, Any]) -> float:
        """Calculate success rate from results"""
        total = len(results.get("attempts", []))
        if total == 0:
            return 0.0
        
        successful = sum(1 for a in results["attempts"] if a.get("success"))
        return successful / total
    
    def _check_detection(self, results: Dict[str, Any]) -> bool:
        """Check if attacks were detected"""
        # Look for signs of detection
        indicators = [
            "blocked",
            "forbidden",
            "rate_limited",
            "captcha",
            "ip_banned"
        ]
        
        for attempt in results.get("attempts", []):
            response = attempt.get("response", {})
            if any(ind in str(response).lower() for ind in indicators):
                return True
        
        return False
    
    async def _update_target_profile(
        self,
        profile: TargetProfile,
        results: Dict[str, Any]
    ) -> TargetProfile:
        """Update target profile based on new results"""
        # Update vulnerabilities with confirmed ones
        for attempt in results.get("attempts", []):
            if attempt.get("success") and attempt.get("vulnerability"):
                vuln = attempt["vulnerability"]
                vuln["confirmed"] = True
                if vuln not in profile.vulnerabilities:
                    profile.vulnerabilities.append(vuln)
        
        return profile
    
    async def _generate_stealth_strategy(
        self,
        profile: TargetProfile,
        remaining: List[AttackDecision]
    ) -> List[AttackDecision]:
        """Generate stealth strategy when detection suspected"""
        # Reduce aggressiveness, add delays, use different techniques
        stealth_decisions = []
        
        for decision in remaining:
            decision.strategy = AttackStrategy.STEALTH
            decision.estimated_time *= 3  # Slower execution
            decision.risk_level = "low"
            stealth_decisions.append(decision)
        
        return stealth_decisions
    
    async def _generate_alternative_strategy(
        self,
        profile: TargetProfile,
        results: Dict[str, Any]
    ) -> List[AttackDecision]:
        """Generate alternative strategy when current approach fails"""
        # Try completely different attack vectors
        return await self.generate_attack_plan(
            profile,
            strategy=AttackStrategy.TARGETED
        )
    
    async def _generate_escalated_strategy(
        self,
        profile: TargetProfile,
        remaining: List[AttackDecision]
    ) -> List[AttackDecision]:
        """Generate escalated strategy when highly successful"""
        # Become more aggressive
        for decision in remaining:
            decision.strategy = AttackStrategy.AGGRESSIVE
            decision.priority -= 1  # Higher priority
        
        return remaining
    
    async def _adjust_decisions(
        self,
        decisions: List[AttackDecision],
        results: Dict[str, Any],
        profile: TargetProfile
    ) -> List[AttackDecision]:
        """Make minor adjustments to decisions"""
        # Fine-tune based on results
        return decisions
    
    async def _store_target_profile(self, profile: TargetProfile):
        """Store target profile in Redis"""
        if self.redis:
            key = f"target_profile:{profile.url}"
            await self.redis.setex(
                key,
                86400,  # 24 hours
                json.dumps(profile.to_dict())
            )
    
    async def _load_historical_data(self):
        """Load historical attack data for learning"""
        if self.redis:
            # Load success patterns
            success_data = await self.redis.get("ai_success_patterns")
            if success_data:
                self.success_patterns = json.loads(success_data)
            
            # Load failure patterns
            failure_data = await self.redis.get("ai_failure_patterns")
            if failure_data:
                self.failure_patterns = json.loads(failure_data)
    
    async def _persist_learning_data(self):
        """Persist learning data to Redis"""
        if self.redis:
            await self.redis.set(
                "ai_success_patterns",
                json.dumps(self.success_patterns)
            )
            await self.redis.set(
                "ai_failure_patterns",
                json.dumps(self.failure_patterns)
            )


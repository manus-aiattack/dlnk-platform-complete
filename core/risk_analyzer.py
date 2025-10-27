import asyncio
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from core.logger import log
from core.data_models import AttackPhase
import numpy as np
from core.context_manager import ContextManager # Import ContextManager


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskFactor:
    name: str
    weight: float
    value: float
    description: str


@dataclass
class RiskAssessment:
    overall_risk: RiskLevel
    risk_score: float
    factors: List[RiskFactor]
    recommendations: List[str]
    mitigation_strategies: List[str]


class RiskAnalyzer:
    def __init__(self, context_manager: ContextManager = None):
        self.context_manager = context_manager
        self.risk_weights = {}
        self.historical_risks = {}
        self.target_risk_profile = {}

    async def initialize(self):
        """Initialize risk analyzer"""
        await self._load_risk_weights()
        await self._load_historical_data()
        await self._analyze_target_risk_profile()

    async def _load_risk_weights(self):
        """Load risk factor weights"""
        self.risk_weights = {
            "detection_probability": 0.3,
            "legal_risk": 0.2,
            "technical_complexity": 0.2,
            "resource_requirements": 0.1,
            "time_constraints": 0.1,
            "stealth_requirements": 0.1
        }

    async def _load_historical_data(self):
        """Load historical risk data"""
        # This would load from database or file
        self.historical_risks = {
            "high_detection_agents": [
                "DDoSAgent", "FuzzingAgent", "HydraAgent", "APIFuzzerAgent"
            ],
            "high_legal_risk_agents": [
                "DDoSAgent", "BotDeploymentAgent", "DataExfiltrationAgent"
            ],
            "high_complexity_agents": [
                "LateralMovementAgent", "PrivilegeEscalationAgent", "ZeroDayHunterAgent"
            ]
        }

    async def _analyze_target_risk_profile(self):
        """Analyze target-specific risk profile"""
        if not self.context_manager:
            return

        target_url = await self.context_manager.get_context('target_url') or ''
        target_host = await self.context_manager.get_context('target_host') or ''

        # Analyze target characteristics
        self.target_risk_profile = {
            "is_government": await self._is_government_target(target_url),
            "is_corporate": await self._is_corporate_target(target_url),
            "has_security_measures": await self._has_security_measures(target_host),
            "is_production": await self._is_production_environment(target_url),
            "has_monitoring": await self._has_monitoring_systems(target_host)
        }

    async def assess_agent_risk(self, agent_name: str, phase: AttackPhase) -> float:
        """Assess risk for specific agent execution"""
        try:
            risk_factors = []

            # Detection probability
            detection_risk = await self._assess_detection_risk(agent_name, phase)
            risk_factors.append(RiskFactor(
                name="detection_probability",
                weight=self.risk_weights["detection_probability"],
                value=detection_risk,
                description=f"Probability of detection for {agent_name}"
            ))

            # Legal risk
            legal_risk = await self._assess_legal_risk(agent_name, phase)
            risk_factors.append(RiskFactor(
                name="legal_risk",
                weight=self.risk_weights["legal_risk"],
                value=legal_risk,
                description=f"Legal risk for {agent_name}"
            ))

            # Technical complexity
            complexity_risk = await self._assess_complexity_risk(agent_name, phase)
            risk_factors.append(RiskFactor(
                name="technical_complexity",
                weight=self.risk_weights["technical_complexity"],
                value=complexity_risk,
                description=f"Technical complexity for {agent_name}"
            ))

            # Resource requirements
            resource_risk = await self._assess_resource_risk(agent_name, phase)
            risk_factors.append(RiskFactor(
                name="resource_requirements",
                weight=self.risk_weights["resource_requirements"],
                value=resource_risk,
                description=f"Resource requirements for {agent_name}"
            ))

            # Calculate overall risk score
            risk_score = sum(
                factor.weight * factor.value for factor in risk_factors)

            return min(risk_score, 1.0)  # Cap at 1.0

        except Exception as e:
            log.error(f"Failed to assess agent risk: {e}")
            return 0.5  # Default medium risk

    async def _assess_detection_risk(self, agent_name: str, phase: AttackPhase) -> float:
        """Assess detection probability"""
        # High detection risk agents
        high_detection_agents = [
            "DDoSAgent", "FuzzingAgent", "HydraAgent", "NucleiAgent", "APIFuzzerAgent"
        ]

        if agent_name in high_detection_agents:
            base_risk = 0.8
        else:
            base_risk = 0.3

        # Adjust based on target security measures
        if self.target_risk_profile.get("has_security_measures", False):
            base_risk += 0.2

        if self.target_risk_profile.get("has_monitoring", False):
            base_risk += 0.2

        # Adjust based on phase
        if phase == AttackPhase.DISRUPTION:
            base_risk += 0.3
        elif phase == AttackPhase.DEFENSE_EVASION:
            base_risk -= 0.1

        return min(base_risk, 1.0)

    async def _assess_legal_risk(self, agent_name: str, phase: AttackPhase) -> float:
        """Assess legal risk"""
        # High legal risk agents
        high_legal_risk_agents = [
            "DDoSAgent", "BotDeploymentAgent", "DataExfiltrationAgent"
        ]

        if agent_name in high_legal_risk_agents:
            base_risk = 0.9
        else:
            base_risk = 0.3

        # Adjust based on target type
        if self.target_risk_profile.get("is_government", False):
            base_risk += 0.3

        if self.target_risk_profile.get("is_corporate", False):
            base_risk += 0.2

        # Adjust based on phase
        if phase == AttackPhase.DISRUPTION:
            base_risk += 0.4
        elif phase == AttackPhase.PERSISTENCE:
            base_risk += 0.3

        return min(base_risk, 1.0)

    async def _assess_complexity_risk(self, agent_name: str, phase: AttackPhase) -> float:
        """Assess technical complexity risk"""
        # High complexity agents
        high_complexity_agents = [
            "LateralMovementAgent", "PrivilegeEscalationAgent",
            "ZeroDayHunterAgent", "DeserializationExploiterAgent"
        ]

        if agent_name in high_complexity_agents:
            base_risk = 0.7
        else:
            base_risk = 0.3

        # Adjust based on target complexity
        if self.target_risk_profile.get("is_production", False):
            base_risk += 0.2

        return min(base_risk, 1.0)

    async def _assess_resource_risk(self, agent_name: str, phase: AttackPhase) -> float:
        """Assess resource requirements risk"""
        # Resource-intensive agents
        resource_intensive_agents = [
            "FuzzingAgent", "ReconnaissanceMaster", "NucleiAgent", "APIFuzzerAgent"
        ]

        if agent_name in resource_intensive_agents:
            base_risk = 0.6
        else:
            base_risk = 0.2

        return min(base_risk, 1.0)

    async def _is_government_target(self, target_url: str) -> bool:
        """Check if target is government-related"""
        government_indicators = [
            ".gov", ".mil", "government", "federal", "state.gov"
        ]

        return any(indicator in target_url.lower() for indicator in government_indicators)

    async def _is_corporate_target(self, target_url: str) -> bool:
        """Check if target is corporate"""
        corporate_indicators = [
            ".com", ".org", "corp", "inc", "ltd", "company"
        ]

        return any(indicator in target_url.lower() for indicator in corporate_indicators)

    async def _has_security_measures(self, target_host: str) -> bool:
        """Check if target has security measures"""
        # This would perform actual checks
        # For now, return a placeholder
        return False

    async def _is_production_environment(self, target_url: str) -> bool:
        """Check if target is production environment"""
        production_indicators = [
            "www.", "app.", "api.", "prod.", "production"
        ]

        return any(indicator in target_url.lower() for indicator in production_indicators)

    async def _has_monitoring_systems(self, target_host: str) -> bool:
        """Check if target has monitoring systems"""
        # This would perform actual checks
        # For now, return a placeholder
        return False

    async def update_risk_assessment(self, execution_result: Dict[str, Any]):
        """Update risk assessment based on execution results"""
        try:
            agent_name = execution_result.get("agent_name", "")
            success = execution_result.get("success", False)
            errors = execution_result.get("errors", [])

            # Update historical risk data
            if agent_name not in self.historical_risks:
                self.historical_risks[agent_name] = {
                    "success_rate": 0.0,
                    "error_count": 0,
                    "total_attempts": 0
                }

            agent_history = self.historical_risks[agent_name]
            agent_history["total_attempts"] += 1

            if success:
                agent_history["success_rate"] = (
                    (agent_history["success_rate"] * (agent_history["total_attempts"] - 1) + 1.0) /
                    agent_history["total_attempts"]
                )
            else:
                agent_history["error_count"] += 1
                agent_history["success_rate"] = (
                    (agent_history["success_rate"] * (agent_history["total_attempts"] - 1) + 0.0) /
                    agent_history["total_attempts"]
                )

            # Update risk weights based on results
            if not success and len(errors) > 0:
                # Increase risk for agents that frequently fail
                if agent_history["error_count"] > agent_history["total_attempts"] * 0.5:
                    # This agent is high risk
                    if "high_risk_agents" not in self.historical_risks:
                        self.historical_risks["high_risk_agents"] = []

                    if agent_name not in self.historical_risks["high_risk_agents"]:
                        self.historical_risks["high_risk_agents"].append(
                            agent_name)

        except Exception as e:
            log.error(f"Failed to update risk assessment: {e}")

    async def get_risk_recommendations(self, agent_name: str, phase: AttackPhase) -> List[str]:
        """Get risk mitigation recommendations"""
        recommendations = []

        risk_score = await self.assess_agent_risk(agent_name, phase)

        if risk_score > 0.8:
            recommendations.extend([
                "Consider using stealth mode",
                "Implement additional evasion techniques",
                "Use proxy or VPN for anonymity",
                "Schedule execution during low-activity hours"
            ])
        elif risk_score > 0.6:
            recommendations.extend([
                "Use moderate stealth techniques",
                "Monitor for detection indicators",
                "Have backup plans ready"
            ])
        else:
            recommendations.extend([
                "Standard execution should be safe",
                "Monitor for any unexpected responses"
            ])

        return recommendations

    async def get_comprehensive_risk_assessment(self, strategies: List[Any]) -> RiskAssessment:
        """Get comprehensive risk assessment for multiple strategies"""
        try:
            all_factors = []
            total_risk_score = 0.0

            for strategy in strategies:
                agent_name = getattr(strategy, 'next_agent', '')
                phase = getattr(strategy, 'phase', AttackPhase.RECONNAISSANCE)

                risk_score = await self.assess_agent_risk(agent_name, phase)
                total_risk_score += risk_score

                # Get individual factors
                detection_risk = await self._assess_detection_risk(agent_name, phase)
                legal_risk = await self._assess_legal_risk(agent_name, phase)
                complexity_risk = await self._assess_complexity_risk(agent_name, phase)
                resource_risk = await self._assess_resource_risk(agent_name, phase)

                all_factors.extend([
                    RiskFactor("detection_probability", 0.3,
                               detection_risk, f"Detection risk for {agent_name}"),
                    RiskFactor("legal_risk", 0.2, legal_risk,
                               f"Legal risk for {agent_name}"),
                    RiskFactor("technical_complexity", 0.2, complexity_risk,
                               f"Complexity risk for {agent_name}"),
                    RiskFactor("resource_requirements", 0.1,
                               resource_risk, f"Resource risk for {agent_name}")
                ])

            # Calculate average risk score
            avg_risk_score = total_risk_score / \
                len(strategies) if strategies else 0.0

            # Determine overall risk level
            if avg_risk_score > 0.8:
                overall_risk = RiskLevel.CRITICAL
            elif avg_risk_score > 0.6:
                overall_risk = RiskLevel.HIGH
            elif avg_risk_score > 0.4:
                overall_risk = RiskLevel.MEDIUM
            else:
                overall_risk = RiskLevel.LOW

            # Generate recommendations
            recommendations = []
            mitigation_strategies = []

            if overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                recommendations.extend([
                    "Consider reducing attack intensity",
                    "Implement additional stealth measures",
                    "Use alternative attack vectors",
                    "Schedule attacks during low-activity periods"
                ])
                mitigation_strategies.extend([
                    "Use proxy chains for anonymity",
                    "Implement traffic obfuscation",
                    "Use living-off-the-land techniques",
                    "Implement time-based evasion"
                ])
            else:
                recommendations.extend([
                    "Standard execution should be safe",
                    "Monitor for detection indicators",
                    "Have contingency plans ready"
                ])
                mitigation_strategies.extend([
                    "Standard security measures",
                    "Basic monitoring",
                    "Regular backup plans"
                ])

            return RiskAssessment(
                overall_risk=overall_risk,
                risk_score=avg_risk_score,
                factors=all_factors,
                recommendations=recommendations,
                mitigation_strategies=mitigation_strategies
            )

        except Exception as e:
            log.error(f"Failed to get comprehensive risk assessment: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.MEDIUM,
                risk_score=0.5,
                factors=[],
                recommendations=["Unable to assess risk"],
                mitigation_strategies=["Use caution"]
            )

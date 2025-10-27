import asyncio
import json
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from core.logger import log
from core.data_models import Strategy, AttackPhase, ScanIntensity
import networkx as nx
from datetime import datetime, timedelta
from core.context_manager import ContextManager # Import ContextManager


class PlanningStrategy(Enum):
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"
    BALANCED = "balanced"
    ADAPTIVE = "adaptive"


@dataclass
class AttackNode:
    id: str
    agent_name: str
    phase: AttackPhase
    prerequisites: List[str] = field(default_factory=list)
    success_probability: float = 0.5
    time_estimate: int = 300  # seconds
    risk_level: str = "medium"
    resources_required: List[str] = field(default_factory=list)
    expected_outcome: str = ""


@dataclass
class AttackGraph:
    nodes: Dict[str, AttackNode] = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)
    start_nodes: List[str] = field(default_factory=list)
    end_nodes: List[str] = field(default_factory=list)


@dataclass
class PlanningContext:
    target_info: Dict[str, Any]
    available_agents: List[str]
    time_constraints: Dict[str, Any]
    risk_tolerance: str
    stealth_requirements: bool
    previous_attempts: List[Dict[str, Any]]
    success_history: Dict[str, float]


class AdvancedAIPlanner:
    def __init__(self, context_manager: ContextManager = None, orchestrator=None): # Changed shared_data to context_manager
        self.context_manager = context_manager # Changed shared_data to context_manager
        self.orchestrator = orchestrator
        self.attack_graph = AttackGraph()
        self.planning_context = None
        self.learning_engine = None
        self.risk_analyzer = None

    async def create_attack_plan(self, objective: str, context: PlanningContext) -> List[Strategy]:
        """Create comprehensive attack plan using AI planning"""
        try:
            self.planning_context = context

            # Initialize components
            await self._initialize_components()

            # Build attack graph
            await self._build_attack_graph(objective)

            # Optimize attack path
            optimal_path = await self._find_optimal_path()

            # Generate strategies
            strategies = await self._generate_strategies(optimal_path)

            # Validate and refine plan
            validated_plan = await self._validate_plan(strategies)

            log.info(
                f"Generated attack plan with {len(validated_plan)} strategies")
            return validated_plan

        except Exception as e:
            log.error(f"Failed to create attack plan: {e}")
            return []

    async def _initialize_components(self):
        """Initialize planning components"""
        from core.learning_engine import LearningEngine
        from core.risk_analyzer import RiskAnalyzer

        self.learning_engine = LearningEngine(self.context_manager) # Pass context_manager
        self.risk_analyzer = RiskAnalyzer(self.context_manager) # Pass context_manager

        await self.learning_engine.load_historical_data()
        await self.risk_analyzer.initialize()

    async def _build_attack_graph(self, objective: str):
        """Build comprehensive attack graph"""
        # Define attack phases and their relationships
        phase_relationships = {
            AttackPhase.RECONNAISSANCE: [AttackPhase.INITIAL_FOOTHOLD],
            AttackPhase.INITIAL_FOOTHOLD: [AttackPhase.ESCALATION, AttackPhase.DEFENSE_EVASION],
            AttackPhase.ESCALATION: [AttackPhase.PERSISTENCE, AttackPhase.DEFENSE_EVASION],
            AttackPhase.PERSISTENCE: [AttackPhase.DISRUPTION],
            AttackPhase.DEFENSE_EVASION: [AttackPhase.ESCALATION, AttackPhase.PERSISTENCE],
            AttackPhase.DISRUPTION: [AttackPhase.REPORTING],
            AttackPhase.REPORTING: []
        }

        # Create nodes for each phase
        for phase, next_phases in phase_relationships.items():
            agents = await self._get_agents_for_phase(phase)

            for agent in agents:
                node_id = f"{phase.name}_{agent}"
                node = AttackNode(
                    id=node_id,
                    agent_name=agent,
                    phase=phase,
                    success_probability=await self._calculate_success_probability(agent, phase),
                    time_estimate=await self._estimate_execution_time(agent),
                    risk_level=await self._assess_risk_level(agent, phase),
                    resources_required=await self._get_required_resources(agent),
                    expected_outcome=await self._get_expected_outcome(agent, phase)
                )

                self.attack_graph.nodes[node_id] = node

                # Add edges to next phases
                for next_phase in next_phases:
                    next_agents = await self._get_agents_for_phase(next_phase)
                    for next_agent in next_agents:
                        next_node_id = f"{next_phase.name}_{next_agent}"
                        if next_node_id in self.attack_graph.nodes:
                            self.attack_graph.edges.append(
                                (node_id, next_node_id))

        # Identify start and end nodes
        self.attack_graph.start_nodes = [node_id for node_id, node in self.attack_graph.nodes.items()
                                         if node.phase == AttackPhase.RECONNAISSANCE]
        self.attack_graph.end_nodes = [node_id for node_id, node in self.attack_graph.nodes.items()
                                       if node.phase == AttackPhase.REPORTING]

    async def _get_agents_for_phase(self, phase: AttackPhase) -> List[str]:
        """Get available agents for specific phase"""
        phase_agent_mapping = {
            AttackPhase.RECONNAISSANCE: [
                "ReconnaissanceMaster", "TriageAgent", "WafDetectorAgent",
                "NmapScanAgent", "TechnologyProfilerAgent"
            ],
            AttackPhase.INITIAL_FOOTHOLD: [
                "NucleiAgent", "FuzzingAgent", "ExploitAgent", "XSS_Agent",
                "SQLInjectionExploiter", "CommandInjectionExploiter", "APIFuzzerAgent"
            ],
            AttackPhase.ESCALATION: [
                "PostExAgent", "PrivilegeEscalationAgent", "LateralMovementAgent",
                "DataDumperAgent", "ShellAgent"
            ],
            AttackPhase.PERSISTENCE: [
                "PersistenceAgent", "BotDeploymentAgent"
            ],
            AttackPhase.DEFENSE_EVASION: [
                "WafBypassExpert", "LivingOffTheLandAgent", "DefensiveCountermeasuresAgent"
            ],
            AttackPhase.DISRUPTION: [
                "DDoSAgent"
            ],
            AttackPhase.REPORTING: [
                "ReportingAgent"
            ]
        }

        available_agents = phase_agent_mapping.get(phase, [])

        # Filter based on available agents in orchestrator
        if self.orchestrator and hasattr(self.orchestrator, 'agents'):
            available_agents = [agent for agent in available_agents
                                if agent in self.orchestrator.agents]

        return available_agents

    async def _calculate_success_probability(self, agent_name: str, phase: AttackPhase) -> float:
        """Calculate success probability for agent in specific phase"""
        if self.learning_engine:
            historical_success = await self.learning_engine.get_agent_success_rate(agent_name, phase)
            if historical_success is not None:
                return historical_success

        # Default success probabilities based on agent type
        default_probabilities = {
            "ReconnaissanceMaster": 0.9,
            "TriageAgent": 0.8,
            "NucleiAgent": 0.7,
            "FuzzingAgent": 0.6,
            "APIFuzzerAgent": 0.7,
            "ExploitAgent": 0.5,
            "XSS_Agent": 0.4,
            "SQLInjectionExploiter": 0.4,
            "CommandInjectionExploiter": 0.3,
            "DeserializationExploiterAgent": 0.3,
            "PostExAgent": 0.6,
            "PrivilegeEscalationAgent": 0.4,
            "LateralMovementAgent": 0.3,
            "PersistenceAgent": 0.7,
            "ReportingAgent": 0.95
        }

        return default_probabilities.get(agent_name, 0.5)

    async def _estimate_execution_time(self, agent_name: str) -> int:
        """Estimate execution time for agent"""
        if self.learning_engine:
            avg_time = await self.learning_engine.get_agent_avg_execution_time(agent_name)
            if avg_time is not None:
                return int(avg_time)

        # Default time estimates
        default_times = {
            "ReconnaissanceMaster": 600,
            "TriageAgent": 120,
            "NucleiAgent": 300,
            "FuzzingAgent": 900,
            "APIFuzzerAgent": 1200,
            "ExploitAgent": 180,
            "XSS_Agent": 240,
            "SQLInjectionExploiter": 300,
            "CommandInjectionExploiter": 180,
            "DeserializationExploiterAgent": 600,
            "PostExAgent": 300,
            "PrivilegeEscalationAgent": 240,
            "LateralMovementAgent": 600,
            "PersistenceAgent": 180,
            "ReportingAgent": 60
        }

        return default_times.get(agent_name, 300)

    async def _assess_risk_level(self, agent_name: str, phase: AttackPhase) -> str:
        """Assess risk level for agent execution"""
        if self.risk_analyzer:
            risk_score = await self.risk_analyzer.assess_agent_risk(agent_name, phase)
            if risk_score > 0.7:
                return "high"
            elif risk_score > 0.4:
                return "medium"
            else:
                return "low"

        # Default risk levels
        high_risk_agents = [
            "DDoSAgent", "ExploitAgent", "CommandInjectionExploiter",
            "LateralMovementAgent", "BotDeploymentAgent", "DeserializationExploiterAgent"
        ]

        medium_risk_agents = [
            "FuzzingAgent", "APIFuzzerAgent", "XSS_Agent", "SQLInjectionExploiter",
            "PrivilegeEscalationAgent", "PersistenceAgent"
        ]

        if agent_name in high_risk_agents:
            return "high"
        elif agent_name in medium_risk_agents:
            return "medium"
        else:
            return "low"

    async def _get_required_resources(self, agent_name: str) -> List[str]:
        """Get required resources for agent"""
        resource_mapping = {
            "ReconnaissanceMaster": ["nmap", "subfinder", "theharvester"],
            "NucleiAgent": ["nuclei"],
            "FuzzingAgent": ["ffuf", "wfuzz"],
            "APIFuzzerAgent": ["requests", "yaml"],
            "ExploitAgent": ["metasploit"],
            "SQLInjectionExploiter": ["sqlmap"],
            "DeserializationExploiterAgent": ["java", "ysoserial"],
            "HydraAgent": ["hydra"],
            "NmapScanAgent": ["nmap"]
        }

        return resource_mapping.get(agent_name, [])

    async def _get_expected_outcome(self, agent_name: str, phase: AttackPhase) -> str:
        """Get expected outcome for agent execution"""
        outcome_mapping = {
            "ReconnaissanceMaster": "Target information and attack surface discovery",
            "TriageAgent": "Prioritized findings and next steps",
            "NucleiAgent": "Vulnerability scan results",
            "FuzzingAgent": "Input validation vulnerabilities",
            "APIFuzzerAgent": "API security vulnerabilities",
            "ExploitAgent": "System compromise or shell access",
            "XSS_Agent": "Cross-site scripting vulnerabilities",
            "SQLInjectionExploiter": "Database access or information disclosure",
            "DeserializationExploiterAgent": "Deserialization vulnerabilities",
            "PostExAgent": "Post-exploitation activities and data collection",
            "PrivilegeEscalationAgent": "Elevated privileges",
            "LateralMovementAgent": "Network access and pivoting",
            "PersistenceAgent": "Persistent access establishment",
            "ReportingAgent": "Comprehensive attack report"
        }

        return outcome_mapping.get(agent_name, "Agent execution completion")

    async def _find_optimal_path(self) -> List[str]:
        """Find optimal attack path using graph algorithms"""
        try:
            # Create NetworkX graph
            G = nx.DiGraph()

            # Add nodes with weights
            for node_id, node in self.attack_graph.nodes.items():
                # Weight based on success probability (inverse) and risk
                weight = (1.0 - node.success_probability) * 100
                if node.risk_level == "high":
                    weight *= 2
                elif node.risk_level == "medium":
                    weight *= 1.5

                G.add_node(node_id, weight=weight, node_data=node)

            # Add edges
            for edge in self.attack_graph.edges:
                G.add_edge(edge[0], edge[1])

            # Find shortest path from start to end
            optimal_path = []
            min_cost = float('inf')

            for start_node in self.attack_graph.start_nodes:
                for end_node in self.attack_graph.end_nodes:
                    try:
                        path = nx.shortest_path(
                            G, start_node, end_node, weight='weight')
                        path_cost = sum(G.nodes[node]['weight']
                                        for node in path)

                        if path_cost < min_cost:
                            min_cost = path_cost
                            optimal_path = path
                    except nx.NetworkXNoPath:
                        continue

            if not optimal_path:
                # Fallback to simple path
                optimal_path = self.attack_graph.start_nodes[:1] + \
                    self.attack_graph.end_nodes[:1]

            log.info(
                f"Found optimal attack path with {len(optimal_path)} nodes")
            return optimal_path

        except Exception as e:
            log.error(f"Failed to find optimal path: {e}")
            return self.attack_graph.start_nodes[:1] if self.attack_graph.start_nodes else []

    async def _generate_strategies(self, path: List[str]) -> List[Strategy]:
        """Generate strategies from optimal path"""
        strategies = []

        for i, node_id in enumerate(path):
            if node_id not in self.attack_graph.nodes:
                continue

            node = self.attack_graph.nodes[node_id]

            # Determine scan intensity based on context
            scan_intensity = ScanIntensity.NORMAL
            if self.planning_context.stealth_requirements:
                scan_intensity = ScanIntensity.STEALTH
            elif self.planning_context.risk_tolerance == "high":
                scan_intensity = ScanIntensity.AGGRESSIVE

            strategy = Strategy(
                phase=node.phase,
                next_agent=node.agent_name,
                directive=f"Execute {node.agent_name} for {node.expected_outcome}",
                context={
                    "node_id": node_id,
                    "success_probability": node.success_probability,
                    "risk_level": node.risk_level,
                    "time_estimate": node.time_estimate,
                    "resources_required": node.resources_required,
                    "expected_outcome": node.expected_outcome
                },
                scan_intensity=scan_intensity
            )

            strategies.append(strategy)

        return strategies

    async def _validate_plan(self, strategies: List[Strategy]) -> List[Strategy]:
        """Validate and refine attack plan"""
        validated_strategies = []

        for strategy in strategies:
            # Check if agent is available
            if (self.orchestrator and hasattr(self.orchestrator, 'agents') and
                    strategy.next_agent not in self.orchestrator.agents):
                log.warning(
                    f"Agent {strategy.next_agent} not available, skipping")
                continue

            # Check resource availability
            required_resources = strategy.context.get("resources_required", [])
            if required_resources:
                available_resources = await self._check_resource_availability(required_resources)
                if not available_resources:
                    log.warning(
                        f"Required resources not available for {strategy.next_agent}")
                    continue

            # Check time constraints
            time_estimate = strategy.context.get("time_estimate", 300)
            if self.planning_context.time_constraints.get("max_execution_time", 0) < time_estimate:
                log.warning(
                    f"Time estimate exceeds constraints for {strategy.next_agent}")
                continue

            validated_strategies.append(strategy)

        return validated_strategies

    async def _check_resource_availability(self, required_resources: List[str]) -> bool:
        """Check if required resources are available"""
        # This would check if tools are installed and available
        # For now, return True as a placeholder
        return True

    async def adapt_plan(self, current_strategy: Strategy, execution_result: Dict[str, Any]) -> List[Strategy]:
        """Adapt plan based on execution results"""
        try:
            # Update learning engine with results
            if self.learning_engine:
                await self.learning_engine.update_agent_performance(
                    current_strategy.next_agent,
                    current_strategy.phase,
                    execution_result
                )

            # Reassess risk based on results
            if self.risk_analyzer:
                await self.risk_analyzer.update_risk_assessment(execution_result)

            # Generate new strategies based on results
            if execution_result.get("success", False):
                # Success - continue with next phase
                next_strategies = await self._generate_next_strategies(current_strategy, execution_result)
            else:
                # Failure - try alternative approaches
                next_strategies = await self._generate_alternative_strategies(current_strategy, execution_result)

            return next_strategies

        except Exception as e:
            log.error(f"Failed to adapt plan: {e}")
            return []

    async def _generate_next_strategies(self, current_strategy: Strategy, result: Dict[str, Any]) -> List[Strategy]:
        """Generate next strategies after successful execution"""
        # This would generate strategies for the next phase
        # Implementation depends on specific results
        return []

    async def _generate_alternative_strategies(self, current_strategy: Strategy, result: Dict[str, Any]) -> List[Strategy]:
        """Generate alternative strategies after failed execution"""
        # This would generate alternative approaches
        # Implementation depends on failure reasons
        return []

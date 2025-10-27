"""
Enhanced AI Orchestrator with Advanced Capabilities
ตามแผนการพัฒนา Manus AI Attack Platform Phase 1
"""

import asyncio
import json
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass

from .orchestrator import Orchestrator
from .data_models import Strategy, AgentData, ErrorType, AttackPhase
from .logger import log


@dataclass
class AgentScore:
    """Agent scoring result"""
    agent_name: str
    score: float
    confidence: float
    reasoning: str
    historical_success_rate: float
    risk_score: float


@dataclass
class ResourceAllocation:
    """Resource allocation for agents"""
    agent_name: str
    cpu_cores: int
    memory_mb: int
    execution_time_limit: int  # seconds
    priority: int


class EnhancedOrchestrator(Orchestrator):
    """Enhanced AI Orchestrator with advanced capabilities"""

    def __init__(self, config_path: Optional[str] = None, workspace_dir: Optional[str] = None):
        """Initialize Enhanced Orchestrator"""
        super().__init__(config_path, workspace_dir)

        # Enhanced capabilities
        self.agent_selection_history = []
        self.parallel_execution_enabled = True
        self.resource_optimization_enabled = True
        self.failure_recovery_enabled = True
        self.performance_monitor = None  # Initialize performance monitor attribute

    async def select_optimal_agents(
        self,
        phase: AttackPhase,
        context: Dict[str, Any],
        constraints: Dict[str, Any]
    ) -> List[str]:
        """
        AI-driven agent selection based on:
        - Historical success rates
        - Target characteristics
        - Resource availability
        - Time constraints

        Returns list of selected agent names
        """
        log.info(f"AI selecting optimal agents for phase: {phase}")

        try:
            # Get candidate agents for this phase
            candidates = self._get_agents_for_phase(phase)

            if not candidates:
                log.warning(f"No candidates found for phase {phase}")
                return []

            # Score each agent using AI
            scored_agents = []
            for agent_name in candidates:
                score = await self._score_agent(
                    agent_name=agent_name,
                    phase=phase,
                    context=context,
                    constraints=constraints
                )
                scored_agents.append(score)

            # Sort by score and select top agents
            scored_agents.sort(key=lambda x: x.score, reverse=True)

            # Apply constraints
            max_agents = constraints.get('max_agents', 5)
            min_score = constraints.get('min_score', 0.5)

            selected = [
                agent.agent_name for agent in scored_agents
                if agent.score >= min_score
            ][:max_agents]

            # Log selection
            log.info(f"Selected {len(selected)} agents: {selected}")
            self.agent_selection_history.append({
                'timestamp': datetime.now().isoformat(),
                'phase': phase.name,
                'candidates': candidates,
                'selected': selected,
                'scores': [s.score for s in scored_agents]
            })

            return selected

        except Exception as e:
            log.error(f"Failed to select agents: {e}")
            # Fallback to basic selection
            return self._get_agents_for_phase(phase)[:5]

    async def _score_agent(
        self,
        agent_name: str,
        phase: AttackPhase,
        context: Dict[str, Any],
        constraints: Dict[str, Any]
    ) -> AgentScore:
        """Score individual agent using AI analysis"""
        try:
            # Get historical performance
            historical_success_rate = self._get_agent_success_rate(agent_name)

            # Get target compatibility
            target_compatibility = await self._assess_target_compatibility(
                agent_name, context.get('target_info', {})
            )

            # Get resource requirements
            resource_score = self._assess_resource_requirements(agent_name, constraints)

            # Get risk assessment
            risk_score = await self._assess_agent_risk(agent_name, phase)

            # Calculate composite score
            composite_score = (
                historical_success_rate * 0.3 +
                target_compatibility * 0.3 +
                resource_score * 0.2 +
                (1 - risk_score) * 0.2
            )

            # Generate reasoning
            reasoning = await self._generate_agent_reasoning(
                agent_name, phase, historical_success_rate, risk_score
            )

            return AgentScore(
                agent_name=agent_name,
                score=composite_score,
                confidence=0.85,  # Base confidence
                reasoning=reasoning,
                historical_success_rate=historical_success_rate,
                risk_score=risk_score
            )

        except Exception as e:
            log.error(f"Failed to score agent {agent_name}: {e}")
            return AgentScore(
                agent_name=agent_name,
                score=0.5,
                confidence=0.1,
                reasoning=f"Scoring failed: {e}",
                historical_success_rate=0.5,
                risk_score=0.5
            )

    def _get_agents_for_phase(self, phase: AttackPhase) -> List[str]:
        """Get list of agents suitable for a phase"""
        phase_agent_mapping = {
            AttackPhase.RECONNAISSANCE: [
                'NmapAgent', 'WhatWebAgent', 'SubdomainEnumerator',
                'PortScannerAgent', 'TechnologyDetectorAgent'
            ],
            AttackPhase.VULNERABILITY_DISCOVERY: [
                'NucleiAgent', 'WPScanAgent', 'SQLMapAgent',
                'XSSScannerAgent', 'OpenVASAgent'
            ],
            AttackPhase.EXPLOITATION: [
                'SQLInjectionExploiter', 'XXEAgent', 'CommandInjectionExploiter',
                'FileUploadExploiter', 'PrivilegeEscalator'
            ],
            AttackPhase.POST_EXPLOITATION: [
                'DataExfiltrator', 'PersistenceAgent', 'LateralMovementAgent',
                'CredentialHarvesterAgent'
            ]
        }

        return phase_agent_mapping.get(phase, [])

    def _get_agent_success_rate(self, agent_name: str) -> float:
        """Get historical success rate for agent"""
        # This would normally query a database
        # For now, return a mock value based on agent name
        base_rates = {
            'NmapAgent': 0.95,
            'WhatWebAgent': 0.90,
            'SubdomainEnumerator': 0.85,
            'NucleiAgent': 0.92,
            'SQLMapAgent': 0.88,
            'SQLInjectionExploiter': 0.80,
            'XXEAgent': 0.75,
            'DataExfiltrator': 0.85,
        }

        return base_rates.get(agent_name, 0.70)

    async def _assess_target_compatibility(self, agent_name: str, target_info: Dict[str, Any]) -> float:
        """Assess how compatible agent is with target"""
        # Mock implementation - would normally use AI analysis
        target_type = target_info.get('type', 'web')
        agent_capabilities = {
            'NmapAgent': ['network', 'web'],
            'SQLMapAgent': ['web', 'database'],
            'XXEAgent': ['web', 'xml'],
        }

        compatible_types = agent_capabilities.get(agent_name, [])
        return 0.9 if target_type in compatible_types else 0.3

    def _assess_resource_requirements(self, agent_name: str, constraints: Dict[str, Any]) -> float:
        """Assess if agent fits resource constraints"""
        # Mock resource requirements
        agent_resources = {
            'NmapAgent': {'cpu': 1, 'memory': 512},
            'SQLMapAgent': {'cpu': 2, 'memory': 1024},
            'XXEAgent': {'cpu': 1, 'memory': 768},
        }

        requirements = agent_resources.get(agent_name, {'cpu': 1, 'memory': 512})
        available_cpu = constraints.get('max_cpu', 8)
        available_memory = constraints.get('max_memory', 4096)

        cpu_score = min(requirements['cpu'] / available_cpu, 1.0)
        memory_score = min(requirements['memory'] / available_memory, 1.0)

        return (cpu_score + memory_score) / 2

    async def _assess_agent_risk(self, agent_name: str, phase: AttackPhase) -> float:
        """Assess risk level of using agent"""
        # Mock risk assessment
        risk_factors = {
            ('SQLInjectionExploiter', AttackPhase.EXPLOITATION): 0.3,
            ('XXEAgent', AttackPhase.EXPLOITATION): 0.4,
            ('CommandInjectionExploiter', AttackPhase.EXPLOITATION): 0.5,
        }

        return risk_factors.get((agent_name, phase), 0.2)

    async def _generate_agent_reasoning(
        self, agent_name: str, phase: AttackPhase, success_rate: float, risk: float
    ) -> str:
        """Generate AI reasoning for agent selection"""
        return f"Selected {agent_name} for {phase.name} due to {success_rate:.1%} success rate and {risk:.1%} risk level"

    async def coordinate_parallel_execution(
        self,
        agent_names: List[str],
        context: Dict[str, Any],
        phase: AttackPhase
    ) -> List[AgentData]:
        """Execute multiple agents in parallel with coordination"""
        log.info(f"Coordinating parallel execution of {len(agent_names)} agents")

        # Allocate resources
        allocations = self._allocate_resources(agent_names, phase)

        # Create execution tasks
        tasks = []
        for agent_name in agent_names:
            task = asyncio.create_task(
                self._execute_agent_with_monitoring(
                    agent_name=agent_name,
                    context=context,
                    phase=phase,
                    allocation=allocations.get(agent_name)
                )
            )
            tasks.append(task)

        # Execute with timeout
        timeout_seconds = context.get('execution_timeout', 300)  # 5 minutes default
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            log.error(f"Parallel execution timed out after {timeout_seconds} seconds")
            return []

        # Process results and handle failures
        processed_results = []
        failed_agents = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                failed_agents.append(agent_names[i])
                log.error(f"Agent {agent_names[i]} failed: {result}")
            else:
                processed_results.append(result)

        # Handle failures with AI decision
        if failed_agents and self.failure_recovery_enabled:
            recovery_results = await self._handle_execution_failures(
                failed_agents=failed_agents,
                successful_results=processed_results,
                context=context,
                phase=phase
            )
            processed_results.extend(recovery_results)

        return processed_results

    def _allocate_resources(self, agent_names: List[str], phase: AttackPhase) -> Dict[str, ResourceAllocation]:
        """Allocate resources to agents"""
        allocations = {}

        for agent_name in agent_names:
            # Mock resource allocation logic
            base_allocation = {
                'NmapAgent': ResourceAllocation(agent_name, 1, 512, 120, 1),
                'SQLMapAgent': ResourceAllocation(agent_name, 2, 1024, 300, 2),
                'XXEAgent': ResourceAllocation(agent_name, 1, 768, 180, 1),
            }

            allocation = base_allocation.get(agent_name)
            if allocation:
                allocations[agent_name] = allocation

        return allocations

    async def _execute_agent_with_monitoring(
        self,
        agent_name: str,
        context: Dict[str, Any],
        phase: AttackPhase,
        allocation: Optional[ResourceAllocation] = None
    ) -> Optional[AgentData]:
        """Execute agent with resource monitoring and error handling"""
        try:
            # Set up resource monitoring
            if allocation:
                # Apply resource limits (mock implementation)
                pass

            # Create strategy
            strategy = Strategy(
                phase=phase,
                directive=f"Execute {agent_name} with phase {phase.name}",
                context=context,
                next_agent=agent_name
            )

            # Execute agent
            result = await self.execute_agent_directly(agent_name, strategy)

            # Monitor resource usage (mock)
            if allocation:
                log.info(f"Agent {agent_name} used resources: CPU={allocation.cpu_cores}, Memory={allocation.memory_mb}MB")

            return result

        except Exception as e:
            log.error(f"Agent {agent_name} execution failed: {e}")
            return AgentData(
                agent_name=agent_name,
                success=False,
                errors=[str(e)],
                error_type=ErrorType.EXECUTION_FAILED
            )

    async def _handle_execution_failures(
        self,
        failed_agents: List[str],
        successful_results: List[AgentData],
        context: Dict[str, Any],
        phase: AttackPhase
    ) -> List[AgentData]:
        """Handle failed agent executions with AI decision making"""
        recovery_results = []

        for failed_agent in failed_agents:
            # Get failure details
            failure_analysis = await self._analyze_failure(failed_agent, phase, context)

            # Decide recovery action
            recovery_action = await self._decide_recovery_action(
                failed_agent=failed_agent,
                failure_analysis=failure_analysis,
                context=context,
                phase=phase
            )

            if recovery_action == "retry":
                # Retry with different parameters
                retry_result = await self._retry_agent(
                    agent_name=failed_agent,
                    context=context,
                    phase=phase,
                    retry_params=failure_analysis.get('retry_params', {})
                )
                if retry_result:
                    recovery_results.append(retry_result)

            elif recovery_action == "skip":
                log.info(f"Skipping recovery for {failed_agent} - not critical")
                # Continue without this agent

            elif recovery_action == "replace":
                # Replace with alternative agent
                replacement_result = await self._find_replacement_agent(
                    failed_agent=failed_agent,
                    context=context,
                    phase=phase
                )
                if replacement_result:
                    recovery_results.append(replacement_result)

        return recovery_results

    async def _analyze_failure(
        self,
        agent_name: str,
        phase: AttackPhase,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze why agent failed"""
        # Mock failure analysis
        return {
            'failure_type': 'timeout',  # timeout, auth_error, network_error, etc.
            'retry_params': {'timeout': 600},  # Additional parameters for retry
            'alternative_agents': self._get_alternative_agents(agent_name, phase),
            'confidence': 0.8
        }

    async def _decide_recovery_action(
        self,
        failed_agent: str,
        failure_analysis: Dict[str, Any],
        context: Dict[str, Any],
        phase: AttackPhase
    ) -> str:
        """Decide how to handle agent failure"""
        failure_type = failure_analysis.get('failure_type', 'unknown')

        # Decision logic based on failure type and phase criticality
        critical_phases = [AttackPhase.EXPLOITATION, AttackPhase.POST_EXPLOITATION]

        if failure_type == 'timeout' and phase in critical_phases:
            return "retry"
        elif failure_type == 'auth_error':
            return "replace"
        else:
            return "skip"

    async def _retry_agent(
        self,
        agent_name: str,
        context: Dict[str, Any],
        phase: AttackPhase,
        retry_params: Dict[str, Any]
    ) -> Optional[AgentData]:
        """Retry agent execution with modified parameters"""
        try:
            # Update context with retry parameters
            retry_context = {**context, **retry_params}

            strategy = Strategy(
                phase=phase,
                directive=f"Retry {agent_name} with modified parameters",
                context=retry_context,
                next_agent=agent_name
            )

            log.info(f"Retrying agent {agent_name} with parameters: {retry_params}")
            return await self.execute_agent_directly(agent_name, strategy)

        except Exception as e:
            log.error(f"Retry failed for {agent_name}: {e}")
            return None

    def _get_alternative_agents(self, failed_agent: str, phase: AttackPhase) -> List[str]:
        """Get list of alternative agents for failed agent"""
        alternatives = {
            'SQLInjectionExploiter': ['SQLMapAgent', 'ManualSQLInjector'],
            'XXEAgent': ['XMLExternalEntityScanner', 'BlindXXEExploiter'],
            'CommandInjectionExploiter': ['OSCommandInjector', 'WebShellExploiter'],
        }

        return alternatives.get(failed_agent, [])

    async def _find_replacement_agent(
        self,
        failed_agent: str,
        context: Dict[str, Any],
        phase: AttackPhase
    ) -> Optional[AgentData]:
        """Find and execute replacement agent"""
        alternatives = self._get_alternative_agents(failed_agent, phase)

        for alt_agent in alternatives:
            if alt_agent in self.agent_registry.agents:
                try:
                    strategy = Strategy(
                        phase=phase,
                        directive=f"Replace {failed_agent} with {alt_agent}",
                        context=context,
                        next_agent=alt_agent
                    )

                    log.info(f"Using replacement agent {alt_agent} for {failed_agent}")
                    return await self.execute_agent_directly(alt_agent, strategy)

                except Exception as e:
                    log.warning(f"Replacement agent {alt_agent} also failed: {e}")
                    continue

        log.warning(f"No suitable replacement found for {failed_agent}")
        return None

    def _get_optimal_resource_allocation(
        self,
        agent_names: List[str],
        phase: AttackPhase,
        constraints: Dict[str, Any]
    ) -> Dict[str, ResourceAllocation]:
        """Optimize resource allocation for agents"""
        if not self.resource_optimization_enabled:
            return self._allocate_resources(agent_names, phase)

        # Advanced resource optimization logic
        total_cpu = constraints.get('max_cpu', 8)
        total_memory = constraints.get('max_memory', 4096)

        # Simple optimization: allocate based on agent priority and resource needs
        allocations = {}
        remaining_cpu = total_cpu
        remaining_memory = total_memory

        # Sort agents by priority (mock priority system)
        agent_priorities = {
            'SQLInjectionExploiter': 1,  # High priority
            'XXEAgent': 2,
            'NmapAgent': 3,  # Lower priority
        }

        sorted_agents = sorted(
            agent_names,
            key=lambda x: agent_priorities.get(x, 5)  # Default priority 5
        )

        for agent_name in sorted_agents:
            base_allocation = self._allocate_resources([agent_name], phase)[agent_name]

            # Adjust allocation based on remaining resources
            if remaining_cpu >= base_allocation.cpu_cores and remaining_memory >= base_allocation.memory_mb:
                allocations[agent_name] = base_allocation
                remaining_cpu -= base_allocation.cpu_cores
                remaining_memory -= base_allocation.memory_mb
            else:
                # Scale down allocation
                scaled_allocation = ResourceAllocation(
                    agent_name=agent_name,
                    cpu_cores=min(base_allocation.cpu_cores, remaining_cpu),
                    memory_mb=min(base_allocation.memory_mb, remaining_memory),
                    execution_time_limit=base_allocation.execution_time_limit,
                    priority=base_allocation.priority
                )
                allocations[agent_name] = scaled_allocation
                remaining_cpu -= scaled_allocation.cpu_cores
                remaining_memory -= scaled_allocation.memory_mb

                if remaining_cpu <= 0 or remaining_memory <= 0:
                    log.warning("Insufficient resources for all agents")
                    break

        return allocations

    async def get_orchestration_metrics(self) -> Dict[str, Any]:
        """Get metrics about orchestration performance"""
        return {
            'agent_selection_count': len(self.agent_selection_history),
            'parallel_execution_enabled': self.parallel_execution_enabled,
            'resource_optimization_enabled': self.resource_optimization_enabled,
            'failure_recovery_enabled': self.failure_recovery_enabled,
            'total_executions': len(self.execution_history),
            'average_execution_time': self._calculate_avg_execution_time(),
            'success_rate': self._calculate_overall_success_rate()
        }

    def _calculate_avg_execution_time(self) -> float:
        """Calculate average execution time"""
        if not self.execution_history:
            return 0.0

        total_time = sum(
            (entry.get('end_time', 0) - entry.get('start_time', 0))
            for entry in self.execution_history
        )
        return total_time / len(self.execution_history)

    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate"""
        if not self.campaign_results:
            return 0.0

        successful_results = sum(1 for result in self.campaign_results if result and result.success)
        return successful_results / len(self.campaign_results)
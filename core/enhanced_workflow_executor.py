"""
Enhanced Workflow Executor - Execute complex attack chains
Orchestrates multiple agents in coordinated sequences with 124 agents
"""

import asyncio
import yaml
import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger("dLNk")


@dataclass
class WorkflowContext:
    """Context for workflow execution"""
    workflow_id: str
    target: Dict[str, Any]
    variables: Dict[str, Any]
    phase_results: Dict[str, Any]
    success: bool = False
    error: Optional[str] = None


class EnhancedWorkflowExecutor:
    """
    Execute attack workflows with multiple phases and agents
    Supports conditional execution, parallel agents, and adaptive replanning
    Integrates all 124 agents in coordinated attack chains
    """
    
    def __init__(self, orchestrator, ai_planner):
        self.orchestrator = orchestrator
        self.ai_planner = ai_planner
        self.workflows_dir = "workflows/attack_chains"
        self.active_workflows = {}
        
        logger.info("Enhanced Workflow Executor initialized")
    
    async def execute_workflow(
        self,
        workflow_name: str,
        target: Dict[str, Any],
        variables: Optional[Dict[str, Any]] = None
    ) -> WorkflowContext:
        """
        Execute a complete attack workflow
        
        Args:
            workflow_name: Name of workflow file (without .yaml)
            target: Target information
            variables: Additional variables for workflow
        
        Returns:
            WorkflowContext with results
        """
        workflow_id = f"{workflow_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(f"Starting workflow: {workflow_id}")
        
        # Load workflow definition
        workflow_def = self._load_workflow(workflow_name)
        if not workflow_def:
            return WorkflowContext(
                workflow_id=workflow_id,
                target=target,
                variables=variables or {},
                phase_results={},
                success=False,
                error="Workflow definition not found"
            )
        
        # Initialize context
        context = WorkflowContext(
            workflow_id=workflow_id,
            target=target,
            variables=variables or {},
            phase_results={}
        )
        
        self.active_workflows[workflow_id] = context
        
        try:
            # Execute phases sequentially
            for phase in workflow_def.get('phases', []):
                phase_name = phase['name']
                logger.info(f"Executing phase: {phase_name}")
                
                # Check phase condition
                if not self._evaluate_condition(phase.get('condition'), context):
                    logger.info(f"Skipping phase {phase_name} - condition not met")
                    continue
                
                # Execute phase
                phase_result = await self._execute_phase(phase, context, workflow_def)
                context.phase_results[phase_name] = phase_result
                
                # Check if phase succeeded
                if not phase_result.get('success', False):
                    logger.warning(f"Phase {phase_name} failed")
                    
                    # Handle failure
                    if not phase.get('always_run', False):
                        on_failure = phase.get('on_failure', {})
                        action = on_failure.get('action', 'abort')
                        
                        if action == 'abort':
                            context.error = f"Phase {phase_name} failed"
                            break
                        elif action == 'retry':
                            # Retry phase
                            max_retries = on_failure.get('max_retries', 1)
                            for retry in range(max_retries):
                                logger.info(f"Retrying phase {phase_name} (attempt {retry+1}/{max_retries})")
                                phase_result = await self._execute_phase(phase, context, workflow_def)
                                if phase_result.get('success', False):
                                    context.phase_results[phase_name] = phase_result
                                    break
                        elif action == 'fallback':
                            # Use fallback agents
                            fallback_agents = on_failure.get('fallback_agents', [])
                            if fallback_agents:
                                logger.info(f"Using fallback agents for {phase_name}")
                                phase['agents'] = [{'name': agent} for agent in fallback_agents]
                                phase_result = await self._execute_phase(phase, context, workflow_def)
                                context.phase_results[phase_name] = phase_result
                
                # Update context variables with phase outputs
                self._update_context_variables(context, phase_result)
            
            # Check overall success
            success_criteria = workflow_def.get('success_criteria', {})
            context.success = self._evaluate_success_criteria(success_criteria, context)
            
            logger.info(f"Workflow {workflow_id} completed - Success: {context.success}")
            
        except Exception as e:
            logger.error(f"Workflow execution error: {e}")
            context.error = str(e)
            context.success = False
        
        finally:
            # Cleanup
            if workflow_id in self.active_workflows:
                del self.active_workflows[workflow_id]
        
        return context
    
    async def _execute_phase(
        self,
        phase: Dict[str, Any],
        context: WorkflowContext,
        workflow_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single phase of the workflow"""
        
        phase_name = phase['name']
        agents_config = phase.get('agents', [])
        
        # Separate parallel and sequential agents
        parallel_agents = []
        sequential_agents = []
        
        for agent_config in agents_config:
            if agent_config.get('parallel', False):
                parallel_agents.append(agent_config)
            else:
                sequential_agents.append(agent_config)
        
        phase_result = {
            'phase': phase_name,
            'success': False,
            'agent_results': {},
            'outputs': {}
        }
        
        # Execute sequential agents
        for agent_config in sequential_agents:
            # Check agent condition
            if not self._evaluate_condition(agent_config.get('condition'), context):
                logger.info(f"Skipping agent {agent_config['name']} - condition not met")
                continue
            
            # Check dependencies
            depends_on = agent_config.get('depends_on', [])
            if depends_on:
                all_deps_met = all(
                    phase_result['agent_results'].get(dep, {}).get('success', False)
                    for dep in depends_on
                )
                if not all_deps_met:
                    logger.warning(f"Skipping agent {agent_config['name']} - dependencies not met")
                    continue
            
            # Execute agent
            agent_result = await self._execute_agent(agent_config, context, workflow_def)
            phase_result['agent_results'][agent_config['name']] = agent_result
            
            # Merge outputs
            if 'outputs' in agent_result:
                phase_result['outputs'].update(agent_result['outputs'])
        
        # Execute parallel agents
        if parallel_agents:
            parallel_tasks = []
            for agent_config in parallel_agents:
                if self._evaluate_condition(agent_config.get('condition'), context):
                    task = self._execute_agent(agent_config, context, workflow_def)
                    parallel_tasks.append((agent_config['name'], task))
            
            # Wait for all parallel agents
            if parallel_tasks:
                results = await asyncio.gather(*[task for _, task in parallel_tasks], return_exceptions=True)
                for (agent_name, _), result in zip(parallel_tasks, results):
                    if isinstance(result, Exception):
                        logger.error(f"Parallel agent {agent_name} failed: {result}")
                        phase_result['agent_results'][agent_name] = {'success': False, 'error': str(result)}
                    else:
                        phase_result['agent_results'][agent_name] = result
                        if 'outputs' in result:
                            phase_result['outputs'].update(result['outputs'])
        
        # Evaluate phase success
        success_criteria = phase.get('success_criteria', [])
        if success_criteria:
            phase_result['success'] = all(
                self._evaluate_condition(criterion, context, phase_result['outputs'])
                for criterion in success_criteria
            )
        else:
            # Default: success if any agent succeeded
            phase_result['success'] = any(
                result.get('success', False)
                for result in phase_result['agent_results'].values()
            )
        
        return phase_result
    
    async def _execute_agent(
        self,
        agent_config: Dict[str, Any],
        context: WorkflowContext,
        workflow_def: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single agent"""
        
        agent_name = agent_config['name']
        logger.info(f"Executing agent: {agent_name}")
        
        try:
            # Get agent from orchestrator
            agent_class = self.orchestrator.agent_registry.get_agent_class(agent_name)
            if not agent_class:
                logger.error(f"Agent {agent_name} not found in registry")
                return {'success': False, 'error': 'Agent not found'}
            
            # Instantiate agent
            agent = agent_class(
                context_manager=self.orchestrator.context_manager,
                orchestrator=self.orchestrator
            )
            
            # Prepare agent config
            config = agent_config.get('config', {})
            
            # Substitute variables in config
            config = self._substitute_variables(config, context)
            
            # Execute agent
            result = await agent.run(**config)
            
            # Extract outputs
            outputs = {}
            expected_outputs = agent_config.get('outputs', [])
            for output_name in expected_outputs:
                if hasattr(result, output_name):
                    outputs[output_name] = getattr(result, output_name)
            
            return {
                'success': result.success if hasattr(result, 'success') else True,
                'outputs': outputs,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Agent {agent_name} execution failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _load_workflow(self, workflow_name: str) -> Optional[Dict[str, Any]]:
        """Load workflow definition from YAML file"""
        
        workflow_path = os.path.join(self.workflows_dir, f"{workflow_name}.yaml")
        
        if not os.path.exists(workflow_path):
            logger.error(f"Workflow file not found: {workflow_path}")
            return None
        
        try:
            with open(workflow_path, 'r') as f:
                workflow_def = yaml.safe_load(f)
            return workflow_def
        except Exception as e:
            logger.error(f"Failed to load workflow: {e}")
            return None
    
    def _evaluate_condition(
        self,
        condition: Optional[str],
        context: WorkflowContext,
        additional_vars: Optional[Dict] = None
    ) -> bool:
        """Evaluate a condition string"""
        
        if not condition:
            return True
        
        # Build evaluation context
        eval_vars = {
            **context.variables,
            **context.phase_results,
            'target': context.target
        }
        
        if additional_vars:
            eval_vars.update(additional_vars)
        
        try:
            # Simple condition evaluation
            # In production, use a proper expression evaluator
            
            # Handle "is not empty"
            if " is not empty" in condition:
                var_name = condition.split(" is not empty")[0].strip()
                value = eval_vars.get(var_name)
                return bool(value)
            
            # Handle "contains"
            if " contains " in condition:
                parts = condition.split(" contains ")
                var_name = parts[0].strip()
                search_value = parts[1].strip().strip("'\"")
                value = eval_vars.get(var_name)
                if isinstance(value, (list, str)):
                    return search_value in value
                return False
            
            # Handle "=="
            if " == " in condition:
                parts = condition.split(" == ")
                left = parts[0].strip()
                right = parts[1].strip().strip("'\"")
                
                # Handle boolean
                if right.lower() in ['true', 'false']:
                    right = right.lower() == 'true'
                
                left_value = eval_vars.get(left, left)
                return left_value == right
            
            # Default: check if variable exists and is truthy
            return bool(eval_vars.get(condition))
            
        except Exception as e:
            logger.error(f"Condition evaluation error: {e}")
            return False
    
    def _evaluate_success_criteria(
        self,
        criteria: Dict[str, List[str]],
        context: WorkflowContext
    ) -> bool:
        """Evaluate workflow success criteria"""
        
        # Check minimum requirements
        minimum = criteria.get('minimum_requirements', [])
        if minimum:
            all_met = all(
                self._evaluate_condition(req, context)
                for req in minimum
            )
            if not all_met:
                return False
        
        # Check optimal requirements (nice to have, not required)
        optimal = criteria.get('optimal_requirements', [])
        if optimal:
            optimal_met = sum(
                1 for req in optimal
                if self._evaluate_condition(req, context)
            )
            logger.info(f"Optimal requirements met: {optimal_met}/{len(optimal)}")
        
        return True
    
    def _update_context_variables(
        self,
        context: WorkflowContext,
        phase_result: Dict[str, Any]
    ):
        """Update context variables with phase outputs"""
        
        if 'outputs' in phase_result:
            context.variables.update(phase_result['outputs'])
    
    def _substitute_variables(
        self,
        config: Dict[str, Any],
        context: WorkflowContext
    ) -> Dict[str, Any]:
        """Substitute variables in config"""
        
        import re
        
        def substitute_value(value):
            if isinstance(value, str):
                # Find {variable} patterns
                pattern = r'\{([^}]+)\}'
                matches = re.findall(pattern, value)
                for match in matches:
                    var_value = context.variables.get(match, f"{{{match}}}")
                    if isinstance(var_value, str):
                        value = value.replace(f"{{{match}}}", var_value)
                    else:
                        value = var_value
                return value
            elif isinstance(value, dict):
                return {k: substitute_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [substitute_value(item) for item in value]
            else:
                return value
        
        return substitute_value(config)
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get status of running workflow"""
        
        context = self.active_workflows.get(workflow_id)
        if not context:
            return None
        
        return {
            'workflow_id': workflow_id,
            'target': context.target,
            'phases_completed': len(context.phase_results),
            'success': context.success,
            'error': context.error
        }
    
    def list_workflows(self) -> List[str]:
        """List available workflows"""
        
        if not os.path.exists(self.workflows_dir):
            return []
        
        workflows = []
        for file in os.listdir(self.workflows_dir):
            if file.endswith('.yaml'):
                workflows.append(file[:-5])  # Remove .yaml extension
        
        return workflows


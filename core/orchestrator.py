"""
AI-Driven Intelligent Orchestrator for dLNk Attack Framework
ระบบประสานงานที่ขับเคลื่อนด้วย AI และเข้าใจบริบทจริงๆ
ไม่ทำงานแบบแข็งๆ แต่ปรับตัวตามสถานการณ์
"""

import asyncio
import yaml
import ollama
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

from .logger import log
from .agent_registry import AgentRegistry
from .context_manager import ContextManager
from .pubsub_manager import PubSubManager
from .data_models import Strategy, AgentData, ErrorType, AttackPhase
from .workflow_executor import WorkflowExecutor


class Orchestrator:
    """AI-Driven Intelligent Orchestrator that understands context and adapts dynamically"""

    def __init__(self, config_path: Optional[str] = None, workspace_dir: Optional[str] = None):
        """
        Initialize the AI-Driven Intelligent Orchestrator
        
        Args:
            config_path: Path to configuration file
            workspace_dir: Working directory for the framework
        """
        self.config_path = config_path
        self.workspace_dir = workspace_dir or Path.cwd() / "workspace"
        self.workspace_dir = Path(self.workspace_dir)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

        # Initialize core components
        self.agent_registry = AgentRegistry()
        self.context_manager = ContextManager()
        self.pubsub_manager = PubSubManager()
        self.workflow_executor = WorkflowExecutor(self)
        
        # AI Intelligence System
        self.ai_model = "mistral:latest"
        self.ai_context = {}  # Store AI understanding context
        self.learning_memory = {}  # Store learning patterns
        self.adaptive_strategies = {}  # Store adaptive strategies
        
        # State management
        self.running = False
        self.campaign_results = []
        self.current_phase = None
        self.start_time = None
        self.end_time = None

        log.info("AI-Driven Intelligent Orchestrator initialized successfully")

    async def initialize(self):
        """Initialize AI intelligence and discover all agents"""
        log.info("Initializing AI-Driven Intelligent Orchestrator...")
        
        try:
            # Auto-discover agents
            self.agent_registry.auto_discover_agents(agents_dir=str(Path(__file__).parent.parent / "agents"))
            log.success(f"Discovered {len(self.agent_registry.agents)} agents")
            
            # Initialize context manager
            await self.context_manager.setup()
            log.success("Context manager initialized")
            
            # Initialize PubSub manager
            await self.pubsub_manager.setup()
            log.success("PubSub manager initialized")

            # Initialize AI intelligence system
            await self._initialize_ai_intelligence()

            # Re-initialize logger with Redis client for streaming
            # Dynamically reconfigure the existing logger with Redis client
            from core.logger import get_logger, log as current_log_instance
            new_log_instance = get_logger(redis_client=self.context_manager.redis)
            # Copy handlers from new_log_instance to current_log_instance
            current_log_instance.handlers = new_log_instance.handlers
            current_log_instance.setLevel(new_log_instance.level)
            current_log_instance.propagate = new_log_instance.propagate
            
        except Exception as e:
            log.error(f"Failed to initialize Orchestrator: {e}", exc_info=True)
            raise

    async def _initialize_ai_intelligence(self):
        """Initialize AI intelligence system"""
        try:
            # Load existing AI context and learning data
            await self._load_ai_memory()
            
            # Initialize AI understanding of available agents
            await self._analyze_agent_capabilities()
            
            # Set up adaptive strategy system
            await self._setup_adaptive_strategies()
            
            log.success("AI Intelligence system initialized")
        except Exception as e:
            log.error(f"Failed to initialize AI intelligence: {e}")

    async def _load_ai_memory(self):
        """Load AI learning memory from previous sessions"""
        try:
            memory_file = self.workspace_dir / "ai_memory.json"
            if memory_file.exists():
                with open(memory_file, "r") as f:
                    self.learning_memory = json.load(f)
                log.info(f"Loaded AI memory with {len(self.learning_memory)} learning patterns")
        except Exception as e:
            log.warning(f"Failed to load AI memory: {e}")

    async def _analyze_agent_capabilities(self):
        """Use AI to analyze and understand agent capabilities"""
        try:
            available_agents = list(self.agent_registry.agents.keys())
            
            prompt = f"""
            Analyze the following attack agents and understand their capabilities:
            
            Available Agents: {available_agents}
            
            For each agent, understand:
            1. What type of attacks they can perform
            2. What phases they work best in
            3. How they can work together
            4. What makes them effective
            
            Focus on attack capabilities and how to use them for maximum effectiveness.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist who understands offensive security tools and techniques."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            self.ai_context["agent_analysis"] = response['message']['content']
            log.info("AI analyzed agent capabilities")
            
        except Exception as e:
            log.error(f"Failed to analyze agent capabilities: {e}")

    async def _setup_adaptive_strategies(self):
        """Set up adaptive strategy system"""
        try:
            prompt = """
            Create adaptive attack strategies that can change based on:
            1. Target characteristics
            2. Attack success/failure
            3. Environmental factors
            4. Available resources
            
            Focus on offensive strategies that maximize attack effectiveness.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist specializing in adaptive offensive techniques."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            self.adaptive_strategies["base_strategies"] = response['message']['content']
            log.info("Adaptive strategies initialized")
            
        except Exception as e:
            log.error(f"Failed to setup adaptive strategies: {e}")

    async def load_workflow(self, workflow_path: str) -> Dict[str, Any]:
        """Load workflow configuration from YAML file"""
        try:
            with open(workflow_path, 'r') as f:
                workflow = yaml.safe_load(f)
            log.info(f"Loaded workflow: {workflow.get('workflow_name', 'Unknown')}")
            return workflow
        except Exception as e:
            log.error(f"Failed to load workflow: {e}")
            raise

    async def execute_workflow(self, workflow_path: str, target: Dict[str, Any]) -> List[AgentData]:
        """
        Execute AI-driven intelligent workflow against a target
        
        Args:
            workflow_path: Path to the workflow YAML file
            target: Target information dictionary
            
        Returns:
            List of AgentData results from all executed agents
        """
        self.running = True
        self.start_time = datetime.now()
        self.campaign_results = []
        try:
            # AI Analysis of target and workflow
            await self._ai_analyze_target_and_workflow(workflow_path, target)
            
            # Load workflow
            workflow = await self.load_workflow(workflow_path)
            
            # Generate a unique workflow ID for this execution
            workflow_run_id = f"workflow_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            await self.context_manager.set_context("current_workflow_id", workflow_run_id)
            await self.context_manager.set_context("current_target", target)
            
            # AI-driven workflow execution
            await self._ai_execute_workflow(workflow, target)

            log.success("AI-driven workflow execution completed")
            
        except Exception as e:
            log.error(f"Workflow execution failed: {e}", exc_info=True)
            raise
        finally:
            self.running = False
            self.end_time = datetime.now()

        return self.campaign_results

    async def _ai_analyze_target_and_workflow(self, workflow_path: str, target: Dict[str, Any]):
        """Use AI to analyze target and workflow for optimal execution"""
        try:
            prompt = f"""
            Analyze the target and workflow for optimal attack execution:
            
            Target: {target}
            Workflow Path: {workflow_path}
            
            Provide:
            1. Target vulnerability assessment
            2. Optimal attack strategy
            3. Risk factors and considerations
            4. Recommended modifications to workflow
            5. Success probability estimation
            
            Focus on maximizing attack effectiveness and minimizing detection.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist analyzing targets and workflows for maximum effectiveness."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            self.ai_context["target_analysis"] = response['message']['content']
            log.info("AI analyzed target and workflow")
            
        except Exception as e:
            log.error(f"Failed to analyze target and workflow: {e}")

    async def _ai_execute_workflow(self, workflow: Dict[str, Any], target: Dict[str, Any]):
        """AI-driven workflow execution with adaptive strategies"""
        try:
            phases = workflow.get('phases', [])
            
            for i, phase in enumerate(phases):
                log.info(f"Executing phase {i+1}: {phase.get('name', 'Unknown')}")
                
                # AI analysis of current phase
                phase_analysis = await self._ai_analyze_phase(phase, target)
                
                # Execute phase with AI guidance
                result = await self._ai_execute_phase(phase, target, phase_analysis)
                
                # AI decision making for next steps
                next_action = await self._ai_decide_next_action(result, phase, target)
                
                if next_action == "continue":
                    continue
                elif next_action == "skip":
                    log.info("AI decided to skip remaining phases")
                    break
                elif next_action == "adapt":
                    log.info("AI decided to adapt workflow")
                    await self._ai_adapt_workflow(phases[i+1:], target, result)

        except Exception as e:
            log.error(f"AI workflow execution failed: {e}")

    async def _ai_analyze_phase(self, phase: Dict[str, Any], target: Dict[str, Any]) -> Dict:
        """Use AI to analyze current phase"""
        try:
            prompt = f"""
            Analyze the current attack phase:
            
            Phase: {phase}
            Target: {target}
            
            Provide:
            1. Phase effectiveness assessment
            2. Recommended modifications
            3. Risk assessment
            4. Success probability
            5. Alternative approaches if needed
            
            Focus on attack effectiveness and stealth.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist analyzing attack phases."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            return {"analysis": response['message']['content']}
            
        except Exception as e:
            log.error(f"Failed to analyze phase: {e}")
            return {"analysis": "Analysis failed"}

    async def _ai_execute_phase(self, phase: Dict[str, Any], target: Dict[str, Any], analysis: Dict) -> bool:
        """Execute phase with AI guidance"""
        try:
            # Use AI analysis to modify phase execution
            if "modify" in analysis.get("analysis", "").lower():
                log.info("AI recommended phase modifications")
                # Apply AI-recommended modifications
            
            # Execute phase with enhanced intelligence
            result = await self._execute_phase(phase)
            
            # Learn from execution result
            await self._ai_learn_from_execution(phase, target, result, analysis)
            
            return result
            
        except Exception as e:
            log.error(f"AI phase execution failed: {e}")
            return False

    async def _ai_decide_next_action(self, result: bool, phase: Dict[str, Any], target: Dict[str, Any]) -> str:
        """Use AI to decide next action based on phase result"""
        try:
            prompt = f"""
            Decide the next action based on phase execution:
            
            Phase Result: {result}
            Phase: {phase.get('name', 'Unknown')}
            Target: {target}
            
            Choose one action:
            1. "continue" - Continue to next phase
            2. "skip" - Skip remaining phases
            3. "adapt" - Adapt workflow strategy
            
            Provide reasoning for your decision.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist making tactical decisions."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Parse AI response to determine action
            response_text = response['message']['content'].lower()
            if "continue" in response_text:
                return "continue"
            elif "skip" in response_text:
                return "skip"
            elif "adapt" in response_text:
                return "adapt"
            else:
                return "continue"  # Default action
                
        except Exception as e:
            log.error(f"Failed to decide next action: {e}")
            return "continue"

    async def _ai_adapt_workflow(self, remaining_phases: List[Dict], target: Dict[str, Any], result: bool):
        """Use AI to adapt remaining workflow phases"""
        try:
            prompt = f"""
            Adapt the remaining workflow phases based on current results:
            
            Remaining Phases: {remaining_phases}
            Target: {target}
            Current Result: {result}
            
            Provide:
            1. Modified phases
            2. New attack strategies
            3. Risk mitigation
            4. Success optimization
            
            Focus on adaptive attack strategies.
            """
            
            response = ollama.chat(
                model=self.ai_model,
                messages=[
                    {"role": "system", "content": "You are an expert attack strategist adapting workflows in real-time."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            log.info("AI adapted workflow strategy")
            
        except Exception as e:
            log.error(f"Failed to adapt workflow: {e}")

    async def _ai_learn_from_execution(self, phase: Dict[str, Any], target: Dict[str, Any], result: bool, analysis: Dict):
        """Learn from execution results"""
        try:
            learning_data = {
                "timestamp": datetime.now().isoformat(),
                "phase": phase,
                "target": target,
                "result": result,
                "analysis": analysis
            }
            
            # Store learning data (convert non-serializable objects)
            serializable_data = {}
            for key, value in learning_data.items():
                try:
                    json.dumps(value)  # Test if serializable
                    serializable_data[key] = value
                except (TypeError, ValueError):
                    # Convert non-serializable objects to string
                    serializable_data[key] = str(value)
            
            self.learning_memory[datetime.now().isoformat()] = serializable_data
            
            # Save learning memory
            memory_file = self.workspace_dir / "ai_memory.json"
            with open(memory_file, "w") as f:
                json.dump(self.learning_memory, f, indent=2)
            
            log.info("AI learned from execution")
            
        except Exception as e:
            log.error(f"Failed to learn from execution: {e}")

    async def _execute_phase(self, phase: Dict[str, Any]) -> bool:
        """Execute a single phase with its agents"""
        phase_name = phase.get('name', 'Unknown')
        self.current_phase = phase_name
        
        log.phase(f"Executing phase: {phase_name}")
        
        try:
            # Check for parallel agents
            if 'parallel_agents' in phase:
                results = await self._execute_parallel_agents(phase['parallel_agents'])
            else:
                results = await self._execute_sequential_agents(phase.get('agents', []))
            
            # Store results
            self.campaign_results.extend(results)
            
            # Check if all agents succeeded
            success = all(r.success for r in results if r)
            
            if success:
                log.success(f"Phase {phase_name} completed successfully")
            else:
                log.warning(f"Phase {phase_name} had some failures")
            
            return success
            
        except Exception as e:
            log.error(f"Phase {phase_name} execution failed: {e}", exc_info=True)
            return False

    async def _execute_sequential_agents(self, agents: List[Dict[str, Any]]) -> List[AgentData]:
        """Execute agents sequentially"""
        results = []
        
        for agent_config in agents:
            result = await self._execute_agent_config(agent_config)
            results.append(result)
            
            # Stop if an agent fails (optional - can be configured)
            if result and not result.success:
                log.warning(f"Agent {agent_config.get('name')} failed, continuing with next agent")
        
        return results

    async def _execute_parallel_agents(self, agents: List[Dict[str, Any]]) -> List[AgentData]:
        """Execute agents in parallel"""
        tasks = [self._execute_agent_config(agent_config) for agent_config in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        # Filter out None results from failed agents, but keep successful ones
        return [result for result in results if not isinstance(result, Exception) and result is not None]

    async def _execute_agent_config(self, agent_config: Dict[str, Any]) -> Optional[AgentData]:
        """Execute a single agent based on configuration"""
        agent_name = agent_config.get('name')
        directive = agent_config.get('directive', '')
        context = agent_config.get('context', {})
        
        try:
            workflow_id = await self.context_manager.get_context('current_workflow_id')
            target_info = await self.context_manager.get_context('current_target')
            target_id = target_info.get('name') if target_info else None

            log.info(f"Executing agent: {agent_name}", extra={
                "agent_name": agent_name,
                "workflow_id": workflow_id,
                "target_id": target_id
            })
            
            # Get agent instance
            agent = await self.agent_registry.get_agent(
                agent_name,
                context_manager=self.context_manager,
                orchestrator=self
            )
            
            # Create strategy
            # Normalize phase name to match enum
            phase_name = self.current_phase.replace(" ", "_").replace("&", "AND").upper()
            # Handle special cases
            if phase_name == "ANALYSIS_AND_REPORTING":
                phase_name = "ANALYSIS_REPORTING"
            elif phase_name == "API_SECURITY_TESTING":
                phase_name = "API_SECURITY_TESTING"
            
            try:
                phase_enum = AttackPhase[phase_name]
            except KeyError:
                log.warning(f"Phase '{self.current_phase}' (normalized: '{phase_name}') not found in AttackPhase enum, using RECONNAISSANCE")
                phase_enum = AttackPhase.RECONNAISSANCE
            
            strategy = Strategy(
                phase=phase_enum,
                directive=directive,
                context=context,
                next_agent=agent_name # Add required next_agent field
            )
            
            # Execute agent with error handling
            result = await agent.execute_with_error_handling(strategy)
            
            if result.success:
                log.success(f"Agent {agent_name} completed successfully")
            else:
                log.warning(f"Agent {agent_name} failed: {result.errors}")
            
            return result
            
        except Exception as e:
            log.error(f"Failed to execute agent {agent_name}: {e}", exc_info=True)
            return AgentData(
                agent_name=agent_name,
                success=False,
                errors=[str(e)],
                error_type=ErrorType.EXECUTION_FAILED
            )

    async def execute_agent_directly(self, agent_name: str, strategy: Strategy) -> AgentData:
        """Execute a single agent directly"""
        try:
            agent = await self.agent_registry.get_agent(
                agent_name,
                context_manager=self.context_manager,
                orchestrator=self
            )
            workflow_id = await self.context_manager.get_context("current_workflow_id")
            target_info = await self.context_manager.get_context("current_target")
            target_id = target_info.get("name") if target_info else None
            
            # Pass extra context to the agent's logger
            strategy.context["workflow_id"] = workflow_id
            strategy.context["target_id"] = target_id

            return await agent.execute_with_error_handling(strategy, extra={
                "workflow_id": workflow_id,
                "target_id": target_id,
                "agent_name": agent_name # Ensure agent_name is also explicitly passed
            })
        except Exception as e:
            log.error(f"Failed to execute agent {agent_name}: {e}", exc_info=True)
            return AgentData(
                agent_name=agent_name,
                success=False,
                errors=[str(e)],
                error_type=ErrorType.EXECUTION_FAILED
            )

    def get_registered_agents(self) -> List[str]:
        """Get list of all registered agents"""
        return list(self.agent_registry.agents.keys())

    def get_agent_info(self, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific agent"""
        agent_class = self.agent_registry.get_agent_class(agent_name)
        if not agent_class:
            return None
        
        return {
            'name': agent_name,
            'class': agent_class.__name__,
            'doc': agent_class.__doc__,
            'config': self.agent_registry.agent_configs.get(agent_name, {})
        }

    async def cleanup(self):
        """Cleanup resources"""
        log.info("Cleaning up Orchestrator resources...")
        await self.context_manager.cleanup()
        await self.pubsub_manager.close()
        log.success("Cleanup completed")

    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status"""
        return {
            'running': self.running,
            'current_phase': self.current_phase,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'results_count': len(self.campaign_results),
            'agents_registered': len(self.agent_registry.agents)
        }


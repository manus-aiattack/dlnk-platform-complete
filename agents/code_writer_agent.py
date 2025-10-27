"""
Code Writer Agent - Self-Modifying AI Agent

This agent can write and modify its own code based on:
1. Failed attack attempts
2. New vulnerability discoveries
3. Performance metrics
4. Feedback from other agents

It uses LLM to generate new agent code or modify existing agents.

WARNING: This is extremely powerful and dangerous. Use with caution!
"""

import asyncio
import os
import ast
import importlib
import sys
from typing import Dict, List, Optional, Any
from loguru import logger
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from datetime import datetime
import json

try:
    from core.llm_provider import get_llm_response
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.warning("LLM provider not available")


class CodeWriterAgent(BaseAgent):
    """
    Agent that can write and modify code.
    
    This agent achieves true autonomy by modifying itself and other agents
    based on experience and feedback.
    """
    
    supported_phases = [AttackPhase.POST_EXPLOITATION]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, agents_dir: str = "agents", **kwargs):
        """
        Initialize Code Writer Agent.
        
        Args:
            context_manager: Context manager instance
            orchestrator: Orchestrator instance
            agents_dir: Directory containing agent code
        """
        super().__init__(context_manager, orchestrator, **kwargs)
        self.agents_dir = agents_dir
        self.modification_history = []
        self.model = "mixtral:latest"
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "create" or "modify"
            context: {
                "agent_name": name of agent,
                "purpose": purpose of agent (for create),
                "target_vulnerability": vulnerability type (for create),
                "modification_request": what to modify (for modify),
                "failure_context": failure context (for modify)
            }
        
        Returns:
            AgentData with agent creation/modification results
        """
        logger.info(f"[CodeWriterAgent] {directive} agent")
        
        try:
            if directive == "create":
                agent_name = context.get("agent_name")
                purpose = context.get("purpose")
                target_vuln = context.get("target_vulnerability")
                
                if not all([agent_name, purpose, target_vuln]):
                    return AgentData(
                        agent_name="CodeWriterAgent",
                        success=False,
                        data={"error": "Missing required parameters"}
                    )
                
                result = await self.create_new_agent(
                    agent_name,
                    purpose,
                    target_vuln,
                    context.get("example_exploits")
                )
            
            elif directive == "modify":
                agent_name = context.get("agent_name")
                modification = context.get("modification_request")
                
                if not all([agent_name, modification]):
                    return AgentData(
                        agent_name="CodeWriterAgent",
                        success=False,
                        data={"error": "Missing required parameters"}
                    )
                
                result = await self.modify_agent(
                    agent_name,
                    modification,
                    context.get("failure_context")
                )
            
            else:
                return AgentData(
                    agent_name="CodeWriterAgent",
                    success=False,
                    data={"error": f"Unknown directive: {directive}"}
                )
            
            if result:
                return AgentData(
                    agent_name="CodeWriterAgent",
                    success=True,
                    data=result
                )
            else:
                return AgentData(
                    agent_name="CodeWriterAgent",
                    success=False,
                    data={"error": "Operation failed"}
                )
        
        except Exception as e:
            logger.error(f"[CodeWriterAgent] Error: {e}")
            return AgentData(
                agent_name="CodeWriterAgent",
                success=False,
                data={"error": str(e)}
            )
        
    async def create_new_agent(
        self,
        agent_name: str,
        purpose: str,
        target_vulnerability: str,
        example_exploits: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Create a brand new agent from scratch using AI.
        
        Args:
            agent_name: Name for the new agent
            purpose: What the agent should do
            target_vulnerability: Vulnerability type to target
            example_exploits: Example exploits for reference
            
        Returns:
            Dictionary with agent code and metadata
        """
        logger.info(f"🤖 Creating new agent: {agent_name}")
        logger.info(f"   Purpose: {purpose}")
        logger.info(f"   Target: {target_vulnerability}")
        
        if not LLM_AVAILABLE:
            logger.error("Cannot create agent without LLM")
            return None
        
        # Build prompt for LLM
        prompt = self._build_agent_creation_prompt(
            agent_name,
            purpose,
            target_vulnerability,
            example_exploits
        )
        
        try:
            # Generate agent code with LLM
            response = await get_llm_response(prompt, model=self.model)
            
            # Extract Python code from response
            code = self._extract_code(response)
            
            if not code:
                logger.error("Failed to extract code from LLM response")
                return None
            
            # Validate code
            if not self._validate_code(code):
                logger.error("Generated code failed validation")
                return None
            
            # Save agent
            agent_path = os.path.join(self.agents_dir, f"{agent_name}.py")
            with open(agent_path, 'w') as f:
                f.write(code)
            
            logger.info(f"✅ New agent created: {agent_path}")
            
            # Record creation
            self.modification_history.append({
                'type': 'creation',
                'agent_name': agent_name,
                'timestamp': datetime.now().isoformat(),
                'purpose': purpose,
                'file_path': agent_path
            })
            
            return {
                'agent_name': agent_name,
                'code': code,
                'file_path': agent_path,
                'status': 'created'
            }
            
        except Exception as e:
            logger.error(f"Agent creation failed: {e}")
            return None
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute code writer agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _build_agent_creation_prompt(
        self,
        agent_name: str,
        purpose: str,
        target_vulnerability: str,
        example_exploits: List[Dict]
    ) -> str:
        """Build prompt for agent creation."""
        
        prompt = f"""You are an expert Python developer specializing in penetration testing tools.

Create a new penetration testing agent with the following specifications:

AGENT NAME: {agent_name}
PURPOSE: {purpose}
TARGET VULNERABILITY: {target_vulnerability}

REQUIREMENTS:
1. Create a complete Python class that inherits from BaseAgent (if available) or is standalone
2. Implement async methods for scanning and exploitation
3. Include proper error handling and logging
4. Use modern Python 3.11+ features
5. Follow the existing agent patterns in the codebase
6. Include docstrings and type hints
7. Make it production-ready

AGENT STRUCTURE:
```python
import asyncio
from typing import Dict, List, Optional
from loguru import logger
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase

class {agent_name}:
    \"\"\"
    Agent for {purpose}
    
    Targets: {target_vulnerability}
    \"\"\"
    
    def __init__(self):
        self.name = "{agent_name}"
        self.vulnerability_type = "{target_vulnerability}"
    
    async def scan(self, target_url: str) -> List[Dict]:
        \"\"\"Scan for vulnerabilities.\"\"\"
        self.log(f"{self.__class__.__name__} method called")
            
    async def exploit(self, target_url: str, vulnerability: Dict) -> Dict:
        \"\"\"Exploit discovered vulnerability.\"\"\"
        self.log(f"{self.__class__.__name__} method called")
        ```
"""
        
        if example_exploits:
            prompt += "\n\nEXAMPLE EXPLOITS FOR REFERENCE:\n"
            for i, exploit in enumerate(example_exploits[:3], 1):
                prompt += f"\n{i}. {exploit.get('description', 'N/A')}\n"
                prompt += f"   Payload: {exploit.get('payload', 'N/A')}\n"
        
        prompt += "\n\nGenerate the complete agent code now. Return ONLY the Python code, no explanations."
        
        return prompt
    
    async def modify_agent(
        self,
        agent_name: str,
        modification_request: str,
        failure_context: Dict = None
    ) -> Dict[str, Any]:
        """
        Modify an existing agent based on feedback or failures.
        
        Args:
            agent_name: Name of agent to modify
            modification_request: What to change
            failure_context: Context about failures that prompted modification
            
        Returns:
            Dictionary with modified code and metadata
        """
        logger.info(f"🔧 Modifying agent: {agent_name}")
        logger.info(f"   Request: {modification_request}")
        
        if not LLM_AVAILABLE:
            logger.error("Cannot modify agent without LLM")
            return None
        
        # Read current agent code
        agent_path = os.path.join(self.agents_dir, f"{agent_name}.py")
        
        if not os.path.exists(agent_path):
            logger.error(f"Agent not found: {agent_path}")
            return None
        
        with open(agent_path, 'r') as f:
            current_code = f.read()
        
        # Build modification prompt
        prompt = self._build_modification_prompt(
            agent_name,
            current_code,
            modification_request,
            failure_context
        )
        
        try:
            # Generate modified code
            response = await get_llm_response(prompt, model=self.model)
            
            # Extract code
            modified_code = self._extract_code(response)
            
            if not modified_code:
                logger.error("Failed to extract modified code")
                return None
            
            # Validate
            if not self._validate_code(modified_code):
                logger.error("Modified code failed validation")
                return None
            
            # Backup original
            backup_path = f"{agent_path}.backup.{int(datetime.now().timestamp())}"
            with open(backup_path, 'w') as f:
                f.write(current_code)
            
            # Save modified code
            with open(agent_path, 'w') as f:
                f.write(modified_code)
            
            logger.info(f"✅ Agent modified: {agent_path}")
            logger.info(f"   Backup: {backup_path}")
            
            # Record modification
            self.modification_history.append({
                'type': 'modification',
                'agent_name': agent_name,
                'timestamp': datetime.now().isoformat(),
                'modification_request': modification_request,
                'file_path': agent_path,
                'backup_path': backup_path
            })
            
            return {
                'agent_name': agent_name,
                'code': modified_code,
                'file_path': agent_path,
                'backup_path': backup_path,
                'status': 'modified'
            }
            
        except Exception as e:
            logger.error(f"Agent modification failed: {e}")
            return None
    
    def _build_modification_prompt(
        self,
        agent_name: str,
        current_code: str,
        modification_request: str,
        failure_context: Dict
    ) -> str:
        """Build prompt for agent modification."""
        
        prompt = f"""You are an expert Python developer. Modify the following agent code.

AGENT NAME: {agent_name}

CURRENT CODE:
```python
{current_code}
```

MODIFICATION REQUEST:
{modification_request}
"""
        
        if failure_context:
            prompt += f"\n\nFAILURE CONTEXT:\n"
            prompt += f"- Failed attempts: {failure_context.get('failed_attempts', 0)}\n"
            prompt += f"- Error messages: {failure_context.get('errors', [])}\n"
            prompt += f"- Success rate: {failure_context.get('success_rate', 0)}%\n"
        
        prompt += """

REQUIREMENTS:
1. Keep the existing structure and interface
2. Improve the requested functionality
3. Fix any bugs or issues
4. Add better error handling if needed
5. Maintain compatibility with the rest of the system

Return ONLY the complete modified Python code, no explanations.
"""
        
        return prompt
    
    def _extract_code(self, response: str) -> Optional[str]:
        """Extract Python code from LLM response."""
        
        # Try to find code blocks
        import re
        
        # Look for ```python ... ``` blocks
        code_blocks = re.findall(r'```python\n(.*?)\n```', response, re.DOTALL)
        
        if code_blocks:
            return code_blocks[0]
        
        # Look for ``` ... ``` blocks
        code_blocks = re.findall(r'```\n(.*?)\n```', response, re.DOTALL)
        
        if code_blocks:
            return code_blocks[0]
        
        # If no code blocks, assume entire response is code
        return response
    
    def _validate_code(self, code: str) -> bool:
        """Validate Python code syntax."""
        
        try:
            ast.parse(code)
            return True
        except SyntaxError as e:
            logger.error(f"Code validation failed: {e}")
            return False
    
    async def improve_agent_from_failures(
        self,
        agent_name: str,
        failure_logs: List[Dict]
    ) -> Dict[str, Any]:
        """
        Automatically improve agent based on failure logs.
        
        Args:
            agent_name: Agent to improve
            failure_logs: List of failure records
            
        Returns:
            Modification result
        """
        logger.info(f"🧠 Analyzing failures for {agent_name}")
        
        # Analyze failures
        analysis = self._analyze_failures(failure_logs)
        
        # Generate modification request
        modification_request = f"""
Based on {len(failure_logs)} failures, improve the agent to:

1. Fix common errors: {', '.join(analysis['common_errors'][:3])}
2. Improve success rate (current: {analysis['success_rate']}%)
3. Add better error handling for: {', '.join(analysis['error_types'][:3])}
4. Optimize payload generation
5. Add retry logic with exponential backoff
"""
        
        # Modify agent
        result = await self.modify_agent(
            agent_name,
            modification_request,
            failure_context=analysis
        )
        
        return result
    
    def _analyze_failures(self, failure_logs: List[Dict]) -> Dict[str, Any]:
        """Analyze failure logs to identify patterns."""
        
        total = len(failure_logs)
        errors = [log.get('error', '') for log in failure_logs]
        
        # Count error types
        error_types = {}
        for error in errors:
            error_type = error.split(':')[0] if ':' in error else 'Unknown'
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        # Find common errors
        common_errors = sorted(error_types.items(), key=lambda x: x[1], reverse=True)
        
        # Calculate success rate (assuming we have success data)
        successes = sum(1 for log in failure_logs if log.get('success', False))
        success_rate = (successes / total * 100) if total > 0 else 0
        
        return {
            'total_attempts': total,
            'failed_attempts': total - successes,
            'success_rate': success_rate,
            'common_errors': [err[0] for err in common_errors],
            'error_types': list(error_types.keys()),
            'errors': errors[:10]  # Last 10 errors
        }
    
    def get_modification_history(self) -> List[Dict]:
        """Get history of all modifications."""
        return self.modification_history
    
    async def test_agent(self, agent_name: str, test_target: str) -> Dict[str, Any]:
        """
        Test an agent after creation/modification.
        
        Args:
            agent_name: Agent to test
            test_target: Test target URL
            
        Returns:
            Test results
        """
        logger.info(f"🧪 Testing agent: {agent_name}")
        
        try:
            # Dynamically import the agent
            module_name = f"agents.{agent_name}"
            
            # Reload if already imported
            if module_name in sys.modules:
                importlib.reload(sys.modules[module_name])
            else:
                importlib.import_module(module_name)
            
            module = sys.modules[module_name]
            
            # Find the agent class
            agent_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and attr_name != 'BaseAgent':
                    agent_class = attr
                    break
            
            if not agent_class:
                logger.error(f"No agent class found in {module_name}")
                return {'status': 'error', 'message': 'No agent class found'}
            
            # Instantiate and test
            agent = agent_class()
            
            # Run scan
            results = await agent.scan(test_target)
            
            logger.info(f"✅ Agent test completed: {len(results)} results")
            
            return {
                'status': 'success',
                'agent_name': agent_name,
                'test_target': test_target,
                'results_count': len(results),
                'results': results[:5]  # First 5 results
            }
            
        except Exception as e:
            logger.error(f"Agent test failed: {e}")
            return {
                'status': 'error',
                'agent_name': agent_name,
                'error': str(e)
            }


async def main():
    """Test Code Writer Agent."""
    
    writer = CodeWriterAgent()
    
    # Test 1: Create new agent
    print("\n=== Creating New Agent ===\n")
    
    result = await writer.create_new_agent(
        agent_name="advanced_xss_hunter",
        purpose="Hunt for advanced XSS vulnerabilities including DOM-based and mutation-based XSS",
        target_vulnerability="XSS",
        example_exploits=[
            {'description': 'DOM XSS', 'payload': '<img src=x onerror=alert(1)>'},
            {'description': 'Mutation XSS', 'payload': '<svg><style><img src=x onerror=alert(1)>'}
        ]
    )
    
    if result:
        print(f"✅ Agent created: {result['agent_name']}")
        print(f"   File: {result['file_path']}")
    
    # Test 2: Modify existing agent
    print("\n=== Modifying Agent ===\n")
    
    # Simulate failure logs
    failure_logs = [
        {'error': 'TimeoutError: Request timeout', 'success': False},
        {'error': 'WAFBlocked: Request blocked by WAF', 'success': False},
        {'error': 'ConnectionError: Connection refused', 'success': False},
    ]
    
    result = await writer.improve_agent_from_failures(
        "sqlmap_agent",
        failure_logs
    )
    
    if result:
        print(f"✅ Agent modified: {result['agent_name']}")
        print(f"   Backup: {result['backup_path']}")
    
    # Show history
    print("\n=== Modification History ===\n")
    for i, mod in enumerate(writer.get_modification_history(), 1):
        print(f"{i}. {mod['type'].upper()}: {mod['agent_name']}")
        print(f"   Time: {mod['timestamp']}")
        print()


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    asyncio.run(main())


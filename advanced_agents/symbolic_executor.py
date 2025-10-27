"""
Symbolic Execution Engine using angr
ใช้ในการวิเคราะห์ crash และหา path ไปยังช่องโหว่
"""

import asyncio
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.logger import log
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase

try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    log.warning("[SymbolicExecutor] angr not installed. Symbolic execution disabled.")


class SymbolicExecutor(BaseAgent):
    """
    Symbolic execution engine using angr for vulnerability analysis
    
    Features:
    - Find paths to crashes
    - Generate exploit inputs
    - Analyze control flow
    - Identify exploitable conditions
    """
    
    supported_phases = [AttackPhase.EXPLOITATION, AttackPhase.POST_EXPLOITATION]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, workspace_dir: str = None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        if workspace_dir is None:
            workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        self.workspace_dir = workspace_dir
        os.makedirs(workspace_dir, exist_ok=True)
        
        if not ANGR_AVAILABLE:
            log.error("[SymbolicExecutor] angr is not installed. Install with: pip install angr")
    
    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main entry point for SymbolicExecutor
        
        Args:
            directive: "analyze", "find_paths", "generate_exploit"
            context: Dict containing binary_path, crash_input, and other parameters
        
        Returns:
            AgentData with execution results
        """
        try:
            if not ANGR_AVAILABLE:
                return AgentData(
                    agent_name="SymbolicExecutor",
                    success=False,
                    data={"error": "angr not installed"}
                )
            
            if directive == "analyze":
                result = await self.analyze_crash(
                    context.get("binary_path"),
                    context.get("crash_input", b""),
                    context.get("crash_address")
                )
            elif directive == "find_paths":
                result = await self.find_vulnerable_paths(context)
            else:
                result = await self.find_vulnerable_paths(context)
            
            return AgentData(
                agent_name="SymbolicExecutor",
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[SymbolicExecutor] Error: {e}")
            return AgentData(
                agent_name="SymbolicExecutor",
                success=False,
                data={"error": str(e)}
            )
    

    async def analyze_crash(self, binary_path: str, crash_input: bytes, crash_address: int = None) -> Dict:
        """
        Use angr to find path to crash and generate exploit
        
        Args:
            binary_path: Path to target binary
            crash_input: Input that caused the crash
            crash_address: Address where crash occurred (optional)
        
        Returns:
            Dict with analysis results
        """
        if not ANGR_AVAILABLE:
            return {
                "success": False,
                "error": "angr not installed"
            }
        
        try:
            log.info(f"[SymbolicExecutor] Analyzing crash in {binary_path}")
            
            # Load binary
            project = angr.Project(binary_path, auto_load_libs=False)
            
            # Create symbolic input
            input_size = len(crash_input)
            symbolic_input = claripy.BVS("input", input_size * 8)
            
            # Create initial state
            state = project.factory.entry_state(
                stdin=symbolic_input,
                add_options={angr.options.LAZY_SOLVES}
            )
            
            # Create simulation manager
            simgr = project.factory.simulation_manager(state)
            
            # If crash address is known, explore to it
            if crash_address:
                log.info(f"[SymbolicExecutor] Exploring to crash address: {hex(crash_address)}")
                simgr.explore(find=crash_address, avoid=[])
            else:
                # Otherwise, explore for a limited time
                log.info("[SymbolicExecutor] Exploring for crashes...")
                simgr.run(n=100)  # Limit exploration steps
            
            # Analyze results
            results = {
                "success": False,
                "binary": binary_path,
                "timestamp": datetime.now().isoformat()
            }
            
            # Check if we found the target
            if simgr.found:
                found_state = simgr.found[0]
                
                # Solve for input
                solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
                
                results.update({
                    "success": True,
                    "exploit_input": solution.hex(),
                    "exploit_input_bytes": len(solution),
                    "method": "symbolic_execution",
                    "crash_address": hex(crash_address) if crash_address else "unknown",
                    "constraints": len(found_state.solver.constraints)
                })
                
                log.success(f"[SymbolicExecutor] Found exploit input: {len(solution)} bytes")
            
            # Check for errored states (potential crashes)
            if simgr.errored:
                errors = []
                for errored in simgr.errored[:5]:  # Limit to first 5
                    errors.append({
                        "error": str(errored.error),
                        "address": hex(errored.state.addr)
                    })
                
                results["errors"] = errors
                log.info(f"[SymbolicExecutor] Found {len(simgr.errored)} errored states")
            
            # Save results
            self._save_results(binary_path, results)
            
            return results
            
        except Exception as e:
            log.error(f"[SymbolicExecutor] Analysis failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def find_vulnerable_paths(self, binary_path: str, target_function: str = None) -> Dict:
        """
        Find potentially vulnerable execution paths
        
        Args:
            binary_path: Path to target binary
            target_function: Specific function to analyze (optional)
        
        Returns:
            Dict with vulnerable paths
        """
        if not ANGR_AVAILABLE:
            return {
                "success": False,
                "error": "angr not installed"
            }
        
        try:
            log.info(f"[SymbolicExecutor] Finding vulnerable paths in {binary_path}")
            
            # Load binary
            project = angr.Project(binary_path, auto_load_libs=False)
            
            # Get CFG
            cfg = project.analyses.CFGFast()
            
            vulnerable_paths = []
            
            # Look for dangerous functions
            dangerous_functions = [
                'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
                'memcpy', 'memmove', 'system', 'exec'
            ]
            
            for func_name in dangerous_functions:
                try:
                    func = project.kb.functions.function(name=func_name)
                    if func:
                        vulnerable_paths.append({
                            "function": func_name,
                            "address": hex(func.addr),
                            "type": "dangerous_function",
                            "severity": "high"
                        })
                        log.warning(f"[SymbolicExecutor] Found dangerous function: {func_name}")
                except KeyError:
                    continue
            
            return {
                "success": True,
                "binary": binary_path,
                "vulnerable_paths": vulnerable_paths,
                "total_functions": len(project.kb.functions)
            }
            
        except Exception as e:
            log.error(f"[SymbolicExecutor] Path analysis failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def generate_exploit_constraints(self, binary_path: str, target_address: int) -> Dict:
        """
        Generate constraints needed to reach a specific address
        
        Args:
            binary_path: Path to target binary
            target_address: Target address to reach
        
        Returns:
            Dict with constraints
        """
        if not ANGR_AVAILABLE:
            return {
                "success": False,
                "error": "angr not installed"
            }
        
        try:
            log.info(f"[SymbolicExecutor] Generating constraints to reach {hex(target_address)}")
            
            # Load binary
            project = angr.Project(binary_path, auto_load_libs=False)
            
            # Create symbolic input
            symbolic_input = claripy.BVS("input", 1000 * 8)  # 1000 bytes
            
            # Create initial state
            state = project.factory.entry_state(stdin=symbolic_input)
            
            # Create simulation manager
            simgr = project.factory.simulation_manager(state)
            
            # Explore to target
            simgr.explore(find=target_address)
            
            if simgr.found:
                found_state = simgr.found[0]
                
                # Get constraints
                constraints = [str(c) for c in found_state.solver.constraints]
                
                # Solve for input
                solution = found_state.solver.eval(symbolic_input, cast_to=bytes)
                
                return {
                    "success": True,
                    "target_address": hex(target_address),
                    "constraints": constraints,
                    "constraint_count": len(constraints),
                    "exploit_input": solution.hex(),
                    "input_size": len(solution)
                }
            else:
                return {
                    "success": False,
                    "message": "Could not find path to target address"
                }
            
        except Exception as e:
            log.error(f"[SymbolicExecutor] Constraint generation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute symbolic executor"""
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

    def _save_results(self, binary_path: str, results: Dict) -> str:
        """Save analysis results to file"""
        import json
        
        filename = f"{self.workspace_dir}/symbolic_{os.path.basename(binary_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        log.info(f"[SymbolicExecutor] Results saved to {filename}")
        return filename


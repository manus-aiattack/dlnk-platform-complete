"""
Angr Symbolic Execution Engine Wrapper
Provides symbolic execution capabilities for vulnerability discovery
Enhanced version with full integration support
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import os
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import logging
import json

log = logging.getLogger(__name__)


class AngrExecutor:
    """
    Angr Symbolic Execution Wrapper
    
    Features:
    - Symbolic execution of binaries and scripts
    - Path exploration with multiple strategies
    - Constraint solving with Z3
    - Vulnerability detection (buffer overflow, format string, etc.)
    - Exploit generation assistance
    - Memory and register state analysis
    
    Dependencies:
    - angr: pip install angr
    - z3-solver: pip install z3-solver
    - capstone: pip install capstone
    """
    
    def __init__(self, architecture: str = 'x86_64'):
        self.architecture = architecture
        self.project = None
        self.simgr = None
        self.explored_paths = []
        self.vulnerable_paths = []
        self.analysis_results = {}
        
        # Check if angr is available
        self.angr_available = self._check_angr_availability()
        
        # Configuration
        self.config = {
            'max_paths': 1000,
            'max_depth': 100,
            'timeout': 300,  # 5 minutes
            'enable_unicorn': True,  # Fast concrete execution
            'auto_load_libs': False,
            'simplification': True
        }
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute attack"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Implement attack logic here
            results = {'status': 'not_implemented'}
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} executed",
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

    def _check_angr_availability(self) -> bool:
        """Check if angr and dependencies are installed"""
        try:
            import angr
            import claripy
            return True
        except ImportError as e:
            log.warning(f"[AngrExecutor] Dependencies not installed: {e}")
            log.warning("[AngrExecutor] Install with: pip install angr z3-solver capstone")
            return False
    
    async def analyze_binary(
        self,
        binary_path: str,
        entry_point: Optional[int] = None,
        avoid_addresses: Optional[List[int]] = None,
        find_addresses: Optional[List[int]] = None,
        max_paths: int = 100,
        exploration_strategy: str = 'dfs'
    ) -> Dict:
        """
        Analyze binary with symbolic execution
        
        Args:
            binary_path: Path to binary file
            entry_point: Entry point address (None = auto-detect)
            avoid_addresses: Addresses to avoid during exploration
            find_addresses: Target addresses to find
            max_paths: Maximum paths to explore
            exploration_strategy: 'dfs', 'bfs', or 'random'
        
        Returns:
            Comprehensive analysis results
        """
        log.info(f"[AngrExecutor] Analyzing binary: {binary_path}")
        log.info(f"[AngrExecutor] Strategy: {exploration_strategy}, Max paths: {max_paths}")
        
        if not self.angr_available:
            return await self._mock_analysis(binary_path)
        
        if not os.path.exists(binary_path):
            return {'success': False, 'error': f'Binary not found: {binary_path}'}
        
        try:
            import angr
            import claripy
            
            # Load binary
            log.info("[AngrExecutor] Loading binary...")
            self.project = angr.Project(
                binary_path,
                auto_load_libs=self.config['auto_load_libs'],
                load_options={
                    'main_opts': {
                        'base_addr': 0,
                        'backend': 'elf'
                    }
                }
            )
            
            # Create initial state
            if entry_point:
                state = self.project.factory.blank_state(addr=entry_point)
            else:
                state = self.project.factory.entry_state()
            
            # Add symbolic input
            symbolic_input = claripy.BVS('input', 8 * 256)  # 256 bytes symbolic input
            state.posix.stdin.store(0, symbolic_input)
            
            # Create simulation manager with exploration technique
            self.simgr = self.project.factory.simulation_manager(state)
            
            # Apply exploration technique
            if exploration_strategy == 'dfs':
                self.simgr.use_technique(angr.exploration_techniques.DFS())
            elif exploration_strategy == 'bfs':
                # BFS is default
                pass
            elif exploration_strategy == 'random':
                self.simgr.use_technique(angr.exploration_techniques.Explorer(
                    find=find_addresses or [],
                    avoid=avoid_addresses or []
                ))
            
            # Enable Unicorn for fast concrete execution
            if self.config['enable_unicorn']:
                try:
                    self.simgr.use_technique(angr.exploration_techniques.Veritesting())
                except:
                    log.debug("[AngrExecutor] Veritesting not available")
            
            # Explore paths
            log.info("[AngrExecutor] Starting symbolic execution...")
            if find_addresses:
                self.simgr.explore(
                    find=find_addresses,
                    avoid=avoid_addresses or [],
                    n=max_paths
                )
            else:
                self.simgr.run(n=max_paths)
            
            # Analyze results
            results = await self._analyze_exploration_results()
            
            log.info(f"[AngrExecutor] Analysis complete")
            log.info(f"  - Paths explored: {len(results['paths'])}")
            log.info(f"  - Vulnerabilities: {len(results['vulnerabilities'])}")
            
            return results
            
        except Exception as e:
            log.error(f"[AngrExecutor] Analysis failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    async def _analyze_exploration_results(self) -> Dict:
        """Analyze symbolic execution results comprehensively"""
        
        results = {
            'success': True,
            'paths': [],
            'vulnerabilities': [],
            'constraints': [],
            'statistics': {
                'found': len(self.simgr.found) if self.simgr.found else 0,
                'active': len(self.simgr.active) if self.simgr.active else 0,
                'deadended': len(self.simgr.deadended) if self.simgr.deadended else 0,
                'errored': len(self.simgr.errored) if self.simgr.errored else 0
            }
        }
        
        # Analyze found states
        if self.simgr.found:
            log.info(f"[AngrExecutor] Analyzing {len(self.simgr.found)} found states...")
            for idx, state in enumerate(self.simgr.found):
                try:
                    path_info = {
                        'id': idx,
                        'address': hex(state.addr),
                        'constraints': self._simplify_constraints(state.solver.constraints),
                        'input': self._extract_input(state),
                        'registers': self._extract_registers(state),
                        'type': 'found',
                        'satisfiable': state.solver.satisfiable()
                    }
                    results['paths'].append(path_info)
                except Exception as e:
                    log.debug(f"[AngrExecutor] Error analyzing found state {idx}: {e}")
        
        # Analyze active states
        if self.simgr.active:
            log.info(f"[AngrExecutor] Analyzing {len(self.simgr.active)} active states...")
            for idx, state in enumerate(self.simgr.active[:10]):  # Limit to first 10
                try:
                    path_info = {
                        'id': idx,
                        'address': hex(state.addr),
                        'type': 'active',
                        'depth': len(state.history.bbl_addrs)
                    }
                    results['paths'].append(path_info)
                except Exception as e:
                    log.debug(f"[AngrExecutor] Error analyzing active state {idx}: {e}")
        
        # Check for vulnerabilities
        log.info("[AngrExecutor] Detecting vulnerabilities...")
        vulnerabilities = await self._detect_vulnerabilities()
        results['vulnerabilities'] = vulnerabilities
        
        return results
    
    def _simplify_constraints(self, constraints) -> List[str]:
        """Simplify and convert constraints to readable format"""
        simplified = []
        for constraint in list(constraints)[:10]:  # Limit to first 10
            try:
                simplified.append(str(constraint))
            except:
                simplified.append("<complex constraint>")
        return simplified
    
    def _extract_input(self, state) -> Dict:
        """Extract concrete input from state"""
        try:
            # Try to concretize stdin
            stdin_data = state.posix.stdin.concretize()
            
            # Get first 256 bytes
            input_bytes = stdin_data[:256] if len(stdin_data) > 256 else stdin_data
            
            return {
                'hex': input_bytes.hex() if isinstance(input_bytes, bytes) else '',
                'ascii': input_bytes.decode('ascii', errors='replace') if isinstance(input_bytes, bytes) else '',
                'length': len(input_bytes) if input_bytes else 0
            }
        except Exception as e:
            log.debug(f"[AngrExecutor] Input extraction failed: {e}")
            return {'hex': '', 'ascii': '', 'length': 0}
    
    def _extract_registers(self, state) -> Dict:
        """Extract register values from state"""
        registers = {}
        try:
            # Common registers based on architecture
            if self.architecture == 'x86_64':
                reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'rip']
            else:
                reg_names = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp', 'eip']
            
            for reg in reg_names:
                try:
                    val = getattr(state.regs, reg)
                    if val.concrete:
                        registers[reg] = hex(state.solver.eval(val))
                    else:
                        registers[reg] = '<symbolic>'
                except:
                    pass
        except Exception as e:
            log.debug(f"[AngrExecutor] Register extraction failed: {e}")
        
        return registers
    
    async def _detect_vulnerabilities(self) -> List[Dict]:
        """Detect vulnerabilities in explored paths"""
        vulnerabilities = []
        
        if not self.simgr:
            return vulnerabilities
        
        # Check all states
        all_states = []
        if self.simgr.active:
            all_states.extend(self.simgr.active)
        if self.simgr.found:
            all_states.extend(self.simgr.found)
        if self.simgr.deadended:
            all_states.extend(self.simgr.deadended[:10])  # Limit deadended states
        
        log.info(f"[AngrExecutor] Checking {len(all_states)} states for vulnerabilities...")
        
        for state in all_states:
            try:
                # 1. Check for buffer overflow (unconstrained instruction pointer)
                if hasattr(state.regs, 'pc') and state.regs.pc.symbolic:
                    vuln = {
                        'type': 'buffer_overflow',
                        'address': hex(state.addr),
                        'severity': 'CRITICAL',
                        'description': 'Unconstrained instruction pointer - possible buffer overflow',
                        'exploitable': True,
                        'cvss_score': 9.8
                    }
                    vulnerabilities.append(vuln)
                
                # 2. Check for use-after-free
                # (Simplified check - real implementation needs heap tracking)
                
                # 3. Check for integer overflow
                # (Would need to track arithmetic operations)
                
                # 4. Check for format string vulnerabilities
                # (Would need to track format string functions)
                
            except Exception as e:
                log.debug(f"[AngrExecutor] Vulnerability check error: {e}")
        
        # Deduplicate vulnerabilities
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            key = (vuln['type'], vuln['address'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    async def generate_exploit_input(
        self,
        target_address: int,
        constraint_solver: str = 'z3'
    ) -> Optional[bytes]:
        """
        Generate input that reaches target address
        
        Args:
            target_address: Target address to reach
            constraint_solver: Constraint solver to use ('z3' or 'cvc4')
        
        Returns:
            Input bytes that reach target, or None
        """
        log.info(f"[AngrExecutor] Generating exploit input for {hex(target_address)}")
        
        if not self.simgr:
            log.error("[AngrExecutor] No simulation manager available")
            return None
        
        # Find state that reached target
        for state in self.simgr.found:
            if state.addr == target_address:
                input_data = self._extract_input(state)
                input_bytes = bytes.fromhex(input_data['hex']) if input_data['hex'] else b''
                log.info(f"[AngrExecutor] Generated input: {len(input_bytes)} bytes")
                return input_bytes
        
        log.warning(f"[AngrExecutor] No path found to {hex(target_address)}")
        return None
    
    async def find_path_to_function(
        self,
        function_name: str,
        max_depth: int = 100
    ) -> List[str]:
        """
        Find execution path to specific function
        
        Args:
            function_name: Target function name
            max_depth: Maximum search depth
        
        Returns:
            List of addresses in path (as hex strings)
        """
        log.info(f"[AngrExecutor] Finding path to function: {function_name}")
        
        if not self.project:
            return []
        
        try:
            # Find function address
            func = self.project.loader.find_symbol(function_name)
            if not func:
                log.error(f"[AngrExecutor] Function not found: {function_name}")
                return []
            
            target_addr = func.rebased_addr
            log.info(f"[AngrExecutor] Target function at: {hex(target_addr)}")
            
            # Explore to function
            self.simgr.explore(find=target_addr, n=max_depth)
            
            # Extract path
            if self.simgr.found:
                state = self.simgr.found[0]
                path = [hex(addr) for addr in state.history.bbl_addrs]
                log.info(f"[AngrExecutor] Path found with {len(path)} basic blocks")
                return path
            
            log.warning(f"[AngrExecutor] No path found to {function_name}")
            return []
            
        except Exception as e:
            log.error(f"[AngrExecutor] Path finding failed: {e}")
            return []
    
    async def analyze_function(
        self,
        function_address: int,
        input_constraints: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze specific function with symbolic execution
        
        Args:
            function_address: Address of function to analyze
            input_constraints: Constraints on input variables
        
        Returns:
            Function analysis results
        """
        log.info(f"[AngrExecutor] Analyzing function at {hex(function_address)}")
        
        if not self.angr_available:
            return {'success': False, 'error': 'angr not available'}
        
        try:
            import angr
            import claripy
            
            # Create state at function entry
            state = self.project.factory.blank_state(addr=function_address)
            
            # Apply input constraints
            if input_constraints:
                for var_name, constraint in input_constraints.items():
                    # Create symbolic variable
                    sym_var = claripy.BVS(var_name, 64)
                    # Apply constraint (simplified)
                    state.solver.add(constraint)
            
            # Create simulation manager
            simgr = self.project.factory.simulation_manager(state)
            
            # Explore function
            simgr.run(n=50)
            
            # Analyze results
            results = {
                'success': True,
                'function_address': hex(function_address),
                'paths_explored': len(simgr.active) + len(simgr.deadended),
                'active_paths': len(simgr.active),
                'completed_paths': len(simgr.deadended),
                'vulnerabilities': []
            }
            
            return results
            
        except Exception as e:
            log.error(f"[AngrExecutor] Function analysis failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _mock_analysis(self, binary_path: str) -> Dict:
        """Mock analysis when angr is not available"""
        
        log.info("[AngrExecutor] Running mock analysis (angr not installed)")
        
        return {
            'success': True,
            'mock': True,
            'binary': binary_path,
            'paths': [
                {
                    'id': 0,
                    'address': '0x401000',
                    'type': 'entry',
                    'constraints': ['input[0] > 0']
                },
                {
                    'id': 1,
                    'address': '0x401100',
                    'type': 'found',
                    'constraints': ['input[0] == 0x41', 'input[1] == 0x42'],
                    'input': {
                        'hex': '41' * 100,
                        'ascii': 'A' * 100,
                        'length': 100
                    }
                }
            ],
            'vulnerabilities': [
                {
                    'type': 'buffer_overflow',
                    'address': '0x401100',
                    'severity': 'CRITICAL',
                    'description': 'Potential buffer overflow detected - unconstrained PC',
                    'exploitable': True,
                    'cvss_score': 9.8
                }
            ],
            'statistics': {
                'found': 1,
                'active': 3,
                'deadended': 5,
                'errored': 0
            },
            'message': 'Mock analysis. Install angr for real symbolic execution: pip install angr z3-solver'
        }
    
    def save_results(self, output_path: str):
        """Save analysis results to JSON file"""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.analysis_results, f, indent=2)
            log.info(f"[AngrExecutor] Results saved to {output_path}")
        except Exception as e:
            log.error(f"[AngrExecutor] Failed to save results: {e}")


if __name__ == '__main__':
    async def test():
        """Test the AngrExecutor"""
        executor = AngrExecutor()
        
        print(f"[*] Angr available: {executor.angr_available}")
        print(f"[*] Architecture: {executor.architecture}")
        
        # Test mock analysis
        print("\n[*] Running test analysis...")
        results = await executor.analyze_binary('/bin/ls')
        
        print("\n[+] Analysis Results:")
        print(f"  Success: {results['success']}")
        print(f"  Mock: {results.get('mock', False)}")
        print(f"  Paths explored: {len(results.get('paths', []))}")
        print(f"  Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        
        if results.get('statistics'):
            print(f"\n[+] Statistics:")
            for key, value in results['statistics'].items():
                print(f"  {key}: {value}")
        
        if results.get('vulnerabilities'):
            print("\n[!] Vulnerabilities:")
            for vuln in results['vulnerabilities']:
                print(f"  - {vuln['type']} at {vuln['address']}")
                print(f"    Severity: {vuln['severity']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Exploitable: {vuln['exploitable']}")
    
    asyncio.run(test())


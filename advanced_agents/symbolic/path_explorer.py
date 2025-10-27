"""
Path Explorer for Symbolic Execution
Implements various path exploration strategies
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
from typing import List, Dict, Set, Optional, Callable
from enum import Enum
from collections import deque
import logging

log = logging.getLogger(__name__)


class ExplorationStrategy(Enum):
    """Path exploration strategies"""
    DFS = "depth_first"
    BFS = "breadth_first"
    RANDOM = "random"
    COVERAGE_GUIDED = "coverage_guided"
    HEURISTIC = "heuristic"


class PathState:
    """Represents a program state during symbolic execution"""
    
    def __init__(self, state_id: int, address: int, constraints: List = None):
        self.state_id = state_id
        self.address = address
        self.constraints = constraints or []
        self.depth = 0
        self.coverage = set()
        self.priority = 0.0
    
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

    def __repr__(self):
        return f"PathState(id={self.state_id}, addr=0x{self.address:x}, depth={self.depth})"


class PathExplorer:
    """
    Path Explorer for Symbolic Execution
    
    Implements multiple exploration strategies to efficiently
    explore program paths during symbolic execution.
    """
    
    def __init__(self, strategy: ExplorationStrategy = ExplorationStrategy.DFS):
        self.strategy = strategy
        self.states = deque()
        self.visited_states = set()
        self.coverage = set()
        self.max_depth = 100
        self.max_states = 10000
        self.state_counter = 0
    
    async def add_state(self, state: PathState):
        """Add a new state to explore"""
        
        if len(self.states) >= self.max_states:
            log.warning(f"[PathExplorer] Max states reached ({self.max_states})")
            return
        
        # Check if state already visited
        state_signature = (state.address, tuple(sorted(state.constraints)))
        if state_signature in self.visited_states:
            return
        
        self.visited_states.add(state_signature)
        
        # Add based on strategy
        if self.strategy == ExplorationStrategy.DFS:
            self.states.append(state)
        
        elif self.strategy == ExplorationStrategy.BFS:
            self.states.appendleft(state)
        
        elif self.strategy == ExplorationStrategy.COVERAGE_GUIDED:
            # Prioritize states that increase coverage
            state.priority = len(state.coverage - self.coverage)
            self._insert_by_priority(state)
        
        elif self.strategy == ExplorationStrategy.HEURISTIC:
            # Use heuristic to prioritize
            state.priority = await self._calculate_heuristic(state)
            self._insert_by_priority(state)
        
        else:  # RANDOM
            import random
            pos = random.randint(0, len(self.states))
            self.states.insert(pos, state)
    
    def _insert_by_priority(self, state: PathState):
        """Insert state by priority (higher priority first)"""
        
        for i, s in enumerate(self.states):
            if state.priority > s.priority:
                self.states.insert(i, state)
                return
        
        self.states.append(state)
    
    async def _calculate_heuristic(self, state: PathState) -> float:
        """Calculate heuristic score for state"""
        
        score = 0.0
        
        # Favor states with less depth
        score += 1.0 / (state.depth + 1)
        
        # Favor states with more coverage
        score += len(state.coverage) * 0.1
        
        # Favor states with fewer constraints
        score += 1.0 / (len(state.constraints) + 1)
        
        return score
    
    async def get_next_state(self) -> Optional[PathState]:
        """Get next state to explore"""
        
        if not self.states:
            return None
        
        state = self.states.pop()
        
        # Update global coverage
        self.coverage.update(state.coverage)
        
        return state
    
    async def explore_paths(
        self,
        initial_state: PathState,
        step_function: Callable,
        max_paths: int = 100
    ) -> List[PathState]:
        """
        Explore paths using the configured strategy
        
        Args:
            initial_state: Initial program state
            step_function: Function to execute one step (returns list of successor states)
            max_paths: Maximum number of paths to explore
        
        Returns:
            List of explored states
        """
        log.info(f"[PathExplorer] Starting path exploration (strategy={self.strategy.value})")
        
        await self.add_state(initial_state)
        
        explored_paths = []
        paths_found = 0
        
        while self.states and paths_found < max_paths:
            state = await self.get_next_state()
            
            if state is None:
                break
            
            # Check depth limit
            if state.depth >= self.max_depth:
                log.debug(f"[PathExplorer] Max depth reached for state {state.state_id}")
                continue
            
            # Execute one step
            try:
                successor_states = await step_function(state)
                
                # Add successor states
                for succ in successor_states:
                    succ.depth = state.depth + 1
                    await self.add_state(succ)
                
                explored_paths.append(state)
                paths_found += 1
                
            except Exception as e:
                log.error(f"[PathExplorer] Error exploring state {state.state_id}: {e}")
        
        log.info(f"[PathExplorer] Explored {paths_found} paths, coverage: {len(self.coverage)} blocks")
        
        return explored_paths
    
    async def find_path_to_address(
        self,
        initial_state: PathState,
        target_address: int,
        step_function: Callable,
        max_iterations: int = 1000
    ) -> Optional[PathState]:
        """
        Find a path to a specific address
        
        Args:
            initial_state: Initial program state
            target_address: Target address to reach
            step_function: Function to execute one step
            max_iterations: Maximum iterations
        
        Returns:
            State that reached the target, or None
        """
        log.info(f"[PathExplorer] Finding path to 0x{target_address:x}")
        
        await self.add_state(initial_state)
        
        iterations = 0
        
        while self.states and iterations < max_iterations:
            state = await self.get_next_state()
            
            if state is None:
                break
            
            # Check if target reached
            if state.address == target_address:
                log.info(f"[PathExplorer] Target reached in {iterations} iterations!")
                return state
            
            # Check depth limit
            if state.depth >= self.max_depth:
                continue
            
            # Execute one step
            try:
                successor_states = await step_function(state)
                
                for succ in successor_states:
                    succ.depth = state.depth + 1
                    await self.add_state(succ)
                
            except Exception as e:
                log.error(f"[PathExplorer] Error: {e}")
            
            iterations += 1
        
        log.warning(f"[PathExplorer] Target not reached after {iterations} iterations")
        return None
    
    async def prune_states(self, condition: Callable[[PathState], bool]):
        """Remove states that don't satisfy condition"""
        
        original_count = len(self.states)
        
        self.states = deque([s for s in self.states if condition(s)])
        
        pruned_count = original_count - len(self.states)
        
        if pruned_count > 0:
            log.info(f"[PathExplorer] Pruned {pruned_count} states")
    
    def get_statistics(self) -> Dict:
        """Get exploration statistics"""
        
        return {
            'strategy': self.strategy.value,
            'states_queued': len(self.states),
            'states_visited': len(self.visited_states),
            'coverage_blocks': len(self.coverage),
            'max_depth': self.max_depth,
            'max_states': self.max_states
        }


if __name__ == '__main__':
    async def test():
        # Create explorer
        explorer = PathExplorer(strategy=ExplorationStrategy.DFS)
        
        # Create initial state
        initial = PathState(0, 0x1000, [])
        
        # Mock step function
        async def mock_step(state: PathState) -> List[PathState]:
            # Simulate branching
            if state.depth < 3:
                succ1 = PathState(explorer.state_counter, state.address + 0x10, state.constraints + ['cond1'])
                explorer.state_counter += 1
                
                succ2 = PathState(explorer.state_counter, state.address + 0x20, state.constraints + ['cond2'])
                explorer.state_counter += 1
                
                return [succ1, succ2]
            return []
        
        # Explore paths
        paths = await explorer.explore_paths(initial, mock_step, max_paths=10)
        
        print(f"Explored {len(paths)} paths")
        print(f"Statistics: {explorer.get_statistics()}")
    
    asyncio.run(test())


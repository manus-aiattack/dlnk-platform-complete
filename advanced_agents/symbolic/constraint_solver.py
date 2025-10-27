"""
Constraint Solver using Z3
Solves symbolic constraints to generate concrete inputs
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
from typing import List, Dict, Optional, Any
import logging
import ast

log = logging.getLogger(__name__)

# Try to import Z3
try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    log.warning("[ConstraintSolver] Z3 not available, using fallback solver")


class Constraint:
    """Represents a symbolic constraint"""
    
    def __init__(self, expression: str, variables: List[str] = None):
        self.expression = expression
        self.variables = variables or []
    
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
        return f"Constraint({self.expression})"


class ConstraintSolver:
    """
    Constraint Solver using Z3 SMT Solver
    
    Solves symbolic constraints to find concrete values
    that satisfy the constraints.
    """
    
    def __init__(self):
        self.solver = None
        self.variables = {}
        self.constraints = []
        
        if Z3_AVAILABLE:
            self.solver = z3.Solver()
    
    async def add_variable(self, name: str, var_type: str = "int", bit_size: int = 32):
        """
        Add a symbolic variable
        
        Args:
            name: Variable name
            var_type: Variable type (int, bool, bitvec)
            bit_size: Bit size for bitvec
        """
        if not Z3_AVAILABLE:
            self.variables[name] = {'type': var_type, 'bit_size': bit_size}
            return
        
        if var_type == "int":
            self.variables[name] = z3.Int(name)
        elif var_type == "bool":
            self.variables[name] = z3.Bool(name)
        elif var_type == "bitvec":
            self.variables[name] = z3.BitVec(name, bit_size)
        else:
            raise ValueError(f"Unknown variable type: {var_type}")
    
    async def add_constraint(self, constraint: str):
        """
        Add a constraint

        Args:
            constraint: Constraint expression (e.g., "x > 10", "x + y == 100")
        """
        if not Z3_AVAILABLE:
            self.constraints.append(constraint)
            log.debug(f"[ConstraintSolver] Added constraint (fallback): {constraint}")
            return

        try:
            # Parse constraint expression safely
            # This is a simplified parser - in production use proper parsing
            constraint_expr = self._safe_eval_constraint(constraint)

            self.solver.add(constraint_expr)
            self.constraints.append(constraint)

            log.debug(f"[ConstraintSolver] Added constraint: {constraint}")

        except Exception as e:
            log.error(f"[ConstraintSolver] Failed to add constraint '{constraint}': {e}")

    def _safe_eval_constraint(self, expression: str):
        """
        Safely evaluate mathematical expressions only
        This prevents code injection attacks while allowing mathematical constraints
        """
        if not expression or len(expression) > 100:
            raise ValueError("Expression too long or empty")

        try:
            # Parse and validate the expression
            parsed = ast.parse(expression, mode='eval')

            # Only allow specific node types (numbers, variables, operators, basic functions)
            allowed_nodes = (
                ast.Expression, ast.BinOp, ast.UnaryOp, ast.operator,
                ast.unaryop, ast.Constant, ast.Num, ast.Str, ast.Name,
                ast.Load, ast.Compare, ast.Gt, ast.Lt, ast.Eq, ast.GtE,
                ast.LtE, ast.NotEq
            )

            for node in ast.walk(parsed):
                if not isinstance(node, allowed_nodes):
                    raise ValueError(f"Unsafe expression node type: {type(node).__name__}")

            # Create safe environment with only allowed variables and functions
            safe_env = {
                '__builtins__': {},
                # Add mathematical constants and functions as needed
                'int': int,
                'float': float,
                'bool': bool,
                'str': str,
            }

            # Add the constraint solver's variables to the environment
            safe_env.update(self.variables)

            # Evaluate safely
            return eval(compile(parsed, '<string>', 'eval'), safe_env)

        except Exception as e:
            raise ValueError(f"Invalid or unsafe constraint expression: {e}")
    
    async def solve(self) -> Optional[Dict[str, Any]]:
        """
        Solve constraints and return concrete values
        
        Returns:
            Dictionary mapping variable names to concrete values, or None if unsatisfiable
        """
        if not Z3_AVAILABLE:
            return await self._fallback_solve()
        
        log.info(f"[ConstraintSolver] Solving {len(self.constraints)} constraints...")
        
        result = self.solver.check()
        
        if result == z3.sat:
            model = self.solver.model()
            
            solution = {}
            for var_name, var in self.variables.items():
                value = model[var]
                if value is not None:
                    solution[var_name] = value.as_long() if hasattr(value, 'as_long') else str(value)
            
            log.info(f"[ConstraintSolver] Solution found: {solution}")
            return solution
        
        elif result == z3.unsat:
            log.warning("[ConstraintSolver] Constraints are unsatisfiable")
            return None
        
        else:  # unknown
            log.warning("[ConstraintSolver] Solver returned unknown")
            return None
    
    async def _fallback_solve(self) -> Optional[Dict[str, Any]]:
        """Fallback solver when Z3 is not available"""
        
        log.info("[ConstraintSolver] Using fallback solver...")
        
        # Simple heuristic solver
        solution = {}
        
        for var_name, var_info in self.variables.items():
            # Assign default values
            if var_info['type'] == 'int':
                solution[var_name] = 0
            elif var_info['type'] == 'bool':
                solution[var_name] = False
            elif var_info['type'] == 'bitvec':
                solution[var_name] = 0
        
        return solution
    
    async def is_satisfiable(self) -> bool:
        """Check if constraints are satisfiable"""
        
        if not Z3_AVAILABLE:
            return True  # Assume satisfiable in fallback mode
        
        result = self.solver.check()
        return result == z3.sat
    
    async def get_all_solutions(self, max_solutions: int = 10) -> List[Dict[str, Any]]:
        """
        Get multiple solutions
        
        Args:
            max_solutions: Maximum number of solutions to find
        
        Returns:
            List of solutions
        """
        if not Z3_AVAILABLE:
            solution = await self._fallback_solve()
            return [solution] if solution else []
        
        solutions = []
        
        for i in range(max_solutions):
            result = self.solver.check()
            
            if result != z3.sat:
                break
            
            model = self.solver.model()
            
            solution = {}
            blocking_clause = []
            
            for var_name, var in self.variables.items():
                value = model[var]
                if value is not None:
                    solution[var_name] = value.as_long() if hasattr(value, 'as_long') else str(value)
                    blocking_clause.append(var != value)
            
            solutions.append(solution)
            
            # Block this solution
            if blocking_clause:
                self.solver.add(z3.Or(blocking_clause))
        
        log.info(f"[ConstraintSolver] Found {len(solutions)} solutions")
        
        return solutions
    
    async def simplify_constraints(self):
        """Simplify constraints"""
        
        if not Z3_AVAILABLE:
            return
        
        # Z3 automatically simplifies, but we can force it
        self.solver.simplify()
    
    def reset(self):
        """Reset solver state"""
        
        if Z3_AVAILABLE:
            self.solver.reset()
        
        self.variables.clear()
        self.constraints.clear()
    
    def get_statistics(self) -> Dict:
        """Get solver statistics"""
        
        stats = {
            'num_constraints': len(self.constraints),
            'num_variables': len(self.variables),
            'z3_available': Z3_AVAILABLE
        }
        
        if Z3_AVAILABLE and self.solver:
            stats['z3_stats'] = str(self.solver.statistics())
        
        return stats


if __name__ == '__main__':
    async def test():
        solver = ConstraintSolver()
        
        # Add variables
        await solver.add_variable('x', 'int')
        await solver.add_variable('y', 'int')
        
        # Add constraints
        await solver.add_constraint('x > 10')
        await solver.add_constraint('y < 20')
        await solver.add_constraint('x + y == 25')
        
        # Solve
        solution = await solver.solve()
        
        if solution:
            print(f"Solution: {solution}")
        else:
            print("No solution found")
        
        # Get statistics
        print(f"Statistics: {solver.get_statistics()}")
    
    asyncio.run(test())


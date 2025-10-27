#!/usr/bin/env python3
"""
Agent Migration Script
Automatically migrate agents to standard structure with:
- BaseAgent inheritance
- async def execute() method
- AgentData return type
"""

import re
from pathlib import Path
import logging
import asyncio

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class AgentMigrator:
    """Migrate agents to standard structure"""
    
    def __init__(self):
        self.base_path = Path("/home/ubuntu/aiprojectattack")
        self.agents_migrated = 0
        self.agents_skipped = 0
        self.agents_failed = 0
    
    async def migrate_all_agents(self):
        """Migrate all agents"""
        log.info("Starting agent migration...")
        
        # Get all agent files
        agent_files = []
        agent_files.extend(list((self.base_path / "agents").glob("*.py")))
        agent_files.extend(list((self.base_path / "advanced_agents").rglob("*.py")))
        
        # Filter out __init__.py and already migrated
        agent_files = [
            f for f in agent_files 
            if not f.name.startswith("__") 
            and f.name not in ["base_agent.py", "data_models.py"]
        ]
        
        log.info(f"Found {len(agent_files)} agents to check")
        
        for agent_file in agent_files:
            try:
                if await self.migrate_agent(agent_file):
                    self.agents_migrated += 1
                else:
                    self.agents_skipped += 1
            except Exception as e:
                log.error(f"Failed to migrate {agent_file.name}: {e}")
                self.agents_failed += 1
        
        log.info(f"""
✅ Agent Migration Complete:
   - Migrated: {self.agents_migrated}
   - Skipped: {self.agents_skipped}
   - Failed: {self.agents_failed}
   - Total: {len(agent_files)}
""")
    
    async def migrate_agent(self, agent_file: Path) -> bool:
        """Migrate single agent"""
        try:
            content = agent_file.read_text()
            
            # Check if already compliant
            if self._is_compliant(content):
                log.debug(f"✓ {agent_file.name} - Already compliant")
                return False
            
            log.info(f"Migrating {agent_file.name}...")
            
            original_content = content
            
            # Step 1: Add imports
            content = self._add_imports(content)
            
            # Step 2: Make class inherit from BaseAgent
            content = self._add_base_agent_inheritance(content)
            
            # Step 3: Add execute method
            content = self._add_execute_method(content, agent_file.name)
            
            # Only write if changes were made
            if content != original_content:
                agent_file.write_text(content)
                log.info(f"  ✅ {agent_file.name} migrated")
                return True
            
            return False
            
        except Exception as e:
            log.error(f"  ❌ {agent_file.name}: {e}")
            raise
    
    def _is_compliant(self, content: str) -> bool:
        """Check if agent is already compliant"""
        has_base_agent = "BaseAgent" in content
        has_execute = "async def execute" in content
        has_agent_data = "AgentData" in content
        
        return has_base_agent and has_execute and has_agent_data
    
    def _add_imports(self, content: str) -> str:
        """Add missing imports"""
        imports_to_add = []
        
        if "from core.base_agent import BaseAgent" not in content:
            imports_to_add.append("from core.base_agent import BaseAgent")
        
        if "from core.data_models import AgentData" not in content:
            imports_to_add.append("from core.data_models import AgentData, Strategy")
        
        if not imports_to_add:
            return content
        
        # Find first import line
        lines = content.split('\n')
        first_import_idx = 0
        
        for i, line in enumerate(lines):
            if line.startswith('import') or line.startswith('from'):
                first_import_idx = i
                break
        
        # Insert new imports after first import
        for imp in reversed(imports_to_add):
            lines.insert(first_import_idx + 1, imp)
        
        return '\n'.join(lines)
    
    def _add_base_agent_inheritance(self, content: str) -> str:
        """Make class inherit from BaseAgent"""
        # Find class definition
        class_match = re.search(r'class\s+(\w+Agent)\s*(?:\([^)]*\))?:', content)
        
        if not class_match:
            return content
        
        class_name = class_match.group(1)
        
        # Check if already inherits from BaseAgent
        if "BaseAgent" in class_match.group(0):
            return content
        
        # Replace class definition
        old_class_def = class_match.group(0)
        new_class_def = f"class {class_name}(BaseAgent):"
        
        content = content.replace(old_class_def, new_class_def, 1)
        
        return content
    
    def _add_execute_method(self, content: str, filename: str) -> str:
        """Add execute method if missing"""
        if "async def execute" in content:
            return content
        
        # Find existing attack/run/scan method
        method_patterns = [
            r'async def (attack|run|scan|exploit|execute_attack)\(self[^)]*\)',
            r'def (attack|run|scan|exploit|execute_attack)\(self[^)]*\)'
        ]
        
        existing_method = None
        for pattern in method_patterns:
            match = re.search(pattern, content)
            if match:
                existing_method = match.group(1)
                break
        
        # Generate execute method
        if existing_method:
            execute_template = f'''
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute {filename.replace('_', ' ').replace('.py', '')}"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.{existing_method}):
                results = await self.{existing_method}(target)
            else:
                results = self.{existing_method}(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{{self.__class__.__name__}} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={{'results': results}}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{{self.__class__.__name__}} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={{}}
            )
'''
        else:
            # Generic execute method
            execute_template = '''
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
'''
        
        # Find where to insert (after __init__ or after class definition)
        init_match = re.search(r'def __init__\(self[^)]*\):.*?(?=\n    def |\n\nclass |\Z)', content, re.DOTALL)
        
        if init_match:
            # Insert after __init__
            insert_pos = init_match.end()
            content = content[:insert_pos] + execute_template + content[insert_pos:]
        else:
            # Insert after class definition
            class_match = re.search(r'class\s+\w+.*?:\s*\n', content)
            if class_match:
                insert_pos = class_match.end()
                content = content[:insert_pos] + execute_template + content[insert_pos:]
        
        return content


async def main():
    migrator = AgentMigrator()
    await migrator.migrate_all_agents()


if __name__ == "__main__":
    asyncio.run(main())


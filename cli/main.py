#!/usr/bin/env python3
"""
dLNk dLNk CLI - Command Line Interface for Offensive Security Framework
"""

import asyncio
import click
import json
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import Orchestrator
from core.logger import log
from core.data_models import Strategy
from config.settings import DEFAULT_WORKFLOW, WORKSPACE_DIR

# Import new CLI modules
from cli import ui, attack_cli, license_cli, loot_cli


class dLNkdLNkCLI:
    """CLI interface for dLNk dLNk Framework"""

    def __init__(self):
        self.orchestrator = None
        self.initialized = False

    async def initialize(self):
        """Initialize the orchestrator"""
        if self.initialized:
            return
        
        # Display hardcore logo
        ui.print_logo()
        log.info("Initializing dLNk dLNk Framework...")
        
        self.orchestrator = Orchestrator(workspace_dir=WORKSPACE_DIR)
        await self.orchestrator.initialize()
        self.initialized = True
        log.success("Framework initialized successfully")

    async def cleanup(self):
        """Cleanup resources"""
        if self.orchestrator:
            await self.orchestrator.cleanup()

    async def run_workflow(self, workflow_path: str, target: dict):
        """Run a complete workflow"""
        await self.initialize()
        
        try:
            log.info(f"Starting workflow: {workflow_path}")
            log.info(f"Target: {target.get('name', 'Unknown')}")
            
            results = await self.orchestrator.execute_workflow(workflow_path, target)
            
            # Display results
            log.success(f"Workflow completed with {len(results)} agent results")
            
            # Summary
            successful = sum(1 for r in results if r and r.success)
            failed = sum(1 for r in results if r and not r.success)
            
            log.info(f"Results: {successful} successful, {failed} failed")
            
            return results
            
        except Exception as e:
            log.error(f"Workflow execution failed: {e}", exc_info=True)
            raise
        finally:
            await self.cleanup()

    async def execute_agent(self, agent_name: str, directive: str, context: dict):
        """Execute a single agent"""
        await self.initialize()
        
        try:
            log.info(f"Executing agent: {agent_name}")
            
            strategy = Strategy(
                phase="manual",
                directive=directive,
                context=context,
                next_agent=None
            )
            
            result = await self.orchestrator.execute_agent_directly(agent_name, strategy)
            
            if result.success:
                log.success(f"Agent {agent_name} executed successfully")
            else:
                log.warning(f"Agent {agent_name} failed: {result.errors}")
            
            return result
            
        except Exception as e:
            log.error(f"Agent execution failed: {e}", exc_info=True)
            raise
        finally:
            await self.cleanup()

    async def list_agents(self):
        """List all available agents"""
        await self.initialize()
        
        agents = self.orchestrator.get_registered_agents()
        
        log.info(f"Available agents ({len(agents)}):")
        for agent_name in sorted(agents):
            info = self.orchestrator.get_agent_info(agent_name)
            if info:
                log.info(f"  - {agent_name}")
        
        return agents

    async def get_status(self):
        """Get orchestrator status"""
        await self.initialize()
        return self.orchestrator.get_status()


# Create CLI instance
cli_instance = dLNkdLNkCLI()


@click.group()
def cli():
    """dLNk dLNk - Offensive Security Framework"""
    pass


@cli.command()
@click.option('--workflow', '-w', default=DEFAULT_WORKFLOW, help='Path to workflow YAML file')
@click.option('--target', '-t', required=True, help='Target URL or IP address')
@click.option('--name', '-n', default='Target', help='Target name')
@click.option('--output', '-o', default=None, help='Output file for results')
def run(workflow: str, target: str, name: str, output: Optional[str]):
    """Run a complete attack workflow against a target"""
    try:
        target_info = {
            'name': name,
            'url': target,
            'timestamp': datetime.now().isoformat()
        }
        
        results = asyncio.run(cli_instance.run_workflow(workflow, target_info))
        
        # Save results if output specified
        if output:
            with open(output, 'w') as f:
                json.dump([r.dict() if hasattr(r, 'dict') else str(r) for r in results], f, indent=2)
            log.success(f"Results saved to {output}")
        
    except Exception as e:
        log.error(f"Error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--agent', '-a', required=True, help='Agent name')
@click.option('--directive', '-d', required=True, help='Directive for the agent')
@click.option('--context', '-c', default='{}', help='JSON context data')
@click.option('--output', '-o', default=None, help='Output file for results')
def agent(agent: str, directive: str, context: str, output: Optional[str]):
    """Execute a single agent"""
    try:
        context_data = json.loads(context)
        result = asyncio.run(cli_instance.execute_agent(agent, directive, context_data))
        
        # Save result if output specified
        if output:
            with open(output, 'w') as f:
                json.dump(result.dict() if hasattr(result, 'dict') else str(result), f, indent=2)
            log.success(f"Result saved to {output}")
        
    except json.JSONDecodeError:
        log.error("Invalid JSON in context")
        sys.exit(1)
    except Exception as e:
        log.error(f"Error: {e}")
        sys.exit(1)


@cli.command()
def agents():
    """List all available agents"""
    try:
        asyncio.run(cli_instance.list_agents())
    except Exception as e:
        log.error(f"Error: {e}")
        sys.exit(1)


@cli.command()
def status():
    """Get framework status"""
    try:
        status_info = asyncio.run(cli_instance.get_status())
        log.info("Framework Status:")
        for key, value in status_info.items():
            log.info(f"  {key}: {value}")
    except Exception as e:
        log.error(f"Error: {e}")
        sys.exit(1)


@cli.command()
@click.option('--workflow', '-w', default=DEFAULT_WORKFLOW, help='Path to workflow YAML file')
def validate(workflow: str):
    """Validate a workflow configuration"""
    try:
        import yaml
        with open(workflow, 'r') as f:
            workflow_data = yaml.safe_load(f)
        
        log.success(f"Workflow is valid: {workflow_data.get('workflow_name', 'Unknown')}")
        log.info(f"Phases: {len(workflow_data.get('phases', []))}")
        
    except Exception as e:
        log.error(f"Workflow validation failed: {e}")
        sys.exit(1)


@cli.command()
def init():
    """Initialize a new dLNk dLNk workspace"""
    try:
        workspace = Path(WORKSPACE_DIR)
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (workspace / 'workflows').mkdir(exist_ok=True)
        (workspace / 'targets').mkdir(exist_ok=True)
        (workspace / 'results').mkdir(exist_ok=True)
        (workspace / 'payloads').mkdir(exist_ok=True)
        (workspace / 'loot').mkdir(exist_ok=True)
        
        log.success(f"Workspace initialized at {workspace}")
        
    except Exception as e:
        log.error(f"Initialization failed: {e}")
        sys.exit(1)


@cli.command()
@click.option('--host', '-h', default='0.0.0.0', help='Server host')
@click.option('--port', '-p', default=8000, help='Server port')
def server(host: str, port: int):
    """Start the API server"""
    try:
        import uvicorn
        from api.main import app
        
        log.info(f"Starting API server on {host}:{port}")
        uvicorn.run(app, host=host, port=port, reload=False)
        
    except ImportError:
        log.error("FastAPI not installed. Run: pip install fastapi uvicorn")
        sys.exit(1)
    except Exception as e:
        log.error(f"Server startup failed: {e}")
        sys.exit(1)


@cli.command()
def version():
    """Show version information"""
    click.echo("dLNk dLNk v2.0-dLNk")
    click.echo("Offensive Security Framework")
    click.echo("Powered by dLNk")


# Add attack, license, and loot commands
cli.add_command(attack_cli.attack_group)
cli.add_command(license_cli.license_group)
cli.add_command(loot_cli.loot_group)


if __name__ == '__main__':
    cli()


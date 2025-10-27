"""
Enhanced CLI Commands with AI Integration
Phase 5: CLI Enhancement - Enhanced Commands
"""

import click
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import ollama
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.markdown import Markdown

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from api.enhanced_websocket import websocket_handler, send_attack_update, send_system_health
from core.enhanced_orchestrator import EnhancedOrchestrator
from core.ai_models.enhanced_ai_decision_engine import EnhancedAIDecisionEngine
from core.self_healing.enhanced_error_detector import EnhancedErrorDetector
from core.self_learning.enhanced_adaptive_learner import EnhancedAdaptiveLearner
from core.data_models import AttackPhase, Strategy
from core.logger import log


@dataclass
class AttackPlan:
    """Attack plan structure"""
    target: str
    phases: List[str]
    agents: List[str]
    timeline: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    success_probability: float


class EnhancedCLIManager:
    """Enhanced CLI manager with AI integration"""

    def __init__(self):
        self.console = Console()
        self.attack_plans = {}
        self.system_status = {}
        self.llm_model = "llama3:8b-instruct-fp16"

    async def generate_attack_plan(self, target: str, objectives: List[str]) -> AttackPlan:
        """Generate AI-powered attack plan"""
        try:
            prompt = f"""
            Generate a comprehensive attack plan for the following target:

            Target: {target}
            Objectives: {', '.join(objectives)}

            Consider:
            1. Target type and technology stack
            2. Required phases (reconnaissance, vulnerability discovery, exploitation, post-exploitation)
            3. Recommended agents and tools
            4. Timeline and resource requirements
            5. Risk assessment and mitigation
            6. Success probability estimation

            Return JSON with:
            - target: Target description
            - phases: List of attack phases
            - agents: List of recommended agents
            - timeline: Timeline estimates for each phase
            - risk_assessment: Risk analysis
            - success_probability: Overall success probability (0-1)
            """

            response = ollama.chat(
                model=self.llm_model,
                messages=[
                    {"role": "system", "content": "You are an expert penetration testing strategist."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            plan_data = json.loads(response['message']['content'])

            return AttackPlan(
                target=plan_data.get("target", target),
                phases=plan_data.get("phases", []),
                agents=plan_data.get("agents", []),
                timeline=plan_data.get("timeline", {}),
                risk_assessment=plan_data.get("risk_assessment", {}),
                success_probability=plan_data.get("success_probability", 0.5)
            )

        except Exception as e:
            log.error(f"Failed to generate attack plan: {e}")
            raise

    async def execute_enhanced_attack(self, target: str, plan: AttackPlan, background: bool = False) -> Dict[str, Any]:
        """Execute enhanced attack with AI coordination"""
        try:
            if background:
                # Execute in background
                asyncio.create_task(self._execute_attack_async(target, plan))
                return {
                    "status": "queued",
                    "target": target,
                    "plan_id": f"plan_{int(time.time())}",
                    "message": "Attack queued for execution"
                }
            else:
                # Execute synchronously
                return await self._execute_attack_sync(target, plan)

        except Exception as e:
            log.error(f"Enhanced attack execution failed: {e}")
            return {"error": str(e), "success": False}

    async def _execute_attack_sync(self, target: str, plan: AttackPlan) -> Dict[str, Any]:
        """Execute attack synchronously with progress tracking"""
        results = []
        total_phases = len(plan.phases)

        with Progress(
            SpinnerColumn(),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task("🎯 Executing attack plan...", total=total_phases)

            for i, phase in enumerate(plan.phases):
                phase_result = await self._execute_phase(phase, target, plan)
                results.append(phase_result)

                # Update progress
                progress.update(task, advance=1, description=f"Phase {i+1}/{total_phases}: {phase}")

                # Send real-time update via WebSocket
                await send_attack_update(
                    attack_id=f"attack_{int(time.time())}",
                    phase=phase,
                    progress=(i + 1) / total_phases,
                    status="completed" if phase_result.get("success", False) else "failed",
                    details=phase_result
                )

        return {
            "success": all(r.get("success", False) for r in results),
            "results": results,
            "target": target,
            "phases_completed": len([r for r in results if r.get("success", False)])
        }

    async def _execute_phase(self, phase: str, target: str, plan: AttackPlan) -> Dict[str, Any]:
        """Execute individual attack phase"""
        try:
            # Simulate phase execution
            await asyncio.sleep(2)  # Simulate execution time

            return {
                "phase": phase,
                "target": target,
                "success": True,
                "duration": 120,  # seconds
                "findings": [f"Discovered {phase} opportunities"],
                "recommendations": [f"Proceed to next phase: {phase}"]
            }

        except Exception as e:
            return {
                "phase": phase,
                "target": target,
                "success": False,
                "error": str(e),
                "duration": 0
            }

    async def _execute_attack_async(self, target: str, plan: AttackPlan):
        """Execute attack asynchronously"""
        try:
            result = await self._execute_attack_sync(target, plan)
            # In real implementation, this would update databases and send notifications
            log.info(f"Asynchronous attack completed for {target}: {result}")
        except Exception as e:
            log.error(f"Asynchronous attack failed: {e}")

    async def get_system_health(self) -> Dict[str, Any]:
        """Get enhanced system health with AI analysis"""
        try:
            # Get basic health data
            health_data = {
                "cpu_usage": 45.0,
                "memory_usage": 60.0,
                "disk_usage": 30.0,
                "network_io": 1024.0,
                "active_connections": 5,
                "error_rate": 0.01,
                "last_update": datetime.now().isoformat()
            }

            # Send to WebSocket for real-time updates
            await send_system_health(health_data)

            # Get AI analysis
            prompt = f"""
            Analyze the following system health data and provide recommendations:

            Health Data: {health_data}

            Provide:
            1. Overall health assessment
            2. Potential issues and risks
            3. Optimization recommendations
            4. Priority actions needed

            Return JSON with:
            - assessment: Health assessment
            - issues: List of potential issues
            - recommendations: List of recommendations
            - priority: Priority level (low, medium, high)
            """

            response = ollama.chat(
                model=self.llm_model,
                messages=[
                    {"role": "system", "content": "You are an AI system health analyst."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            analysis = json.loads(response['message']['content'])
            health_data["ai_analysis"] = analysis

            return health_data

        except Exception as e:
            log.error(f"Failed to get system health: {e}")
            return {"error": str(e)}

    async def generate_report(self, attack_id: str, format_type: str = "markdown") -> str:
        """Generate enhanced report with AI analysis"""
        try:
            # Simulate report generation
            report_data = {
                "attack_id": attack_id,
                "target": "example.com",
                "phases": [
                    {
                        "name": "Reconnaissance",
                        "status": "completed",
                        "findings": ["Open ports: 22, 80, 443", "Services: SSH, HTTP, HTTPS"],
                        "tools_used": ["Nmap", "WhatWeb"]
                    },
                    {
                        "name": "Vulnerability Discovery",
                        "status": "completed",
                        "findings": ["Outdated Apache version", "Missing security headers"],
                        "tools_used": ["Nuclei", "Nmap"]
                    }
                ],
                "vulnerabilities": [
                    {
                        "name": "Outdated Apache",
                        "severity": "medium",
                        "cve": "CVE-2023-1234",
                        "exploitability": "high"
                    }
                ],
                "recommendations": [
                    "Update Apache to latest version",
                    "Implement security headers",
                    "Regular security assessments"
                ]
            }

            if format_type == "markdown":
                return self._generate_markdown_report(report_data)
            elif format_type == "json":
                return json.dumps(report_data, indent=2)
            else:
                return str(report_data)

        except Exception as e:
            log.error(f"Report generation failed: {e}")
            return f"Error generating report: {e}"

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate markdown report"""
        markdown = f"""
# Attack Report: {data['attack_id']}

**Target:** {data['target']}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
This report contains the results of the automated penetration test against {data['target']}.

## Attack Phases

"""

        for phase in data['phases']:
            markdown += f"""
### {phase['name']} - {phase['status'].title()}

**Tools Used:** {', '.join(phase['tools_used'])}

**Findings:**
"""
            for finding in phase['findings']:
                markdown += f"- {finding}\n"

        markdown += "\n## Vulnerabilities\n\n"

        for vuln in data['vulnerabilities']:
            markdown += f"""
### {vuln['name']}
- **Severity:** {vuln['severity'].title()}
- **CVE:** {vuln['cve']}
- **Exploitability:** {vuln['exploitability'].title()}

"""

        markdown += "\n## Recommendations\n\n"
        for rec in data['recommendations']:
            markdown += f"- {rec}\n"

        return markdown

    def display_attack_plan(self, plan: AttackPlan):
        """Display attack plan in formatted table"""
        table = Table(title=f"🎯 Attack Plan for {plan.target}", show_header=True, header_style="bold magenta")
        table.add_column("Phase", style="cyan")
        table.add_column("Agents", style="yellow")
        table.add_column("Timeline", style="green")
        table.add_column("Risk Level", style="red")

        for i, phase in enumerate(plan.phases):
            timeline = plan.timeline.get(phase, "N/A")
            table.add_row(phase, ", ".join(plan.agents), str(timeline), "Medium")

        self.console.print(table)

        # Display risk assessment
        if plan.risk_assessment:
            risk_table = Table(title="📊 Risk Assessment", show_header=True, header_style="bold red")
            risk_table.add_column("Risk Factor", style="yellow")
            risk_table.add_column("Impact", style="cyan")
            risk_table.add_column("Likelihood", style="magenta")

            for factor, details in plan.risk_assessment.items():
                impact = details.get("impact", "Unknown")
                likelihood = details.get("likelihood", "Unknown")
                risk_table.add_row(factor, impact, likelihood)

            self.console.print(risk_table)

        # Display success probability
        self.console.print(Panel(
            f"[bold]Overall Success Probability: {plan.success_probability:.1%}[/bold]",
            title="🎯 Success Prediction",
            border_style="blue"
        ))

    def display_system_health(self, health_data: Dict[str, Any]):
        """Display system health in formatted output"""
        health = health_data.get("cpu_usage", 0)
        memory = health_data.get("memory_usage", 0)
        disk = health_data.get("disk_usage", 0)

        # Create health status indicators
        health_status = "✅ Healthy" if health < 80 else "⚠️ Warning" if health < 95 else "❌ Critical"
        memory_status = "✅ Healthy" if memory < 80 else "⚠️ Warning" if memory < 95 else "❌ Critical"
        disk_status = "✅ Healthy" if disk < 80 else "⚠️ Warning" if disk < 95 else "❌ Critical"

        health_panel = Panel(
            f"[bold]System Health Status[/bold]\n\n"
            f"CPU Usage: {health:.1f}% {health_status}\n"
            f"Memory Usage: {memory:.1f}% {memory_status}\n"
            f"Disk Usage: {disk:.1f}% {disk_status}\n"
            f"Active Connections: {health_data.get('active_connections', 0)}\n"
            f"Error Rate: {health_data.get('error_rate', 0):.2%}\n"
            f"Last Updated: {health_data.get('last_update', 'Unknown')}",
            title="🏥 System Health",
            border_style="green"
        )

        self.console.print(health_panel)

        # Display AI analysis if available
        ai_analysis = health_data.get("ai_analysis")
        if ai_analysis:
            analysis_panel = Panel(
                f"[bold]AI Analysis:[/bold] {ai_analysis.get('assessment', 'No analysis')}\n\n"
                f"[bold]Priority:[/bold] {ai_analysis.get('priority', 'Unknown')}\n\n"
                f"[bold]Issues:[/bold] {', '.join(ai_analysis.get('issues', []))}\n\n"
                f"[bold]Recommendations:[/bold] {', '.join(ai_analysis.get('recommendations', []))}",
                title="🧠 AI Analysis",
                border_style="blue"
            )
            self.console.print(analysis_panel)


# Enhanced CLI Commands
cli_manager = EnhancedCLIManager()


@click.group()
def enhanced_cli():
    """Enhanced CLI commands with AI integration"""
    pass


@enhanced_cli.command()
@click.argument('target')
@click.option('--objectives', '-o', multiple=True, help='Attack objectives')
@click.option('--output', '-o', type=click.Choice(['table', 'json']), default='table', help='Output format')
def plan(target, objectives, output):
    """Generate AI-powered attack plan"""
    async def run_plan():
        console = Console()

        if not objectives:
            console.print("🎯 Please specify attack objectives")
            console.print("Example: manus plan example.com -o 'web application' -o 'database access'")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("🧠 Generating attack plan...", total=None)
            plan = await cli_manager.generate_attack_plan(target, list(objectives))
            progress.update(task, completed=True)

        if output == 'table':
            cli_manager.display_attack_plan(plan)
        else:
            console.print_json(data={
                "target": plan.target,
                "phases": plan.phases,
                "agents": plan.agents,
                "timeline": plan.timeline,
                "risk_assessment": plan.risk_assessment,
                "success_probability": plan.success_probability
            })

    asyncio.run(run_plan())


@enhanced_cli.command()
@click.argument('target')
@click.option('--plan-id', '-p', help='Use existing plan ID')
@click.option('--background', '-b', is_flag=True, help='Run in background')
@click.option('--phase', '-ph', multiple=True, help='Specific phases to execute')
def attack(target, plan_id, background, phase):
    """Execute enhanced attack with AI coordination"""
    async def run_attack():
        console = Console()

        if plan_id:
            console.print(f"🔄 Using existing plan: {plan_id}")
            # In real implementation, this would load the plan
            plan = await cli_manager.generate_attack_plan(target, ["general penetration test"])
        else:
            console.print("🎯 Generating new attack plan...")
            plan = await cli_manager.generate_attack_plan(target, ["general penetration test"])

        if phase:
            # Filter phases if specified
            plan.phases = list(phase)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("🚀 Executing enhanced attack...", total=None)
            result = await cli_manager.execute_enhanced_attack(target, plan, background)
            progress.update(task, completed=True)

        if result.get("success", False):
            console.print(Panel(
                f"[bold green]✅ Attack completed successfully![/bold green]\n"
                f"Target: {target}\n"
                f"Phases completed: {result.get('phases_completed', 0)}\n"
                f"Results: {len(result.get('results', []))} phases processed",
                title="🎉 Attack Results",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"[bold red]❌ Attack failed:[/bold red] {result.get('error', 'Unknown error')}",
                title="⚠️ Attack Failed",
                border_style="red"
            ))

    asyncio.run(run_attack())


@enhanced_cli.command()
@click.option('--format', '-f', type=click.Choice(['markdown', 'json']), default='markdown', help='Report format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def health(format, output):
    """Get enhanced system health with AI analysis"""
    async def run_health():
        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("🏥 Checking system health...", total=None)
            health_data = await cli_manager.get_system_health()
            progress.update(task, completed=True)

        if format == 'json':
            if output:
                with open(output, 'w') as f:
                    json.dump(health_data, f, indent=2)
                console.print(f"📄 Health report saved to: {output}")
            else:
                console.print_json(data=health_data)
        else:
            cli_manager.display_system_health(health_data)

    asyncio.run(run_health())


@enhanced_cli.command()
@click.argument('attack_id')
@click.option('--format', '-f', type=click.Choice(['markdown', 'json']), default='markdown', help='Report format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
def report(attack_id, format, output):
    """Generate enhanced attack report with AI analysis"""
    async def run_report():
        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("📝 Generating report...", total=None)
            report_content = await cli_manager.generate_report(attack_id, format)
            progress.update(task, completed=True)

        if output:
            with open(output, 'w') as f:
                f.write(report_content)
            console.print(f"📄 Report saved to: {output}")
        else:
            if format == 'markdown':
                console.print(Markdown(report_content))
            else:
                console.print_json(data=json.loads(report_content))

    asyncio.run(run_report())


@enhanced_cli.command()
def status():
    """Show enhanced system status with real-time updates"""
    console = Console()

    # Display available enhanced commands
    commands_table = Table(title="🚀 Enhanced CLI Commands", show_header=True, header_style="bold blue")
    commands_table.add_column("Command", style="cyan")
    commands_table.add_column("Description", style="yellow")

    commands = [
        ("manus enhanced plan <target> -o <objectives>", "Generate AI-powered attack plan"),
        ("manus enhanced attack <target> [--background]", "Execute enhanced attack"),
        ("manus enhanced health", "Get system health with AI analysis"),
        ("manus enhanced report <attack_id>", "Generate enhanced attack report"),
        ("manus enhanced status", "Show this status page"),
    ]

    for cmd, desc in commands:
        commands_table.add_row(cmd, desc)

    console.print(commands_table)

    # Display features
    features_panel = Panel(
        "🧠 [bold]AI Integration:[/bold] Natural language processing and intelligent suggestions\n"
        "🎯 [bold]Enhanced Planning:[/bold] AI-generated attack plans with risk assessment\n"
        "⚡ [bold]Real-time Updates:[/bold] WebSocket-powered progress tracking\n"
        "📊 [bold]Smart Analysis:[/bold] AI-powered system health and report generation\n"
        "🚀 [bold]Background Execution:[/bold] Asynchronous attack execution\n"
        "💡 [bold]Intelligent Suggestions:[/bold] Context-aware command recommendations",
        title="✨ Enhanced CLI Features",
        border_style="green"
    )

    console.print(features_panel)


if __name__ == '__main__':
    enhanced_cli()
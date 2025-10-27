"""
AI-Powered CLI Assistant with Natural Language Processing
Phase 5: CLI Enhancement - AI Assistant
"""

import click
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
import re
import difflib
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.markdown import Markdown
import ollama

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from api.enhanced_websocket import websocket_handler
from core.enhanced_orchestrator import EnhancedOrchestrator
from core.ai_models.enhanced_ai_decision_engine import EnhancedAIDecisionEngine
from core.data_models import AttackPhase, Strategy
from core.logger import log


@dataclass
class CommandSuggestion:
    """Command suggestion with explanation"""
    command: str
    explanation: str
    confidence: float
    category: str
    parameters: List[str]


@dataclass
class NLPParseResult:
    """Natural language parsing result"""
    intent: str
    action: str
    target: Optional[str] = None
    parameters: Dict[str, Any] = None
    confidence: float = 0.0
    suggested_commands: List[str] = None


class AIAssistant:
    """AI-powered CLI assistant with natural language processing"""

    def __init__(self, model_name: str = "llama3:8b-instruct-fp16"):
        self.model_name = model_name
        self.console = Console()
        self.conversation_history = []
        self.command_database = self._load_command_database()
        self.context = {}
        self.settings = self._load_settings()

    def _load_command_database(self) -> Dict[str, Dict[str, Any]]:
        """Load command database for suggestions"""
        return {
            "attack": {
                "description": "Execute attack operations",
                "commands": [
                    "manus attack <target> --type <type>",
                    "manus attack <target> --phase <phase>",
                    "manus attack <target> --agents <agents>",
                ],
                "examples": [
                    "manus attack http://example.com --type web",
                    "manus attack 192.168.1.100 --phase reconnaissance",
                ]
            },
            "scan": {
                "description": "Perform scanning operations",
                "commands": [
                    "manus scan <target> --ports <ports>",
                    "manus scan <target> --services",
                    "manus scan <target> --vulnerabilities",
                ],
                "examples": [
                    "manus scan http://example.com --ports 1-1000",
                    "manus scan 192.168.1.100 --services",
                ]
            },
            "exploit": {
                "description": "Execute exploitation operations",
                "commands": [
                    "manus exploit <target> --vuln <vulnerability>",
                    "manus exploit <target> --payload <payload>",
                ],
                "examples": [
                    "manus exploit http://example.com --vuln sql_injection",
                    "manus exploit 192.168.1.100 --payload reverse_shell",
                ]
            },
            "status": {
                "description": "Check system status and progress",
                "commands": [
                    "manus status",
                    "manus status --attacks",
                    "manus status --agents",
                ],
                "examples": [
                    "manus status",
                    "manus status --attacks",
                ]
            },
            "report": {
                "description": "Generate and view reports",
                "commands": [
                    "manus report <attack_id>",
                    "manus report --recent",
                    "manus report --export <format>",
                ],
                "examples": [
                    "manus report attack_123",
                    "manus report --recent",
                ]
            }
        }

    def _load_settings(self) -> Dict[str, Any]:
        """Load assistant settings"""
        return {
            "confidence_threshold": 0.7,
            "suggestion_count": 5,
            "conversation_history_limit": 10,
            "auto_complete_enabled": True,
            "suggestions_enabled": True,
            "natural_language_enabled": True
        }

    async def parse_natural_language(self, user_input: str) -> NLPParseResult:
        """Parse natural language input into CLI commands"""
        try:
            # First, check if it's already a valid command
            if user_input.strip().startswith('manus '):
                return NLPParseResult(
                    intent="direct_command",
                    action="execute",
                    confidence=1.0
                )

            # Use LLM to parse natural language
            prompt = self._build_nlp_prompt(user_input)

            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are an AI CLI assistant that understands natural language commands for penetration testing operations."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            result_data = json.loads(response['message']['content'])

            # Extract suggestions if available
            suggested_commands = result_data.get("suggested_commands", [])
            if isinstance(suggested_commands, str):
                suggested_commands = [suggested_commands]

            return NLPParseResult(
                intent=result_data.get("intent", "unknown"),
                action=result_data.get("action", "unknown"),
                target=result_data.get("target"),
                parameters=result_data.get("parameters", {}),
                confidence=result_data.get("confidence", 0.0),
                suggested_commands=suggested_commands
            )

        except Exception as e:
            log.error(f"Natural language parsing failed: {e}")
            return NLPParseResult(
                intent="error",
                action="error",
                confidence=0.0,
                suggested_commands=[f"manus help"]
            )

    def _build_nlp_prompt(self, user_input: str) -> str:
        """Build prompt for natural language parsing"""
        return f"""
        Parse the following natural language request into a CLI command structure:

        User request: "{user_input}"

        Available operations:
        - attack: Execute attack operations against targets
        - scan: Perform network and vulnerability scanning
        - exploit: Execute exploitation techniques
        - status: Check system and attack status
        - report: Generate and view reports

        Return JSON with:
        - intent: The main intent of the request
        - action: The specific action to take
        - target: The target (if specified)
        - parameters: Any additional parameters
        - confidence: 0-1 confidence score
        - suggested_commands: List of suggested CLI commands

        Examples:
        Input: "Scan the web server at example.com"
        Output: {{"intent": "scan", "action": "scan", "target": "example.com", "confidence": 0.9, "suggested_commands": ["manus scan example.com --services"]}}

        Input: "Attack the database server with SQL injection"
        Output: {{"intent": "attack", "action": "exploit", "target": "database server", "parameters": {{"vulnerability": "sql_injection"}}, "confidence": 0.85, "suggested_commands": ["manus attack database_server --vuln sql_injection"]}}
        """

    async def suggest_next_command(self, context: Dict[str, Any]) -> List[CommandSuggestion]:
        """Suggest next commands based on current context"""
        try:
            prompt = self._build_suggestion_prompt(context)

            response = ollama.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are an expert penetration testing advisor providing command suggestions."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            suggestions_data = json.loads(response['message']['content'])

            suggestions = []
            for suggestion in suggestions_data.get("suggestions", []):
                suggestions.append(CommandSuggestion(
                    command=suggestion["command"],
                    explanation=suggestion["explanation"],
                    confidence=suggestion["confidence"],
                    category=suggestion.get("category", "general"),
                    parameters=suggestion.get("parameters", [])
                ))

            return suggestions

        except Exception as e:
            log.error(f"Command suggestion failed: {e}")
            return []

    def _build_suggestion_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for command suggestions"""
        last_command = context.get('last_command', 'None')
        last_result = context.get('last_result', 'None')
        current_phase = context.get('current_phase', 'None')

        return f"""
        Based on the current context, suggest the next commands:

        Context:
        - Last command: {last_command}
        - Last result: {last_result}
        - Current phase: {current_phase}

        Available command categories:
        - attack: Execute attack operations
        - scan: Perform scanning operations
        - exploit: Execute exploitation operations
        - status: Check system status
        - report: Generate reports

        Return JSON array of suggested commands with:
        - command: The suggested CLI command
        - explanation: Brief explanation of why this command is suggested
        - confidence: 0-1 confidence score
        - category: Command category
        - parameters: Suggested parameters

        Provide 3-5 suggestions with the most relevant commands first.
        """

    def get_command_completions(self, partial_command: str) -> List[str]:
        """Get command completions for auto-complete"""
        if not self.settings["auto_complete_enabled"]:
            return []

        completions = []
        partial_words = partial_command.split()

        if len(partial_words) == 1 and partial_words[0] == "manus":
            # Complete with main commands
            main_commands = ["attack", "scan", "exploit", "status", "report", "config", "help"]
            for cmd in main_commands:
                if cmd.startswith(partial_words[0] if len(partial_words) == 0 else partial_words[-1]):
                    completions.append(f"manus {cmd}")

        elif len(partial_words) >= 2:
            # Complete with sub-commands and options
            main_cmd = partial_words[1]
            if main_cmd in ["attack", "scan", "exploit"]:
                options = ["--target", "--type", "--phase", "--agents", "--ports", "--vuln", "--payload"]
                for opt in options:
                    if opt.startswith(partial_words[-1]):
                        completions.append(opt)

        return completions[:10]  # Limit completions

    async def execute_command(self, command: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute CLI command and return result"""
        try:
            start_time = time.time()

            # Simulate command execution (in real implementation, this would call actual CLI)
            if command.startswith("manus attack"):
                result = await self._simulate_attack_command(command)
            elif command.startswith("manus scan"):
                result = await self._simulate_scan_command(command)
            elif command.startswith("manus status"):
                result = await self._simulate_status_command(command)
            elif command.startswith("manus report"):
                result = await self._simulate_report_command(command)
            else:
                result = {"error": f"Unknown command: {command}", "success": False}

            execution_time = time.time() - start_time

            # Update context
            if context:
                context['last_command'] = command
                context['last_result'] = result
                context['execution_time'] = execution_time

            return result

        except Exception as e:
            log.error(f"Command execution failed: {e}")
            return {"error": str(e), "success": False}

    async def _simulate_attack_command(self, command: str) -> Dict[str, Any]:
        """Simulate attack command execution"""
        # In real implementation, this would call actual attack functions
        return {
            "command": "attack",
            "target": "simulated_target",
            "status": "queued",
            "attack_id": f"attack_{int(time.time())}",
            "estimated_completion": "2024-01-01T12:00:00Z",
            "success": True,
            "message": "Attack command executed successfully"
        }

    async def _simulate_scan_command(self, command: str) -> Dict[str, Any]:
        """Simulate scan command execution"""
        return {
            "command": "scan",
            "target": "simulated_target",
            "status": "completed",
            "results": {
                "open_ports": [22, 80, 443],
                "services": ["ssh", "http", "https"],
                "vulnerabilities": ["outdated_software"]
            },
            "success": True,
            "message": "Scan completed successfully"
        }

    async def _simulate_status_command(self, command: str) -> Dict[str, Any]:
        """Simulate status command execution"""
        return {
            "command": "status",
            "system_health": {
                "cpu_usage": 45.0,
                "memory_usage": 60.0,
                "disk_usage": 30.0,
                "status": "healthy"
            },
            "active_attacks": 2,
            "agent_count": 15,
            "success": True
        }

    async def _simulate_report_command(self, command: str) -> Dict[str, Any]:
        """Simulate report command execution"""
        return {
            "command": "report",
            "report_id": f"report_{int(time.time())}",
            "summary": "Execution completed successfully",
            "success": True,
            "message": "Report generated successfully"
        }

    def display_suggestions(self, suggestions: List[CommandSuggestion]):
        """Display command suggestions in a formatted table"""
        if not suggestions:
            return

        table = Table(title="🎯 Command Suggestions", show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan")
        table.add_column("Confidence", style="yellow")
        table.add_column("Category", style="green")
        table.add_column("Explanation", style="white")

        for suggestion in suggestions:
            confidence_str = f"{suggestion.confidence:.1%}"
            table.add_row(
                suggestion.command,
                confidence_str,
                suggestion.category,
                suggestion.explanation
            )

        self.console.print(table)

    def display_nlp_result(self, result: NLPParseResult):
        """Display natural language parsing result"""
        if result.confidence >= self.settings["confidence_threshold"]:
            self.console.print(Panel(
                f"[bold green]✅ Intent recognized:[/bold green] {result.intent}\n"
                f"[bold blue]🎯 Action:[/bold blue] {result.action}\n"
                f"[bold yellow]🎯 Confidence:[/bold yellow] {result.confidence:.1%}\n"
                f"[bold white]🎯 Target:[/bold white] {result.target or 'N/A'}",
                title="🧠 Natural Language Analysis",
                border_style="green"
            ))

            if result.suggested_commands:
                self.console.print("\n[bold]Suggested Commands:[/bold]")
                for i, cmd in enumerate(result.suggested_commands, 1):
                    self.console.print(f"{i}. [cyan]{cmd}[/cyan]")

        else:
            self.console.print(Panel(
                f"[bold red]❌ Low confidence:[/bold red] {result.confidence:.1%}\n"
                f"[bold yellow]💡 Try rephrasing your request or use direct commands.[/bold yellow]",
                title="⚠️ Analysis Result",
                border_style="red"
            ))

    async def interactive_mode(self):
        """Run interactive AI assistant mode"""
        self.console.print(Panel(
            "[bold green]🤖 Manus AI Assistant[/bold green]\n"
            "Welcome to the AI-powered CLI assistant!\n"
            "You can use natural language or direct commands.\n"
            "Type 'help' for assistance or 'exit' to quit.",
            title="🚀 AI Assistant Ready",
            border_style="blue"
        ))

        context = {}

        while True:
            try:
                # Get user input
                user_input = Prompt.ask("\n[bold]You[/bold]", default="")

                if user_input.lower() in ['exit', 'quit', 'q']:
                    self.console.print("[bold green]👋 Goodbye![/bold green]")
                    break

                elif user_input.lower() in ['help', 'h']:
                    await self._display_help()
                    continue

                elif user_input.lower() in ['clear', 'cls']:
                    os.system('clear' if os.name == 'posix' else 'cls')
                    continue

                # Parse input
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    transient=True
                ) as progress:
                    task = progress.add_task("🧠 Analyzing request...", total=None)
                    result = await self.parse_natural_language(user_input)
                    progress.update(task, completed=True)

                # Display analysis
                self.display_nlp_result(result)

                # Execute or suggest
                if result.confidence >= self.settings["confidence_threshold"]:
                    if result.intent == "direct_command":
                        # Execute directly
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[progress.description]{task.description}"),
                            BarColumn(),
                            transient=True
                        ) as progress:
                            task = progress.add_task("🚀 Executing command...", total=None)
                            execution_result = await self.execute_command(user_input, context)
                            progress.update(task, completed=True)

                        self._display_execution_result(execution_result)

                    else:
                        # Get user confirmation
                        if result.suggested_commands:
                            suggested_cmd = result.suggested_commands[0]
                            confirm = Confirm(f"Execute: [cyan]{suggested_cmd}[/cyan]?", default=True)

                            if confirm:
                                with Progress(
                                    SpinnerColumn(),
                                    TextColumn("[progress.description]{task.description}"),
                                    BarColumn(),
                                    transient=True
                                ) as progress:
                                    task = progress.add_task("🚀 Executing command...", total=None)
                                    execution_result = await self.execute_command(suggested_cmd, context)
                                    progress.update(task, completed=True)

                                self._display_execution_result(execution_result)

                # Generate next suggestions
                if self.settings["suggestions_enabled"]:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        transient=True
                    ) as progress:
                        task = progress.add_task("💡 Generating suggestions...", total=None)
                        suggestions = await self.suggest_next_command(context)
                        progress.update(task, completed=True)

                    self.display_suggestions(suggestions)

            except KeyboardInterrupt:
                self.console.print("\n[bold red]Interrupted by user[/bold red]")
                break
            except Exception as e:
                log.error(f"Interactive mode error: {e}")
                self.console.print(f"[bold red]Error: {e}[/bold red]")

    def _display_help(self):
        """Display help information"""
        help_text = """
        # Manus AI Assistant Help

        ## Natural Language Commands
        - "Scan the web server at example.com"
        - "Attack the database with SQL injection"
        - "Check the status of active attacks"
        - "Generate a report for the latest attack"

        ## Direct Commands
        - `manus attack <target> --type <type>`
        - `manus scan <target> --ports <ports>`
        - `manus exploit <target> --vuln <vulnerability>`
        - `manus status`
        - `manus report <attack_id>`

        ## Assistant Commands
        - `help` - Show this help
        - `clear` - Clear the screen
        - `exit` - Exit the assistant

        ## Features
        - 🧠 Natural language command parsing
        - 💡 Intelligent command suggestions
        - 🎯 Context-aware recommendations
        - ⚡ Auto-completion support
        """

        self.console.print(Markdown(help_text))

    def _display_execution_result(self, result: Dict[str, Any]):
        """Display command execution result"""
        if result.get("success", False):
            self.console.print(Panel(
                f"[bold green]✅ Success![/bold green]\n"
                f"[bold white]{result.get('message', 'Command executed successfully')}[/bold white]",
                title="🎉 Execution Result",
                border_style="green"
            ))
        else:
            self.console.print(Panel(
                f"[bold red]❌ Error:[/bold red] {result.get('error', 'Unknown error')}",
                title="⚠️ Execution Failed",
                border_style="red"
            ))


@click.group()
def cli():
    """Manus AI Attack Platform CLI with AI Assistant"""
    pass


@cli.command()
@click.option('--interactive', '-i', is_flag=True, help='Interactive AI assistant mode')
@click.option('--model', '-m', default='llama3:8b-instruct-fp16', help='LLM model to use')
def assistant(interactive, model):
    """AI-powered CLI assistant with natural language processing"""
    ai_assistant = AIAssistant(model_name=model)

    if interactive:
        # Run interactive mode
        asyncio.run(ai_assistant.interactive_mode())
    else:
        # Run single command mode
        console = Console()
        console.print("Use --interactive flag to start the AI assistant")
        console.print("Example: manus assistant -i")


@cli.command()
@click.argument('text', required=False)
@click.option('--model', '-m', default='llama3:8b-instruct-fp16', help='LLM model to use')
def ask(text, model):
    """Ask the AI assistant a question using natural language"""
    ai_assistant = AIAssistant(model_name=model)

    if not text:
        console = Console()
        text = Prompt.ask("What would you like to ask?")

    async def run_ask():
        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("🧠 Analyzing request...", total=None)
            result = await ai_assistant.parse_natural_language(text)
            progress.update(task, completed=True)

        ai_assistant.display_nlp_result(result)

    asyncio.run(run_ask())


@cli.command()
@click.argument('command', required=False)
@click.option('--model', '-m', default='llama3:8b-instruct-fp16', help='LLM model to use')
def suggest(command, model):
    """Get command suggestions based on context"""
    ai_assistant = AIAssistant(model_name=model)

    context = {}
    if command:
        context['last_command'] = command

    async def run_suggest():
        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("💡 Generating suggestions...", total=None)
            suggestions = await ai_assistant.suggest_next_command(context)
            progress.update(task, completed=True)

        ai_assistant.display_suggestions(suggestions)

    asyncio.run(run_suggest())


if __name__ == '__main__':
    cli()
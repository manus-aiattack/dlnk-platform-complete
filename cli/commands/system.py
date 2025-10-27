"""System Commands"""
import click
from rich.console import Console

console = Console()

@click.group(name='system')
def system_commands():
    """System commands"""
    pass

@system_commands.command(name='status')
def status():
    """Show system status"""
    console.print("[cyan]System status...[/cyan]")

@system_commands.command(name='agents')
def agents():
    """List all agents"""
    console.print("[cyan]Listing agents...[/cyan]")

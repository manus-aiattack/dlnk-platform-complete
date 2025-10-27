"""
Attack Commands
"""

import click
import questionary
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from cli.client import get_client
from cli.config import get_config

console = Console()


@click.group(name='attack')
def attack_commands():
    """Attack management commands"""
    pass


@attack_commands.command(name='start')
@click.argument('target', required=False)
@click.option('--type', 'attack_type', default='full_auto', help='Attack type')
@click.option('--follow', is_flag=True, help='Follow attack progress')
def start(target, attack_type, follow):
    """Start a new attack"""
    config = get_config()
    if not config.is_authenticated():
        console.print("[red]Please login first: dlnk auth login[/red]")
        return
    
    client = get_client()
    
    # Interactive target input if not provided
    if not target:
        target = questionary.text(
            "Enter target URL:",
            validate=lambda x: x.startswith('http') or "URL must start with http:// or https://"
        ).ask()
        
        if not target:
            console.print("[yellow]Attack cancelled[/yellow]")
            return
    
    # Interactive attack type selection
    if not attack_type or attack_type == 'full_auto':
        attack_type = questionary.select(
            "Select attack type:",
            choices=[
                "full_auto - Full automated attack",
                "scan - Vulnerability scanning only",
                "exploit - Exploitation only",
                "sql_injection - SQL Injection",
                "xss - Cross-Site Scripting",
                "command_injection - Command Injection"
            ]
        ).ask()
        
        if attack_type:
            attack_type = attack_type.split(' - ')[0]
        else:
            console.print("[yellow]Attack cancelled[/yellow]")
            return
    
    try:
        console.print(f"[cyan]Starting {attack_type} attack on {target}...[/cyan]")
        result = client.start_attack(target, attack_type)
        
        attack_id = result['attack_id']
        console.print(Panel.fit(
            f"[green]✓ Attack started successfully[/green]\n"
            f"[cyan]Attack ID:[/cyan] {attack_id}\n"
            f"[cyan]Target:[/cyan] {target}\n"
            f"[cyan]Type:[/cyan] {attack_type}",
            title="Attack Started",
            border_style="green"
        ))
        
        if follow:
            _follow_attack(attack_id)
            
    except Exception as e:
        console.print(f"[red]✗ Failed to start attack: {e}[/red]")


def _follow_attack(attack_id: str):
    """Follow attack progress"""
    client = get_client()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Running attack...", total=100)
        
        while True:
            try:
                status = client.get_attack(attack_id)
                progress.update(task, completed=status['progress'], description=f"[cyan]{status['phase']}...")
                
                if status['status'] in ['completed', 'failed', 'cancelled']:
                    break
                
                time.sleep(2)
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Stopped following (attack still running)[/yellow]")
                break
            except Exception as e:
                console.print(f"\n[red]Error: {e}[/red]")
                break
        
        # Show final results
        if status['status'] == 'completed':
            console.print(f"\n[green]✓ Attack completed![/green]")
            console.print(f"Vulnerabilities found: {status.get('vulnerabilities_found', 0)}")
        elif status['status'] == 'failed':
            console.print(f"\n[red]✗ Attack failed: {status.get('error', 'Unknown error')}[/red]")


@attack_commands.command(name='list')
@click.option('--status', help='Filter by status')
def list_attacks(status):
    """List all attacks"""
    config = get_config()
    if not config.is_authenticated():
        console.print("[red]Please login first[/red]")
        return
    
    client = get_client()
    
    try:
        attacks = client.list_attacks(status=status)
        
        if not attacks:
            console.print("[yellow]No attacks found[/yellow]")
            return
        
        table = Table(title="Attacks")
        table.add_column("ID", style="cyan")
        table.add_column("Target", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Status", style="magenta")
        table.add_column("Progress", style="blue")
        table.add_column("Vulns", style="red")
        
        for attack in attacks:
            table.add_row(
                attack['id'][:8],
                attack['target_url'][:40],
                attack['attack_type'],
                attack['status'],
                f"{attack['progress']}%",
                str(attack.get('vulnerabilities_found', 0))
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@attack_commands.command(name='show')
@click.argument('attack_id')
def show(attack_id):
    """Show attack details"""
    config = get_config()
    if not config.is_authenticated():
        console.print("[red]Please login first[/red]")
        return
    
    client = get_client()
    
    try:
        attack = client.get_attack(attack_id)
        
        console.print(Panel.fit(
            f"[cyan]ID:[/cyan] {attack['id']}\n"
            f"[cyan]Target:[/cyan] {attack['target_url']}\n"
            f"[cyan]Type:[/cyan] {attack['attack_type']}\n"
            f"[cyan]Status:[/cyan] {attack['status']}\n"
            f"[cyan]Progress:[/cyan] {attack['progress']}%\n"
            f"[cyan]Phase:[/cyan] {attack['phase']}\n"
            f"[cyan]Vulnerabilities:[/cyan] {attack.get('vulnerabilities_found', 0)}\n"
            f"[cyan]Started:[/cyan] {attack['start_time']}",
            title="Attack Details",
            border_style="cyan"
        ))
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@attack_commands.command(name='stop')
@click.argument('attack_id')
def stop(attack_id):
    """Stop a running attack"""
    config = get_config()
    if not config.is_authenticated():
        console.print("[red]Please login first[/red]")
        return
    
    client = get_client()
    
    if not questionary.confirm(f"Stop attack {attack_id}?").ask():
        console.print("[yellow]Cancelled[/yellow]")
        return
    
    try:
        client.stop_attack(attack_id)
        console.print(f"[green]✓ Attack {attack_id} stopped[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@attack_commands.command(name='delete')
@click.argument('attack_id')
def delete(attack_id):
    """Delete an attack"""
    config = get_config()
    if not config.is_authenticated():
        console.print("[red]Please login first[/red]")
        return
    
    client = get_client()
    
    if not questionary.confirm(f"Delete attack {attack_id}? This cannot be undone.").ask():
        console.print("[yellow]Cancelled[/yellow]")
        return
    
    try:
        client.delete_attack(attack_id)
        console.print(f"[green]✓ Attack {attack_id} deleted[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


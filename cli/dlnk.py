#!/usr/bin/env python3
"""
dLNk Attack Platform - Terminal CLI
Command-line interface for dLNk Attack Platform
"""

import click
import asyncio
import aiohttp
import json
import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.live import Live
from rich import print as rprint
from datetime import datetime
import time

console = Console()

# Configuration
API_URL = os.getenv("DLNK_API_URL", "localhost:8000")
API_KEY = os.getenv("DLNK_API_KEY", "")


@click.group()
@click.version_option(version="2.0.0", prog_name="dLNk")
def cli():
    """
    🎯 dLNk Attack Platform - Terminal CLI
    
    Advanced penetration testing platform with AI-powered automation.
    
    \b
    Setup:
        export DLNK_API_KEY="your_api_key_here"
        export DLNK_API_URL="localhost:8000"  # optional
    
    \b
    Examples:
        dlnk attack https://localhost:8000
        dlnk status <attack_id>
        dlnk history
        dlnk admin keys
    """
    if not API_KEY:
        console.print("[red]❌ Error: DLNK_API_KEY not set[/red]")
        console.print("[yellow]💡 Run: export DLNK_API_KEY='your_key_here'[/yellow]")
        raise click.Abort()


@cli.command()
@click.argument('target_url')
@click.option('--mode', '-m', type=click.Choice(['auto', 'stealth', 'aggressive']), default='auto',
              help='Attack mode')
@click.option('--follow', '-f', is_flag=True, help='Follow attack progress in real-time')
def attack(target_url, mode, follow):
    """
    🎯 Launch automated attack
    
    \b
    Examples:
        dlnk attack https://localhost:8000
        dlnk attack https://localhost:8000 --mode stealth
        dlnk attack https://localhost:8000 --follow
    """
    asyncio.run(_attack(target_url, mode, follow))


async def _attack(target_url: str, mode: str, follow: bool):
    """Launch attack"""
    
    console.print(Panel.fit(
        f"[bold cyan]🎯 dLNk Attack Platform[/bold cyan]\n"
        f"[white]Target:[/white] {target_url}\n"
        f"[white]Mode:[/white] {mode}",
        title="Launch Attack"
    ))
    
    try:
        async with aiohttp.ClientSession() as session:
            # Launch attack
            console.print("\n[yellow]⏳ Launching attack...[/yellow]")
            
            async with session.post(
                f"{API_URL}/api/attack/launch",
                headers={"X-API-Key": API_KEY},
                json={"target_url": target_url, "attack_mode": mode}
            ) as response:
                if response.status != 200:
                    error = await response.text()
                    console.print(f"[red]❌ Failed to launch attack: {error}[/red]")
                    return
                
                data = await response.json()
                attack_id = data["attack_id"]
            
            console.print(f"[green]✅ Attack launched successfully![/green]")
            console.print(f"[cyan]Attack ID:[/cyan] {attack_id}")
            
            if follow:
                console.print("\n[yellow]📊 Following attack progress...[/yellow]\n")
                await _follow_attack(session, attack_id)
            else:
                console.print(f"\n[yellow]💡 Track progress:[/yellow] dlnk status {attack_id}")
    
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


async def _follow_attack(session: aiohttp.ClientSession, attack_id: str):
    """Follow attack progress in real-time"""
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Attack in progress...", total=100)
        
        while True:
            try:
                async with session.get(
                    f"{API_URL}/api/attack/{attack_id}/status",
                    headers={"X-API-Key": API_KEY}
                ) as response:
                    if response.status != 200:
                        break
                    
                    data = await response.json()
                    status = data["status"]
                    prog = data["progress"]
                    
                    progress.update(task, completed=prog, description=f"[cyan]{status}")
                    
                    if status in ["completed", "failed", "stopped"]:
                        break
                
                await asyncio.sleep(2)
            
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                break
        
        # Show final results
        await _show_results(session, attack_id)


async def _show_results(session: aiohttp.ClientSession, attack_id: str):
    """Show attack results"""
    
    console.print("\n" + "="*60)
    console.print("[bold green]📊 Attack Results[/bold green]")
    console.print("="*60 + "\n")
    
    try:
        # Get status
        async with session.get(
            f"{API_URL}/api/attack/{attack_id}/status",
            headers={"X-API-Key": API_KEY}
        ) as response:
            status_data = await response.json()
        
        # Get vulnerabilities
        async with session.get(
            f"{API_URL}/api/attack/{attack_id}/vulnerabilities",
            headers={"X-API-Key": API_KEY}
        ) as response:
            vulns = await response.json()
        
        # Status table
        status_table = Table(show_header=False, box=None)
        status_table.add_column("Key", style="cyan")
        status_table.add_column("Value", style="white")
        
        status_table.add_row("Status", status_data["status"])
        status_table.add_row("Progress", f"{status_data['progress']}%")
        status_table.add_row("Vulnerabilities", str(status_data["vulnerabilities_found"]))
        status_table.add_row("Successful Exploits", str(status_data["exploits_successful"]))
        status_table.add_row("Data Exfiltrated", f"{status_data['data_exfiltrated_bytes']} bytes")
        
        console.print(status_table)
        
        # Vulnerabilities table
        if vulns:
            console.print("\n[bold cyan]🔍 Discovered Vulnerabilities:[/bold cyan]\n")
            
            vuln_table = Table(show_header=True)
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Title", style="white")
            vuln_table.add_column("CVSS", style="yellow")
            
            for vuln in vulns:
                severity_color = {
                    "critical": "red",
                    "high": "orange1",
                    "medium": "yellow",
                    "low": "green"
                }.get(vuln["severity"], "white")
                
                vuln_table.add_row(
                    vuln["vuln_type"],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    vuln["title"][:50],
                    str(vuln.get("cvss_score", "N/A"))
                )
            
            console.print(vuln_table)
        
        console.print(f"\n[green]✅ Attack completed![/green]")
    
    except Exception as e:
        console.print(f"[red]Error fetching results: {e}[/red]")


@cli.command()
@click.argument('attack_id')
def status(attack_id):
    """
    📊 Get attack status
    
    \b
    Example:
        dlnk status abc123-def456-ghi789
    """
    asyncio.run(_status(attack_id))


async def _status(attack_id: str):
    """Get attack status"""
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{API_URL}/api/attack/{attack_id}/status",
                headers={"X-API-Key": API_KEY}
            ) as response:
                if response.status != 200:
                    error = await response.text()
                    console.print(f"[red]❌ Error: {error}[/red]")
                    return
                
                data = await response.json()
        
        # Display status
        table = Table(show_header=False, box=None)
        table.add_column("Key", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Attack ID", attack_id)
        table.add_row("Target", data["target_url"])
        table.add_row("Status", data["status"])
        table.add_row("Progress", f"{data['progress']}%")
        table.add_row("Vulnerabilities", str(data["vulnerabilities_found"]))
        table.add_row("Successful Exploits", str(data["exploits_successful"]))
        table.add_row("Started", data["started_at"])
        
        if data["completed_at"]:
            table.add_row("Completed", data["completed_at"])
        
        console.print("\n")
        console.print(Panel(table, title="[bold cyan]Attack Status[/bold cyan]"))
    
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@cli.command()
@click.option('--limit', '-l', default=10, help='Number of attacks to show')
def history(limit):
    """
    📜 Show attack history
    
    \b
    Example:
        dlnk history
        dlnk history --limit 20
    """
    asyncio.run(_history(limit))


async def _history(limit: int):
    """Show attack history"""
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{API_URL}/api/attack/history?limit={limit}",
                headers={"X-API-Key": API_KEY}
            ) as response:
                if response.status != 200:
                    error = await response.text()
                    console.print(f"[red]❌ Error: {error}[/red]")
                    return
                
                attacks = await response.json()
        
        if not attacks:
            console.print("[yellow]No attacks found[/yellow]")
            return
        
        # Display table
        table = Table(show_header=True)
        table.add_column("ID", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Status", style="yellow")
        table.add_column("Progress", style="green")
        table.add_column("Vulns", style="red")
        table.add_column("Started", style="blue")
        
        for attack in attacks:
            table.add_row(
                attack["attack_id"][:8] + "...",
                attack["target_url"][:30],
                attack["status"],
                f"{attack['progress']}%",
                str(attack["vulnerabilities_found"]),
                attack["started_at"][:19]
            )
        
        console.print("\n")
        console.print(table)
        console.print(f"\n[cyan]Showing {len(attacks)} attacks[/cyan]")
    
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@cli.command()
@click.argument('attack_id')
def stop(attack_id):
    """
    🛑 Stop running attack
    
    \b
    Example:
        dlnk stop abc123-def456-ghi789
    """
    asyncio.run(_stop(attack_id))


async def _stop(attack_id: str):
    """Stop attack"""
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{API_URL}/api/attack/{attack_id}/stop",
                headers={"X-API-Key": API_KEY}
            ) as response:
                if response.status != 200:
                    error = await response.text()
                    console.print(f"[red]❌ Error: {error}[/red]")
                    return
                
                data = await response.json()
        
        console.print(f"[green]✅ {data['message']}[/green]")
    
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


@cli.group()
def admin():
    """
    👑 Admin commands
    
    Manage API keys and system settings.
    """
    pass


@admin.command('keys')
def admin_keys():
    """List all API keys"""
    asyncio.run(_admin_keys())


async def _admin_keys():
    """List API keys"""
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{API_URL}/api/admin/keys",
                headers={"X-API-Key": API_KEY}
            ) as response:
                if response.status != 200:
                    error = await response.text()
                    console.print(f"[red]❌ Error: {error}[/red]")
                    return
                
                keys = await response.json()
        
        if not keys:
            console.print("[yellow]No keys found[/yellow]")
            return
        
        # Display table
        table = Table(show_header=True)
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("User", style="white")
        table.add_column("Usage", style="green")
        table.add_column("Status", style="red")
        table.add_column("Created", style="blue")
        
        for key in keys:
            status = "active" if key["is_active"] else "revoked"
            usage = f"{key['usage_count']}/{key['usage_limit'] or '∞'}"
            
            table.add_row(
                str(key["id"]),
                key["key_type"],
                key["user_name"] or "N/A",
                usage,
                status,
                key["created_at"][:19]
            )
        
        console.print("\n")
        console.print(table)
        console.print(f"\n[cyan]Total: {len(keys)} keys[/cyan]")
    
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")


if __name__ == '__main__':
    cli()


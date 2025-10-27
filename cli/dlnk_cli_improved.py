#!/usr/bin/env python3
"""
dLNk Attack Platform CLI - Improved Version
Command Line Interface for AI-Powered Cybersecurity Testing Platform

Usage:
    dlnk attack <url> [options]
    dlnk status <attack_id>
    dlnk history [options]
    dlnk admin [subcommand]
    dlnk config [subcommand]
    dlnk help [command]
"""

import click
import sys
import json
import requests
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint

# Initialize Rich console
console = Console()

# Default configuration
DEFAULT_CONFIG = {
    'api_url': 'http://localhost:8000',
    'api_key': None,
    'timeout': 30,
    'verify_ssl': True,
}

# Config file path
CONFIG_FILE = Path.home() / '.dlnk' / 'config.json'


class CLIConfig:
    """CLI Configuration Manager"""
    
    def __init__(self):
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return {**DEFAULT_CONFIG, **json.load(f)}
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to load config: {e}[/yellow]")
        return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()


class APIClient:
    """API Client for dLNk Platform"""
    
    def __init__(self, config: CLIConfig):
        self.config = config
        self.base_url = config.get('api_url')
        self.api_key = config.get('api_key')
        self.timeout = config.get('timeout', 30)
        self.verify_ssl = config.get('verify_ssl', True)
    
    def _headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers
    
    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request"""
        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault('headers', self._headers())
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            console.print(f"[red]API Error: {e}[/red]")
            sys.exit(1)
    
    def get(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """GET request"""
        response = self._request('GET', endpoint, **kwargs)
        return response.json()
    
    def post(self, endpoint: str, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """POST request"""
        kwargs['json'] = data
        response = self._request('POST', endpoint, **kwargs)
        return response.json()
    
    def put(self, endpoint: str, data: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        """PUT request"""
        kwargs['json'] = data
        response = self._request('PUT', endpoint, **kwargs)
        return response.json()
    
    def delete(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """DELETE request"""
        response = self._request('DELETE', endpoint, **kwargs)
        return response.json()


# Initialize config and client
config = CLIConfig()
api = APIClient(config)


@click.group()
@click.version_option(version='2.0.0', prog_name='dLNk Attack Platform')
def cli():
    """
    dLNk Attack Platform CLI
    
    AI-Powered Cybersecurity Testing Platform
    
    Examples:
        dlnk attack https://example.com
        dlnk status abc123
        dlnk history --limit 10
        dlnk admin keys list
    """
    pass


@cli.command()
@click.argument('url')
@click.option('--follow', '-f', is_flag=True, help='Follow attack progress in real-time')
@click.option('--mode', '-m', type=click.Choice(['auto', 'manual']), default='auto', help='Attack mode')
@click.option('--agents', '-a', multiple=True, help='Specific agents to use')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
def attack(url: str, follow: bool, mode: str, agents: tuple, output: Optional[str]):
    """
    Launch an attack against a target URL
    
    Examples:
        dlnk attack https://example.com
        dlnk attack https://example.com --follow
        dlnk attack https://example.com --agents SQLMapAgent --agents XSSHunter
    """
    console.print(Panel.fit(
        f"[cyan]Launching attack against:[/cyan] [bold]{url}[/bold]",
        title="dLNk Attack Platform",
        border_style="cyan"
    ))
    
    # Prepare attack data
    attack_data = {
        'target_url': url,
        'mode': mode,
        'agents': list(agents) if agents else None,
    }
    
    try:
        # Launch attack
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Launching attack...", total=None)
            result = api.post('/api/attacks', attack_data)
            progress.update(task, completed=True)
        
        attack_id = result.get('attack_id')
        console.print(f"[green]✓[/green] Attack launched successfully!")
        console.print(f"[cyan]Attack ID:[/cyan] {attack_id}")
        
        if follow:
            # Follow attack progress
            follow_attack_progress(attack_id)
        else:
            console.print(f"\n[yellow]Tip:[/yellow] Use 'dlnk status {attack_id}' to check progress")
        
        # Save results if requested
        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
            console.print(f"[green]✓[/green] Results saved to {output}")
    
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('attack_id')
@click.option('--follow', '-f', is_flag=True, help='Follow attack progress')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def status(attack_id: str, follow: bool, json_output: bool):
    """
    Get status of an attack
    
    Examples:
        dlnk status abc123
        dlnk status abc123 --follow
        dlnk status abc123 --json
    """
    try:
        if follow:
            follow_attack_progress(attack_id)
        else:
            result = api.get(f'/api/attacks/{attack_id}')
            
            if json_output:
                console.print_json(data=result)
            else:
                display_attack_status(result)
    
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(1)


@cli.command()
@click.option('--limit', '-l', default=10, help='Number of attacks to show')
@click.option('--status', '-s', help='Filter by status')
@click.option('--json', 'json_output', is_flag=True, help='Output as JSON')
def history(limit: int, status: Optional[str], json_output: bool):
    """
    Show attack history
    
    Examples:
        dlnk history
        dlnk history --limit 20
        dlnk history --status completed
    """
    try:
        params = {'limit': limit}
        if status:
            params['status'] = status
        
        result = api.get('/api/attacks', params=params)
        
        if json_output:
            console.print_json(data=result)
        else:
            display_attack_history(result)
    
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(1)


@cli.group()
def admin():
    """
    Admin commands
    
    Subcommands:
        keys    - Manage API keys
        users   - Manage users
        stats   - View statistics
    """
    pass


@admin.group()
def keys():
    """Manage API keys"""
    pass


@keys.command('list')
def keys_list():
    """List all API keys"""
    try:
        result = api.get('/api/admin/keys')
        display_keys_table(result)
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(1)


@keys.command('create')
@click.option('--name', '-n', required=True, help='Key name')
@click.option('--role', '-r', type=click.Choice(['admin', 'user']), default='user', help='Key role')
@click.option('--expires', '-e', help='Expiration date (YYYY-MM-DD)')
def keys_create(name: str, role: str, expires: Optional[str]):
    """Create a new API key"""
    try:
        data = {'name': name, 'role': role}
        if expires:
            data['expires_at'] = expires
        
        result = api.post('/api/admin/keys', data)
        console.print(f"[green]✓[/green] API Key created successfully!")
        console.print(f"[cyan]Key:[/cyan] {result['key']}")
        console.print(f"[yellow]⚠ Save this key securely - it won't be shown again![/yellow]")
    
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(1)


@keys.command('revoke')
@click.argument('key_id')
def keys_revoke(key_id: str):
    """Revoke an API key"""
    try:
        api.delete(f'/api/admin/keys/{key_id}')
        console.print(f"[green]✓[/green] API Key revoked successfully!")
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}")
        sys.exit(1)


@cli.group()
def config_group():
    """
    Configuration commands
    
    Subcommands:
        show    - Show current configuration
        set     - Set configuration value
        init    - Initialize configuration
    """
    pass


@config_group.command('show')
def config_show():
    """Show current configuration"""
    table = Table(title="dLNk CLI Configuration")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in config.config.items():
        if key == 'api_key' and value:
            value = value[:8] + '...' + value[-4:]
        table.add_row(key, str(value))
    
    console.print(table)


@config_group.command('set')
@click.argument('key')
@click.argument('value')
def config_set(key: str, value: str):
    """Set configuration value"""
    config.set(key, value)
    console.print(f"[green]✓[/green] Configuration updated: {key} = {value}")


@config_group.command('init')
def config_init():
    """Initialize configuration"""
    console.print("[cyan]Initializing dLNk CLI configuration...[/cyan]")
    
    api_url = click.prompt("API URL", default="http://localhost:8000")
    api_key = click.prompt("API Key", hide_input=True)
    
    config.set('api_url', api_url)
    config.set('api_key', api_key)
    
    console.print(f"[green]✓[/green] Configuration saved to {CONFIG_FILE}")


# Helper functions

def follow_attack_progress(attack_id: str):
    """Follow attack progress in real-time"""
    console.print(f"[cyan]Following attack progress...[/cyan] (Press Ctrl+C to stop)")
    
    try:
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Attack Progress", total=100)
            
            while True:
                result = api.get(f'/api/attacks/{attack_id}')
                status = result.get('status')
                progress_value = result.get('progress', 0)
                
                progress.update(task, completed=progress_value)
                
                if status in ['completed', 'failed']:
                    break
                
                import time
                time.sleep(2)
        
        display_attack_status(result)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped following attack[/yellow]")


def display_attack_status(attack: Dict[str, Any]):
    """Display attack status"""
    table = Table(title=f"Attack Status: {attack.get('id')}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Target", attack.get('target_url'))
    table.add_row("Status", attack.get('status'))
    table.add_row("Progress", f"{attack.get('progress', 0)}%")
    table.add_row("Started", attack.get('started_at'))
    table.add_row("Vulnerabilities", str(len(attack.get('vulnerabilities', []))))
    
    console.print(table)


def display_attack_history(attacks: list):
    """Display attack history"""
    table = Table(title="Attack History")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Progress", style="blue")
    table.add_column("Started", style="magenta")
    
    for attack in attacks:
        table.add_row(
            attack.get('id', '')[:8],
            attack.get('target_url', ''),
            attack.get('status', ''),
            f"{attack.get('progress', 0)}%",
            attack.get('started_at', '')
        )
    
    console.print(table)


def display_keys_table(keys: list):
    """Display API keys table"""
    table = Table(title="API Keys")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Role", style="yellow")
    table.add_column("Created", style="blue")
    table.add_column("Expires", style="magenta")
    table.add_column("Status", style="red")
    
    for key in keys:
        table.add_row(
            key.get('id', '')[:8],
            key.get('name', ''),
            key.get('role', ''),
            key.get('created_at', ''),
            key.get('expires_at', 'Never'),
            key.get('status', '')
        )
    
    console.print(table)


# Register config group with proper name
cli.add_command(config_group, name='config')


if __name__ == '__main__':
    cli()


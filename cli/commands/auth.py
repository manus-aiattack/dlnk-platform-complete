"""
Authentication Commands
"""

import click
import questionary
from rich.console import Console
from rich.panel import Panel
from cli.config import get_config
from cli.client import get_client

console = Console()


@click.group(name='auth')
def auth_commands():
    """Authentication commands"""
    pass


@auth_commands.command(name='login')
@click.option('--api-key', help='API key for authentication')
def login(api_key):
    """Login to dLNk platform"""
    config = get_config()
    client = get_client()
    
    # Get API key if not provided
    if not api_key:
        api_key = questionary.password(
            "Enter your API key:",
            validate=lambda x: len(x) > 0 or "API key cannot be empty"
        ).ask()
        
        if not api_key:
            console.print("[red]Login cancelled[/red]")
            return
    
    try:
        # Verify API key with server
        result = client.login(api_key)
        
        # Save credentials
        config.set_api_key(api_key)
        config.set_user(result['username'], result['role'])
        
        console.print(Panel.fit(
            f"[green]✓ Successfully logged in as {result['username']} ({result['role']})[/green]",
            title="Login Success",
            border_style="green"
        ))
        
    except Exception as e:
        console.print(f"[red]✗ Login failed: {e}[/red]")


@auth_commands.command(name='logout')
def logout():
    """Logout from dLNk platform"""
    config = get_config()
    
    if not config.is_authenticated():
        console.print("[yellow]Not logged in[/yellow]")
        return
    
    # Confirm logout
    if questionary.confirm("Are you sure you want to logout?").ask():
        config.clear_user()
        console.print("[green]✓ Successfully logged out[/green]")
    else:
        console.print("[yellow]Logout cancelled[/yellow]")


@auth_commands.command(name='whoami')
def whoami():
    """Show current user information"""
    config = get_config()
    
    if not config.is_authenticated():
        console.print("[yellow]Not logged in[/yellow]")
        return
    
    console.print(Panel.fit(
        f"[cyan]Username:[/cyan] {config.user.username}\n"
        f"[cyan]Role:[/cyan] {config.user.role}\n"
        f"[cyan]API URL:[/cyan] {config.api.url}",
        title="Current User",
        border_style="cyan"
    ))


@auth_commands.command(name='status')
def status():
    """Check authentication status"""
    config = get_config()
    
    if config.is_authenticated():
        console.print("[green]✓ Authenticated[/green]")
        console.print(f"User: {config.user.username} ({config.user.role})")
    else:
        console.print("[red]✗ Not authenticated[/red]")
        console.print("Run 'dlnk auth login' to login")


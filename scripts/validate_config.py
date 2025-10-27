#!/usr/bin/env python3
"""
Configuration Validation Script
Validates environment variables and configuration settings
"""
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from config.env_loader import validate_config, ConfigError
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError as e:
    print(f"Error: Required package not found: {e}")
    print("Please install required packages: pip install rich python-dotenv")
    sys.exit(1)

console = Console()


def check_env_file():
    """Check if .env file exists"""
    env_path = Path('.env')
    env_example_path = Path('.env.example')
    
    if not env_path.exists():
        console.print("[yellow]⚠️  Warning: .env file not found[/yellow]")
        
        if env_example_path.exists():
            console.print("Creating .env from .env.example...")
            import shutil
            shutil.copy(env_example_path, env_path)
            console.print("[green]✅ Created .env file[/green]")
            console.print("[yellow]⚠️  Please edit .env and set your configuration[/yellow]")
            return False
        else:
            console.print("[red]❌ .env.example not found[/red]")
            console.print("Please create .env file manually")
            return False
    
    console.print("[green]✅ .env file found[/green]")
    return True


def display_config():
    """Display current configuration"""
    table = Table(title="Current Configuration", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan", width=15)
    table.add_column("Variable", style="green", width=25)
    table.add_column("Value", style="yellow", width=30)
    table.add_column("Status", style="white", width=10)
    
    configs = [
        # Database
        ("Database", "DB_HOST", os.getenv('DB_HOST', 'localhost'), True),
        ("Database", "DB_PORT", os.getenv('DB_PORT', '5432'), True),
        ("Database", "DB_USER", os.getenv('DB_USER', 'dlnk'), True),
        ("Database", "DB_PASSWORD", "***" if os.getenv('DB_PASSWORD', "") else "NOT SET", bool(os.getenv('DB_PASSWORD', ""))),
        ("Database", "DB_NAME", os.getenv('DB_NAME', 'dlnk_db'), True),
        
        # Redis
        ("Redis", "REDIS_HOST", os.getenv('REDIS_HOST', 'localhost'), True),
        ("Redis", "REDIS_PORT", os.getenv('REDIS_PORT', '6379'), True),
        
        # LLM
        ("LLM", "LLM_PROVIDER", os.getenv('LLM_PROVIDER', 'ollama'), True),
        ("LLM", "OLLAMA_HOST", os.getenv('OLLAMA_HOST', 'localhost'), True),
        ("LLM", "OLLAMA_PORT", os.getenv('OLLAMA_PORT', '11434'), True),
        ("LLM", "OLLAMA_MODEL", os.getenv('OLLAMA_MODEL', 'mixtral:latest'), True),
        
        # C2
        ("C2", "C2_HOST", os.getenv('C2_HOST', 'localhost'), True),
        ("C2", "C2_PORT", os.getenv('C2_PORT', '8000'), True),
        ("C2", "C2_PROTOCOL", os.getenv('C2_PROTOCOL', 'http'), True),
        
        # Security
        ("Security", "SECRET_KEY", "***" if os.getenv('SECRET_KEY', "") else "NOT SET", bool(os.getenv('SECRET_KEY', ""))),
        ("Security", "WEBSHELL_PASSWORD", "***" if os.getenv('WEBSHELL_PASSWORD', "") else "changeme", os.getenv('WEBSHELL_PASSWORD', "") != 'changeme'),
        
        # Feature Flags
        ("Features", "SIMULATION_MODE", os.getenv('SIMULATION_MODE', 'False'), True),
    ]
    
    for category, var, value, is_set in configs:
        status = "✅" if is_set else "❌"
        table.add_row(category, var, str(value), status)
    
    console.print(table)


def check_security_issues():
    """Check for common security issues"""
    issues = []
    warnings = []
    
    # Check SECRET_KEY
    secret_key = os.getenv('SECRET_KEY', "")
    if not secret_key:
        issues.append("SECRET_KEY is not set")
    elif secret_key == 'dlnk-dlnk-secret-key-change-in-production':
        issues.append("SECRET_KEY is using default value - MUST be changed for production")
    elif len(secret_key) < 32:
        warnings.append("SECRET_KEY is too short (should be at least 32 characters)")
    
    # Check WEBSHELL_PASSWORD
    webshell_password = os.getenv('WEBSHELL_PASSWORD', 'changeme')
    if webshell_password == 'changeme':
        warnings.append("WEBSHELL_PASSWORD is using default value - should be changed")
    
    # Check DB_PASSWORD
    if not os.getenv('DB_PASSWORD', ""):
        warnings.append("DB_PASSWORD is not set - database connection may fail")
    
    # Check SIMULATION_MODE
    simulation_mode = os.getenv('SIMULATION_MODE', 'False').lower()
    if simulation_mode == 'false':
        warnings.append("SIMULATION_MODE is False - system will perform LIVE ATTACKS")
    
    return issues, warnings


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 dLNk Configuration Validation[/bold cyan]",
        border_style="cyan"
    ))
    console.print()
    
    # Check .env file
    if not check_env_file():
        console.print("\n[red]Please create and configure .env file before continuing[/red]")
        sys.exit(1)
    
    console.print()
    
    # Display configuration
    display_config()
    console.print()
    
    # Check security issues
    console.print("[bold cyan]🔐 Security Check[/bold cyan]")
    issues, warnings = check_security_issues()
    
    if issues:
        console.print("\n[bold red]❌ Critical Issues:[/bold red]")
        for issue in issues:
            console.print(f"  • {issue}")
    
    if warnings:
        console.print("\n[bold yellow]⚠️  Warnings:[/bold yellow]")
        for warning in warnings:
            console.print(f"  • {warning}")
    
    if not issues and not warnings:
        console.print("[green]✅ No security issues found[/green]")
    
    console.print()
    
    # Validate configuration
    console.print("[bold cyan]🔍 Validating Configuration...[/bold cyan]")
    try:
        validate_config()
        console.print("[green]✅ Configuration is valid[/green]")
        console.print()
        console.print(Panel.fit(
            "[bold green]✅ All checks passed! System is ready to use.[/bold green]",
            border_style="green"
        ))
        sys.exit(0)
    except ConfigError as e:
        console.print(f"[red]❌ Configuration Error:[/red]")
        console.print(f"[red]{e}[/red]")
        console.print()
        console.print(Panel.fit(
            "[bold red]❌ Configuration validation failed. Please fix the errors above.[/bold red]",
            border_style="red"
        ))
        sys.exit(1)


if __name__ == "__main__":
    main()


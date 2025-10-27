#!/usr/bin/env python3
"""
dLNk dLNk Attack Platform - Startup Script
ตรวจสอบและเตรียมระบบก่อนรัน
"""

import os
import sys
from pathlib import Path
import asyncio
from dotenv import load_dotenv

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables from .env file
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file)
    print(f"✓ Loaded environment from {env_file}")
else:
    print(f"⚠️  Warning: .env file not found at {env_file}")

from api.services.tool_verifier import get_tool_verifier
from api.services.agent_registry import init_agent_registry
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint


console = Console()


def print_banner():
    """แสดง banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║    ██████╗ ██╗     ███╗   ██╗██╗  ██╗                        ║
    ║    ██╔══██╗██║     ████╗  ██║██║ ██╔╝                        ║
    ║    ██║  ██║██║     ██╔██╗ ██║█████╔╝                         ║
    ║    ██║  ██║██║     ██║╚██╗██║██╔═██╗                         ║
    ║    ██████╔╝███████╗██║ ╚████║██║  ██╗                        ║
    ║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                        ║
    ║                                                               ║
    ║           dLNk ATTACK PLATFORM v2.0                         ║
    ║        AI-Powered Penetration Testing System                 ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold red")


def check_environment():
    """ตรวจสอบ environment variables"""
    console.print("\n[bold cyan]Checking Environment Variables...[/bold cyan]")
    
    required_vars = [
        "C2_DOMAIN"
    ]
    
    optional_vars = [
        "DATABASE_URL",
        "OLLAMA_HOST",
        "WORKSPACE_DIR",
        "LOOT_DIR",
        "NOTIFICATION_CHANNELS",
        "SMTP_HOST",
        "TELEGRAM_BOT_TOKEN",
        "DISCORD_WEBHOOK_URL"
    ]
    
    missing = []
    for var in required_vars:
        if not os.getenv(var):
            missing.append(var)
            console.print(f"  ❌ {var}: [red]Not set[/red]")
        else:
            value = os.getenv(var)
            # Hide sensitive parts
            if "PASSWORD" in var or "TOKEN" in var or "SECRET" in var:
                display_value = value[:10] + "..." if len(value) > 10 else "***"
            else:
                display_value = value
            console.print(f"  ✅ {var}: [green]{display_value}[/green]")
    
    console.print(f"\n[bold]Optional Variables:[/bold]")
    for var in optional_vars:
        value = os.getenv(var)
        if value:
            console.print(f"  ✅ {var}: [green]Set[/green]")
        else:
            console.print(f"  ⚠️  {var}: [yellow]Not set[/yellow]")
    
    if missing:
        console.print(f"\n[bold red]Missing required variables: {', '.join(missing)}[/bold red]")
        console.print("[yellow]Please set them in .env file[/yellow]")
        return False
    
    return True


def verify_tools():
    """ตรวจสอบเครื่องมือ"""
    console.print("\n[bold cyan]Verifying Tools and Dependencies...[/bold cyan]")
    
    verifier = get_tool_verifier()
    results = verifier.verify_all()
    
    # System Tools
    console.print("\n[bold]System Tools:[/bold]")
    for tool, info in results["tools"].items():
        status = "✅" if info["status"] else "❌"
        color = "green" if info["status"] else "red"
        console.print(f"  {status} {tool}: [{color}]{info['message']}[/{color}]")
    
    # Python Packages
    console.print("\n[bold]Python Packages:[/bold]")
    for package, info in results["python_packages"].items():
        status = "✅" if info["status"] else "❌"
        color = "green" if info["status"] else "red"
        version = info.get("version", "unknown")
        console.print(f"  {status} {package}: [{color}]{version}[/{color}]")
    
    # Ollama
    console.print("\n[bold]Ollama LLM:[/bold]")
    ollama = results["ollama"]
    if ollama["available"]:
        console.print(f"  ✅ Ollama: [green]Running at {ollama['host']}[/green]")
        console.print(f"  📦 Models: {', '.join(ollama['models'])}")
    else:
        console.print(f"  ❌ Ollama: [red]{ollama['error']}[/red]")
    
    # Database
    console.print("\n[bold]Database:[/bold]")
    db = results["database"]
    if db["available"]:
        console.print(f"  ✅ PostgreSQL: [green]Connected to {db['url']}[/green]")
    else:
        console.print(f"  ❌ PostgreSQL: [red]{db['error']}[/red]")
    
    # Overall Status
    console.print(f"\n[bold]Overall Status: ", end="")
    if results["overall_status"] == "healthy":
        console.print("[bold green]HEALTHY ✅[/bold green]")
    elif results["overall_status"] == "degraded":
        console.print("[bold yellow]DEGRADED ⚠️[/bold yellow]")
    else:
        console.print("[bold red]UNHEALTHY ❌[/bold red]")
    
    if results["issues"]:
        console.print("\n[bold red]Issues Found:[/bold red]")
        for issue in results["issues"]:
            console.print(f"  • {issue}")
    
    return results["overall_status"] != "unhealthy"


def initialize_agents():
    """โหลด Agents"""
    console.print("\n[bold cyan]Initializing Attack Agents...[/bold cyan]")
    
    try:
        count = init_agent_registry()
        console.print(f"  ✅ Loaded [green]{count}[/green] attack agents")
        return True
    except Exception as e:
        console.print(f"  ❌ Error loading agents: [red]{e}[/red]")
        return False


def create_directories():
    """สร้างโครงสร้างโฟลเดอร์"""
    console.print("\n[bold cyan]Creating Directory Structure...[/bold cyan]")
    
    workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
    loot_dir = os.getenv("LOOT_DIR", "workspace/loot")
    
    directories = [
        workspace_dir,
        loot_dir,
        f"{loot_dir}/exfiltrated",
        "logs",
        "reports",
        "data"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        console.print(f"  ✅ Created: [green]{directory}[/green]")
    
    return True


async def initialize_database():
    """เตรียม Database"""
    console.print("\n[bold cyan]Initializing Database...[/bold cyan]")
    
    try:
        from api.services.database import get_database
        
        db = get_database()
        await db.init_db()
        
        console.print("  ✅ Database initialized")
        
        # Create admin key if not exists
        admin_key = await db.get_or_create_admin_key()
        
        # Save admin key to file
        with open("ADMIN_KEY.txt", "w") as f:
            f.write(admin_key)
        
        console.print(f"  ✅ Admin key: [green]{admin_key}[/green]")
        console.print(f"  📄 Saved to: [green]ADMIN_KEY.txt[/green]")
        
        return True
    
    except Exception as e:
        console.print(f"  ❌ Database initialization failed: [red]{e}[/red]")
        return False


def print_summary():
    """แสดงสรุป"""
    console.print("\n" + "="*70)
    console.print("[bold green]✅ System Ready![/bold green]")
    console.print("="*70)
    
    console.print("\n[bold cyan]Next Steps:[/bold cyan]")
    console.print("  1. Start API server:")
    console.print("     [yellow]python api/main.py[/yellow]")
    console.print("\n  2. Access API at:")
    console.print("     [yellow]localhost:8000[/yellow]")
    console.print("\n  3. View API docs at:")
    console.print("     [yellow]localhost:8000/docs[/yellow]")
    console.print("\n  4. Use Admin Key from:")
    console.print("     [yellow]ADMIN_KEY.txt[/yellow]")
    
    console.print("\n[bold cyan]Important Notes:[/bold cyan]")
    console.print("  ⚠️  System is in [red]LIVE ATTACK MODE[/red]")
    console.print("  ⚠️  Only use on authorized targets")
    console.print("  ⚠️  Unauthorized use is illegal")
    
    console.print("\n" + "="*70 + "\n")


def main():
    """Main startup function"""
    print_banner()
    
    console.print("[bold]Starting dLNk dLNk Attack Platform...[/bold]\n")
    
    # Check environment
    if not check_environment():
        console.print("\n[bold red]❌ Environment check failed[/bold red]")
        console.print("[yellow]Please configure .env file and try again[/yellow]")
        sys.exit(1)
    
    # Verify tools
    if not verify_tools():
        console.print("\n[bold red]❌ Tool verification failed[/bold red]")
        console.print("[yellow]Some critical tools are missing. System may not work properly.[/yellow]")
        
        response = input("\nContinue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Create directories
    if not create_directories():
        console.print("\n[bold red]❌ Directory creation failed[/bold red]")
        sys.exit(1)
    
    # Initialize agents
    if not initialize_agents():
        console.print("\n[bold red]❌ Agent initialization failed[/bold red]")
        sys.exit(1)
    
    # Initialize database
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    if not loop.run_until_complete(initialize_database()):
        console.print("\n[bold red]❌ Database initialization failed[/bold red]")
        loop.close()
        sys.exit(1)
    
    loop.close()
    
    # Print summary
    print_summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Fatal error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


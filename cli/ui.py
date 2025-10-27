"""
UI Components สำหรับ dLNk dLNk
สไตล์ Hardcore พร้อม dLNk สีรุ้ง
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.style import Style

console = Console()


def get_rainbow_text(text: str) -> Text:
    """สร้างข้อความสีรุ้ง"""
    colors = ["red", "yellow", "green", "cyan", "blue", "magenta"]
    rainbow_text = Text()
    
    for i, char in enumerate(text):
        color = colors[i % len(colors)]
        rainbow_text.append(char, style=color)
    
    return rainbow_text


def print_logo():
    """แสดงโลโก้ dLNk dLNk สไตล์ Hardcore"""
    
    logo = r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║    ██████╗ ██╗     ███╗   ██╗██╗  ██╗                        ║
    ║    ██╔══██╗██║     ████╗  ██║██║ ██╔╝                        ║
    ║    ██║  ██║██║     ██╔██╗ ██║█████╔╝                         ║
    ║    ██║  ██║██║     ██║╚██╗██║██╔═██╗                         ║
    ║    ██████╔╝███████╗██║ ╚████║██║  ██╗                        ║
    ║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                        ║
    ║                                                               ║
    ║         ADVANCED PENETRATION ATTACK PLATFORM                 ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    
    # แสดงโลโก้สีแดงเข้ม (Hardcore style)
    console.print(logo, style="bold red")
    
    # แสดง dLNk สีรุ้ง
    dLNk_text = get_rainbow_text("dLNk")
    subtitle = Text()
    subtitle.append("                    Powered by ", style="dim white")
    subtitle.append(dLNk_text)
    subtitle.append(" Framework", style="dim white")
    
    console.print(subtitle)
    console.print()
    
    # แสดงคำเตือน
    warning = Panel(
        "[bold yellow]⚠️  WARNING ⚠️[/bold yellow]\n\n"
        "[red]This is an OFFENSIVE SECURITY FRAMEWORK[/red]\n"
        "[red]For AUTHORIZED PENETRATION TESTING ONLY[/red]\n\n"
        "[dim]Unauthorized access to computer systems is illegal.[/dim]",
        border_style="bold red",
        title="[bold red]⚡ LEGAL NOTICE ⚡[/bold red]"
    )
    console.print(warning)
    console.print()


def print_dLNk_header():
    """แสดง dLNk header สีรุ้งแบบเล็ก"""
    dLNk_text = get_rainbow_text("dLNk")
    header = Text()
    header.append("[", style="dim white")
    header.append(dLNk_text)
    header.append("]", style="dim white")
    console.print(header, end=" ")


def print_phase_banner(phase_name: str, phase_number: int = None):
    """แสดง Banner สำหรับแต่ละ Phase"""
    
    if phase_number:
        title = f"Phase {phase_number}: {phase_name}"
    else:
        title = phase_name
    
    banner = Panel(
        f"[bold red]{title}[/bold red]",
        border_style="bold red",
        padding=(1, 2)
    )
    
    console.print()
    print_dLNk_header()
    console.print(banner)
    console.print()


def print_success(message: str):
    """แสดงข้อความสำเร็จ"""
    print_dLNk_header()
    console.print(f"[bold green]✅ {message}[/bold green]")


def print_error(message: str):
    """แสดงข้อความผิดพลาด"""
    print_dLNk_header()
    console.print(f"[bold red]❌ {message}[/bold red]")


def print_warning(message: str):
    """แสดงคำเตือน"""
    print_dLNk_header()
    console.print(f"[bold yellow]⚠️  {message}[/bold yellow]")


def print_info(message: str):
    """แสดงข้อมูล"""
    print_dLNk_header()
    console.print(f"[cyan]{message}[/cyan]")


def print_attack_menu():
    """แสดงเมนูโจมตีหลัก"""
    
    menu = """
[bold red]╔════════════════════════════════════════╗[/bold red]
[bold red]║[/bold red]     [bold white]ATTACK OPERATIONS MENU[/bold white]        [bold red]║[/bold red]
[bold red]╠════════════════════════════════════════╣[/bold red]
[bold red]║[/bold red]                                        [bold red]║[/bold red]
[bold red]║[/bold red]  [bold cyan]1.[/bold cyan] [white]Scan Target[/white]                     [bold red]║[/bold red]
[bold red]║[/bold red]     [dim]สแกนหาช่องโหว่ในเป้าหมาย[/dim]          [bold red]║[/bold red]
[bold red]║[/bold red]                                        [bold red]║[/bold red]
[bold red]║[/bold red]  [bold cyan]2.[/bold cyan] [white]Exploit Vulnerabilities[/white]         [bold red]║[/bold red]
[bold red]║[/bold red]     [dim]ใช้ประโยชน์จากช่องโหว่[/dim]            [bold red]║[/bold red]
[bold red]║[/bold red]                                        [bold red]║[/bold red]
[bold red]║[/bold red]  [bold cyan]3.[/bold cyan] [white]Post-Exploitation[/white]               [bold red]║[/bold red]
[bold red]║[/bold red]     [dim]Shell, Privesc, Backdoor, Dump[/dim]   [bold red]║[/bold red]
[bold red]║[/bold red]                                        [bold red]║[/bold red]
[bold red]║[/bold red]  [bold cyan]4.[/bold cyan] [white]Full Auto Attack[/white]                [bold red]║[/bold red]
[bold red]║[/bold red]     [dim]โจมตีอัตโนมัติ 100%[/dim]               [bold red]║[/bold red]
[bold red]║[/bold red]                                        [bold red]║[/bold red]
[bold red]║[/bold red]  [bold cyan]0.[/bold cyan] [white]Exit[/white]                            [bold red]║[/bold red]
[bold red]║[/bold red]                                        [bold red]║[/bold red]
[bold red]╚════════════════════════════════════════╝[/bold red]
    """
    
    print_dLNk_header()
    console.print(menu)


def print_vulnerability_summary(vulns: list):
    """แสดงสรุปช่องโหว่ที่พบ"""
    
    from rich.table import Table
    
    table = Table(title="🎯 ช่องโหว่ที่พบ", border_style="red")
    table.add_column("ประเภท", style="cyan", no_wrap=True)
    table.add_column("ความรุนแรง", style="yellow")
    table.add_column("จำนวน", justify="right", style="white")
    
    # จัดกลุ่มช่องโหว่
    vuln_groups = {}
    for vuln in vulns:
        vuln_type = vuln.get("type", "Unknown")
        severity = vuln.get("severity", "Unknown")
        key = (vuln_type, severity)
        
        if key not in vuln_groups:
            vuln_groups[key] = 0
        vuln_groups[key] += 1
    
    # เพิ่มข้อมูลในตาราง
    for (vuln_type, severity), count in vuln_groups.items():
        # เลือกสีตามความรุนแรง
        if severity == "Critical":
            severity_text = f"[bold red]{severity}[/bold red]"
        elif severity == "High":
            severity_text = f"[red]{severity}[/red]"
        elif severity == "Medium":
            severity_text = f"[yellow]{severity}[/yellow]"
        else:
            severity_text = f"[green]{severity}[/green]"
        
        table.add_row(vuln_type, severity_text, str(count))
    
    print_dLNk_header()
    console.print(table)


def print_exploit_result(vuln_type: str, success: bool, details: str = ""):
    """แสดงผลลัพธ์การใช้ประโยชน์"""
    
    if success:
        print_dLNk_header()
        console.print(f"[bold green]💥 {vuln_type}: SUCCESS[/bold green]")
        if details:
            console.print(f"   [dim]{details}[/dim]")
    else:
        print_dLNk_header()
        console.print(f"[bold red]❌ {vuln_type}: FAILED[/bold red]")
        if details:
            console.print(f"   [dim]{details}[/dim]")


def print_shell_banner():
    """แสดง Banner เมื่อได้ Shell"""
    
    shell_art = """
[bold green]
    ╔═══════════════════════════════════════╗
    ║                                       ║
    ║     🐚  SHELL ACQUIRED  🐚            ║
    ║                                       ║
    ║   [bold white]Access Granted to Target System[/bold white]   ║
    ║                                       ║
    ╚═══════════════════════════════════════╝
[/bold green]
    """
    
    print_dLNk_header()
    console.print(shell_art)


def print_progress_bar(current: int, total: int, description: str = ""):
    """แสดง Progress Bar แบบง่าย"""
    
    percentage = (current / total) * 100 if total > 0 else 0
    bar_length = 40
    filled = int(bar_length * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_length - filled)
    
    print_dLNk_header()
    console.print(f"[cyan]{description}[/cyan] [{bar}] {percentage:.1f}%")


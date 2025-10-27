"""
CLI commands for License Management
"""

import click
from rich.console import Console
from rich.table import Table
from datetime import datetime

from core.license_manager import get_license_manager
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


@click.group(name='license')
def license_group():
    """จัดการ License Key"""
    pass


@license_group.command(name='generate')
@click.option('--hours', type=int, help='จำนวนชั่วโมงที่ใช้ได้')
@click.option('--days', type=int, help='จำนวนวันที่ใช้ได้')
@click.option('--months', type=int, help='จำนวนเดือนที่ใช้ได้')
@click.option('--uses', type=int, default=1, help='จำนวนครั้งที่ใช้ได้ (default: 1)')
@click.option('--user', type=str, help='ชื่อผู้ใช้')
def generate_license(hours, days, months, uses, user):
    """สร้าง License Key ใหม่"""
    
    if not any([hours, days, months]):
        console.print("[red]❌ กรุณาระบุระยะเวลา (--hours, --days, หรือ --months)[/red]")
        return
    
    lm = get_license_manager()
    
    user_info = {"username": user} if user else None
    
    license_key = lm.generate_license_key(
        duration_hours=hours,
        duration_days=days,
        duration_months=months,
        max_uses=uses,
        user_info=user_info
    )
    
    console.print("\n[bold green]✅ สร้าง License Key สำเร็จ![/bold green]\n")
    console.print(f"[bold cyan]License Key:[/bold cyan]")
    console.print(f"[yellow]{license_key}[/yellow]\n")
    
    # แสดงรายละเอียด
    table = Table(title="รายละเอียด License")
    table.add_column("รายการ", style="cyan")
    table.add_column("ค่า", style="yellow")
    
    if hours:
        table.add_row("ระยะเวลา", f"{hours} ชั่วโมง")
    elif days:
        table.add_row("ระยะเวลา", f"{days} วัน")
    elif months:
        table.add_row("ระยะเวลา", f"{months} เดือน")
    
    table.add_row("จำนวนครั้งที่ใช้ได้", str(uses))
    if user:
        table.add_row("ผู้ใช้", user)
    
    console.print(table)
    console.print("\n[bold yellow]⚠️  กรุณาเก็บ License Key นี้ไว้อย่างปลอดภัย[/bold yellow]\n")


@license_group.command(name='activate')
@click.argument('license_key')
def activate_license(license_key):
    """เปิดใช้งาน License Key"""
    
    lm = get_license_manager()
    
    console.print("\n[cyan]🔑 กำลังเปิดใช้งาน License...[/cyan]")
    
    success, message = lm.activate_license(license_key)
    
    if success:
        console.print(f"\n[bold green]{message}[/bold green]\n")
    else:
        console.print(f"\n[bold red]{message}[/bold red]\n")


@license_group.command(name='info')
def license_info():
    """แสดงข้อมูล License ปัจจุบัน"""
    
    lm = get_license_manager()
    info = lm.get_license_info()
    
    if not info:
        console.print("\n[yellow]⚠️  ไม่พบ License ที่เปิดใช้งาน[/yellow]\n")
        console.print("[cyan]💡 ใช้คำสั่ง 'dlnk-dlnk license activate <KEY>' เพื่อเปิดใช้งาน License[/cyan]\n")
        return
    
    table = Table(title="ข้อมูล License ปัจจุบัน")
    table.add_column("รายการ", style="cyan")
    table.add_column("ค่า", style="yellow")
    
    table.add_row("Machine ID", info.get("machine_id", "N/A")[:32] + "...")
    
    if "activated_at" in info:
        activated = datetime.fromisoformat(info["activated_at"])
        table.add_row("เปิดใช้งานเมื่อ", activated.strftime("%Y-%m-%d %H:%M:%S"))
    
    if "expires_at" in info:
        expiry = datetime.fromisoformat(info["expires_at"])
        table.add_row("หมดอายุ", expiry.strftime("%Y-%m-%d %H:%M:%S"))
        
        remaining = expiry - datetime.now()
        if remaining.total_seconds() > 0:
            days = remaining.days
            hours = remaining.seconds // 3600
            table.add_row("เวลาคงเหลือ", f"{days} วัน {hours} ชั่วโมง")
        else:
            table.add_row("สถานะ", "[red]หมดอายุแล้ว[/red]")
    
    uses = info.get("uses", 0)
    max_uses = info.get("max_uses", 1)
    table.add_row("การใช้งาน", f"{uses}/{max_uses} ครั้ง")
    
    if lm.is_terminal_locked():
        table.add_row("Terminal Lock", "[green]✅ Locked[/green]")
    else:
        table.add_row("Terminal Lock", "[yellow]⚠️  Not Locked[/yellow]")
    
    console.print("\n")
    console.print(table)
    console.print("\n")


@license_group.command(name='revoke')
@click.confirmation_option(prompt='คุณแน่ใจหรือไม่ที่จะยกเลิก License?')
def revoke_license():
    """ยกเลิก License ปัจจุบัน"""
    
    lm = get_license_manager()
    lm.revoke_license()
    
    console.print("\n[bold green]✅ ยกเลิก License สำเร็จ[/bold green]\n")


@license_group.command(name='unlock')
def unlock_terminal():
    """ปลด Terminal Lock (ใช้เมื่อต้องการย้าย terminal)"""
    
    lm = get_license_manager()
    
    if not lm.is_terminal_locked():
        console.print("\n[yellow]⚠️  Terminal ไม่ได้ถูก Lock[/yellow]\n")
        return
    
    lm.unlock_terminal()
    console.print("\n[bold green]✅ ปลด Terminal Lock สำเร็จ[/bold green]\n")


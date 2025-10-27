"""
Attack CLI - ระบบโจมตีแบบ 3 ขั้นตอน
1. Scan - สแกนหาช่องโหว่
2. Exploit - ใช้ประโยชน์จากช่องโหว่
3. Post-Exploit - ดำเนินการหลังการโจมตี (Shell, Privilege Escalation, Backdoor, Data Dump)
"""

import asyncio
import click
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime

from core.orchestrator import Orchestrator
from core.license_manager import get_license_manager
from core.logger import get_logger
from core.data_models import Target

console = Console()
log = get_logger(__name__)


def check_license():
    """ตรวจสอบ License ก่อนใช้งาน"""
    lm = get_license_manager()
    info = lm.get_license_info()
    
    if not info:
        console.print("\n[bold red]❌ ไม่พบ License[/bold red]")
        console.print("[yellow]กรุณาเปิดใช้งาน License ก่อน: dlnk-dlnk license activate <KEY>[/yellow]\n")
        return False
    
    # ตรวจสอบ License
    license_key = info.get("key")
    is_valid, message = lm.validate_license(license_key)
    
    if not is_valid:
        console.print(f"\n[bold red]{message}[/bold red]\n")
        return False
    
    return True


@click.group(name='attack')
def attack_group():
    """ระบบโจมตีและใช้ประโยชน์จากช่องโหว่"""
    pass


@attack_group.command(name='scan')
@click.option('--target', '-t', required=True, help='เป้าหมายที่จะโจมตี (URL หรือ IP)')
@click.option('--output', '-o', help='ไฟล์สำหรับบันทึกผลลัพธ์')
@click.option('--aggressive', '-a', is_flag=True, help='โหมดโจมตีแบบรุนแรง')
def scan_target(target, output, aggressive):
    """
    ขั้นตอนที่ 1: สแกนหาช่องโหว่
    
    ระบบจะทำการ:
    - สแกนพอร์ตและบริการ
    - ตรวจสอบเทคโนโลยีที่ใช้
    - ตรวจจับ WAF
    - สแกนหาช่องโหว่ทั่วไป (SQL Injection, XSS, SSRF, IDOR, etc.)
    - รวบรวมข้อมูลและจัดหมวดหมู่ช่องโหว่
    """
    
    if not check_license():
        return
    
    console.print(Panel.fit(
        f"[bold red]🎯 เริ่มโจมตีเป้าหมาย: {target}[/bold red]",
        border_style="red"
    ))
    
    # สร้าง Orchestrator
    orchestrator = Orchestrator()
    
    async def run_scan():
        try:
            await orchestrator.initialize()
            
            # สร้าง Target
            target_model = Target(
                name=f"Attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                url=target,
                attack_mode=True,
                aggressive=aggressive
            )
            
            # โหลด Workflow สำหรับ Scan
            workflow_path = Path("config/attack_scan_workflow.yaml")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[red]กำลังสแกนหาช่องโหว่...", total=None)
                
                results = await orchestrator.execute_workflow(
                    workflow_path=str(workflow_path),
                    target=target_model
                )
                
                progress.update(task, completed=True)
            
            # แสดงผลลัพธ์
            display_scan_results(results, target)
            
            # บันทึกผลลัพธ์
            if output:
                save_results(results, output)
                console.print(f"\n[green]✅ บันทึกผลลัพธ์ไว้ที่: {output}[/green]")
            
            # บันทึกไว้ใน workspace สำหรับขั้นตอนถัดไป
            workspace_dir = Path("workspace")
            workspace_dir.mkdir(exist_ok=True)
            
            scan_file = workspace_dir / f"scan_{target.replace('://', '_').replace('/', '_')}.json"
            save_results(results, str(scan_file))
            
            console.print(f"\n[cyan]💾 บันทึก Scan Results ไว้ที่: {scan_file}[/cyan]")
            console.print(f"[yellow]📌 ใช้คำสั่งนี้เพื่อใช้ประโยชน์จากช่องโหว่: dlnk-dlnk attack exploit --scan-file {scan_file}[/yellow]\n")
            
        finally:
            await orchestrator.cleanup()
    
    asyncio.run(run_scan())


@attack_group.command(name='exploit')
@click.option('--scan-file', '-s', required=True, help='ไฟล์ผลลัพธ์จากการ Scan')
@click.option('--vuln-type', '-v', help='ประเภทช่องโหว่ที่ต้องการใช้ประโยชน์ (ถ้าไม่ระบุจะใช้ทั้งหมด)')
@click.option('--output', '-o', help='ไฟล์สำหรับบันทึกผลลัพธ์')
@click.option('--callback-url', '-c', help='URL สำหรับรับ callback (สำหรับ XSS, SSRF)')
def exploit_vulnerabilities(scan_file, vuln_type, output, callback_url):
    """
    ขั้นตอนที่ 2: ใช้ประโยชน์จากช่องโหว่
    
    ระบบจะทำการ:
    - วิเคราะห์ช่องโหว่ที่พบจากการ Scan
    - เลือกและสร้าง Payload ที่เหมาะสม
    - ใช้ประโยชน์จากช่องโหว่แต่ละประเภท
    - พยายามได้ RCE หรือ Shell
    - บันทึกผลลัพธ์การโจมตี
    """
    
    if not check_license():
        return
    
    # โหลดผลลัพธ์จากการ Scan
    if not Path(scan_file).exists():
        console.print(f"\n[bold red]❌ ไม่พบไฟล์: {scan_file}[/bold red]\n")
        return
    
    with open(scan_file, 'r') as f:
        scan_results = json.load(f)
    
    console.print(Panel.fit(
        f"[bold red]💥 เริ่มใช้ประโยชน์จากช่องโหว่[/bold red]",
        border_style="red"
    ))
    
    # แสดงช่องโหว่ที่พบ
    display_vulnerabilities(scan_results)
    
    # ถามผู้ใช้ว่าต้องการใช้ประโยชน์จากช่องโหว่ไหน
    if not vuln_type:
        console.print("\n[yellow]📋 เลือกช่องโหว่ที่ต้องการใช้ประโยชน์:[/yellow]")
        console.print("[cyan]  1. SQL Injection[/cyan]")
        console.print("[cyan]  2. XSS (Cross-Site Scripting)[/cyan]")
        console.print("[cyan]  3. RCE (Remote Code Execution)[/cyan]")
        console.print("[cyan]  4. SSRF (Server-Side Request Forgery)[/cyan]")
        console.print("[cyan]  5. IDOR (Insecure Direct Object Reference)[/cyan]")
        console.print("[cyan]  6. File Upload[/cyan]")
        console.print("[cyan]  7. ทั้งหมด (Auto)[/cyan]")
        
        choice = click.prompt("\nเลือก", type=int, default=7)
        
        vuln_map = {
            1: "sql_injection",
            2: "xss",
            3: "rce",
            4: "ssrf",
            5: "idor",
            6: "file_upload",
            7: "all"
        }
        
        vuln_type = vuln_map.get(choice, "all")
    
    # สร้าง Orchestrator
    orchestrator = Orchestrator()
    
    async def run_exploit():
        try:
            await orchestrator.initialize()
            
            # โหลด Workflow สำหรับ Exploit
            workflow_path = Path("config/attack_exploit_workflow.yaml")
            
            # สร้าง Target จากผลลัพธ์ Scan
            target_url = scan_results.get("target", "")
            target_model = Target(
                name=f"Exploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                url=target_url,
                attack_mode=True,
                vuln_type=vuln_type,
                callback_url=callback_url,
                scan_results=scan_results
            )
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[red]กำลังใช้ประโยชน์จากช่องโหว่...", total=None)
                
                results = await orchestrator.execute_workflow(
                    workflow_path=str(workflow_path),
                    target=target_model
                )
                
                progress.update(task, completed=True)
            
            # แสดงผลลัพธ์
            display_exploit_results(results)
            
            # บันทึกผลลัพธ์
            if output:
                save_results(results, output)
                console.print(f"\n[green]✅ บันทึกผลลัพธ์ไว้ที่: {output}[/green]")
            
            # บันทึกไว้ใน workspace สำหรับขั้นตอนถัดไป
            workspace_dir = Path("workspace")
            exploit_file = workspace_dir / f"exploit_{target_url.replace('://', '_').replace('/', '_')}.json"
            save_results(results, str(exploit_file))
            
            console.print(f"\n[cyan]💾 บันทึก Exploit Results ไว้ที่: {exploit_file}[/cyan]")
            
            # ตรวจสอบว่าได้ Shell หรือไม่
            if has_shell(results):
                console.print(f"\n[bold green]🎉 ได้ Shell แล้ว! ใช้คำสั่งนี้เพื่อดำเนินการต่อ:[/bold green]")
                console.print(f"[yellow]dlnk-dlnk attack post-exploit --exploit-file {exploit_file}[/yellow]\n")
            else:
                console.print(f"\n[yellow]⚠️  ยังไม่ได้ Shell แต่สามารถดำเนินการ Post-Exploit ได้:[/yellow]")
                console.print(f"[cyan]dlnk-dlnk attack post-exploit --exploit-file {exploit_file}[/cyan]\n")
            
        finally:
            await orchestrator.cleanup()
    
    asyncio.run(run_exploit())


@attack_group.command(name='post-exploit')
@click.option('--exploit-file', '-e', required=True, help='ไฟล์ผลลัพธ์จากการ Exploit')
@click.option('--action', '-a', help='การดำเนินการ (shell, privesc, backdoor, dump)')
@click.option('--output-dir', '-o', help='โฟลเดอร์สำหรับบันทึกข้อมูลที่ Dump')
def post_exploitation(exploit_file, action, output_dir):
    """
    ขั้นตอนที่ 3: ดำเนินการหลังการโจมตี
    
    ระบบจะทำการ:
    - รับ Shell และยกระดับเป็น Interactive Shell
    - ยกระดับสิทธิ์ (Privilege Escalation)
    - สร้าง Backdoor เพื่อเข้าถึงในอนาคต
    - Dump ข้อมูลสำคัญ (Database, Files, Credentials)
    - ส่งข้อมูลกลับมายังเครื่องผู้โจมตี
    """
    
    if not check_license():
        return
    
    # โหลดผลลัพธ์จากการ Exploit
    if not Path(exploit_file).exists():
        console.print(f"\n[bold red]❌ ไม่พบไฟล์: {exploit_file}[/bold red]\n")
        return
    
    with open(exploit_file, 'r') as f:
        exploit_results = json.load(f)
    
    console.print(Panel.fit(
        f"[bold red]🔥 เริ่ม Post-Exploitation[/bold red]",
        border_style="red"
    ))
    
    # ถามผู้ใช้ว่าต้องการทำอะไร
    if not action:
        console.print("\n[yellow]📋 เลือกการดำเนินการ:[/yellow]")
        console.print("[cyan]  1. รับ Shell และ Upgrade[/cyan]")
        console.print("[cyan]  2. ยกระดับสิทธิ์ (Privilege Escalation)[/cyan]")
        console.print("[cyan]  3. สร้าง Backdoor[/cyan]")
        console.print("[cyan]  4. Dump ข้อมูล (Database, Files)[/cyan]")
        console.print("[cyan]  5. ทั้งหมด (Auto)[/cyan]")
        
        choice = click.prompt("\nเลือก", type=int, default=5)
        
        action_map = {
            1: "shell",
            2: "privesc",
            3: "backdoor",
            4: "dump",
            5: "all"
        }
        
        action = action_map.get(choice, "all")
    
    # กำหนด output directory
    if not output_dir:
        output_dir = Path("workspace/loot")
        output_dir.mkdir(parents=True, exist_ok=True)
    
    # สร้าง Orchestrator
    orchestrator = Orchestrator()
    
    async def run_post_exploit():
        try:
            await orchestrator.initialize()
            
            # โหลด Workflow สำหรับ Post-Exploit
            workflow_path = Path("config/attack_post_exploit_workflow.yaml")
            
            # สร้าง Target จากผลลัพธ์ Exploit
            target_url = exploit_results.get("target", "")
            target_model = Target(
                name=f"PostExploit_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                url=target_url,
                attack_mode=True,
                post_exploit_action=action,
                output_dir=str(output_dir),
                exploit_results=exploit_results
            )
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[red]กำลังดำเนินการ Post-Exploitation...", total=None)
                
                results = await orchestrator.execute_workflow(
                    workflow_path=str(workflow_path),
                    target=target_model
                )
                
                progress.update(task, completed=True)
            
            # แสดงผลลัพธ์
            display_post_exploit_results(results, output_dir)
            
            console.print(f"\n[bold green]✅ Post-Exploitation เสร็จสมบูรณ์![/bold green]\n")
            
        finally:
            await orchestrator.cleanup()
    
    asyncio.run(run_post_exploit())


def display_scan_results(results, target):
    """แสดงผลลัพธ์การ Scan"""
    console.print(f"\n[bold green]✅ สแกนเสร็จสมบูรณ์![/bold green]\n")
    
    # สร้างตารางแสดงช่องโหว่
    table = Table(title=f"ช่องโหว่ที่พบใน {target}")
    table.add_column("ประเภท", style="cyan")
    table.add_column("ความรุนแรง", style="yellow")
    table.add_column("รายละเอียด", style="white")
    
    for result in results:
        if result.get("vulnerabilities"):
            for vuln in result["vulnerabilities"]:
                table.add_row(
                    vuln.get("type", "Unknown"),
                    vuln.get("severity", "Unknown"),
                    vuln.get("description", "")[:50] + "..."
                )
    
    console.print(table)


def display_vulnerabilities(scan_results):
    """แสดงช่องโหว่ที่พบจากการ Scan"""
    console.print("\n[bold yellow]📊 ช่องโหว่ที่พบ:[/bold yellow]\n")
    
    vulns = scan_results.get("vulnerabilities", [])
    
    if not vulns:
        console.print("[red]ไม่พบช่องโหว่[/red]\n")
        return
    
    for i, vuln in enumerate(vulns, 1):
        console.print(f"[cyan]{i}. {vuln.get('type', 'Unknown')}[/cyan] - {vuln.get('severity', 'Unknown')}")


def display_exploit_results(results):
    """แสดงผลลัพธ์การใช้ประโยชน์"""
    console.print(f"\n[bold green]✅ ใช้ประโยชน์จากช่องโหว่เสร็จสมบูรณ์![/bold green]\n")
    
    table = Table(title="ผลลัพธ์การโจมตี")
    table.add_column("ช่องโหว่", style="cyan")
    table.add_column("สถานะ", style="yellow")
    table.add_column("ผลลัพธ์", style="white")
    
    for result in results:
        if result.get("exploited"):
            table.add_row(
                result.get("vuln_type", "Unknown"),
                "[green]✅ สำเร็จ[/green]",
                result.get("result", "")[:50] + "..."
            )
        else:
            table.add_row(
                result.get("vuln_type", "Unknown"),
                "[red]❌ ล้มเหลว[/red]",
                result.get("error", "")[:50] + "..."
            )
    
    console.print(table)


def display_post_exploit_results(results, output_dir):
    """แสดงผลลัพธ์ Post-Exploitation"""
    console.print(f"\n[bold green]📦 ผลลัพธ์ Post-Exploitation:[/bold green]\n")
    
    table = Table(title="สิ่งที่ได้รับ")
    table.add_column("ประเภท", style="cyan")
    table.add_column("รายละเอียด", style="white")
    
    for result in results:
        if result.get("shell"):
            table.add_row("🐚 Shell", result["shell"].get("type", "Unknown"))
        
        if result.get("privesc"):
            table.add_row("👑 Privilege", result["privesc"].get("level", "Unknown"))
        
        if result.get("backdoor"):
            table.add_row("🚪 Backdoor", result["backdoor"].get("method", "Unknown"))
        
        if result.get("data_dump"):
            table.add_row("💾 Data Dump", f"{len(result['data_dump'])} files")
    
    console.print(table)
    console.print(f"\n[cyan]📁 ข้อมูลที่ Dump บันทึกไว้ที่: {output_dir}[/cyan]\n")


def save_results(results, output_file):
    """บันทึกผลลัพธ์เป็นไฟล์ JSON"""
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def has_shell(results):
    """ตรวจสอบว่าได้ Shell หรือไม่"""
    for result in results:
        if result.get("shell") or result.get("rce"):
            return True
    return False


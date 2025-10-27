#!/usr/bin/env python3
"""
dLNk Attack Platform - Command Line Interface
Full-featured CLI for managing attacks, campaigns, and agents
"""

import click
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()


class DLNKClient:
    """dLNk API Client"""
    
    def __init__(self, base_url: str = "http://localhost:8000", api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key or self._load_api_key()
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
    
    def _load_api_key(self) -> str:
        """Load API key from config"""
        config_file = Path.home() / ".dlnk" / "config.json"
        
        if config_file.exists():
            with open(config_file) as f:
                config = json.load(f)
                return config.get("api_key", "")
        
        return ""
    
    def _save_api_key(self, api_key: str):
        """Save API key to config"""
        config_dir = Path.home() / ".dlnk"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "config.json"
        config = {"api_key": api_key, "base_url": self.base_url}
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def get(self, endpoint: str):
        """GET request"""
        response = requests.get(f"{self.base_url}{endpoint}", headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def post(self, endpoint: str, data: dict):
        """POST request"""
        response = requests.post(f"{self.base_url}{endpoint}", headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def delete(self, endpoint: str):
        """DELETE request"""
        response = requests.delete(f"{self.base_url}{endpoint}", headers=self.headers)
        response.raise_for_status()
        return response.json()


@click.group()
@click.option('--api-key', envvar='DLNK_API_KEY', help='API Key for authentication')
@click.option('--base-url', default='http://localhost:8000', help='Base URL of dLNk API')
@click.pass_context
def cli(ctx, api_key, base_url):
    """dLNk Attack Platform CLI - เครื่องมือโจมตีอัตโนมัติ"""
    ctx.ensure_object(dict)
    ctx.obj['client'] = DLNKClient(base_url, api_key)


@cli.group()
def config():
    """จัดการการตั้งค่า"""
    pass


@config.command()
@click.argument('api_key')
@click.pass_context
def set_api_key(ctx, api_key):
    """ตั้งค่า API Key"""
    client = ctx.obj['client']
    client._save_api_key(api_key)
    console.print("[green]✓[/green] API Key saved successfully")


@cli.group()
def target():
    """จัดการเป้าหมาย (Targets)"""
    pass


@target.command('add')
@click.option('--name', required=True, help='ชื่อเป้าหมาย')
@click.option('--url', required=True, help='URL เป้าหมาย')
@click.option('--description', help='รายละเอียด')
@click.pass_context
def target_add(ctx, name, url, description):
    """เพิ่มเป้าหมายใหม่"""
    client = ctx.obj['client']
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("กำลังเพิ่มเป้าหมาย...", total=None)
        
        data = {
            "name": name,
            "url": url,
            "description": description or ""
        }
        
        result = client.post("/api/targets", data)
        progress.stop()
    
    console.print(f"[green]✓[/green] เพิ่มเป้าหมายสำเร็จ: {result['target_id']}")


@target.command('list')
@click.pass_context
def target_list(ctx):
    """แสดงรายการเป้าหมายทั้งหมด"""
    client = ctx.obj['client']
    
    targets = client.get("/api/targets")
    
    table = Table(title="เป้าหมายทั้งหมด")
    table.add_column("ID", style="cyan")
    table.add_column("ชื่อ", style="magenta")
    table.add_column("URL", style="green")
    table.add_column("สถานะ", style="yellow")
    
    for target in targets:
        table.add_row(
            target['id'],
            target['name'],
            target['url'],
            target.get('status', 'active')
        )
    
    console.print(table)


@target.command('delete')
@click.argument('target_id')
@click.pass_context
def target_delete(ctx, target_id):
    """ลบเป้าหมาย"""
    client = ctx.obj['client']
    
    if click.confirm(f'คุณแน่ใจหรือไม่ที่จะลบเป้าหมาย {target_id}?'):
        client.delete(f"/api/targets/{target_id}")
        console.print(f"[green]✓[/green] ลบเป้าหมายสำเร็จ")


@cli.group()
def campaign():
    """จัดการแคมเปญโจมตี (Campaigns)"""
    pass


@campaign.command('create')
@click.option('--target', required=True, help='Target ID')
@click.option('--name', required=True, help='ชื่อแคมเปญ')
@click.option('--type', type=click.Choice(['reconnaissance', 'vulnerability_scan', 'exploitation', 'full']), default='full', help='ประเภทการโจมตี')
@click.pass_context
def campaign_create(ctx, target, name, type):
    """สร้างแคมเปญโจมตีใหม่"""
    client = ctx.obj['client']
    
    data = {
        "target_id": target,
        "name": name,
        "attack_type": type
    }
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("กำลังสร้างแคมเปญ...", total=None)
        result = client.post("/api/campaigns", data)
        progress.stop()
    
    console.print(f"[green]✓[/green] สร้างแคมเปญสำเร็จ: {result['campaign_id']}")


@campaign.command('start')
@click.argument('campaign_id')
@click.pass_context
def campaign_start(ctx, campaign_id):
    """เริ่มแคมเปญโจมตี"""
    client = ctx.obj['client']
    
    console.print(f"[yellow]⚡[/yellow] กำลังเริ่มแคมเปญ {campaign_id}...")
    
    result = client.post(f"/api/campaigns/{campaign_id}/start", {})
    
    console.print(f"[green]✓[/green] เริ่มแคมเปญสำเร็จ")
    console.print(f"สถานะ: {result.get('status', 'running')}")


@campaign.command('status')
@click.argument('campaign_id')
@click.pass_context
def campaign_status(ctx, campaign_id):
    """ตรวจสอบสถานะแคมเปญ"""
    client = ctx.obj['client']
    
    status = client.get(f"/api/campaigns/{campaign_id}/status")
    
    table = Table(title=f"สถานะแคมเปญ {campaign_id}")
    table.add_column("รายการ", style="cyan")
    table.add_column("ค่า", style="green")
    
    table.add_row("สถานะ", status.get('status', 'unknown'))
    table.add_row("ความคืบหน้า", f"{status.get('progress', 0):.1f}%")
    table.add_row("งานที่เสร็จ", str(status.get('completed_tasks', 0)))
    table.add_row("งานทั้งหมด", str(status.get('total_tasks', 0)))
    table.add_row("ช่องโหว่ที่พบ", str(status.get('vulnerabilities_found', 0)))
    
    console.print(table)


@campaign.command('list')
@click.pass_context
def campaign_list(ctx):
    """แสดงรายการแคมเปญทั้งหมด"""
    client = ctx.obj['client']
    
    campaigns = client.get("/api/campaigns")
    
    table = Table(title="แคมเปญทั้งหมด")
    table.add_column("ID", style="cyan")
    table.add_column("ชื่อ", style="magenta")
    table.add_column("เป้าหมาย", style="green")
    table.add_column("สถานะ", style="yellow")
    table.add_column("ความคืบหน้า", style="blue")
    
    for camp in campaigns:
        table.add_row(
            camp['id'],
            camp['name'],
            camp.get('target_name', 'N/A'),
            camp.get('status', 'unknown'),
            f"{camp.get('progress', 0):.1f}%"
        )
    
    console.print(table)


@campaign.command('stop')
@click.argument('campaign_id')
@click.pass_context
def campaign_stop(ctx, campaign_id):
    """หยุดแคมเปญ"""
    client = ctx.obj['client']
    
    if click.confirm(f'คุณแน่ใจหรือไม่ที่จะหยุดแคมเปญ {campaign_id}?'):
        client.post(f"/api/campaigns/{campaign_id}/stop", {})
        console.print(f"[green]✓[/green] หยุดแคมเปญสำเร็จ")


@cli.group()
def agent():
    """จัดการ Agents"""
    pass


@agent.command('list')
@click.pass_context
def agent_list(ctx):
    """แสดงรายการ Agents ทั้งหมด"""
    client = ctx.obj['client']
    
    agents = client.get("/api/agents")
    
    table = Table(title="Attack Agents")
    table.add_column("ชื่อ", style="cyan")
    table.add_column("ประเภท", style="magenta")
    table.add_column("สถานะ", style="green")
    table.add_column("ความสามารถ", style="yellow")
    
    for ag in agents:
        table.add_row(
            ag['name'],
            ag.get('type', 'unknown'),
            ag.get('status', 'ready'),
            ', '.join(ag.get('capabilities', []))[:50]
        )
    
    console.print(table)


@agent.command('execute')
@click.option('--name', required=True, help='ชื่อ Agent')
@click.option('--target', required=True, help='Target URL')
@click.pass_context
def agent_execute(ctx, name, target):
    """รัน Agent เดี่ยว"""
    client = ctx.obj['client']
    
    data = {
        "agent_name": name,
        "target_url": target
    }
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task(f"กำลังรัน {name}...", total=None)
        result = client.post("/api/agents/execute", data)
        progress.stop()
    
    console.print(f"[green]✓[/green] รัน Agent สำเร็จ")
    console.print(f"ผลลัพธ์: {result.get('summary', 'N/A')}")


@cli.group()
def report():
    """จัดการรายงาน"""
    pass


@report.command('generate')
@click.argument('campaign_id')
@click.option('--format', type=click.Choice(['json', 'pdf', 'html']), default='json', help='รูปแบบรายงาน')
@click.option('--output', help='ไฟล์ output')
@click.pass_context
def report_generate(ctx, campaign_id, format, output):
    """สร้างรายงานแคมเปญ"""
    client = ctx.obj['client']
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("กำลังสร้างรายงาน...", total=None)
        
        result = client.post(f"/api/campaigns/{campaign_id}/report", {"format": format})
        
        progress.stop()
    
    if output:
        with open(output, 'w') as f:
            if format == 'json':
                json.dump(result, f, indent=2)
            else:
                f.write(result.get('content', ''))
        
        console.print(f"[green]✓[/green] บันทึกรายงานที่: {output}")
    else:
        console.print(json.dumps(result, indent=2))


@cli.command()
@click.pass_context
def status(ctx):
    """ตรวจสอบสถานะระบบ"""
    client = ctx.obj['client']
    
    try:
        health = client.get("/health")
        
        table = Table(title="สถานะระบบ dLNk")
        table.add_column("รายการ", style="cyan")
        table.add_column("ค่า", style="green")
        
        table.add_row("สถานะ", "🟢 Online" if health.get('status') == 'healthy' else "🔴 Offline")
        table.add_row("Database", "✓ Connected" if health.get('database') else "✗ Disconnected")
        table.add_row("Agents", str(health.get('agents_count', 0)))
        table.add_row("Active Campaigns", str(health.get('active_campaigns', 0)))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]✗[/red] ไม่สามารถเชื่อมต่อกับ API: {e}")


@cli.command()
@click.option('--target', required=True, help='Target URL')
@click.option('--type', type=click.Choice(['quick', 'full', 'stealth']), default='quick', help='ประเภทการโจมตี')
@click.pass_context
def attack(ctx, target, type):
    """เริ่มการโจมตีอย่างรวดเร็ว"""
    client = ctx.obj['client']
    
    console.print(f"[yellow]⚡[/yellow] กำลังโจมตี {target}...")
    console.print(f"ประเภท: {type}")
    
    # Create target
    target_data = {"name": f"Quick Attack - {target}", "url": target}
    target_result = client.post("/api/targets", target_data)
    target_id = target_result['target_id']
    
    # Create campaign
    campaign_data = {
        "target_id": target_id,
        "name": f"Quick {type} attack",
        "attack_type": type
    }
    campaign_result = client.post("/api/campaigns", campaign_data)
    campaign_id = campaign_result['campaign_id']
    
    # Start campaign
    client.post(f"/api/campaigns/{campaign_id}/start", {})
    
    console.print(f"[green]✓[/green] เริ่มการโจมตีสำเร็จ")
    console.print(f"Campaign ID: {campaign_id}")
    console.print(f"\nใช้คำสั่ง: dlnk campaign status {campaign_id} เพื่อดูสถานะ")


if __name__ == '__main__':
    cli(obj={})


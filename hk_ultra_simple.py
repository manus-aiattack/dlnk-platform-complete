#!/usr/bin/env python3.11
"""
HK - Hacker Knowledge CLI
Ultra simple version - just print questions and wait for Manus to answer
"""

import sys
import json
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
except ImportError:
    import os
    os.system("pip3 install -q rich >&2")
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt


class HK:
    def __init__(self):
        self.console = Console()
        self.history_dir = Path.home() / '.hk_history'
        self.history_dir.mkdir(exist_ok=True)
        self.history_file = self.history_dir / 'conversation.json'
        self.history = []
        self._load_history()
    
    def _load_history(self):
        """โหลดประวัติ"""
        try:
            if self.history_file.exists():
                data = json.loads(self.history_file.read_text(encoding='utf-8'))
                self.history = data.get('messages', [])[-50:]
        except:
            pass
    
    def _save_history(self):
        """บันทึกประวัติ"""
        try:
            self.history_file.write_text(json.dumps({
                'timestamp': datetime.now().isoformat(),
                'messages': self.history
            }, ensure_ascii=False, indent=2), encoding='utf-8')
        except:
            pass
    
    def banner(self):
        """แสดง banner"""
        self.console.print("""
╔═══════════════════════════════════════════════════════════╗
║   ██████╗ ██╗     ███╗   ██╗██╗  ██╗                    ║
║   ██╔══██╗██║     ████╗  ██║██║ ██╔╝                    ║
║   ██║  ██║██║     ██╔██╗ ██║█████╔╝                     ║
║   ██║  ██║██║     ██║╚██╗██║██╔═██╗                     ║
║   ██████╔╝███████╗██║ ╚████║██║  ██╗                    ║
║   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                    ║
║                                                           ║
║   HK - Hacker Knowledge                                  ║
║   Powered by Manus AI                                    ║
╚═══════════════════════════════════════════════════════════╝
""", style="bold cyan")
        
        if self.history:
            self.console.print(f"[dim]โหลดประวัติ {len(self.history)} ข้อความ[/dim]\n")
    
    def run(self):
        """Main loop"""
        self.banner()
        
        while True:
            try:
                # รับคำถาม
                question = Prompt.ask("\n[bold green]You[/bold green]").strip()
                
                if not question:
                    continue
                
                # คำสั่งพิเศษ
                if question.lower() in ['exit', 'quit', 'q']:
                    self.console.print("\n[cyan]👋 ขอบคุณที่ใช้งาน![/cyan]\n")
                    break
                
                elif question.lower() == 'clear':
                    self.history = []
                    self._save_history()
                    import os
                    os.system('clear')
                    self.banner()
                    continue
                
                elif question.lower() == 'history':
                    self.console.print("\n[cyan]ประวัติ 10 ข้อความล่าสุด:[/cyan]\n")
                    for msg in self.history[-10:]:
                        role = "You" if msg['role'] == 'user' else "Manus"
                        content = msg['content'][:80] + "..." if len(msg['content']) > 80 else msg['content']
                        self.console.print(f"[dim]{role}:[/dim] {content}")
                    continue
                
                elif question.lower() == 'help':
                    self.console.print(Panel("""
**คำสั่ง:**
- exit/quit/q - ออก
- clear - ล้างประวัติ
- history - ดูประวัติ
- help - ความช่วยเหลือ

**การใช้งาน:**
พิมพ์คำถามอะไรก็ได้ Manus จะตอบ
""", title="Help", border_style="cyan"))
                    continue
                
                # บันทึกคำถาม
                self.history.append({
                    'role': 'user',
                    'content': question,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                
                # แสดงคำถามให้ Manus เห็น (ใน terminal output)
                self.console.print(f"\n[yellow]📤 Question:[/yellow] {question}")
                self.console.print("[dim]Waiting for Manus...[/dim]\n")
                
                # รอคำตอบจาก Manus (ผ่าน stdin)
                self.console.print("[cyan]🤖 Manus AI:[/cyan]")
                
                # อ่านคำตอบ (Manus จะพิมพ์เข้ามาทาง stdin)
                # ในกรณีนี้ Manus จะต้องตอบผ่าน terminal โดยตรง
                # หรือใช้วิธี redirect
                
                # สำหรับ demo: ให้ user พิมพ์คำตอบเอง (simulate Manus)
                # ในการใช้งานจริง Manus จะ inject คำตอบเข้ามาอัตโนมัติ
                
                self.console.print("[dim](Manus will answer here automatically)[/dim]")
                self.console.print("[yellow]For now, type answer manually (or press Enter to skip):[/yellow]")
                
                answer = input().strip()
                
                if answer:
                    # บันทึกคำตอบ
                    self.history.append({
                        'role': 'assistant',
                        'content': answer,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
                    # แสดงคำตอบ
                    try:
                        self.console.print(Markdown(answer))
                    except:
                        self.console.print(answer)
                    
                    # บันทึกประวัติ
                    self._save_history()
                
            except KeyboardInterrupt:
                self.console.print("\n\n[cyan]👋 ขอบคุณที่ใช้งาน![/cyan]\n")
                break
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    hk = HK()
    hk.run()


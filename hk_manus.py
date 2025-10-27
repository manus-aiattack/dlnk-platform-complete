#!/usr/bin/env python3.11
"""
dLNk Attack Platform - HK CLI with Manus Integration
Command: hk
Interactive AI assistant powered by Manus (no external API needed)
"""

import sys
import os
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

# Add project to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.syntax import Syntax
except ImportError:
    print("Installing required packages...")
    os.system("pip3 install -q rich")
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.syntax import Syntax


class ManusAIAssistant:
    """AI Assistant powered by Manus (sandbox-only)"""
    
    def __init__(self):
        self.console = Console()
        self.working_dir = Path.cwd()
        
        # History
        self.history_dir = Path.home() / '.hk_history'
        self.history_dir.mkdir(exist_ok=True)
        self.history_file = self.history_dir / 'conversation.json'
        self.conversation_history = []
        
        # Load previous history
        self._load_history()
        
        # Session file for communication with Manus
        self.session_dir = Path('/tmp/hk_session')
        self.session_dir.mkdir(exist_ok=True)
        self.request_file = self.session_dir / 'request.txt'
        self.response_file = self.session_dir / 'response.txt'
    
    def show_banner(self):
        """Show welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ██╗     ███╗   ██╗██╗  ██╗                    ║
║   ██╔══██╗██║     ████╗  ██║██║ ██╔╝                    ║
║   ██║  ██║██║     ██╔██╗ ██║█████╔╝                     ║
║   ██║  ██║██║     ██║╚██╗██║██╔═██╗                     ║
║   ██████╔╝███████╗██║ ╚████║██║  ██╗                    ║
║   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                    ║
║                                                           ║
║   HK - Hacker Knowledge                                  ║
║   Powered by Manus AI (Sandbox Edition)                  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

💬 คุยเรื่องอะไรก็ได้ | 📝 สร้างและแก้ไขไฟล์ | ⚡ รันคำสั่ง

พิมพ์ 'exit' เพื่อออก | 'help' สำหรับความช่วยเหลือ
"""
        self.console.print(banner, style="bold cyan")
        
        if self.conversation_history:
            self.console.print(f"[dim]โหลดประวัติการสนทนา {len(self.conversation_history)} ข้อความ[/dim]\n")
    
    def show_help(self):
        """Show help"""
        help_text = """
**คำสั่งพิเศษ:**

- `exit`, `quit`, `q` - ออกจากโปรแกรม
- `clear` - ล้างประวัติการสนทนา
- `history` - แสดงประวัติการสนทนา
- `export` - ส่งออกประวัติเป็น Markdown
- `help` - แสดงความช่วยเหลือ

**ตัวอย่างการใช้งาน:**

- "สรุปภาพรวมโปรเจค dLNk"
- "สร้างไฟล์ test.py"
- "แก้ไข config.json"
- "ตรวจสอบสถานะระบบ"
- "วิธีใช้งาน C2"
- "สร้าง reverse shell payload"
"""
        self.console.print(Panel(Markdown(help_text), title="Help", border_style="green"))
    
    def _load_history(self):
        """Load conversation history"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.conversation_history = data.get('messages', [])[-20:]
        except Exception as e:
            pass
    
    def _save_history(self):
        """Save conversation history"""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'messages': self.conversation_history
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            pass
    
    def export_history(self):
        """Export history to markdown"""
        try:
            export_file = self.history_dir / f'export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
            
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write(f"# HK Conversation History\n\n")
                f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("---\n\n")
                
                for msg in self.conversation_history:
                    role = msg['role']
                    content = msg['content']
                    
                    if role == 'user':
                        f.write(f"## 👤 You\n\n{content}\n\n")
                    elif role == 'assistant':
                        f.write(f"## 🤖 Manus AI\n\n{content}\n\n")
                    
                    f.write("---\n\n")
            
            self.console.print(f"[green]✓ ส่งออกประวัติไปยัง: {export_file}[/green]")
            return str(export_file)
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return None
    
    def show_history(self, limit=10):
        """Show recent history"""
        if not self.conversation_history:
            self.console.print("[yellow]ไม่มีประวัติการสนทนา[/yellow]")
            return
        
        self.console.print(f"\n[bold cyan]ประวัติการสนทนา (ล่าสุด {limit} ข้อความ)[/bold cyan]\n")
        
        recent = self.conversation_history[-limit:]
        for i, msg in enumerate(recent, 1):
            role = "👤 You" if msg['role'] == 'user' else "🤖 Manus"
            content = msg['content'][:100] + "..." if len(msg['content']) > 100 else msg['content']
            self.console.print(f"{i}. {role}: {content}")
        
        self.console.print()
    
    def chat(self, user_message: str):
        """Send message to Manus AI"""
        # Save user message
        self.conversation_history.append({
            "role": "user",
            "content": user_message,
            "timestamp": datetime.now().isoformat()
        })
        
        # Write request
        self.request_file.write_text(json.dumps({
            "message": user_message,
            "history": self.conversation_history[-10:],  # Last 10 messages for context
            "working_dir": str(self.working_dir),
            "timestamp": datetime.now().isoformat()
        }, ensure_ascii=False, indent=2), encoding='utf-8')
        
        # Show instruction to user
        self.console.print("\n[bold yellow]📝 กรุณาตอบคำถามนี้ในหน้าต่าง Manus:[/bold yellow]")
        self.console.print(f"[cyan]{user_message}[/cyan]\n")
        
        self.console.print("[dim]คำตอบจะถูกบันทึกอัตโนมัติ...[/dim]")
        self.console.print(f"[dim]Request file: {self.request_file}[/dim]")
        self.console.print(f"[dim]Response file: {self.response_file}[/dim]\n")
        
        # Wait for response
        self.console.print("[yellow]⏳ รอคำตอบจาก Manus AI...[/yellow]")
        self.console.print("[dim](กด Ctrl+C เพื่อยกเลิก)[/dim]\n")
        
        try:
            # Wait for response file
            import time
            timeout = 300  # 5 minutes
            start_time = time.time()
            
            while not self.response_file.exists():
                if time.time() - start_time > timeout:
                    self.console.print("[red]✗ Timeout: ไม่ได้รับคำตอบภายใน 5 นาที[/red]")
                    return None
                time.sleep(1)
            
            # Read response
            response_data = json.loads(self.response_file.read_text(encoding='utf-8'))
            response_text = response_data.get('response', '')
            
            # Save to history
            self.conversation_history.append({
                "role": "assistant",
                "content": response_text,
                "timestamp": datetime.now().isoformat()
            })
            
            self._save_history()
            
            # Clean up
            self.response_file.unlink()
            
            return response_text
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]ยกเลิกการรอคำตอบ[/yellow]")
            return None
        except Exception as e:
            self.console.print(f"[red]✗ Error: {e}[/red]")
            return None
    
    def execute_command(self, command: str) -> bool:
        """Execute special commands"""
        cmd = command.strip().lower()
        
        if cmd in ['exit', 'quit', 'q']:
            self.console.print("\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/bold cyan]\n")
            return False
        
        elif cmd == 'clear':
            self.conversation_history = []
            self._save_history()
            os.system('clear' if os.name != 'nt' else 'cls')
            self.show_banner()
            self.console.print("[green]✓ ล้างประวัติการสนทนาแล้ว[/green]\n")
            return True
        
        elif cmd == 'help':
            self.show_help()
            return True
        
        elif cmd == 'history':
            self.show_history()
            return True
        
        elif cmd == 'export':
            self.export_history()
            return True
        
        return None
    
    def run(self):
        """Main loop"""
        # Set UTF-8 encoding
        if hasattr(sys.stdin, 'reconfigure'):
            sys.stdin.reconfigure(encoding='utf-8', errors='ignore')
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='ignore')
        
        self.show_banner()
        
        # Show instructions
        self.console.print("[bold green]🎯 วิธีใช้งาน:[/bold green]")
        self.console.print("1. พิมพ์คำถามหรือคำสั่งที่นี่")
        self.console.print("2. ระบบจะแสดงคำถามให้คุณตอบในหน้าต่าง Manus")
        self.console.print("3. คำตอบจะถูกบันทึกและแสดงอัตโนมัติ\n")
        
        while True:
            try:
                # Get user input
                user_input = Prompt.ask("\n[bold green]You[/bold green]").strip()
                
                if not user_input:
                    continue
                
                # Clean input
                user_input = user_input.encode('utf-8', errors='ignore').decode('utf-8')
                
                # Check for special commands
                cmd_result = self.execute_command(user_input)
                if cmd_result is False:
                    break
                elif cmd_result is True:
                    continue
                
                # Send to Manus AI
                response = self.chat(user_input)
                
                if response:
                    self.console.print("\n[bold cyan]🤖 Manus AI:[/bold cyan]")
                    try:
                        self.console.print(Markdown(response))
                    except Exception:
                        self.console.print(response)
                
            except KeyboardInterrupt:
                self.console.print("\n\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/bold cyan]\n")
                break
            except Exception as e:
                import traceback
                self.console.print(f"\n[red]❌ Error: {e}[/red]")
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main():
    """Main entry point"""
    assistant = ManusAIAssistant()
    assistant.run()


if __name__ == "__main__":
    main()


#!/usr/bin/env python3.11
"""
dLNk Attack Platform - HK CLI (Simple Version)
Command: hk
Interactive conversation logger - answers provided by Manus AI directly
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Add project to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
except ImportError:
    print("Installing required packages...")
    os.system("pip3 install -q rich")
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax


class SimpleAIAssistant:
    """Simple AI Assistant - logs conversations"""
    
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
║   Conversation Logger for Manus AI                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

💬 พิมพ์คำถาม → คัดลอกไปถาม Manus → วางคำตอบกลับมา

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

**วิธีใช้งาน:**

1. พิมพ์คำถามของคุณ
2. คัดลอกคำถามไปถาม Manus AI ในหน้าต่างหลัก
3. คัดลอกคำตอบกลับมาวางที่นี่
4. ระบบจะบันทึกการสนทนาอัตโนมัติ

**ตัวอย่าง:**

```
You: สรุปภาพรวมโปรเจค dLNk
[คัดลอกไปถาม Manus]

Manus Answer (paste here): [วางคำตอบ]
```
"""
        self.console.print(Panel(Markdown(help_text), title="Help", border_style="green"))
    
    def _load_history(self):
        """Load conversation history"""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.conversation_history = data.get('messages', [])[-50:]
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
                    timestamp = msg.get('timestamp', '')
                    
                    if role == 'user':
                        f.write(f"## 👤 You\n\n")
                        if timestamp:
                            f.write(f"*{timestamp}*\n\n")
                        f.write(f"{content}\n\n")
                    elif role == 'assistant':
                        f.write(f"## 🤖 Manus AI\n\n")
                        if timestamp:
                            f.write(f"*{timestamp}*\n\n")
                        f.write(f"{content}\n\n")
                    
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
        
        recent = self.conversation_history[-limit*2:]  # x2 because user+assistant pairs
        for i in range(0, len(recent), 2):
            if i < len(recent):
                user_msg = recent[i]
                self.console.print(f"\n[bold green]You:[/bold green] {user_msg['content'][:100]}...")
                
                if i+1 < len(recent):
                    ai_msg = recent[i+1]
                    self.console.print(f"[bold cyan]Manus:[/bold cyan] {ai_msg['content'][:100]}...")
        
        self.console.print()
    
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
        
        while True:
            try:
                # Get user question
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
                
                # Save user message
                self.conversation_history.append({
                    "role": "user",
                    "content": user_input,
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                
                # Show instruction
                self.console.print("\n[yellow]📋 คัดลอกคำถามนี้ไปถาม Manus AI:[/yellow]")
                self.console.print(Panel(user_input, border_style="yellow"))
                
                # Get answer from user (paste from Manus)
                self.console.print("\n[cyan]📥 วางคำตอบจาก Manus AI ที่นี่:[/cyan]")
                self.console.print("[dim](กด Enter 2 ครั้งเพื่อจบ หรือพิมพ์ 'skip' เพื่อข้าม)[/dim]\n")
                
                answer_lines = []
                empty_count = 0
                
                while True:
                    try:
                        line = input()
                        
                        if line.strip().lower() == 'skip':
                            answer_lines = []
                            break
                        
                        if not line.strip():
                            empty_count += 1
                            if empty_count >= 2:
                                break
                        else:
                            empty_count = 0
                            answer_lines.append(line)
                    except EOFError:
                        break
                
                if answer_lines:
                    answer = '\n'.join(answer_lines).strip()
                    
                    # Save assistant message
                    self.conversation_history.append({
                        "role": "assistant",
                        "content": answer,
                        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
                    # Save history
                    self._save_history()
                    
                    # Display answer
                    self.console.print("\n[bold cyan]🤖 Manus AI:[/bold cyan]")
                    try:
                        self.console.print(Markdown(answer))
                    except Exception:
                        self.console.print(answer)
                    
                    self.console.print("\n[green]✓ บันทึกการสนทนาแล้ว[/green]")
                else:
                    self.console.print("[yellow]⊘ ข้ามคำตอบ[/yellow]")
                
            except KeyboardInterrupt:
                self.console.print("\n\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/bold cyan]\n")
                break
            except Exception as e:
                import traceback
                self.console.print(f"\n[red]❌ Error: {e}[/red]")
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")


def main():
    """Main entry point"""
    assistant = SimpleAIAssistant()
    assistant.run()


if __name__ == "__main__":
    main()


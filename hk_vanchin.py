#!/usr/bin/env python3
"""
HK - Hacker Knowledge CLI with Vanchin AI
"""

import os
import sys
import json
import requests
from datetime import datetime
from rich.console import Console
from rich.markdown import Markdown

console = Console()

class HK:
    def __init__(self):
        self.api_key = os.getenv("VC_API_KEY", "jjMoD5XYaClAwYlfMUzllfWucvd3NPZy67F3Ax4IT-c")
        self.base_url = "https://vanchin.streamlake.ai/api/gateway/v1/endpoints"
        self.model = "ep-rtt0hh-1761571039145129553"
        self.history_file = os.path.expanduser("~/.hk_history/conversation.json")
        self.conversation_history = []
        
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        self.load_history()
        
        console.print("[bold cyan]╔═══════════════════════════════════════════════════════════╗[/]")
        console.print("[bold cyan]║   dLNk - Hacker Knowledge (Powered by Vanchin AI)       ║[/]")
        console.print("[bold cyan]╚═══════════════════════════════════════════════════════════╝[/]")
        console.print()
    
    def load_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    data = json.load(f)
                    self.conversation_history = data.get("messages", [])[-20:]
                console.print(f"[dim]โหลดประวัติการสนทนา {len(self.conversation_history)} ข้อความ[/]")
            except:
                pass
    
    def save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump({"messages": self.conversation_history}, f, indent=2)
        except:
            pass
    
    def chat(self, user_message):
        self.conversation_history.append({"role": "user", "content": user_message})
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": self.conversation_history,
                "max_tokens": 2000,
                "temperature": 0.7
            }
            
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            data = response.json()
            assistant_message = data["choices"][0]["message"]["content"]
            
            self.conversation_history.append({"role": "assistant", "content": assistant_message})
            self.save_history()
            
            return assistant_message
            
        except Exception as e:
            return f"❌ Error: {e}"
    
    def run(self):
        console.print("[dim]พิมพ์คำถามหรือคำสั่งของคุณ[/]")
        console.print("[dim]พิมพ์ 'exit' หรือ 'quit' เพื่อออก[/]")
        console.print()
        
        while True:
            try:
                user_input = console.input("\n[bold green]You:[/] ")
                
                if not user_input.strip():
                    continue
                
                if user_input.lower() in ['exit', 'quit', 'q']:
                    console.print("\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/]")
                    break
                
                if user_input.lower() == 'clear':
                    self.conversation_history = []
                    self.save_history()
                    console.print("[dim]ล้างประวัติการสนทนาแล้ว[/]")
                    continue
                
                if user_input.lower() == 'history':
                    console.print(f"\n[bold]ประวัติการสนทนา ({len(self.conversation_history)} ข้อความ):[/]")
                    for msg in self.conversation_history[-10:]:
                        role = msg.get("role", "unknown")
                        content = msg.get("content", "")[:100]
                        console.print(f"[dim]{role}:[/] {content}...")
                    continue
                
                console.print("\n[bold blue]🤖 Vanchin AI:[/]")
                response = self.chat(user_input)
                
                try:
                    md = Markdown(response)
                    console.print(md)
                except:
                    console.print(response)
                
            except KeyboardInterrupt:
                console.print("\n\n[bold cyan]👋 ขอบคุณที่ใช้งาน![/]")
                break
            except Exception as e:
                console.print(f"\n[bold red]❌ Error: {e}[/]")

if __name__ == "__main__":
    hk = HK()
    hk.run()

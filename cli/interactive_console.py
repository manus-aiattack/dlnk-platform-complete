"""
Interactive Console for dLNk Attack Platform
คล้าย Metasploit Console
"""

import asyncio
import sys
import os
from typing import Dict, List, Optional
from datetime import datetime

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter, NestedCompleter
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.styles import Style
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    print("[!] prompt_toolkit not installed. Install with: pip install prompt_toolkit")

from core.logger import log
from api.services.database import Database
from api.services.attack_manager import AttackManager


class DLNkConsole:
    """
    Interactive console like Metasploit
    
    Commands:
    - use <agent>: Select agent to use
    - set <option> <value>: Set option value
    - show <info>: Show information (agents, options, attacks)
    - run: Run selected agent
    - search <query>: Search agents
    - back: Go back to main context
    - help: Show help
    - exit: Exit console
    """
    
    def __init__(self, db: Database, attack_manager: AttackManager):
        """
        Initialize console
        
        Args:
            db: Database instance
            attack_manager: AttackManager instance
        """
        self.db = db
        self.attack_manager = attack_manager
        
        self.current_agent = None
        self.options = {}
        self.agents_list = []
        
        # Setup prompt toolkit
        if PROMPT_TOOLKIT_AVAILABLE:
            self.style = Style.from_dict({
                'prompt': '#00ff00 bold',
                'agent': '#ff0000 bold',
            })
            
            self.completer = self._create_completer()
            self.session = PromptSession(
                completer=self.completer,
                history=FileHistory(os.path.expanduser('~/.dlnk_history')),
                style=self.style
            )
        else:
            self.session = None
    
    def _create_completer(self):
        """Create command completer"""
        
        commands = {
            'use': None,
            'set': None,
            'show': WordCompleter(['agents', 'options', 'attacks', 'targets']),
            'run': None,
            'search': None,
            'back': None,
            'help': None,
            'exit': None,
            'clear': None,
        }
        
        return NestedCompleter.from_nested_dict(commands)
    
    def banner(self) -> str:
        """Return console banner"""
        
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║      ██████╗ ██╗     ███╗   ██╗██╗  ██╗                      ║
║      ██╔══██╗██║     ████╗  ██║██║ ██╔╝                      ║
║      ██║  ██║██║     ██╔██╗ ██║█████╔╝                       ║
║      ██║  ██║██║     ██║╚██╗██║██╔═██╗                       ║
║      ██████╔╝███████╗██║ ╚████║██║  ██╗                      ║
║      ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                      ║
║                                                               ║
║           Advanced Attack Platform Console                   ║
║                    Version 1.0.0                             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Type 'help' for available commands
Type 'show agents' to list all available agents
Type 'exit' to quit

"""
        return banner
    
    async def run(self):
        """Main console loop"""
        
        if not PROMPT_TOOLKIT_AVAILABLE:
            print("[!] prompt_toolkit not available. Using basic input.")
        
        print(self.banner())
        
        # Load agents list
        await self._load_agents()
        
        while True:
            try:
                # Get prompt
                if self.current_agent:
                    prompt_text = [
                        ('class:agent', f'dLNk'),
                        ('', '('),
                        ('class:prompt', self.current_agent),
                        ('', ') > '),
                    ]
                else:
                    prompt_text = [
                        ('class:prompt', 'dLNk'),
                        ('', ' > '),
                    ]
                
                # Get input
                if self.session:
                    command = await self.session.prompt_async(prompt_text)
                else:
                    if self.current_agent:
                        command = input(f"dLNk({self.current_agent}) > ")
                    else:
                        command = input("dLNk > ")
                
                # Execute command
                await self.execute_command(command.strip())
                
            except KeyboardInterrupt:
                print("\n[!] Use 'exit' to quit")
                continue
            except EOFError:
                break
            except Exception as e:
                log.error(f"[Console] Error: {e}")
                print(f"[!] Error: {e}")
    
    async def execute_command(self, command: str):
        """
        Execute console command
        
        Args:
            command: Command string
        """
        if not command:
            return
        
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Command routing
        if cmd == 'help':
            self.show_help()
        
        elif cmd == 'use':
            if args:
                await self.use_agent(' '.join(args))
            else:
                print("[!] Usage: use <agent_name>")
        
        elif cmd == 'set':
            if len(args) >= 2:
                self.set_option(args[0], ' '.join(args[1:]))
            else:
                print("[!] Usage: set <option> <value>")
        
        elif cmd == 'show':
            if args:
                await self.show_info(args[0])
            else:
                print("[!] Usage: show <agents|options|attacks|targets>")
        
        elif cmd == 'run':
            await self.run_agent()
        
        elif cmd == 'search':
            if args:
                self.search_agents(' '.join(args))
            else:
                print("[!] Usage: search <query>")
        
        elif cmd == 'back':
            self.back()
        
        elif cmd == 'clear':
            os.system('clear' if os.name != 'nt' else 'cls')
        
        elif cmd == 'exit' or cmd == 'quit':
            print("[*] Exiting...")
            sys.exit(0)
        
        else:
            print(f"[!] Unknown command: {cmd}")
            print("[*] Type 'help' for available commands")
    
    async def _load_agents(self):
        """Load available agents from database"""
        try:
            # This would query the database for available agents
            # For now, we'll use a hardcoded list
            self.agents_list = [
                'sql_injection',
                'xss_hunter',
                'auth_bypass',
                'zero_day_hunter',
                'directory_traversal',
                'command_injection',
                'xxe_injection',
                'ssrf_hunter',
            ]
            
            log.info(f"[Console] Loaded {len(self.agents_list)} agents")
        
        except Exception as e:
            log.error(f"[Console] Failed to load agents: {e}")
    
    async def use_agent(self, agent_name: str):
        """
        Select agent to use
        
        Args:
            agent_name: Agent name
        """
        # Check if agent exists
        if agent_name not in self.agents_list:
            print(f"[!] Agent '{agent_name}' not found")
            print("[*] Use 'show agents' to list available agents")
            return
        
        self.current_agent = agent_name
        self.options = {
            'target_url': '',
            'timeout': '300',
            'threads': '10',
        }
        
        print(f"[+] Using agent: {agent_name}")
        print("[*] Use 'show options' to see required options")
    
    def set_option(self, option: str, value: str):
        """
        Set option value
        
        Args:
            option: Option name
            value: Option value
        """
        if not self.current_agent:
            print("[!] No agent selected. Use 'use <agent>' first.")
            return
        
        self.options[option.lower()] = value
        print(f"[+] {option} => {value}")
    
    async def show_info(self, info_type: str):
        """
        Show information
        
        Args:
            info_type: Type of information (agents, options, attacks, targets)
        """
        if info_type == 'agents':
            print("\n[*] Available Agents:\n")
            print(f"{'Name':<30} {'Description':<50}")
            print("=" * 80)
            
            for agent in self.agents_list:
                desc = f"Agent for {agent.replace('_', ' ')}"
                print(f"{agent:<30} {desc:<50}")
            
            print(f"\n[*] Total: {len(self.agents_list)} agents\n")
        
        elif info_type == 'options':
            if not self.current_agent:
                print("[!] No agent selected")
                return
            
            print(f"\n[*] Options for {self.current_agent}:\n")
            print(f"{'Option':<20} {'Value':<30} {'Required':<10}")
            print("=" * 60)
            
            for option, value in self.options.items():
                required = "yes" if option == "target_url" else "no"
                print(f"{option:<20} {value:<30} {required:<10}")
            
            print()
        
        elif info_type == 'attacks':
            print("\n[*] Recent Attacks:\n")
            # Query database for recent attacks
            print("[*] Feature coming soon...\n")
        
        elif info_type == 'targets':
            print("\n[*] Saved Targets:\n")
            # Query database for saved targets
            print("[*] Feature coming soon...\n")
        
        else:
            print(f"[!] Unknown info type: {info_type}")
    
    async def run_agent(self):
        """Run selected agent"""
        
        if not self.current_agent:
            print("[!] No agent selected. Use 'use <agent>' first.")
            return
        
        # Validate required options
        if not self.options.get('target_url'):
            print("[!] Required option 'target_url' not set")
            return
        
        print(f"[*] Running {self.current_agent}...")
        print(f"[*] Target: {self.options['target_url']}")
        
        try:
            # Start attack
            result = await self.attack_manager.start_attack(
                target_url=self.options['target_url'],
                attack_type=self.current_agent,
                agents=[self.current_agent],
                options=self.options
            )
            
            attack_id = result.get('attack_id')
            
            print(f"[+] Attack started: {attack_id}")
            print(f"[*] Use 'show attacks' to monitor progress")
        
        except Exception as e:
            log.error(f"[Console] Failed to run agent: {e}")
            print(f"[!] Failed to start attack: {e}")
    
    def search_agents(self, query: str):
        """
        Search agents by name or description
        
        Args:
            query: Search query
        """
        print(f"\n[*] Searching for: {query}\n")
        
        results = [agent for agent in self.agents_list if query.lower() in agent.lower()]
        
        if results:
            print(f"{'Name':<30} {'Description':<50}")
            print("=" * 80)
            
            for agent in results:
                desc = f"Agent for {agent.replace('_', ' ')}"
                print(f"{agent:<30} {desc:<50}")
            
            print(f"\n[*] Found {len(results)} agents\n")
        else:
            print("[!] No agents found\n")
    
    def back(self):
        """Go back to main context"""
        
        if self.current_agent:
            print(f"[*] Leaving {self.current_agent}")
            self.current_agent = None
            self.options = {}
        else:
            print("[!] Already at main context")
    
    def show_help(self):
        """Show help message"""
        
        help_text = """
[*] Available Commands:

    use <agent>              - Select an agent to use
    set <option> <value>     - Set an option value
    show <info>              - Show information
                               agents   - List all agents
                               options  - Show current options
                               attacks  - Show recent attacks
                               targets  - Show saved targets
    run                      - Run the selected agent
    search <query>           - Search for agents
    back                     - Return to main context
    clear                    - Clear screen
    help                     - Show this help message
    exit                     - Exit console

[*] Example Usage:

    dLNk > use sql_injection
    dLNk(sql_injection) > set target_url https://localhost:8000
    dLNk(sql_injection) > set threads 20
    dLNk(sql_injection) > show options
    dLNk(sql_injection) > run
    dLNk(sql_injection) > back
    dLNk > exit

"""
        print(help_text)


async def main():
    """Main entry point"""
    
    # Initialize database and attack manager
    # (In production, these would be properly initialized)
    db = None
    attack_manager = None
    
    console = DLNkConsole(db, attack_manager)
    await console.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)


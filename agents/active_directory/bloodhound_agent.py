"""
BloodHound Agent - Map Active Directory attack paths
Uses BloodHound.py and SharpHound (free tools)
"""

import asyncio
import os
import json
import logging
from typing import Dict, Any, List
from core.base_agent import BaseAgent
from core.agent_data import AgentData

log = logging.getLogger(__name__)


class BloodHoundAgent(BaseAgent):
    """
    BloodHound data collection and attack path analysis agent
    
    Collects:
    - Domain users, groups, computers
    - ACLs and permissions
    - Group memberships
    - Session information
    - Trust relationships
    
    Analyzes:
    - Shortest paths to Domain Admin
    - Kerberoastable users
    - AS-REP Roastable users
    - Unconstrained delegation
    - High-value targets
    """
    
    def __init__(self):
        super().__init__(
            name="BloodHoundAgent",
            description="Collect and analyze AD attack paths using BloodHound",
            version="1.0.0"
        )
        self.output_dir = "workspace/bloodhound"
        os.makedirs(self.output_dir, exist_ok=True)
        self.timeout = 600  # 10 minutes for full collection
    
    async def run(self, strategy: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            strategy: {
                "action": "collect" or "analyze",
                "domain": "example.com",
                "username": "user",
                "password": "pass",
                "dc_ip": "10.0.0.1" (optional),
                "collection_method": "All", "DCOnly", "Session", etc. (default: All),
                "target_user": "admin" (for analysis)
            }
        """
        try:
            action = strategy.get('action', 'collect')
            domain = strategy.get('domain')
            username = strategy.get('username')
            password = strategy.get('password')
            
            if not all([domain, username, password]):
                return AgentData(success=False, errors=["Missing credentials: domain, username, password required"])
            
            if action == "collect":
                result = await self.collect_data(domain, username, password, strategy)
            elif action == "analyze":
                result = await self.analyze_attack_paths(domain, strategy)
            elif action == "auto":
                # Collect then analyze
                collect_result = await self.collect_data(domain, username, password, strategy)
                if collect_result.get("success"):
                    analyze_result = await self.analyze_attack_paths(domain, strategy)
                    result = {
                        "success": True,
                        "collection": collect_result,
                        "analysis": analyze_result
                    }
                else:
                    result = collect_result
            else:
                return AgentData(success=False, errors=[f"Unknown action: {action}"])
            
            return AgentData(
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[BloodHound] Error: {e}")
            return AgentData(success=False, errors=[str(e)])
    
    async def collect_data(
        self,
        domain: str,
        username: str,
        password: str,
        strategy: Dict
    ) -> Dict:
        """
        Collect BloodHound data using bloodhound-python
        
        Args:
            collection_method: All, DCOnly, Session, LoggedOn, Trusts, ACL, etc.
        """
        
        dc_ip = strategy.get('dc_ip')
        collection_method = strategy.get('collection_method', 'All')
        
        log.info(f"[BloodHound] Collecting data from {domain} using method: {collection_method}")
        
        cmd = [
            'bloodhound-python',
            '-d', domain,
            '-u', username,
            '-p', password,
            '-c', collection_method,
            '--zip'
        ]
        
        if dc_ip:
            cmd.extend(['-dc', dc_ip])
        
        # Add nameserver if provided
        if dc_ip:
            cmd.extend(['-ns', dc_ip])
        
        try:
            result = await self._run_command(cmd, cwd=self.output_dir)
            
            if result["exit_code"] == 0:
                # Find generated ZIP files
                zip_files = [f for f in os.listdir(self.output_dir) if f.endswith('.zip')]
                json_files = [f for f in os.listdir(self.output_dir) if f.endswith('.json')]
                
                if zip_files or json_files:
                    log.success(f"[BloodHound] Data collection successful: {len(zip_files)} ZIP files, {len(json_files)} JSON files")
                    
                    # Parse JSON files for quick stats
                    stats = await self._parse_collected_data(json_files)
                    
                    return {
                        "success": True,
                        "method": "bloodhound-python",
                        "zip_files": zip_files,
                        "json_files": json_files,
                        "output_dir": self.output_dir,
                        "stats": stats,
                        "raw_output": result["stdout"]
                    }
                else:
                    return {
                        "success": False,
                        "message": "No output files generated",
                        "raw_output": result["stdout"]
                    }
            else:
                return {
                    "success": False,
                    "error": result["stderr"],
                    "raw_output": result["stdout"]
                }
        
        except FileNotFoundError:
            log.warning("[BloodHound] bloodhound-python not found, trying SharpHound...")
            return await self._collect_with_sharphound(domain, username, password, strategy)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _collect_with_sharphound(
        self,
        domain: str,
        username: str,
        password: str,
        strategy: Dict
    ) -> Dict:
        """Fallback: Use SharpHound via PowerShell"""
        
        log.info("[BloodHound] Attempting collection with SharpHound...")
        
        # This requires SharpHound.exe on Windows
        # For Linux, we can only suggest manual upload
        
        return {
            "success": False,
            "error": "bloodhound-python not found",
            "install_command": "pip3 install bloodhound",
            "alternative": "Upload and run SharpHound.exe on Windows target",
            "sharphound_url": "https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe"
        }
    
    async def analyze_attack_paths(self, domain: str, strategy: Dict) -> Dict:
        """
        Analyze collected data for attack paths
        
        Looks for:
        - Paths to Domain Admins
        - Kerberoastable accounts
        - AS-REP Roastable accounts
        - Unconstrained delegation
        - High-value targets
        """
        
        log.info(f"[BloodHound] Analyzing attack paths...")
        
        # Parse JSON files
        json_files = [f for f in os.listdir(self.output_dir) if f.endswith('.json')]
        
        if not json_files:
            return {
                "success": False,
                "error": "No JSON files found. Run collection first."
            }
        
        attack_paths = {
            "domain_admins": [],
            "kerberoastable": [],
            "asreproastable": [],
            "unconstrained_delegation": [],
            "high_value_targets": [],
            "shortest_paths": []
        }
        
        for json_file in json_files:
            file_path = os.path.join(self.output_dir, json_file)
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Analyze based on file type
                if 'users' in json_file.lower():
                    attack_paths.update(self._analyze_users(data))
                elif 'computers' in json_file.lower():
                    attack_paths.update(self._analyze_computers(data))
                elif 'groups' in json_file.lower():
                    attack_paths.update(self._analyze_groups(data))
            
            except Exception as e:
                log.error(f"[BloodHound] Error parsing {json_file}: {e}")
        
        # Find target user if specified
        target_user = strategy.get('target_user', 'Administrator')
        paths_to_target = self._find_paths_to_user(target_user, attack_paths)
        
        return {
            "success": True,
            "attack_paths": attack_paths,
            "paths_to_target": paths_to_target,
            "recommendations": self._generate_recommendations(attack_paths)
        }
    
    async def _parse_collected_data(self, json_files: List[str]) -> Dict:
        """Parse collected JSON files for statistics"""
        
        stats = {
            "users": 0,
            "computers": 0,
            "groups": 0,
            "domains": 0
        }
        
        for json_file in json_files:
            file_path = os.path.join(self.output_dir, json_file)
            
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if isinstance(data, dict):
                    if 'data' in data:
                        stats["users"] += len([x for x in data['data'] if x.get('type') == 'User'])
                        stats["computers"] += len([x for x in data['data'] if x.get('type') == 'Computer'])
                        stats["groups"] += len([x for x in data['data'] if x.get('type') == 'Group'])
                        stats["domains"] += len([x for x in data['data'] if x.get('type') == 'Domain'])
            
            except Exception as e:
                log.error(f"[BloodHound] Error parsing {json_file}: {e}")
        
        return stats
    
    def _analyze_users(self, data: Dict) -> Dict:
        """Analyze user data for vulnerabilities"""
        
        results = {
            "kerberoastable": [],
            "asreproastable": [],
            "high_value_targets": []
        }
        
        if 'data' not in data:
            return results
        
        for item in data['data']:
            if item.get('type') != 'User':
                continue
            
            props = item.get('Properties', {})
            name = props.get('name', 'Unknown')
            
            # Check for Kerberoastable
            if props.get('hasspn', False):
                results["kerberoastable"].append(name)
            
            # Check for AS-REP Roastable
            if props.get('dontreqpreauth', False):
                results["asreproastable"].append(name)
            
            # Check for high-value
            if props.get('highvalue', False) or 'admin' in name.lower():
                results["high_value_targets"].append(name)
        
        return results
    
    def _analyze_computers(self, data: Dict) -> Dict:
        """Analyze computer data for delegation"""
        
        results = {
            "unconstrained_delegation": []
        }
        
        if 'data' not in data:
            return results
        
        for item in data['data']:
            if item.get('type') != 'Computer':
                continue
            
            props = item.get('Properties', {})
            name = props.get('name', 'Unknown')
            
            # Check for unconstrained delegation
            if props.get('unconstraineddelegation', False):
                results["unconstrained_delegation"].append(name)
        
        return results
    
    def _analyze_groups(self, data: Dict) -> Dict:
        """Analyze group memberships"""
        
        results = {
            "domain_admins": []
        }
        
        if 'data' not in data:
            return results
        
        for item in data['data']:
            if item.get('type') != 'Group':
                continue
            
            props = item.get('Properties', {})
            name = props.get('name', '')
            
            # Find Domain Admins group members
            if 'domain admins' in name.lower():
                members = item.get('Members', [])
                for member in members:
                    member_name = member.get('ObjectIdentifier', 'Unknown')
                    results["domain_admins"].append(member_name)
        
        return results
    
    def _find_paths_to_user(self, target_user: str, attack_paths: Dict) -> List[str]:
        """Find attack paths to target user"""
        
        paths = []
        
        # Check if target is in Domain Admins
        if target_user in attack_paths.get("domain_admins", []):
            paths.append(f"{target_user} is already a Domain Admin")
        
        # Check for Kerberoastable path
        if target_user in attack_paths.get("kerberoastable", []):
            paths.append(f"Kerberoast {target_user} -> Crack hash -> Compromise account")
        
        # Check for AS-REP Roastable path
        if target_user in attack_paths.get("asreproastable", []):
            paths.append(f"AS-REP Roast {target_user} -> Crack hash -> Compromise account")
        
        return paths
    
    def _generate_recommendations(self, attack_paths: Dict) -> List[str]:
        """Generate attack recommendations based on findings"""
        
        recommendations = []
        
        if attack_paths.get("kerberoastable"):
            recommendations.append(
                f"Found {len(attack_paths['kerberoastable'])} Kerberoastable accounts. "
                "Use Kerberoasting agent to extract and crack service tickets."
            )
        
        if attack_paths.get("asreproastable"):
            recommendations.append(
                f"Found {len(attack_paths['asreproastable'])} AS-REP Roastable accounts. "
                "Use AS-REP Roasting agent to extract and crack hashes."
            )
        
        if attack_paths.get("unconstrained_delegation"):
            recommendations.append(
                f"Found {len(attack_paths['unconstrained_delegation'])} computers with unconstrained delegation. "
                "Compromise these computers to capture TGTs."
            )
        
        if attack_paths.get("high_value_targets"):
            recommendations.append(
                f"Found {len(attack_paths['high_value_targets'])} high-value targets. "
                "Focus attacks on these accounts."
            )
        
        return recommendations
    
    async def _run_command(self, cmd: List[str], cwd: str = None) -> Dict:
        """Run command asynchronously"""
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            return {
                "exit_code": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore')
            }
        
        except asyncio.TimeoutError:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Command timed out"
            }
        except Exception as e:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e)
            }


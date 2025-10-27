"""
Notification Service for dLNk Attack Platform
Unified notifications across multiple channels
"""

import asyncio
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime


class NotificationChannel(str, Enum):
    """Notification channels"""
    EMAIL = "email"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    CONSOLE = "console"
    WEBHOOK = "webhook"


class NotificationService:
    """
    Unified Notification Service
    
    Sends notifications across multiple channels
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Notification Service
        
        Args:
            config: Configuration dictionary with channel settings
        """
        self.config = config
        self.enabled_channels = config.get("enabled_channels", [NotificationChannel.CONSOLE])
        
        # Email settings
        self.smtp_host = config.get("smtp_host")
        self.smtp_port = config.get("smtp_port", 587)
        self.smtp_username = config.get("smtp_username")
        self.smtp_password = config.get("smtp_password")
        self.email_from = config.get("email_from", self.smtp_username)
        
        # Telegram settings
        self.telegram_bot_token = config.get("telegram_bot_token")
        self.telegram_chat_id = config.get("telegram_chat_id")
        
        # Discord settings
        self.discord_webhook_url = config.get("discord_webhook_url")
    
    async def send_notification(
        self,
        title: str,
        message: str,
        channels: Optional[List[NotificationChannel]] = None,
        priority: str = "normal",
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Send notification to multiple channels
        
        Args:
            title: Notification title
            message: Notification message
            channels: List of channels to send to (None = all enabled)
            priority: Priority level (low, normal, high, critical)
            metadata: Additional metadata
        """
        if channels is None:
            channels = self.enabled_channels
        
        tasks = []
        for channel in channels:
            if channel == NotificationChannel.EMAIL:
                tasks.append(self.send_email(title, message, metadata))
            elif channel == NotificationChannel.TELEGRAM:
                tasks.append(self.send_telegram(title, message, metadata))
            elif channel == NotificationChannel.DISCORD:
                tasks.append(self.send_discord(title, message, metadata))
            elif channel == NotificationChannel.CONSOLE:
                tasks.append(self.send_console(title, message, metadata))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_email(
        self,
        subject: str,
        body: str,
        metadata: Optional[Dict[str, Any]] = None,
        recipients: Optional[List[str]] = None
    ):
        """
        Send email notification
        
        Args:
            subject: Email subject
            body: Email body
            metadata: Additional metadata
            recipients: List of recipient emails
        """
        if not all([self.smtp_host, self.smtp_username, self.smtp_password]):
            return
        
        if recipients is None:
            recipients = self.config.get("email_recipients", [])
        
        if not recipients:
            return
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[dLNk] {subject}"
            msg['From'] = self.email_from
            msg['To'] = ', '.join(recipients)
            
            # Create HTML body
            html_body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .header {{ background: #667eea; color: white; padding: 20px; }}
                    .content {{ padding: 20px; }}
                    .footer {{ background: #f5f5f5; padding: 10px; text-align: center; color: #666; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>🎯 dLNk Attack Platform</h2>
                </div>
                <div class="content">
                    <h3>{subject}</h3>
                    <p>{body}</p>
                    {f"<pre>{metadata}</pre>" if metadata else ""}
                </div>
                <div class="footer">
                    <p>Generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            await asyncio.to_thread(self._send_smtp, msg, recipients)
            
        except Exception as e:
            print(f"Failed to send email: {e}")
    
    def _send_smtp(self, msg, recipients):
        """Send email via SMTP (blocking)"""
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_username, self.smtp_password)
            server.send_message(msg)
    
    async def send_telegram(
        self,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Send Telegram notification
        
        Args:
            title: Message title
            message: Message content
            metadata: Additional metadata
        """
        if not all([self.telegram_bot_token, self.telegram_chat_id]):
            return
        
        try:
            # Format message
            text = f"🎯 *{title}*\n\n{message}"
            if metadata:
                text += f"\n\n```\n{metadata}\n```"
            
            # Send via Telegram Bot API
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": text,
                "parse_mode": "Markdown"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data) as response:
                    if response.status != 200:
                        print(f"Telegram API error: {await response.text()}")
                        
        except Exception as e:
            print(f"Failed to send Telegram message: {e}")
    
    async def send_discord(
        self,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Send Discord notification
        
        Args:
            title: Message title
            message: Message content
            metadata: Additional metadata
        """
        if not self.discord_webhook_url:
            return
        
        try:
            # Create embed
            embed = {
                "title": f"🎯 {title}",
                "description": message,
                "color": 6855914,  # Purple color
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {
                    "text": "dLNk Attack Platform"
                }
            }
            
            if metadata:
                embed["fields"] = [
                    {
                        "name": "Details",
                        "value": f"```json\n{metadata}\n```",
                        "inline": False
                    }
                ]
            
            data = {"embeds": [embed]}
            
            # Send via Discord Webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(self.discord_webhook_url, json=data) as response:
                    if response.status not in [200, 204]:
                        print(f"Discord webhook error: {await response.text()}")
                        
        except Exception as e:
            print(f"Failed to send Discord message: {e}")
    
    async def send_console(
        self,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Send console notification (print to stdout)
        
        Args:
            title: Message title
            message: Message content
            metadata: Additional metadata
        """
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        print(f"\n{'=' * 80}")
        print(f"[{timestamp}] 🔔 {title}")
        print(f"{'-' * 80}")
        print(message)
        if metadata:
            print(f"{'-' * 80}")
            print(f"Metadata: {metadata}")
        print(f"{'=' * 80}\n")
    
    async def notify_attack_start(
        self,
        attack_id: str,
        target_url: str,
        attack_type: str
    ):
        """
        Notify when attack starts
        
        Args:
            attack_id: Attack ID
            target_url: Target URL
            attack_type: Attack type
        """
        await self.send_notification(
            title="Attack Started",
            message=f"Attack {attack_id} started against {target_url}",
            metadata={
                "attack_id": attack_id,
                "target": target_url,
                "type": attack_type,
                "status": "started"
            },
            priority="normal"
        )
    
    async def notify_attack_complete(
        self,
        attack_id: str,
        target_url: str,
        vulnerabilities_count: int,
        execution_time: float
    ):
        """
        Notify when attack completes
        
        Args:
            attack_id: Attack ID
            target_url: Target URL
            vulnerabilities_count: Number of vulnerabilities found
            execution_time: Execution time in seconds
        """
        await self.send_notification(
            title="Attack Completed",
            message=f"Attack {attack_id} completed. Found {vulnerabilities_count} vulnerabilities in {execution_time:.2f}s",
            metadata={
                "attack_id": attack_id,
                "target": target_url,
                "vulnerabilities": vulnerabilities_count,
                "execution_time": f"{execution_time:.2f}s",
                "status": "completed"
            },
            priority="high"
        )
    
    async def notify_vulnerability_found(
        self,
        attack_id: str,
        vulnerability_type: str,
        severity: str,
        location: str
    ):
        """
        Notify when vulnerability is found
        
        Args:
            attack_id: Attack ID
            vulnerability_type: Type of vulnerability
            severity: Severity level
            location: Location of vulnerability
        """
        priority = "critical" if severity.lower() == "critical" else "high"
        
        await self.send_notification(
            title=f"{severity.upper()} Vulnerability Found",
            message=f"Found {vulnerability_type} vulnerability at {location}",
            metadata={
                "attack_id": attack_id,
                "type": vulnerability_type,
                "severity": severity,
                "location": location
            },
            priority=priority
        )
    
    async def notify_shell_obtained(
        self,
        attack_id: str,
        target_url: str,
        shell_type: str
    ):
        """
        Notify when shell is obtained
        
        Args:
            attack_id: Attack ID
            target_url: Target URL
            shell_type: Type of shell
        """
        await self.send_notification(
            title="Shell Obtained",
            message=f"Successfully obtained {shell_type} shell on {target_url}",
            metadata={
                "attack_id": attack_id,
                "target": target_url,
                "shell_type": shell_type
            },
            priority="critical"
        )
    
    async def notify_error(
        self,
        attack_id: str,
        error_message: str
    ):
        """
        Notify when error occurs
        
        Args:
            attack_id: Attack ID
            error_message: Error message
        """
        await self.send_notification(
            title="Attack Error",
            message=f"Error in attack {attack_id}: {error_message}",
            metadata={
                "attack_id": attack_id,
                "error": error_message
            },
            priority="high"
        )


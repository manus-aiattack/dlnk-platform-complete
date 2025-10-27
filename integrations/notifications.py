"""
Notification Integration System
ระบบแจ้งเตือนผ่าน Slack, Discord, Telegram
"""

import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from core.logger import log


class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(Enum):
    """Notification channels"""
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    EMAIL = "email"


class SlackNotifier:
    """Slack notification integration"""
    
    def __init__(self, webhook_url: str):
        """
        Initialize Slack notifier
        
        Args:
            webhook_url: Slack webhook URL
        """
        self.webhook_url = webhook_url
    
    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        fields: Optional[List[Dict[str, str]]] = None
    ) -> bool:
        """
        ส่ง notification ไปยัง Slack
        
        Args:
            message: Message text
            title: Message title
            priority: Priority level
            fields: Additional fields
        
        Returns:
            Success status
        """
        try:
            # Color based on priority
            colors = {
                NotificationPriority.LOW: "#36a64f",
                NotificationPriority.MEDIUM: "#ff9900",
                NotificationPriority.HIGH: "#ff6600",
                NotificationPriority.CRITICAL: "#ff0000"
            }
            
            color = colors.get(priority, "#808080")
            
            # Build payload
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": title or "dLNk Attack Platform Notification",
                        "text": message,
                        "fields": fields or [],
                        "footer": "dLNk Attack Platform",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 200:
                        log.info("[SlackNotifier] Notification sent successfully")
                        return True
                    else:
                        log.error(f"[SlackNotifier] Failed to send notification: {response.status}")
                        return False
        
        except Exception as e:
            log.error(f"[SlackNotifier] Error sending notification: {e}")
            return False


class DiscordNotifier:
    """Discord notification integration"""
    
    def __init__(self, webhook_url: str):
        """
        Initialize Discord notifier
        
        Args:
            webhook_url: Discord webhook URL
        """
        self.webhook_url = webhook_url
    
    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        fields: Optional[List[Dict[str, str]]] = None
    ) -> bool:
        """
        ส่ง notification ไปยัง Discord
        
        Args:
            message: Message text
            title: Message title
            priority: Priority level
            fields: Additional fields
        
        Returns:
            Success status
        """
        try:
            # Color based on priority
            colors = {
                NotificationPriority.LOW: 0x36a64f,
                NotificationPriority.MEDIUM: 0xff9900,
                NotificationPriority.HIGH: 0xff6600,
                NotificationPriority.CRITICAL: 0xff0000
            }
            
            color = colors.get(priority, 0x808080)
            
            # Build embed
            embed = {
                "title": title or "dLNk Attack Platform Notification",
                "description": message,
                "color": color,
                "timestamp": datetime.now().isoformat(),
                "footer": {
                    "text": "dLNk Attack Platform"
                }
            }
            
            # Add fields
            if fields:
                embed["fields"] = [
                    {"name": f["name"], "value": f["value"], "inline": f.get("inline", False)}
                    for f in fields
                ]
            
            payload = {
                "embeds": [embed]
            }
            
            # Send to Discord
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status in [200, 204]:
                        log.info("[DiscordNotifier] Notification sent successfully")
                        return True
                    else:
                        log.error(f"[DiscordNotifier] Failed to send notification: {response.status}")
                        return False
        
        except Exception as e:
            log.error(f"[DiscordNotifier] Error sending notification: {e}")
            return False


class TelegramNotifier:
    """Telegram notification integration"""
    
    def __init__(self, bot_token: str, chat_id: str):
        """
        Initialize Telegram notifier
        
        Args:
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}"
    
    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        parse_mode: str = "HTML"
    ) -> bool:
        """
        ส่ง notification ไปยัง Telegram
        
        Args:
            message: Message text
            title: Message title
            priority: Priority level
            parse_mode: Message parse mode (HTML or Markdown)
        
        Returns:
            Success status
        """
        try:
            # Priority emoji
            priority_emoji = {
                NotificationPriority.LOW: "ℹ️",
                NotificationPriority.MEDIUM: "⚠️",
                NotificationPriority.HIGH: "🔴",
                NotificationPriority.CRITICAL: "🚨"
            }
            
            emoji = priority_emoji.get(priority, "📢")
            
            # Format message
            if parse_mode == "HTML":
                formatted_message = f"{emoji} <b>{title or 'dLNk Attack Platform'}</b>\n\n{message}"
            else:
                formatted_message = f"{emoji} **{title or 'dLNk Attack Platform'}**\n\n{message}"
            
            # Build payload
            payload = {
                "chat_id": self.chat_id,
                "text": formatted_message,
                "parse_mode": parse_mode
            }
            
            # Send to Telegram
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.api_url}/sendMessage", json=payload) as response:
                    if response.status == 200:
                        log.info("[TelegramNotifier] Notification sent successfully")
                        return True
                    else:
                        log.error(f"[TelegramNotifier] Failed to send notification: {response.status}")
                        return False
        
        except Exception as e:
            log.error(f"[TelegramNotifier] Error sending notification: {e}")
            return False


class NotificationManager:
    """
    Notification Manager
    
    จัดการการส่ง notifications ผ่านหลาย channels
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize notification manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.notifiers = {}
        
        # Initialize notifiers
        if config.get("slack_webhook_url"):
            self.notifiers[NotificationChannel.SLACK] = SlackNotifier(
                config["slack_webhook_url"]
            )
        
        if config.get("discord_webhook_url"):
            self.notifiers[NotificationChannel.DISCORD] = DiscordNotifier(
                config["discord_webhook_url"]
            )
        
        if config.get("telegram_bot_token") and config.get("telegram_chat_id"):
            self.notifiers[NotificationChannel.TELEGRAM] = TelegramNotifier(
                config["telegram_bot_token"],
                config["telegram_chat_id"]
            )
    
    async def send(
        self,
        message: str,
        title: Optional[str] = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        channels: Optional[List[NotificationChannel]] = None,
        fields: Optional[List[Dict[str, str]]] = None
    ) -> Dict[NotificationChannel, bool]:
        """
        ส่ง notification ผ่านหลาย channels
        
        Args:
            message: Message text
            title: Message title
            priority: Priority level
            channels: List of channels to send to (None = all)
            fields: Additional fields
        
        Returns:
            Dictionary of channel -> success status
        """
        results = {}
        
        # Determine channels to send to
        target_channels = channels or list(self.notifiers.keys())
        
        # Send to each channel
        for channel in target_channels:
            notifier = self.notifiers.get(channel)
            if notifier:
                success = await notifier.send(message, title, priority, fields)
                results[channel] = success
        
        return results
    
    async def send_vulnerability_alert(
        self,
        vulnerability: Dict[str, Any],
        target: str
    ) -> Dict[NotificationChannel, bool]:
        """
        ส่ง vulnerability alert
        
        Args:
            vulnerability: Vulnerability data
            target: Target URL/IP
        
        Returns:
            Send results
        """
        vuln_type = vulnerability.get("type", "Unknown")
        severity = vulnerability.get("severity", "Unknown")
        cvss_score = vulnerability.get("cvss_score", "N/A")
        
        message = f"""
🎯 **Target:** {target}
🔍 **Vulnerability:** {vuln_type}
⚠️ **Severity:** {severity}
📊 **CVSS Score:** {cvss_score}
📍 **Location:** {vulnerability.get('location', 'N/A')}

**Description:**
{vulnerability.get('description', 'No description available')}
        """
        
        # Determine priority from severity
        priority_mapping = {
            "Critical": NotificationPriority.CRITICAL,
            "High": NotificationPriority.HIGH,
            "Medium": NotificationPriority.MEDIUM,
            "Low": NotificationPriority.LOW
        }
        priority = priority_mapping.get(severity, NotificationPriority.MEDIUM)
        
        fields = [
            {"name": "Type", "value": vuln_type, "inline": True},
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "CVSS", "value": str(cvss_score), "inline": True}
        ]
        
        return await self.send(
            message=message,
            title=f"🚨 Vulnerability Found: {vuln_type}",
            priority=priority,
            fields=fields
        )
    
    async def send_attack_complete(
        self,
        session_id: str,
        target: str,
        stats: Dict[str, Any]
    ) -> Dict[NotificationChannel, bool]:
        """
        ส่ง attack completion notification
        
        Args:
            session_id: Session ID
            target: Target URL/IP
            stats: Attack statistics
        
        Returns:
            Send results
        """
        message = f"""
✅ **Attack Session Completed**

🎯 **Target:** {target}
🆔 **Session ID:** {session_id}

**Statistics:**
- Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}
- Critical: {stats.get('critical', 0)}
- High: {stats.get('high', 0)}
- Medium: {stats.get('medium', 0)}
- Low: {stats.get('low', 0)}

**Duration:** {stats.get('duration', 'N/A')}
        """
        
        fields = [
            {"name": "Total Vulnerabilities", "value": str(stats.get('total_vulnerabilities', 0)), "inline": True},
            {"name": "Critical", "value": str(stats.get('critical', 0)), "inline": True},
            {"name": "High", "value": str(stats.get('high', 0)), "inline": True}
        ]
        
        return await self.send(
            message=message,
            title="✅ Attack Session Completed",
            priority=NotificationPriority.MEDIUM,
            fields=fields
        )
    
    async def send_system_alert(
        self,
        alert_type: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.HIGH
    ) -> Dict[NotificationChannel, bool]:
        """
        ส่ง system alert
        
        Args:
            alert_type: Alert type
            message: Alert message
            priority: Priority level
        
        Returns:
            Send results
        """
        return await self.send(
            message=message,
            title=f"🔔 System Alert: {alert_type}",
            priority=priority
        )


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        # Configuration
        config = {
            "slack_webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
            "discord_webhook_url": "https://discord.com/api/webhooks/YOUR/WEBHOOK/URL",
            "telegram_bot_token": "YOUR_BOT_TOKEN",
            "telegram_chat_id": "YOUR_CHAT_ID"
        }
        
        # Initialize manager
        manager = NotificationManager(config)
        
        # Send vulnerability alert
        vulnerability = {
            "type": "SQL Injection",
            "severity": "Critical",
            "cvss_score": 9.8,
            "location": "/api/users?id=1",
            "description": "SQL injection vulnerability in user_id parameter"
        }
        
        results = await manager.send_vulnerability_alert(vulnerability, "http://localhost:8000")
        print(f"Vulnerability alert sent: {results}")
        
        # Send attack complete notification
        stats = {
            "total_vulnerabilities": 15,
            "critical": 2,
            "high": 5,
            "medium": 6,
            "low": 2,
            "duration": "45 minutes"
        }
        
        results = await manager.send_attack_complete("session_123", "http://localhost:8000", stats)
        print(f"Attack complete notification sent: {results}")
    
    asyncio.run(main())


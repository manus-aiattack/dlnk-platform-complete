import asyncio
import json
import os
from typing import Dict, Any, Optional
from core.logger import log
from config import settings


class ConfigManager:
    """จัดการ configuration ของระบบ"""

    def __init__(self):
        self.config = {}
        self.config_file = "config/system_config.json"

    async def load_config(self):
        """โหลด configuration"""
        try:
            # โหลดจากไฟล์ถ้ามี
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            else:
                # ใช้ค่าเริ่มต้น
                self.config = await self._get_default_config()
                await self.save_config()

            log.info("✅ โหลด configuration สำเร็จ")
            return True

        except Exception as e:
            log.error(f"❌ โหลด configuration ล้มเหลว: {e}")
            return False

    async def _get_default_config(self) -> Dict[str, Any]:
        """รับค่าเริ่มต้นของ configuration"""
        return {
            "llm_provider": settings.LLM_PROVIDER,
            "llm_model": settings.LLM_MODEL,
            "llm_api_key": "",
            "llm_base_url": settings.OLLAMA_HOST,
            "llm_max_tokens": 4000,
            "llm_temperature": 0.7,
            "llm_timeout": 30,
            "target_url": "",
            "target_host": "",
            "objective": "",
            "risk_tolerance": "medium",
            "stealth_requirements": False,
            "time_constraints": {
                "max_execution_time": 3600
            },
            "agents": {
                "enabled": True,
                "max_concurrent": 5,
                "timeout": 300
            },
            "monitoring": {
                "enabled": True,
                "log_level": "INFO",
                "save_logs": True
            },
            "reporting": {
                "enabled": True,
                "output_format": "json",
                "save_reports": True
            }
        }

    async def save_config(self):
        """บันทึก configuration"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)

            log.info("✅ บันทึก configuration สำเร็จ")
            return True

        except Exception as e:
            log.error(f"❌ บันทึก configuration ล้มเหลว: {e}")
            return False

    async def get_config(self) -> Dict[str, Any]:
        """รับ configuration"""
        return self.config

    async def update_config(self, updates: Dict[str, Any]) -> bool:
        """อัปเดต configuration"""
        try:
            self.config.update(updates)
            await self.save_config()

            log.info("✅ อัปเดต configuration สำเร็จ")
            return True

        except Exception as e:
            log.error(f"❌ อัปเดต configuration ล้มเหลว: {e}")
            return False

    async def get_setting(self, key: str, default: Any = None) -> Any:
        """รับการตั้งค่าตาม key"""
        return self.config.get(key, default)

    async def set_setting(self, key: str, value: Any) -> bool:
        """ตั้งค่าตาม key"""
        try:
            self.config[key] = value
            await self.save_config()

            log.info(f"✅ ตั้งค่า {key} = {value}")
            return True

        except Exception as e:
            log.error(f"❌ ตั้งค่า {key} ล้มเหลว: {e}")
            return False

"""
License Manager for dLNk dLNk Framework
Handles license key generation, validation, and terminal locking
"""

import hashlib
import json
import os
import platform
import socket
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.logger import get_logger

log = get_logger(__name__)


class LicenseManager:
    """จัดการ License Key และ Terminal Locking"""
    
    def __init__(self, license_dir: str = None):
        self.license_dir = Path(license_dir or os.path.expanduser("~/.dlnk"))
        self.license_dir.mkdir(parents=True, exist_ok=True)
        self.license_file = self.license_dir / "license.dat"
        self.lock_file = self.license_dir / "terminal.lock"
        self.master_key = self._get_master_key()
        
    def _get_master_key(self) -> bytes:
        """สร้าง Master Key สำหรับ encryption"""
        # ใช้ข้อมูลเครื่องเพื่อสร้าง key ที่ unique
        machine_id = self._get_machine_id()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'dlnk_salt_2024',
            iterations=100000,
        )
        return kdf.derive(machine_id.encode())
    
    def _get_machine_id(self) -> str:
        """ดึง Machine ID ที่ unique สำหรับเครื่องนี้"""
        try:
            # ใช้ MAC address + hostname + platform
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 2*6, 2)][::-1])
            hostname = socket.gethostname()
            system = platform.system()
            machine_str = f"{mac}:{hostname}:{system}"
            return hashlib.sha256(machine_str.encode()).hexdigest()
        except Exception as e:
            log.error(f"ไม่สามารถดึง Machine ID: {e}")
            return "default_machine_id"
    
    def _get_terminal_id(self) -> str:
        """ดึง Terminal ID ที่ unique สำหรับ terminal session นี้"""
        try:
            # ใช้ PID + PPID + TTY
            pid = os.getpid()
            ppid = os.getppid()
            tty = os.ttyname(0) if os.isatty(0) else "no_tty"
            terminal_str = f"{pid}:{ppid}:{tty}"
            return hashlib.sha256(terminal_str.encode()).hexdigest()
        except Exception as e:
            log.error(f"ไม่สามารถดึง Terminal ID: {e}")
            return f"terminal_{os.getpid()}"
    
    def generate_license_key(
        self,
        duration_hours: int = None,
        duration_days: int = None,
        duration_months: int = None,
        max_uses: int = 1,
        user_info: Dict[str, Any] = None
    ) -> str:
        """
        สร้าง License Key
        
        Args:
            duration_hours: จำนวนชั่วโมงที่ใช้ได้
            duration_days: จำนวนวันที่ใช้ได้
            duration_months: จำนวนเดือนที่ใช้ได้
            max_uses: จำนวนครั้งที่ใช้ได้ (default: 1 = ใช้ได้ครั้งเดียว)
            user_info: ข้อมูลผู้ใช้เพิ่มเติม
        
        Returns:
            License key string
        """
        # คำนวณวันหมดอายุ
        now = datetime.now()
        if duration_hours:
            expiry = now + timedelta(hours=duration_hours)
        elif duration_days:
            expiry = now + timedelta(days=duration_days)
        elif duration_months:
            expiry = now + timedelta(days=duration_months * 30)
        else:
            # Default: 1 วัน
            expiry = now + timedelta(days=1)
        
        # สร้าง License data
        license_data = {
            "version": "1.0",
            "issued_at": now.isoformat(),
            "expires_at": expiry.isoformat(),
            "max_uses": max_uses,
            "machine_id": self._get_machine_id(),
            "user_info": user_info or {}
        }
        
        # Encrypt license data
        fernet = Fernet(Fernet.generate_key())
        encrypted = fernet.encrypt(json.dumps(license_data).encode())
        
        # สร้าง license key (base64 encoded)
        license_key = encrypted.hex()
        
        log.success(f"สร้าง License Key สำเร็จ (หมดอายุ: {expiry.strftime('%Y-%m-%d %H:%M:%S')})")
        return license_key
    
    def validate_license(self, license_key: str) -> tuple[bool, str]:
        """
        ตรวจสอบ License Key
        
        Returns:
            (is_valid, message)
        """
        try:
            # ตรวจสอบว่า terminal นี้ถูก lock แล้วหรือไม่
            if self.is_terminal_locked():
                current_terminal = self._get_terminal_id()
                locked_terminal = self._get_locked_terminal()
                
                if current_terminal != locked_terminal:
                    return False, "❌ License นี้ถูกใช้งานใน Terminal อื่นแล้ว (Terminal Locked)"
            
            # Decrypt license key
            encrypted_data = bytes.fromhex(license_key)
            
            # ตรวจสอบว่า license ถูกบันทึกไว้หรือไม่
            if not self.license_file.exists():
                return False, "❌ ไม่พบ License ที่บันทึกไว้"
            
            with open(self.license_file, 'r') as f:
                stored_data = json.load(f)
            
            # ตรวจสอบ Machine ID
            current_machine = self._get_machine_id()
            if stored_data.get("machine_id") != current_machine:
                return False, "❌ License นี้ไม่สามารถใช้งานบนเครื่องนี้ได้"
            
            # ตรวจสอบวันหมดอายุ
            expiry = datetime.fromisoformat(stored_data["expires_at"])
            if datetime.now() > expiry:
                return False, f"❌ License หมดอายุแล้ว (หมดอายุ: {expiry.strftime('%Y-%m-%d %H:%M:%S')})"
            
            # ตรวจสอบจำนวนครั้งที่ใช้
            uses = stored_data.get("uses", 0)
            max_uses = stored_data.get("max_uses", 1)
            
            if uses >= max_uses:
                return False, f"❌ License ถูกใช้งานครบจำนวนครั้งที่กำหนดแล้ว ({uses}/{max_uses})"
            
            # อัปเดตจำนวนครั้งที่ใช้
            stored_data["uses"] = uses + 1
            stored_data["last_used"] = datetime.now().isoformat()
            
            with open(self.license_file, 'w') as f:
                json.dump(stored_data, f, indent=2)
            
            # Lock terminal
            self._lock_terminal()
            
            remaining_time = expiry - datetime.now()
            days = remaining_time.days
            hours = remaining_time.seconds // 3600
            
            return True, f"✅ License ถูกต้อง (เหลือเวลา: {days} วัน {hours} ชั่วโมง, ใช้ไปแล้ว: {uses + 1}/{max_uses})"
            
        except Exception as e:
            log.error(f"เกิดข้อผิดพลาดในการตรวจสอบ License: {e}")
            return False, f"❌ License ไม่ถูกต้องหรือเสียหาย: {str(e)}"
    
    def activate_license(self, license_key: str) -> tuple[bool, str]:
        """
        เปิดใช้งาน License Key
        
        Returns:
            (success, message)
        """
        try:
            # Decrypt และตรวจสอบ license key
            encrypted_data = bytes.fromhex(license_key)
            
            # ในการใช้งานจริง ควรใช้ key ที่ server ให้มา
            # ที่นี่เราจะใช้วิธีง่ายๆ โดยเก็บข้อมูลไว้ใน license file
            
            # สร้าง license data
            now = datetime.now()
            expires_at = now + timedelta(days=365)  # Default 1 year
            license_data = {
                "key": license_key,
                "machine_id": self._get_machine_id(),
                "activated_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "max_uses": 999999,
                "uses": 0
            }
            
            # บันทึก license
            with open(self.license_file, 'w') as f:
                json.dump(license_data, f, indent=2)
            
            log.success("เปิดใช้งาน License สำเร็จ")
            return True, "✅ เปิดใช้งาน License สำเร็จ"
            
        except Exception as e:
            log.error(f"ไม่สามารถเปิดใช้งาน License: {e}")
            return False, f"❌ ไม่สามารถเปิดใช้งาน License: {str(e)}"
    
    def _lock_terminal(self):
        """Lock terminal ปัจจุบัน"""
        terminal_id = self._get_terminal_id()
        lock_data = {
            "terminal_id": terminal_id,
            "locked_at": datetime.now().isoformat(),
            "pid": os.getpid()
        }
        
        with open(self.lock_file, 'w') as f:
            json.dump(lock_data, f, indent=2)
        
        log.info(f"Terminal ถูก Lock แล้ว (ID: {terminal_id[:16]}...)")
    
    def is_terminal_locked(self) -> bool:
        """ตรวจสอบว่า terminal ถูก lock หรือไม่"""
        return self.lock_file.exists()
    
    def _get_locked_terminal(self) -> Optional[str]:
        """ดึง Terminal ID ที่ถูก lock"""
        if not self.lock_file.exists():
            return None
        
        try:
            with open(self.lock_file, 'r') as f:
                lock_data = json.load(f)
            return lock_data.get("terminal_id")
        except Exception:
            return None
    
    def unlock_terminal(self):
        """ปลด lock terminal"""
        if self.lock_file.exists():
            self.lock_file.unlink()
            log.info("Terminal ถูกปลด Lock แล้ว")
    
    def get_license_info(self) -> Optional[Dict[str, Any]]:
        """ดึงข้อมูล License ปัจจุบัน"""
        if not self.license_file.exists():
            return None
        
        try:
            with open(self.license_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            log.error(f"ไม่สามารถอ่านข้อมูล License: {e}")
            return None
    
    def revoke_license(self):
        """ยกเลิก License"""
        if self.license_file.exists():
            self.license_file.unlink()
        
        self.unlock_terminal()
        log.info("License ถูกยกเลิกแล้ว")


# Singleton instance
_license_manager = None

def get_license_manager() -> LicenseManager:
    """ดึง LicenseManager instance"""
    global _license_manager
    if _license_manager is None:
        _license_manager = LicenseManager()
    return _license_manager


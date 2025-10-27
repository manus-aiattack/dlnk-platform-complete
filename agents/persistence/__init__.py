"""
Persistence Module
ฝังตัวในระบบเป้าหมายแบบถาวร
"""

from .linux_persistence import LinuxPersistence
from .windows_persistence import WindowsPersistence
from .web_persistence import WebPersistence

__all__ = [
    'LinuxPersistence',
    'WindowsPersistence',
    'WebPersistence'
]


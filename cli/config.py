"""
CLI Configuration Management
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class APIConfig:
    """API configuration"""
    url: str = "http://localhost:8000"
    key: Optional[str] = None
    timeout: int = 30


@dataclass
class UserConfig:
    """User configuration"""
    username: Optional[str] = None
    role: Optional[str] = None


@dataclass
class PreferencesConfig:
    """User preferences"""
    theme: str = "dark"
    output_format: str = "table"  # table, json, yaml
    verbose: bool = False
    color: bool = True


@dataclass
class NotificationsConfig:
    """Notifications configuration"""
    enabled: bool = True
    channels: list = None
    
    def __post_init__(self):
        if self.channels is None:
            self.channels = ["terminal"]


class CLIConfig:
    """
    CLI Configuration Manager
    
    Manages configuration file at ~/.dlnk/config.yaml
    """
    
    def __init__(self):
        self.config_dir = Path.home() / ".dlnk"
        self.config_file = self.config_dir / "config.yaml"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.api = APIConfig()
        self.user = UserConfig()
        self.preferences = PreferencesConfig()
        self.notifications = NotificationsConfig()
        
        self.load()
    
    def load(self):
        """Load configuration from file"""
        if not self.config_file.exists():
            self.save()  # Create default config
            return
        
        try:
            with open(self.config_file, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            # Load API config
            if 'api' in data:
                self.api = APIConfig(**data['api'])
            
            # Load user config
            if 'user' in data:
                self.user = UserConfig(**data['user'])
            
            # Load preferences
            if 'preferences' in data:
                self.preferences = PreferencesConfig(**data['preferences'])
            
            # Load notifications
            if 'notifications' in data:
                self.notifications = NotificationsConfig(**data['notifications'])
                
        except Exception as e:
            print(f"Warning: Failed to load config: {e}")
            self.save()  # Reset to defaults
    
    def save(self):
        """Save configuration to file"""
        data = {
            'api': asdict(self.api),
            'user': asdict(self.user),
            'preferences': asdict(self.preferences),
            'notifications': asdict(self.notifications)
        }
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)
        except Exception as e:
            print(f"Warning: Failed to save config: {e}")
    
    def set_api_key(self, api_key: str):
        """Set API key"""
        self.api.key = api_key
        self.save()
    
    def set_api_url(self, url: str):
        """Set API URL"""
        self.api.url = url
        self.save()
    
    def set_user(self, username: str, role: str):
        """Set user information"""
        self.user.username = username
        self.user.role = role
        self.save()
    
    def clear_user(self):
        """Clear user information"""
        self.user.username = None
        self.user.role = None
        self.api.key = None
        self.save()
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.api.key is not None
    
    def get_api_headers(self) -> Dict[str, str]:
        """Get API headers"""
        headers = {
            "Content-Type": "application/json"
        }
        if self.api.key:
            headers["Authorization"] = f"Bearer {self.api.key}"
        return headers
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'api': asdict(self.api),
            'user': asdict(self.user),
            'preferences': asdict(self.preferences),
            'notifications': asdict(self.notifications)
        }


# Global config instance
_config = None


def get_config() -> CLIConfig:
    """Get global config instance"""
    global _config
    if _config is None:
        _config = CLIConfig()
    return _config


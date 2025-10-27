"""
Agents Package
Provides unified imports for all agents
"""

# Import agents with their actual class names
from agents.zero_day_hunter_weaponized import ZeroDayHunterAgent
from agents.xss_agent import XSS_Agent
from agents.command_injection_exploiter import CommandInjectionExploiter
from agents.sqlmap_agent import SqlmapAgent

# Create aliases for easier imports
ZeroDayHunter = ZeroDayHunterAgent
XSSAgent = XSS_Agent
CommandInjectionAgent = CommandInjectionExploiter

__all__ = [
    'ZeroDayHunterAgent',
    'ZeroDayHunter',
    'XSS_Agent',
    'XSSAgent',
    'CommandInjectionExploiter',
    'CommandInjectionAgent',
    'SqlmapAgent',
]

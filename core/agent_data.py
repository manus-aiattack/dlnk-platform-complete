"""
Agent Data Module
Alias for data_models to maintain backward compatibility
"""

from .data_models import *

# Re-export everything from data_models
__all__ = [
    'AgentData',
    'Strategy',
    'ErrorType',
    'TargetInfo',
    'VulnerabilityInfo',
    'ExploitInfo',
    'ScanResult',
    'AttackResult',
]


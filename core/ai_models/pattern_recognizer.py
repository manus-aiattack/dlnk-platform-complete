"""
Pattern Recognizer for attack patterns
"""

import asyncio
from typing import List, Dict, Set
import logging

log = logging.getLogger(__name__)


class PatternRecognizer:
    """Recognizes attack patterns"""
    
    def __init__(self):
        self.known_patterns = {}
        self.pattern_frequency = {}
    
    async def learn_pattern(self, pattern: str, category: str):
        """Learn a new pattern"""
        if category not in self.known_patterns:
            self.known_patterns[category] = set()
        
        self.known_patterns[category].add(pattern)
        
        # Track frequency
        if pattern not in self.pattern_frequency:
            self.pattern_frequency[pattern] = 0
        self.pattern_frequency[pattern] += 1
    
    async def recognize(self, data: str) -> List[Dict]:
        """Recognize patterns in data"""
        recognized = []
        
        for category, patterns in self.known_patterns.items():
            for pattern in patterns:
                if pattern in data:
                    recognized.append({
                        'pattern': pattern,
                        'category': category,
                        'frequency': self.pattern_frequency.get(pattern, 0)
                    })
        
        return recognized
    
    async def get_top_patterns(self, n: int = 10) -> List[Dict]:
        """Get top N most frequent patterns"""
        sorted_patterns = sorted(
            self.pattern_frequency.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]
        
        return [
            {'pattern': pattern, 'frequency': freq}
            for pattern, freq in sorted_patterns
        ]

"""
Feature Extractor for ML training
"""

import asyncio
import re
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class FeatureExtractor:
    """Extracts features from vulnerability data"""
    
    def __init__(self):
        self.vuln_keywords = {
            'sql_injection': ['sql', 'injection', 'query', 'database'],
            'xss': ['xss', 'cross-site', 'script', 'javascript'],
            'command_injection': ['command', 'exec', 'shell', 'system'],
            'path_traversal': ['path', 'directory', 'traversal', 'file'],
            'buffer_overflow': ['buffer', 'overflow', 'memory', 'heap', 'stack']
        }
    
    async def extract_features(self, vuln_data: Dict) -> List[float]:
        """Extract numerical features from vulnerability data"""
        
        description = vuln_data.get('description', '').lower()
        cvss = vuln_data.get('cvss', 0) or 0
        
        features = []
        
        # Feature 1: CVSS score (normalized)
        features.append(float(cvss) / 10.0)
        
        # Feature 2-6: Keyword presence (binary)
        for vuln_type, keywords in self.vuln_keywords.items():
            has_keyword = any(kw in description for kw in keywords)
            features.append(1.0 if has_keyword else 0.0)
        
        # Feature 7: Description length (normalized)
        features.append(min(len(description) / 1000.0, 1.0))
        
        # Feature 8: Number of technical terms
        technical_terms = ['remote', 'code', 'execution', 'privilege', 'escalation', 'denial', 'service']
        term_count = sum(1 for term in technical_terms if term in description)
        features.append(term_count / len(technical_terms))
        
        return features
    
    async def extract_label(self, vuln_data: Dict) -> str:
        """Extract vulnerability type label"""
        
        description = vuln_data.get('description', '').lower()
        
        # Determine vulnerability type
        for vuln_type, keywords in self.vuln_keywords.items():
            if any(kw in description for kw in keywords):
                return vuln_type
        
        return 'other'
    
    async def extract_batch(self, vuln_data_list: List[Dict]) -> Dict:
        """Extract features and labels for batch of data"""
        
        log.info(f"[FeatureExtractor] Extracting features from {len(vuln_data_list)} samples")
        
        features = []
        labels = []
        
        for vuln_data in vuln_data_list:
            try:
                feat = await self.extract_features(vuln_data)
                label = await self.extract_label(vuln_data)
                
                features.append(feat)
                labels.append(label)
            
            except Exception as e:
                log.error(f"[FeatureExtractor] Error extracting features: {e}")
        
        return {
            'features': features,
            'labels': labels,
            'count': len(features)
        }

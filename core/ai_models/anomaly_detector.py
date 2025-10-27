"""
Anomaly Detector for unusual patterns
"""

import asyncio
import numpy as np
from typing import List, Dict
import logging

log = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class AnomalyDetector:
    """ML-based anomaly detector"""
    
    def __init__(self):
        self.model = None
        self.is_trained = False
        
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42
            )
    
    async def train(self, features: List[List[float]]):
        """Train the detector"""
        if not SKLEARN_AVAILABLE:
            return
        
        log.info(f"[AnomalyDetector] Training on {len(features)} samples")
        
        self.model.fit(features)
        self.is_trained = True
    
    async def detect(self, features: List[float]) -> Dict:
        """Detect anomalies"""
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return {'is_anomaly': False, 'score': 0.0}
        
        features_array = np.array([features])
        prediction = self.model.predict(features_array)[0]
        score = self.model.score_samples(features_array)[0]
        
        return {
            'is_anomaly': prediction == -1,
            'anomaly_score': float(score),
            'severity': 'HIGH' if score < -0.5 else 'MEDIUM' if score < 0 else 'LOW'
        }

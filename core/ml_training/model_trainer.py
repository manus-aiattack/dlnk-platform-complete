"""
Model Trainer
"""

import asyncio
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class ModelTrainer:
    """Trains ML models"""
    
    def __init__(self):
        self.training_history = []
    
    async def train_classifier(self, model, features: List[List[float]], labels: List[str]) -> Dict:
        """Train a classifier model"""
        
        log.info(f"[ModelTrainer] Training classifier on {len(features)} samples")
        
        try:
            # Train model
            await model.train(features, labels)
            
            result = {
                'success': True,
                'samples': len(features),
                'unique_labels': len(set(labels))
            }
            
            self.training_history.append(result)
            
            return result
        
        except Exception as e:
            log.error(f"[ModelTrainer] Training failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def train_predictor(self, model, features: List[List[float]], labels: List[int]) -> Dict:
        """Train a predictor model"""
        
        log.info(f"[ModelTrainer] Training predictor on {len(features)} samples")
        
        try:
            await model.train(features, labels)
            
            result = {
                'success': True,
                'samples': len(features)
            }
            
            self.training_history.append(result)
            
            return result
        
        except Exception as e:
            log.error(f"[ModelTrainer] Training failed: {e}")
            return {'success': False, 'error': str(e)}

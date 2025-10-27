"""
ML Training Pipeline for dLNk Attack Platform
Trains models on attack data for continuous improvement
"""

import asyncio
import json
import numpy as np
from typing import Dict, List, Optional
from pathlib import Path
import logging
from datetime import datetime

log = logging.getLogger(__name__)


class MLTrainingPipeline:
    """
    Machine Learning Training Pipeline
    
    Features:
    - Collect attack data
    - Train vulnerability detection models
    - Train exploit success prediction models
    - Model versioning and deployment
    """
    
    def __init__(self, data_dir: str = "/tmp/dlnk_training_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.training_data = []
        self.models = {}
        
    async def collect_training_data(self, attack_result: Dict):
        """Collect training data from attack results"""
        
        training_sample = {
            'timestamp': datetime.now().isoformat(),
            'target_url': attack_result.get('target_url'),
            'attack_type': attack_result.get('attack_type'),
            'payload': attack_result.get('payload'),
            'success': attack_result.get('success', False),
            'vulnerability_type': attack_result.get('vulnerability_type'),
            'response_data': attack_result.get('response_data', ''),
            'status_code': attack_result.get('status_code', 0),
            'response_time': attack_result.get('response_time', 0.0),
            'confidence': attack_result.get('confidence', 0.0)
        }
        
        self.training_data.append(training_sample)
        
        # Save to disk
        await self._save_training_sample(training_sample)
        
        log.info(f"[TrainingPipeline] Collected training sample: {attack_result.get('attack_type')}")
    
    async def train_vulnerability_detector(self):
        """Train vulnerability detection model"""
        
        log.info("[TrainingPipeline] Training vulnerability detector...")
        
        if len(self.training_data) < 10:
            log.warning("[TrainingPipeline] Not enough training data (need at least 10 samples)")
            return
        
        # Extract features and labels
        X, y = self._prepare_training_data()
        
        # Train model (simplified - in production use scikit-learn, TensorFlow, etc.)
        model = self._train_classifier(X, y)
        
        self.models['vulnerability_detector'] = model
        
        # Save model
        await self._save_model('vulnerability_detector', model)
        
        log.info("[TrainingPipeline] Vulnerability detector training completed")
    
    async def train_exploit_predictor(self):
        """Train exploit success prediction model"""
        
        log.info("[TrainingPipeline] Training exploit predictor...")
        
        if len(self.training_data) < 10:
            log.warning("[TrainingPipeline] Not enough training data")
            return
        
        # Extract features for exploit prediction
        X, y = self._prepare_exploit_data()
        
        # Train model
        model = self._train_regressor(X, y)
        
        self.models['exploit_predictor'] = model
        
        # Save model
        await self._save_model('exploit_predictor', model)
        
        log.info("[TrainingPipeline] Exploit predictor training completed")
    
    def _prepare_training_data(self) -> tuple:
        """Prepare training data for vulnerability detection"""
        
        X = []  # Features
        y = []  # Labels
        
        for sample in self.training_data:
            features = self._extract_features(sample)
            label = 1 if sample['success'] else 0
            
            X.append(features)
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def _prepare_exploit_data(self) -> tuple:
        """Prepare training data for exploit prediction"""
        
        X = []  # Features
        y = []  # Success probability
        
        for sample in self.training_data:
            features = self._extract_features(sample)
            success_prob = sample['confidence'] if sample['success'] else 0.0
            
            X.append(features)
            y.append(success_prob)
        
        return np.array(X), np.array(y)
    
    def _extract_features(self, sample: Dict) -> List[float]:
        """Extract features from training sample"""
        
        features = []
        
        # Response features
        features.append(sample.get('status_code', 0) / 1000.0)  # Normalize
        features.append(sample.get('response_time', 0.0))
        features.append(len(sample.get('response_data', '')) / 10000.0)  # Normalize
        
        # Payload features
        payload = sample.get('payload', '')
        features.append(len(payload) / 1000.0)  # Normalize
        features.append(self._count_special_chars(payload))
        
        # Attack type features (one-hot encoding)
        attack_types = ['sql_injection', 'xss', 'rce', 'lfi', 'ssrf']
        attack_type = sample.get('attack_type', '')
        for at in attack_types:
            features.append(1.0 if at == attack_type else 0.0)
        
        return features
    
    def _count_special_chars(self, text: str) -> float:
        """Count special characters ratio"""
        if not text:
            return 0.0
        special = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special / len(text)
    
    def _train_classifier(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train classification model (simplified)"""
        
        # This is a simplified version
        # In production, use scikit-learn, TensorFlow, PyTorch, etc.
        
        # Calculate simple statistics for each feature
        model = {
            'type': 'classifier',
            'feature_means': X.mean(axis=0).tolist(),
            'feature_stds': X.std(axis=0).tolist(),
            'positive_rate': y.mean(),
            'n_samples': len(X)
        }
        
        return model
    
    def _train_regressor(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """Train regression model (simplified)"""
        
        # This is a simplified version
        # In production, use proper ML libraries
        
        model = {
            'type': 'regressor',
            'feature_means': X.mean(axis=0).tolist(),
            'feature_stds': X.std(axis=0).tolist(),
            'target_mean': y.mean(),
            'target_std': y.std(),
            'n_samples': len(X)
        }
        
        return model
    
    async def _save_training_sample(self, sample: Dict):
        """Save training sample to disk"""
        
        filename = f"sample_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
        filepath = self.data_dir / filename
        
        try:
            with open(filepath, 'w') as f:
                json.dump(sample, f, indent=2)
        except Exception as e:
            log.error(f"[TrainingPipeline] Failed to save sample: {e}")
    
    async def _save_model(self, model_name: str, model: Dict):
        """Save trained model to disk"""
        
        model_path = self.data_dir / f"{model_name}_model.json"
        
        try:
            with open(model_path, 'w') as f:
                json.dump(model, f, indent=2)
            log.info(f"[TrainingPipeline] Model saved: {model_path}")
        except Exception as e:
            log.error(f"[TrainingPipeline] Failed to save model: {e}")
    
    async def load_training_data(self):
        """Load training data from disk"""
        
        log.info("[TrainingPipeline] Loading training data...")
        
        self.training_data = []
        
        for filepath in self.data_dir.glob("sample_*.json"):
            try:
                with open(filepath, 'r') as f:
                    sample = json.load(f)
                    self.training_data.append(sample)
            except Exception as e:
                log.error(f"[TrainingPipeline] Failed to load {filepath}: {e}")
        
        log.info(f"[TrainingPipeline] Loaded {len(self.training_data)} training samples")
    
    async def evaluate_models(self) -> Dict:
        """Evaluate trained models"""
        
        log.info("[TrainingPipeline] Evaluating models...")
        
        evaluation = {
            'vulnerability_detector': {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0
            },
            'exploit_predictor': {
                'mae': 0.0,
                'rmse': 0.0
            }
        }
        
        # In production, implement proper evaluation metrics
        # For now, return placeholder
        
        return evaluation


if __name__ == '__main__':
    async def test():
        pipeline = MLTrainingPipeline()
        
        # Simulate collecting training data
        attack_results = [
            {
                'target_url': 'http://test.com',
                'attack_type': 'sql_injection',
                'payload': "' OR 1=1--",
                'success': True,
                'vulnerability_type': 'sql_injection',
                'response_data': 'SQL error',
                'status_code': 500,
                'response_time': 0.5,
                'confidence': 0.9
            },
            {
                'target_url': 'http://test.com',
                'attack_type': 'xss',
                'payload': '<script>alert(1)</script>',
                'success': False,
                'vulnerability_type': None,
                'response_data': 'OK',
                'status_code': 200,
                'response_time': 0.1,
                'confidence': 0.0
            }
        ]
        
        for result in attack_results:
            await pipeline.collect_training_data(result)
        
        print(f"Collected {len(pipeline.training_data)} training samples")
    
    asyncio.run(test())


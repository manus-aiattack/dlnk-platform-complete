"""
Model Evaluator
"""

import asyncio
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class ModelEvaluator:
    """Evaluates ML models"""
    
    def __init__(self):
        pass
    
    async def evaluate_classifier(self, model, test_features: List[List[float]], test_labels: List[str]) -> Dict:
        """Evaluate classifier model"""
        
        log.info(f"[ModelEvaluator] Evaluating on {len(test_features)} samples")
        
        correct = 0
        predictions = []
        
        for features, true_label in zip(test_features, test_labels):
            result = await model.predict(features)
            predicted_label = result.get('vulnerability_type')
            
            predictions.append(predicted_label)
            
            if predicted_label == true_label:
                correct += 1
        
        accuracy = correct / len(test_labels) if test_labels else 0.0
        
        return {
            'accuracy': accuracy,
            'correct': correct,
            'total': len(test_labels),
            'predictions': predictions
        }
    
    async def evaluate_predictor(self, model, test_features: List[List[float]], test_labels: List[int]) -> Dict:
        """Evaluate predictor model"""
        
        log.info(f"[ModelEvaluator] Evaluating predictor on {len(test_features)} samples")
        
        correct = 0
        
        for features, true_label in zip(test_features, test_labels):
            result = await model.predict_success(features)
            predicted = 1 if result.get('will_succeed') else 0
            
            if predicted == true_label:
                correct += 1
        
        accuracy = correct / len(test_labels) if test_labels else 0.0
        
        return {
            'accuracy': accuracy,
            'correct': correct,
            'total': len(test_labels)
        }

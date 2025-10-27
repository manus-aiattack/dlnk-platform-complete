"""
Self-Learning System API Routes
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/learning", tags=["learning"])


class AttackFeedback(BaseModel):
    attack_type: str
    target: str
    strategy: str
    parameters: Dict
    success: bool
    execution_time: float
    vulnerabilities_found: List[str] = []
    error: Optional[str] = None


class StrategyRequest(BaseModel):
    attack_type: str
    target_info: Dict


# Global learner instance
learner = None


def get_learner():
    """Get or create learner instance"""
    global learner
    
    if learner is None:
        from core.self_learning.adaptive_learner import AdaptiveLearner
        learner = AdaptiveLearner()
    
    return learner


@router.post("/feedback")
async def submit_feedback(feedback: AttackFeedback):
    """Submit attack feedback for learning"""
    
    log.info(f"[LearningAPI] Receiving feedback: {feedback.attack_type}")
    
    try:
        learner = get_learner()
        
        attack_data = {
            'type': feedback.attack_type,
            'target': feedback.target,
            'strategy': feedback.strategy,
            'parameters': feedback.parameters
        }
        
        result = {
            'success': feedback.success,
            'execution_time': feedback.execution_time,
            'vulnerabilities': feedback.vulnerabilities_found,
            'error': feedback.error
        }
        
        await learner.learn_from_attack(attack_data, result)
        
        return {
            'success': True,
            'message': 'Feedback recorded and learned'
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to process feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recommend")
async def recommend_strategy(request: StrategyRequest):
    """Get recommended strategy for attack"""
    
    log.info(f"[LearningAPI] Recommending strategy for: {request.attack_type}")
    
    try:
        learner = get_learner()
        
        recommendation = await learner.recommend_strategy(
            request.attack_type,
            request.target_info
        )
        
        return {
            'success': True,
            'recommendation': recommendation
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to recommend strategy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_learning_statistics():
    """Get learning system statistics"""
    
    try:
        learner = get_learner()
        
        stats = await learner.get_learning_statistics()
        
        return {
            'success': True,
            'statistics': stats
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/strategies")
async def get_learned_strategies():
    """Get all learned strategies"""
    
    try:
        learner = get_learner()
        
        return {
            'success': True,
            'strategies': learner.learned_strategies
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to get strategies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/optimize")
async def optimize_parameters(
    attack_type: str,
    current_parameters: Dict
):
    """Optimize attack parameters"""
    
    log.info(f"[LearningAPI] Optimizing parameters for: {attack_type}")
    
    try:
        learner = get_learner()
        
        optimized = await learner.optimize_parameters(
            attack_type,
            current_parameters
        )
        
        return {
            'success': True,
            'optimized_parameters': optimized
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to optimize parameters: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict")
async def predict_success(
    attack_type: str,
    strategy: str,
    target_info: Dict
):
    """Predict attack success probability"""
    
    log.info(f"[LearningAPI] Predicting success for: {attack_type}/{strategy}")
    
    try:
        learner = get_learner()
        
        probability = await learner.predict_success_probability(
            attack_type,
            strategy,
            target_info
        )
        
        return {
            'success': True,
            'probability': probability,
            'confidence': 'high' if probability > 0.7 else 'medium' if probability > 0.4 else 'low'
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to predict success: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export")
async def export_knowledge():
    """Export knowledge base"""
    
    log.info("[LearningAPI] Exporting knowledge base")
    
    try:
        learner = get_learner()
        
        output_path = "/tmp/knowledge_export.json"
        await learner.export_knowledge_base(output_path)
        
        return {
            'success': True,
            'export_path': output_path,
            'message': 'Knowledge base exported'
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to export knowledge: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/import")
async def import_knowledge(import_path: str):
    """Import knowledge base"""
    
    log.info(f"[LearningAPI] Importing knowledge base from: {import_path}")
    
    try:
        learner = get_learner()
        
        await learner.import_knowledge_base(import_path)
        
        return {
            'success': True,
            'message': 'Knowledge base imported'
        }
        
    except Exception as e:
        log.error(f"[LearningAPI] Failed to import knowledge: {e}")
        raise HTTPException(status_code=500, detail=str(e))


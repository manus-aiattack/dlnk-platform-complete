"""
AI API Routes
AI-powered analysis and decision making
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging
import datetime

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai"])


class AnalysisRequest(BaseModel):
    target: Dict
    analysis_type: str = "full"  # full, quick, vulnerability, path


class AnalysisResponse(BaseModel):
    analysis_id: str
    vulnerabilities: List[Dict]
    attack_paths: List[Dict]
    recommendations: List[str]
    confidence: float


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_target(request: AnalysisRequest):
    """
    Analyze target using AI
    
    Args:
        request: AnalysisRequest with target information
    
    Returns:
        AnalysisResponse with AI analysis results
    """
    try:
        from core.ai_integration import ai_integration
        
        # Perform AI analysis
        result = await ai_integration.analyze_target(str(request.target), request.target)
        
        if result.get("success"):
            import uuid
            return AnalysisResponse(
                analysis_id=str(uuid.uuid4()),
                vulnerabilities=[],  # analyze_target returns reconnaissance, not vulnerabilities
                attack_paths=[],     # These would come from a different analysis phase
                recommendations=result.get("recommendations", []),
                confidence=result.get("confidence", 0.0)
            )
        else:
            raise HTTPException(status_code=500, detail="Analysis failed")
    
    except Exception as e:
        logger.error(f"AI analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/suggest-attack")
async def suggest_attack(target: Dict):
    """
    Suggest best attack strategy using AI
    
    Args:
        target: Target information
    
    Returns:
        Suggested attack strategy
    """
    try:
        from core.ai_integration import ai_integration

        result = await ai_integration.suggest_attack_vector([], target)
        
        return {
            "success": True,
            "strategy": result.get("strategy"),
            "steps": result.get("steps", []),
            "estimated_success_rate": result.get("success_rate", 0.0)
        }
    
    except Exception as e:
        logger.error(f"AI suggest attack error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/optimize-payload")
async def optimize_payload(payload: Dict):
    """
    Optimize payload using AI
    
    Args:
        payload: Original payload
    
    Returns:
        Optimized payload
    """
    try:
        from core.ai_integration import ai_integration

        result = await ai_integration.generate_exploit_code({}, str(payload))
        
        return {
            "success": True,
            "original_payload": payload,
            "optimized_payload": result.get("payload"),
            "improvements": result.get("improvements", [])
        }
    
    except Exception as e:
        logger.error(f"AI optimize payload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict-success")
async def predict_success(attack_plan: Dict):
    """
    Predict attack success rate using AI
    
    Args:
        attack_plan: Attack plan details
    
    Returns:
        Success prediction
    """
    try:
        from core.ai_integration import ai_integration

        result = await ai_integration.generate_report([], attack_plan)
        
        return {
            "success": True,
            "success_rate": result.get("success_rate", 0.0),
            "confidence": result.get("confidence", 0.0),
            "factors": result.get("factors", [])
        }
    
    except Exception as e:
        logger.error(f"AI predict success error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/learning-stats")
async def get_learning_stats():
    """
    Get AI learning statistics
    
    Returns:
        Learning statistics
    """
    try:
        from core.self_learning import SelfLearningSystem
        
        learning = SelfLearningSystem()
        stats = await learning.get_statistics()
        
        return {
            "success": True,
            "stats": stats
        }
    
    except Exception as e:
        logger.error(f"Get learning stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/train")
async def train_model(training_data: Dict):
    """
    Train AI model with new data
    
    Args:
        training_data: Training data
    
    Returns:
        Training results
    """
    try:
        from core.self_learning import SelfLearningSystem
        
        learning = SelfLearningSystem()
        result = await learning.train(training_data)
        
        return {
            "success": True,
            "model_version": result.get("version"),
            "accuracy": result.get("accuracy", 0.0)
        }
    
    except Exception as e:
        logger.error(f"AI train error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_ai_status():
    """
    Get AI model status and capabilities
    """
    try:
        from core.ai_integration import ai_integration

        # Get model status
        model_status = ai_integration.get_model_status()

        return {
            "model": model_status.get("model", "unknown"),
            "status": model_status.get("status", "ready"),
            "capabilities": model_status.get("capabilities", []),
            "timestamp": datetime.datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"AI status error: {e}")
        return {
            "model": "unknown",
            "status": "error",
            "capabilities": [],
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }


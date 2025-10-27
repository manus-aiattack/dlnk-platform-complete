"""
Model Manager for ML models
"""
from typing import List

import asyncio
import pickle
from pathlib import Path
from typing import Dict, Any
import logging

log = logging.getLogger(__name__)


class ModelManager:
    """Manages ML models"""
    
    def __init__(self, models_dir: str = '/tmp/ml_models'):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.loaded_models = {}
    
    async def save_model(self, model: Any, name: str):
        """Save a model"""
        model_path = self.models_dir / f"{name}.pkl"
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            
            log.info(f"[ModelManager] Saved model: {name}")
        
        except Exception as e:
            log.error(f"[ModelManager] Failed to save model {name}: {e}")
    
    async def load_model(self, name: str) -> Any:
        """Load a model"""
        if name in self.loaded_models:
            return self.loaded_models[name]
        
        model_path = self.models_dir / f"{name}.pkl"
        
        if not model_path.exists():
            log.warning(f"[ModelManager] Model not found: {name}")
            return None
        
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            
            self.loaded_models[name] = model
            log.info(f"[ModelManager] Loaded model: {name}")
            
            return model
        
        except Exception as e:
            log.error(f"[ModelManager] Failed to load model {name}: {e}")
            return None
    
    async def list_models(self) -> List[str]:
        """List available models"""
        return [f.stem for f in self.models_dir.glob('*.pkl')]
    
    async def delete_model(self, name: str):
        """Delete a model"""
        model_path = self.models_dir / f"{name}.pkl"
        
        if model_path.exists():
            model_path.unlink()
            log.info(f"[ModelManager] Deleted model: {name}")
        
        if name in self.loaded_models:
            del self.loaded_models[name]

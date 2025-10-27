"""
Dataset Manager
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class DatasetManager:
    """Manages training datasets"""
    
    def __init__(self, dataset_dir: str = '/tmp/datasets'):
        self.dataset_dir = Path(dataset_dir)
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
    
    async def save_dataset(self, data: Dict, name: str):
        """Save dataset"""
        
        dataset_path = self.dataset_dir / f"{name}.json"
        
        try:
            with open(dataset_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            log.info(f"[DatasetManager] Saved dataset: {name}")
        
        except Exception as e:
            log.error(f"[DatasetManager] Failed to save dataset {name}: {e}")
    
    async def load_dataset(self, name: str) -> Dict:
        """Load dataset"""
        
        dataset_path = self.dataset_dir / f"{name}.json"
        
        if not dataset_path.exists():
            log.warning(f"[DatasetManager] Dataset not found: {name}")
            return {}
        
        try:
            with open(dataset_path, 'r') as f:
                data = json.load(f)
            
            log.info(f"[DatasetManager] Loaded dataset: {name}")
            
            return data
        
        except Exception as e:
            log.error(f"[DatasetManager] Failed to load dataset {name}: {e}")
            return {}
    
    async def list_datasets(self) -> List[str]:
        """List available datasets"""
        return [f.stem for f in self.dataset_dir.glob('*.json')]

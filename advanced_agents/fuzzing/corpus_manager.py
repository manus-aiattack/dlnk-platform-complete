"""
Corpus Manager for dLNk Attack Platform
Manages fuzzing corpus with intelligent selection and minimization
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import os
import hashlib
import json
from typing import Dict, List, Optional, Set
from pathlib import Path
from collections import defaultdict
import logging

log = logging.getLogger(__name__)


class CorpusManager:
    """
    Corpus Manager
    
    Features:
    - Corpus storage and retrieval
    - Coverage-based corpus minimization
    - Intelligent corpus selection
    - Corpus mutation and evolution
    - Deduplication
    """
    
    def __init__(self, corpus_dir: str = "/tmp/dlnk_corpus"):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        
        self.corpus_items = []
        self.coverage_map = defaultdict(set)  # coverage -> corpus items
        self.hash_map = {}  # hash -> corpus item
        
    async def add_corpus_item(
        self,
        data: bytes,
        coverage: Set[int] = None,
        metadata: Dict = None
    ) -> str:
        """
        Add item to corpus
        
        Args:
            data: Corpus item data
            coverage: Code coverage achieved by this input
            metadata: Additional metadata
        
        Returns:
            Corpus item ID
        """
        # Calculate hash
        item_hash = self._hash_data(data)
        
        # Check for duplicates
        if item_hash in self.hash_map:
            log.debug(f"[CorpusManager] Duplicate corpus item: {item_hash}")
            return item_hash
        
        # Create corpus item
        item = {
            'id': item_hash,
            'data': data,
            'size': len(data),
            'coverage': coverage or set(),
            'metadata': metadata or {},
            'score': 0.0
        }
        
        # Calculate score
        item['score'] = self._calculate_score(item)
        
        # Store item
        self.corpus_items.append(item)
        self.hash_map[item_hash] = item
        
        # Update coverage map
        if coverage:
            for cov_point in coverage:
                self.coverage_map[cov_point].add(item_hash)
        
        # Save to disk
        await self._save_corpus_item(item)
        
        log.info(f"[CorpusManager] Added corpus item: {item_hash} (size: {len(data)}, score: {item['score']:.2f})")
        
        return item_hash
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute attack"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Implement attack logic here
            results = {'status': 'not_implemented'}
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} executed",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _hash_data(self, data: bytes) -> str:
        """Calculate hash of data"""
        return hashlib.sha256(data).hexdigest()[:16]
    
    def _calculate_score(self, item: Dict) -> float:
        """Calculate corpus item score"""
        
        score = 0.0
        
        # Coverage score (40%)
        coverage_score = len(item['coverage']) / 1000.0  # Normalize
        score += coverage_score * 0.4
        
        # Size score (20%) - prefer smaller inputs
        size_score = 1.0 / (1.0 + item['size'] / 1000.0)
        score += size_score * 0.2
        
        # Uniqueness score (20%)
        uniqueness_score = self._calculate_uniqueness(item)
        score += uniqueness_score * 0.2
        
        # Metadata score (20%)
        if item['metadata'].get('caused_crash', False):
            score += 0.2
        elif item['metadata'].get('new_coverage', False):
            score += 0.15
        
        return score
    
    def _calculate_uniqueness(self, item: Dict) -> float:
        """Calculate uniqueness score"""
        
        # Check how many coverage points are unique to this item
        unique_coverage = 0
        for cov_point in item['coverage']:
            if len(self.coverage_map[cov_point]) == 1:
                unique_coverage += 1
        
        if not item['coverage']:
            return 0.0
        
        return unique_coverage / len(item['coverage'])
    
    async def get_corpus_items(
        self,
        count: int = None,
        min_score: float = 0.0,
        sort_by: str = 'score'
    ) -> List[Dict]:
        """
        Get corpus items
        
        Args:
            count: Maximum number of items to return
            min_score: Minimum score threshold
            sort_by: Sort criterion ('score', 'size', 'coverage')
        
        Returns:
            List of corpus items
        """
        # Filter by score
        filtered = [item for item in self.corpus_items if item['score'] >= min_score]
        
        # Sort
        if sort_by == 'score':
            filtered.sort(key=lambda x: x['score'], reverse=True)
        elif sort_by == 'size':
            filtered.sort(key=lambda x: x['size'])
        elif sort_by == 'coverage':
            filtered.sort(key=lambda x: len(x['coverage']), reverse=True)
        
        # Limit count
        if count:
            filtered = filtered[:count]
        
        return filtered
    
    async def minimize_corpus(self, target_coverage: Set[int] = None) -> int:
        """
        Minimize corpus while maintaining coverage
        
        Args:
            target_coverage: Target coverage to maintain (None = all current coverage)
        
        Returns:
            Number of items in minimized corpus
        """
        log.info("[CorpusManager] Minimizing corpus...")
        
        # Get all coverage if not specified
        if target_coverage is None:
            target_coverage = set()
            for item in self.corpus_items:
                target_coverage.update(item['coverage'])
        
        # Greedy set cover algorithm
        minimized = []
        remaining_coverage = target_coverage.copy()
        
        while remaining_coverage:
            # Find item that covers most remaining coverage
            best_item = None
            best_coverage = set()
            
            for item in self.corpus_items:
                if item in minimized:
                    continue
                
                covered = item['coverage'] & remaining_coverage
                if len(covered) > len(best_coverage):
                    best_item = item
                    best_coverage = covered
            
            if not best_item:
                break
            
            minimized.append(best_item)
            remaining_coverage -= best_coverage
        
        # Update corpus
        self.corpus_items = minimized
        
        log.info(f"[CorpusManager] Minimized corpus: {len(minimized)} items "
                f"(coverage: {len(target_coverage - remaining_coverage)}/{len(target_coverage)})")
        
        return len(minimized)
    
    async def select_interesting_items(self, count: int = 10) -> List[Dict]:
        """
        Select most interesting corpus items for mutation
        
        Args:
            count: Number of items to select
        
        Returns:
            Selected corpus items
        """
        log.info(f"[CorpusManager] Selecting {count} interesting items...")
        
        # Score all items
        scored_items = []
        for item in self.corpus_items:
            interest_score = self._calculate_interest_score(item)
            scored_items.append((interest_score, item))
        
        # Sort by interest score
        scored_items.sort(reverse=True, key=lambda x: x[0])
        
        # Select top items
        selected = [item for score, item in scored_items[:count]]
        
        return selected
    
    def _calculate_interest_score(self, item: Dict) -> float:
        """Calculate interest score for mutation selection"""
        
        score = 0.0
        
        # Recent new coverage
        if item['metadata'].get('new_coverage', False):
            score += 0.5
        
        # Caused crashes
        if item['metadata'].get('caused_crash', False):
            score += 0.3
        
        # High coverage
        coverage_score = len(item['coverage']) / 1000.0
        score += coverage_score * 0.2
        
        return score
    
    async def merge_corpus(self, other_corpus_dir: str):
        """
        Merge another corpus into this one
        
        Args:
            other_corpus_dir: Path to other corpus directory
        """
        log.info(f"[CorpusManager] Merging corpus from {other_corpus_dir}")
        
        other_dir = Path(other_corpus_dir)
        if not other_dir.exists():
            log.error(f"[CorpusManager] Corpus directory not found: {other_corpus_dir}")
            return
        
        merged_count = 0
        
        for corpus_file in other_dir.glob('corpus_*.json'):
            try:
                with open(corpus_file, 'r') as f:
                    item_data = json.load(f)
                
                # Add to corpus
                data = bytes.fromhex(item_data['data_hex'])
                coverage = set(item_data.get('coverage', []))
                metadata = item_data.get('metadata', {})
                
                await self.add_corpus_item(data, coverage, metadata)
                merged_count += 1
                
            except Exception as e:
                log.error(f"[CorpusManager] Failed to merge {corpus_file}: {e}")
        
        log.info(f"[CorpusManager] Merged {merged_count} items")
    
    async def export_corpus(self, output_dir: str, format: str = 'raw'):
        """
        Export corpus to directory
        
        Args:
            output_dir: Output directory
            format: Export format ('raw', 'json', 'hex')
        """
        log.info(f"[CorpusManager] Exporting corpus to {output_dir}")
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        for i, item in enumerate(self.corpus_items):
            if format == 'raw':
                output_file = output_path / f"corpus_{i:06d}.bin"
                with open(output_file, 'wb') as f:
                    f.write(item['data'])
            
            elif format == 'json':
                output_file = output_path / f"corpus_{i:06d}.json"
                export_data = {
                    'id': item['id'],
                    'data_hex': item['data'].hex(),
                    'size': item['size'],
                    'coverage': list(item['coverage']),
                    'metadata': item['metadata'],
                    'score': item['score']
                }
                with open(output_file, 'w') as f:
                    json.dump(export_data, f, indent=2)
            
            elif format == 'hex':
                output_file = output_path / f"corpus_{i:06d}.hex"
                with open(output_file, 'w') as f:
                    f.write(item['data'].hex())
        
        log.info(f"[CorpusManager] Exported {len(self.corpus_items)} items")
    
    async def _save_corpus_item(self, item: Dict):
        """Save corpus item to disk"""
        
        corpus_file = self.corpus_dir / f"corpus_{item['id']}.json"
        
        try:
            save_data = {
                'id': item['id'],
                'data_hex': item['data'].hex(),
                'size': item['size'],
                'coverage': list(item['coverage']),
                'metadata': item['metadata'],
                'score': item['score']
            }
            
            with open(corpus_file, 'w') as f:
                json.dump(save_data, f, indent=2)
                
        except Exception as e:
            log.error(f"[CorpusManager] Failed to save corpus item: {e}")
    
    async def load_corpus(self):
        """Load corpus from disk"""
        
        log.info("[CorpusManager] Loading corpus from disk...")
        
        self.corpus_items = []
        self.hash_map = {}
        self.coverage_map = defaultdict(set)
        
        for corpus_file in self.corpus_dir.glob('corpus_*.json'):
            try:
                with open(corpus_file, 'r') as f:
                    item_data = json.load(f)
                
                item = {
                    'id': item_data['id'],
                    'data': bytes.fromhex(item_data['data_hex']),
                    'size': item_data['size'],
                    'coverage': set(item_data['coverage']),
                    'metadata': item_data['metadata'],
                    'score': item_data['score']
                }
                
                self.corpus_items.append(item)
                self.hash_map[item['id']] = item
                
                for cov_point in item['coverage']:
                    self.coverage_map[cov_point].add(item['id'])
                
            except Exception as e:
                log.error(f"[CorpusManager] Failed to load {corpus_file}: {e}")
        
        log.info(f"[CorpusManager] Loaded {len(self.corpus_items)} corpus items")
    
    async def get_statistics(self) -> Dict:
        """Get corpus statistics"""
        
        total_coverage = set()
        for item in self.corpus_items:
            total_coverage.update(item['coverage'])
        
        sizes = [item['size'] for item in self.corpus_items]
        
        stats = {
            'total_items': len(self.corpus_items),
            'total_coverage': len(total_coverage),
            'avg_size': sum(sizes) / len(sizes) if sizes else 0,
            'min_size': min(sizes) if sizes else 0,
            'max_size': max(sizes) if sizes else 0,
            'total_size': sum(sizes)
        }
        
        return stats


if __name__ == '__main__':
    async def test():
        manager = CorpusManager()
        
        # Add some test corpus items
        test_data = [
            (b'GET / HTTP/1.1\r\n', {1, 2, 3, 4}),
            (b'POST /api HTTP/1.1\r\n', {2, 3, 5, 6}),
            (b'{"key": "value"}', {7, 8, 9}),
            (b'<xml>test</xml>', {3, 10, 11})
        ]
        
        for data, coverage in test_data:
            await manager.add_corpus_item(data, coverage)
        
        # Get statistics
        stats = await manager.get_statistics()
        print("Corpus Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Minimize corpus
        minimized_count = await manager.minimize_corpus()
        print(f"\nMinimized corpus: {minimized_count} items")
        
        # Select interesting items
        interesting = await manager.select_interesting_items(count=2)
        print(f"\nSelected {len(interesting)} interesting items")
    
    asyncio.run(test())


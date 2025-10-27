"""
Self-Learning System for dLNk Attack Platform
เรียนรู้จากการโจมตีที่สำเร็จและสร้างเทคนิคใหม่ด้วย AI
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from pathlib import Path
from collections import defaultdict
from loguru import logger


@dataclass
class AttackPattern:
    """Pattern ของการโจมตี"""
    pattern_id: str
    name: str
    attack_type: str
    techniques: List[str]
    success_rate: float
    avg_duration: float
    target_types: List[str]
    conditions: Dict[str, Any]
    payload_templates: List[str]
    learned_from: List[str]  # attack_ids
    created_at: datetime
    last_used: Optional[datetime] = None
    use_count: int = 0


@dataclass
class KnowledgeEntry:
    """รายการความรู้"""
    entry_id: str
    category: str  # technique, vulnerability, tool, payload
    title: str
    description: str
    effectiveness: float  # 0.0 - 1.0
    tags: List[str]
    examples: List[Dict[str, Any]]
    source: str  # learned, manual, ai_generated
    created_at: datetime
    confidence: float = 0.8


@dataclass
class LearningSession:
    """Session การเรียนรู้"""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime]
    attacks_analyzed: int
    patterns_discovered: int
    knowledge_gained: int
    success_rate: float
    insights: List[str]


class SelfLearningSystem:
    """
    Self-Learning System
    
    Features:
    - Learn from successful attacks
    - Generate new techniques with AI
    - Pattern recognition
    - Knowledge base management
    - Adaptive strategy selection
    - Continuous improvement
    """
    
    def __init__(
        self,
        knowledge_base_file: str = "data/knowledge_base.json",
        patterns_file: str = "data/attack_patterns.json"
    ):
        self.name = "SelfLearningSystem"
        
        # Files
        self.knowledge_base_file = Path(knowledge_base_file)
        self.patterns_file = Path(patterns_file)
        self.knowledge_base_file.parent.mkdir(parents=True, exist_ok=True)
        self.patterns_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Data structures
        self.knowledge_base: List[KnowledgeEntry] = []
        self.attack_patterns: List[AttackPattern] = []
        self.learning_sessions: List[LearningSession] = []
        
        # Statistics
        self.total_attacks_learned = 0
        self.total_patterns_discovered = 0
        self.total_knowledge_entries = 0
        
        # Load data
        self._load_knowledge_base()
        self._load_patterns()
        
        logger.info(f"[{self.name}] Initialized with {len(self.knowledge_base)} knowledge entries and {len(self.attack_patterns)} patterns")
    
    async def learn_from_attack(
        self,
        attack_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        เรียนรู้จากการโจมตี
        
        Args:
            attack_data: ข้อมูลการโจมตี
                - attack_id: str
                - attack_type: str
                - target: str
                - target_type: str
                - techniques: List[str]
                - payloads: List[str]
                - success: bool
                - duration: float
                - results: Dict
        """
        self.total_attacks_learned += 1
        
        logger.info(f"[{self.name}] Learning from attack: {attack_data.get('attack_id', 'Unknown')}")
        
        # เรียนรู้เฉพาะการโจมตีที่สำเร็จ
        if not attack_data.get("success", False):
            logger.debug(f"[{self.name}] Skipping failed attack")
            return {
                "learned": False,
                "reason": "Attack was not successful"
            }
        
        learned_items = []
        
        # 1. Extract techniques
        techniques = attack_data.get("techniques", [])
        for technique in techniques:
            entry = await self._learn_technique(technique, attack_data)
            if entry:
                learned_items.append(entry)
        
        # 2. Extract payloads
        payloads = attack_data.get("payloads", [])
        for payload in payloads:
            entry = await self._learn_payload(payload, attack_data)
            if entry:
                learned_items.append(entry)
        
        # 3. Discover patterns
        pattern = await self._discover_pattern(attack_data)
        if pattern:
            self.attack_patterns.append(pattern)
            self.total_patterns_discovered += 1
            learned_items.append(f"pattern:{pattern.pattern_id}")
        
        # 4. Extract insights
        insights = await self._extract_insights(attack_data)
        
        # Save
        self._save_knowledge_base()
        self._save_patterns()
        
        logger.success(f"[{self.name}] Learned {len(learned_items)} items from attack")
        
        return {
            "learned": True,
            "items_learned": len(learned_items),
            "patterns_discovered": 1 if pattern else 0,
            "insights": insights
        }
    
    async def _learn_technique(
        self,
        technique: str,
        attack_data: Dict[str, Any]
    ) -> Optional[str]:
        """เรียนรู้เทคนิค"""
        
        # ตรวจสอบว่ามีอยู่แล้วหรือไม่
        existing = self._find_knowledge_entry("technique", technique)
        
        if existing:
            # อัพเดท effectiveness
            existing.effectiveness = (existing.effectiveness + 1.0) / 2
            existing.examples.append({
                "attack_id": attack_data.get("attack_id"),
                "target": attack_data.get("target"),
                "success": True
            })
            logger.debug(f"[{self.name}] Updated technique: {technique}")
            return None
        else:
            # สร้างใหม่
            entry = KnowledgeEntry(
                entry_id=f"tech_{len(self.knowledge_base)}_{int(datetime.now().timestamp())}",
                category="technique",
                title=technique,
                description=f"Technique learned from attack {attack_data.get('attack_id')}",
                effectiveness=0.8,
                tags=[attack_data.get("attack_type", "unknown")],
                examples=[{
                    "attack_id": attack_data.get("attack_id"),
                    "target": attack_data.get("target"),
                    "success": True
                }],
                source="learned",
                created_at=datetime.now()
            )
            
            self.knowledge_base.append(entry)
            self.total_knowledge_entries += 1
            
            logger.success(f"[{self.name}] Learned new technique: {technique}")
            return entry.entry_id
    
    async def _learn_payload(
        self,
        payload: str,
        attack_data: Dict[str, Any]
    ) -> Optional[str]:
        """เรียนรู้ payload"""
        
        # ตรวจสอบว่ามีอยู่แล้วหรือไม่
        existing = self._find_knowledge_entry("payload", payload)
        
        if existing:
            existing.effectiveness = (existing.effectiveness + 1.0) / 2
            return None
        else:
            entry = KnowledgeEntry(
                entry_id=f"payload_{len(self.knowledge_base)}_{int(datetime.now().timestamp())}",
                category="payload",
                title=payload[:50],  # Truncate
                description=f"Payload learned from attack {attack_data.get('attack_id')}",
                effectiveness=0.8,
                tags=[attack_data.get("attack_type", "unknown")],
                examples=[{
                    "attack_id": attack_data.get("attack_id"),
                    "payload": payload,
                    "success": True
                }],
                source="learned",
                created_at=datetime.now()
            )
            
            self.knowledge_base.append(entry)
            self.total_knowledge_entries += 1
            
            logger.success(f"[{self.name}] Learned new payload")
            return entry.entry_id
    
    async def _discover_pattern(
        self,
        attack_data: Dict[str, Any]
    ) -> Optional[AttackPattern]:
        """ค้นหา pattern ใหม่"""
        
        attack_type = attack_data.get("attack_type", "unknown")
        techniques = attack_data.get("techniques", [])
        target_type = attack_data.get("target_type", "unknown")
        
        # ตรวจสอบว่ามี pattern คล้ายกันหรือไม่
        similar_pattern = self._find_similar_pattern(attack_type, techniques)
        
        if similar_pattern:
            # อัพเดท pattern ที่มีอยู่
            similar_pattern.use_count += 1
            similar_pattern.last_used = datetime.now()
            similar_pattern.learned_from.append(attack_data.get("attack_id", "unknown"))
            
            # อัพเดท success rate
            similar_pattern.success_rate = (similar_pattern.success_rate + 1.0) / 2
            
            logger.debug(f"[{self.name}] Updated existing pattern: {similar_pattern.name}")
            return None
        else:
            # สร้าง pattern ใหม่
            pattern = AttackPattern(
                pattern_id=f"pattern_{len(self.attack_patterns)}_{int(datetime.now().timestamp())}",
                name=f"{attack_type}_pattern_{len(self.attack_patterns)}",
                attack_type=attack_type,
                techniques=techniques,
                success_rate=1.0,
                avg_duration=attack_data.get("duration", 0.0),
                target_types=[target_type],
                conditions=attack_data.get("conditions", {}),
                payload_templates=attack_data.get("payloads", []),
                learned_from=[attack_data.get("attack_id", "unknown")],
                created_at=datetime.now()
            )
            
            logger.success(f"[{self.name}] Discovered new pattern: {pattern.name}")
            return pattern
    
    async def _extract_insights(
        self,
        attack_data: Dict[str, Any]
    ) -> List[str]:
        """สกัดความรู้เชิงลึก"""
        insights = []
        
        # Insight 1: Success factors
        if attack_data.get("success"):
            insights.append(f"Attack type '{attack_data.get('attack_type')}' is effective against '{attack_data.get('target_type')}'")
        
        # Insight 2: Timing
        duration = attack_data.get("duration", 0)
        if duration < 10:
            insights.append(f"Fast execution ({duration:.2f}s) contributed to success")
        
        # Insight 3: Techniques combination
        techniques = attack_data.get("techniques", [])
        if len(techniques) > 1:
            insights.append(f"Combination of {len(techniques)} techniques was effective")
        
        return insights
    
    def _find_knowledge_entry(
        self,
        category: str,
        title: str
    ) -> Optional[KnowledgeEntry]:
        """ค้นหา knowledge entry"""
        for entry in self.knowledge_base:
            if entry.category == category and entry.title == title:
                return entry
        return None
    
    def _find_similar_pattern(
        self,
        attack_type: str,
        techniques: List[str]
    ) -> Optional[AttackPattern]:
        """ค้นหา pattern ที่คล้ายกัน"""
        for pattern in self.attack_patterns:
            if pattern.attack_type == attack_type:
                # เช็คว่า techniques ซ้ำกันมากกว่า 50%
                common = set(pattern.techniques) & set(techniques)
                if len(common) / max(len(pattern.techniques), len(techniques)) > 0.5:
                    return pattern
        return None
    
    async def generate_new_technique(
        self,
        attack_type: str,
        target_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        สร้างเทคนิคใหม่ด้วย AI
        
        Args:
            attack_type: ประเภทการโจมตี
            target_type: ประเภท target
            context: ข้อมูลเพิ่มเติม
        """
        logger.info(f"[{self.name}] Generating new technique for {attack_type} on {target_type}")
        
        # ค้นหา knowledge ที่เกี่ยวข้อง
        relevant_knowledge = self._get_relevant_knowledge(attack_type, target_type)
        
        # ค้นหา patterns ที่เกี่ยวข้อง
        relevant_patterns = [
            p for p in self.attack_patterns
            if p.attack_type == attack_type or target_type in p.target_types
        ]
        
        # สร้างเทคนิคใหม่โดยการผสมผสาน
        new_technique = {
            "name": f"AI_Generated_{attack_type}_{int(datetime.now().timestamp())}",
            "attack_type": attack_type,
            "target_type": target_type,
            "techniques": [],
            "payloads": [],
            "confidence": 0.7,
            "based_on": []
        }
        
        # รวม techniques จาก patterns
        for pattern in relevant_patterns[:3]:  # Top 3
            new_technique["techniques"].extend(pattern.techniques)
            new_technique["payloads"].extend(pattern.payload_templates)
            new_technique["based_on"].append(pattern.pattern_id)
        
        # ลบ duplicates
        new_technique["techniques"] = list(set(new_technique["techniques"]))
        new_technique["payloads"] = list(set(new_technique["payloads"]))
        
        logger.success(f"[{self.name}] Generated new technique with {len(new_technique['techniques'])} techniques")
        
        return new_technique
    
    def _get_relevant_knowledge(
        self,
        attack_type: str,
        target_type: str
    ) -> List[KnowledgeEntry]:
        """ดึง knowledge ที่เกี่ยวข้อง"""
        relevant = []
        
        for entry in self.knowledge_base:
            if attack_type in entry.tags or target_type in entry.tags:
                relevant.append(entry)
        
        # เรียงตาม effectiveness
        relevant.sort(key=lambda x: x.effectiveness, reverse=True)
        
        return relevant[:10]  # Top 10
    
    def recommend_attack_strategy(
        self,
        target_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        แนะนำกลยุทธ์การโจมตีที่เหมาะสม
        
        Args:
            target_info: ข้อมูล target
                - target_type: str
                - technologies: List[str]
                - vulnerabilities: List[str]
        """
        target_type = target_info.get("target_type", "unknown")
        
        logger.info(f"[{self.name}] Recommending strategy for {target_type}")
        
        # ค้นหา patterns ที่เหมาะสม
        suitable_patterns = [
            p for p in self.attack_patterns
            if target_type in p.target_types
        ]
        
        # เรียงตาม success rate
        suitable_patterns.sort(key=lambda x: x.success_rate, reverse=True)
        
        if not suitable_patterns:
            logger.warning(f"[{self.name}] No suitable patterns found")
            return {
                "recommended": False,
                "reason": "No suitable patterns in knowledge base"
            }
        
        best_pattern = suitable_patterns[0]
        
        recommendation = {
            "recommended": True,
            "pattern": {
                "name": best_pattern.name,
                "attack_type": best_pattern.attack_type,
                "techniques": best_pattern.techniques,
                "success_rate": best_pattern.success_rate,
                "avg_duration": best_pattern.avg_duration
            },
            "confidence": best_pattern.success_rate,
            "alternatives": [
                {
                    "name": p.name,
                    "success_rate": p.success_rate
                }
                for p in suitable_patterns[1:4]  # Top 3 alternatives
            ]
        }
        
        logger.success(f"[{self.name}] Recommended: {best_pattern.name} (success rate: {best_pattern.success_rate:.2%})")
        
        return recommendation
    
    def get_statistics(self) -> Dict[str, Any]:
        """ดึงสถิติ"""
        return {
            "total_attacks_learned": self.total_attacks_learned,
            "total_patterns_discovered": self.total_patterns_discovered,
            "total_knowledge_entries": self.total_knowledge_entries,
            "knowledge_base_size": len(self.knowledge_base),
            "attack_patterns_count": len(self.attack_patterns),
            "learning_sessions": len(self.learning_sessions),
            "avg_pattern_success_rate": sum(p.success_rate for p in self.attack_patterns) / len(self.attack_patterns) if self.attack_patterns else 0
        }
    
    def get_knowledge_summary(self) -> Dict[str, Any]:
        """สรุป knowledge base"""
        by_category = defaultdict(int)
        by_source = defaultdict(int)
        
        for entry in self.knowledge_base:
            by_category[entry.category] += 1
            by_source[entry.source] += 1
        
        return {
            "total_entries": len(self.knowledge_base),
            "by_category": dict(by_category),
            "by_source": dict(by_source),
            "top_techniques": [
                {
                    "title": e.title,
                    "effectiveness": e.effectiveness
                }
                for e in sorted(self.knowledge_base, key=lambda x: x.effectiveness, reverse=True)[:5]
            ]
        }
    
    def _load_knowledge_base(self):
        """โหลด knowledge base"""
        if not self.knowledge_base_file.exists():
            return
        
        try:
            with open(self.knowledge_base_file, 'r') as f:
                data = json.load(f)
            
            for item in data:
                entry = KnowledgeEntry(
                    entry_id=item["entry_id"],
                    category=item["category"],
                    title=item["title"],
                    description=item["description"],
                    effectiveness=item["effectiveness"],
                    tags=item["tags"],
                    examples=item["examples"],
                    source=item["source"],
                    created_at=datetime.fromisoformat(item["created_at"]),
                    confidence=item.get("confidence", 0.8)
                )
                self.knowledge_base.append(entry)
            
            logger.info(f"[{self.name}] Loaded {len(self.knowledge_base)} knowledge entries")
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to load knowledge base: {e}")
    
    def _save_knowledge_base(self):
        """บันทึก knowledge base"""
        try:
            data = []
            for entry in self.knowledge_base:
                data.append({
                    "entry_id": entry.entry_id,
                    "category": entry.category,
                    "title": entry.title,
                    "description": entry.description,
                    "effectiveness": entry.effectiveness,
                    "tags": entry.tags,
                    "examples": entry.examples,
                    "source": entry.source,
                    "created_at": entry.created_at.isoformat(),
                    "confidence": entry.confidence
                })
            
            with open(self.knowledge_base_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to save knowledge base: {e}")
    
    def _load_patterns(self):
        """โหลด attack patterns"""
        if not self.patterns_file.exists():
            return
        
        try:
            with open(self.patterns_file, 'r') as f:
                data = json.load(f)
            
            for item in data:
                pattern = AttackPattern(
                    pattern_id=item["pattern_id"],
                    name=item["name"],
                    attack_type=item["attack_type"],
                    techniques=item["techniques"],
                    success_rate=item["success_rate"],
                    avg_duration=item["avg_duration"],
                    target_types=item["target_types"],
                    conditions=item["conditions"],
                    payload_templates=item["payload_templates"],
                    learned_from=item["learned_from"],
                    created_at=datetime.fromisoformat(item["created_at"]),
                    last_used=datetime.fromisoformat(item["last_used"]) if item.get("last_used") else None,
                    use_count=item.get("use_count", 0)
                )
                self.attack_patterns.append(pattern)
            
            logger.info(f"[{self.name}] Loaded {len(self.attack_patterns)} attack patterns")
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to load patterns: {e}")
    
    def _save_patterns(self):
        """บันทึก attack patterns"""
        try:
            data = []
            for pattern in self.attack_patterns:
                data.append({
                    "pattern_id": pattern.pattern_id,
                    "name": pattern.name,
                    "attack_type": pattern.attack_type,
                    "techniques": pattern.techniques,
                    "success_rate": pattern.success_rate,
                    "avg_duration": pattern.avg_duration,
                    "target_types": pattern.target_types,
                    "conditions": pattern.conditions,
                    "payload_templates": pattern.payload_templates,
                    "learned_from": pattern.learned_from,
                    "created_at": pattern.created_at.isoformat(),
                    "last_used": pattern.last_used.isoformat() if pattern.last_used else None,
                    "use_count": pattern.use_count
                })
            
            with open(self.patterns_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to save patterns: {e}")


# Singleton instance
self_learning = SelfLearningSystem()


# Helper functions
async def learn_from_attack(attack_data: Dict[str, Any]) -> Dict[str, Any]:
    """Learn from attack wrapper"""
    return await self_learning.learn_from_attack(attack_data)


async def generate_new_technique(
    attack_type: str,
    target_type: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Generate new technique wrapper"""
    return await self_learning.generate_new_technique(attack_type, target_type, context)


def recommend_attack_strategy(target_info: Dict[str, Any]) -> Dict[str, Any]:
    """Recommend attack strategy wrapper"""
    return self_learning.recommend_attack_strategy(target_info)


"""
Attack Service for dLNk Attack Platform
Unified attack management across CLI, Web, and API
"""

import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum
from dataclasses import dataclass, asdict
import json


class AttackType(str, Enum):
    """Attack types"""
    FULL_AUTO = "full_auto"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    ZERO_DAY_HUNT = "zero_day_hunt"


class AttackStatus(str, Enum):
    """Attack status"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Attack:
    """Attack data model"""
    id: str
    user_id: str
    target_url: str
    attack_type: AttackType
    status: AttackStatus
    progress: int  # 0-100
    phase: str
    vulnerabilities_found: int
    start_time: str
    end_time: Optional[str]
    result: Optional[Dict[str, Any]]
    error: Optional[str]
    metadata: Dict[str, Any]


@dataclass
class AttackResults:
    """Attack results data model"""
    attack_id: str
    target_url: str
    attack_type: str
    status: str
    vulnerabilities: List[Dict[str, Any]]
    exfiltrated_data: List[Dict[str, Any]]
    shells: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    report_url: Optional[str]
    execution_time: float
    metadata: Dict[str, Any]


class AttackService:
    """
    Unified Attack Service
    
    Manages attack lifecycle across all interfaces (CLI, Web, API)
    """
    
    def __init__(self, database_service, orchestrator, context_manager):
        """
        Initialize Attack Service
        
        Args:
            database_service: Database service instance
            orchestrator: Attack orchestrator instance
            context_manager: Context manager for attack state
        """
        self.db = database_service
        self.orchestrator = orchestrator
        self.context = context_manager
        self.active_attacks: Dict[str, Attack] = {}
    
    async def start_attack(
        self,
        target_url: str,
        attack_type: AttackType,
        user_id: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Attack:
        """
        Start a new attack
        
        Args:
            target_url: Target URL to attack
            attack_type: Type of attack to perform
            user_id: User ID initiating the attack
            options: Additional attack options
            
        Returns:
            Attack object with attack details
        """
        attack_id = str(uuid.uuid4())
        
        attack = Attack(
            id=attack_id,
            user_id=user_id,
            target_url=target_url,
            attack_type=attack_type,
            status=AttackStatus.PENDING,
            progress=0,
            phase="initialization",
            vulnerabilities_found=0,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            result=None,
            error=None,
            metadata=options or {}
        )
        
        # Store in database
        await self.db.create_attack(asdict(attack))
        
        # Store in active attacks
        self.active_attacks[attack_id] = attack
        
        # Initialize context
        await self.context.initialize_attack(attack_id, target_url)
        
        # Start attack in background
        asyncio.create_task(self._execute_attack(attack))
        
        return attack
    
    async def _execute_attack(self, attack: Attack):
        """
        Execute attack in background
        
        Args:
            attack: Attack object to execute
        """
        try:
            # Update status to running
            attack.status = AttackStatus.RUNNING
            await self._update_attack(attack)
            
            # Execute attack via orchestrator
            result = await self.orchestrator.execute_attack(
                target_url=attack.target_url,
                attack_type=attack.attack_type.value,
                attack_id=attack.id,
                options=attack.metadata
            )
            
            # Update with results
            attack.status = AttackStatus.COMPLETED
            attack.progress = 100
            attack.end_time = datetime.utcnow().isoformat()
            attack.result = result
            attack.vulnerabilities_found = len(result.get("vulnerabilities", []))
            
        except Exception as e:
            attack.status = AttackStatus.FAILED
            attack.error = str(e)
            attack.end_time = datetime.utcnow().isoformat()
        
        finally:
            await self._update_attack(attack)
    
    async def stop_attack(self, attack_id: str) -> bool:
        """
        Stop a running attack
        
        Args:
            attack_id: Attack ID to stop
            
        Returns:
            True if stopped successfully
        """
        attack = self.active_attacks.get(attack_id)
        if not attack:
            return False
        
        if attack.status != AttackStatus.RUNNING:
            return False
        
        # Stop orchestrator
        await self.orchestrator.stop_attack(attack_id)
        
        # Update status
        attack.status = AttackStatus.CANCELLED
        attack.end_time = datetime.utcnow().isoformat()
        await self._update_attack(attack)
        
        return True
    
    async def get_attack_status(self, attack_id: str) -> Optional[Attack]:
        """
        Get attack status
        
        Args:
            attack_id: Attack ID
            
        Returns:
            Attack object or None if not found
        """
        # Try active attacks first
        if attack_id in self.active_attacks:
            return self.active_attacks[attack_id]
        
        # Try database
        attack_data = await self.db.get_attack(attack_id)
        if attack_data:
            return Attack(**attack_data)
        
        return None
    
    async def get_attack_results(self, attack_id: str) -> Optional[AttackResults]:
        """
        Get attack results
        
        Args:
            attack_id: Attack ID
            
        Returns:
            AttackResults object or None if not found
        """
        attack = await self.get_attack_status(attack_id)
        if not attack or not attack.result:
            return None
        
        execution_time = 0
        if attack.start_time and attack.end_time:
            start = datetime.fromisoformat(attack.start_time)
            end = datetime.fromisoformat(attack.end_time)
            execution_time = (end - start).total_seconds()
        
        return AttackResults(
            attack_id=attack.id,
            target_url=attack.target_url,
            attack_type=attack.attack_type.value,
            status=attack.status.value,
            vulnerabilities=attack.result.get("vulnerabilities", []),
            exfiltrated_data=attack.result.get("exfiltrated_data", []),
            shells=attack.result.get("shells", []),
            credentials=attack.result.get("credentials", []),
            report_url=attack.result.get("report_url"),
            execution_time=execution_time,
            metadata=attack.metadata
        )
    
    async def list_attacks(
        self,
        user_id: Optional[str] = None,
        status: Optional[AttackStatus] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Attack]:
        """
        List attacks with filters
        
        Args:
            user_id: Filter by user ID
            status: Filter by status
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List of Attack objects
        """
        filters = {}
        if user_id:
            filters["user_id"] = user_id
        if status:
            filters["status"] = status.value
        
        attacks_data = await self.db.list_attacks(filters, limit, offset)
        return [Attack(**data) for data in attacks_data]
    
    async def delete_attack(self, attack_id: str) -> bool:
        """
        Delete an attack
        
        Args:
            attack_id: Attack ID to delete
            
        Returns:
            True if deleted successfully
        """
        # Remove from active attacks
        if attack_id in self.active_attacks:
            del self.active_attacks[attack_id]
        
        # Delete from database
        return await self.db.delete_attack(attack_id)
    
    async def _update_attack(self, attack: Attack):
        """
        Update attack in database and active attacks
        
        Args:
            attack: Attack object to update
        """
        await self.db.update_attack(attack.id, asdict(attack))
        self.active_attacks[attack.id] = attack
    
    async def get_active_attacks_count(self) -> int:
        """
        Get count of active attacks
        
        Returns:
            Number of active attacks
        """
        return len([
            a for a in self.active_attacks.values()
            if a.status == AttackStatus.RUNNING
        ])
    
    async def pause_attack(self, attack_id: str) -> bool:
        """
        Pause a running attack
        
        Args:
            attack_id: Attack ID to pause
            
        Returns:
            True if paused successfully
        """
        attack = self.active_attacks.get(attack_id)
        if not attack or attack.status != AttackStatus.RUNNING:
            return False
        
        attack.status = AttackStatus.PAUSED
        await self._update_attack(attack)
        return True
    
    async def resume_attack(self, attack_id: str) -> bool:
        """
        Resume a paused attack
        
        Args:
            attack_id: Attack ID to resume
            
        Returns:
            True if resumed successfully
        """
        attack = self.active_attacks.get(attack_id)
        if not attack or attack.status != AttackStatus.PAUSED:
            return False
        
        attack.status = AttackStatus.RUNNING
        await self._update_attack(attack)
        
        # Resume execution
        asyncio.create_task(self._execute_attack(attack))
        return True


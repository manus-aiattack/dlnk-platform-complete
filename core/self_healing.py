"""
Self-Healing System for dLNk Attack Platform
Auto-detect และ auto-recovery จากข้อผิดพลาด
"""

import asyncio
import time
import traceback
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
import json
from loguru import logger


class ErrorSeverity(Enum):
    """ระดับความรุนแรงของ error"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """กลยุทธ์การ recovery"""
    RETRY = "retry"
    FALLBACK = "fallback"
    RESTART = "restart"
    SKIP = "skip"
    MANUAL = "manual"


@dataclass
class ErrorRecord:
    """บันทึก error"""
    error_id: str
    timestamp: datetime
    error_type: str
    error_message: str
    component: str
    severity: ErrorSeverity
    context: Dict[str, Any]
    stack_trace: Optional[str] = None
    recovery_attempted: bool = False
    recovery_strategy: Optional[RecoveryStrategy] = None
    recovery_success: bool = False
    retry_count: int = 0


@dataclass
class RecoveryAction:
    """การกระทำเพื่อ recovery"""
    action_type: RecoveryStrategy
    max_retries: int = 3
    retry_delay: float = 1.0  # seconds
    exponential_backoff: bool = True
    fallback_func: Optional[Callable] = None
    restart_component: Optional[str] = None


class SelfHealingSystem:
    """
    Self-Healing System
    
    Features:
    - Auto-detect errors
    - Auto-recovery strategies
    - Exponential backoff retry
    - Error history logging
    - Pattern recognition
    - Predictive healing
    """
    
    def __init__(self, history_file: str = "logs/error_history.json"):
        self.name = "SelfHealingSystem"
        self.error_history: List[ErrorRecord] = []
        self.recovery_strategies: Dict[str, RecoveryAction] = {}
        self.history_file = Path(history_file)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.total_errors = 0
        self.total_recoveries = 0
        self.successful_recoveries = 0
        
        # Load history
        self._load_history()
        
        # Register default strategies
        self._register_default_strategies()
        
        logger.info(f"[{self.name}] Initialized")
    
    def _register_default_strategies(self):
        """ลงทะเบียน recovery strategies เริ่มต้น"""
        
        # Network errors - retry with backoff
        self.register_strategy(
            "NetworkError",
            RecoveryAction(
                action_type=RecoveryStrategy.RETRY,
                max_retries=5,
                retry_delay=2.0,
                exponential_backoff=True
            )
        )
        
        # Timeout errors - retry with longer delay
        self.register_strategy(
            "TimeoutError",
            RecoveryAction(
                action_type=RecoveryStrategy.RETRY,
                max_retries=3,
                retry_delay=5.0,
                exponential_backoff=True
            )
        )
        
        # Connection errors - retry
        self.register_strategy(
            "ConnectionError",
            RecoveryAction(
                action_type=RecoveryStrategy.RETRY,
                max_retries=5,
                retry_delay=3.0,
                exponential_backoff=True
            )
        )
        
        # Rate limit - wait and retry
        self.register_strategy(
            "RateLimitError",
            RecoveryAction(
                action_type=RecoveryStrategy.RETRY,
                max_retries=10,
                retry_delay=60.0,
                exponential_backoff=False
            )
        )
        
        # Authentication errors - manual intervention
        self.register_strategy(
            "AuthenticationError",
            RecoveryAction(
                action_type=RecoveryStrategy.MANUAL,
                max_retries=0
            )
        )
        
        # Resource errors - fallback
        self.register_strategy(
            "ResourceError",
            RecoveryAction(
                action_type=RecoveryStrategy.FALLBACK,
                max_retries=1
            )
        )
    
    def register_strategy(self, error_type: str, action: RecoveryAction):
        """ลงทะเบียน recovery strategy"""
        self.recovery_strategies[error_type] = action
        logger.debug(f"[{self.name}] Registered strategy for {error_type}: {action.action_type.value}")
    
    async def handle_error(
        self,
        error: Exception,
        component: str,
        context: Optional[Dict[str, Any]] = None,
        func: Optional[Callable] = None,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        จัดการ error และพยายาม recovery
        
        Args:
            error: Exception ที่เกิดขึ้น
            component: component ที่เกิด error
            context: ข้อมูลบริบท
            func: function ที่จะ retry (ถ้ามี)
            *args, **kwargs: arguments สำหรับ func
        
        Returns:
            ผลลัพธ์การ recovery
        """
        self.total_errors += 1
        
        # สร้าง error record
        error_record = ErrorRecord(
            error_id=f"ERR_{int(time.time())}_{self.total_errors}",
            timestamp=datetime.now(),
            error_type=type(error).__name__,
            error_message=str(error),
            component=component,
            severity=self._determine_severity(error),
            context=context or {},
            stack_trace=traceback.format_exc()
        )
        
        logger.error(f"[{self.name}] Error detected: {error_record.error_type} in {component}")
        logger.error(f"[{self.name}] Message: {error_record.error_message}")
        
        # บันทึก error
        self.error_history.append(error_record)
        
        # ตรวจสอบว่ามี recovery strategy หรือไม่
        strategy = self.recovery_strategies.get(error_record.error_type)
        
        if not strategy:
            logger.warning(f"[{self.name}] No recovery strategy for {error_record.error_type}")
            self._save_history()
            return {
                "success": False,
                "error_id": error_record.error_id,
                "recovery_attempted": False,
                "message": "No recovery strategy available"
            }
        
        # พยายาม recovery
        error_record.recovery_attempted = True
        error_record.recovery_strategy = strategy.action_type
        
        self.total_recoveries += 1
        
        result = await self._execute_recovery(
            error_record,
            strategy,
            func,
            *args,
            **kwargs
        )
        
        # อัพเดท record
        error_record.recovery_success = result["success"]
        error_record.retry_count = result.get("retry_count", 0)
        
        if result["success"]:
            self.successful_recoveries += 1
            logger.success(f"[{self.name}] Recovery successful for {error_record.error_id}")
        else:
            logger.error(f"[{self.name}] Recovery failed for {error_record.error_id}")
        
        # บันทึก history
        self._save_history()
        
        return result
    
    async def _execute_recovery(
        self,
        error_record: ErrorRecord,
        strategy: RecoveryAction,
        func: Optional[Callable],
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        ดำเนินการ recovery ตาม strategy
        """
        if strategy.action_type == RecoveryStrategy.RETRY:
            return await self._retry_with_backoff(
                error_record,
                strategy,
                func,
                *args,
                **kwargs
            )
        
        elif strategy.action_type == RecoveryStrategy.FALLBACK:
            return await self._fallback_recovery(
                error_record,
                strategy,
                *args,
                **kwargs
            )
        
        elif strategy.action_type == RecoveryStrategy.RESTART:
            return await self._restart_component(
                error_record,
                strategy
            )
        
        elif strategy.action_type == RecoveryStrategy.SKIP:
            return {
                "success": True,
                "message": "Error skipped",
                "action": "skip"
            }
        
        elif strategy.action_type == RecoveryStrategy.MANUAL:
            return {
                "success": False,
                "message": "Manual intervention required",
                "action": "manual"
            }
        
        return {
            "success": False,
            "message": "Unknown recovery strategy"
        }
    
    async def _retry_with_backoff(
        self,
        error_record: ErrorRecord,
        strategy: RecoveryAction,
        func: Optional[Callable],
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Retry พร้อม exponential backoff
        """
        if not func:
            return {
                "success": False,
                "message": "No function to retry"
            }
        
        retry_count = 0
        last_error = None
        
        while retry_count < strategy.max_retries:
            retry_count += 1
            
            # คำนวณ delay
            if strategy.exponential_backoff:
                delay = strategy.retry_delay * (2 ** (retry_count - 1))
            else:
                delay = strategy.retry_delay
            
            logger.info(f"[{self.name}] Retry {retry_count}/{strategy.max_retries} after {delay}s")
            
            await asyncio.sleep(delay)
            
            try:
                # ลอง execute function
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                logger.success(f"[{self.name}] Retry successful on attempt {retry_count}")
                
                return {
                    "success": True,
                    "result": result,
                    "retry_count": retry_count,
                    "action": "retry"
                }
            
            except Exception as e:
                last_error = e
                logger.warning(f"[{self.name}] Retry {retry_count} failed: {e}")
        
        return {
            "success": False,
            "message": f"All {strategy.max_retries} retries failed",
            "last_error": str(last_error),
            "retry_count": retry_count,
            "action": "retry"
        }
    
    async def _fallback_recovery(
        self,
        error_record: ErrorRecord,
        strategy: RecoveryAction,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        ใช้ fallback function
        """
        if not strategy.fallback_func:
            return {
                "success": False,
                "message": "No fallback function available"
            }
        
        try:
            logger.info(f"[{self.name}] Executing fallback function")
            
            if asyncio.iscoroutinefunction(strategy.fallback_func):
                result = await strategy.fallback_func(*args, **kwargs)
            else:
                result = strategy.fallback_func(*args, **kwargs)
            
            logger.success(f"[{self.name}] Fallback successful")
            
            return {
                "success": True,
                "result": result,
                "action": "fallback"
            }
        
        except Exception as e:
            logger.error(f"[{self.name}] Fallback failed: {e}")
            return {
                "success": False,
                "message": f"Fallback failed: {e}",
                "action": "fallback"
            }
    
    async def _restart_component(
        self,
        error_record: ErrorRecord,
        strategy: RecoveryAction
    ) -> Dict[str, Any]:
        """
        Restart component
        """
        component = strategy.restart_component or error_record.component
        
        logger.info(f"[{self.name}] Restarting component: {component}")
        
        # TODO: Implement component restart logic
        # This would depend on how components are managed
        
        return {
            "success": False,
            "message": "Component restart not implemented yet",
            "action": "restart"
        }
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """กำหนดระดับความรุนแรงของ error"""
        error_type = type(error).__name__
        
        critical_errors = [
            "SystemExit",
            "KeyboardInterrupt",
            "MemoryError",
            "OSError"
        ]
        
        high_errors = [
            "AuthenticationError",
            "PermissionError",
            "DatabaseError"
        ]
        
        medium_errors = [
            "TimeoutError",
            "ConnectionError",
            "ValueError"
        ]
        
        if error_type in critical_errors:
            return ErrorSeverity.CRITICAL
        elif error_type in high_errors:
            return ErrorSeverity.HIGH
        elif error_type in medium_errors:
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _load_history(self):
        """โหลด error history จากไฟล์"""
        if not self.history_file.exists():
            return
        
        try:
            with open(self.history_file, 'r') as f:
                data = json.load(f)
            
            # Convert to ErrorRecord objects
            for item in data:
                record = ErrorRecord(
                    error_id=item["error_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    error_type=item["error_type"],
                    error_message=item["error_message"],
                    component=item["component"],
                    severity=ErrorSeverity(item["severity"]),
                    context=item.get("context", {}),
                    stack_trace=item.get("stack_trace"),
                    recovery_attempted=item.get("recovery_attempted", False),
                    recovery_strategy=RecoveryStrategy(item["recovery_strategy"]) if item.get("recovery_strategy") else None,
                    recovery_success=item.get("recovery_success", False),
                    retry_count=item.get("retry_count", 0)
                )
                self.error_history.append(record)
            
            logger.info(f"[{self.name}] Loaded {len(self.error_history)} error records")
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to load history: {e}")
    
    def _save_history(self):
        """บันทึก error history ลงไฟล์"""
        try:
            data = []
            for record in self.error_history:
                data.append({
                    "error_id": record.error_id,
                    "timestamp": record.timestamp.isoformat(),
                    "error_type": record.error_type,
                    "error_message": record.error_message,
                    "component": record.component,
                    "severity": record.severity.value,
                    "context": record.context,
                    "stack_trace": record.stack_trace,
                    "recovery_attempted": record.recovery_attempted,
                    "recovery_strategy": record.recovery_strategy.value if record.recovery_strategy else None,
                    "recovery_success": record.recovery_success,
                    "retry_count": record.retry_count
                })
            
            with open(self.history_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to save history: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """ดึงสถิติ"""
        recent_errors = [
            r for r in self.error_history
            if r.timestamp > datetime.now() - timedelta(hours=24)
        ]
        
        return {
            "total_errors": self.total_errors,
            "total_recoveries": self.total_recoveries,
            "successful_recoveries": self.successful_recoveries,
            "success_rate": self.successful_recoveries / self.total_recoveries if self.total_recoveries > 0 else 0,
            "recent_errors_24h": len(recent_errors),
            "error_history_size": len(self.error_history),
            "registered_strategies": len(self.recovery_strategies)
        }
    
    def get_error_patterns(self) -> Dict[str, Any]:
        """วิเคราะห์ pattern ของ error"""
        error_types = {}
        component_errors = {}
        
        for record in self.error_history:
            # Count by error type
            if record.error_type not in error_types:
                error_types[record.error_type] = 0
            error_types[record.error_type] += 1
            
            # Count by component
            if record.component not in component_errors:
                component_errors[record.component] = 0
            component_errors[record.component] += 1
        
        return {
            "error_types": error_types,
            "component_errors": component_errors,
            "most_common_error": max(error_types.items(), key=lambda x: x[1])[0] if error_types else None,
            "most_problematic_component": max(component_errors.items(), key=lambda x: x[1])[0] if component_errors else None
        }
    
    def clear_old_history(self, days: int = 30):
        """ลบ history เก่า"""
        cutoff = datetime.now() - timedelta(days=days)
        
        before = len(self.error_history)
        self.error_history = [
            r for r in self.error_history
            if r.timestamp > cutoff
        ]
        after = len(self.error_history)
        
        removed = before - after
        logger.info(f"[{self.name}] Cleared {removed} old error records")
        
        self._save_history()
        
        return removed


# Singleton instance
self_healing = SelfHealingSystem()


# Decorator for auto-healing
def auto_heal(component: str, context: Optional[Dict[str, Any]] = None):
    """
    Decorator สำหรับ auto-healing
    
    Usage:
        @auto_heal("MyComponent")
        async def my_function():
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                result = await self_healing.handle_error(
                    e,
                    component,
                    context,
                    func,
                    *args,
                    **kwargs
                )
                
                if result["success"]:
                    return result.get("result")
                else:
                    raise e
        
        return wrapper
    return decorator


"""
Zero-Day Hunter Notification System
แจ้งเตือน user เกี่ยวกับ progress และ estimated time
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from enum import Enum

log = logging.getLogger(__name__)


class ZeroDayPhase(Enum):
    """Phases of Zero-Day discovery"""
    INITIALIZING = "initializing"
    FUZZING = "fuzzing"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    TAINT_ANALYSIS = "taint_analysis"
    CRASH_ANALYSIS = "crash_analysis"
    EXPLOIT_GENERATION = "exploit_generation"
    EXPLOIT_VALIDATION = "exploit_validation"
    COMPLETED = "completed"


class NotificationLevel(Enum):
    """Notification importance levels"""
    INFO = "info"
    WARNING = "warning"
    SUCCESS = "success"
    ERROR = "error"


class ZeroDayNotification:
    """Notification message"""
    
    def __init__(
        self,
        level: NotificationLevel,
        phase: ZeroDayPhase,
        message: str,
        progress: float = 0.0,
        estimated_time_remaining: Optional[int] = None,
        details: Optional[Dict] = None
    ):
        self.level = level
        self.phase = phase
        self.message = message
        self.progress = progress  # 0.0 to 1.0
        self.estimated_time_remaining = estimated_time_remaining  # seconds
        self.details = details or {}
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'level': self.level.value,
            'phase': self.phase.value,
            'message': self.message,
            'progress': self.progress,
            'estimated_time_remaining': self.estimated_time_remaining,
            'details': self.details,
            'timestamp': self.timestamp.isoformat()
        }


class ZeroDayNotificationSystem:
    """
    Notification system for Zero-Day Hunter
    Tracks progress and sends notifications to user
    """
    
    def __init__(self):
        self.callbacks: List[Callable] = []
        self.current_phase: Optional[ZeroDayPhase] = None
        self.start_time: Optional[datetime] = None
        self.phase_start_times: Dict[ZeroDayPhase, datetime] = {}
        self.phase_durations: Dict[ZeroDayPhase, int] = {}  # seconds
        self.notifications: List[ZeroDayNotification] = []
        
        # Estimated durations for each phase (in seconds)
        self.estimated_phase_durations = {
            ZeroDayPhase.INITIALIZING: 30,
            ZeroDayPhase.FUZZING: 3600,  # 1 hour
            ZeroDayPhase.SYMBOLIC_EXECUTION: 1800,  # 30 minutes
            ZeroDayPhase.TAINT_ANALYSIS: 900,  # 15 minutes
            ZeroDayPhase.CRASH_ANALYSIS: 300,  # 5 minutes
            ZeroDayPhase.EXPLOIT_GENERATION: 600,  # 10 minutes
            ZeroDayPhase.EXPLOIT_VALIDATION: 300,  # 5 minutes
        }
    
    def register_callback(self, callback: Callable):
        """
        Register callback for notifications
        
        Args:
            callback: Function to call with notification
        """
        self.callbacks.append(callback)
    
    async def send_notification(self, notification: ZeroDayNotification):
        """
        Send notification to all registered callbacks
        
        Args:
            notification: Notification to send
        """
        self.notifications.append(notification)
        log.info(f"[ZeroDay] {notification.phase.value}: {notification.message}")
        
        # Call all callbacks
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(notification)
                else:
                    callback(notification)
            except Exception as e:
                log.error(f"[ZeroDay] Callback error: {e}")
    
    async def start_discovery(self):
        """Start Zero-Day discovery process"""
        self.start_time = datetime.now()
        self.current_phase = ZeroDayPhase.INITIALIZING
        self.phase_start_times[self.current_phase] = self.start_time
        
        # Calculate total estimated time
        total_estimated = sum(self.estimated_phase_durations.values())
        
        notification = ZeroDayNotification(
            level=NotificationLevel.INFO,
            phase=ZeroDayPhase.INITIALIZING,
            message="🚀 Starting Zero-Day Discovery Process",
            progress=0.0,
            estimated_time_remaining=total_estimated,
            details={
                'total_phases': len(ZeroDayPhase) - 1,  # Exclude COMPLETED
                'estimated_total_time': total_estimated,
                'estimated_total_time_formatted': self._format_duration(total_estimated),
                'warning': '⚠️  This process may take several hours. You will be notified of progress.'
            }
        )
        
        await self.send_notification(notification)
    
    async def start_phase(self, phase: ZeroDayPhase, details: Optional[Dict] = None):
        """
        Start a new phase
        
        Args:
            phase: Phase to start
            details: Additional details about the phase
        """
        # Complete previous phase
        if self.current_phase and self.current_phase != phase:
            await self._complete_phase(self.current_phase)
        
        self.current_phase = phase
        self.phase_start_times[phase] = datetime.now()
        
        # Calculate progress
        completed_phases = len([p for p in ZeroDayPhase if p.value < phase.value])
        total_phases = len(ZeroDayPhase) - 1  # Exclude COMPLETED
        progress = completed_phases / total_phases
        
        # Calculate remaining time
        remaining_phases = [p for p in ZeroDayPhase if p.value >= phase.value and p != ZeroDayPhase.COMPLETED]
        estimated_remaining = sum(self.estimated_phase_durations.get(p, 0) for p in remaining_phases)
        
        message = self._get_phase_message(phase)
        
        notification = ZeroDayNotification(
            level=NotificationLevel.INFO,
            phase=phase,
            message=message,
            progress=progress,
            estimated_time_remaining=estimated_remaining,
            details=details or {}
        )
        
        await self.send_notification(notification)
    
    async def update_progress(
        self,
        phase: ZeroDayPhase,
        progress: float,
        message: Optional[str] = None,
        details: Optional[Dict] = None
    ):
        """
        Update progress within a phase
        
        Args:
            phase: Current phase
            progress: Progress within phase (0.0 to 1.0)
            message: Optional message
            details: Additional details
        """
        # Calculate overall progress
        completed_phases = len([p for p in ZeroDayPhase if p.value < phase.value])
        total_phases = len(ZeroDayPhase) - 1
        phase_weight = 1.0 / total_phases
        overall_progress = (completed_phases + progress) / total_phases
        
        # Estimate remaining time
        if phase in self.phase_start_times:
            elapsed = (datetime.now() - self.phase_start_times[phase]).total_seconds()
            if progress > 0:
                estimated_phase_total = elapsed / progress
                estimated_phase_remaining = estimated_phase_total - elapsed
            else:
                estimated_phase_remaining = self.estimated_phase_durations.get(phase, 0)
        else:
            estimated_phase_remaining = self.estimated_phase_durations.get(phase, 0)
        
        # Add remaining phases
        remaining_phases = [p for p in ZeroDayPhase if p.value > phase.value and p != ZeroDayPhase.COMPLETED]
        estimated_remaining = estimated_phase_remaining + sum(
            self.estimated_phase_durations.get(p, 0) for p in remaining_phases
        )
        
        notification = ZeroDayNotification(
            level=NotificationLevel.INFO,
            phase=phase,
            message=message or f"Progress: {progress*100:.1f}%",
            progress=overall_progress,
            estimated_time_remaining=int(estimated_remaining),
            details=details or {}
        )
        
        await self.send_notification(notification)
    
    async def report_finding(
        self,
        phase: ZeroDayPhase,
        finding_type: str,
        severity: str,
        details: Dict
    ):
        """
        Report a finding (crash, vulnerability, etc.)
        
        Args:
            phase: Phase where finding was discovered
            finding_type: Type of finding (crash, vuln, etc.)
            severity: Severity level
            details: Finding details
        """
        message = f"🎯 Found {finding_type} (Severity: {severity})"
        
        notification = ZeroDayNotification(
            level=NotificationLevel.SUCCESS,
            phase=phase,
            message=message,
            details={
                'finding_type': finding_type,
                'severity': severity,
                **details
            }
        )
        
        await self.send_notification(notification)
    
    async def report_error(
        self,
        phase: ZeroDayPhase,
        error: str,
        details: Optional[Dict] = None
    ):
        """
        Report an error
        
        Args:
            phase: Phase where error occurred
            error: Error message
            details: Additional details
        """
        notification = ZeroDayNotification(
            level=NotificationLevel.ERROR,
            phase=phase,
            message=f"❌ Error: {error}",
            details=details or {}
        )
        
        await self.send_notification(notification)
    
    async def complete_discovery(self, results: Dict):
        """
        Complete Zero-Day discovery
        
        Args:
            results: Final results
        """
        if self.current_phase:
            await self._complete_phase(self.current_phase)
        
        total_duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        notification = ZeroDayNotification(
            level=NotificationLevel.SUCCESS,
            phase=ZeroDayPhase.COMPLETED,
            message="✅ Zero-Day Discovery Completed!",
            progress=1.0,
            estimated_time_remaining=0,
            details={
                'total_duration': total_duration,
                'total_duration_formatted': self._format_duration(int(total_duration)),
                'results': results
            }
        )
        
        await self.send_notification(notification)
    
    async def _complete_phase(self, phase: ZeroDayPhase):
        """Complete a phase and record duration"""
        if phase in self.phase_start_times:
            duration = (datetime.now() - self.phase_start_times[phase]).total_seconds()
            self.phase_durations[phase] = int(duration)
    
    def _get_phase_message(self, phase: ZeroDayPhase) -> str:
        """Get user-friendly message for phase"""
        messages = {
            ZeroDayPhase.INITIALIZING: "🔧 Initializing Zero-Day Hunter...",
            ZeroDayPhase.FUZZING: "🔍 Fuzzing target (This may take 1-2 hours)...",
            ZeroDayPhase.SYMBOLIC_EXECUTION: "🧠 Performing symbolic execution (30-60 minutes)...",
            ZeroDayPhase.TAINT_ANALYSIS: "🔬 Analyzing data flow (15-30 minutes)...",
            ZeroDayPhase.CRASH_ANALYSIS: "💥 Analyzing crashes (5-10 minutes)...",
            ZeroDayPhase.EXPLOIT_GENERATION: "⚡ Generating exploits (10-20 minutes)...",
            ZeroDayPhase.EXPLOIT_VALIDATION: "✅ Validating exploits (5-10 minutes)...",
        }
        return messages.get(phase, f"Processing {phase.value}...")
    
    def _format_duration(self, seconds: int) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds} seconds"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minutes"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    def get_status(self) -> Dict:
        """Get current status"""
        if not self.start_time:
            return {'status': 'not_started'}
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'status': 'running' if self.current_phase != ZeroDayPhase.COMPLETED else 'completed',
            'current_phase': self.current_phase.value if self.current_phase else None,
            'elapsed_time': int(elapsed),
            'elapsed_time_formatted': self._format_duration(int(elapsed)),
            'phase_durations': {
                phase.value: duration
                for phase, duration in self.phase_durations.items()
            },
            'total_notifications': len(self.notifications)
        }


# Global instance
notification_system = ZeroDayNotificationSystem()


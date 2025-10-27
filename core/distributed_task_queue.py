"""
Distributed Task Queue Manager
Manages distributed execution of agents across multiple workers using Redis
"""

import asyncio
import json
import uuid
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from core.logger import get_logger
from core.redis_client import get_redis_client

log = get_logger(__name__)


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


@dataclass
class Task:
    """Distributed task"""
    task_id: str
    agent_name: str
    target: Dict[str, Any]
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    worker_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 600  # seconds
    
    def to_dict(self):
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "target": self.target,
            "parameters": self.parameters,
            "priority": self.priority.value,
            "status": self.status.value,
            "worker_id": self.worker_id,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "timeout": self.timeout
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        """Create Task from dictionary"""
        return cls(
            task_id=data["task_id"],
            agent_name=data["agent_name"],
            target=data["target"],
            parameters=data.get("parameters", {}),
            priority=TaskPriority(data.get("priority", TaskPriority.NORMAL.value)),
            status=TaskStatus(data.get("status", TaskStatus.PENDING.value)),
            worker_id=data.get("worker_id"),
            created_at=datetime.fromisoformat(data["created_at"]),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            result=data.get("result"),
            error=data.get("error"),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 3),
            timeout=data.get("timeout", 600)
        )


class DistributedTaskQueue:
    """
    Distributed Task Queue Manager
    
    Features:
    - Priority-based task scheduling
    - Worker pool management
    - Task retry logic
    - Timeout handling
    - Result aggregation
    - Load balancing
    - Health monitoring
    """
    
    QUEUE_KEY = "dlnk:task_queue"
    TASK_KEY_PREFIX = "dlnk:task:"
    WORKER_KEY_PREFIX = "dlnk:worker:"
    RESULT_KEY_PREFIX = "dlnk:result:"
    
    def __init__(self):
        self.redis = None
        self.worker_id = str(uuid.uuid4())
        self.is_running = False
        self.task_handlers = {}
        
    async def initialize(self):
        """Initialize task queue"""
        self.redis = await get_redis_client()
        log.info(f"Distributed task queue initialized (worker: {self.worker_id})")
    
    async def submit_task(
        self,
        agent_name: str,
        target: Dict[str, Any],
        parameters: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        timeout: int = 600
    ) -> str:
        """
        Submit a task to the distributed queue
        
        Args:
            agent_name: Name of agent to execute
            target: Target information
            parameters: Agent parameters
            priority: Task priority
            timeout: Task timeout in seconds
            
        Returns:
            Task ID
        """
        task = Task(
            task_id=str(uuid.uuid4()),
            agent_name=agent_name,
            target=target,
            parameters=parameters or {},
            priority=priority,
            timeout=timeout
        )
        
        # Store task data
        task_key = f"{self.TASK_KEY_PREFIX}{task.task_id}"
        await self.redis.setex(
            task_key,
            3600,  # 1 hour TTL
            json.dumps(task.to_dict())
        )
        
        # Add to priority queue
        await self.redis.zadd(
            self.QUEUE_KEY,
            {task.task_id: priority.value}
        )
        
        task.status = TaskStatus.QUEUED
        await self._update_task_status(task)
        
        log.info(f"Task {task.task_id} submitted for agent {agent_name}")
        
        return task.task_id
    
    async def submit_batch(
        self,
        tasks: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Submit multiple tasks at once
        
        Args:
            tasks: List of task specifications
            
        Returns:
            List of task IDs
        """
        task_ids = []
        
        for task_spec in tasks:
            task_id = await self.submit_task(
                agent_name=task_spec["agent_name"],
                target=task_spec["target"],
                parameters=task_spec.get("parameters"),
                priority=task_spec.get("priority", TaskPriority.NORMAL),
                timeout=task_spec.get("timeout", 600)
            )
            task_ids.append(task_id)
        
        log.info(f"Submitted batch of {len(task_ids)} tasks")
        
        return task_ids
    
    async def get_next_task(self) -> Optional[Task]:
        """
        Get next task from queue (highest priority)
        
        Returns:
            Task object or None if queue is empty
        """
        # Get highest priority task
        result = await self.redis.zpopmax(self.QUEUE_KEY)
        
        if not result:
            return None
        
        task_id, priority = result[0]
        
        # Load task data
        task_key = f"{self.TASK_KEY_PREFIX}{task_id}"
        task_data = await self.redis.get(task_key)
        
        if not task_data:
            log.warning(f"Task {task_id} not found in storage")
            return None
        
        task = Task.from_dict(json.loads(task_data))
        
        # Mark as running
        task.status = TaskStatus.RUNNING
        task.worker_id = self.worker_id
        task.started_at = datetime.now()
        await self._update_task_status(task)
        
        log.info(f"Worker {self.worker_id} picked up task {task_id}")
        
        return task
    
    async def complete_task(
        self,
        task_id: str,
        result: Dict[str, Any]
    ):
        """
        Mark task as completed with result
        
        Args:
            task_id: Task ID
            result: Task result data
        """
        task = await self._get_task(task_id)
        if not task:
            log.warning(f"Task {task_id} not found")
            return
        
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now()
        task.result = result
        
        await self._update_task_status(task)
        
        # Store result
        result_key = f"{self.RESULT_KEY_PREFIX}{task_id}"
        await self.redis.setex(
            result_key,
            3600,  # 1 hour TTL
            json.dumps(result)
        )
        
        log.info(f"Task {task_id} completed successfully")
    
    async def fail_task(
        self,
        task_id: str,
        error: str,
        retry: bool = True
    ):
        """
        Mark task as failed
        
        Args:
            task_id: Task ID
            error: Error message
            retry: Whether to retry the task
        """
        task = await self._get_task(task_id)
        if not task:
            log.warning(f"Task {task_id} not found")
            return
        
        task.error = error
        task.retry_count += 1
        
        # Retry if not exceeded max retries
        if retry and task.retry_count < task.max_retries:
            log.info(f"Retrying task {task_id} (attempt {task.retry_count + 1}/{task.max_retries})")
            
            task.status = TaskStatus.QUEUED
            task.worker_id = None
            task.started_at = None
            
            # Re-add to queue with lower priority
            await self.redis.zadd(
                self.QUEUE_KEY,
                {task_id: task.priority.value - task.retry_count}
            )
        else:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now()
            log.error(f"Task {task_id} failed: {error}")
        
        await self._update_task_status(task)
    
    async def cancel_task(self, task_id: str):
        """Cancel a pending or running task"""
        task = await self._get_task(task_id)
        if not task:
            return
        
        if task.status in [TaskStatus.PENDING, TaskStatus.QUEUED]:
            # Remove from queue
            await self.redis.zrem(self.QUEUE_KEY, task_id)
        
        task.status = TaskStatus.CANCELLED
        task.completed_at = datetime.now()
        await self._update_task_status(task)
        
        log.info(f"Task {task_id} cancelled")
    
    async def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """Get current status of a task"""
        task = await self._get_task(task_id)
        return task.status if task else None
    
    async def get_task_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get result of a completed task"""
        result_key = f"{self.RESULT_KEY_PREFIX}{task_id}"
        result_data = await self.redis.get(result_key)
        
        if result_data:
            return json.loads(result_data)
        
        return None
    
    async def wait_for_task(
        self,
        task_id: str,
        timeout: int = 600
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for task to complete and return result
        
        Args:
            task_id: Task ID
            timeout: Maximum wait time in seconds
            
        Returns:
            Task result or None if timeout
        """
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            status = await self.get_task_status(task_id)
            
            if status == TaskStatus.COMPLETED:
                return await self.get_task_result(task_id)
            elif status in [TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.TIMEOUT]:
                task = await self._get_task(task_id)
                raise Exception(f"Task {task_id} {status.value}: {task.error if task else 'Unknown error'}")
            
            await asyncio.sleep(1)
        
        # Timeout
        await self.fail_task(task_id, "Task timeout", retry=False)
        raise TimeoutError(f"Task {task_id} timed out after {timeout} seconds")
    
    async def wait_for_batch(
        self,
        task_ids: List[str],
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Wait for multiple tasks to complete
        
        Args:
            task_ids: List of task IDs
            timeout: Maximum wait time in seconds
            
        Returns:
            Dictionary mapping task_id to result
        """
        results = {}
        
        # Wait for all tasks concurrently
        tasks = [
            self.wait_for_task(task_id, timeout)
            for task_id in task_ids
        ]
        
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for task_id, result in zip(task_ids, completed_results):
            if isinstance(result, Exception):
                log.error(f"Task {task_id} failed: {result}")
                results[task_id] = {"error": str(result)}
            else:
                results[task_id] = result
        
        return results
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        queue_size = await self.redis.zcard(self.QUEUE_KEY)
        
        # Count tasks by status
        status_counts = {status.value: 0 for status in TaskStatus}
        
        # Get all task keys
        task_keys = await self.redis.keys(f"{self.TASK_KEY_PREFIX}*")
        
        for key in task_keys:
            task_data = await self.redis.get(key)
            if task_data:
                task = Task.from_dict(json.loads(task_data))
                status_counts[task.status.value] += 1
        
        # Count active workers
        worker_keys = await self.redis.keys(f"{self.WORKER_KEY_PREFIX}*")
        active_workers = len(worker_keys)
        
        return {
            "queue_size": queue_size,
            "status_counts": status_counts,
            "active_workers": active_workers,
            "total_tasks": len(task_keys)
        }
    
    async def register_task_handler(
        self,
        agent_name: str,
        handler: Callable
    ):
        """Register a handler function for an agent"""
        self.task_handlers[agent_name] = handler
        log.info(f"Registered handler for agent: {agent_name}")
    
    async def start_worker(self):
        """Start worker loop to process tasks"""
        self.is_running = True
        
        # Register worker
        worker_key = f"{self.WORKER_KEY_PREFIX}{self.worker_id}"
        await self.redis.setex(
            worker_key,
            60,  # 1 minute TTL, renewed by heartbeat
            json.dumps({
                "worker_id": self.worker_id,
                "started_at": datetime.now().isoformat(),
                "status": "active"
            })
        )
        
        log.info(f"Worker {self.worker_id} started")
        
        # Start heartbeat
        asyncio.create_task(self._heartbeat())
        
        # Process tasks
        while self.is_running:
            try:
                task = await self.get_next_task()
                
                if task:
                    await self._execute_task(task)
                else:
                    # No tasks, wait a bit
                    await asyncio.sleep(1)
                    
            except Exception as e:
                log.error(f"Worker error: {e}")
                await asyncio.sleep(5)
    
    async def stop_worker(self):
        """Stop worker loop"""
        self.is_running = False
        
        # Unregister worker
        worker_key = f"{self.WORKER_KEY_PREFIX}{self.worker_id}"
        await self.redis.delete(worker_key)
        
        log.info(f"Worker {self.worker_id} stopped")
    
    async def _execute_task(self, task: Task):
        """Execute a task"""
        try:
            # Get handler for agent
            handler = self.task_handlers.get(task.agent_name)
            
            if not handler:
                raise Exception(f"No handler registered for agent: {task.agent_name}")
            
            # Execute with timeout
            result = await asyncio.wait_for(
                handler(task.target, task.parameters),
                timeout=task.timeout
            )
            
            await self.complete_task(task.task_id, result)
            
        except asyncio.TimeoutError:
            await self.fail_task(
                task.task_id,
                f"Task execution timed out after {task.timeout} seconds",
                retry=True
            )
        except Exception as e:
            await self.fail_task(
                task.task_id,
                str(e),
                retry=True
            )
    
    async def _heartbeat(self):
        """Send periodic heartbeat to keep worker registered"""
        while self.is_running:
            try:
                worker_key = f"{self.WORKER_KEY_PREFIX}{self.worker_id}"
                await self.redis.expire(worker_key, 60)
                await asyncio.sleep(30)
            except Exception as e:
                log.error(f"Heartbeat error: {e}")
    
    async def _get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        task_key = f"{self.TASK_KEY_PREFIX}{task_id}"
        task_data = await self.redis.get(task_key)
        
        if task_data:
            return Task.from_dict(json.loads(task_data))
        
        return None
    
    async def _update_task_status(self, task: Task):
        """Update task status in storage"""
        task_key = f"{self.TASK_KEY_PREFIX}{task.task_id}"
        await self.redis.setex(
            task_key,
            3600,  # 1 hour TTL
            json.dumps(task.to_dict())
        )


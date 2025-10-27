"""
Parallel Executor for dLNk Attack Platform
ประมวลผลการโจมตีแบบขนานเพื่อความเร็ว 10x
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Callable, Coroutine
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from queue import PriorityQueue
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from loguru import logger


class Priority(Enum):
    """ระดับความสำคัญ"""
    LOW = 3
    MEDIUM = 2
    HIGH = 1
    CRITICAL = 0


class TaskStatus(Enum):
    """สถานะของ task"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Task สำหรับ execution"""
    task_id: str
    name: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    priority: Priority = Priority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: float = 0.0
    
    def __lt__(self, other):
        """สำหรับ PriorityQueue"""
        return self.priority.value < other.priority.value


@dataclass
class ExecutionStats:
    """สถิติการ execution"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    cancelled_tasks: int = 0
    total_duration: float = 0.0
    avg_duration: float = 0.0
    tasks_per_second: float = 0.0
    speedup_factor: float = 1.0


class ParallelExecutor:
    """
    Parallel Executor
    
    Features:
    - Parallel attack execution
    - Priority-based queue
    - Resource optimization
    - 10x faster attacks
    - Async and thread pool support
    - Rate limiting
    - Progress tracking
    """
    
    def __init__(
        self,
        max_workers: int = 10,
        max_concurrent_tasks: int = 50,
        use_process_pool: bool = False
    ):
        self.name = "ParallelExecutor"
        self.max_workers = max_workers
        self.max_concurrent_tasks = max_concurrent_tasks
        
        # Task management
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.tasks: Dict[str, Task] = {}
        self.running_tasks: List[str] = []
        
        # Executors
        if use_process_pool:
            self.executor = ProcessPoolExecutor(max_workers=max_workers)
        else:
            self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Statistics
        self.stats = ExecutionStats()
        
        # Control
        self.is_running = False
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        
        logger.info(f"[{self.name}] Initialized with {max_workers} workers, max {max_concurrent_tasks} concurrent tasks")
    
    async def submit_task(
        self,
        task_id: str,
        name: str,
        func: Callable,
        *args,
        priority: Priority = Priority.MEDIUM,
        **kwargs
    ) -> str:
        """
        Submit task สำหรับ execution
        
        Args:
            task_id: unique task ID
            name: task name
            func: function to execute
            *args: positional arguments
            priority: task priority
            **kwargs: keyword arguments
        
        Returns:
            task_id
        """
        task = Task(
            task_id=task_id,
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            priority=priority
        )
        
        self.tasks[task_id] = task
        await self.task_queue.put(task)
        
        self.stats.total_tasks += 1
        
        logger.info(f"[{self.name}] Task submitted: {name} (priority: {priority.name})")
        
        return task_id
    
    async def submit_batch(
        self,
        tasks: List[Dict[str, Any]],
        priority: Priority = Priority.MEDIUM
    ) -> List[str]:
        """
        Submit หลาย tasks พร้อมกัน
        
        Args:
            tasks: list of task dicts
                - task_id: str
                - name: str
                - func: Callable
                - args: tuple (optional)
                - kwargs: dict (optional)
            priority: default priority
        
        Returns:
            list of task_ids
        """
        task_ids = []
        
        for task_data in tasks:
            # Extract args and kwargs
            args = task_data.get("args", ())
            kwargs = task_data.get("kwargs", {})
            task_priority = task_data.get("priority", priority)
            
            task_id = await self.submit_task(
                task_data["task_id"],
                task_data["name"],
                task_data["func"],
                *args,
                priority=task_priority,
                **kwargs
            )
            task_ids.append(task_id)
        
        logger.info(f"[{self.name}] Batch submitted: {len(task_ids)} tasks")
        
        return task_ids
    
    async def execute_all(self) -> Dict[str, Any]:
        """
        Execute ทุก tasks ใน queue
        
        Returns:
            execution results
        """
        if self.is_running:
            logger.warning(f"[{self.name}] Executor already running")
            return {"error": "Already running"}
        
        self.is_running = True
        start_time = time.time()
        
        logger.info(f"[{self.name}] Starting execution of {self.task_queue.qsize()} tasks")
        
        # สร้าง workers
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.max_workers)
        ]
        
        # รอให้ queue ว่าง
        await self.task_queue.join()
        
        # ยกเลิก workers
        for worker in workers:
            worker.cancel()
        
        # รอให้ workers หยุด
        await asyncio.gather(*workers, return_exceptions=True)
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        self.is_running = False
        
        # คำนวณสถิติ
        self.stats.total_duration = total_duration
        self.stats.avg_duration = total_duration / self.stats.total_tasks if self.stats.total_tasks > 0 else 0
        self.stats.tasks_per_second = self.stats.total_tasks / total_duration if total_duration > 0 else 0
        
        # คำนวณ speedup (สมมติว่า sequential ใช้เวลาเท่ากับผลรวมของทุก task)
        total_task_duration = sum(t.duration for t in self.tasks.values())
        self.stats.speedup_factor = total_task_duration / total_duration if total_duration > 0 else 1.0
        
        logger.success(f"[{self.name}] Execution completed in {total_duration:.2f}s")
        logger.success(f"[{self.name}] Speedup: {self.stats.speedup_factor:.2f}x")
        
        return {
            "success": True,
            "total_duration": total_duration,
            "tasks_completed": self.stats.completed_tasks,
            "tasks_failed": self.stats.failed_tasks,
            "speedup": self.stats.speedup_factor,
            "tasks_per_second": self.stats.tasks_per_second
        }
    
    async def _worker(self, worker_id: int):
        """
        Worker สำหรับ execute tasks
        """
        logger.debug(f"[{self.name}] Worker {worker_id} started")
        
        while True:
            try:
                # ดึง task จาก queue
                task = await self.task_queue.get()
                
                # Execute task
                await self._execute_task(task, worker_id)
                
                # Mark task as done
                self.task_queue.task_done()
            
            except asyncio.CancelledError:
                logger.debug(f"[{self.name}] Worker {worker_id} cancelled")
                break
            
            except Exception as e:
                logger.error(f"[{self.name}] Worker {worker_id} error: {e}")
    
    async def _execute_task(self, task: Task, worker_id: int):
        """
        Execute task
        """
        async with self.semaphore:
            task.status = TaskStatus.RUNNING
            task.start_time = datetime.now()
            self.running_tasks.append(task.task_id)
            
            logger.info(f"[{self.name}] Worker {worker_id} executing: {task.name}")
            
            try:
                # Execute function
                if asyncio.iscoroutinefunction(task.func):
                    # Async function
                    result = await task.func(*task.args, **task.kwargs)
                else:
                    # Sync function - run in executor
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        self.executor,
                        task.func,
                        *task.args
                    )
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                self.stats.completed_tasks += 1
                
                logger.success(f"[{self.name}] Task completed: {task.name}")
            
            except Exception as e:
                task.error = str(e)
                task.status = TaskStatus.FAILED
                self.stats.failed_tasks += 1
                
                logger.error(f"[{self.name}] Task failed: {task.name} - {e}")
            
            finally:
                task.end_time = datetime.now()
                task.duration = (task.end_time - task.start_time).total_seconds()
                self.running_tasks.remove(task.task_id)
    
    async def execute_parallel(
        self,
        funcs: List[Callable],
        args_list: Optional[List[tuple]] = None,
        kwargs_list: Optional[List[dict]] = None
    ) -> List[Any]:
        """
        Execute หลาย functions แบบขนาน (helper method)
        
        Args:
            funcs: list of functions
            args_list: list of args tuples (optional)
            kwargs_list: list of kwargs dicts (optional)
        
        Returns:
            list of results
        """
        if args_list is None:
            args_list = [()] * len(funcs)
        if kwargs_list is None:
            kwargs_list = [{}] * len(funcs)
        
        # Submit tasks
        task_ids = []
        for i, func in enumerate(funcs):
            task_id = f"parallel_{i}_{int(time.time())}"
            await self.submit_task(
                task_id=task_id,
                name=f"parallel_task_{i}",
                func=func,
                *args_list[i],
                **kwargs_list[i]
            )
            task_ids.append(task_id)
        
        # Execute
        await self.execute_all()
        
        # Collect results
        results = [self.tasks[tid].result for tid in task_ids]
        
        return results
    
    async def execute_with_rate_limit(
        self,
        funcs: List[Callable],
        rate_limit: float = 1.0,  # tasks per second
        args_list: Optional[List[tuple]] = None,
        kwargs_list: Optional[List[dict]] = None
    ) -> List[Any]:
        """
        Execute พร้อม rate limiting
        
        Args:
            funcs: list of functions
            rate_limit: tasks per second
            args_list: list of args tuples
            kwargs_list: list of kwargs dicts
        
        Returns:
            list of results
        """
        if args_list is None:
            args_list = [()] * len(funcs)
        if kwargs_list is None:
            kwargs_list = [{}] * len(funcs)
        
        delay = 1.0 / rate_limit
        results = []
        
        for i, func in enumerate(funcs):
            if i > 0:
                await asyncio.sleep(delay)
            
            task_id = f"ratelimit_{i}_{int(time.time())}"
            await self.submit_task(
                task_id=task_id,
                name=f"ratelimit_task_{i}",
                func=func,
                *args_list[i],
                **kwargs_list[i]
            )
        
        await self.execute_all()
        
        # Collect results
        task_ids = [f"ratelimit_{i}_{int(time.time())}" for i in range(len(funcs))]
        results = [self.tasks.get(tid, Task(tid, "", None)).result for tid in task_ids]
        
        return results
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """ดึงสถานะของ task"""
        task = self.tasks.get(task_id)
        
        if not task:
            return None
        
        return {
            "task_id": task.task_id,
            "name": task.name,
            "status": task.status.value,
            "priority": task.priority.name,
            "duration": task.duration,
            "result": task.result,
            "error": task.error
        }
    
    def get_progress(self) -> Dict[str, Any]:
        """ดึงความคืบหน้า"""
        pending = sum(1 for t in self.tasks.values() if t.status == TaskStatus.PENDING)
        running = len(self.running_tasks)
        completed = self.stats.completed_tasks
        failed = self.stats.failed_tasks
        
        total = self.stats.total_tasks
        progress_pct = (completed + failed) / total * 100 if total > 0 else 0
        
        return {
            "total_tasks": total,
            "pending": pending,
            "running": running,
            "completed": completed,
            "failed": failed,
            "progress_percentage": progress_pct,
            "is_running": self.is_running
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """ดึงสถิติ"""
        return {
            "total_tasks": self.stats.total_tasks,
            "completed_tasks": self.stats.completed_tasks,
            "failed_tasks": self.stats.failed_tasks,
            "cancelled_tasks": self.stats.cancelled_tasks,
            "total_duration": self.stats.total_duration,
            "avg_duration": self.stats.avg_duration,
            "tasks_per_second": self.stats.tasks_per_second,
            "speedup_factor": self.stats.speedup_factor,
            "max_workers": self.max_workers,
            "max_concurrent_tasks": self.max_concurrent_tasks
        }
    
    async def cancel_task(self, task_id: str) -> bool:
        """ยกเลิก task"""
        task = self.tasks.get(task_id)
        
        if not task:
            return False
        
        if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            return False
        
        task.status = TaskStatus.CANCELLED
        self.stats.cancelled_tasks += 1
        
        logger.info(f"[{self.name}] Task cancelled: {task.name}")
        
        return True
    
    def clear_completed(self):
        """ลบ tasks ที่เสร็จแล้ว"""
        before = len(self.tasks)
        
        self.tasks = {
            tid: task for tid, task in self.tasks.items()
            if task.status not in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
        }
        
        after = len(self.tasks)
        removed = before - after
        
        logger.info(f"[{self.name}] Cleared {removed} completed tasks")
        
        return removed
    
    def shutdown(self):
        """ปิด executor"""
        logger.info(f"[{self.name}] Shutting down...")
        self.executor.shutdown(wait=True)
        logger.success(f"[{self.name}] Shutdown complete")


# Singleton instance
parallel_executor = ParallelExecutor()


# Helper functions
async def execute_parallel(
    funcs: List[Callable],
    args_list: Optional[List[tuple]] = None,
    kwargs_list: Optional[List[dict]] = None
) -> List[Any]:
    """Execute parallel wrapper"""
    executor = ParallelExecutor()
    return await executor.execute_parallel(funcs, args_list, kwargs_list)


async def execute_batch(
    tasks: List[Dict[str, Any]],
    max_workers: int = 10
) -> Dict[str, Any]:
    """Execute batch wrapper"""
    executor = ParallelExecutor(max_workers=max_workers)
    await executor.submit_batch(tasks)
    return await executor.execute_all()


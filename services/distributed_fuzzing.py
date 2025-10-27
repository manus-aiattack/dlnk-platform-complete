"""
Distributed Fuzzing System
ระบบ fuzzing แบบกระจาย สำหรับ fuzzing หลาย machines พร้อมกัน
"""

import asyncio
import os
import json
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from core.logger import log


class FuzzingNodeStatus(Enum):
    """สถานะของ fuzzing node"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    OFFLINE = "offline"


@dataclass
class FuzzingNode:
    """Fuzzing node information"""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    status: FuzzingNodeStatus
    cpu_cores: int
    memory_gb: int
    current_job: Optional[str] = None
    jobs_completed: int = 0
    crashes_found: int = 0
    last_heartbeat: Optional[str] = None


@dataclass
class FuzzingJob:
    """Fuzzing job definition"""
    job_id: str
    target_binary: str
    input_seeds: List[str]
    duration: int  # seconds
    timeout: int  # ms per test
    memory_limit: int  # MB
    assigned_node: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed
    crashes_found: int = 0
    execs_per_sec: float = 0.0
    coverage: float = 0.0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class DistributedFuzzingOrchestrator:
    """
    Orchestrator สำหรับ distributed fuzzing
    
    Features:
    - Node management
    - Job scheduling
    - Load balancing
    - Crash collection
    - Metrics aggregation
    """
    
    def __init__(self, db=None):
        """
        Initialize distributed fuzzing orchestrator
        
        Args:
            db: Database connection (optional)
        """
        self.db = db
        self.nodes: Dict[str, FuzzingNode] = {}
        self.jobs: Dict[str, FuzzingJob] = {}
        self.crashes: List[Dict[str, Any]] = []
        
        self.is_running = False
        self.orchestrator_tasks = []
    
    async def start(self):
        """เริ่มต้น orchestrator"""
        try:
            self.is_running = True
            
            # เริ่ม background tasks
            self.orchestrator_tasks = [
                asyncio.create_task(self._monitor_nodes()),
                asyncio.create_task(self._schedule_jobs()),
                asyncio.create_task(self._collect_crashes())
            ]
            
            log.info("[DistributedFuzzing] Orchestrator started")
            return True
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to start orchestrator: {e}")
            return False
    
    async def stop(self):
        """หยุด orchestrator"""
        try:
            self.is_running = False
            
            # หยุด background tasks
            for task in self.orchestrator_tasks:
                task.cancel()
            
            self.orchestrator_tasks = []
            
            log.info("[DistributedFuzzing] Orchestrator stopped")
            return True
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to stop orchestrator: {e}")
            return False
    
    async def register_node(
        self,
        hostname: str,
        ip_address: str,
        port: int,
        cpu_cores: int,
        memory_gb: int
    ) -> str:
        """
        ลงทะเบียน fuzzing node
        
        Args:
            hostname: Hostname
            ip_address: IP address
            port: Port number
            cpu_cores: Number of CPU cores
            memory_gb: Memory in GB
        
        Returns:
            Node ID
        """
        try:
            # สร้าง node ID
            node_id = hashlib.sha256(f"{hostname}:{ip_address}:{port}".encode()).hexdigest()[:16]
            
            # สร้าง node object
            node = FuzzingNode(
                node_id=node_id,
                hostname=hostname,
                ip_address=ip_address,
                port=port,
                status=FuzzingNodeStatus.IDLE,
                cpu_cores=cpu_cores,
                memory_gb=memory_gb,
                last_heartbeat=datetime.now().isoformat()
            )
            
            # บันทึก node
            self.nodes[node_id] = node
            
            log.info(f"[DistributedFuzzing] Node registered: {node_id} ({hostname})")
            
            return node_id
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to register node: {e}")
            raise
    
    async def unregister_node(self, node_id: str) -> bool:
        """
        ยกเลิกการลงทะเบียน node
        
        Args:
            node_id: Node ID
        
        Returns:
            Success status
        """
        try:
            if node_id in self.nodes:
                # หยุด job ที่กำลังรันบน node นี้
                node = self.nodes[node_id]
                if node.current_job:
                    await self._stop_job(node.current_job)
                
                # ลบ node
                del self.nodes[node_id]
                
                log.info(f"[DistributedFuzzing] Node unregistered: {node_id}")
                return True
            
            return False
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to unregister node: {e}")
            return False
    
    async def submit_job(
        self,
        target_binary: str,
        input_seeds: List[str],
        duration: int = 3600,
        timeout: int = 100,
        memory_limit: int = 256
    ) -> str:
        """
        Submit fuzzing job
        
        Args:
            target_binary: Path to target binary
            input_seeds: List of seed input files
            duration: Fuzzing duration in seconds
            timeout: Timeout per test in ms
            memory_limit: Memory limit in MB
        
        Returns:
            Job ID
        """
        try:
            # สร้าง job ID
            job_id = hashlib.sha256(f"{target_binary}:{datetime.now().isoformat()}".encode()).hexdigest()[:16]
            
            # สร้าง job object
            job = FuzzingJob(
                job_id=job_id,
                target_binary=target_binary,
                input_seeds=input_seeds,
                duration=duration,
                timeout=timeout,
                memory_limit=memory_limit
            )
            
            # บันทึก job
            self.jobs[job_id] = job
            
            log.info(f"[DistributedFuzzing] Job submitted: {job_id}")
            
            return job_id
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to submit job: {e}")
            raise
    
    async def _monitor_nodes(self):
        """ติดตาม node status"""
        while self.is_running:
            try:
                current_time = datetime.now()
                
                for node_id, node in list(self.nodes.items()):
                    # ตรวจสอบ heartbeat
                    if node.last_heartbeat:
                        last_heartbeat = datetime.fromisoformat(node.last_heartbeat)
                        time_diff = (current_time - last_heartbeat).total_seconds()
                        
                        # ถ้าไม่มี heartbeat เกิน 60 วินาที ถือว่า offline
                        if time_diff > 60:
                            node.status = FuzzingNodeStatus.OFFLINE
                            log.warning(f"[DistributedFuzzing] Node {node_id} is offline")
                
                await asyncio.sleep(10)  # ตรวจสอบทุก 10 วินาที
            
            except Exception as e:
                log.error(f"[DistributedFuzzing] Node monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def _schedule_jobs(self):
        """จัดการ job scheduling"""
        while self.is_running:
            try:
                # หา pending jobs
                pending_jobs = [job for job in self.jobs.values() if job.status == "pending"]
                
                for job in pending_jobs:
                    # หา idle node
                    idle_node = self._find_best_node()
                    
                    if idle_node:
                        # Assign job to node
                        await self._assign_job(job.job_id, idle_node.node_id)
                
                await asyncio.sleep(5)  # ตรวจสอบทุก 5 วินาที
            
            except Exception as e:
                log.error(f"[DistributedFuzzing] Job scheduling error: {e}")
                await asyncio.sleep(5)
    
    async def _collect_crashes(self):
        """รวบรวม crashes จาก nodes"""
        while self.is_running:
            try:
                for node_id, node in self.nodes.items():
                    if node.current_job:
                        # ดึง crashes จาก node (ในระบบจริงจะเรียก API)
                        crashes = await self._fetch_crashes_from_node(node_id)
                        
                        if crashes:
                            self.crashes.extend(crashes)
                            node.crashes_found += len(crashes)
                            
                            log.info(f"[DistributedFuzzing] Collected {len(crashes)} crashes from {node_id}")
                
                await asyncio.sleep(30)  # รวบรวมทุก 30 วินาที
            
            except Exception as e:
                log.error(f"[DistributedFuzzing] Crash collection error: {e}")
                await asyncio.sleep(30)
    
    def _find_best_node(self) -> Optional[FuzzingNode]:
        """
        หา node ที่เหมาะสมที่สุดสำหรับ job
        
        Returns:
            Best available node
        """
        idle_nodes = [node for node in self.nodes.values() if node.status == FuzzingNodeStatus.IDLE]
        
        if not idle_nodes:
            return None
        
        # เลือก node ที่มี CPU cores มากที่สุด
        best_node = max(idle_nodes, key=lambda n: n.cpu_cores)
        
        return best_node
    
    async def _assign_job(self, job_id: str, node_id: str):
        """
        Assign job to node
        
        Args:
            job_id: Job ID
            node_id: Node ID
        """
        try:
            job = self.jobs[job_id]
            node = self.nodes[node_id]
            
            # Update job
            job.assigned_node = node_id
            job.status = "running"
            job.started_at = datetime.now().isoformat()
            
            # Update node
            node.current_job = job_id
            node.status = FuzzingNodeStatus.RUNNING
            
            # เริ่ม fuzzing บน node (ในระบบจริงจะเรียก API)
            await self._start_fuzzing_on_node(node_id, job)
            
            log.info(f"[DistributedFuzzing] Job {job_id} assigned to node {node_id}")
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to assign job: {e}")
    
    async def _start_fuzzing_on_node(self, node_id: str, job: FuzzingJob):
        """
        เริ่ม fuzzing บน node
        
        Args:
            node_id: Node ID
            job: Fuzzing job
        """
        # ในระบบจริงจะเรียก API ของ node
        log.info(f"[DistributedFuzzing] Starting fuzzing on node {node_id} for job {job.job_id}")
    
    async def _stop_job(self, job_id: str):
        """
        หยุด job
        
        Args:
            job_id: Job ID
        """
        try:
            job = self.jobs.get(job_id)
            if not job:
                return
            
            # Update job
            job.status = "completed"
            job.completed_at = datetime.now().isoformat()
            
            # Update node
            if job.assigned_node:
                node = self.nodes.get(job.assigned_node)
                if node:
                    node.current_job = None
                    node.status = FuzzingNodeStatus.IDLE
                    node.jobs_completed += 1
            
            log.info(f"[DistributedFuzzing] Job {job_id} stopped")
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to stop job: {e}")
    
    async def _fetch_crashes_from_node(self, node_id: str) -> List[Dict[str, Any]]:
        """
        ดึง crashes จาก node
        
        Args:
            node_id: Node ID
        
        Returns:
            List of crashes
        """
        # ในระบบจริงจะเรียก API ของ node
        # Simulated crashes
        return []
    
    async def update_heartbeat(self, node_id: str, metrics: Dict[str, Any]) -> bool:
        """
        อัพเดท heartbeat จาก node
        
        Args:
            node_id: Node ID
            metrics: Node metrics
        
        Returns:
            Success status
        """
        try:
            node = self.nodes.get(node_id)
            if not node:
                return False
            
            # Update heartbeat
            node.last_heartbeat = datetime.now().isoformat()
            
            # Update metrics
            if node.current_job:
                job = self.jobs.get(node.current_job)
                if job:
                    job.execs_per_sec = metrics.get("execs_per_sec", 0.0)
                    job.coverage = metrics.get("coverage", 0.0)
                    job.crashes_found = metrics.get("crashes_found", 0)
            
            return True
        
        except Exception as e:
            log.error(f"[DistributedFuzzing] Failed to update heartbeat: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """
        รับสถานะของระบบ
        
        Returns:
            Status dictionary
        """
        total_nodes = len(self.nodes)
        active_nodes = sum(1 for n in self.nodes.values() if n.status == FuzzingNodeStatus.RUNNING)
        idle_nodes = sum(1 for n in self.nodes.values() if n.status == FuzzingNodeStatus.IDLE)
        offline_nodes = sum(1 for n in self.nodes.values() if n.status == FuzzingNodeStatus.OFFLINE)
        
        total_jobs = len(self.jobs)
        running_jobs = sum(1 for j in self.jobs.values() if j.status == "running")
        completed_jobs = sum(1 for j in self.jobs.values() if j.status == "completed")
        pending_jobs = sum(1 for j in self.jobs.values() if j.status == "pending")
        
        total_crashes = len(self.crashes)
        
        return {
            "nodes": {
                "total": total_nodes,
                "active": active_nodes,
                "idle": idle_nodes,
                "offline": offline_nodes
            },
            "jobs": {
                "total": total_jobs,
                "running": running_jobs,
                "completed": completed_jobs,
                "pending": pending_jobs
            },
            "crashes": {
                "total": total_crashes
            }
        }
    
    def get_nodes(self) -> List[Dict[str, Any]]:
        """
        รับรายการ nodes
        
        Returns:
            List of nodes
        """
        return [asdict(node) for node in self.nodes.values()]
    
    def get_jobs(self) -> List[Dict[str, Any]]:
        """
        รับรายการ jobs
        
        Returns:
            List of jobs
        """
        return [asdict(job) for job in self.jobs.values()]
    
    def get_crashes(self) -> List[Dict[str, Any]]:
        """
        รับรายการ crashes
        
        Returns:
            List of crashes
        """
        return self.crashes


# Example usage
if __name__ == "__main__":
    async def main():
        # Initialize orchestrator
        orchestrator = DistributedFuzzingOrchestrator()
        await orchestrator.start()
        
        # Register nodes
        node1_id = await orchestrator.register_node(
            hostname="fuzzer-01",
            ip_address="192.168.1.101",
            port=8001,
            cpu_cores=8,
            memory_gb=16
        )
        
        node2_id = await orchestrator.register_node(
            hostname="fuzzer-02",
            ip_address="192.168.1.102",
            port=8002,
            cpu_cores=16,
            memory_gb=32
        )
        
        # Submit job
        job_id = await orchestrator.submit_job(
            target_binary="/path/to/binary",
            input_seeds=["/path/to/seeds/input1.txt"],
            duration=3600
        )
        
        # Wait a bit
        await asyncio.sleep(5)
        
        # Get status
        status = orchestrator.get_status()
        print(f"Status: {json.dumps(status, indent=2)}")
        
        # Stop
        await orchestrator.stop()
    
    asyncio.run(main())


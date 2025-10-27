"""
Monitoring API Routes
Real-time system monitoring and metrics
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List, Dict, Any
from datetime import datetime, timedelta
from api.services.database import Database
from api.services.auth import AuthService
import psutil
import asyncio

router = APIRouter()

# Dependency injection - will be set by main.py
db: Database = None
auth_service: AuthService = None

def set_dependencies(database: Database, auth_svc: AuthService):
    """Set dependencies from main.py"""
    global db, auth_service
    db = database
    auth_service = auth_svc


@router.get("/metrics/system")
async def get_system_metrics(req: Request):
    """ดูข้อมูล System metrics แบบละเอียด"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # CPU metrics
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    cpu_freq = psutil.cpu_freq()
    cpu_count = psutil.cpu_count()
    
    # Memory metrics
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    # Disk metrics
    disk = psutil.disk_usage('/')
    disk_io = psutil.disk_io_counters()
    
    # Network metrics
    net_io = psutil.net_io_counters()
    
    # Process metrics
    process = psutil.Process()
    process_memory = process.memory_info()
    process_cpu = process.cpu_percent(interval=1)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "cpu": {
            "percent_total": sum(cpu_percent) / len(cpu_percent),
            "percent_per_core": cpu_percent,
            "frequency_mhz": cpu_freq.current if cpu_freq else 0,
            "core_count": cpu_count
        },
        "memory": {
            "total_gb": memory.total / (1024**3),
            "available_gb": memory.available / (1024**3),
            "used_gb": memory.used / (1024**3),
            "percent": memory.percent,
            "swap_total_gb": swap.total / (1024**3),
            "swap_used_gb": swap.used / (1024**3),
            "swap_percent": swap.percent
        },
        "disk": {
            "total_gb": disk.total / (1024**3),
            "used_gb": disk.used / (1024**3),
            "free_gb": disk.free / (1024**3),
            "percent": disk.percent,
            "read_mb": disk_io.read_bytes / (1024**2) if disk_io else 0,
            "write_mb": disk_io.write_bytes / (1024**2) if disk_io else 0
        },
        "network": {
            "bytes_sent_mb": net_io.bytes_sent / (1024**2),
            "bytes_recv_mb": net_io.bytes_recv / (1024**2),
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv
        },
        "process": {
            "memory_mb": process_memory.rss / (1024**2),
            "cpu_percent": process_cpu,
            "threads": process.num_threads()
        }
    }


@router.get("/metrics/attacks")
async def get_attack_metrics(req: Request, hours: int = 24):
    """ดูสถิติการโจมตีย้อนหลัง"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Calculate time range
    start_time = datetime.now() - timedelta(hours=hours)
    
    # Query database
    async with db.pool.acquire() as conn:
        # Total attacks
        if user["role"] == "admin":
            total = await conn.fetchval("""
                SELECT COUNT(*) FROM attacks
                WHERE started_at >= $1
            """, start_time)
            
            # By status
            by_status = await conn.fetch("""
                SELECT status, COUNT(*) as count
                FROM attacks
                WHERE started_at >= $1
                GROUP BY status
            """, start_time)
            
            # By type
            by_type = await conn.fetch("""
                SELECT attack_type, COUNT(*) as count
                FROM attacks
                WHERE started_at >= $1
                GROUP BY attack_type
            """, start_time)
            
            # By user
            by_user = await conn.fetch("""
                SELECT u.username, COUNT(*) as count
                FROM attacks a
                JOIN users u ON a.user_id = u.id
                WHERE a.started_at >= $1
                GROUP BY u.username
                ORDER BY count DESC
                LIMIT 10
            """, start_time)
        else:
            # User can only see their own stats
            total = await conn.fetchval("""
                SELECT COUNT(*) FROM attacks
                WHERE user_id = $1 AND started_at >= $2
            """, user["id"], start_time)
            
            by_status = await conn.fetch("""
                SELECT status, COUNT(*) as count
                FROM attacks
                WHERE user_id = $1 AND started_at >= $2
                GROUP BY status
            """, user["id"], start_time)
            
            by_type = await conn.fetch("""
                SELECT attack_type, COUNT(*) as count
                FROM attacks
                WHERE user_id = $1 AND started_at >= $2
                GROUP BY attack_type
            """, user["id"], start_time)
            
            by_user = []
    
    return {
        "time_range_hours": hours,
        "total_attacks": total,
        "by_status": {row["status"]: row["count"] for row in by_status},
        "by_type": {row["attack_type"]: row["count"] for row in by_type},
        "by_user": {row["username"]: row["count"] for row in by_user} if user["role"] == "admin" else {}
    }


@router.get("/metrics/success-rate")
async def get_success_rate(req: Request, hours: int = 24):
    """ดูอัตราความสำเร็จของการโจมตี"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    start_time = datetime.now() - timedelta(hours=hours)
    
    async with db.pool.acquire() as conn:
        if user["role"] == "admin":
            stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN status = 'stopped' THEN 1 ELSE 0 END) as stopped,
                    SUM(CASE WHEN status IN ('pending', 'running') THEN 1 ELSE 0 END) as active
                FROM attacks
                WHERE started_at >= $1
            """, start_time)
        else:
            stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN status = 'stopped' THEN 1 ELSE 0 END) as stopped,
                    SUM(CASE WHEN status IN ('pending', 'running') THEN 1 ELSE 0 END) as active
                FROM attacks
                WHERE user_id = $1 AND started_at >= $2
            """, user["id"], start_time)
    
    total = stats["total"] or 0
    success = stats["success"] or 0
    failed = stats["failed"] or 0
    stopped = stats["stopped"] or 0
    active = stats["active"] or 0
    
    success_rate = (success / total * 100) if total > 0 else 0
    
    return {
        "time_range_hours": hours,
        "total": total,
        "success": success,
        "failed": failed,
        "stopped": stopped,
        "active": active,
        "success_rate_percent": round(success_rate, 2)
    }


@router.get("/metrics/vulnerabilities")
async def get_vulnerability_stats(req: Request, hours: int = 24):
    """ดูสถิติช่องโหว่ที่พบ"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    start_time = datetime.now() - timedelta(hours=hours)
    
    # Query agent logs for vulnerabilities
    async with db.pool.acquire() as conn:
        if user["role"] == "admin":
            logs = await conn.fetch("""
                SELECT agent_name, output, created_at
                FROM agent_logs
                WHERE status = 'success' 
                AND output LIKE '%vulnerab%'
                AND created_at >= $1
                ORDER BY created_at DESC
            """, start_time)
        else:
            logs = await conn.fetch("""
                SELECT al.agent_name, al.output, al.created_at
                FROM agent_logs al
                JOIN attacks a ON al.attack_id = a.attack_id
                WHERE a.user_id = $1
                AND al.status = 'success'
                AND al.output LIKE '%vulnerab%'
                AND al.created_at >= $2
                ORDER BY al.created_at DESC
            """, user["id"], start_time)
    
    # Count by agent
    vuln_by_agent = {}
    for log in logs:
        agent = log["agent_name"]
        vuln_by_agent[agent] = vuln_by_agent.get(agent, 0) + 1
    
    return {
        "time_range_hours": hours,
        "total_vulnerabilities_found": len(logs),
        "by_agent": vuln_by_agent
    }


@router.get("/metrics/data-exfiltrated")
async def get_data_exfiltration_stats(req: Request, hours: int = 24):
    """ดูสถิติข้อมูลที่ดึงออกมา"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    start_time = datetime.now() - timedelta(hours=hours)
    
    async with db.pool.acquire() as conn:
        if user["role"] == "admin":
            stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_files,
                    SUM(file_size) as total_size,
                    COUNT(DISTINCT attack_id) as attacks_with_data
                FROM dumped_files
                WHERE created_at >= $1
            """, start_time)
            
            # By type
            by_type = await conn.fetch("""
                SELECT file_type, COUNT(*) as count, SUM(file_size) as total_size
                FROM dumped_files
                WHERE created_at >= $1
                GROUP BY file_type
            """, start_time)
        else:
            stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_files,
                    SUM(df.file_size) as total_size,
                    COUNT(DISTINCT df.attack_id) as attacks_with_data
                FROM dumped_files df
                JOIN attacks a ON df.attack_id = a.attack_id
                WHERE a.user_id = $1 AND df.created_at >= $2
            """, user["id"], start_time)
            
            by_type = await conn.fetch("""
                SELECT df.file_type, COUNT(*) as count, SUM(df.file_size) as total_size
                FROM dumped_files df
                JOIN attacks a ON df.attack_id = a.attack_id
                WHERE a.user_id = $1 AND df.created_at >= $2
                GROUP BY df.file_type
            """, user["id"], start_time)
    
    return {
        "time_range_hours": hours,
        "total_files": stats["total_files"] or 0,
        "total_size_mb": (stats["total_size"] or 0) / (1024**2),
        "attacks_with_data": stats["attacks_with_data"] or 0,
        "by_type": {
            row["file_type"]: {
                "count": row["count"],
                "size_mb": row["total_size"] / (1024**2)
            }
            for row in by_type
        }
    }


@router.get("/health/detailed")
async def get_detailed_health(req: Request):
    """ตรวจสอบสุขภาพระบบแบบละเอียด"""
    # Get user
    api_key = req.headers.get("X-API-Key")
    user = await auth_service.verify_key(api_key)
    
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    health = {
        "timestamp": datetime.now().isoformat(),
        "overall_status": "healthy",
        "components": {}
    }
    
    # Database health
    try:
        db_healthy = await db.health_check()
        health["components"]["database"] = {
            "status": "healthy" if db_healthy else "unhealthy",
            "type": "PostgreSQL"
        }
    except Exception as e:
        health["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health["overall_status"] = "degraded"
    
    # LLM health
    try:
        import ollama
        models = ollama.list()
        health["components"]["llm"] = {
            "status": "healthy",
            "models": [m["name"] for m in models.get("models", [])],
            "count": len(models.get("models", []))
        }
    except Exception as e:
        health["components"]["llm"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health["overall_status"] = "degraded"
    
    # Disk space health
    disk = psutil.disk_usage('/')
    disk_status = "healthy" if disk.percent < 90 else "warning" if disk.percent < 95 else "critical"
    health["components"]["disk"] = {
        "status": disk_status,
        "percent": disk.percent,
        "free_gb": disk.free / (1024**3)
    }
    if disk_status != "healthy":
        health["overall_status"] = "degraded"
    
    # Memory health
    memory = psutil.virtual_memory()
    memory_status = "healthy" if memory.percent < 90 else "warning" if memory.percent < 95 else "critical"
    health["components"]["memory"] = {
        "status": memory_status,
        "percent": memory.percent,
        "available_gb": memory.available / (1024**3)
    }
    if memory_status != "healthy":
        health["overall_status"] = "degraded"
    
    # Active attacks
    active_count = await db.get_active_attacks_count()
    health["components"]["attacks"] = {
        "status": "healthy",
        "active_count": active_count
    }
    
    return health


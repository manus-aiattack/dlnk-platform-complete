"""
Statistics API Routes
Attack statistics and analytics
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/statistics", tags=["statistics"])


class StatisticsResponse(BaseModel):
    totalAttacks: int
    successfulAttacks: int
    failedAttacks: int
    averageDuration: float
    attacksByType: Dict[str, int]
    attacksOverTime: List[Dict[str, str]]
    successRate: float


# Mock statistics data (replace with database)
attacks_history = [
    {"id": "atk_001", "type": "SQL Injection", "success": True, "duration": 12.5, "timestamp": "2025-10-20T10:00:00"},
    {"id": "atk_002", "type": "XSS", "success": True, "duration": 8.3, "timestamp": "2025-10-20T11:00:00"},
    {"id": "atk_003", "type": "Buffer Overflow", "success": False, "duration": 45.2, "timestamp": "2025-10-21T09:00:00"},
    {"id": "atk_004", "type": "SQL Injection", "success": True, "duration": 15.7, "timestamp": "2025-10-22T14:00:00"},
    {"id": "atk_005", "type": "RCE", "success": True, "duration": 22.1, "timestamp": "2025-10-23T16:00:00"},
    {"id": "atk_006", "type": "XSS", "success": False, "duration": 6.8, "timestamp": "2025-10-24T12:00:00"},
    {"id": "atk_007", "type": "Privilege Escalation", "success": True, "duration": 18.9, "timestamp": "2025-10-25T08:00:00"},
]


@router.get("", response_model=StatisticsResponse)
async def get_statistics(range: str = Query("7d", regex="^(24h|7d|30d|all)$")):
    """
    Get attack statistics
    
    Args:
        range: Time range (24h, 7d, 30d, all)
    
    Returns:
        StatisticsResponse with aggregated statistics
    """
    try:
        # Filter attacks by time range
        now = datetime.now()
        
        if range == "24h":
            cutoff = now - timedelta(days=1)
        elif range == "7d":
            cutoff = now - timedelta(days=7)
        elif range == "30d":
            cutoff = now - timedelta(days=30)
        else:
            cutoff = datetime.min
        
        filtered_attacks = [
            a for a in attacks_history
            if datetime.fromisoformat(a["timestamp"]) >= cutoff
        ]
        
        # Calculate statistics
        total_attacks = len(filtered_attacks)
        successful_attacks = len([a for a in filtered_attacks if a["success"]])
        failed_attacks = total_attacks - successful_attacks
        
        # Average duration
        if total_attacks > 0:
            average_duration = sum(a["duration"] for a in filtered_attacks) / total_attacks
        else:
            average_duration = 0.0
        
        # Attacks by type
        attacks_by_type = {}
        for attack in filtered_attacks:
            attack_type = attack["type"]
            attacks_by_type[attack_type] = attacks_by_type.get(attack_type, 0) + 1
        
        # Attacks over time
        attacks_over_time = []
        
        if range == "24h":
            # Group by hour
            for i in range(24):
                hour_start = now - timedelta(hours=23-i)
                hour_end = hour_start + timedelta(hours=1)
                
                count = len([
                    a for a in filtered_attacks
                    if hour_start <= datetime.fromisoformat(a["timestamp"]) < hour_end
                ])
                
                attacks_over_time.append({
                    "date": hour_start.strftime("%H:00"),
                    "count": count
                })
        else:
            # Group by day
            days = 7 if range == "7d" else 30 if range == "30d" else 365
            
            for i in range(days):
                day_start = now - timedelta(days=days-1-i)
                day_end = day_start + timedelta(days=1)
                
                count = len([
                    a for a in filtered_attacks
                    if day_start <= datetime.fromisoformat(a["timestamp"]) < day_end
                ])
                
                attacks_over_time.append({
                    "date": day_start.strftime("%Y-%m-%d"),
                    "count": count
                })
        
        # Success rate
        success_rate = (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0.0
        
        return StatisticsResponse(
            totalAttacks=total_attacks,
            successfulAttacks=successful_attacks,
            failedAttacks=failed_attacks,
            averageDuration=average_duration,
            attacksByType=attacks_by_type,
            attacksOverTime=attacks_over_time,
            successRate=success_rate
        )
    
    except Exception as e:
        logger.error(f"Get statistics error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attacks")
async def get_attacks_history():
    """Get full attacks history"""
    return {"attacks": attacks_history}


@router.get("/top-techniques")
async def get_top_techniques(limit: int = 10):
    """Get top attack techniques"""
    
    # Count attacks by type
    technique_counts = {}
    for attack in attacks_history:
        attack_type = attack["type"]
        technique_counts[attack_type] = technique_counts.get(attack_type, 0) + 1
    
    # Sort by count
    top_techniques = sorted(
        technique_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:limit]
    
    return {
        "techniques": [
            {"name": name, "count": count}
            for name, count in top_techniques
        ]
    }


@router.get("/success-rate")
async def get_success_rate_by_type():
    """Get success rate by attack type"""
    
    # Calculate success rate for each type
    type_stats = {}
    
    for attack in attacks_history:
        attack_type = attack["type"]
        
        if attack_type not in type_stats:
            type_stats[attack_type] = {"total": 0, "successful": 0}
        
        type_stats[attack_type]["total"] += 1
        if attack["success"]:
            type_stats[attack_type]["successful"] += 1
    
    # Calculate rates
    success_rates = {
        attack_type: {
            "total": stats["total"],
            "successful": stats["successful"],
            "rate": (stats["successful"] / stats["total"] * 100) if stats["total"] > 0 else 0.0
        }
        for attack_type, stats in type_stats.items()
    }
    
    return {"success_rates": success_rates}


@router.get("/timeline")
async def get_attack_timeline(days: int = 30):
    """Get attack timeline"""
    
    now = datetime.now()
    cutoff = now - timedelta(days=days)
    
    timeline = [
        {
            "id": attack["id"],
            "type": attack["type"],
            "success": attack["success"],
            "duration": attack["duration"],
            "timestamp": attack["timestamp"]
        }
        for attack in attacks_history
        if datetime.fromisoformat(attack["timestamp"]) >= cutoff
    ]
    
    # Sort by timestamp
    timeline.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {"timeline": timeline}


@router.post("/record")
async def record_attack(attack: Dict):
    """Record new attack for statistics"""
    
    # Add timestamp if not present
    if "timestamp" not in attack:
        attack["timestamp"] = datetime.now().isoformat()
    
    # Add to history
    attacks_history.append(attack)
    
    return {"success": True, "attack_id": attack.get("id")}


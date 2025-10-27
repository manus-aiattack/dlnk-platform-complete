"""
One-Click Attack API Endpoint
Simple API for automated penetration testing
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict
import asyncio
import logging

# Import orchestrator
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.one_click_orchestrator import OneClickOrchestrator

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/one-click", tags=["one-click-attack"])

# Global orchestrator instance
orchestrator = OneClickOrchestrator()

# Store ongoing attacks
ongoing_attacks = {}


class OneClickAttackRequest(BaseModel):
    """One-click attack request"""
    target_url: HttpUrl
    api_key: Optional[str] = None
    async_mode: bool = True


class OneClickAttackResponse(BaseModel):
    """One-click attack response"""
    attack_id: str
    status: str
    message: str


@router.post("/attack", response_model=OneClickAttackResponse)
async def start_one_click_attack(
    request: OneClickAttackRequest,
    background_tasks: BackgroundTasks
):
    """
    Start a one-click automated attack
    
    **Input:**
    - target_url: Target URL to attack
    - api_key: Optional API key for authentication
    - async_mode: Run attack in background (default: true)
    
    **Output:**
    - attack_id: Unique attack identifier
    - status: Attack status
    - message: Status message
    
    **Example:**
    ```json
    {
        "target_url": "http://example.com",
        "api_key": "your_api_key",
        "async_mode": true
    }
    ```
    """
    
    try:
        target_url = str(request.target_url)
        
        log.info(f"[API] Starting one-click attack on: {target_url}")
        
        if request.async_mode:
            # Run in background
            import time
            attack_id = f"attack_{int(time.time())}"
            
            # Add to background tasks
            background_tasks.add_task(
                run_attack_background,
                attack_id,
                target_url,
                request.api_key
            )
            
            ongoing_attacks[attack_id] = {
                'status': 'running',
                'target_url': target_url,
                'progress': 0
            }
            
            return OneClickAttackResponse(
                attack_id=attack_id,
                status="started",
                message=f"Attack started in background. Use /attack/{attack_id}/status to check progress."
            )
        
        else:
            # Run synchronously (not recommended for production)
            result = await orchestrator.execute_one_click_attack(
                target_url=target_url,
                api_key=request.api_key
            )
            
            return OneClickAttackResponse(
                attack_id=result['attack_id'],
                status="completed",
                message="Attack completed successfully"
            )
    
    except Exception as e:
        log.error(f"[API] One-click attack failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack/{attack_id}/status")
async def get_attack_status(attack_id: str):
    """
    Get status of ongoing attack
    
    **Returns:**
    - attack_id: Attack identifier
    - status: Current status (running/completed/failed)
    - progress: Progress percentage
    - current_phase: Current attack phase
    - results: Attack results (if completed)
    """
    
    if attack_id not in ongoing_attacks:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    attack_info = ongoing_attacks[attack_id]
    
    return {
        'attack_id': attack_id,
        'status': attack_info['status'],
        'progress': attack_info.get('progress', 0),
        'current_phase': attack_info.get('current_phase'),
        'target_url': attack_info.get('target_url'),
        'results': attack_info.get('results')
    }


@router.get("/attack/{attack_id}/results")
async def get_attack_results(attack_id: str):
    """
    Get detailed results of completed attack
    
    **Returns:**
    - Complete attack results including:
      - Vulnerabilities found
      - Successful exploits
      - Exfiltrated data
      - Installed backdoors
      - Credentials harvested
    """
    
    if attack_id not in ongoing_attacks:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    attack_info = ongoing_attacks[attack_id]
    
    if attack_info['status'] != 'completed':
        raise HTTPException(
            status_code=400,
            detail=f"Attack is still {attack_info['status']}"
        )
    
    return attack_info.get('results', {})


@router.delete("/attack/{attack_id}")
async def stop_attack(attack_id: str):
    """
    Stop an ongoing attack
    
    **Returns:**
    - message: Confirmation message
    """
    
    if attack_id not in ongoing_attacks:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    attack_info = ongoing_attacks[attack_id]
    
    if attack_info['status'] == 'running':
        attack_info['status'] = 'stopped'
        return {'message': f'Attack {attack_id} stopped'}
    else:
        return {'message': f'Attack {attack_id} already {attack_info["status"]}'}


@router.get("/attacks")
async def list_attacks():
    """
    List all attacks
    
    **Returns:**
    - List of all attacks with their status
    """
    
    attacks = []
    
    for attack_id, info in ongoing_attacks.items():
        attacks.append({
            'attack_id': attack_id,
            'target_url': info.get('target_url'),
            'status': info['status'],
            'progress': info.get('progress', 0)
        })
    
    return {
        'total': len(attacks),
        'attacks': attacks
    }


async def run_attack_background(attack_id: str, target_url: str, api_key: Optional[str]):
    """Run attack in background"""
    
    try:
        log.info(f"[Background] Starting attack {attack_id}")
        
        # Update status
        ongoing_attacks[attack_id]['status'] = 'running'
        ongoing_attacks[attack_id]['current_phase'] = 'reconnaissance'
        ongoing_attacks[attack_id]['progress'] = 10
        
        # Execute attack
        result = await orchestrator.execute_one_click_attack(
            target_url=target_url,
            api_key=api_key
        )
        
        # Update with results
        ongoing_attacks[attack_id]['status'] = 'completed'
        ongoing_attacks[attack_id]['progress'] = 100
        ongoing_attacks[attack_id]['results'] = result
        
        log.info(f"[Background] Attack {attack_id} completed")
    
    except Exception as e:
        log.error(f"[Background] Attack {attack_id} failed: {e}")
        ongoing_attacks[attack_id]['status'] = 'failed'
        ongoing_attacks[attack_id]['error'] = str(e)


# Health check
@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'one-click-attack',
        'active_attacks': len([a for a in ongoing_attacks.values() if a['status'] == 'running'])
    }


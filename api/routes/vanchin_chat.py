#!/usr/bin/env python3
"""
Vanchin Chat API Routes
API สำหรับ Web Chat Interface ที่ใช้ Vanchin AI
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from loguru import logger

from core.vanchin_client import vanchin_client


router = APIRouter(prefix="/api/vanchin", tags=["Vanchin Chat"])


class ChatRequest(BaseModel):
    """Chat request model"""
    messages: List[Dict[str, str]]
    temperature: float = 0.7
    max_tokens: int = 2000


class ChatResponse(BaseModel):
    """Chat response model"""
    response: str
    model: str
    timestamp: str


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Chat with Vanchin AI
    
    Request:
    ```json
    {
        "messages": [
            {"role": "user", "content": "สวัสดี"},
            {"role": "assistant", "content": "สวัสดีครับ"},
            {"role": "user", "content": "วันนี้อากาศเป็นยังไง"}
        ]
    }
    ```
    
    Response:
    ```json
    {
        "response": "วันนี้อากาศดีครับ...",
        "model": "ep-rtt0hh-1761571039145129553",
        "timestamp": "2024-10-27T10:00:00"
    }
    ```
    """
    try:
        logger.info(f"[Vanchin Chat] Received chat request with {len(request.messages)} messages")
        
        # Call Vanchin AI
        response_text = vanchin_client.chat(
            messages=request.messages,
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )
        
        logger.success(f"[Vanchin Chat] Response generated: {len(response_text)} chars")
        
        from datetime import datetime
        
        return ChatResponse(
            response=response_text,
            model=vanchin_client.model,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"[Vanchin Chat] Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def status():
    """
    Get Vanchin AI status
    """
    return {
        "status": "online",
        "provider": "Vanchin AI",
        "model": vanchin_client.model,
        "base_url": vanchin_client.base_url
    }


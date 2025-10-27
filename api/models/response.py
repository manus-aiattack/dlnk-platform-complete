"""
Standardized API Response Models
"""

from typing import Optional, Any, List, Dict
from datetime import datetime
from pydantic import BaseModel, Field


class APIResponse(BaseModel):
    """Standard API response format"""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class PaginatedResponse(BaseModel):
    """Paginated API response"""
    success: bool = True
    data: List[Any]
    total: int
    page: int
    page_size: int
    pages: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    """Error response"""
    success: bool = False
    error: str
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


def success_response(data: Any = None, message: str = None) -> APIResponse:
    """Create success response"""
    return APIResponse(
        success=True,
        data=data,
        message=message
    )


def error_response(error: str, error_code: str = None, details: Dict[str, Any] = None) -> ErrorResponse:
    """Create error response"""
    return ErrorResponse(
        error=error,
        error_code=error_code,
        details=details
    )


def paginated_response(
    data: List[Any],
    total: int,
    page: int,
    page_size: int
) -> PaginatedResponse:
    """Create paginated response"""
    pages = (total + page_size - 1) // page_size
    return PaginatedResponse(
        data=data,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages
    )


"""
License Management Service
Handles license validation, feature gating, and usage tracking
"""

import asyncio
import hashlib
import hmac
import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.logger import log
from core.context_manager import ContextManager


class LicenseType(str):
    TRIAL = "trial"
    BASIC = "basic"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class License(BaseModel):
    license_key: str
    license_type: LicenseType
    organization: str
    issued_date: str
    expiry_date: str
    max_agents: int
    max_concurrent_workflows: int
    features: List[str]
    hardware_id: Optional[str] = None


class LicenseValidationRequest(BaseModel):
    license_key: str
    hardware_id: str


class FeatureAccessRequest(BaseModel):
    license_key: str
    feature_name: str


class LicenseService:
    """License Management Service"""
    
    def __init__(self):
        self.context_manager = None
        self.secret_key = os.getenv("LICENSE_SECRET_KEY", "dlnk_secret_key_change_me")
        self.encryption_key = self._derive_encryption_key()
        self.fernet = Fernet(self.encryption_key)
        
        # Feature definitions
        self.feature_tiers = {
            "trial": [
                "basic_scanning",
                "manual_exploitation",
                "basic_reporting"
            ],
            "basic": [
                "basic_scanning",
                "manual_exploitation",
                "basic_reporting",
                "automated_workflows",
                "basic_agents"
            ],
            "professional": [
                "basic_scanning",
                "manual_exploitation",
                "basic_reporting",
                "automated_workflows",
                "basic_agents",
                "advanced_agents",
                "ai_planning",
                "threat_intelligence",
                "advanced_c2",
                "data_exfiltration"
            ],
            "enterprise": [
                "basic_scanning",
                "manual_exploitation",
                "basic_reporting",
                "automated_workflows",
                "basic_agents",
                "advanced_agents",
                "ai_planning",
                "threat_intelligence",
                "advanced_c2",
                "data_exfiltration",
                "distributed_execution",
                "custom_agents",
                "api_access",
                "priority_support"
            ]
        }
    
    async def initialize(self):
        """Initialize service"""
        try:
            self.context_manager = ContextManager()
            await self.context_manager.setup()
            
            log.success("License Service initialized")
            
        except Exception as e:
            log.error(f"Failed to initialize License Service: {e}")
            raise
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from secret"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'dlnk_salt',
            iterations=100000,
        )
        key = kdf.derive(self.secret_key.encode())
        return base64.urlsafe_b64encode(key)
    
    def generate_license(
        self,
        license_type: LicenseType,
        organization: str,
        duration_days: int = 365,
        hardware_id: Optional[str] = None
    ) -> License:
        """Generate a new license"""
        try:
            issued_date = datetime.now()
            expiry_date = issued_date + timedelta(days=duration_days)
            
            # Determine license parameters based on type
            license_params = self._get_license_params(license_type)
            
            # Generate license key
            license_data = {
                "type": license_type,
                "org": organization,
                "issued": issued_date.isoformat(),
                "expiry": expiry_date.isoformat(),
                "hw_id": hardware_id
            }
            
            license_key = self._generate_license_key(license_data)
            
            license = License(
                license_key=license_key,
                license_type=license_type,
                organization=organization,
                issued_date=issued_date.isoformat(),
                expiry_date=expiry_date.isoformat(),
                max_agents=license_params["max_agents"],
                max_concurrent_workflows=license_params["max_concurrent_workflows"],
                features=self.feature_tiers.get(license_type, []),
                hardware_id=hardware_id
            )
            
            log.info(f"Generated {license_type} license for {organization}")
            
            return license
            
        except Exception as e:
            log.error(f"Failed to generate license: {e}")
            raise
    
    def _get_license_params(self, license_type: LicenseType) -> Dict:
        """Get license parameters based on type"""
        params = {
            "trial": {
                "max_agents": 10,
                "max_concurrent_workflows": 1
            },
            "basic": {
                "max_agents": 30,
                "max_concurrent_workflows": 3
            },
            "professional": {
                "max_agents": 62,
                "max_concurrent_workflows": 10
            },
            "enterprise": {
                "max_agents": -1,  # Unlimited
                "max_concurrent_workflows": -1  # Unlimited
            }
        }
        
        return params.get(license_type, params["trial"])
    
    def _generate_license_key(self, license_data: Dict) -> str:
        """Generate encrypted license key"""
        try:
            # Create JWT token
            token = jwt.encode(
                license_data,
                self.secret_key,
                algorithm="HS256"
            )
            
            # Encrypt token
            encrypted = self.fernet.encrypt(token.encode())
            
            # Format as license key (XXXX-XXXX-XXXX-XXXX)
            key_hex = encrypted.hex()[:16]
            formatted_key = '-'.join([key_hex[i:i+4] for i in range(0, 16, 4)])
            
            return formatted_key.upper()
            
        except Exception as e:
            log.error(f"Failed to generate license key: {e}")
            raise
    
    async def validate_license(self, license_key: str, hardware_id: str) -> Dict:
        """Validate license"""
        try:
            # Decrypt and decode license
            license_data = self._decode_license_key(license_key)
            
            if not license_data:
                return {
                    "valid": False,
                    "error": "Invalid license key"
                }
            
            # Check expiry
            expiry_date = datetime.fromisoformat(license_data.get("expiry"))
            if datetime.now() > expiry_date:
                return {
                    "valid": False,
                    "error": "License expired"
                }
            
            # Check hardware ID (if license is hardware-locked)
            if license_data.get("hw_id") and license_data.get("hw_id") != hardware_id:
                return {
                    "valid": False,
                    "error": "Hardware ID mismatch"
                }
            
            # Store validated license in context
            await self.context_manager.set_context("active_license", license_data)
            
            log.success(f"License validated for {license_data.get('org')}")
            
            return {
                "valid": True,
                "license_type": license_data.get("type"),
                "organization": license_data.get("org"),
                "expiry_date": license_data.get("expiry"),
                "features": self.feature_tiers.get(license_data.get("type"), [])
            }
            
        except Exception as e:
            log.error(f"License validation error: {e}")
            return {
                "valid": False,
                "error": str(e)
            }
    
    def _decode_license_key(self, license_key: str) -> Optional[Dict]:
        """Decode license key"""
        try:
            # Remove dashes and convert to bytes
            key_hex = license_key.replace("-", "").lower()
            
            # This is a simplified version - in production, implement proper decryption
            # For now, return mock license data
            return {
                "type": "professional",
                "org": "Test Organization",
                "issued": datetime.now().isoformat(),
                "expiry": (datetime.now() + timedelta(days=365)).isoformat(),
                "hw_id": None
            }
            
        except Exception as e:
            log.error(f"Failed to decode license key: {e}")
            return None
    
    async def check_feature_access(self, feature_name: str) -> bool:
        """Check if current license has access to feature"""
        try:
            license_data = await self.context_manager.get_context("active_license")
            
            if not license_data:
                log.warning("No active license found")
                return False
            
            license_type = license_data.get("type")
            allowed_features = self.feature_tiers.get(license_type, [])
            
            has_access = feature_name in allowed_features
            
            if not has_access:
                log.warning(f"Feature '{feature_name}' not available in {license_type} license")
            
            return has_access
            
        except Exception as e:
            log.error(f"Feature access check error: {e}")
            return False
    
    async def track_usage(self, metric: str, value: int = 1):
        """Track usage metrics"""
        try:
            license_data = await self.context_manager.get_context("active_license")
            
            if not license_data:
                return
            
            # Get current usage
            usage_key = f"license_usage:{license_data.get('org')}"
            usage = await self.context_manager.get_context(usage_key) or {}
            
            # Update metric
            if metric not in usage:
                usage[metric] = 0
            usage[metric] += value
            usage["last_updated"] = datetime.now().isoformat()
            
            # Store updated usage
            await self.context_manager.set_context(usage_key, usage)
            
        except Exception as e:
            log.error(f"Usage tracking error: {e}")
    
    async def get_usage_stats(self, organization: str) -> Dict:
        """Get usage statistics"""
        try:
            usage_key = f"license_usage:{organization}"
            usage = await self.context_manager.get_context(usage_key) or {}
            
            return usage
            
        except Exception as e:
            log.error(f"Failed to get usage stats: {e}")
            return {}
    
    async def check_limits(self) -> Dict:
        """Check if current usage is within license limits"""
        try:
            license_data = await self.context_manager.get_context("active_license")
            
            if not license_data:
                return {"within_limits": False, "error": "No active license"}
            
            # Get license parameters
            license_type = license_data.get("type")
            params = self._get_license_params(license_type)
            
            # Get current usage
            usage = await self.get_usage_stats(license_data.get("org"))
            
            # Check limits
            limits_ok = True
            limit_details = {}
            
            # Check agent count
            if params["max_agents"] != -1:
                current_agents = usage.get("agents_launched", 0)
                if current_agents > params["max_agents"]:
                    limits_ok = False
                limit_details["agents"] = {
                    "current": current_agents,
                    "max": params["max_agents"],
                    "within_limit": current_agents <= params["max_agents"]
                }
            
            # Check concurrent workflows
            if params["max_concurrent_workflows"] != -1:
                current_workflows = usage.get("concurrent_workflows", 0)
                if current_workflows > params["max_concurrent_workflows"]:
                    limits_ok = False
                limit_details["workflows"] = {
                    "current": current_workflows,
                    "max": params["max_concurrent_workflows"],
                    "within_limit": current_workflows <= params["max_concurrent_workflows"]
                }
            
            return {
                "within_limits": limits_ok,
                "license_type": license_type,
                "details": limit_details
            }
            
        except Exception as e:
            log.error(f"Limit check error: {e}")
            return {"within_limits": False, "error": str(e)}


# FastAPI Application
app = FastAPI(title="License Management Service")
license_service: Optional[LicenseService] = None


@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    global license_service
    
    try:
        license_service = LicenseService()
        await license_service.initialize()
        
        log.success("License Management Service started")
        
    except Exception as e:
        log.error(f"Failed to start License Management Service: {e}")
        raise


@app.post("/license/generate")
async def generate_license(
    license_type: str,
    organization: str,
    duration_days: int = 365,
    hardware_id: Optional[str] = None
):
    """Generate a new license"""
    try:
        license = license_service.generate_license(
            license_type=license_type,
            organization=organization,
            duration_days=duration_days,
            hardware_id=hardware_id
        )
        return license.dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/license/validate")
async def validate_license(request: LicenseValidationRequest):
    """Validate a license"""
    try:
        result = await license_service.validate_license(
            license_key=request.license_key,
            hardware_id=request.hardware_id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/license/check-feature")
async def check_feature_access(request: FeatureAccessRequest):
    """Check feature access"""
    try:
        # First validate license
        validation = await license_service.validate_license(
            license_key=request.license_key,
            hardware_id="temp"
        )
        
        if not validation.get("valid"):
            return {"has_access": False, "error": validation.get("error")}
        
        # Check feature access
        has_access = await license_service.check_feature_access(request.feature_name)
        
        return {
            "has_access": has_access,
            "feature_name": request.feature_name,
            "license_type": validation.get("license_type")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/license/limits")
async def check_limits():
    """Check license limits"""
    try:
        limits = await license_service.check_limits()
        return limits
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/license/usage/{organization}")
async def get_usage_stats(organization: str):
    """Get usage statistics"""
    try:
        stats = await license_service.get_usage_stats(organization)
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    if license_service is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    return {"status": "ready"}


if __name__ == "__main__":
    import uvicorn
    import base64
    uvicorn.run(app, host="0.0.0.0", port=8007)


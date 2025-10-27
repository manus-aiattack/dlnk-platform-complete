"""
Vanchin AI Agent API Routes
Provides AI Agent capabilities with Sandbox filesystem access
Uses Vanchin API instead of OpenAI
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
import subprocess
import json
import pathlib
import sys

# Add core to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')
from core.vanchin_multi_client import vanchin_multi_client

router = APIRouter(prefix="/api/vanchin")


# ============================================================================
# Models
# ============================================================================

class ChatMessage(BaseModel):
    role: str = Field(..., description="Message role: user, assistant, system")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., description="Conversation history")
    temperature: float = Field(0.7, ge=0, le=2)
    max_tokens: int = Field(2000, ge=1, le=4000)


class ChatResponse(BaseModel):
    role: str
    content: str
    timestamp: str
    actions_taken: Optional[List[Dict[str, Any]]] = None


class FileListRequest(BaseModel):
    path: str = Field("/home/ubuntu/aiprojectattack", description="Directory path to list")
    recursive: bool = Field(False, description="List recursively")


class FileReadRequest(BaseModel):
    path: str = Field(..., description="File path to read")
    encoding: str = Field("utf-8", description="File encoding")


class FileWriteRequest(BaseModel):
    path: str = Field(..., description="File path to write")
    content: str = Field(..., description="File content")
    encoding: str = Field("utf-8", description="File encoding")
    create_dirs: bool = Field(True, description="Create parent directories if not exist")


class FileDeleteRequest(BaseModel):
    path: str = Field(..., description="File or directory path to delete")
    recursive: bool = Field(False, description="Delete directory recursively")


class CommandExecuteRequest(BaseModel):
    command: str = Field(..., description="Shell command to execute")
    cwd: Optional[str] = Field(None, description="Working directory")
    timeout: int = Field(30, ge=1, le=300, description="Command timeout in seconds")


# ============================================================================
# Filesystem Operations
# ============================================================================

@router.post("/files/list")
async def list_files(request: FileListRequest):
    """List files in a directory"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")
        
        if not path.is_dir():
            raise HTTPException(status_code=400, detail=f"Path is not a directory: {request.path}")
        
        files = []
        
        if request.recursive:
            for item in path.rglob("*"):
                try:
                    stat = item.stat()
                    files.append({
                        "path": str(item),
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:]
                    })
                except (PermissionError, OSError):
                    continue
        else:
            for item in path.iterdir():
                try:
                    stat = item.stat()
                    files.append({
                        "path": str(item),
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:]
                    })
                except (PermissionError, OSError):
                    continue
        
        return {
            "success": True,
            "path": str(path),
            "files": sorted(files, key=lambda x: (x["type"] == "file", x["name"])),
            "count": len(files)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing files: {str(e)}")


@router.post("/files/read")
async def read_file(request: FileReadRequest):
    """Read file content"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {request.path}")
        
        if not path.is_file():
            raise HTTPException(status_code=400, detail=f"Path is not a file: {request.path}")
        
        # Check file size (limit to 10MB)
        if path.stat().st_size > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
        
        content = path.read_text(encoding=request.encoding)
        
        return {
            "success": True,
            "path": str(path),
            "content": content,
            "size": path.stat().st_size,
            "encoding": request.encoding
        }
    
    except HTTPException:
        raise
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Unable to decode file with specified encoding")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")


@router.post("/files/write")
async def write_file(request: FileWriteRequest):
    """Write content to file"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        # Create parent directories if needed
        if request.create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)
        
        path.write_text(request.content, encoding=request.encoding)
        
        return {
            "success": True,
            "path": str(path),
            "size": path.stat().st_size,
            "message": "File written successfully"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error writing file: {str(e)}")


@router.post("/files/delete")
async def delete_file(request: FileDeleteRequest):
    """Delete file or directory"""
    try:
        path = pathlib.Path(request.path).resolve()
        
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")
        
        if path.is_file():
            path.unlink()
            return {
                "success": True,
                "path": str(path),
                "message": "File deleted successfully"
            }
        elif path.is_dir():
            if request.recursive:
                import shutil
                shutil.rmtree(path)
                return {
                    "success": True,
                    "path": str(path),
                    "message": "Directory deleted successfully"
                }
            else:
                path.rmdir()
                return {
                    "success": True,
                    "path": str(path),
                    "message": "Empty directory deleted successfully"
                }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting: {str(e)}")


# ============================================================================
# Command Execution
# ============================================================================

@router.post("/command/execute")
async def execute_command(request: CommandExecuteRequest):
    """Execute shell command"""
    try:
        result = subprocess.run(
            request.command,
            shell=True,
            cwd=request.cwd,
            capture_output=True,
            text=True,
            timeout=request.timeout
        )
        
        return {
            "success": result.returncode == 0,
            "command": request.command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "cwd": request.cwd or os.getcwd()
        }
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail=f"Command timeout after {request.timeout} seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error executing command: {str(e)}")


# ============================================================================
# AI Chat with Agent Capabilities (Using Vanchin API)
# ============================================================================

@router.post("/chat", response_model=ChatResponse)
async def chat_with_agent(request: ChatRequest):
    """Chat with AI Agent that has access to filesystem and tools using Vanchin API"""
    try:
        # Convert messages to dict format
        messages = [{"role": msg.role, "content": msg.content} for msg in request.messages]
        
        # Add system message if not present
        if not any(msg["role"] == "system" for msg in messages):
            system_message = {
                "role": "system",
                "content": """You are Vanchin AI Agent, an intelligent assistant with access to the filesystem and command execution capabilities.

You are running in a Manus Sandbox environment with the following capabilities:
- List, read, write, and delete files
- Execute shell commands
- Access to the project directory: /home/ubuntu/aiprojectattack

When users ask you to perform tasks:
1. Analyze what needs to be done
2. Explain your plan clearly
3. Tell the user what actions you would take (list files, read files, execute commands)
4. Provide helpful and accurate responses

Be helpful, precise, and secure in your operations. Always explain what you're doing."""
            }
            messages.insert(0, system_message)
        
        # Call Vanchin Multi-Client (with automatic failover)
        response_text = vanchin_multi_client.chat(
            messages=messages,
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )
        
        # Check if response contains action requests
        actions_taken = []
        
        # Simple pattern matching for common requests
        if "list files" in response_text.lower() or "show files" in response_text.lower():
            actions_taken.append({
                "type": "suggestion",
                "action": "list_files",
                "description": "Agent suggests listing files"
            })
        
        if "read file" in response_text.lower() or "show content" in response_text.lower():
            actions_taken.append({
                "type": "suggestion",
                "action": "read_file",
                "description": "Agent suggests reading a file"
            })
        
        return ChatResponse(
            role="assistant",
            content=response_text,
            timestamp=datetime.now().isoformat(),
            actions_taken=actions_taken if actions_taken else None
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in chat: {str(e)}")


@router.get("/status")
async def get_status():
    """Get Vanchin Agent status"""
    client_status = vanchin_multi_client.get_status()
    
    return {
        "status": "operational",
        "version": "3.0.0",
        "api_provider": "Vanchin Multi-Client System",
        "capabilities": [
            "filesystem_access",
            "command_execution",
            "ai_chat",
            "project_analysis",
            "automatic_failover",
            "multi_api_support"
        ],
        "sandbox_path": "/home/ubuntu/aiprojectattack",
        "api_clients": client_status,
        "timestamp": datetime.now().isoformat()
    }


@router.post("/reset_health")
async def reset_health():
    """Reset health status of all API clients"""
    vanchin_multi_client.reset_health()
    return {
        "success": True,
        "message": "All API clients health reset"
    }


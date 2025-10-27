#!/usr/bin/env python3
"""
Run the dLNk API Server
"""

import uvicorn
from api.main import app

if __name__ == "__main__":
    uvicorn.run(
        "run_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
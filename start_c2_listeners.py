#!/usr/bin/env python3
"""
dLNk C2 Listeners Auto-Start
Automatically starts C2 listeners on system boot
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.shell_handler import ShellHandler
from loguru import logger

async def start_all_listeners():
    """Start all C2 listeners"""
    logger.info("[C2] Starting C2 listeners...")
    
    handler = ShellHandler()
    
    # Start primary listener on port 4444
    logger.info("[C2] Starting listener on port 4444...")
    success = await handler.start_listener(port=4444)
    
    if success:
        logger.success("[C2] ✅ Listener started on 0.0.0.0:4444")
        logger.info("[C2] C2 infrastructure ready")
        logger.info("[C2] Waiting for incoming connections...")
        
        # Keep running
        try:
            while True:
                await asyncio.sleep(60)
                # Log active sessions every minute
                active = len([s for s in handler.sessions.values() if s.is_active])
                if active > 0:
                    logger.info(f"[C2] Active sessions: {active}")
        except KeyboardInterrupt:
            logger.info("[C2] Shutting down...")
            handler.stop_listener()
    else:
        logger.error("[C2] ❌ Failed to start listener")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(start_all_listeners())
        sys.exit(exit_code)
    except Exception as e:
        logger.error(f"[C2] Fatal error: {e}")
        sys.exit(1)


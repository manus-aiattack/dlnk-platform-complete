import logging
import os
import json
import sys
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text
from rich.theme import Theme
from rich.panel import Panel
import sys
from pathlib import Path

# Add project root to sys.path for module imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from config import settings
except ImportError:
    settings = None  # Fallback if config not available
import redis.asyncio as aioredis
import asyncio # Added missing import
from typing import Optional # Added missing import


class RedisPubSubHandler(logging.Handler):
    def __init__(self, redis_client: aioredis.Redis, channel: str = "log_stream", **kwargs):
        super().__init__(**kwargs)
        self.redis = redis_client
        self.channel = channel

    def emit(self, record):
        try:
            message = self.format(record)
            # Attempt to get the current running event loop
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(self.redis.publish(self.channel, message), loop)
            else:
                # If no running loop, log a warning or handle differently
                # For now, we'll just print a warning to stderr
                print("Warning: Asyncio event loop not running for RedisPubSubHandler. Message not published.", file=sys.stderr)
        except Exception:
            self.handleError(record)
# --- ASCII Art Logo ---
LOGO = r"""
[bold cyan]
██████╗ ██╗     ███╗   ██╗██╗  ██╗
██╔══██╗██║     ████╗  ██║██║ ██╔╝
██║  ██║██║     ██╔██╗ ██║█████╔╝ 
██║  ██║██║     ██║╚██╗██║██╔═██╗ 
██████╔╝███████╗██║ ╚████║██║  ██╗ 
╚═════╝ ╚══════╝╚═╝  ╚═══╝╚╚═╝  ╚═╝ 
[/bold cyan]
"""

# --- Custom Log Levels ---
SUCCESS_LEVEL = 25
PHASE_LEVEL = 35

logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")
logging.addLevelName(PHASE_LEVEL, "PHASE")


def success(self, message, *args, **kws):
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kws)


def phase(self, message, *args, **kws):
    if self.isEnabledFor(PHASE_LEVEL):
        self._log(PHASE_LEVEL, message, args, **kws)


logging.Logger.success = success
logging.Logger.phase = phase

# --- Custom JSON Formatter ---


class JsonFormatter(logging.Formatter):
    """Formats log records into a JSON string."""

    def format(self, record):
        log_object = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
            "agent_name": getattr(record, "agent_name", None),
            "task_id": getattr(record, "task_id", None),
            "workflow_id": getattr(record, "workflow_id", None),
            "target_id": getattr(record, "target_id", None)
        }
        if record.exc_info:
            log_object['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_object)

# --- Logger Setup ---


def get_logger(name="dLNk", redis_client: Optional[aioredis.Redis] = None):
    """Configures and returns a logger with a modern, compact RichHandler."""
    # Fallback values if settings is None
    log_file = os.path.abspath(settings.LOG_FILE) if settings else "logs/dlnk.log"
    json_log_file = os.path.abspath(settings.JSON_LOG_FILE) if settings else "logs/dlnk.json"
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(name)
    if logger.hasHandlers():
        logger.handlers.clear()

    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO) if settings else logging.INFO
    logger.setLevel(log_level)

    # 1. Rich Console Handler (Hacker Theme)
    hacker_theme = Theme({
        "logging.level.success": "bold green",
        "logging.level.phase": "bold magenta",
        "logging.level.info": "cyan",
        "logging.level.warning": "yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold red on white",
        "logging.level.debug": "dim white",
    })
    
    console = Console(theme=hacker_theme)
    
    handler = RichHandler(
        console=console,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        show_path=False,
        log_time_format="[%H:%M:%S]",
    )
    
    # Custom format for the handler
    handler.setFormatter(logging.Formatter(
        fmt="%(message)s",
        datefmt="[%X]"
    ))

    logger.addHandler(handler)

    # 2. JSON File Handler (for structured logging)
    json_file_handler = logging.FileHandler(json_log_file)
    json_file_handler.setLevel(log_level)
    json_formatter = JsonFormatter()
    json_file_handler.setFormatter(json_formatter)
    logger.addHandler(json_file_handler)

    # Add a global attribute for the console to be used by other modules
    logger.console = console

    # 3. Redis Pub/Sub Handler (for real-time dashboard streaming)
    if redis_client:
        redis_handler = RedisPubSubHandler(redis_client=redis_client)
        redis_handler.setLevel(log_level)
        redis_handler.setFormatter(JsonFormatter())
        logger.addHandler(redis_handler)

    return logger


def display_logo():
    """Displays the ASCII art logo with color."""
    console = Console()
    logo_text = Text.from_markup(LOGO, justify="center")
    console.print(logo_text)
    console.print("[bold white]Autonomous Security Operations[/bold white]", justify="center")
    console.print("-" * 60, justify="center")


# --- Pre-configured logger instance ---
log = get_logger() # Placeholder, will be initialized properly by orchestrator

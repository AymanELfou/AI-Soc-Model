"""
logger.py
=========
Centralized structured logger for the AI Security Agent.
Logs to both console and file (logs/agent.log).
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

def setup_logger(name: str = "ai_security_agent", log_dir: str = "./logs", level: int = logging.INFO) -> logging.Logger:
    """Setup and return a configured logger instance."""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "agent.log")

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # Rotating File Handler (10MB max size, 5 backups)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    return logger

# Global default logger instance
logger = setup_logger()

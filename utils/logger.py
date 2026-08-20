"""
utils/logger.py
One rotating log file per component, plus a shared console handler.
Keeps monitor failures visible without spamming stdout when running as CLI.
"""

import logging
import logging.handlers
from pathlib import Path

import config


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        # Already configured (module re-imported) — don't double-attach handlers.
        return logger

    logger.setLevel(config.LOG_LEVEL)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    log_file = Path(config.LOG_DIR) / "cybersentinel.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    logger.propagate = False
    return logger

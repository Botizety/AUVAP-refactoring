"""Logging utilities for the AUVAP project.

This module centralizes log configuration so every run produces consistent
console and file output with basic retention and compression for older logs.
"""

from __future__ import annotations

import gzip
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path

LOGGER_NAME = "auvap"
LOG_FILE_PATTERN = "auvap_%Y%m%d_%H%M%S.log"


def setup_logging(log_dir: str = "logs", log_level: str = "INFO") -> logging.Logger:
    """Configure console and file logging for the current run.

    Args:
        log_dir: Directory where log files should be written.
        log_level: Minimum level for console logging.

    Returns:
        Configured logger instance ready for use across the application.
    """

    level = _safe_log_level(log_level)
    log_path = _create_log_file(log_dir)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    _retain_and_compress_logs(Path(log_dir))
    logger.debug("Logging initialized -> %s", log_path)
    return logger


def _safe_log_level(log_level: str) -> int:
    """Resolve a user-supplied log level string to a logging constant."""

    normalized = (log_level or "INFO").upper()
    if normalized in logging._nameToLevel:  # type: ignore[attr-defined]
        return logging._nameToLevel[normalized]  # type: ignore[attr-defined]
    return logging.INFO


def _create_log_file(log_dir: str) -> Path:
    """Create a timestamped log file path within *log_dir*."""

    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime(LOG_FILE_PATTERN)
    return directory / timestamp


def _retain_and_compress_logs(directory: Path, keep: int = 10) -> None:
    """Keep the newest *keep* logs uncompressed and gzip older runs."""

    if not directory.exists():
        return

    log_files = sorted(
        (p for p in directory.glob("auvap_*.log")),
        key=os.path.getmtime,
        reverse=True,
    )

    for index, log_path in enumerate(log_files):
        if index < keep:
            continue
        _compress_log(log_path)


def _compress_log(log_path: Path) -> None:
    """Compress *log_path* in-place using gzip if not already compressed."""

    gz_path = log_path.with_suffix(log_path.suffix + ".gz")
    if gz_path.exists():
        log_path.unlink(missing_ok=True)
        return

    with log_path.open("rb") as source, gzip.open(gz_path, "wb") as target:
        shutil.copyfileobj(source, target)
    log_path.unlink(missing_ok=True)

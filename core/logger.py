"""
core/logger.py — BlueSentinel V2.0 Structured Logger
=====================================================
Two-channel logging:
- Console: colored output via colorama
- File: structured JSON, one record per line (NDJSON format)
- Retention: 7 days (auto-purge on startup)
- Log files: logs/bluesentinel_YYYY-MM-DD.log (one file per day)
- Query: get_logs_by_date(date) or get_logs_range(start, end)
"""

import logging
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

LOG_DIR             = Path("logs")
LOG_RETENTION_DAYS  = 7
_loggers: Dict[str, logging.Logger] = {}
_log_lock = threading.Lock()


class JSONFileHandler(logging.Handler):
    """
    Writes structured JSON log records to daily log files.
    One JSON object per line (NDJSON format) for easy parsing.
    File: logs/bluesentinel_YYYY-MM-DD.log
    """

    def __init__(self):
        super().__init__()
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def _get_log_file(self) -> Path:
        date_str = datetime.utcnow().strftime('%Y-%m-%d')
        return LOG_DIR / f"bluesentinel_{date_str}.log"

    def emit(self, record: logging.LogRecord):
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level":     record.levelname,
                "module":    record.name,
                "message":   record.getMessage(),
                "context":   getattr(record, 'context', {}),
            }
            if record.exc_info:
                log_entry["exception"] = self.formatException(record.exc_info)

            line = json.dumps(log_entry, ensure_ascii=False) + "\n"
            with _log_lock:
                with open(self._get_log_file(), 'a', encoding='utf-8') as f:
                    f.write(line)
        except Exception:
            pass


class ColorConsoleHandler(logging.StreamHandler):
    """Colored console output."""

    COLORS = {
        'DEBUG':    '\033[38;2;58;85;112m',
        'INFO':     '\033[38;2;0;212;255m',
        'WARNING':  '\033[38;2;255;184;0m',
        'ERROR':    '\033[38;2;255;59;92m',
        'CRITICAL': '\033[38;2;255;59;92m' + Style.BRIGHT,
    }

    def emit(self, record: logging.LogRecord):
        color = self.COLORS.get(record.levelname, '')
        reset = Style.RESET_ALL
        ts    = datetime.utcnow().strftime('%H:%M:%S')
        ctx   = getattr(record, 'context', {})
        ctx_str = f" {json.dumps(ctx)}" if ctx else ""
        msg = (
            f"\033[38;2;58;85;112m[{ts}]{reset} "
            f"{color}[{record.levelname[:4]}]{reset} "
            f"\033[38;2;122;154;184m{record.name}{reset}: "
            f"{record.getMessage()}{ctx_str}"
        )
        try:
            print(msg)
        except Exception:
            pass


def purge_old_logs():
    """Delete log files older than LOG_RETENTION_DAYS."""
    if not LOG_DIR.exists():
        return
    cutoff = datetime.utcnow() - timedelta(days=LOG_RETENTION_DAYS)
    for log_file in LOG_DIR.glob("bluesentinel_*.log"):
        try:
            date_str  = log_file.stem.replace("bluesentinel_", "")
            file_date = datetime.strptime(date_str, "%Y-%m-%d")
            if file_date < cutoff:
                log_file.unlink()
        except Exception:
            pass


def get_logger(name: str) -> logging.Logger:
    """Get or create a logger for the given module name."""
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(f"bluesentinel.{name}")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(ColorConsoleHandler())
        logger.addHandler(JSONFileHandler())
        logger.propagate = False

    _loggers[name] = logger
    return logger


def get_logs_by_date(date: str) -> List[dict]:
    """
    Return all log entries for a specific date.
    date format: 'YYYY-MM-DD'
    """
    log_file = LOG_DIR / f"bluesentinel_{date}.log"
    if not log_file.exists():
        return []
    entries = []
    for line in log_file.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return entries


def get_logs_range(start_date: str, end_date: str) -> List[dict]:
    """
    Return all log entries between start_date and end_date (inclusive).
    date format: 'YYYY-MM-DD'
    """
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end   = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        return []

    all_entries = []
    current = start
    while current <= end:
        date_str = current.strftime("%Y-%m-%d")
        all_entries.extend(get_logs_by_date(date_str))
        current += timedelta(days=1)

    return all_entries


def list_available_log_dates() -> List[str]:
    """Return list of dates that have log files, most recent first."""
    if not LOG_DIR.exists():
        return []
    dates = []
    for log_file in sorted(LOG_DIR.glob("bluesentinel_*.log"), reverse=True):
        date_str = log_file.stem.replace("bluesentinel_", "")
        if log_file.stat().st_size > 0:
            dates.append(date_str)
    return dates


# Backward-compatible alias
class ContextLogger:
    """Wraps a logger and automatically injects context into every call."""
    def __init__(self, logger: logging.Logger, context: Dict[str, Any] = None):
        self._logger = logger
        self._context = context or {}

    def _log(self, level: int, msg: str, context: Optional[Dict[str, Any]] = None) -> None:
        merged = {**self._context, **(context or {})}
        extra = {"context": merged} if merged else {}
        self._logger.log(level, msg, extra=extra)

    def debug(self, msg, context=None):
        self._log(logging.DEBUG, msg, context)

    def info(self, msg, context=None):
        self._log(logging.INFO, msg, context)

    def warning(self, msg, context=None):
        self._log(logging.WARNING, msg, context)

    def error(self, msg, context=None):
        self._log(logging.ERROR, msg, context)

    def critical(self, msg, context=None):
        self._log(logging.CRITICAL, msg, context)


# Purge old logs on module import
purge_old_logs()

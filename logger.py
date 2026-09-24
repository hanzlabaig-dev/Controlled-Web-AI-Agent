"""
logger.py — Structured JSON-lines logging with automatic redaction.

Never logs secrets: API keys, passwords, cookies, authorization headers,
session tokens. security.redact_headers / redact_json_body are applied to
anything that goes through log_tool_call.
"""

import json
import os
from datetime import datetime, timezone

import config
import security


def _ensure_log_dir():
    log_dir = os.path.dirname(config.LOG_FILE_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)


def log_event(event: dict) -> None:
    """Append a single JSON event to the log file. Never raises."""
    _ensure_log_dir()
    event = dict(event)
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        with open(config.LOG_FILE_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except OSError:
        # Logging must never crash the agent.
        pass


def log_tool_call(
    tool: str,
    *,
    path: str = None,
    url: str = None,
    status: int = None,
    method: str = None,
    request_headers: dict = None,
    response_headers: dict = None,
    request_body=None,
    error: str = None,
    approved: bool = None,
) -> None:
    event = {
        "tool": tool,
        "method": method,
        "path": path,
        "url": url,
        "status": status,
        "approved": approved,
        "error": error,
    }
    if request_headers:
        event["request_headers"] = security.redact_headers(request_headers)
    if response_headers:
        event["response_headers"] = security.redact_headers(response_headers)
    if request_body is not None:
        event["request_body"] = security.redact_json_body(request_body)

    # Drop None values for cleaner logs.
    event = {k: v for k, v in event.items() if v is not None}
    log_event(event)


def log_security_block(tool: str, reason: str) -> None:
    log_event({"tool": tool, "blocked": True, "reason": reason})

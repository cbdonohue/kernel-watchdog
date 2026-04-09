"""
alerts.py — Alert dispatchers for kernel-watchdog.

Dispatchers:
  - Console logger (always active)
  - Telegram bot message
  - Webhook (generic HTTP POST)
  - File logger (JSONL append)

Configuration lives in rules YAML under the 'config' key:

    config:
      telegram:
        enabled: true
        bot_token: "YOUR_BOT_TOKEN"
        chat_id: "YOUR_CHAT_ID"
        min_severity: high     # only send high/critical alerts
      webhook:
        enabled: false
        url: "https://example.com/hook"
        headers:
          Authorization: "Bearer token"
        min_severity: medium
      log:
        enabled: true
        path: alerts.jsonl
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

import urllib.request
import urllib.error

log = logging.getLogger("alerts")

# Severity ordering for min_severity filtering
SEVERITY_ORDER = {
    "critical": 5,
    "high":     4,
    "medium":   3,
    "low":      2,
    "info":     1,
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


def _severity_passes(event_severity: str, min_severity: str) -> bool:
    """Return True if event_severity >= min_severity."""
    return SEVERITY_ORDER.get(event_severity, 0) >= SEVERITY_ORDER.get(min_severity, 0)


def _format_event(rule, event: dict) -> str:
    """Build a human-readable alert summary."""
    emoji  = SEVERITY_EMOJI.get(rule.severity, "❓")
    ts     = event.get("ts", "")
    etype  = event.get("type", "unknown").upper()
    pid    = event.get("pid", "?")
    uid    = event.get("uid", "?")
    comm   = event.get("comm", "?")

    lines = [
        f"{emoji} [{rule.severity.upper()}] {rule.name}",
        f"   desc:  {rule.description}" if rule.description else "",
        f"   event: {etype} | pid={pid} uid={uid} comm={comm}",
    ]

    # Type-specific details
    if etype == "EXEC":
        lines.append(f"   file:  {event.get('filename', '?')}")
    elif etype == "OPEN":
        lines.append(f"   path:  {event.get('path', '?')}")
    elif etype == "CONNECT":
        lines.append(f"   net:   {event.get('src', '?')} → {event.get('dst', '?')}:{event.get('dport', '?')}")
    elif etype == "PRIVESC":
        lines.append(f"   uid change: {event.get('uid', '?')} → {event.get('new_uid', '?')} via {event.get('syscall', '?')}")

    lines.append(f"   ts:    {ts}")
    return "\n".join(l for l in lines if l)


# ──────────────────────────────────────────────────────────────────────────────
# Individual dispatchers
# ──────────────────────────────────────────────────────────────────────────────

class ConsoleDispatcher:
    """Always-on: prints to stdout via logging."""

    def dispatch(self, rule, event: dict):
        msg = _format_event(rule, event)
        level = {
            "critical": logging.CRITICAL,
            "high":     logging.ERROR,
            "medium":   logging.WARNING,
            "low":      logging.INFO,
            "info":     logging.DEBUG,
        }.get(rule.severity, logging.INFO)
        log.log(level, "\n%s", msg)


class TelegramDispatcher:
    """
    Sends alert messages to a Telegram chat via Bot API.

    Rate-limited to avoid flooding (max 1 message / 2 seconds per chat).
    Retries once on transient HTTP errors.
    """

    API_BASE = "https://api.telegram.org/bot{token}/sendMessage"
    _last_sent: float = 0.0
    _lock = threading.Lock()
    MIN_INTERVAL = 2.0  # seconds between messages

    def __init__(self, bot_token: str, chat_id: str, min_severity: str = "high"):
        self.bot_token    = bot_token
        self.chat_id      = str(chat_id)
        self.min_severity = min_severity
        self.url          = self.API_BASE.format(token=bot_token)

    def dispatch(self, rule, event: dict):
        if not _severity_passes(rule.severity, self.min_severity):
            return

        text = _format_event(rule, event)
        self._send(text)

    def _send(self, text: str, attempt: int = 1):
        with self._lock:
            elapsed = time.monotonic() - self._last_sent
            if elapsed < self.MIN_INTERVAL:
                time.sleep(self.MIN_INTERVAL - elapsed)
            self._last_sent = time.monotonic()

        payload = json.dumps({
            "chat_id":    self.chat_id,
            "text":       text,
            "parse_mode": "HTML",
        }).encode()

        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status not in (200, 201):
                    log.warning("Telegram returned HTTP %d", resp.status)
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt == 1:
                retry_after = int(exc.headers.get("Retry-After", 5))
                log.warning("Telegram rate-limited, retrying in %ds", retry_after)
                time.sleep(retry_after)
                self._send(text, attempt=2)
            else:
                log.error("Telegram HTTP error %d: %s", exc.code, exc.reason)
        except Exception as exc:
            log.error("Telegram dispatch error: %s", exc)


class WebhookDispatcher:
    """Posts JSON alert payloads to a generic HTTP endpoint."""

    def __init__(self, url: str, headers: Optional[dict] = None,
                 min_severity: str = "medium"):
        self.url          = url
        self.headers      = headers or {}
        self.min_severity = min_severity

    def dispatch(self, rule, event: dict):
        if not _severity_passes(rule.severity, self.min_severity):
            return

        payload = json.dumps({
            "rule":      rule.name,
            "severity":  rule.severity,
            "tags":      rule.tags,
            "event":     event,
            "ts":        datetime.now(timezone.utc).isoformat(),
        }).encode()

        headers = {"Content-Type": "application/json", **self.headers}
        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                log.debug("Webhook response: %d", resp.status)
        except Exception as exc:
            log.error("Webhook dispatch error: %s", exc)


class FileDispatcher:
    """Appends JSON alert records to a JSONL file."""

    def __init__(self, path: str, min_severity: str = "info"):
        self.path         = Path(path)
        self.min_severity = min_severity
        self._fh          = self.path.open("a", buffering=1)

    def dispatch(self, rule, event: dict):
        if not _severity_passes(rule.severity, self.min_severity):
            return
        record = {
            "alert_ts":  datetime.now(timezone.utc).isoformat(),
            "rule":      rule.name,
            "severity":  rule.severity,
            "tags":      rule.tags,
            "event":     event,
        }
        self._fh.write(json.dumps(record) + "\n")

    def close(self):
        self._fh.close()


# ──────────────────────────────────────────────────────────────────────────────
# Alert dispatcher — orchestrates all channels
# ──────────────────────────────────────────────────────────────────────────────

class AlertDispatcher:
    """
    Reads alert channel configuration and dispatches fired rules
    to all enabled channels.
    """

    def __init__(self, config: dict):
        self._dispatchers = []
        self._setup(config)

    def _setup(self, config: dict):
        # Console is always on
        self._dispatchers.append(ConsoleDispatcher())

        # Telegram
        tg = config.get("telegram", {})
        if tg.get("enabled"):
            token = tg.get("bot_token", "")
            chat  = tg.get("chat_id", "")
            if token and chat:
                self._dispatchers.append(TelegramDispatcher(
                    bot_token=token,
                    chat_id=str(chat),
                    min_severity=tg.get("min_severity", "high"),
                ))
                log.info("Telegram alerts enabled (min_severity=%s)", tg.get("min_severity", "high"))
            else:
                log.warning("Telegram enabled but bot_token/chat_id missing — skipping")

        # Webhook
        wh = config.get("webhook", {})
        if wh.get("enabled"):
            url = wh.get("url", "")
            if url:
                self._dispatchers.append(WebhookDispatcher(
                    url=url,
                    headers=wh.get("headers", {}),
                    min_severity=wh.get("min_severity", "medium"),
                ))
                log.info("Webhook alerts enabled → %s", url)
            else:
                log.warning("Webhook enabled but URL missing — skipping")

        # File
        fl = config.get("log", {})
        if fl.get("enabled"):
            path = fl.get("path", "alerts.jsonl")
            self._dispatchers.append(FileDispatcher(
                path=path,
                min_severity=fl.get("min_severity", "info"),
            ))
            log.info("File alerts enabled → %s", path)

    def dispatch(self, rule, event: dict):
        """Fan out to all configured dispatchers (non-blocking best-effort)."""
        for d in self._dispatchers:
            try:
                d.dispatch(rule, event)
            except Exception as exc:
                log.error("Dispatcher %s error: %s", type(d).__name__, exc)

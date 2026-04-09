"""
tests/test_alerts.py — Unit tests for alert dispatchers.

Tests use mocking to avoid real HTTP calls or file I/O side effects.
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock, call
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alerts import (
    ConsoleDispatcher,
    TelegramDispatcher,
    WebhookDispatcher,
    FileDispatcher,
    AlertDispatcher,
    _severity_passes,
    _format_event,
    SEVERITY_ORDER,
)
from rules import Rule


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

def make_rule(name="test-rule", severity="high", description="Test rule"):
    return Rule({
        "name": name,
        "severity": severity,
        "description": description,
        "event_type": "open",
        "conditions": [],
        "tags": ["test"],
    })


SAMPLE_EVENT = {
    "type": "open",
    "ts": "2025-01-01T12:00:00+00:00",
    "pid": 1234,
    "uid": 1000,
    "gid": 1000,
    "comm": "bash",
    "path": "/etc/passwd",
}

EXEC_EVENT = {
    "type": "exec",
    "ts": "2025-01-01T12:00:01+00:00",
    "pid": 5678,
    "uid": 0,
    "comm": "sudo",
    "filename": "/usr/bin/sudo",
    "args": "-l",
}

NET_EVENT = {
    "type": "connect",
    "ts": "2025-01-01T12:00:02+00:00",
    "pid": 999,
    "uid": 1000,
    "comm": "curl",
    "src": "10.0.0.1",
    "dst": "93.184.216.34",
    "dport": 443,
    "sport": 54321,
}

PRIVESC_EVENT = {
    "type": "privesc",
    "ts": "2025-01-01T12:00:03+00:00",
    "pid": 8888,
    "uid": 1000,
    "new_uid": 0,
    "comm": "exploit",
    "syscall": "setuid",
}


# ──────────────────────────────────────────────────────────────────────────────
# Utility tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSeverityPasses(unittest.TestCase):
    def test_critical_passes_any(self):
        for sev in SEVERITY_ORDER:
            assert _severity_passes("critical", sev)

    def test_info_only_passes_info(self):
        assert _severity_passes("info", "info")
        assert not _severity_passes("info", "low")

    def test_high_passes_high_medium_low_info(self):
        assert _severity_passes("high", "high")
        assert _severity_passes("high", "medium")
        assert _severity_passes("high", "info")
        assert not _severity_passes("high", "critical")


class TestFormatEvent(unittest.TestCase):
    def test_open_format(self):
        rule = make_rule(severity="high")
        msg = _format_event(rule, SAMPLE_EVENT)
        assert "/etc/passwd" in msg
        assert "HIGH" in msg
        assert "test-rule" in msg

    def test_exec_format(self):
        rule = make_rule(severity="medium")
        msg = _format_event(rule, EXEC_EVENT)
        assert "sudo" in msg.lower() or "/usr/bin/sudo" in msg

    def test_net_format(self):
        rule = make_rule(severity="low")
        msg = _format_event(rule, NET_EVENT)
        assert "93.184.216.34" in msg or "443" in msg

    def test_privesc_format(self):
        rule = make_rule(severity="critical")
        msg = _format_event(rule, PRIVESC_EVENT)
        assert "setuid" in msg or "1000" in msg


# ──────────────────────────────────────────────────────────────────────────────
# ConsoleDispatcher
# ──────────────────────────────────────────────────────────────────────────────

class TestConsoleDispatcher(unittest.TestCase):
    def test_dispatch_does_not_raise(self):
        d = ConsoleDispatcher()
        rule = make_rule()
        # Should not raise regardless of severity
        d.dispatch(rule, SAMPLE_EVENT)
        d.dispatch(make_rule(severity="critical"), PRIVESC_EVENT)


# ──────────────────────────────────────────────────────────────────────────────
# TelegramDispatcher
# ──────────────────────────────────────────────────────────────────────────────

class TestTelegramDispatcher(unittest.TestCase):
    def _make(self, min_severity="low"):
        return TelegramDispatcher(
            bot_token="fake_token",
            chat_id="12345",
            min_severity=min_severity,
        )

    @patch("alerts.urllib.request.urlopen")
    def test_sends_on_high_severity(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_resp.status    = 200
        mock_urlopen.return_value = mock_resp

        d = self._make(min_severity="high")
        rule = make_rule(severity="critical")
        d.dispatch(rule, SAMPLE_EVENT)
        mock_urlopen.assert_called_once()

    @patch("alerts.urllib.request.urlopen")
    def test_skips_below_min_severity(self, mock_urlopen):
        d = self._make(min_severity="high")
        rule = make_rule(severity="low")
        d.dispatch(rule, SAMPLE_EVENT)
        mock_urlopen.assert_not_called()

    @patch("alerts.urllib.request.urlopen")
    def test_payload_contains_rule_name(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_resp.status    = 200
        mock_urlopen.return_value = mock_resp

        d = self._make(min_severity="info")
        rule = make_rule(name="my-special-rule", severity="high")
        d.dispatch(rule, SAMPLE_EVENT)

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        body = req.data.decode()
        assert "my-special-rule" in body


# ──────────────────────────────────────────────────────────────────────────────
# WebhookDispatcher
# ──────────────────────────────────────────────────────────────────────────────

class TestWebhookDispatcher(unittest.TestCase):
    @patch("alerts.urllib.request.urlopen")
    def test_sends_json_payload(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_resp.status    = 200
        mock_urlopen.return_value = mock_resp

        d = WebhookDispatcher(url="https://example.com/hook", min_severity="info")
        rule = make_rule(severity="medium")
        d.dispatch(rule, SAMPLE_EVENT)

        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode())
        assert body["rule"] == "test-rule"
        assert body["severity"] == "medium"
        assert "event" in body

    @patch("alerts.urllib.request.urlopen")
    def test_skips_below_min_severity(self, mock_urlopen):
        d = WebhookDispatcher(url="https://example.com/hook", min_severity="high")
        rule = make_rule(severity="low")
        d.dispatch(rule, SAMPLE_EVENT)
        mock_urlopen.assert_not_called()

    @patch("alerts.urllib.request.urlopen")
    def test_custom_headers_sent(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__  = MagicMock(return_value=False)
        mock_resp.status    = 200
        mock_urlopen.return_value = mock_resp

        d = WebhookDispatcher(
            url="https://example.com/hook",
            headers={"Authorization": "Bearer secret"},
            min_severity="info",
        )
        rule = make_rule(severity="info")
        d.dispatch(rule, SAMPLE_EVENT)
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer secret"


# ──────────────────────────────────────────────────────────────────────────────
# FileDispatcher
# ──────────────────────────────────────────────────────────────────────────────

class TestFileDispatcher(unittest.TestCase):
    def test_writes_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as tf:
            path = tf.name

        try:
            d = FileDispatcher(path=path, min_severity="info")
            rule = make_rule(severity="high")
            d.dispatch(rule, SAMPLE_EVENT)
            d.dispatch(rule, NET_EVENT)
            d.close()

            with open(path) as f:
                lines = f.readlines()

            assert len(lines) == 2
            rec = json.loads(lines[0])
            assert rec["rule"] == "test-rule"
            assert rec["severity"] == "high"
            assert "event" in rec
        finally:
            os.unlink(path)

    def test_skips_below_min_severity(self):
        with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as tf:
            path = tf.name
        try:
            d = FileDispatcher(path=path, min_severity="high")
            rule = make_rule(severity="low")
            d.dispatch(rule, SAMPLE_EVENT)
            d.close()

            with open(path) as f:
                content = f.read()
            assert content == ""
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# AlertDispatcher
# ──────────────────────────────────────────────────────────────────────────────

class TestAlertDispatcher(unittest.TestCase):
    def _make_config(self, **overrides):
        base = {
            "telegram": {"enabled": False},
            "webhook":  {"enabled": False},
            "log":      {"enabled": False},
        }
        base.update(overrides)
        return base

    def test_console_always_present(self):
        d = AlertDispatcher(self._make_config())
        from alerts import ConsoleDispatcher
        assert any(isinstance(x, ConsoleDispatcher) for x in d._dispatchers)

    def test_telegram_added_when_enabled(self):
        config = self._make_config(telegram={
            "enabled": True,
            "bot_token": "tok",
            "chat_id": "123",
            "min_severity": "high",
        })
        d = AlertDispatcher(config)
        from alerts import TelegramDispatcher
        assert any(isinstance(x, TelegramDispatcher) for x in d._dispatchers)

    def test_telegram_skipped_without_token(self):
        config = self._make_config(telegram={
            "enabled": True,
            "bot_token": "",
            "chat_id": "123",
        })
        d = AlertDispatcher(config)
        from alerts import TelegramDispatcher
        assert not any(isinstance(x, TelegramDispatcher) for x in d._dispatchers)

    def test_file_dispatcher_added(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
            path = tf.name
        try:
            config = self._make_config(log={"enabled": True, "path": path, "min_severity": "info"})
            d = AlertDispatcher(config)
            from alerts import FileDispatcher
            assert any(isinstance(x, FileDispatcher) for x in d._dispatchers)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

"""
tests/test_rules.py — Unit tests for the rule engine.

Run with:
    pytest tests/
    # or
    python -m pytest tests/ -v
"""

import os
import sys
import tempfile
import textwrap
import pytest

# Allow importing from project root without installing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rules import RuleEngine, Rule, evaluate_condition


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

MINIMAL_RULES_YAML = textwrap.dedent("""
config:
  telegram:
    enabled: false
  webhook:
    enabled: false
  log:
    enabled: false

rules:
  - name: passwd-read
    description: /etc/passwd opened
    event_type: open
    severity: high
    enabled: true
    conditions:
      - field: path
        op: eq
        value: /etc/passwd

  - name: shell-spawn
    description: Bash/sh spawned
    event_type: exec
    severity: medium
    enabled: true
    conditions:
      - field: filename
        op: regex
        value: "/(bash|sh)$"

  - name: setuid-root
    description: setuid(0) called
    event_type: privesc
    severity: critical
    enabled: true
    conditions:
      - field: new_uid
        op: eq
        value: 0
      - field: uid
        op: ne
        value: 0

  - name: disabled-rule
    description: This rule should never fire
    event_type: "*"
    severity: info
    enabled: false
    conditions: []
""")


@pytest.fixture
def rules_file(tmp_path):
    f = tmp_path / "test_rules.yaml"
    f.write_text(MINIMAL_RULES_YAML)
    return str(f)


@pytest.fixture
def engine(rules_file):
    return RuleEngine(rules_file)


# ──────────────────────────────────────────────────────────────────────────────
# evaluate_condition tests
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCondition:
    def test_eq_match(self):
        cond = {"field": "path", "op": "eq", "value": "/etc/passwd"}
        assert evaluate_condition({"path": "/etc/passwd"}, cond) is True

    def test_eq_no_match(self):
        cond = {"field": "path", "op": "eq", "value": "/etc/passwd"}
        assert evaluate_condition({"path": "/etc/shadow"}, cond) is False

    def test_ne(self):
        cond = {"field": "uid", "op": "ne", "value": 0}
        assert evaluate_condition({"uid": 1000}, cond) is True
        assert evaluate_condition({"uid": 0}, cond) is False

    def test_contains(self):
        cond = {"field": "filename", "op": "contains", "value": "sudo"}
        assert evaluate_condition({"filename": "/usr/bin/sudo"}, cond) is True
        assert evaluate_condition({"filename": "/usr/bin/ls"}, cond) is False

    def test_startswith(self):
        cond = {"field": "path", "op": "startswith", "value": "/etc/cron"}
        assert evaluate_condition({"path": "/etc/cron.d/myjob"}, cond) is True
        assert evaluate_condition({"path": "/tmp/cron"}, cond) is False

    def test_endswith(self):
        cond = {"field": "path", "op": "endswith", "value": ".sh"}
        assert evaluate_condition({"path": "/tmp/exploit.sh"}, cond) is True
        assert evaluate_condition({"path": "/tmp/exploit.py"}, cond) is False

    def test_regex(self):
        cond = {"field": "filename", "op": "regex", "value": r"/(bash|sh)$"}
        assert evaluate_condition({"filename": "/bin/bash"}, cond) is True
        assert evaluate_condition({"filename": "/bin/bash2"}, cond) is False

    def test_lt_gt(self):
        assert evaluate_condition({"dport": 80},   {"field": "dport", "op": "lt", "value": 1024}) is True
        assert evaluate_condition({"dport": 8080}, {"field": "dport", "op": "gt", "value": 1024}) is True
        assert evaluate_condition({"dport": 80},   {"field": "dport", "op": "gt", "value": 1024}) is False

    def test_in_op(self):
        cond = {"field": "comm", "op": "in", "value": ["nc", "ncat", "netcat"]}
        assert evaluate_condition({"comm": "nc"}, cond) is True
        assert evaluate_condition({"comm": "ls"}, cond) is False

    def test_not_in(self):
        cond = {"field": "comm", "op": "not_in", "value": ["nc", "ncat"]}
        assert evaluate_condition({"comm": "bash"}, cond) is True
        assert evaluate_condition({"comm": "nc"},   cond) is False

    def test_negate(self):
        cond = {"field": "uid", "op": "eq", "value": 0, "negate": True}
        assert evaluate_condition({"uid": 1000}, cond) is True  # uid != 0 → negated True
        assert evaluate_condition({"uid": 0},    cond) is False

    def test_missing_field(self):
        cond = {"field": "nonexistent", "op": "eq", "value": "x"}
        assert evaluate_condition({}, cond) is False

    def test_dot_notation(self):
        cond = {"field": "meta.host", "op": "eq", "value": "server1"}
        assert evaluate_condition({"meta": {"host": "server1"}}, cond) is True
        assert evaluate_condition({"meta": {"host": "server2"}}, cond) is False


# ──────────────────────────────────────────────────────────────────────────────
# Rule model tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRule:
    def test_basic_match(self):
        rule = Rule({
            "name": "test",
            "event_type": "open",
            "severity": "high",
            "conditions": [{"field": "path", "op": "eq", "value": "/etc/passwd"}],
        })
        assert rule.matches({"type": "open", "path": "/etc/passwd"})
        assert not rule.matches({"type": "open", "path": "/etc/shadow"})

    def test_wrong_event_type(self):
        rule = Rule({
            "name": "test",
            "event_type": "exec",
            "severity": "info",
            "conditions": [],
        })
        assert not rule.matches({"type": "open"})

    def test_wildcard_event_type(self):
        rule = Rule({
            "name": "test",
            "event_type": "*",
            "severity": "info",
            "conditions": [],
        })
        assert rule.matches({"type": "exec"})
        assert rule.matches({"type": "open"})
        assert rule.matches({"type": "connect"})

    def test_disabled_rule(self):
        rule = Rule({
            "name": "test",
            "event_type": "*",
            "severity": "info",
            "enabled": False,
            "conditions": [],
        })
        assert not rule.matches({"type": "exec"})

    def test_multi_condition_and(self):
        rule = Rule({
            "name": "test",
            "event_type": "privesc",
            "severity": "critical",
            "conditions": [
                {"field": "new_uid", "op": "eq", "value": 0},
                {"field": "uid",     "op": "ne", "value": 0},
            ],
        })
        # Both conditions must match
        assert rule.matches({"type": "privesc", "new_uid": 0, "uid": 1000})
        # Only first matches → should fail
        assert not rule.matches({"type": "privesc", "new_uid": 0, "uid": 0})


# ──────────────────────────────────────────────────────────────────────────────
# RuleEngine tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRuleEngine:
    def test_load(self, engine):
        assert len(engine.rules) == 4
        enabled = [r for r in engine.rules if r.enabled]
        assert len(enabled) == 3

    def test_evaluate_passwd(self, engine):
        event = {"type": "open", "path": "/etc/passwd", "pid": 1234, "uid": 1000}
        matched = engine.evaluate(event)
        names = [r.name for r in matched]
        assert "passwd-read" in names

    def test_evaluate_shell(self, engine):
        event = {"type": "exec", "filename": "/bin/bash", "pid": 5678, "uid": 0}
        matched = engine.evaluate(event)
        names = [r.name for r in matched]
        assert "shell-spawn" in names

    def test_evaluate_privesc(self, engine):
        event = {"type": "privesc", "new_uid": 0, "uid": 1000, "pid": 999}
        matched = engine.evaluate(event)
        names = [r.name for r in matched]
        assert "setuid-root" in names

    def test_disabled_rule_never_fires(self, engine):
        # The disabled-rule has no conditions and type="*" — should still not fire
        event = {"type": "exec", "filename": "/bin/sh"}
        matched = engine.evaluate(event)
        names = [r.name for r in matched]
        assert "disabled-rule" not in names

    def test_no_match(self, engine):
        event = {"type": "connect", "dst": "8.8.8.8", "dport": 443}
        matched = engine.evaluate(event)
        assert matched == []

    def test_summary(self, engine):
        s = engine.summary()
        assert "high" in s
        assert "medium" in s
        assert "critical" in s

    def test_reload(self, rules_file):
        engine = RuleEngine(rules_file)
        count_before = len(engine.rules)
        engine.reload()
        assert len(engine.rules) == count_before


# ──────────────────────────────────────────────────────────────────────────────
# Default rules file sanity check
# ──────────────────────────────────────────────────────────────────────────────

class TestDefaultRules:
    """Validate the default rules/default.yaml is parseable and correct."""

    @pytest.fixture
    def default_engine(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "rules", "default.yaml"
        )
        return RuleEngine(path)

    def test_default_loads(self, default_engine):
        assert len(default_engine.rules) > 0

    def test_critical_rules_present(self, default_engine):
        names = [r.name for r in default_engine.rules]
        assert "setuid-to-root" in names
        assert "shadow-read" in names

    def test_passwd_fires(self, default_engine):
        event = {"type": "open", "path": "/etc/passwd", "uid": 1000}
        matched = default_engine.evaluate(event)
        assert any(r.name == "passwd-read" for r in matched)

    def test_shadow_fires(self, default_engine):
        event = {"type": "open", "path": "/etc/shadow", "uid": 1000}
        matched = default_engine.evaluate(event)
        assert any(r.name == "shadow-read" for r in matched)

    def test_netcat_fires(self, default_engine):
        event = {"type": "exec", "filename": "/usr/bin/nc", "uid": 1000}
        matched = default_engine.evaluate(event)
        assert any(r.name == "netcat-exec" for r in matched)

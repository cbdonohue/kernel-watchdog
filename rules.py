"""
rules.py — Rule engine for kernel-watchdog.

Rules are defined in YAML and evaluated against incoming kernel events.
Each rule specifies:
  - name:       Human-readable label
  - description: What the rule detects
  - event_type: exec | open | connect | privesc  (or '*' for any)
  - severity:   critical | high | medium | low | info
  - conditions: list of field matchers (all must match — AND logic)
  - enabled:    true/false

Condition matchers supported:
  eq, ne, contains, startswith, endswith, regex, lt, gt, in, not_in

Example YAML:
    - name: passwd-read
      event_type: open
      severity: high
      conditions:
        - field: path
          op: eq
          value: /etc/passwd
"""

import re
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

log = logging.getLogger("rules")


# ──────────────────────────────────────────────────────────────────────────────
# Condition evaluation
# ──────────────────────────────────────────────────────────────────────────────

def _cast(value: Any, target: Any) -> Any:
    """Try to cast value to the same type as target for comparison."""
    try:
        return type(target)(value)
    except (ValueError, TypeError):
        return value


def evaluate_condition(event: dict, condition: dict) -> bool:
    """
    Evaluate a single condition dict against an event dict.

    Condition keys:
        field (str)  — event field name (supports dot notation: e.g., 'meta.host')
        op    (str)  — operator
        value (any)  — comparison value
        negate (bool) — invert result (optional, default False)
    """
    field  = condition.get("field", "")
    op     = condition.get("op", "eq").lower()
    target = condition.get("value")
    negate = condition.get("negate", False)

    # Dot-notation field access
    parts = field.split(".")
    actual = event
    for part in parts:
        if isinstance(actual, dict):
            actual = actual.get(part)
        else:
            actual = None
            break

    if actual is None and op not in ("is_null", "is_not_null"):
        return negate  # field absent → condition fails (or True if negated)

    result = _apply_op(op, actual, target)
    return (not result) if negate else result


def _apply_op(op: str, actual: Any, target: Any) -> bool:
    if op == "eq":
        return str(actual) == str(target)
    if op == "ne":
        return str(actual) != str(target)
    if op == "contains":
        return str(target).lower() in str(actual).lower()
    if op == "not_contains":
        return str(target).lower() not in str(actual).lower()
    if op == "startswith":
        return str(actual).lower().startswith(str(target).lower())
    if op == "endswith":
        return str(actual).lower().endswith(str(target).lower())
    if op == "regex":
        return bool(re.search(str(target), str(actual)))
    if op == "lt":
        return float(actual) < float(target)
    if op == "gt":
        return float(actual) > float(target)
    if op == "lte":
        return float(actual) <= float(target)
    if op == "gte":
        return float(actual) >= float(target)
    if op == "in":
        return str(actual) in [str(v) for v in (target or [])]
    if op == "not_in":
        return str(actual) not in [str(v) for v in (target or [])]
    if op == "is_null":
        return actual is None
    if op == "is_not_null":
        return actual is not None
    log.warning("Unknown op '%s' — treating as False", op)
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Rule model
# ──────────────────────────────────────────────────────────────────────────────

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_EVENT_TYPES = {"exec", "open", "connect", "privesc", "*"}


class Rule:
    """A single detection rule loaded from YAML."""

    def __init__(self, raw: dict, index: int = 0):
        self.index       = index
        self.name        = raw.get("name", f"rule_{index}")
        self.description = raw.get("description", "")
        self.event_type  = raw.get("event_type", "*")
        self.severity    = raw.get("severity", "info").lower()
        self.conditions  = raw.get("conditions", [])
        self.enabled     = raw.get("enabled", True)
        self.tags        = raw.get("tags", [])
        self.alert       = raw.get("alert", {})    # e.g. {telegram: true, log: true}
        self._validate()

    def _validate(self):
        if self.severity not in VALID_SEVERITIES:
            log.warning("Rule '%s': unknown severity '%s'", self.name, self.severity)
        if self.event_type not in VALID_EVENT_TYPES:
            log.warning("Rule '%s': unknown event_type '%s'", self.name, self.event_type)

    def matches(self, event: dict) -> bool:
        """Return True if this rule fires on the given event."""
        if not self.enabled:
            return False

        # Check event type filter
        et = self.event_type
        if et != "*" and event.get("type") != et:
            return False

        # All conditions must pass (AND logic)
        for cond in self.conditions:
            if not evaluate_condition(event, cond):
                return False

        return True

    def __repr__(self) -> str:
        return f"<Rule name={self.name!r} severity={self.severity} event={self.event_type}>"


# ──────────────────────────────────────────────────────────────────────────────
# Rule engine
# ──────────────────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    Loads rules from YAML and evaluates them against events.

    Usage:
        engine = RuleEngine("rules/default.yaml")
        matched = engine.evaluate(event_dict)
        for rule in matched:
            print(rule.name, rule.severity)
    """

    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules: List[Rule] = []
        self.config: dict = {}
        self._load()

    def _load(self):
        path = Path(self.rules_path)
        if not path.exists():
            log.error("Rules file not found: %s", self.rules_path)
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")

        with path.open() as f:
            doc = yaml.safe_load(f)

        if not isinstance(doc, dict):
            raise ValueError("Rules YAML must be a mapping with 'config' and 'rules' keys.")

        self.config = doc.get("config", {})
        raw_rules   = doc.get("rules", [])

        self.rules = []
        for i, raw in enumerate(raw_rules):
            try:
                rule = Rule(raw, index=i)
                self.rules.append(rule)
            except Exception as exc:
                log.warning("Skipping rule #%d due to error: %s", i, exc)

        enabled = sum(1 for r in self.rules if r.enabled)
        log.info("Loaded %d rules (%d enabled) from %s", len(self.rules), enabled, self.rules_path)

    def reload(self):
        """Hot-reload rules from disk (useful for SIGHUP handling)."""
        log.info("Reloading rules from %s", self.rules_path)
        self._load()

    def evaluate(self, event: dict) -> List[Rule]:
        """Return list of rules that matched this event."""
        return [r for r in self.rules if r.matches(event)]

    def summary(self) -> dict:
        """Return a summary of loaded rules grouped by severity."""
        out: Dict[str, List[str]] = {}
        for r in self.rules:
            out.setdefault(r.severity, []).append(r.name)
        return out

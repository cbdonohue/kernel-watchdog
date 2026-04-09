# kernel-watchdog 🔍

> **Minimal Linux kernel event monitor using eBPF — Falco-lite**

A lightweight, hackable security monitoring tool that uses eBPF (via BCC) to watch your Linux kernel in real-time. Catches suspicious process execution, file access, network connections, and privilege escalation — with configurable YAML rules and Telegram notifications.

Inspired by [Falco](https://falco.org/), built for those who want to understand and own their detection stack.

---

## Features

| Category | What it monitors |
|---|---|
| **Process Exec** | Every `execve` call — command, arguments, parent PID |
| **File Access** | `openat` calls — path, flags, which process |
| **Network** | TCP `connect` calls — source/destination IP and port |
| **Privilege Escalation** | `setuid` / `setreuid` calls — UID changes |
| **Rules Engine** | YAML rules with flexible field matchers |
| **Alerts** | Console, Telegram bot, generic webhook, JSONL file |
| **TUI Dashboard** | Real-time curses UI with tabs, filtering, scrolling |
| **JSON Event Log** | Structured JSONL output for SIEM integration |

---

## Architecture

```
kernel-watchdog/
├── watchdog.py          # Main orchestrator — loads eBPF, event loop
├── rules.py             # Rule engine — YAML loader, condition evaluator
├── alerts.py            # Alert dispatchers — Telegram, webhook, file, console
├── tui.py               # Curses TUI dashboard
├── rules/
│   └── default.yaml     # Default detection rules (20+ rules)
├── tests/
│   ├── test_rules.py    # Rule engine unit tests
│   └── test_alerts.py   # Alert dispatcher tests
└── requirements.txt
```

---

## Requirements

- Linux kernel ≥ 4.1 (eBPF support)
- Python ≥ 3.8
- **BCC** (BPF Compiler Collection) — kernel headers required
- Root / `CAP_BPF` + `CAP_PERFMON` privileges

### Install BCC

**Ubuntu/Debian:**
```bash
sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install bcc bcc-tools python3-bcc kernel-devel
```

**Arch Linux:**
```bash
sudo pacman -S bcc bcc-tools python-bcc linux-headers
```

**From source** (if package is outdated):
```bash
# See: https://github.com/iovisor/bcc/blob/master/INSTALL.md
```

### Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/cbdonohue/kernel-watchdog
cd kernel-watchdog

# Install dependencies
sudo apt install python3-bpfcc linux-headers-$(uname -r)
pip install pyyaml

# Run (requires root)
sudo python3 watchdog.py
```

That's it. You'll see kernel events streaming to your terminal as they happen.

---

## Usage

```
sudo python3 watchdog.py [OPTIONS]

Options:
  --rules PATH     Path to rules YAML (default: rules/default.yaml)
  --log PATH       Append all events as JSONL to this file
  --tui            Enable curses TUI dashboard
  --verbose / -v   Print every raw event (very noisy)
  --help           Show help
```

### Examples

```bash
# Basic monitoring with console output
sudo python3 watchdog.py

# With TUI dashboard
sudo python3 watchdog.py --tui

# Log all events to file + custom rules
sudo python3 watchdog.py --log /var/log/kernel-watchdog.jsonl --rules /etc/watchdog/rules.yaml

# Verbose: dump every raw event
sudo python3 watchdog.py --verbose

# Run in background
sudo python3 watchdog.py --log events.jsonl &
```

### TUI Dashboard Keybindings

| Key | Action |
|---|---|
| `q` / `Q` | Quit |
| `c` | Clear event buffer |
| `Tab` | Cycle tabs (All / Exec / Open / Net / Privesc) |
| `1`–`5` | Jump to tab directly |
| `↑` / `↓` | Scroll events |
| `PgUp` / `PgDn` | Page scroll |
| `?` | Toggle help overlay |

---

## Configuration

Rules are defined in YAML. The file has two top-level sections: `config` and `rules`.

### Alert Configuration (`config`)

```yaml
config:
  # Telegram bot notifications
  telegram:
    enabled: true
    bot_token: "1234567890:ABCDefGhIJKlmNoPQRsTUVwxyZ"
    chat_id: "987654321"
    min_severity: high      # only send high or critical alerts

  # Generic webhook (Slack, Discord, PagerDuty, custom)
  webhook:
    enabled: false
    url: "https://hooks.slack.com/services/YOUR/WEBHOOK"
    headers:
      Authorization: "Bearer my_token"
    min_severity: medium

  # Append alerts to a JSONL file
  log:
    enabled: true
    path: alerts.jsonl
    min_severity: info      # log everything
```

### Setting Up Telegram Alerts

1. Create a bot: message [@BotFather](https://t.me/botfather) → `/newbot`
2. Copy the bot token
3. Start a chat with your bot, then get your chat ID:
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
   ```
4. Add to `rules/default.yaml` under `config.telegram`

### Writing Rules

```yaml
rules:
  - name: my-custom-rule
    description: Detects something suspicious
    event_type: open          # exec | open | connect | privesc | *
    severity: high            # critical | high | medium | low | info
    enabled: true
    tags: [credentials, files]
    conditions:
      - field: path
        op: eq
        value: /etc/shadow
      - field: uid
        op: ne
        value: 0              # not root — flag non-root access
```

### Available Event Fields

**`exec` events** (process execution):
| Field | Description |
|---|---|
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `uid` / `gid` | User/Group ID |
| `comm` | Process name (short) |
| `filename` | Full path of executable |
| `args` | First argument |

**`open` events** (file access):
| Field | Description |
|---|---|
| `pid` / `uid` / `gid` | Process/user IDs |
| `comm` | Process name |
| `path` | File path opened |
| `flags` | Open flags (0=read-only, >0 includes write) |

**`connect` events** (TCP connections):
| Field | Description |
|---|---|
| `pid` / `uid` | Process/user IDs |
| `comm` | Process name |
| `src` / `dst` | Source/destination IP |
| `sport` / `dport` | Source/destination port |

**`privesc` events** (privilege changes):
| Field | Description |
|---|---|
| `pid` / `uid` | Process/user IDs |
| `new_uid` | Target UID |
| `comm` | Process name |
| `syscall` | `setuid` or `setreuid` |

### Condition Operators

| Operator | Description |
|---|---|
| `eq` | Exact match |
| `ne` | Not equal |
| `contains` | Substring match (case-insensitive) |
| `not_contains` | Inverse substring |
| `startswith` | Prefix match |
| `endswith` | Suffix match |
| `regex` | Python regex match |
| `lt` / `gt` / `lte` / `gte` | Numeric comparison |
| `in` | Value in list |
| `not_in` | Value not in list |
| `is_null` / `is_not_null` | Field presence check |

Add `negate: true` to any condition to invert it.

### Multiple conditions = AND logic

All conditions in a rule must match for the rule to fire. For OR logic, create separate rules.

---

## Default Rules

The bundled `rules/default.yaml` includes 20+ rules covering:

**Privilege Escalation:**
- `setuid-to-root` — `setuid(0)` from non-root (CRITICAL)
- `setreuid-to-root` — `setreuid` to root eUID (CRITICAL)
- `sudo-exec` — sudo invocation (HIGH)
- `su-exec` — `su` invocation (MEDIUM)

**Sensitive File Access:**
- `shadow-read` — `/etc/shadow` access (CRITICAL)
- `passwd-read` — `/etc/passwd` access (HIGH)
- `sudoers-read` — `/etc/sudoers*` access (HIGH)
- `ssh-key-read` — SSH private keys (HIGH)
- `cron-modification` — cron write access (MEDIUM)
- `hosts-modification` — `/etc/hosts` writes (MEDIUM)

**Process Execution:**
- `netcat-exec` — nc/ncat execution (HIGH)
- `shell-spawn` — bash/sh spawns (MEDIUM)
- `curl-wget-exec` — download cradles (LOW)
- `suid-binary-exec` — SUID binary execution (MEDIUM)
- `package-manager-exec` — apt/yum/pip/npm (LOW)

**Network:**
- `outbound-ssh` — outbound port 22 (LOW)
- `outbound-dns` — DNS queries (INFO, disabled)

---

## Event Log Format

With `--log events.jsonl`, every event is appended as JSON:

```json
{"type": "open", "ts": "2025-01-01T12:00:00+00:00", "pid": 1234, "uid": 1000, "gid": 1000, "comm": "bash", "path": "/etc/passwd", "flags": 0}
{"type": "exec", "ts": "2025-01-01T12:00:01+00:00", "pid": 5678, "ppid": 1234, "uid": 0, "gid": 0, "comm": "sudo", "filename": "/usr/bin/sudo", "args": "-l"}
{"type": "privesc", "ts": "2025-01-01T12:00:02+00:00", "pid": 9999, "uid": 1000, "new_uid": 0, "comm": "exploit", "syscall": "setuid"}
```

Use with `jq` for filtering:
```bash
# Show only high-severity alerts
jq 'select(.type == "open" and .path == "/etc/shadow")' events.jsonl

# Count events by type
jq -r .type events.jsonl | sort | uniq -c | sort -rn
```

---

## Running Tests

```bash
# Install test dependencies
pip install pytest pyyaml

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_rules.py -v

# With coverage
pip install pytest-cov
pytest tests/ --cov=. --cov-report=term-missing
```

---

## Systemd Service

Run kernel-watchdog as a system service:

```ini
# /etc/systemd/system/kernel-watchdog.service
[Unit]
Description=kernel-watchdog eBPF event monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kernel-watchdog/watchdog.py \
    --rules /etc/kernel-watchdog/rules.yaml \
    --log /var/log/kernel-watchdog/events.jsonl
Restart=on-failure
RestartSec=5s
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now kernel-watchdog
sudo journalctl -u kernel-watchdog -f
```

---

## SIEM Integration

Events are plain JSONL — pipe to any SIEM:

```bash
# Ship to Elasticsearch via Filebeat
# filebeat.yml:
#   filestream.paths: [/var/log/kernel-watchdog/events.jsonl]
#   parsers: [{ndjson: {}}]

# Or tail and ship to Loki
tail -f events.jsonl | promtail --stdin

# Or forward to syslog
tail -f events.jsonl | logger -t kernel-watchdog
```

---

## Limitations & Caveats

- **Root required**: eBPF probes need `CAP_BPF` + `CAP_PERFMON` (or full root)
- **Kernel headers**: BCC requires matching kernel headers to compile eBPF programs
- **Performance**: eBPF is fast, but very high-frequency events (like DNS per-query) can increase overhead — tune rules to filter noise
- **Container awareness**: Events show host-side PIDs; namespaced container PIDs differ
- **Not a firewall**: kernel-watchdog observes and alerts — it does not block events

---

## Contributing

PRs welcome. Ideas for contribution:
- More eBPF probes (file writes, mmap, ptrace)
- `or` / `not` rule logic grouping
- Rate-limiting per rule (suppress repeated alerts)
- Container/namespace awareness
- Prometheus metrics endpoint
- Rule hot-reload on SIGHUP

---

## License

MIT — use freely, hack boldly.

---

*Built with [BCC](https://github.com/iovisor/bcc) · Inspired by [Falco](https://falco.org/)*

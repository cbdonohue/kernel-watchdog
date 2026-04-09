# Architecture

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Linux Kernel                            │
│   execve() ──► kprobe  openat() ──► kprobe  setuid() ──► kprobe│
│   tcp_v4_connect() ──► kprobe                                   │
└──────────────┬──────────────────────────────────────────────────┘
               │ eBPF perf ring buffers
               ▼
┌──────────────────────────────────┐
│         watchdog.py              │
│   KernelWatchdog.run()           │
│   perf_buffer_poll() loop        │
│   _cb_exec / _cb_open / _cb_net  │
│   _cb_privesc                    │
└──────┬───────────────────────────┘
       │ event dict
       ▼
┌──────────────────┐    ┌─────────────────────────────────────────┐
│    rules.py      │    │              alerts.py                  │
│  RuleEngine      │───►│  AlertDispatcher                        │
│  - load YAML     │    │  ├── ConsoleDispatcher (always on)      │
│  - evaluate()    │    │  ├── TelegramDispatcher (optional)      │
│  → [Rule, ...]   │    │  ├── WebhookDispatcher (optional)       │
└──────────────────┘    │  └── FileDispatcher (optional)         │
                        └─────────────────────────────────────────┘
                                          │
       ┌──────────────────────────────────┘
       ▼
┌──────────────────┐
│     tui.py       │ (optional --tui flag)
│  WatchdogTUI     │
│  curses dashboard│
│  reads event_queue (thread-safe)
└──────────────────┘
```

## Data Flow

1. **eBPF probes** fire on kernel syscalls and push events into perf ring buffers
2. **watchdog.py** polls ring buffers at ~100ms intervals, decodes C structs into Python dicts
3. Each event is:
   - Written to JSONL log (if `--log` specified)
   - Pushed to the TUI event queue (ring buffer, max 500 events)
   - Evaluated by `RuleEngine.evaluate()`
4. Matched rules are passed to `AlertDispatcher.dispatch()`, which fans out to all configured channels

## Thread Safety

- `event_queue` is protected by `event_lock` (threading.Lock)
- TUI runs in a daemon thread; reads queue with the lock held
- Telegram dispatcher has its own rate-limit lock
- eBPF callbacks execute in the main thread's poll loop

## eBPF Programs

Each probe group is loaded as a separate BPF object to isolate failures:

| Object | Probe | Syscall | Output map |
|---|---|---|---|
| `_bpf_exec` | kprobe | `execve` | `exec_events` |
| `_bpf_open` | kprobe | `openat` | `open_events` |
| `_bpf_net` | kprobe | `tcp_v4_connect` | `net_events` |
| `_bpf_privesc` | kprobe | `setuid`, `setreuid` | `privesc_events` |

## Rule Evaluation

Rules use AND logic across conditions. OR logic is achieved by writing separate rules.

Condition evaluation is purely Python — no JIT/compilation. This keeps it inspectable and hackable at the cost of some throughput (acceptable at typical event rates).

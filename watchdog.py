#!/usr/bin/env python3
"""
kernel-watchdog: Minimal Linux kernel event monitor using eBPF (BCC).

Inspired by Falco — lightweight, hackable, and configurable.
Monitors: process exec, file open/write, network connects, privilege escalation.

Usage:
    sudo python3 watchdog.py [--rules rules/default.yaml] [--log events.jsonl] [--tui]
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Third-party
try:
    from bcc import BPF
except ImportError:
    print("[ERROR] BCC (BPF Compiler Collection) not found.")
    print("Install: sudo apt install python3-bpfcc  OR  pip install bcc")
    sys.exit(1)

import yaml

from rules import RuleEngine
from alerts import AlertDispatcher

# ──────────────────────────────────────────────────────────────────────────────
# eBPF C programs
# ──────────────────────────────────────────────────────────────────────────────

EBPF_EXEC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 256
#define MAX_ARGS 8

struct exec_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    u32  gid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
    char args[ARGSIZE];
};

BPF_PERF_OUTPUT(exec_events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp)
{
    struct exec_event_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data.pid  = bpf_get_current_pid_tgid() >> 32;
    data.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.gid  = bpf_get_current_uid_gid() >> 32;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    // Read first arg (argv[1]) if present
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), &argv[1]);
    if (argp)
        bpf_probe_read_user_str(&data.args, sizeof(data.args), argp);

    exec_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

EBPF_OPENAT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define PATHSIZE 256

struct open_event_t {
    u32  pid;
    u32  uid;
    u32  gid;
    int  flags;
    char comm[TASK_COMM_LEN];
    char path[PATHSIZE];
};

BPF_PERF_OUTPUT(open_events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename,
                 int flags, umode_t mode)
{
    struct open_event_t data = {};
    data.pid   = bpf_get_current_pid_tgid() >> 32;
    data.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.gid   = bpf_get_current_uid_gid() >> 32;
    data.flags = flags;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), filename);
    open_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

EBPF_NETWORK = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct net_event_t {
    u32  pid;
    u32  uid;
    u32  saddr;
    u32  daddr;
    u16  dport;
    u16  sport;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(net_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk)
{
    if (sk->__sk_common.skc_family != AF_INET)
        return 0;

    struct net_event_t data = {};
    data.pid   = bpf_get_current_pid_tgid() >> 32;
    data.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.daddr = sk->__sk_common.skc_daddr;
    data.dport = sk->__sk_common.skc_dport;
    data.sport = sk->__sk_common.skc_num;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    net_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

EBPF_PRIVESC = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct privesc_event_t {
    u32  pid;
    u32  uid;
    u32  new_uid;
    char comm[TASK_COMM_LEN];
    char syscall[16];
};

BPF_PERF_OUTPUT(privesc_events);

// Track setuid
int trace_setuid(struct pt_regs *ctx, uid_t uid)
{
    u32 current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // Only flag non-root processes trying to become root (or switching uid)
    if (uid != current_uid) {
        struct privesc_event_t data = {};
        data.pid     = bpf_get_current_pid_tgid() >> 32;
        data.uid     = current_uid;
        data.new_uid = uid;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        __builtin_memcpy(data.syscall, "setuid", 7);
        privesc_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Track setreuid
int trace_setreuid(struct pt_regs *ctx, uid_t ruid, uid_t euid)
{
    u32 current_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (euid == 0 && current_uid != 0) {
        struct privesc_event_t data = {};
        data.pid     = bpf_get_current_pid_tgid() >> 32;
        data.uid     = current_uid;
        data.new_uid = euid;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        __builtin_memcpy(data.syscall, "setreuid", 9);
        privesc_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Helper: IP formatting
# ──────────────────────────────────────────────────────────────────────────────

def ip_from_int(n: int) -> str:
    """Convert a little-endian packed int to dotted-decimal IP string."""
    return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"


def port_from_net(n: int) -> int:
    """Convert network-byte-order port to host order."""
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF)


# ──────────────────────────────────────────────────────────────────────────────
# Watchdog core
# ──────────────────────────────────────────────────────────────────────────────

class KernelWatchdog:
    """
    Main orchestrator: loads eBPF probes, processes events,
    evaluates rules, and dispatches alerts.
    """

    def __init__(
        self,
        rules_path: str = "rules/default.yaml",
        log_path: Optional[str] = None,
        tui_mode: bool = False,
        verbose: bool = False,
    ):
        self.rules_path = rules_path
        self.log_path   = log_path
        self.tui_mode   = tui_mode
        self.verbose    = verbose
        self.running    = False

        # Shared event queue for TUI
        self.event_queue: list[dict] = []
        self.event_lock  = threading.Lock()
        self.max_events  = 500  # ring buffer size

        # Sub-systems
        self.rule_engine = RuleEngine(rules_path)
        self.dispatcher  = AlertDispatcher(self.rule_engine.config)

        # Log file handle
        self._log_fh = None
        if log_path:
            self._log_fh = open(log_path, "a", buffering=1)

        # BPF objects (one per probe group)
        self._bpf_exec    = None
        self._bpf_open    = None
        self._bpf_net     = None
        self._bpf_privesc = None

        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%H:%M:%S",
        )
        self.log = logging.getLogger("watchdog")

    # ── eBPF init ──────────────────────────────────────────────────────────

    def _load_probes(self):
        self.log.info("Compiling and loading eBPF probes…")
        try:
            self._bpf_exec = BPF(text=EBPF_EXEC)
            self._bpf_exec.attach_kprobe(event=self._bpf_exec.get_syscall_fnname("execve"),
                                          fn_name="trace_execve")

            self._bpf_open = BPF(text=EBPF_OPENAT)
            self._bpf_open.attach_kprobe(event=self._bpf_open.get_syscall_fnname("openat"),
                                          fn_name="trace_openat")

            self._bpf_net = BPF(text=EBPF_NETWORK)
            self._bpf_net.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

            self._bpf_privesc = BPF(text=EBPF_PRIVESC)
            self._bpf_privesc.attach_kprobe(
                event=self._bpf_privesc.get_syscall_fnname("setuid"),
                fn_name="trace_setuid")
            self._bpf_privesc.attach_kprobe(
                event=self._bpf_privesc.get_syscall_fnname("setreuid"),
                fn_name="trace_setreuid")

            self.log.info("eBPF probes loaded successfully.")
        except Exception as exc:
            self.log.error("Failed to load eBPF probes: %s", exc)
            raise

    # ── Callbacks ─────────────────────────────────────────────────────────

    def _cb_exec(self, cpu, data, size):
        evt = self._bpf_exec["exec_events"].event(data)
        event = {
            "type":     "exec",
            "ts":       datetime.now(timezone.utc).isoformat(),
            "pid":      evt.pid,
            "ppid":     evt.ppid,
            "uid":      evt.uid,
            "gid":      evt.gid,
            "comm":     evt.comm.decode("utf-8", errors="replace"),
            "filename": evt.filename.decode("utf-8", errors="replace"),
            "args":     evt.args.decode("utf-8", errors="replace"),
        }
        self._handle_event(event)

    def _cb_open(self, cpu, data, size):
        evt = self._bpf_open["open_events"].event(data)
        event = {
            "type":  "open",
            "ts":    datetime.now(timezone.utc).isoformat(),
            "pid":   evt.pid,
            "uid":   evt.uid,
            "gid":   evt.gid,
            "flags": evt.flags,
            "comm":  evt.comm.decode("utf-8", errors="replace"),
            "path":  evt.path.decode("utf-8", errors="replace"),
        }
        self._handle_event(event)

    def _cb_net(self, cpu, data, size):
        evt = self._bpf_net["net_events"].event(data)
        event = {
            "type":  "connect",
            "ts":    datetime.now(timezone.utc).isoformat(),
            "pid":   evt.pid,
            "uid":   evt.uid,
            "comm":  evt.comm.decode("utf-8", errors="replace"),
            "src":   ip_from_int(evt.saddr),
            "dst":   ip_from_int(evt.daddr),
            "dport": port_from_net(evt.dport),
            "sport": evt.sport,
        }
        self._handle_event(event)

    def _cb_privesc(self, cpu, data, size):
        evt = self._bpf_privesc["privesc_events"].event(data)
        event = {
            "type":    "privesc",
            "ts":      datetime.now(timezone.utc).isoformat(),
            "pid":     evt.pid,
            "uid":     evt.uid,
            "new_uid": evt.new_uid,
            "comm":    evt.comm.decode("utf-8", errors="replace"),
            "syscall": evt.syscall.decode("utf-8", errors="replace").rstrip("\x00"),
        }
        self._handle_event(event)

    # ── Event pipeline ────────────────────────────────────────────────────

    def _handle_event(self, event: dict):
        """Central event handler: log → rule match → alert."""
        if self.verbose:
            self.log.debug("EVENT %s", json.dumps(event))

        # Log to JSONL file
        if self._log_fh:
            self._log_fh.write(json.dumps(event) + "\n")

        # Push to TUI queue
        with self.event_lock:
            self.event_queue.append(event)
            if len(self.event_queue) > self.max_events:
                self.event_queue.pop(0)

        # Evaluate alert rules
        matched = self.rule_engine.evaluate(event)
        for rule in matched:
            self.dispatcher.dispatch(rule, event)

    # ── Main loop ─────────────────────────────────────────────────────────

    def run(self):
        """Start all probes and poll event buffers."""
        self._load_probes()
        self.running = True

        self._bpf_exec["exec_events"].open_perf_buffer(self._cb_exec)
        self._bpf_open["open_events"].open_perf_buffer(self._cb_open)
        self._bpf_net["net_events"].open_perf_buffer(self._cb_net)
        self._bpf_privesc["privesc_events"].open_perf_buffer(self._cb_privesc)

        self.log.info("Watching kernel events. Press Ctrl+C to stop.")

        if self.tui_mode:
            from tui import WatchdogTUI
            tui = WatchdogTUI(self)
            tui_thread = threading.Thread(target=tui.run, daemon=True)
            tui_thread.start()

        try:
            while self.running:
                for bpf in (self._bpf_exec, self._bpf_open,
                            self._bpf_net, self._bpf_privesc):
                    bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            self.log.info("Interrupted. Shutting down.")
        finally:
            self.shutdown()

    def shutdown(self):
        self.running = False
        if self._log_fh:
            self._log_fh.close()
        self.log.info("Watchdog stopped.")


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="kernel-watchdog — eBPF kernel event monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--rules", default="rules/default.yaml",
                   help="Path to rules YAML file (default: rules/default.yaml)")
    p.add_argument("--log",   default=None,
                   help="Append JSON events to this file (JSONL format)")
    p.add_argument("--tui",   action="store_true",
                   help="Enable curses TUI dashboard")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print every raw event to stdout")
    return p.parse_args()


def main():
    if os.geteuid() != 0:
        print("[ERROR] kernel-watchdog must be run as root (sudo).")
        sys.exit(1)

    args = parse_args()

    def _sigterm(sig, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _sigterm)

    watcher = KernelWatchdog(
        rules_path=args.rules,
        log_path=args.log,
        tui_mode=args.tui,
        verbose=args.verbose,
    )
    watcher.run()


if __name__ == "__main__":
    main()

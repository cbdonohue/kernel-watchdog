"""
tui.py — Curses TUI dashboard for kernel-watchdog.

Displays recent kernel events in a categorised, colour-coded table.
Launch with: sudo python3 watchdog.py --tui

Keybindings:
  q / Q      Quit
  c          Clear event buffer
  f <str>    Filter by process name or path (type after 'f', hit Enter)
  1-4        Switch tabs: All / Exec / Open / Network / Privesc
  Tab        Cycle tabs
  ?          Toggle help overlay
"""

import curses
import threading
import time
from datetime import datetime
from typing import Optional


# Severity → curses colour pair index
SEVERITY_COLORS = {
    "critical": 1,   # red bold
    "high":     2,   # red
    "medium":   3,   # yellow
    "low":      4,   # cyan
    "info":     5,   # white
}

EVENT_TYPE_LABEL = {
    "exec":    "EXEC",
    "open":    "OPEN",
    "connect": "NET ",
    "privesc": "PRIV",
}

TABS = ["All", "Exec", "Open", "Net", "Privesc"]
TAB_FILTER = {
    "All":     None,
    "Exec":    "exec",
    "Open":    "open",
    "Net":     "connect",
    "Privesc": "privesc",
}


def _event_summary(event: dict) -> str:
    """One-line human-readable summary of an event."""
    etype = event.get("type", "?")
    comm  = event.get("comm", "?")[:16]
    pid   = event.get("pid", "?")

    if etype == "exec":
        return f"{comm}({pid}) → {event.get('filename', '?')[:50]}"
    elif etype == "open":
        return f"{comm}({pid}) → {event.get('path', '?')[:50]}"
    elif etype == "connect":
        return f"{comm}({pid}) → {event.get('dst', '?')}:{event.get('dport', '?')}"
    elif etype == "privesc":
        return (f"{comm}({pid}) uid {event.get('uid', '?')} → "
                f"{event.get('new_uid', '?')} via {event.get('syscall', '?')}")
    return str(event)[:60]


def _ts_short(ts: str) -> str:
    try:
        return ts[11:19]  # HH:MM:SS from ISO-8601
    except Exception:
        return ts


class WatchdogTUI:
    """
    Curses-based dashboard for real-time kernel event monitoring.
    Reads from the watchdog's shared event_queue (thread-safe).
    """

    REFRESH_HZ = 4  # redraws per second

    def __init__(self, watchdog):
        self.watchdog    = watchdog
        self.active_tab  = 0
        self.filter_text = ""
        self.help_shown  = False
        self.scroll_off  = 0  # lines scrolled from bottom
        self._running    = True

    # ── curses init ───────────────────────────────────────────────────────

    def run(self):
        curses.wrapper(self._main)

    def _main(self, stdscr):
        self._init_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(1000 // self.REFRESH_HZ)

        while self._running and self.watchdog.running:
            try:
                self._draw(stdscr)
                key = stdscr.getch()
                self._handle_key(key, stdscr)
            except curses.error:
                pass
            except KeyboardInterrupt:
                break

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED,     -1)   # critical
        curses.init_pair(2, curses.COLOR_RED,     -1)   # high
        curses.init_pair(3, curses.COLOR_YELLOW,  -1)   # medium
        curses.init_pair(4, curses.COLOR_CYAN,    -1)   # low
        curses.init_pair(5, curses.COLOR_WHITE,   -1)   # info
        curses.init_pair(6, curses.COLOR_BLACK,   curses.COLOR_WHITE)   # header
        curses.init_pair(7, curses.COLOR_GREEN,   -1)   # tab active
        curses.init_pair(8, curses.COLOR_MAGENTA, -1)   # privesc
        curses.init_pair(9, curses.COLOR_BLUE,    -1)   # net

    # ── drawing ───────────────────────────────────────────────────────────

    def _draw(self, stdscr):
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # Title bar
        title = " kernel-watchdog v1.0 — eBPF Event Monitor "
        stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
        stdscr.addstr(0, 0, title.center(w)[:w])
        stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)

        # Stats row
        with self.watchdog.event_lock:
            total = len(self.watchdog.event_queue)
        stats = (f"  Events: {total}  |  Filter: {self.filter_text or '(none)'}  |"
                 f"  [?] help  [q] quit  [{time.strftime('%H:%M:%S')}]")
        stdscr.addstr(1, 0, stats[:w], curses.color_pair(5))

        # Tab bar
        self._draw_tabs(stdscr, 2, w)

        # Column headers
        hdr = f"{'TIME':>8}  {'TYPE':4}  {'SEV':8}  {'PROCESS':<18}  DETAIL"
        stdscr.attron(curses.A_UNDERLINE)
        stdscr.addstr(3, 0, hdr[:w])
        stdscr.attroff(curses.A_UNDERLINE)

        # Event rows
        events = self._filtered_events()
        view_h = h - 6  # rows available
        total_ev = len(events)
        # Show last `view_h` events, with scroll
        start = max(0, total_ev - view_h - self.scroll_off)
        visible = events[start: start + view_h]

        for row, event in enumerate(visible, start=4):
            if row >= h - 2:
                break
            self._draw_event_row(stdscr, row, w, event)

        # Status bar
        scroll_info = f"  ↑↓ scroll  offset={self.scroll_off}/{max(0, total_ev - view_h)}"
        stdscr.addstr(h - 2, 0, scroll_info[:w], curses.color_pair(5))

        # Help overlay
        if self.help_shown:
            self._draw_help(stdscr, h, w)

        stdscr.refresh()

    def _draw_tabs(self, stdscr, row: int, w: int):
        x = 0
        for i, tab in enumerate(TABS):
            label = f" {tab} "
            if i == self.active_tab:
                stdscr.addstr(row, x, label, curses.color_pair(7) | curses.A_BOLD)
            else:
                stdscr.addstr(row, x, label, curses.color_pair(5))
            x += len(label) + 1

    def _draw_event_row(self, stdscr, row: int, w: int, event: dict):
        etype = event.get("type", "?")
        sev   = event.get("_rule_severity", "info")

        ts_str  = _ts_short(event.get("ts", ""))
        type_lbl = EVENT_TYPE_LABEL.get(etype, etype[:4].upper())
        sev_lbl  = sev[:8]
        comm     = event.get("comm", "?")[:18]
        detail   = _event_summary(event)

        line = f"{ts_str:>8}  {type_lbl:4}  {sev_lbl:<8}  {comm:<18}  {detail}"
        line = line[:w]

        # Colour by event type / severity
        if etype == "privesc":
            attr = curses.color_pair(8) | curses.A_BOLD
        elif etype == "connect":
            attr = curses.color_pair(9)
        else:
            cp = SEVERITY_COLORS.get(sev, 5)
            attr = curses.color_pair(cp)
            if sev == "critical":
                attr |= curses.A_BOLD

        try:
            stdscr.addstr(row, 0, line, attr)
        except curses.error:
            pass

    def _draw_help(self, stdscr, h: int, w: int):
        lines = [
            "┌─── HELP ────────────────────────────┐",
            "│  q/Q       Quit                     │",
            "│  c         Clear event buffer       │",
            "│  Tab/1-5   Switch tabs               │",
            "│  ↑ / ↓     Scroll events             │",
            "│  PgUp/PgDn Page scroll               │",
            "│  ?         Toggle this help          │",
            "└─────────────────────────────────────┘",
        ]
        top  = h // 2 - len(lines) // 2
        left = w // 2 - 22
        for i, l in enumerate(lines):
            try:
                stdscr.addstr(top + i, left, l, curses.color_pair(6))
            except curses.error:
                pass

    # ── filtering ─────────────────────────────────────────────────────────

    def _filtered_events(self) -> list:
        tab_type = TAB_FILTER.get(TABS[self.active_tab])
        with self.watchdog.event_lock:
            events = list(self.watchdog.event_queue)

        if tab_type:
            events = [e for e in events if e.get("type") == tab_type]

        if self.filter_text:
            ft = self.filter_text.lower()
            events = [
                e for e in events
                if ft in e.get("comm", "").lower()
                or ft in e.get("path", "").lower()
                or ft in e.get("filename", "").lower()
                or ft in e.get("dst", "").lower()
            ]

        return events

    # ── key handling ──────────────────────────────────────────────────────

    def _handle_key(self, key: int, stdscr):
        if key == ord("q") or key == ord("Q"):
            self._running = False
            self.watchdog.running = False

        elif key == ord("c"):
            with self.watchdog.event_lock:
                self.watchdog.event_queue.clear()
            self.scroll_off = 0

        elif key == ord("?"):
            self.help_shown = not self.help_shown

        elif key == 9 or key == curses.KEY_BTAB:  # Tab
            self.active_tab = (self.active_tab + 1) % len(TABS)
            self.scroll_off = 0

        elif ord("1") <= key <= ord("5"):
            self.active_tab = key - ord("1")
            self.scroll_off = 0

        elif key == curses.KEY_UP:
            self.scroll_off += 1

        elif key == curses.KEY_DOWN:
            self.scroll_off = max(0, self.scroll_off - 1)

        elif key == curses.KEY_PPAGE:
            self.scroll_off += 10

        elif key == curses.KEY_NPAGE:
            self.scroll_off = max(0, self.scroll_off - 10)

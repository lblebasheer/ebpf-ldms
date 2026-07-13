#!/usr/bin/env python3
"""profstat - live profiler stats for vfslatency eBPF maps.

Reads PROF_* maps via bpftool and displays a continuously refreshing
histogram view. Press 'r' to reset, 'q' to quit.
"""
import json
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import tty

MAPS = {
    "PROF_CTRL": {"key": "PROF_CTRL", "type": "ctrl"},
    "PROF_PATH_RES_HIST": {"key": "PROF_PATH_RES", "type": "hist_log2", "label": "Path Resolution (ns)"},
    "PROF_EXIT_HIST": {"key": "PROF_EXIT_HIST", "type": "hist_log2", "label": "Exit Probe (ns)"},
    "PROF_WALK_ITERS_HIST": {"key": "PROF_WALK_ITERS", "type": "hist_linear", "label": "Walk Iterations"},
    "PROF_RINGBUF_DROPS": {"key": "PROF_RINGBUF", "type": "counter", "label": "Ringbuf Drops"},
}

REFRESH_SEC = 1.0
BAR_WIDTH = 40


def bpftool(*args):
    try:
        r = subprocess.run(
            ["bpftool"] + list(args),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5,
        )
        if r.returncode != 0:
            return None
        return json.loads(r.stdout.decode())
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def find_maps():
    data = bpftool("map", "show", "--json")
    if not data or not isinstance(data, list):
        return {}
    found = {}
    for m in data:
        name = m.get("name", "")
        for map_name, info in MAPS.items():
            if name.startswith(info["key"]):
                found[map_name] = m["id"]
    return found


def read_map(map_id):
    data = bpftool("map", "dump", "id", str(map_id), "--json")
    if not data or not isinstance(data, list):
        return []
    entries = []
    for item in data:
        kb = item.get("key", [])
        vb = item.get("value", [])
        if len(kb) >= 4 and len(vb) >= 8:
            key_bytes = bytes(int(x, 0) for x in kb[:4])
            val_bytes = bytes(int(x, 0) for x in vb[:8])
            entries.append((
                struct.unpack("<I", key_bytes)[0],
                struct.unpack("<Q", val_bytes)[0],
            ))
    return entries


def read_counter(map_id):
    entries = read_map(map_id)
    return entries[0][1] if entries else 0


def reset_maps(map_ids):
    ctrl_id = map_ids.get("PROF_CTRL")
    if ctrl_id is None:
        return False
    r = subprocess.run(
        ["bpftool", "map", "update", "id", str(ctrl_id),
         "key", "hex", "00", "00", "00", "00",
         "value", "hex", "01", "00", "00", "00", "00", "00", "00", "00"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=5,
    )
    return r.returncode == 0


def fmt_ns(ns):
    if ns < 1000:
        return f"{ns}ns"
    elif ns < 1_000_000:
        return f"{ns/1000:.1f}us"
    else:
        return f"{ns/1_000_000:.2f}ms"


def render_bar(count, max_count):
    if max_count == 0:
        return ""
    filled = int((count / max_count) * BAR_WIDTH)
    return "#" * filled


def render(entries, label, log2=True):
    lines = [f"  {label}"]
    nonzero = [(k, v) for k, v in entries if v > 0]
    if not nonzero:
        lines.append("    (no data)")
        return lines
    max_count = max(v for _, v in nonzero)
    for key, count in sorted(nonzero):
        if log2:
            lbl = "0" if key == 0 else fmt_ns(1 << key)
        else:
            lbl = str(key)
        bar = render_bar(count, max_count)
        lines.append(f"  {lbl:>8} |{bar} {count}")
    return lines


def render_all(map_ids):
    lines = ["vfslatency profiler  (r: reset  q: quit)", ""]

    ctrl_id = map_ids.get("PROF_CTRL")
    reset_ts = read_counter(ctrl_id) if ctrl_id else 0
    if reset_ts > 1:
        lines.append(f"  reset @ {reset_ts} ns")
    else:
        lines.append("  no data yet")
    lines.append("")

    for name in ("PROF_PATH_RES_HIST", "PROF_EXIT_HIST", "PROF_WALK_ITERS_HIST"):
        info = MAPS[name]
        mid = map_ids.get(name)
        if mid:
            entries = read_map(mid)
            log2 = info["type"] == "hist_log2"
            lines.extend(render(entries, info["label"], log2))
        else:
            lines.append(f"  {info['label']}: map not found")
        lines.append("")

    drops_id = map_ids.get("PROF_RINGBUF_DROPS")
    if drops_id:
        lines.append(f"  Ringbuf Drops: {read_counter(drops_id)}")
    else:
        lines.append("  Ringbuf Drops: map not found")

    return "\n".join(lines)


def main():
    signal.signal(signal.SIGINT, lambda *_: None)

    print("Looking for PROF_* maps...")
    map_ids = {}
    while not map_ids:
        map_ids = find_maps()
        if not map_ids:
            print(".", end="", flush=True)
            time.sleep(1)
    print(f"\rFound {len(map_ids)} maps                    ")

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            os.system("clear")
            print(render_all(map_ids))
            start = time.monotonic()
            while time.monotonic() - start < REFRESH_SEC:
                if select.select([sys.stdin], [], [], 0)[0]:
                    ch = sys.stdin.read(1)
                    if ch == "q":
                        return
                    elif ch == "r":
                        reset_maps(map_ids)
                        time.sleep(0.1)
                        break
                time.sleep(0.05)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


if __name__ == "__main__":
    main()

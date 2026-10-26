#!/usr/bin/env python3
"""3x-ui / Xray log events: collect from local logs, push batches over HTTPS.

Modes (argv[1]):
  collect  read new lines of the logs (saved offsets), update local state
  push     send state to $XLE_URL; pending events are dropped only on 2xx

What is read (all optional, a missing file is skipped):
  $XLE_BANNED_LOG  3x-ui limit-IP bans  "... BAN [Email] = u1 [IP] = 1.2.3.4 banned ..."
                   (+ its *.prev.log: 3x-ui rotates it at local midnight)
  $XLE_PANEL_LOG   3xui.log: TLS handshake errors (probes), "ERROR - XRAY" lines,
                   "node traffic sync: fetch from <node> failed" (master only)
  $XLE_ACCESS_LOG  Xray access log: per client email / day / protocol the number
                   of accepted connections, distinct source IPs and distinct source
                   networks (/24 IPv4, /48 IPv6).

Privacy: the destination of an access-log line (where the user went) is never
parsed, stored or sent. Source IPs live only in the local state file (root,
0600) to count distinct addresses, for today and yesterday (UTC); only the
count leaves the host.

Counters and per-day aggregates are cumulative: the receiver keeps MAX, so a
repeated push is harmless. Stdlib only.
"""
import fcntl
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ENV = os.environ.get
NODE = ENV("XLE_NODE", "")
URL = ENV("XLE_URL", "")
TOKEN = ENV("XLE_TOKEN", "")
TIMEOUT = int(ENV("XLE_TIMEOUT", "30"))
STATE_DIR = ENV("XLE_STATE_DIR", "/var/lib/3xui-log-events")
BANNED_LOG = ENV("XLE_BANNED_LOG", "/var/log/x-ui/3xipl-banned.log")
# 3x-ui moves the ban log to *.prev.log at local midnight and truncates it:
# bans written after the last collect would be lost. Read the copy too; the
# receiver deduplicates events, so lines seen twice are harmless.
BANNED_PREV_LOG = ENV("XLE_BANNED_PREV_LOG", re.sub(r"\.log$", ".prev.log", BANNED_LOG))
PANEL_LOG = ENV("XLE_PANEL_LOG", "/var/log/x-ui/3xui.log")
ACCESS_LOG = ENV("XLE_ACCESS_LOG", "/var/log/x-ui/access.log")
MAX_EVENTS = int(ENV("XLE_MAX_EVENTS", "5000"))
MAX_ERRORS_PER_RUN = int(ENV("XLE_MAX_ERRORS_PER_RUN", "20"))
MAX_READ_BYTES = int(ENV("XLE_MAX_READ_BYTES", str(64 * 1024 * 1024)))
LOG_FILE = ENV("XLE_LOG_FILE", "")
SKIP_EMAIL_PREFIXES = tuple(p for p in ENV("XLE_SKIP_EMAIL_PREFIXES", "chain-").split(",") if p)

TS = r"(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)"
BAN_RE = re.compile(TS + r"\s+BAN\s+\[Email\]\s*=\s*(\S+)\s+\[IP\]\s*=\s*(\S+)")
SYNC_FAIL_RE = re.compile(TS + r".*node traffic sync: fetch from (\S+) failed")
XRAY_ERROR_RE = re.compile(TS + r"\s+ERROR - XRAY:\s*(.*)$")
PROBE_RE = re.compile(TS + r".*TLS handshake error from ")
# "<ts>.<us> from [tcp:]<ip>:<port> accepted <DESTINATION> [<inbound-tag> ...] email: <e>"
# The destination is matched by \S+ and NOT captured.
ACCESS_RE = re.compile(
    TS + r"(?:\.\d+)? from (?:tcp:|udp:)?\[?([0-9A-Fa-f:.]+?)\]?:\d+ accepted \S+ "
    r"\[([^\]\s]+)[^\]]*\](?: email: (\S+))?")


def log(msg):
    line = f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}Z {msg}"
    print(line, flush=True)
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


def to_epoch(stamp):
    """Log timestamps are in the host's local time."""
    return int(time.mktime(time.strptime(stamp, "%Y/%m/%d %H:%M:%S")))


def utc_day(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()


def net_of(ip):
    """Network of a source address: /24 for IPv4, /48 for IPv6.

    Mobile operators hand out a new IP every few minutes: one phone shows up
    as dozens of IPs a day, but within a few networks. The count of networks
    is much closer to the count of devices / places than the count of IPs.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def protocol_of(tag):
    """3x-ui node inbound tags: in-<id>-tcp (VLESS/XHTTP), in-<id>-udp (Hysteria)."""
    t = tag.lower()
    return "hysteria" if t.endswith("-udp") or "hysteria" in t else "vless"


# ------------------------------- state -------------------------------

def _path(name):
    return os.path.join(STATE_DIR, name)


def load_state():
    try:
        with open(_path("state.json"), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    st.setdefault("offsets", {})
    st.setdefault("events", [])
    st.setdefault("counters", {})   # day -> type -> count
    st.setdefault("conns", {})      # day -> email -> proto -> {conns, ips[], first, last}
    return st


def save_state(st):
    tmp = _path("state.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, separators=(",", ":"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, _path("state.json"))


def prune(st, now):
    keep = {utc_day(now), utc_day(now - 86400)}
    for key in ("counters", "conns"):
        for day in [d for d in st[key] if d not in keep]:
            del st[key][day]
    if len(st["events"]) > MAX_EVENTS:
        st["events"] = st["events"][-MAX_EVENTS:]


def read_new_lines(st, path):
    """New complete lines since the saved offset (handles rotation/truncation)."""
    try:
        s = os.stat(path)
    except OSError:
        return []
    off = st["offsets"].get(path) or {}
    pos = off.get("pos", 0)
    if off.get("ino") != s.st_ino or s.st_size < pos:
        pos = 0
    with open(path, "rb") as f:
        f.seek(pos)
        data = f.read(MAX_READ_BYTES)
    cut = data.rfind(b"\n")
    if cut < 0:
        return []
    chunk = data[:cut + 1]
    st["offsets"][path] = {"ino": s.st_ino, "pos": pos + len(chunk)}
    return chunk.decode("utf-8", "replace").splitlines()


# ------------------------------- collect -------------------------------

def bump(st, day, kind, n=1):
    c = st["counters"].setdefault(day, {})
    c[kind] = c.get(kind, 0) + n


def collect(st, now):
    stats = {"bans": 0, "probes": 0, "errors": 0, "sync": 0, "access": 0}
    ban_lines = []
    for path in (BANNED_PREV_LOG, BANNED_LOG):
        if path:
            ban_lines += read_new_lines(st, path)
    seen = set()
    for line in ban_lines:
        m = BAN_RE.search(line)
        if m and line not in seen:
            seen.add(line)
            st["events"].append({"type": "limit_ip_ban", "ts": to_epoch(m.group(1)),
                                 "email": m.group(2), "ip": m.group(3)})
            stats["bans"] += 1

    errors_left = MAX_ERRORS_PER_RUN
    for line in read_new_lines(st, PANEL_LOG):
        m = SYNC_FAIL_RE.search(line)
        if m:
            st["events"].append({"type": "node_sync_fail", "ts": to_epoch(m.group(1)),
                                 "target": m.group(2)})
            stats["sync"] += 1
            continue
        m = XRAY_ERROR_RE.search(line)
        if m:
            ts = to_epoch(m.group(1))
            bump(st, utc_day(ts), "xray_error")
            if errors_left > 0:
                st["events"].append({"type": "xray_error", "ts": ts, "message": m.group(2)[:300]})
                errors_left -= 1
            stats["errors"] += 1
            continue
        m = PROBE_RE.search(line)
        if m:
            bump(st, utc_day(to_epoch(m.group(1))), "probe")
            stats["probes"] += 1

    for line in read_new_lines(st, ACCESS_LOG):
        m = ACCESS_RE.search(line)
        if not m or not m.group(4):
            continue
        email = m.group(4)
        if email.startswith(SKIP_EMAIL_PREFIXES):
            continue
        ts = to_epoch(m.group(1))
        rec = (st["conns"].setdefault(utc_day(ts), {}).setdefault(email, {})
               .setdefault(protocol_of(m.group(3)),
                           {"conns": 0, "ips": [], "first": ts, "last": ts}))
        rec["conns"] += 1
        if m.group(2) not in rec["ips"]:
            rec["ips"].append(m.group(2))
        rec["first"] = min(rec["first"], ts)
        rec["last"] = max(rec["last"], ts)
        stats["access"] += 1
    prune(st, now)
    return stats


# ------------------------------- push -------------------------------

def build_payload(st, now):
    counters = []
    for day, kinds in sorted(st["counters"].items()):
        for kind in ("probe", "xray_error"):
            counters.append({"day": day, "type": kind, "count": int(kinds.get(kind, 0))})
    if not st["counters"]:
        # Heartbeat: the receiver shows the node as reporting even on a quiet day.
        counters = [{"day": utc_day(now), "type": "probe", "count": 0}]
    conns = []
    for day, emails in sorted(st["conns"].items()):
        for email, protos in emails.items():
            for proto, r in protos.items():
                conns.append({"day": day, "email": email, "protocol": proto,
                              "conns": r["conns"], "ips": len(r["ips"]),
                              "nets": len({net_of(ip) for ip in r["ips"]}),
                              "first_seen": r["first"], "last_seen": r["last"]})
    return {"node": NODE, "sent_at": now, "events": list(st["events"]),
            "counters": counters, "conns": conns}


def push(st, now):
    if not URL or not TOKEN:
        log("push: XLE_URL/XLE_TOKEN not set, skipping")
        return 0
    payload = build_payload(st, now)
    req = urllib.request.Request(
        URL, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        log(f"push: HTTP {e.code} {e.read(300).decode('utf-8', 'replace')}")
        return 1
    except (urllib.error.URLError, OSError) as e:
        log(f"push: failed: {e}")
        return 1
    sent = len(payload["events"])
    del st["events"][:sent]
    log(f"push: ok events={sent} counters={len(payload['counters'])} "
        f"conns={len(payload['conns'])} reply={body[:200]}")
    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("collect", "push"):
        print("usage: 3xui-log-events collect|push", file=sys.stderr)
        return 2
    if not NODE:
        print("XLE_NODE is not set", file=sys.stderr)
        return 2
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(_path("lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        st = load_state()
        now = int(time.time())
        if mode == "collect":
            stats = collect(st, now)
            save_state(st)
            log("collect: " + " ".join(f"{k}={v}" for k, v in stats.items())
                + f" pending_events={len(st['events'])}")
            return 0
        rc = push(st, now)
        save_state(st)
        return rc


if __name__ == "__main__":
    sys.exit(main())

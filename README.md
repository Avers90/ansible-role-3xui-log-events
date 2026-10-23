# ansible-role-3xui-log-events

Turn [3x-ui](https://github.com/MHSanaei/3x-ui) / Xray logs on master and node
hosts into a small stream of events and per-user counters, and push them to an
HTTP endpoint (e.g. an admin panel). Nothing about **where** users go leaves
the host.

## What is collected

| Source | Event / counter | Use |
|---|---|---|
| `3xipl-banned.log` | `limit_ip_ban` — client email, source IP, time | The panel cut a connection for 30 min because the client had more simultaneous devices than its `limitIp`. Users see it as "VPN keeps dropping" |
| `3xui.log` | `probe` counter per day — `TLS handshake error` lines | Scanners and active probing of the node; a sudden jump is an early blocking signal |
| `3xui.log` | `xray_error` counter per day + up to 20 events per run (message, 300 chars) | Xray crashes, inbound restarts |
| `3xui.log` (master) | `node_sync_fail` — target node | `node traffic sync: fetch from <node> failed` |
| Xray access log | per email / UTC day / protocol: accepted connections, distinct source IPs, first/last seen | Real device count vs. the plan limit, VLESS vs. Hysteria per user |

### Privacy

- The access-log **destination** (`accepted tcp:site:443`) is matched but never
  captured, stored or sent.
- Source IPs are kept only in the local state file (`/var/lib/3xui-log-events/state.json`,
  root, `0600`) for today and yesterday (UTC), to count distinct addresses.
  Only the count is pushed.
- The access log itself contains destinations. The role rotates it daily
  (`copytruncate`, 1 old copy kept, `maxsize 200M`). Turn the access log off in
  the panel and the per-user stats simply stop; everything else keeps working.
- Service clients (`chain-*`, node-to-node links) are skipped.

## How it runs

| Unit | When | What |
|---|---|---|
| `3xui-log-events-collect.timer` | every 5 min | read new lines of each log from the saved offset (rotation / truncation detected by inode and size), update `state.json` |
| `3xui-log-events-push.timer` | every 10 min (+ up to 60 s jitter) | POST the state, drop pending events only on HTTP 2xx |

Counters and per-day aggregates are **cumulative** and resent every time; the
receiver keeps the maximum, so a retried push never doubles anything. Pending
events are deduplicated by the receiver as well. A failed push keeps them
(bounded by `xui_log_events_max_events`).

Both units: `Nice=19`, `IOSchedulingClass=idle`, `CPUQuota=10%`,
`MemoryMax=128M`, `ProtectSystem=strict`, only `CAP_DAC_READ_SEARCH`.
Every run writes one line to journald and `/var/log/3xui-log-events/3xui-log-events.log`:

```
2026-10-23 20:20:27Z collect: bans=1 probes=200 errors=0 sync=3 access=3 pending_events=4
2026-10-23 20:30:41Z push: ok events=4 counters=2 conns=1 reply={"ok": true, ...}
2026-10-23 20:40:41Z push: HTTP 500 {"error": "storage"}
```

## Requirements

- Debian / Ubuntu, `python3` (stdlib only)
- 3x-ui ≥ 3.10 with logs in `/var/log/x-ui` (the panel's systemd sandbox
  allows writing there)
- For per-user stats: Xray access log enabled in the panel —
  *Xray Settings → Log → Access log* = `/var/log/x-ui/access.log`. Check on
  every node that the setting reached it (`/usr/local/x-ui/bin/config.json`,
  `"log": {"access": ...}`).

Node inbound tags look like `in-<id>-tcp` / `in-<id>-udp`; `-udp` is counted as
Hysteria, the rest as VLESS.

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `xui_log_events_node` | `edge-kz-01…` → `kz-01`, `panel-…` → `master` | Name sent in every batch; must match the node name in the master panel |
| `xui_log_events_log_dir` | `/var/log/x-ui` | Where 3x-ui writes its logs |
| `xui_log_events_banned_log` / `_panel_log` / `_access_log` | `3xipl-banned.log` / `3xui.log` / `access.log` in the log dir | Inputs; a missing file is skipped |
| `xui_log_events_access_log_rotate` | `true` | Install `/etc/logrotate.d/xray-access` |
| `xui_log_events_access_log_keep_days` | `1` | Rotated copies kept |
| `xui_log_events_access_log_maxsize` | `200M` | Rotate earlier when bigger (checked when logrotate runs) |
| `xui_log_events_skip_email_prefixes` | `chain-` | Comma-separated client email prefixes to ignore |
| `xui_log_events_collect_interval` | `5min` | Collect timer |
| `xui_log_events_push_url` | `""` | `https://…`; empty = collect only |
| `xui_log_events_push_token` | `""` | Bearer token (vault) |
| `xui_log_events_push_interval` | `10min` | Push timer |
| `xui_log_events_push_timeout` | `30` | Seconds |
| `xui_log_events_max_events` | `5000` | Pending events kept while the receiver is down |
| `xui_log_events_max_errors_per_run` | `20` | Xray error lines sent as events per run (all are counted) |
| `xui_log_events_max_read_bytes` | `64 MiB` | Per file per run; the rest is read next run |
| `xui_log_events_log_file_dir` | `/var/log/3xui-log-events` | Own log; empty = journald only |
| `xui_log_events_state_dir` | `/var/lib/3xui-log-events` | State and lock |

## Payload

```json
{"node": "kz-01", "sent_at": 1792770000,
 "events":   [{"type": "limit_ip_ban", "ts": 1792770091, "email": "u763", "ip": "1.2.3.4"},
              {"type": "xray_error", "ts": 1792770100, "message": "..."},
              {"type": "node_sync_fail", "ts": 1792770200, "target": "kz-01"}],
 "counters": [{"day": "2026-10-23", "type": "probe", "count": 5207},
              {"day": "2026-10-23", "type": "xray_error", "count": 5}],
 "conns":    [{"day": "2026-10-23", "email": "u763", "protocol": "vless",
               "conns": 12, "ips": 2, "first_seen": 1792760000, "last_seen": 1792770000}]}
```

Timestamps are Unix seconds; log lines are parsed in the host's local time zone.

## Example Playbook

```yaml
- hosts: component_3xui_panel:component_3xui_node
  become: true
  roles:
    - role: 3xui-log-events
      vars:
        xui_log_events_push_url: https://example.com/internal/proxy-node-events
        xui_log_events_push_token: "{{ vault_xui_log_events_token }}"
```

## Manual checks

```bash
sudo systemctl start 3xui-log-events@collect.service
sudo tail /var/log/3xui-log-events/3xui-log-events.log
sudo systemctl list-timers '3xui-log-events*'
```

## Known limits

- Access-log lines written between the last read and a `copytruncate` (up to
  one collect interval) are lost. `3xipl-banned.log` is safe: 3x-ui moves it to
  `3xipl-banned.prev.log` at local midnight, the role reads that copy too
  (events are deduplicated by the receiver).
- Distinct IPs are counted per node; one device on two countries counts twice.

## License

MIT

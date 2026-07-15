# netpolicyd HTTP API

Base URL default: `http://127.0.0.1:51910`

## Auth

All `/v1/*` routes require:

```http
Authorization: Bearer <token>
```

Open (no auth):

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`

## Core

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/version` | `{ "version": "…" }` |
| GET | `/v1/status` | Backend, tool detect, object counts, last apply |
| GET | `/v1/overview` | Status + all objects (+ host dump unless `?skip_host=1`) |
| GET | `/v1/dataplane` | Live host dump (`ip`, `nft`, `iptables`, `tc`) |
| GET | `/v1/traffic` | Live throughput + sockets (iface rates, by IP/port, connections) |
| POST | `/v1/apply` | Reconcile desired → host. `?dry_run=1` plans only |
| PUT/POST | `/v1/desired` | Replace bulk state from control plane, then apply |

## Policies

High-level ordered rules (egress, allow, deny, …).

| Method | Path |
|--------|------|
| GET/POST | `/v1/policies` |
| GET/PATCH/DELETE | `/v1/policies/{id}` |

**POST body (create):**

```json
{
  "name": "user4-via-gre-lab",
  "priority": 10,
  "subjects": [{ "kind": "cidr", "value": "10.77.0.4/32" }],
  "destination": { "kind": "any", "value": "0.0.0.0/0" },
  "action": "egress",
  "egress_name": "gre-lab",
  "source_cidr": "10.77.0.4/32"
}
```

Actions: `allow` · `deny` · `egress` · `direct` · `masquerade` · `forward`.

Egress applies `ip rule` + custom table default via `egress_name`, and auto-masquerade unless an explicit NAT already covers the same source/out-iface.

## Routes

| Method | Path |
|--------|------|
| GET/POST | `/v1/routes` |
| DELETE | `/v1/routes/{id}` |

```json
{
  "table": "100",
  "dst": "default",
  "device": "gre-lab",
  "gateway": "",
  "metric": 0,
  "onlink": false,
  "enabled": true
}
```

## NAT

| Method | Path |
|--------|------|
| GET/POST | `/v1/nat` |
| DELETE | `/v1/nat/{id}` |

```json
{
  "kind": "masquerade",
  "source_cidr": "10.77.0.0/24",
  "source_list": "",
  "out_iface": "gre-lab",
  "to_source": "",
  "enabled": true
}
```

`kind`: `masquerade` | `snat` (requires `to_source`).  
`source_list`: named IP list — expanded to one rule per entry at apply.

## Forwards

| Method | Path |
|--------|------|
| GET/POST | `/v1/forwards` |
| DELETE | `/v1/forwards/{id}` |

```json
{
  "action": "accept",
  "in_iface": "wg0",
  "out_iface": "ens18",
  "source": "10.77.0.0/24",
  "dest": "",
  "enabled": true
}
```

## Firewall

Full filter/nat/mangle rules (nft preferred, iptables fallback).

| Method | Path |
|--------|------|
| GET/POST | `/v1/firewall` |
| DELETE | `/v1/firewall/{id}` |

```json
{
  "name": "ssh-in",
  "priority": 100,
  "backend": "auto",
  "table": "filter",
  "chain": "input",
  "action": "accept",
  "protocol": "tcp",
  "dport": "22",
  "source": "",
  "source_list": "",
  "dest": "",
  "dest_list": "",
  "in_iface": "",
  "out_iface": "",
  "ct_state": "",
  "enabled": true
}
```

| Field | Notes |
|-------|--------|
| `backend` | `auto` · `nft` · `iptables` |
| `table` | `filter` · `nat` · `mangle` · `raw` |
| `chain` | `input` · `forward` · `output` · `prerouting` · `postrouting` |
| `action` | `accept` · `drop` · `reject` · `masquerade` · `snat` · `dnat` · `mark` · `log` · `redirect` · `return` |
| `ct_state` | e.g. `established,related` |
| `source_list` / `dest_list` | IP list name or id — expanded at apply |

**Apply is idempotent for nft:** managed chains are flushed, then re-populated. Repeated apply does not stack rules.

## IP addresses / rules / links

| Method | Path |
|--------|------|
| GET/POST | `/v1/ip/addrs` |
| DELETE | `/v1/ip/addrs/{id}` |
| GET/POST | `/v1/ip/rules` |
| DELETE | `/v1/ip/rules/{id}` |
| GET/POST | `/v1/ip/links` |
| DELETE | `/v1/ip/links/{id}` |

Address:

```json
{ "device": "gre-lab", "cidr": "10.77.0.1/24", "scope": "global", "enabled": true }
```

Policy rule:

```json
{ "from": "10.77.0.4/32", "table": "100", "priority": 11000, "action": "lookup", "enabled": true }
```

Link:

```json
{ "name": "gre-lab", "up": true, "mtu": 1400, "enabled": true }
```

## IP lists

Named sets of IPs/CIDRs for bulk NAT/firewall.

| Method | Path |
|--------|------|
| GET/POST | `/v1/ip/lists` |
| GET/DELETE | `/v1/ip/lists/{id}` |
| POST | `/v1/ip/lists/{id}/entries` |

```json
// create
{ "name": "clients", "entries": ["10.77.0.1", "10.77.0.2/32", "10.78.0.0/24"] }

// append
{ "entries": ["10.77.0.9"], "text": "10.77.0.10\n# comment\n10.77.0.11/32" }
```

Bare IPv4 becomes `/32` when expanded into rules.

## Traffic control (TC)

| Method | Path |
|--------|------|
| GET/POST | `/v1/tc` |
| DELETE | `/v1/tc/{id}` |

Rates are **bits/sec** (`50000000` = 50 Mbit/s).

```json
{
  "name": "user4-cap",
  "device": "gre-lab",
  "rate_tx_bps": 50000000,
  "rate_rx_bps": 20000000,
  "match_kind": "src_cidr",
  "match_value": "10.77.0.4/32",
  "enabled": true
}
```

`match_kind`: `any` · `src_cidr` · `dst_cidr` · `fwmark`.

## Sysctl

| Method | Path |
|--------|------|
| GET/PUT/POST | `/v1/sysctl/ip_forward` | `{ "enabled": true }` |
| GET/POST | `/v1/sysctl` | managed key/value list |
| DELETE | `/v1/sysctl/{key}` | e.g. `net.ipv4.conf.all.rp_filter` |

```json
{ "key": "net.ipv4.conf.all.rp_filter", "value": "2", "managed": true }
```

## Live traffic

| Method | Path |
|--------|------|
| GET | `/v1/traffic` |

Interface RX/TX rates from `/proc/net/dev` (bits/s via process-local sample delta). Socket inventory from `ss` (per IP, per port, top connections). First sample after daemon start has `interval_sec: 0` and zero rates; subsequent samples report deltas.

```json
{
  "collected_at": "2026-07-15T12:00:00Z",
  "interval_sec": 1.02,
  "ss_available": true,
  "total_rx_bps": 1250000,
  "total_tx_bps": 480000,
  "total_conns": 42,
  "established": 10,
  "listen": 8,
  "interfaces": [
    { "name": "eth0", "rx_bytes": 1, "tx_bytes": 2, "rx_bps": 1e6, "tx_bps": 4e5, "rx_pps": 100, "tx_pps": 50 }
  ],
  "by_ip": [
    { "ip": "10.0.0.1", "side": "local", "conns": 3, "bytes_sent": 1000, "bytes_recv": 2000 }
  ],
  "by_port": [
    { "port": "22", "proto": "tcp", "side": "local", "conns": 2 }
  ],
  "connections": [
    {
      "proto": "tcp", "state": "ESTAB",
      "local_ip": "10.0.0.1", "local_port": "22",
      "remote_ip": "1.2.3.4", "remote_port": "50000",
      "bytes_sent": 100, "bytes_recv": 200, "send_bps": 8000
    }
  ]
}
```

## Apply result

```json
{
  "ok": true,
  "dry_run": false,
  "applied": 12,
  "skipped": 0,
  "commands": ["sysctl -w …", "nft flush chain …", "nft add rule …"],
  "errors": [],
  "message": "applied 12 commands",
  "generation": 0
}
```

## Errors

```json
{
  "error": {
    "code": "bad_request",
    "message": "name required"
  }
}
```

Common codes: `unauthorized` · `bad_request` · `not_found`.

## Metrics

`GET /metrics` — Prometheus text:

- `netpolicyd_up`
- `netpolicyd_policies`
- `netpolicyd_policies_enabled`

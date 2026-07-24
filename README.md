# netpolicyd

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/reloadlife/netpolicyd)](https://github.com/reloadlife/netpolicyd/releases)

**netpolicyd** is a Linux **host network policy** daemon: desired-state routing, firewall, NAT, addresses, traffic control, and sysctls, applied through `ip` / `nft` / `iptables` / `tc`.

**netpolicyctl** is the control panel: easy/advanced full-screen TUI plus CLI.

How it works: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## What it manages

| Surface | Tools |
|---------|--------|
| **Policies** | Ordered rules expanded to policy routes / egress |
| **Routes / IP rules** | `ip route`, `ip rule` |
| **Addresses / links** | `ip addr`, `ip link` |
| **Firewall** | `nft` (preferred) or `iptables` |
| **NAT** | Masquerade / SNAT (CIDR or IP lists) |
| **IP lists** | Named groups of IPs/CIDRs |
| **TC** | HTB + ingress police (bits/s) |
| **Sysctl** | `ip_forward`, `rp_filter`, … |
| **Traffic** | Live RX/TX rates, sockets by IP/port/connection |
| **Dataplane** | Live host dump of firewall/routing |

Apply is **idempotent** for managed firewall state: owned chains are flushed, then rebuilt from desired config.

## Quick start

```bash
make build
./bin/netpolicyd --listen 127.0.0.1:51910 --token dev-token

export NETPOLICYCTL_URL=http://127.0.0.1:51910 NETPOLICYCTL_TOKEN=dev-token
./bin/netpolicyctl                 # TUI (easy mode)
./bin/netpolicyctl status
./bin/netpolicyctl apply --dry-run
```

## Example: source-based egress

```bash
curl -s -H "Authorization: Bearer dev-token" -H 'Content-Type: application/json' \
  -d '{
    "name": "src-via-gre-lab",
    "priority": 10,
    "subjects": [{"kind":"cidr","value":"10.77.0.4/32"}],
    "destination": {"kind":"any","value":"0.0.0.0/0"},
    "action": "egress",
    "egress_name": "gre-lab",
    "source_cidr": "10.77.0.4/32"
  }' http://127.0.0.1:51910/v1/policies

./bin/netpolicyctl apply
```

Roughly plans `ip rule` / table default via `gre-lab`, optional masquerade, and related firewall.

## WAN exit (`action=direct`, destination `any`)

Node uplink selection (control-plane WAN egress) must use `action=direct` with
`destination.kind=any` **and** `egress_name` set to the uplink (e.g. `eth0`).
That installs `from SRC lookup main` at priority `10000+P`, keeps the prune
list non-empty (so stale blackholes die), and auto-emits MASQ + forward-accept
out the uplink. Clearing `egress_name` or treating `direct`+`any` as a no-op
is a known outage class (2026-07-24).

## netpolicyctl

| Mode | Start |
|------|--------|
| **Easy** (default) | `netpolicyctl` · `NETPOLICYCTL_MODE=easy` |
| **Advanced** | `netpolicyctl --advanced` · toggle **`m`** in TUI |

**Easy:** Home · Fastpath · Masq · Block/Allow · Lists · Config · Speed · Traffic · Live  
**Advanced:** Status · Policies · Routes · NAT · Forwards · Firewall · IP · TC · Traffic · Dataplane  

See [docs/TUI.md](docs/TUI.md).

## HTTP API (default `:51910`)

Auth: `Authorization: Bearer <token>` on `/v1/*`.

| Area | Paths |
|------|--------|
| Health | `GET /healthz` |
| Status | `GET /v1/status` · `/v1/overview` · `/v1/dataplane` · `/v1/traffic` |
| Desired | `PUT /v1/desired` · `POST /v1/apply` |
| Objects | `/v1/policies` · `/v1/routes` · `/v1/nat` · `/v1/forwards` · `/v1/firewall` · `/v1/ip/*` · `/v1/tc` · `/v1/sysctl` |
| Metrics | `GET /metrics` |

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How netpolicyd works |
| [docs/API.md](docs/API.md) | HTTP contract |
| [docs/TUI.md](docs/TUI.md) | Easy / advanced UI |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Flags, env, apply model |
| [docs/INSTALL.md](docs/INSTALL.md) | Build, install, systemd |
| [docs/SECURITY.md](docs/SECURITY.md) | Hardening notes |

## Donations

If this project is useful to you, donations are welcome:

| Network | Address |
|---------|---------|
| **Bitcoin** (BTC) | `bc1qy08pk2teys968hphh98rv8y9azeraf2c8vsdm8` |
| **EVM** (ETH, BNB, USDT, and other EVM chains) | `0x8B6CE1EA8F17f6941F13A621b92Af345a75D8c41` |
| **TRON** (TRX) | `TGXJToyAsUtw1388jR5aW9ZohjSCDtmKbg` |

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

If you run a modified version of `netpolicyd` as a network service, you must offer the corresponding source to users who interact with it over the network (AGPL §13).

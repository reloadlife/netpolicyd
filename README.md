# netpolicyd

Host **network policy** daemon: policy routing, firewall, NAT, addresses, and traffic control.

Controlled only over HTTP (Bearer token). Companion CLI + TUI: **netpolicyctl**.

## What it manages

| Surface | Tools |
|---------|--------|
| **Policies** | Ordered rules — e.g. client CIDR exits via a tunnel |
| **Routes / IP rules** | `ip route`, `ip rule` |
| **Addresses / links** | `ip addr`, `ip link` |
| **Firewall** | `nft` (preferred) or `iptables` |
| **NAT** | Masquerade / SNAT |
| **IP lists** | Named groups of IPs/CIDRs for bulk rules |
| **TC** | HTB + ingress police (bits/s) |
| **Sysctl** | `ip_forward`, `rp_filter`, … |

Apply is **idempotent** for managed firewall state: chains are flushed, then rebuilt from desired config (no stacked duplicate rules).

## Quick start

```bash
make build
./bin/netpolicyd --listen 127.0.0.1:51910 --token dev-token

export NETPOLICYCTL_URL=http://127.0.0.1:51910 NETPOLICYCTL_TOKEN=dev-token
./bin/netpolicyctl                 # TUI (easy mode)
./bin/netpolicyctl status
./bin/netpolicyctl apply --dry-run
```

## Example: user via GRE

```bash
curl -s -H "Authorization: Bearer dev-token" -H 'Content-Type: application/json' \
  -d '{
    "name": "user4-via-gre-lab",
    "priority": 10,
    "subjects": [{"kind":"cidr","value":"10.77.0.4/32"}],
    "destination": {"kind":"any","value":"0.0.0.0/0"},
    "action": "egress",
    "egress_name": "gre-lab",
    "source_cidr": "10.77.0.4/32"
  }' http://127.0.0.1:51910/v1/policies
```

Roughly applies:

```sh
ip route replace default dev gre-lab table 100
ip rule add from 10.77.0.4/32 table 100 priority …
nft flush chain inet netpolicyd postrouting
nft add rule inet netpolicyd postrouting ip saddr 10.77.0.4/32 oifname "gre-lab" masquerade …
sysctl -w net.ipv4.ip_forward=1
```

## netpolicyctl

| Mode | Start |
|------|--------|
| **Easy** (default) | `netpolicyctl` · `NETPOLICYCTL_MODE=easy` |
| **Advanced** | `netpolicyctl --advanced` · toggle with **`m`** in TUI |

**Easy tabs:** Home · Fastpath · Masq · Block/Allow · Lists · Config · Speed · Live  

**Advanced tabs:** Status · Policies · Routes · NAT · Forwards · Firewall · IP · TC · Dataplane  

See [docs/TUI.md](docs/TUI.md).

## HTTP API (default `:51910`)

Auth: `Authorization: Bearer <token>` on `/v1/*`.

| Area | Paths |
|------|--------|
| Health | `GET /healthz` |
| Status | `GET /v1/status` · `GET /v1/overview` · `GET /v1/dataplane` |
| Desired | `PUT /v1/desired` · `POST /v1/apply?dry_run=1` |
| Policies | `/v1/policies` |
| Routes / NAT / Forwards | `/v1/routes` · `/v1/nat` · `/v1/forwards` |
| Firewall | `/v1/firewall` |
| IP | `/v1/ip/addrs` · `/v1/ip/rules` · `/v1/ip/links` · `/v1/ip/lists` |
| TC | `/v1/tc` |
| Sysctl | `/v1/sysctl` · `/v1/sysctl/ip_forward` |
| Metrics | `GET /metrics` |

Full reference: [docs/API.md](docs/API.md).

## Documentation

| Doc | |
|-----|--|
| [docs/INSTALL.md](docs/INSTALL.md) | Build, install, systemd |
| [docs/API.md](docs/API.md) | HTTP contract |
| [docs/TUI.md](docs/TUI.md) | Easy / advanced UI |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Flags, env, apply model, sysctls |
| [configs/](configs/) | Example env files |
| [deploy/netpolicyd.service](deploy/netpolicyd.service) | systemd unit |

## Why “netpolicyd”?

systemd’s **firewalld** already owns that name. This daemon is a focused control-plane target for host policy + routing + NAT + TC over a small HTTP API.

## License

See repository root if a LICENSE file is present; otherwise treat as private/internal unless stated.

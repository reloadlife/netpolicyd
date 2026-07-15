# Configuration

## Daemon

Flags (preferred for simple deploys):

```bash
netpolicyd --listen 127.0.0.1:51910 --token SECRET
netpolicyd --mock   # plan only
```

Optional env file for systemd (`/etc/netpolicyd/netpolicyd.env`):

```bash
NETPOLICYD_LISTEN=127.0.0.1:51910
NETPOLICYD_TOKEN=change-me
# NETPOLICYD_MOCK=1
```

See `configs/netpolicyd.example.env` and `deploy/netpolicyd.service`.

### Backend selection

| Condition | Backend |
|-----------|---------|
| `--mock` or no `ip` binary | `mock` — record commands, do not exec |
| `ip` present | `live` — exec plan via `sh -c` |

Missing `nft` / `iptables` / `tc` does not fail health: those parts are skipped or planned for dry-run/mock. Prefer **nft** for filter/nat when available.

### Apply model

Desired state lives in memory (policies, routes, NAT, firewall, TC, IP objects, lists, sysctls).

`POST /v1/apply`:

1. Build command plan from desired state  
2. **Flush** managed nft chains / iptables `NETPOLICYD*` chains  
3. Re-add rules from scratch (idempotent)  
4. Run `ip` / `sysctl` / `tc` as needed  

So the host’s managed table matches desired state after each successful apply. Unmanaged rules outside `inet netpolicyd` / `NETPOLICYD*` are left alone.

### Auto masquerade for egress

Enabled egress policies generate masquerade for `source_cidr` (or first cidr subject) out `egress_name`, **unless** an explicit NAT already covers that source+out-iface.

## Client (netpolicyctl)

```bash
export NETPOLICYCTL_URL=http://127.0.0.1:51910
export NETPOLICYCTL_TOKEN=change-me
export NETPOLICYCTL_MODE=easy      # or advanced
export NETPOLICYCTL_REFRESH=2     # seconds
```

See `configs/netpolicyctl.example.env`.

## Recommended host sysctls (gateway)

Usually set via Config TUI or API:

| Key | Suggested | Why |
|-----|-----------|-----|
| `net.ipv4.ip_forward` | `1` | Route through host |
| `net.ipv6.conf.all.forwarding` | `1` | If you forward v6 |
| `net.ipv4.conf.all.rp_filter` | `2` | Loose RPF — asymmetric return paths (tunnels) |
| `net.ipv4.conf.default.rp_filter` | `2` | Same for new ifaces |
| `net.ipv4.conf.<dev>.rp_filter` | `2` | Per egress/tunnel iface |

## Security notes

- Default listen is **loopback** — keep it that way unless you have a private control network  
- Rotate `--token` in production  
- Live apply requires net admin capability; do not expose the API publicly without TLS termination and strong auth at the edge  
- Dry-run (`apply?dry_run=1`) never changes the host  

## Persistence

The in-process store is **memory-only**. Restart loses desired state unless a control plane re-pushes via `PUT /v1/desired` or local tools re-create objects. Host kernel state may remain until reboot or manual cleanup (`nft delete table inet netpolicyd`).

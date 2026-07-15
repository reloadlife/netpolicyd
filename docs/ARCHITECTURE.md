# How netpolicyd works

`netpolicyd` is a Linux **host network policy** daemon. It holds a *desired* configuration (routes, firewall, NAT, addresses, traffic control, sysctls) and **applies** it to the host by running `ip`, `nft`/`iptables`, `tc`, and `sysctl`. The companion binary `netpolicyctl` is a TUI/CLI client for the HTTP API.

## Components

```
netpolicyctl  ── HTTP (Bearer) ──►  netpolicyd API (:51910)
                                        │
                         ┌──────────────┼──────────────┐
                         │              │              │
                      memory store   apply runner   host dump
                   (policies, routes,  (plan/exec)  (dataplane,
                    NAT, FW, TC, IP)                 traffic)
                         │              │
                         └──────► desired state ──► kernel
```

| Piece | Role |
|-------|------|
| **Store** | In-memory objects: policies, routes, NAT, forwards, firewall, IP, lists, TC, sysctls |
| **Apply** | Builds an ordered command plan; dry-run or execute on the host |
| **Firewall backend** | Prefer **nftables**; fall back to **iptables** when needed |
| **Dataplane** | Read-only snapshot of live host firewall/routing (`ip`, `nft`, …) |
| **Traffic** | Live interface rates (`/proc/net/dev` deltas) + socket inventory (`ss`) |
| **netpolicyctl** | Easy/advanced Bubble Tea TUI + CLI |

## Apply model

1. Operator (or control plane) writes **desired** objects via API or bulk `PUT /v1/desired`.
2. `POST /v1/apply` (or apply-on-desired) runs the reconciler.
3. Managed firewall/NAT state is applied **idempotently**: netpolicyd-owned chains are flushed, then rebuilt from desired rules (no stacked duplicates).
4. Routes, addresses, TC, and sysctls are planned and applied in dependency order.
5. Result includes the command list, success/error counts, and generation.

Dry-run (`?dry_run=1`) returns the same plan without executing.

## Policy surfaces

| Surface | Meaning |
|---------|---------|
| **Policies** | Ordered high-level rules (e.g. “this source CIDR uses egress device X”) expanded to `ip rule` / table routes / optional NAT |
| **Routes / IP rules** | Explicit `ip route` / `ip rule` entries |
| **Addresses / links** | Managed `ip addr` / `ip link` objects |
| **Firewall** | filter/nat/mangle rules via nft or iptables |
| **NAT** | Masquerade / SNAT (and list-expanded sources) |
| **Forwards** | Accept/drop style forward-path helpers |
| **IP lists** | Named CIDR groups expanded into concrete rules |
| **TC** | HTB egress + ingress police; rates in **bits/s** |
| **Sysctl** | Managed keys such as `ip_forward`, `rp_filter` |

## Easy vs advanced UI

- **Easy mode** — plain-language jobs: fastpath (policy route), masq, block/allow, lists, config, speed limits, live traffic, host dump.  
- **Advanced mode** — full tabs for every object type and raw dataplane.

Toggle with **`m`** in the TUI.

## Live observation

| Endpoint / tab | Source |
|----------------|--------|
| `/v1/dataplane` | Live `ip` / `nft` / `iptables` / `tc` text dumps |
| `/v1/traffic` | Interface RX/TX rates + `ss` aggregates (by IP, port, connection) |

Traffic rates need two samples; the TUI refreshes ~1s on the Traffic tab.

## Mock vs live

If `ip` is not available (or `--mock`), the runner **plans** commands only and does not exec. With tools present, apply executes for real and requires appropriate privileges (`CAP_NET_ADMIN` / root).

## Related binaries

| Binary | Purpose |
|--------|---------|
| `netpolicyd` | Daemon |
| `netpolicyctl` | Operator TUI/CLI |

Default control API: **`127.0.0.1:51910`**.

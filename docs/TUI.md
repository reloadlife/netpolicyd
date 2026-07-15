# netpolicyctl TUI

Full-screen terminal UI for netpolicyd. Starts in **easy** mode by default.

```bash
netpolicyctl                 # TUI
netpolicyctl --advanced      # start in advanced
netpolicyctl --easy
```

Env: `NETPOLICYCTL_URL` · `NETPOLICYCTL_TOKEN` · `NETPOLICYCTL_MODE=easy|advanced` · `NETPOLICYCTL_REFRESH`

Toggle modes anytime: **`m`**.

Quit: **`q`** / `Ctrl+C`.

---

## Easy mode

Plain-language jobs. No tables/chains unless you switch to advanced.

| Key | Tab |
|-----|-----|
| **1 Home** | Status, counts, checklist |
| **2 Fastpath** | Client CIDR → tunnel (policy route) |
| **3 Masq** | Masquerade (CIDR or IP list); optional full return |
| **4 Block/Allow** | Ports, IPs, services, IP lists |
| **5 Lists** | Named IP/CIDR groups |
| **6 Config** | IP forward, routing, routes, sysctls |
| **7 Speed** | Bandwidth limits (bits/s, e.g. `50mbit`) |
| **8 Live** | Live host dump |

### Global keys (easy)

| Key | Action |
|-----|--------|
| `1`–`8` / tab | Switch tab |
| `n` | New / wizard |
| `j` `k` | Move / scroll |
| `enter` | Detail |
| `D` | Delete (confirm `y`) |
| `a` | Apply |
| `A` | Dry-run apply |
| `r` | Refresh |
| `m` | Advanced mode |
| `q` | Quit |

### Shortcuts

| Key | Where | Action |
|-----|--------|--------|
| `f` | Home / Config | Toggle IP forward |
| `g` | Home / Config | Gateway wizard (forward + established + path) |
| `u` | Config | Add route |
| `p` | Config / Masq | Loose `rp_filter=2` |
| `o` | Home / Block | Quick allow SSH |
| `b` | Home / Block | Quick block wizard |
| `i` | Lists | Add IPs to selected list |
| `t` | Fastpath | Toggle rule on/off |

### Typical gateway flow

1. **Lists** → create `clients` with tunnel IPs  
2. **Fastpath** → Who = client CIDR, Via = `gre-lab`, + Return NAT if desired  
3. **Masq** → Who list = `clients`, Out = `gre-lab` (if not done in fastpath)  
4. **Config** → `f` / `g` for forward + routing  
5. **Block/Allow** → open ports or block sources (From list = `clients`)  
6. **`a`** apply  

---

## Advanced mode

Full operator surface.

| Tab | Contents |
|-----|----------|
| 1 Status | Backend, tools, counts, last apply |
| 2 Policies | Full policy CRUD |
| 3 Routes | Explicit routes |
| 4 NAT | Masquerade / SNAT |
| 5 Forwards | Accept/drop paths |
| 6 Firewall | filter/nat/mangle · nft or iptables |
| 7 IP | addrs / rules / links (`[` `]` section) |
| 8 TC | Bandwidth |
| 9 Dataplane | Full host dump |

Keys: `n` new · `e` edit · `t` toggle · `D` delete · `a`/`A` apply · `m` easy · `q` quit.

Forms: `tab`/`↑↓` fields · `←→`/space for selects · `enter` save · `esc` cancel.

---

## CLI (non-TUI)

```bash
netpolicyctl status
netpolicyctl policies
netpolicyctl routes
netpolicyctl nat
netpolicyctl forwards
netpolicyctl firewall
netpolicyctl tc
netpolicyctl lists
netpolicyctl ip [addrs|rules|links]
netpolicyctl overview
netpolicyctl dataplane
netpolicyctl apply [--dry-run]
netpolicyctl version
```

Add `--json` / `-j` on list commands where tables are default.

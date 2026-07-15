# Install & run

## Requirements

- Linux host with Go **1.24+** to build
- Runtime tools (for live apply): `ip`, and ideally `nft` and/or `iptables`, `tc`, `sysctl`
- Capability `CAP_NET_ADMIN` when applying live rules

Without `ip`, the daemon starts in **mock** backend (plans commands, does not exec).

## Build

```bash
make build
# → bin/netpolicyd  bin/netpolicyctl
```

```bash
make test
```

## Run (dev)

```bash
./bin/netpolicyd --listen 127.0.0.1:51910 --token dev-token
# or mock:
./bin/netpolicyd --listen 127.0.0.1:51910 --token dev-token --mock
```

```bash
export NETPOLICYCTL_URL=http://127.0.0.1:51910
export NETPOLICYCTL_TOKEN=dev-token
./bin/netpolicyctl              # TUI (easy mode)
./bin/netpolicyctl status
./bin/netpolicyctl apply --dry-run
```

## Flags (netpolicyd)

| Flag | Default | Meaning |
|------|---------|---------|
| `--listen` | `127.0.0.1:51910` | HTTP bind |
| `--token` | `dev-token` | Bearer token for `/v1/*` |
| `--mock` | false | Never exec host tools |
| `version` (arg) | | Print version and exit |

## Install binaries (local)

From the repo:

```bash
make build
make install
```

This installs:

| Path | |
|------|--|
| `/usr/local/bin/netpolicyd` | daemon |
| `/usr/local/bin/netpolicyctl` | CLI + TUI |
| `~/.local/bin/netpolicy*` | symlinks (ensure `~/.local/bin` is on `PATH`) |
| `~/.local/share/networkingd/daemons/netpolicyd/bin/` | copy if that dir exists |

Restart a running daemon after install:

```bash
# if using the local networkingd layout:
kill "$(cat ~/.local/share/networkingd/daemons/netpolicyd/daemon.pid)" 2>/dev/null
~/.local/share/networkingd/daemons/netpolicyd/bin/netpolicyd \
  --listen 127.0.0.1:51910 --token dev-token \
  >> ~/.local/share/networkingd/daemons/netpolicyd/daemon.log 2>&1 &
echo $! > ~/.local/share/networkingd/daemons/netpolicyd/daemon.pid
```

TUI needs a **real terminal** (not a pipe):

```bash
export NETPOLICYCTL_URL=http://127.0.0.1:51910
export NETPOLICYCTL_TOKEN=dev-token
netpolicyctl          # easy mode
netpolicyctl --advanced
```

## Install as systemd service

```bash
make install
sudo mkdir -p /etc/netpolicyd
sudo cp configs/netpolicyd.example.env /etc/netpolicyd/netpolicyd.env
# edit token + listen
sudo cp deploy/netpolicyd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netpolicyd
```

## Firewall the API

Default listen is loopback. For remote control, bind carefully and restrict with host firewall or a private network — the token alone is not a substitute for network isolation.

## Uninstall

```bash
sudo systemctl disable --now netpolicyd
sudo rm -f /usr/local/bin/netpolicyd /usr/local/bin/netpolicyctl
sudo rm -f /etc/systemd/system/netpolicyd.service
# optional: clear managed nft table
sudo nft delete table inet netpolicyd 2>/dev/null || true
```

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `backend=mock` | Is `ip` on PATH or under `/usr/sbin`? |
| Rules not applying | Run `netpolicyctl apply` without dry-run; check daemon logs |
| Duplicate nft rules (old versions) | Upgrade; apply flushes managed chains each time. One-shot: `nft flush chain inet netpolicyd postrouting` |
| 401 unauthorized | `NETPOLICYCTL_TOKEN` / daemon `--token` mismatch |
| Permission denied on apply | Run with `CAP_NET_ADMIN` or as root for live mode |

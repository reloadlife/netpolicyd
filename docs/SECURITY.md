# Security

## Threat model

`netpolicyd` can change host routing and firewall state. Compromise of the control API is equivalent to local root for networking.

| Surface | Risk | Mitigation |
|---------|------|------------|
| Control API | Unauthorized apply | Strong Bearer token; loopback or private management network |
| Apply path | Destructive host changes | Dry-run first; least-privilege operators; audit `LastApply` commands |
| Dataplane / traffic | Info disclosure | Same auth as API (Bearer on `/v1/*`); firewall non-loopback |

## Checklist

1. Set a strong token (`--token` / env); never leave `dev-token` on exposed hosts.  
2. Bind API to `127.0.0.1` or a management interface only.  
3. Run apply only from trusted operators / automation.  
4. Prefer `nft` backend when available; review dry-run output.  
5. Use systemd with a dedicated user and `CAP_NET_ADMIN` only where required.

## Auth

`Authorization: Bearer <token>` on all `/v1/*` routes. `/healthz` and `/metrics` may be unauthenticated depending on deployment—restrict with host firewall.

## Reporting

Report security issues privately to the repository owner (`reloadlife`).

package apply

import (
	"fmt"
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// planIPAddrs emits `ip addr replace` for managed addresses.
func planIPAddrs(addrs []api.IPAddrSpec) []string {
	var cmds []string
	for _, a := range addrs {
		if !a.Enabled || a.Device == "" || a.CIDR == "" {
			continue
		}
		parts := []string{"ip", "addr", "replace", a.CIDR, "dev", a.Device}
		if a.Peer != "" {
			parts = append(parts, "peer", a.Peer)
		}
		if a.Broadcast != "" {
			parts = append(parts, "broadcast", a.Broadcast)
		}
		scope := a.Scope
		if scope == "" {
			scope = "global"
		}
		parts = append(parts, "scope", scope)
		if a.Label != "" {
			parts = append(parts, "label", a.Label)
		}
		cmds = append(cmds, strings.Join(parts, " "))
	}
	return cmds
}

// ipRulePrio is the priority a spec lands on. Shared with the prune keep-list
// in apply.go: if the two ever disagree the prune deletes the rule it just
// added, which is how the fail-closed egress guard went missing.
func ipRulePrio(r api.IPRuleSpec, i int) int {
	if r.Priority > 0 {
		return r.Priority
	}
	return 11000 + i
}

// planIPRules emits `ip rule add` for explicit policy routing.
func planIPRules(rules []api.IPRuleSpec) []string {
	var cmds []string
	for i, r := range rules {
		if !r.Enabled {
			continue
		}
		prio := ipRulePrio(r, i)
		// Best-effort delete then add for idempotency on same selectors.
		del := buildIPRule("del", r, prio)
		add := buildIPRule("add", r, prio)
		if del != "" {
			cmds = append(cmds, del+" 2>/dev/null || true")
		}
		if add != "" {
			cmds = append(cmds, add)
		}
	}
	return cmds
}

func buildIPRule(op string, r api.IPRuleSpec, prio int) string {
	parts := []string{"ip", "rule", op}
	if r.From != "" {
		parts = append(parts, "from", r.From)
	} else if op == "add" {
		parts = append(parts, "from", "all")
	}
	if r.To != "" {
		parts = append(parts, "to", r.To)
	}
	if r.Iif != "" {
		parts = append(parts, "iif", r.Iif)
	}
	if r.Oif != "" {
		parts = append(parts, "oif", r.Oif)
	}
	if r.FwMark != 0 {
		parts = append(parts, "fwmark", fmt.Sprintf("0x%x", r.FwMark))
	}
	parts = append(parts, "priority", fmt.Sprintf("%d", prio))

	act := strings.ToLower(r.Action)
	if act == "" {
		act = "lookup"
	}
	switch act {
	case "lookup":
		table := r.Table
		if table == "" {
			table = "main"
		}
		parts = append(parts, "lookup", table)
	case "blackhole", "unreachable", "prohibit":
		parts = append(parts, act)
	default:
		parts = append(parts, "lookup", r.Table)
	}
	return strings.Join(parts, " ")
}

// planLinks emits `ip link set` for MTU / admin up-down.
func planLinks(links []api.LinkSpec) []string {
	var cmds []string
	for _, l := range links {
		if !l.Enabled || l.Name == "" {
			continue
		}
		if l.MTU > 0 {
			cmds = append(cmds, fmt.Sprintf("ip link set dev %s mtu %d", l.Name, l.MTU))
		}
		if l.Up != nil {
			if *l.Up {
				cmds = append(cmds, fmt.Sprintf("ip link set dev %s up", l.Name))
			} else {
				cmds = append(cmds, fmt.Sprintf("ip link set dev %s down", l.Name))
			}
		}
	}
	return cmds
}

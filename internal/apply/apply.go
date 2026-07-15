// Package apply turns desired policies into ip/nft/iptables/tc commands.
// When tools are missing, DryRun/mock records planned commands without failing.
package apply

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// Backend is mock (log only) or live (exec).
type Backend string

const (
	BackendMock Backend = "mock"
	BackendLive Backend = "live"
)

// Runner executes or records commands.
type Runner struct {
	Backend Backend
	// TableBase is the first custom routing table id for egress (default 100).
	TableBase int
}

func NewRunner(forceMock bool) *Runner {
	b := BackendLive
	if forceMock || !hasBin("ip") {
		b = BackendMock
	}
	return &Runner{Backend: b, TableBase: 100}
}

func hasBin(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := dir + "/" + name
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// Detect returns which tools exist on the host.
func Detect() (ip, nft, tc bool) {
	return hasBin("ip"), hasBin("nft"), hasBin("tc")
}

// Plan builds the command list for a full reconcile.
func (r *Runner) Plan(s api.ApplyState) []string {
	var cmds []string
	if s.IPForward {
		cmds = append(cmds, "sysctl -w net.ipv4.ip_forward=1")
		cmds = append(cmds, "sysctl -w net.ipv6.conf.all.forwarding=1")
	}
	// Explicit managed sysctls (rp_filter, etc.)
	for _, sc := range s.Sysctls {
		if !sc.Managed || sc.Key == "" {
			continue
		}
		cmds = append(cmds, fmt.Sprintf("sysctl -w %s=%s", sc.Key, sc.Value))
	}

	// Links first (MTU/up) then addresses
	if hasBin("ip") || r.Backend == BackendMock {
		cmds = append(cmds, planLinks(s.Links)...)
		cmds = append(cmds, planIPAddrs(s.IPAddrs)...)
	}

	// Ensure netpolicyd routing tables exist for each unique egress
	tableOf := map[string]int{}
	next := r.TableBase
	for _, p := range s.Policies {
		if !p.Enabled || p.Action != api.ActionEgress || p.EgressName == "" {
			continue
		}
		if _, ok := tableOf[p.EgressName]; ok {
			continue
		}
		tableOf[p.EgressName] = next
		cmds = append(cmds, "mkdir -p /etc/iproute2 && touch /etc/iproute2/rt_tables")
		cmds = append(cmds, fmt.Sprintf(
			"grep -q 'netpolicyd-%s' /etc/iproute2/rt_tables 2>/dev/null || echo '%d netpolicyd-%s' >> /etc/iproute2/rt_tables",
			p.EgressName, next, p.EgressName))
		cmds = append(cmds, fmt.Sprintf(
			"ip route replace default dev %s table %d", p.EgressName, next))
		next++
	}

	// Explicit routes
	for _, rt := range s.Routes {
		if !rt.Enabled {
			continue
		}
		table := rt.Table
		if table == "" {
			table = "main"
		}
		dst := rt.Dst
		if dst == "" || dst == "default" {
			dst = "default"
		}
		parts := []string{"ip", "route", "replace", dst}
		if rt.Gateway != "" {
			parts = append(parts, "via", rt.Gateway)
		}
		if rt.Device != "" {
			parts = append(parts, "dev", rt.Device)
		}
		if rt.OnLink {
			parts = append(parts, "onlink")
		}
		if rt.Metric > 0 {
			parts = append(parts, "metric", fmt.Sprintf("%d", rt.Metric))
		}
		if table != "main" {
			parts = append(parts, "table", table)
		}
		cmds = append(cmds, strings.Join(parts, " "))
	}

	// Explicit IP rules
	if hasBin("ip") || r.Backend == BackendMock {
		cmds = append(cmds, planIPRules(s.IPRules)...)
	}

	// Policy rules → ip rule + optional mark
	for _, p := range s.Policies {
		if !p.Enabled {
			continue
		}
		src := p.SourceCIDR
		if src == "" {
			for _, sub := range p.Subjects {
				if sub.Kind == "cidr" && sub.Value != "" {
					src = sub.Value
					break
				}
			}
		}
		switch p.Action {
		case api.ActionEgress:
			tid := tableOf[p.EgressName]
			if tid == 0 {
				continue
			}
			if src != "" {
				cmds = append(cmds, fmt.Sprintf(
					"ip rule del from %s table %d 2>/dev/null || true", src, tid))
				cmds = append(cmds, fmt.Sprintf(
					"ip rule add from %s table %d priority %d", src, tid, 10000+p.Priority))
			}
			if p.Mark != 0 {
				cmds = append(cmds, fmt.Sprintf(
					"ip rule add fwmark %d table %d priority %d", p.Mark, tid, 10000+p.Priority+1))
			}
		case api.ActionDeny:
			// folded into firewall as drop via synthetic rule below
			if src != "" {
				s.Firewall = append(s.Firewall, api.FirewallRule{
					ID: "pol-deny-" + p.ID, Name: p.Name, Enabled: true, Priority: p.Priority,
					Table: "filter", Chain: "forward", Source: src, Action: "drop",
					Comment: "policy-deny:" + p.Name, Backend: "auto",
				})
			}
		case api.ActionAllow, api.ActionDirect, api.ActionMasq, api.ActionForward:
			// allow/direct: no special rule; masq/forward handled elsewhere
		}
	}

	// Auto-masq for egress policies only when no explicit NAT already covers
	// the same (source, out_iface). Avoids duplicates with easy "with_return" / masq tab.
	extraNAT := append([]api.NATSpec{}, s.NAT...)
	covered := map[string]bool{}
	for _, n := range s.NAT {
		if !n.Enabled {
			continue
		}
		covered[natCoverKey(n.SourceCIDR, n.SourceList, n.OutIface)] = true
	}
	for _, p := range s.Policies {
		if !p.Enabled || p.Action != api.ActionEgress || p.EgressName == "" {
			continue
		}
		src := p.SourceCIDR
		if src == "" {
			for _, sub := range p.Subjects {
				if sub.Kind == "cidr" {
					src = sub.Value
					break
				}
			}
		}
		if src == "" {
			src = "0.0.0.0/0"
		}
		src = normalizeCIDR(src)
		key := natCoverKey(src, "", p.EgressName)
		if covered[key] {
			continue
		}
		// Also skip if any explicit NAT masqs this oif for 0.0.0.0/0 or empty source.
		if covered[natCoverKey("", "", p.EgressName)] || covered[natCoverKey("0.0.0.0/0", "", p.EgressName)] {
			continue
		}
		covered[key] = true
		extraNAT = append(extraNAT, api.NATSpec{
			ID: "auto-masq-" + p.ID, Enabled: true, Kind: "masquerade",
			SourceCIDR: src, OutIface: p.EgressName, Comment: "egress-" + p.Name,
		})
	}

	// Unified firewall (nft + iptables) including NAT + Forwards (+ IP list expand)
	cmds = append(cmds, planFirewall(s.Firewall, extraNAT, s.Forwards, s.IPLists)...)

	// Traffic control
	if hasBin("tc") || r.Backend == BackendMock {
		cmds = append(cmds, planTC(s.TC)...)
	}

	return cmds
}

// Apply runs the plan. Returns result with commands and errors.
func (r *Runner) Apply(s api.ApplyState, dryRun bool) api.ApplyResult {
	cmds := r.Plan(s)
	res := api.ApplyResult{
		OK:       true,
		DryRun:   dryRun || r.Backend == BackendMock,
		Commands: cmds,
		Applied:  0,
	}
	if dryRun || r.Backend == BackendMock {
		res.Message = "mock/dry-run: commands planned, not executed"
		res.Skipped = len(cmds)
		if r.Backend == BackendMock {
			res.Message = "backend=mock (ip/nft/iptables/tc limited); commands recorded only"
		}
		return res
	}
	for _, c := range cmds {
		if err := runShell(c); err != nil {
			res.OK = false
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", c, err))
			continue
		}
		res.Applied++
	}
	if res.OK {
		res.Message = fmt.Sprintf("applied %d commands", res.Applied)
	} else {
		res.Message = fmt.Sprintf("applied %d with %d errors", res.Applied, len(res.Errors))
	}
	return res
}

func runShell(cmdline string) error {
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.Env = append(os.Environ(),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func natCoverKey(src, list, oif string) string {
	return normalizeCIDR(src) + "|" + list + "|" + oif
}

// nftComment returns a shell-safe double-quoted comment without nft-breaking chars.
func nftComment(s string) string {
	if s == "" {
		s = "netpolicyd"
	}
	s = strings.Map(func(r rune) rune {
		switch r {
		case '"', '\\', ':', ';', '{', '}', '\n', '\r':
			return '-'
		default:
			return r
		}
	}, s)
	return `"` + s + `"`
}

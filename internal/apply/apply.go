// Package apply turns desired policies into ip/nft/iptables/tc commands.
// When tools are missing, DryRun/mock records planned commands without failing.
package apply

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
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
					"ip rule del fwmark %d table %d 2>/dev/null || true", p.Mark, tid))
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
	missingDevs := map[string]bool{}
	for _, c := range cmds {
		// Skip ip/tc against netdevs that are not present (stale gre-lab, mock WG, …)
		// so a missing egress does not spam hard errors every reconcile.
		if dev := deviceRequiredByCmd(c); dev != "" && !linkExists(dev) {
			missingDevs[dev] = true
			res.Skipped++
			continue
		}
		if err := runShell(c); err != nil {
			if dev, ok := missingDeviceErr(err); ok {
				missingDevs[dev] = true
				res.Skipped++
				continue
			}
			res.OK = false
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", c, err))
			continue
		}
		res.Applied++
	}
	switch {
	case !res.OK:
		res.Message = fmt.Sprintf("applied %d with %d errors", res.Applied, len(res.Errors))
	case len(missingDevs) > 0:
		devs := make([]string, 0, len(missingDevs))
		for d := range missingDevs {
			devs = append(devs, d)
		}
		sort.Strings(devs)
		res.Message = fmt.Sprintf("applied %d, skipped %d (missing device: %s)",
			res.Applied, res.Skipped, strings.Join(devs, ", "))
	default:
		res.Message = fmt.Sprintf("applied %d commands", res.Applied)
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

// linkExists reports whether a netdev is present under /sys/class/net.
func linkExists(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/ \t") {
		return false
	}
	st, err := os.Stat("/sys/class/net/" + name)
	return err == nil && st.IsDir()
}

// deviceRequiredByCmd extracts a single netdev from ip/tc commands that need it present.
// Returns "" for commands that do not target a specific interface.
func deviceRequiredByCmd(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) < 3 {
		return ""
	}
	// tc … dev NAME …
	if fields[0] == "tc" {
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
		return ""
	}
	// ip route … dev NAME …
	// ip addr … dev NAME …
	// ip link set NAME …
	if fields[0] == "ip" {
		for i := 1; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
		if len(fields) >= 4 && fields[1] == "link" && fields[2] == "set" {
			// ip link set gre-lab up / mtu …
			name := fields[3]
			if name != "dev" {
				return name
			}
		}
	}
	return ""
}

// missingDeviceErr detects "Cannot find device \"X\"" from ip/tc.
func missingDeviceErr(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	s := err.Error()
	const marker = "Cannot find device "
	i := strings.Index(s, marker)
	if i < 0 {
		return "", false
	}
	rest := s[i+len(marker):]
	rest = strings.TrimSpace(rest)
	rest = strings.Trim(rest, `"'`)
	// take first token
	if j := strings.IndexAny(rest, " \n\t:"); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.Trim(rest, `"'`)
	if rest == "" {
		return "", false
	}
	return rest, true
}

func natCoverKey(src, list, oif string) string {
	return normalizeCIDR(src) + "|" + list + "|" + oif
}

// sanitizeToken reduces free-form text to a single shell- and nft-safe token.
//
// Whitelist, not denylist: these strings are Join'd into a command line that is
// handed to `sh -c`, so ANY character outside [A-Za-z0-9_.-] becomes '-'. The
// previous denylist let `, |, & and $ through — a root command-injection sink
// reachable from the user-supplied comment / log-prefix fields.
func sanitizeToken(s string) string {
	if s == "" {
		s = "netpolicyd"
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '_', r == '.', r == '-':
			return r
		default:
			return '-'
		}
	}, s)
	// collapse runs of '-'
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		s = "netpolicyd"
	}
	return s
}

// nftComment returns a shell-safe double-quoted comment for nft.
func nftComment(s string) string {
	return `"` + sanitizeToken(s) + `"`
}

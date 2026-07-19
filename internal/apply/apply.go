// Package apply turns desired policies into ip/nft/iptables/tc commands.
// When tools are missing, DryRun/mock records planned commands without failing.
package apply

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
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

	// Ensure netpolicyd routing tables exist for each unique egress.
	//
	// Table ids are assigned over SORTED egress names, not in policy iteration
	// order. Policy order is not stable between applies (the control plane
	// builds per-device egress policies from a map), and an unstable assignment
	// is a correctness bug, not a cosmetic one:
	//
	//   - `ip rule del from X table N` before the add only matches if N is the
	//     same N as last time. When it drifts, the old rule survives and a new
	//     one is added beside it, so rules accumulate without bound.
	//   - Worse, those siblings point at DIFFERENT egresses. On thr-respina one
	//     VIP ended up with rules for tables 100, 101, 102 and 103
	//     simultaneously; whichever sorts first wins, so a device silently
	//     exits through a tunnel nobody selected.
	//
	// Sorting makes zur0 the same table id on every apply, on every node.
	egressNames := make([]string, 0, 8)
	seenEgress := map[string]bool{}
	for _, p := range s.Policies {
		if !p.Enabled || p.Action != api.ActionEgress || p.EgressName == "" {
			continue
		}
		if seenEgress[p.EgressName] {
			continue
		}
		seenEgress[p.EgressName] = true
		egressNames = append(egressNames, p.EgressName)
	}
	sort.Strings(egressNames)

	// Sorting alone is not enough. The set only contains egresses some device
	// currently selects, so one device switching tunnels changes the set and
	// reshuffles every id below it — orphaning every existing rule, because
	// `ip rule del ... table N` still names the old N. Observed as duplicate
	// rules for one VIP pointing at both zur0 and de0.
	//
	// /etc/iproute2/rt_tables is the registry: an egress keeps whatever id it
	// was first given, for as long as that line exists. New names take the next
	// free id. This is stable across set changes, restarts, and reorderings.
	existing := readRTTableIDs()
	usedID := map[int]bool{}
	for _, id := range existing {
		usedID[id] = true
	}
	nextFree := r.TableBase
	allocate := func() int {
		for usedID[nextFree] {
			nextFree++
		}
		usedID[nextFree] = true
		return nextFree
	}

	tableOf := map[string]int{}
	for _, name := range egressNames {
		tid, ok := existing[name]
		if !ok {
			tid = allocate()
		}
		tableOf[name] = tid
		cmds = append(cmds, "mkdir -p /etc/iproute2 && touch /etc/iproute2/rt_tables")
		// Rewrite rather than skip-if-present: a stale line mapping this name to
		// a different id makes `ip rule show` and rt_tables disagree, which is
		// how the numbers above became impossible to read off the host.
		cmds = append(cmds, fmt.Sprintf(
			"sed -i '/[[:space:]]netpolicyd-%s$/d' /etc/iproute2/rt_tables 2>/dev/null; echo '%d netpolicyd-%s' >> /etc/iproute2/rt_tables",
			name, tid, name))
		cmds = append(cmds, fmt.Sprintf(
			"ip route replace default dev %s table %d", name, tid))
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

	// Policy rules → ip rule + optional mark.
	// keepIPRule records every managed rule this generation wants, so the prune
	// below can delete the ones that belong to policies that have gone away.
	keepIPRule := map[string]bool{}
	for _, p := range s.Policies {
		if !p.Enabled {
			continue
		}
		src := policySourceCIDR(p)
		switch p.Action {
		case api.ActionEgress:
			tid := tableOf[p.EgressName]
			if tid == 0 {
				continue
			}
			if src != "" {
				prio := 10000 + p.Priority
				cmds = append(cmds, fmt.Sprintf(
					"ip rule del from %s table %d 2>/dev/null || true", src, tid))
				cmds = append(cmds, fmt.Sprintf(
					"ip rule add from %s table %d priority %d", src, tid, prio))
				keepIPRule[ipRuleKey(src, prio)] = true
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
		src := policySourceCIDR(p)
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

	// Auto forward-accept for egress policies.
	//
	// The route alone does not get the packet out: it still has to survive the
	// forward hook. Deriving the accept from the same policy set means an egress
	// becomes usable the moment it is declared, instead of when someone
	// remembers to re-run a script holding a hardcoded interface list.
	//
	// This is the 2026-07-19 outage: a device switched from one egress to
	// another, the ip rule and route were written correctly, and every packet
	// was dropped at forward because the new egress was not on that list.
	//
	// Emitted as ordinary FirewallRules so they ride the same plan (and the same
	// flush-then-add) as everything else in the managed chains.
	extraFW := append([]api.FirewallRule{}, s.Firewall...)
	fwSeen := map[string]bool{}
	for _, r := range s.Firewall {
		if r.Enabled {
			fwSeen[firewallFingerprint(r)] = true
		}
	}
	for _, p := range s.Policies {
		if !p.Enabled || p.Action != api.ActionEgress || p.EgressName == "" {
			continue
		}
		src := normalizeCIDR(policySourceCIDR(p))
		if src == "" {
			continue
		}
		for _, r := range []api.FirewallRule{{
			ID: "auto-fwd-" + p.ID, Enabled: true, Priority: 90,
			Table: "filter", Chain: "forward",
			Source: src, OutIface: p.EgressName, Action: "accept",
			Comment: "egress-forward:" + p.Name, Backend: "auto",
		}, {
			// Return path. Conntrack normally covers this, but not across a
			// conntrack flush, a NAT rebuild, or an offloaded flow re-entering
			// the slow path — and a half-open return path is very hard to debug.
			ID: "auto-fwd-ret-" + p.ID, Enabled: true, Priority: 90,
			Table: "filter", Chain: "forward",
			Dest: src, InIface: p.EgressName, Action: "accept",
			Comment: "egress-return:" + p.Name, Backend: "auto",
		}} {
			fp := firewallFingerprint(r)
			if fwSeen[fp] {
				continue
			}
			fwSeen[fp] = true
			extraFW = append(extraFW, r)
		}
	}

	// Prune managed ip rules whose policy is gone.
	//
	// Without this the applier is additive-only: it writes rules for what is in
	// desired and never removes rules for what left. A deleted device kept its
	// `ip rule` forever, so re-issuing that VIP to a new device silently handed
	// the new device the old one's egress.
	//
	// Never prune on an empty keep-list. Right after a restart, desired state is
	// empty until the control plane pushes — and an empty keep-list means "I do
	// not know what should exist yet", not "nothing should exist". Pruning there
	// deletes every managed rule on the host; that is exactly what happened on
	// thr-respina, taking all 17 devices' egress with it.
	//
	// The cost of this guard is that removing the very last egress policy leaves
	// its rule behind until another one exists. That is strictly better than a
	// restart race emptying the fleet.
	if (hasBin("ip") || r.Backend == BackendMock) && len(keepIPRule) > 0 {
		cmds = append(cmds, pruneIPRules(keepIPRule))
	}

	// Unified firewall (nft + iptables) including NAT + Forwards (+ IP list expand)
	cmds = append(cmds, planFirewall(extraFW, extraNAT, s.Forwards, s.IPLists)...)

	// Traffic control
	if hasBin("tc") || r.Backend == BackendMock {
		cmds = append(cmds, planTC(s.TC)...)
	}

	return cmds
}

// rtTablesPath is where iproute2 keeps the table id -> name registry.
var rtTablesPath = "/etc/iproute2/rt_tables"

// readRTTableIDs returns the table id already assigned to each netpolicyd-managed
// egress, so an egress keeps its id for as long as the line survives. Missing or
// unreadable file yields an empty map, which just means everything is allocated
// fresh — correct on a first run.
func readRTTableIDs() map[string]int {
	out := map[string]int{}
	raw, err := os.ReadFile(rtTablesPath)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) != 2 || !strings.HasPrefix(f[1], "netpolicyd-") {
			continue
		}
		id, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		out[strings.TrimPrefix(f[1], "netpolicyd-")] = id
	}
	return out
}

// policySourceCIDR is the client source a policy applies to: the explicit
// SourceCIDR override, else the first cidr subject. Empty when neither is set.
func policySourceCIDR(p api.PolicyRule) string {
	if p.SourceCIDR != "" {
		return p.SourceCIDR
	}
	for _, sub := range p.Subjects {
		if sub.Kind == "cidr" && sub.Value != "" {
			return sub.Value
		}
	}
	return ""
}

// ipRuleKey identifies a managed `ip rule` by the selectors we can read back
// from `ip rule show`.
func ipRuleKey(from string, prio int) string {
	return fmt.Sprintf("%s@%d", normalizeCIDR(from), prio)
}

// managedIPRulePrioMin/Max bound the priority band netpolicyd owns. Egress
// policies land at 10000+Priority, so anything else in this band is ours and
// stale. Rules outside the band (the kernel's 0/32766/32767, or an operator's
// hand-written rule at a different priority) are never touched.
const (
	managedIPRulePrioMin = 10000
	managedIPRulePrioMax = 10999
)

// pruneIPRules emits one command that deletes every `ip rule` in netpolicyd's
// priority band that this generation did not ask for.
//
// One exec, not one per stale rule: the live rule set is only knowable on the
// host, so the comparison happens there against a keep-list we build here.
func pruneIPRules(keep map[string]bool) string {
	want := make([]string, 0, len(keep))
	for k := range keep {
		want = append(want, k)
	}
	sort.Strings(want) // stable output so dry-run plans are diffable
	return fmt.Sprintf(
		`npd_keep=%s; ip -o rule show 2>/dev/null | `+
			`sed -n 's/^\([0-9]\{1,\}\):[[:space:]]*from \([^ ]\{1,\}\) .*$/\1 \2/p' | `+
			`while read -r npd_prio npd_from; do `+
			`[ "$npd_prio" -ge %d ] && [ "$npd_prio" -le %d ] || continue; `+
			`[ "$npd_from" = all ] && continue; `+
			// `ip rule show` prints a host selector WITHOUT its prefix length
			// ("from 10.0.0.1", never "from 10.0.0.1/32") while the keep-list is
			// normalized. Without this the two never match and the prune deletes
			// every managed rule on the host — which is exactly what it did.
			`npd_key="$npd_from"; case "$npd_key" in */*) ;; *:*) npd_key="$npd_key/128";; *) npd_key="$npd_key/32";; esac; `+
			`case " $npd_keep " in *" $npd_key@$npd_prio "*) continue;; esac; `+
			`ip rule del from "$npd_from" priority "$npd_prio" 2>/dev/null || true; `+
			`done`,
		shellQuote(strings.Join(want, " ")), managedIPRulePrioMin, managedIPRulePrioMax)
}

// shellQuote single-quotes a value for safe interpolation into sh -c.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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

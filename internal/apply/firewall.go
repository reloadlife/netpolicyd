package apply

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// planFirewall emits nft and/or iptables commands for managed firewall rules,
// plus converted NAT + Forward specs for unified dataplane apply.
// lists expands source_list/dest_list references on rules and NAT.
//
// Idempotent: managed nft chains are flushed before rules are re-added so
// repeated apply does not accumulate duplicates.
func planFirewall(rules []api.FirewallRule, nat []api.NATSpec, forwards []api.ForwardSpec, lists []api.IPList) []string {
	rules = expandFirewallLists(rules, lists)
	nat = expandNATLists(nat, lists)
	nat = dedupeNAT(nat)

	// Expand legacy NAT/Forward into FirewallRule shape so one planner applies all.
	all := make([]api.FirewallRule, 0, len(rules)+len(nat)+len(forwards))
	all = append(all, rules...)
	for _, n := range nat {
		if !n.Enabled {
			continue
		}
		r := api.FirewallRule{
			ID: n.ID, Name: n.Comment, Enabled: true, Priority: 500,
			Table: "nat", Chain: "postrouting", Source: n.SourceCIDR, OutIface: n.OutIface,
			Comment: n.Comment, Backend: "auto",
		}
		if n.Kind == "snat" {
			r.Action = "snat"
			r.ToSource = n.ToSource
		} else {
			r.Action = "masquerade"
		}
		all = append(all, r)
	}
	for _, f := range forwards {
		if !f.Enabled {
			continue
		}
		act := strings.ToLower(f.Action)
		if act == "" {
			act = "accept"
		}
		all = append(all, api.FirewallRule{
			ID: f.ID, Enabled: true, Priority: 100,
			Table: "filter", Chain: "forward",
			InIface: f.InIface, OutIface: f.OutIface,
			Source: f.Source, Dest: f.Dest, Action: act, Backend: "auto",
		})
	}

	all = dedupeFirewallRules(all)

	// Sort by priority
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Priority != all[j].Priority {
			return all[i].Priority < all[j].Priority
		}
		return all[i].ID < all[j].ID
	})

	nftOK := hasBin("nft")
	iptOK := hasBin("iptables") || hasBin("iptables-save")
	// In mock, plan both so dry-run shows full intent.
	mock := !nftOK && !iptOK

	// Does any rule actually target the iptables backend? ("auto" picks nft
	// whenever nft exists, so on an nft host this is normally false.)
	needIPT := false
	for _, r := range all {
		if !r.Enabled {
			continue
		}
		be := strings.ToLower(r.Backend)
		if be == "" || be == "auto" {
			if nftOK || mock {
				be = "nft"
			} else {
				be = "iptables"
			}
		}
		if be == "iptables" {
			needIPT = true
			break
		}
	}

	var cmds []string
	// Always ensure+flush managed chains whenever the backend is usable, even
	// when no rule currently targets it — deleting the last nft/iptables rule
	// must still flush the managed chains so stale rules disappear from the host.
	if nftOK || mock {
		cmds = append(cmds, ensureNFTBase()...)
		cmds = append(cmds, flushNFTChains()...)
	}
	switch {
	case needIPT || mock:
		// Rules to place: create chains + jumps, then they get flushed/refilled.
		cmds = append(cmds, ensureIptablesBase()...)
	case iptOK:
		// No iptables-backed rules, but stale ones may be live from a previous
		// generation. Flush them — without creating chains/jumps and without
		// paying ~32 execs per apply on hosts that never used this backend.
		cmds = append(cmds, flushIptablesChains()...)
	}

	// Track emitted command lines to avoid identical adds in one plan.
	seenCmd := map[string]bool{}
	for _, r := range all {
		if !r.Enabled {
			continue
		}
		be := strings.ToLower(r.Backend)
		if be == "" || be == "auto" {
			if nftOK || mock {
				be = "nft"
			} else if iptOK {
				be = "iptables"
			} else {
				be = "nft"
			}
		}
		var c string
		switch be {
		case "iptables":
			c = iptablesCmd(r)
		default:
			c = nftRuleCmd(r)
		}
		if c == "" || seenCmd[c] {
			continue
		}
		seenCmd[c] = true
		cmds = append(cmds, c)
	}
	return cmds
}

// dedupeNAT keeps first of identical kind+source+list+oif+tosource.
// Source CIDRs are normalized (bare host → /32) so 10.0.0.1 and 10.0.0.1/32 match.
func dedupeNAT(nat []api.NATSpec) []api.NATSpec {
	seen := map[string]bool{}
	var out []api.NATSpec
	for _, n := range nat {
		if !n.Enabled {
			continue
		}
		n.SourceCIDR = normalizeCIDR(n.SourceCIDR)
		key := strings.ToLower(n.Kind) + "|" + n.SourceCIDR + "|" + n.SourceList + "|" + n.OutIface + "|" + n.ToSource
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out
}

// dedupeFirewallRules drops rules that would compile to the same match+action.
func dedupeFirewallRules(rules []api.FirewallRule) []api.FirewallRule {
	seen := map[string]bool{}
	var out []api.FirewallRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		r.Source = normalizeCIDR(r.Source)
		r.Dest = normalizeCIDR(r.Dest)
		key := firewallFingerprint(r)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

func firewallFingerprint(r api.FirewallRule) string {
	return strings.Join([]string{
		strings.ToLower(r.Table),
		strings.ToLower(r.Chain),
		strings.ToLower(r.Action),
		normalizeCIDR(r.Source), normalizeCIDR(r.Dest), r.SourceList, r.DestList,
		r.InIface, r.OutIface,
		strings.ToLower(r.Protocol), r.Sport, r.Dport,
		r.CtState, r.ToSource, r.ToDestination,
		fmt.Sprintf("%d", r.FwMark), fmt.Sprintf("%d", r.SetMark),
		strings.ToLower(r.Backend),
	}, "|")
}

// normalizeCIDR turns bare IPv4 into /32 (and IPv6 into /128) for stable matching.
func normalizeCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/") {
		return s
	}
	if strings.Count(s, ".") == 3 && !strings.Contains(s, ":") {
		return s + "/32"
	}
	if strings.Contains(s, ":") {
		return s + "/128"
	}
	return s
}

func ensureNFTBase() []string {
	return []string{
		`nft list table inet netpolicyd >/dev/null 2>&1 || nft add table inet netpolicyd`,
		`nft list chain inet netpolicyd input >/dev/null 2>&1 || nft add chain inet netpolicyd input { type filter hook input priority filter \; policy accept \; }`,
		`nft list chain inet netpolicyd forward >/dev/null 2>&1 || nft add chain inet netpolicyd forward { type filter hook forward priority filter \; policy accept \; }`,
		`nft list chain inet netpolicyd output >/dev/null 2>&1 || nft add chain inet netpolicyd output { type filter hook output priority filter \; policy accept \; }`,
		`nft list chain inet netpolicyd prerouting >/dev/null 2>&1 || nft add chain inet netpolicyd prerouting { type nat hook prerouting priority dstnat \; }`,
		`nft list chain inet netpolicyd postrouting >/dev/null 2>&1 || nft add chain inet netpolicyd postrouting { type nat hook postrouting priority srcnat \; }`,
		`nft list chain inet netpolicyd mangle_prerouting >/dev/null 2>&1 || nft add chain inet netpolicyd mangle_prerouting { type filter hook prerouting priority mangle \; }`,
		`nft list chain inet netpolicyd mangle_postrouting >/dev/null 2>&1 || nft add chain inet netpolicyd mangle_postrouting { type filter hook postrouting priority mangle \; }`,
		`nft list chain inet netpolicyd mangle_forward >/dev/null 2>&1 || nft add chain inet netpolicyd mangle_forward { type filter hook forward priority mangle \; }`,
		// legacy alias — keep for older hosts but we flush it; prefer "forward" for new rules
		`nft list chain inet netpolicyd filter >/dev/null 2>&1 || nft add chain inet netpolicyd filter { type filter hook forward priority filter \; policy accept \; }`,
	}
}

// flushNFTChains clears all rules in managed chains before re-add (idempotent apply).
func flushNFTChains() []string {
	chains := []string{
		"input", "forward", "output",
		"prerouting", "postrouting",
		"mangle_prerouting", "mangle_postrouting", "mangle_forward",
		"filter",
	}
	var cmds []string
	for _, ch := range chains {
		cmds = append(cmds, fmt.Sprintf("nft flush chain inet netpolicyd %s 2>/dev/null || true", ch))
	}
	return cmds
}

// flushIptablesChains clears managed iptables chains WITHOUT creating them.
//
// Guarded by one existence check in a single sh -c: a host with no managed
// iptables chains pays one exec, not the ~32 that unconditionally running
// ensureIptablesBase would cost on every apply (apply runs on every write).
func flushIptablesChains() []string {
	return []string{
		`iptables -t filter -L NETPOLICYD_FWD -n >/dev/null 2>&1 && { ` +
			`iptables -t filter -F NETPOLICYD_IN 2>/dev/null; ` +
			`iptables -t filter -F NETPOLICYD_FWD 2>/dev/null; ` +
			`iptables -t filter -F NETPOLICYD_OUT 2>/dev/null; ` +
			`iptables -t nat -F NETPOLICYD_PRE 2>/dev/null; ` +
			`iptables -t nat -F NETPOLICYD_POST 2>/dev/null; ` +
			`iptables -t mangle -F NETPOLICYD_PRE 2>/dev/null; ` +
			`iptables -t mangle -F NETPOLICYD_POST 2>/dev/null; ` +
			`iptables -t mangle -F NETPOLICYD_FWD 2>/dev/null; } || true`,
	}
}

// ensureIptablesBase creates/flushes dedicated NETPOLICYD jump chains so
// repeated apply does not pile rules into built-in chains.
func ensureIptablesBase() []string {
	return []string{
		// filter — separate chains per hook so input rules never match forward traffic
		`iptables -t filter -N NETPOLICYD_IN 2>/dev/null || iptables -t filter -F NETPOLICYD_IN`,
		`iptables -t filter -N NETPOLICYD_FWD 2>/dev/null || iptables -t filter -F NETPOLICYD_FWD`,
		`iptables -t filter -N NETPOLICYD_OUT 2>/dev/null || iptables -t filter -F NETPOLICYD_OUT`,
		`iptables -t filter -C INPUT -j NETPOLICYD_IN 2>/dev/null || iptables -t filter -I INPUT 1 -j NETPOLICYD_IN`,
		`iptables -t filter -C FORWARD -j NETPOLICYD_FWD 2>/dev/null || iptables -t filter -I FORWARD 1 -j NETPOLICYD_FWD`,
		`iptables -t filter -C OUTPUT -j NETPOLICYD_OUT 2>/dev/null || iptables -t filter -I OUTPUT 1 -j NETPOLICYD_OUT`,
		// nat
		`iptables -t nat -N NETPOLICYD_PRE 2>/dev/null || iptables -t nat -F NETPOLICYD_PRE`,
		`iptables -t nat -N NETPOLICYD_POST 2>/dev/null || iptables -t nat -F NETPOLICYD_POST`,
		`iptables -t nat -C PREROUTING -j NETPOLICYD_PRE 2>/dev/null || iptables -t nat -I PREROUTING 1 -j NETPOLICYD_PRE`,
		`iptables -t nat -C POSTROUTING -j NETPOLICYD_POST 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j NETPOLICYD_POST`,
		// mangle
		`iptables -t mangle -N NETPOLICYD_PRE 2>/dev/null || iptables -t mangle -F NETPOLICYD_PRE`,
		`iptables -t mangle -N NETPOLICYD_POST 2>/dev/null || iptables -t mangle -F NETPOLICYD_POST`,
		`iptables -t mangle -N NETPOLICYD_FWD 2>/dev/null || iptables -t mangle -F NETPOLICYD_FWD`,
		`iptables -t mangle -C PREROUTING -j NETPOLICYD_PRE 2>/dev/null || iptables -t mangle -I PREROUTING 1 -j NETPOLICYD_PRE`,
		`iptables -t mangle -C POSTROUTING -j NETPOLICYD_POST 2>/dev/null || iptables -t mangle -I POSTROUTING 1 -j NETPOLICYD_POST`,
		`iptables -t mangle -C FORWARD -j NETPOLICYD_FWD 2>/dev/null || iptables -t mangle -I FORWARD 1 -j NETPOLICYD_FWD`,
	}
}

func nftChainName(table, chain string) string {
	table = strings.ToLower(table)
	chain = strings.ToLower(chain)
	if table == "mangle" {
		switch chain {
		case "prerouting":
			return "mangle_prerouting"
		case "postrouting":
			return "mangle_postrouting"
		case "forward":
			return "mangle_forward"
		case "input":
			return "mangle_prerouting"
		case "output":
			return "mangle_postrouting"
		}
	}
	// filter/nat use same chain names
	switch chain {
	case "input", "forward", "output", "prerouting", "postrouting":
		return chain
	default:
		// custom chain in filter
		return chain
	}
}

func nftRuleCmd(r api.FirewallRule) string {
	chain := nftChainName(r.Table, r.Chain)
	var parts []string
	parts = append(parts, "nft", "add", "rule", "inet", "netpolicyd", chain)

	if r.InIface != "" {
		parts = append(parts, "iifname", strconv.Quote(r.InIface))
	}
	if r.OutIface != "" {
		parts = append(parts, "oifname", strconv.Quote(r.OutIface))
	}
	proto := strings.ToLower(r.Protocol)
	if r.Source != "" {
		parts = append(parts, "ip", "saddr", r.Source)
	}
	if r.Dest != "" {
		parts = append(parts, "ip", "daddr", r.Dest)
	}
	if proto != "" && proto != "all" && proto != "ip" {
		parts = append(parts, proto)
		if r.Sport != "" {
			parts = append(parts, "sport", r.Sport)
		}
		if r.Dport != "" {
			parts = append(parts, "dport", r.Dport)
		}
	} else if r.Sport != "" || r.Dport != "" {
		// ports without proto — assume tcp
		parts = append(parts, "tcp")
		if r.Sport != "" {
			parts = append(parts, "sport", r.Sport)
		}
		if r.Dport != "" {
			parts = append(parts, "dport", r.Dport)
		}
	}
	if r.FwMark != 0 {
		parts = append(parts, "meta", "mark", fmt.Sprintf("0x%x", r.FwMark))
	}
	if cs := strings.TrimSpace(r.CtState); cs != "" {
		// nft: ct state established,related
		parts = append(parts, "ct", "state", cs)
	}

	act := strings.ToLower(r.Action)
	switch act {
	case "accept", "drop", "return":
		parts = append(parts, act)
	case "reject":
		parts = append(parts, "reject")
	case "masquerade":
		parts = append(parts, "masquerade")
	case "snat":
		if r.ToSource == "" {
			return ""
		}
		parts = append(parts, "snat", "to", r.ToSource)
	case "dnat":
		if r.ToDestination == "" {
			return ""
		}
		parts = append(parts, "dnat", "to", r.ToDestination)
	case "redirect":
		if r.ToDestination != "" {
			parts = append(parts, "redirect", "to", r.ToDestination)
		} else {
			parts = append(parts, "redirect")
		}
	case "mark":
		if r.SetMark == 0 {
			return ""
		}
		parts = append(parts, "meta", "mark", "set", fmt.Sprintf("0x%x", r.SetMark))
	case "log":
		pref := r.LogPrefix
		if pref == "" {
			pref = "netpolicyd"
		}
		parts = append(parts, "log", "prefix", nftComment(pref))
	default:
		parts = append(parts, act)
	}
	cmt := r.Comment
	if cmt == "" {
		cmt = r.Name
	}
	if cmt == "" {
		cmt = r.ID
	}
	if cmt != "" {
		parts = append(parts, "comment", nftComment(cmt))
	}
	return strings.Join(parts, " ")
}

func iptablesCmd(r api.FirewallRule) string {
	table := strings.ToLower(r.Table)
	if table == "" {
		table = "filter"
	}
	// Use dedicated NETPOLICYD* chains (flushed each apply) instead of
	// appending forever to built-in INPUT/FORWARD/POSTROUTING.
	chain := iptablesManagedChain(table, r.Chain)
	if chain == "" {
		return ""
	}

	var args []string
	args = append(args, "iptables", "-t", table, "-A", chain)
	if r.Source != "" {
		args = append(args, "-s", r.Source)
	}
	if r.Dest != "" {
		args = append(args, "-d", r.Dest)
	}
	if r.InIface != "" {
		args = append(args, "-i", r.InIface)
	}
	if r.OutIface != "" {
		args = append(args, "-o", r.OutIface)
	}
	proto := strings.ToLower(r.Protocol)
	if proto != "" && proto != "all" {
		args = append(args, "-p", proto)
	} else if r.Sport != "" || r.Dport != "" {
		args = append(args, "-p", "tcp")
		proto = "tcp"
	}
	if r.Sport != "" {
		args = append(args, "--sport", r.Sport)
	}
	if r.Dport != "" {
		args = append(args, "--dport", r.Dport)
	}
	if r.FwMark != 0 {
		args = append(args, "-m", "mark", "--mark", fmt.Sprintf("0x%x", r.FwMark))
	}
	if cs := strings.TrimSpace(r.CtState); cs != "" {
		// map "established,related" → ESTABLISHED,RELATED
		up := strings.ToUpper(cs)
		args = append(args, "-m", "conntrack", "--ctstate", up)
	}

	act := strings.ToLower(r.Action)
	switch act {
	case "accept", "drop", "return", "reject":
		args = append(args, "-j", strings.ToUpper(act))
	case "masquerade":
		args = append(args, "-j", "MASQUERADE")
	case "snat":
		if r.ToSource == "" {
			return ""
		}
		args = append(args, "-j", "SNAT", "--to-source", r.ToSource)
	case "dnat":
		if r.ToDestination == "" {
			return ""
		}
		args = append(args, "-j", "DNAT", "--to-destination", r.ToDestination)
	case "redirect":
		args = append(args, "-j", "REDIRECT")
		if r.ToDestination != "" {
			// port only for redirect
			args = append(args, "--to-ports", strings.TrimPrefix(r.ToDestination, ":"))
		}
	case "mark":
		if r.SetMark == 0 {
			return ""
		}
		args = append(args, "-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", r.SetMark))
	case "log":
		args = append(args, "-j", "LOG")
		pref := r.LogPrefix
		if pref == "" {
			pref = "netpolicyd"
		}
		// --log-prefix is Join'd into the sh -c line: one safe token, no spaces
		args = append(args, "--log-prefix", sanitizeToken(pref))
	default:
		args = append(args, "-j", strings.ToUpper(act))
	}
	cmt := r.Comment
	if cmt == "" {
		cmt = r.Name
	}
	if cmt == "" {
		cmt = r.ID
	}
	if cmt != "" {
		// same sh -c sink as nft — whitelist, never a denylist
		args = append(args, "-m", "comment", "--comment", "netpolicyd:"+sanitizeToken(cmt))
	}
	return strings.Join(args, " ")
}

// iptablesManagedChain maps logical chain → NETPOLICYD jump target.
func iptablesManagedChain(table, chain string) string {
	chain = strings.ToLower(chain)
	switch table {
	case "nat":
		switch chain {
		case "prerouting":
			return "NETPOLICYD_PRE"
		case "postrouting":
			return "NETPOLICYD_POST"
		default:
			return "NETPOLICYD_POST"
		}
	case "mangle":
		switch chain {
		case "prerouting":
			return "NETPOLICYD_PRE"
		case "postrouting":
			return "NETPOLICYD_POST"
		case "forward":
			return "NETPOLICYD_FWD"
		default:
			return "NETPOLICYD_PRE"
		}
	case "raw":
		switch chain {
		case "prerouting":
			return "PREROUTING"
		case "output":
			return "OUTPUT"
		default:
			return "PREROUTING"
		}
	default: // filter
		switch chain {
		case "input":
			return "NETPOLICYD_IN"
		case "output":
			return "NETPOLICYD_OUT"
		case "forward":
			return "NETPOLICYD_FWD"
		default:
			return "NETPOLICYD_FWD"
		}
	}
}

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
	// On an nft host, list references compile to set references — do NOT expand
	// them into a rule per entry. Expansion is only for the iptables backend,
	// which has no equivalent of a named set.
	// Lists compile to named nft sets, so they are never expanded per entry.
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

	// nft is the only backend.
	//
	// The iptables path was dead code that still cost something: `auto`
	// resolved to nft whenever the nft binary existed, which is every host in
	// this fleet, so all seven NETPOLICYD_* chains sat empty while their seven
	// jump rules were evaluated for every packet through INPUT, FORWARD,
	// OUTPUT, PREROUTING and POSTROUTING — and flushIptablesChains() ran on
	// every apply to clean chains nothing wrote to.
	//
	// Keeping two backends also meant two places to reason about, which is the
	// same shape as the two-owners-of-the-forward-hook bug that caused the
	// 2026-07-19 outage. One backend, one source of truth.
	//
	// Rules explicitly requesting Backend "iptables" are now emitted as nft:
	// the alternative is dropping them silently, and a firewall rule that
	// vanishes is worse than one expressed in the other syntax.
	var nftRules []api.FirewallRule
	for _, r := range all {
		if r.Enabled {
			nftRules = append(nftRules, r)
		}
	}
	var cmds []string
	if c := planNFTBatch(nftRules, lists); c != "" {
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

// natFamily returns the "ip"/"ip6" qualifier nft requires for snat/dnat inside
// an inet table: bare `dnat to 10.0.0.1` is rejected with "specify `dnat ip' or
// 'dnat ip6' in inet table to disambiguate".
//
// This mattered more than it looks. The managed table is applied as one atomic
// transaction, so a single malformed rule rejects the ENTIRE ruleset — het's
// mesh port-forward DNAT rules silently blocked every other rule on that node
// from updating, leaving a stale generation resident and healthy-looking.
func natFamily(addr string) string {
	host := addr
	if i := strings.LastIndex(host, "]"); i > 0 {
		return "ip6" // [2001:db8::1]:443
	}
	if strings.Count(host, ":") > 1 {
		return "ip6"
	}
	return "ip"
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
	body := nftRuleBody(r)
	if body == "" {
		return ""
	}
	return "nft add rule inet netpolicyd " + nftChainName(r.Table, r.Chain) + " " + body
}

// nftRuleBody is the match+action half of a rule, without the
// `nft add rule inet netpolicyd <chain>` prefix, so the same compiler serves
// both the one-command-per-rule path and the batched `nft -f` script.
func nftRuleBody(r api.FirewallRule) string {
	var parts []string

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
		parts = append(parts, "snat", natFamily(r.ToSource), "to", r.ToSource)
	case "dnat":
		if r.ToDestination == "" {
			return ""
		}
		parts = append(parts, "dnat", natFamily(r.ToDestination), "to", r.ToDestination)
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

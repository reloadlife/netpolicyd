package apply

import (
	"fmt"
	"sort"
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// This file emits the whole managed nft table as ONE `nft -f` transaction.
//
// It replaces a loop that ran `nft add rule …` once per rule through `sh -c`.
// On thr-respina that was 10,365 rules — the iran-direct policy expanded to one
// rule per Iran CIDR per device — rebuilt on every apply, at two forks each.
// Measured 1,054 forks in 10s, ~200s per apply, 11% CPU sustained, and the
// apply mutex held so continuously that /v1/apply?dry_run=1 timed out.
//
// Two changes kill that:
//
//  1. IP lists compile to named nft sets instead of a rule per entry. Set
//     lookup is an interval tree, not a linear scan, so it is also what every
//     forwarded packet stops paying for. (The *legacy* hand-written ruleset on
//     that node already did this correctly with a 1,462-entry iran_ips set.
//     Expanding lists into rules was a regression.)
//
//  2. Atomic table replace. `nft -f` applies a file as a single transaction, so
//     declaring an empty table, deleting it, and redefining it in one script
//     swaps the entire ruleset with no window where it is half-applied and no
//     flush needed. It is also inherently idempotent: the table is whatever the
//     script says, never that plus whatever a previous generation left.

// nftManagedChains is every chain in the managed table, with its hook spec.
// Order is fixed so generated scripts are diffable between runs.
var nftManagedChains = []struct{ name, spec string }{
	{"input", "type filter hook input priority filter; policy accept;"},
	{"forward", "type filter hook forward priority filter; policy accept;"},
	{"output", "type filter hook output priority filter; policy accept;"},
	{"prerouting", "type nat hook prerouting priority dstnat;"},
	{"postrouting", "type nat hook postrouting priority srcnat;"},
	{"mangle_prerouting", "type filter hook prerouting priority mangle;"},
	{"mangle_postrouting", "type filter hook postrouting priority mangle;"},
	{"mangle_forward", "type filter hook forward priority mangle;"},
	// legacy alias — same hook as forward, kept so old rules referencing it
	// still land somewhere rather than failing the transaction
	{"filter", "type filter hook forward priority filter; policy accept;"},
}

// nftSetName is the set name for an IP list. Sanitized because list names are
// user-supplied and land in a generated script.
func nftSetName(listNameOrID string) string {
	return "npd_list_" + sanitizeToken(listNameOrID)
}

// planNFTBatch renders the managed table as one atomic `nft -f` command, or ""
// when there is nothing to emit.
//
// Rules whose SourceList/DestList reference a known list are compiled to a set
// reference; the caller must NOT have pre-expanded those.
func planNFTBatch(rules []api.FirewallRule, lists []api.IPList) string {
	idx := listIndex(lists)

	// Only emit sets that a rule actually references — an unused 2,000-element
	// set is still 2,000 elements the kernel holds.
	used := map[string]bool{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, ref := range []string{r.SourceList, r.DestList} {
			if ref == "" {
				continue
			}
			if _, ok := idx[strings.TrimSpace(ref)]; ok {
				used[strings.TrimSpace(ref)] = true
			}
		}
	}

	byChain := map[string][]string{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		body := nftRuleBodyWithSets(r, idx)
		if body == "" {
			continue
		}
		ch := nftChainName(r.Table, r.Chain)
		byChain[ch] = append(byChain[ch], body)
	}

	var b strings.Builder
	// Declare-then-delete makes the replace idempotent whether or not the table
	// already exists; both statements are in the same transaction as the
	// definition below, so the dataplane never observes the gap.
	b.WriteString("table inet netpolicyd {}\n")
	b.WriteString("delete table inet netpolicyd\n")
	b.WriteString("table inet netpolicyd {\n")

	refs := make([]string, 0, len(used))
	for k := range used {
		refs = append(refs, k)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		entries := listEntries(idx, ref)
		if len(entries) == 0 {
			continue
		}
		b.WriteString(fmt.Sprintf("  set %s {\n", nftSetName(ref)))
		b.WriteString("    type ipv4_addr\n    flags interval\n    auto-merge\n")
		b.WriteString("    elements = { " + strings.Join(entries, ", ") + " }\n")
		b.WriteString("  }\n")
	}

	for _, ch := range nftManagedChains {
		b.WriteString(fmt.Sprintf("  chain %s {\n    %s\n", ch.name, ch.spec))
		for _, body := range byChain[ch.name] {
			b.WriteString("    " + body + "\n")
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")

	// Heredoc quoted so the shell does no expansion on the script.
	return "nft -f - <<'NPD_NFT_EOF'\n" + b.String() + "NPD_NFT_EOF"
}

// nftRuleBodyWithSets compiles a rule, substituting @set references for
// SourceList/DestList when the list is known. Unknown lists fall back to the
// literal Source/Dest so an unresolvable reference degrades to the old
// behaviour instead of silently matching everything.
func nftRuleBodyWithSets(r api.FirewallRule, idx map[string]api.IPList) string {
	src, dst := strings.TrimSpace(r.SourceList), strings.TrimSpace(r.DestList)
	srcOK, dstOK := false, false
	if src != "" {
		_, srcOK = idx[src]
	}
	if dst != "" {
		_, dstOK = idx[dst]
	}
	if !srcOK && !dstOK {
		return nftRuleBody(r)
	}
	cp := r
	cp.SourceList, cp.DestList = "", ""
	if srcOK {
		cp.Source = "@" + nftSetName(src)
	}
	if dstOK {
		cp.Dest = "@" + nftSetName(dst)
	}
	return nftRuleBody(cp)
}

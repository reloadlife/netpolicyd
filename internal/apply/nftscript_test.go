package apply

import (
	"fmt"
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// iranLike builds a list the size of the real one on thr-respina.
func iranLike(n int) api.IPList {
	l := api.IPList{ID: "list-iran", Name: "iran"}
	for i := 0; i < n; i++ {
		l.Entries = append(l.Entries, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	return l
}

// The regression this whole change exists for: a list reference must compile to
// ONE rule against a named set, not one rule per entry. thr-respina had 10,365
// rules in a single chain because iran-direct expanded 2,073 CIDRs x 4 devices,
// re-executed one fork at a time on every apply.
func TestListCompilesToSetNotRulePerEntry(t *testing.T) {
	lists := []api.IPList{iranLike(2073)}
	var rules []api.FirewallRule
	for i, vip := range []string{"100.67.80.4/32", "100.67.80.15/32", "100.67.84.2/32", "10.98.2.2/32"} {
		rules = append(rules, api.FirewallRule{
			ID: fmt.Sprintf("iran-direct-%d", i), Enabled: true, Backend: "nft",
			Table: "filter", Chain: "forward",
			Source: vip, DestList: "iran", Action: "accept",
		})
	}
	script := planNFTBatch(rules, lists)
	if script == "" {
		t.Fatal("empty script")
	}
	// Count accept *rules*, not the `policy accept;` in chain declarations.
	got := 0
	for _, ln := range strings.Split(script, "\n") {
		if strings.Contains(ln, "accept") && !strings.Contains(ln, "policy") {
			got++
		}
	}
	if got != 4 {
		t.Errorf("expected 4 accept rules (one per device), got %d", got)
	}
	if !strings.Contains(script, "@npd_list_iran") {
		t.Errorf("rules do not reference the set:\n%s", firstLines(script, 20))
	}
	if !strings.Contains(script, "flags interval") || !strings.Contains(script, "auto-merge") {
		t.Error("set should be an interval set with auto-merge")
	}
	// One set definition holds the CIDRs; they must not appear as rule matches.
	if n := strings.Count(script, "ip daddr 10."); n != 0 {
		t.Errorf("%d CIDRs leaked into rules — list was expanded, not set-ified", n)
	}
}

// An unresolvable list must not silently become "match everything".
func TestUnknownListFallsBackToLiteral(t *testing.T) {
	script := planNFTBatch([]api.FirewallRule{{
		ID: "r1", Enabled: true, Backend: "nft",
		Table: "filter", Chain: "forward",
		Source: "10.0.0.1/32", DestList: "does-not-exist", Action: "drop",
	}}, nil)
	if strings.Contains(script, "@npd_list_") {
		t.Errorf("referenced a set that was never defined:\n%s", script)
	}
	if !strings.Contains(script, "ip saddr 10.0.0.1/32") {
		t.Errorf("lost the literal match:\n%s", script)
	}
}

// Only referenced lists are materialized — an unused list is elements the
// kernel would hold for nothing.
func TestUnreferencedListNotEmitted(t *testing.T) {
	script := planNFTBatch([]api.FirewallRule{{
		ID: "r1", Enabled: true, Backend: "nft",
		Table: "filter", Chain: "forward", Source: "10.0.0.1/32", Action: "accept",
	}}, []api.IPList{iranLike(50)})
	if strings.Contains(script, "npd_list_iran") {
		t.Errorf("emitted an unreferenced set:\n%s", script)
	}
}

// Every managed chain must exist even when it holds no rules, or a later
// `nft add rule` against it fails.
func TestAllManagedChainsDeclared(t *testing.T) {
	script := planNFTBatch([]api.FirewallRule{{
		ID: "r1", Enabled: true, Backend: "nft",
		Table: "filter", Chain: "input", Action: "accept",
	}}, nil)
	for _, ch := range nftManagedChains {
		if !strings.Contains(script, "chain "+ch.name+" {") {
			t.Errorf("chain %q not declared", ch.name)
		}
	}
}

// Repeated planning is byte-identical: a generated ruleset that reorders
// between runs is impossible to diff when something breaks.
func TestBatchIsDeterministic(t *testing.T) {
	lists := []api.IPList{iranLike(20), {ID: "l2", Name: "other", Entries: []string{"192.0.2.0/24"}}}
	rules := []api.FirewallRule{
		{ID: "a", Enabled: true, Backend: "nft", Table: "filter", Chain: "forward", DestList: "iran", Action: "accept"},
		{ID: "b", Enabled: true, Backend: "nft", Table: "filter", Chain: "forward", DestList: "other", Action: "drop"},
	}
	if planNFTBatch(rules, lists) != planNFTBatch(rules, lists) {
		t.Error("plan is not deterministic")
	}
}

func firstLines(s string, n int) string {
	parts := strings.SplitN(s, "\n", n+1)
	if len(parts) > n {
		parts = parts[:n]
	}
	return strings.Join(parts, "\n")
}

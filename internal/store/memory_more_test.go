package store

import (
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestFirewallCRUD(t *testing.T) {
	m := New()
	r, err := m.UpsertFirewall(api.FirewallRule{
		Table: "filter", Chain: "input", Action: "accept",
		Protocol: "tcp", Dport: "22", Enabled: true,
	})
	if err != nil || r.ID == "" {
		t.Fatal(err, r)
	}
	if len(m.ListFirewall()) != 1 {
		t.Fatal()
	}
	if err := m.DeleteFirewall(r.ID); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallValidation(t *testing.T) {
	m := New()
	if _, err := m.UpsertFirewall(api.FirewallRule{Table: "filter", Action: "accept"}); err == nil {
		t.Fatal("chain required")
	}
	if _, err := m.UpsertFirewall(api.FirewallRule{Table: "filter", Chain: "input"}); err == nil {
		t.Fatal("action required")
	}
	if _, err := m.UpsertFirewall(api.FirewallRule{Table: "bogus", Chain: "input", Action: "accept"}); err == nil {
		t.Fatal("table invalid")
	}
}

func TestTCUpsert(t *testing.T) {
	m := New()
	tc, err := m.UpsertTC(api.TCSpec{
		Device: "gre-lab", RateTxBps: 1e6, MatchKind: "src_cidr", MatchValue: "10.0.0.1/32", Enabled: true,
	})
	if err != nil || tc.ID == "" {
		t.Fatal(err, tc)
	}
	if _, err := m.UpsertTC(api.TCSpec{Device: "x", Enabled: true}); err == nil {
		t.Fatal("need rates")
	}
	if err := m.DeleteTC(tc.ID); err != nil {
		t.Fatal(err)
	}
}

func TestForwardAndLink(t *testing.T) {
	m := New()
	f, err := m.UpsertForward(api.ForwardSpec{Action: "accept", InIface: "wg0", OutIface: "ens18", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if f.ID == "" {
		t.Fatal()
	}
	up := true
	l, err := m.UpsertLink(api.LinkSpec{Name: "gre-lab", Up: &up, MTU: 1400, Enabled: true})
	if err != nil || l.ID == "" {
		t.Fatal(err)
	}
	if err := m.DeleteForward(f.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteLink(l.ID); err != nil {
		t.Fatal(err)
	}
}

func TestIPAddrAndRule(t *testing.T) {
	m := New()
	a, err := m.UpsertIPAddr(api.IPAddrSpec{Device: "lo", CIDR: "127.0.0.2/32", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := m.UpsertIPRule(api.IPRuleSpec{From: "10.0.0.1/32", Table: "100", Action: "lookup", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || r.ID == "" {
		t.Fatal()
	}
	if err := m.DeleteIPAddr(a.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteIPRule(r.ID); err != nil {
		t.Fatal(err)
	}
}

func TestReplacePoliciesAndLastApply(t *testing.T) {
	m := New()
	m.ReplacePolicies([]api.PolicyRule{
		{ID: "a", Name: "one", Priority: 2, Action: api.ActionAllow},
		{Name: "two", Priority: 1, Action: api.ActionDeny}, // auto id
	})
	list := m.ListPolicies()
	if len(list) != 2 {
		t.Fatal(len(list))
	}
	// sorted by priority
	if list[0].Priority > list[1].Priority {
		t.Fatal(list)
	}
	m.SetLastApply(api.ApplyResult{OK: true, Message: "ok"}, 7)
	res, at, gen := m.LastApply()
	if !res.OK || gen != 7 || at.IsZero() {
		t.Fatal(res, at, gen)
	}
}

func TestDeleteIPListByName(t *testing.T) {
	m := New()
	_, err := m.UpsertIPList(api.IPList{Name: "bye", Entries: []string{"1.1.1.1/32"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteIPList("bye"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.GetIPList("bye"); ok {
		t.Fatal("still there")
	}
}

// A desired-state push must replace the TC set, not merge into it.
//
// Every family except Policies was upsert-only, so netpolicyd accumulated
// every spec it had ever been sent and kept re-applying the dead ones. Live on
// sky-ams-1 that meant four TC specs where the control plane sent one: two for
// sessions that had ended and one naming an interface that does not exist, all
// failing on every reconcile and burying the real error.
func TestReplaceTCDropsStaleSpecs(t *testing.T) {
	m := New()
	if _, err := m.UpsertTC(api.TCSpec{
		ID: "tc-old", Device: "oc-oc-sky-in0", RateTxBps: 1000,
		MatchKind: "src_cidr", MatchValue: "10.98.1.41/32",
	}); err != nil {
		t.Fatal(err)
	}
	m.ReplaceTC([]api.TCSpec{{
		ID: "tc-new", Device: "oc-oc-sky-in0", RateTxBps: 2000,
		MatchKind: "src_cidr", MatchValue: "10.98.1.3/32",
	}})
	got := m.ListTC()
	if len(got) != 1 {
		t.Fatalf("got %d specs, want 1 — the stale spec survived the push", len(got))
	}
	if got[0].ID != "tc-new" {
		t.Errorf("kept %q, want tc-new", got[0].ID)
	}
}

func TestForcePruneWhenAssertedEmpty(t *testing.T) {
	m := New()
	if _, err := m.UpsertIPRule(api.IPRuleSpec{
		ID: "stale-bh", Enabled: true, Priority: 10500,
		From: "10.98.1.9/32", Action: "blackhole",
	}); err != nil {
		t.Fatal(err)
	}
	m.ReplaceIPRules([]api.IPRuleSpec{})
	if n := len(m.ListIPRules()); n != 0 {
		t.Fatalf("ReplaceIPRules([]) left %d rules — stale blackhole would be re-applied", n)
	}
	if _, err := m.UpsertFirewall(api.FirewallRule{
		ID: "stale-fw", Table: "filter", Chain: "forward", Action: "drop", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	m.ReplaceFirewall([]api.FirewallRule{})
	if n := len(m.ListFirewall()); n != 0 {
		t.Fatalf("ReplaceFirewall([]) left %d rules", n)
	}
}

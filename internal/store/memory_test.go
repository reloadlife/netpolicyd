package store

import (
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestPolicyCRUD(t *testing.T) {
	m := New()
	en := true
	p, err := m.CreatePolicy(api.PolicyCreateRequest{
		Name: "user4", Priority: 10, Enabled: &en,
		Subjects:    []api.Subject{{Kind: "cidr", Value: "10.77.0.4/32"}},
		Destination: api.Destination{Kind: "any", Value: "0.0.0.0/0"},
		Action:      api.ActionEgress, EgressName: "gre-lab",
		SourceCIDR: "10.77.0.4/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" || !p.Enabled {
		t.Fatalf("%+v", p)
	}
	list := m.ListPolicies()
	if len(list) != 1 {
		t.Fatal(len(list))
	}
	off := false
	if _, err := m.UpdatePolicy(p.ID, api.PolicyUpdateRequest{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	got, ok := m.GetPolicy(p.ID)
	if !ok || got.Enabled {
		t.Fatal(got)
	}
	if err := m.DeletePolicy(p.ID); err != nil {
		t.Fatal(err)
	}
	if len(m.ListPolicies()) != 0 {
		t.Fatal("not empty")
	}
}

func TestIPListUniqueNameAndAppend(t *testing.T) {
	m := New()
	l, err := m.UpsertIPList(api.IPList{Name: "clients", Entries: []string{"10.0.0.1", "10.0.0.1", " 10.0.0.2 "}})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 2 {
		t.Fatalf("dedupe entries: %v", l.Entries)
	}
	if _, err := m.UpsertIPList(api.IPList{Name: "clients", Entries: []string{"1.1.1.1"}}); err == nil {
		t.Fatal("expected duplicate name error")
	}
	l2, err := m.AppendIPListEntries(l.ID, []string{"10.0.0.3/32", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(l2.Entries) != 3 {
		t.Fatalf("%v", l2.Entries)
	}
	byName, ok := m.GetIPList("clients")
	if !ok || byName.ID != l.ID {
		t.Fatal(byName)
	}
}

func TestSnapshotIncludesListsAndSysctl(t *testing.T) {
	m := New()
	m.SetIPForward(true)
	_, _ = m.UpsertSysctl(api.SysctlSpec{Key: "net.ipv4.conf.all.rp_filter", Value: "2"})
	_, _ = m.UpsertIPList(api.IPList{Name: "x", Entries: []string{"1.2.3.4/32"}})
	s := m.Snapshot()
	if !s.IPForward || len(s.Sysctls) != 1 || len(s.IPLists) != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestNATAndRoute(t *testing.T) {
	m := New()
	n := m.UpsertNAT(api.NATSpec{Kind: "masquerade", SourceCIDR: "10.0.0.0/8", OutIface: "ens18", Enabled: true})
	if n.ID == "" {
		t.Fatal("id")
	}
	rt := m.UpsertRoute(api.RouteSpec{Table: "main", Dst: "default", Device: "ens18", Enabled: true})
	if rt.ID == "" {
		t.Fatal("route id")
	}
	if err := m.DeleteNAT(n.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteRoute(rt.ID); err != nil {
		t.Fatal(err)
	}
}

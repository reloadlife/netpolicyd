package tui

import (
	"strings"
	"testing"

	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

func TestEasyEgressList(t *testing.T) {
	m := rootModel{
		policies: []pkgapi.PolicyRule{
			{ID: "1", Action: pkgapi.ActionEgress, Name: "a"},
			{ID: "2", Action: pkgapi.ActionAllow, Name: "b"},
			{ID: "3", Action: pkgapi.ActionEgress, Name: "c"},
		},
	}
	list := m.easyEgressList()
	if len(list) != 2 {
		t.Fatalf("got %d", len(list))
	}
}

func TestEasyAccessList(t *testing.T) {
	m := rootModel{
		firewall: []pkgapi.FirewallRule{
			{ID: "1", Table: "filter", Action: "accept"},
			{ID: "2", Table: "nat", Action: "masquerade"},
			{ID: "3", Table: "filter", Action: "drop"},
			{ID: "4", Table: "filter", Action: "dnat"},
		},
	}
	list := m.easyAccessList()
	if len(list) != 2 {
		t.Fatalf("got %d want 2", len(list))
	}
}

func TestDefaultEasyMode(t *testing.T) {
	m := newRootModel(Config{})
	if !m.uiEasy {
		t.Fatal("expected easy by default")
	}
	if m.tab != easyHome {
		t.Fatalf("tab=%d", m.tab)
	}
	adv := false
	m2 := newRootModel(Config{EasyMode: &adv})
	if m2.uiEasy {
		t.Fatal("expected advanced")
	}
}

func TestToggleMode(t *testing.T) {
	m := newRootModel(Config{})
	if !m.uiEasy {
		t.Fatal()
	}
	m.setUIMode(false)
	if m.uiEasy || m.tab != tabStatus {
		t.Fatalf("easy=%v tab=%d", m.uiEasy, m.tab)
	}
	m.setUIMode(true)
	if !m.uiEasy || m.tab != easyHome {
		t.Fatalf("easy=%v tab=%d", m.uiEasy, m.tab)
	}
}

func TestSplitEasyPorts(t *testing.T) {
	cases := map[string][]string{
		"":           nil,
		"any":        nil,
		"22":         {"22"},
		"80,443":     {"80", "443"},
		"80 443":     {"80", "443"},
		"8000-8100":  {"8000-8100"},
		" 22, 80 , ": {"22", "80"},
	}
	for in, want := range cases {
		got := splitEasyPorts(in)
		if len(got) != len(want) {
			t.Fatalf("%q: got %v want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: got %v want %v", in, got, want)
			}
		}
	}
}

func TestNormalizeEasyIP(t *testing.T) {
	if got := normalizeEasyIP("10.0.0.1"); got != "10.0.0.1/32" {
		t.Fatal(got)
	}
	if got := normalizeEasyIP("10.0.0.0/8"); got != "10.0.0.0/8" {
		t.Fatal(got)
	}
	if got := normalizeEasyIP("any"); got != "" {
		t.Fatal(got)
	}
	if got := normalizeEasyIP("fd00::1"); got != "fd00::1/128" {
		t.Fatal(got)
	}
}

func TestEasyServicePreset(t *testing.T) {
	p, proto, ok := easyServicePreset("ssh (22/tcp)")
	if !ok || p != "22" || proto != "tcp" {
		t.Fatalf("%s %s %v", p, proto, ok)
	}
	p, proto, ok = easyServicePreset("https (443/tcp)")
	if !ok || p != "443" || proto != "tcp" {
		t.Fatalf("%s %s", p, proto)
	}
	_, _, ok = easyServicePreset("custom")
	if ok {
		t.Fatal("custom should not preset")
	}
}

func TestEasyAccessAutoName(t *testing.T) {
	n := easyAccessAutoName("block", "input", "1.2.3.4/32", "", []string{"22"}, "tcp")
	if !strings.Contains(n, "block") || !strings.Contains(n, "22") {
		t.Fatal(n)
	}
}

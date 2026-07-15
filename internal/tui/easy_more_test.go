package tui

import (
	"testing"

	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

func TestEasyListNames(t *testing.T) {
	m := rootModel{ipLists: []pkgapi.IPList{{Name: "clients"}, {Name: "blocked"}}}
	names := m.easyListNames()
	if len(names) != 3 || names[0] != "(none)" || names[1] != "clients" {
		t.Fatal(names)
	}
}

func TestSplitEasyListEntries(t *testing.T) {
	got := splitEasyListEntries("10.0.0.1 10.0.0.2\n#c\n10.0.0.3/32")
	if len(got) != 3 {
		t.Fatal(got)
	}
}

func TestEasyServicePresetsMore(t *testing.T) {
	cases := []struct {
		s, port, proto string
		ok             bool
	}{
		{"http (80/tcp)", "80", "tcp", true},
		{"dns (53/udp)", "53", "udp", true},
		{"rdp (3389/tcp)", "3389", "tcp", true},
		{"wireguard (51820/udp)", "51820", "udp", true},
		{"all traffic (any)", "", "any", true},
	}
	for _, c := range cases {
		p, pr, ok := easyServicePreset(c.s)
		if ok != c.ok || p != c.port || pr != c.proto {
			t.Fatalf("%s: got %q %q %v", c.s, p, pr, ok)
		}
	}
}

func TestSanitizeSysctlDev(t *testing.T) {
	if sanitizeSysctlDev("gre-lab") != "gre-lab" {
		t.Fatal()
	}
	if sanitizeSysctlDev("evil;rm") == "evil;rm" {
		t.Fatal("should strip")
	}
}

func TestFormEmptyUpdate(t *testing.T) {
	f := formModel{}
	f, _ = f.Update(nil)
	if f.focus != 0 {
		// just shouldn't panic
	}
}

func TestEasyRowCount(t *testing.T) {
	m := rootModel{
		uiEasy: true, tab: easyLists,
		ipLists: []pkgapi.IPList{{Name: "a"}, {Name: "b"}},
	}
	if m.easyRowCount() != 2 {
		t.Fatal(m.easyRowCount())
	}
	m.tab = easyAccess
	m.firewall = []pkgapi.FirewallRule{
		{Table: "filter", Action: "accept"},
		{Table: "nat", Action: "masquerade"},
	}
	if m.easyRowCount() != 1 {
		t.Fatal(m.easyRowCount())
	}
}

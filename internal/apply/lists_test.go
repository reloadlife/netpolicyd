package apply

import (
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestExpandFirewallLists(t *testing.T) {
	lists := []api.IPList{{
		ID: "list-1", Name: "clients",
		Entries: []string{"10.77.0.1", "10.77.0.2/32"},
	}}
	rules := []api.FirewallRule{{
		ID: "fw", Enabled: true, Table: "filter", Chain: "forward",
		SourceList: "clients", Action: "accept", OutIface: "gre-lab",
	}}
	out := expandFirewallLists(rules, lists)
	if len(out) != 2 {
		t.Fatalf("got %d", len(out))
	}
	if out[0].Source != "10.77.0.1/32" {
		t.Fatalf("bare IP normalize: %q", out[0].Source)
	}
	if out[1].Source != "10.77.0.2/32" {
		t.Fatalf("%q", out[1].Source)
	}
}

func TestExpandNATLists(t *testing.T) {
	lists := []api.IPList{{Name: "nets", Entries: []string{"10.0.0.0/8", "192.168.0.0/16"}}}
	nats := []api.NATSpec{{
		ID: "n", Enabled: true, Kind: "masquerade", SourceList: "nets", OutIface: "ens18",
	}}
	out := expandNATLists(nats, lists)
	if len(out) != 2 {
		t.Fatalf("%d", len(out))
	}
	joined := out[0].SourceCIDR + "," + out[1].SourceCIDR
	if !strings.Contains(joined, "10.0.0.0/8") {
		t.Fatal(joined)
	}
}

func TestPlanFirewallWithList(t *testing.T) {
	cmds := planFirewall([]api.FirewallRule{{
		ID: "x", Enabled: true, Backend: "nft", Table: "filter", Chain: "input",
		SourceList: "bad", Action: "drop",
	}}, nil, nil, []api.IPList{{Name: "bad", Entries: []string{"1.2.3.4/32", "5.6.7.8/32"}}})
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "1.2.3.4/32") || !strings.Contains(joined, "5.6.7.8/32") {
		t.Fatal(joined)
	}
}

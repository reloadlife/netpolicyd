package apply

import (
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestPlanFirewallNFT(t *testing.T) {
	cmds := planFirewall([]api.FirewallRule{{
		ID: "fw1", Enabled: true, Priority: 10, Backend: "nft",
		Table: "filter", Chain: "input", Protocol: "tcp", Dport: "22",
		Action: "accept", Name: "ssh",
	}}, nil, nil, nil)
	joined := strings.Join(cmds, "\n")
	// The managed table is replaced wholesale in one transaction, so the base
	// is the table definition inside the batch rather than a separate command.
	if !strings.Contains(joined, "delete table inet netpolicyd") ||
		!strings.Contains(joined, "table inet netpolicyd {") {
		t.Fatalf("missing nft table replace:\n%s", joined)
	}
	if !strings.Contains(joined, "tcp dport 22 accept") {
		t.Fatalf("missing accept rule:\n%s", joined)
	}
}

// The iptables backend is gone; nft is the only one. A rule that still asks
// for Backend "iptables" must be emitted as nft rather than silently dropped —
// a firewall rule that vanishes is worse than one expressed in another syntax.
func TestIptablesBackedRuleStillEmittedAsNFT(t *testing.T) {
	cmds := planFirewall([]api.FirewallRule{{
		ID: "fw2", Enabled: true, Backend: "iptables",
		Table: "filter", Chain: "forward", Source: "10.0.0.0/8",
		OutIface: "ens18", Action: "accept",
	}}, nil, nil, nil)
	joined := strings.Join(cmds, "\n")
	if strings.Contains(joined, "NETPOLICYD_FWD") || strings.Contains(joined, "-A ") {
		t.Fatalf("still emitting iptables:\n%s", joined)
	}
	if !strings.Contains(joined, "ip saddr 10.0.0.0/8") {
		t.Fatalf("rule was dropped instead of translated:\n%s", joined)
	}
}

func TestPlanFirewallNATForward(t *testing.T) {
	cmds := planFirewall(nil,
		[]api.NATSpec{{ID: "n1", Enabled: true, Kind: "masquerade", SourceCIDR: "10.77.0.0/24", OutIface: "gre-lab"}},
		[]api.ForwardSpec{{ID: "f1", Enabled: true, InIface: "wg0", OutIface: "ens18", Action: "accept"}},
		nil,
	)
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "masquerade") {
		t.Fatalf("missing masq:\n%s", joined)
	}
	if !strings.Contains(joined, "forward") || !strings.Contains(joined, "accept") {
		t.Fatalf("missing forward accept:\n%s", joined)
	}
}

func TestPlanIPAddr(t *testing.T) {
	cmds := planIPAddrs([]api.IPAddrSpec{{
		ID: "a1", Enabled: true, Device: "gre-lab", CIDR: "10.77.0.1/24",
	}})
	if len(cmds) != 1 || !strings.Contains(cmds[0], "ip addr replace 10.77.0.1/24 dev gre-lab") {
		t.Fatalf("%v", cmds)
	}
}

func TestPlanIPRule(t *testing.T) {
	cmds := planIPRules([]api.IPRuleSpec{{
		ID: "r1", Enabled: true, Priority: 100, From: "10.77.0.4/32", Table: "100", Action: "lookup",
	}})
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip rule add from 10.77.0.4/32") {
		t.Fatalf("%s", joined)
	}
	if !strings.Contains(joined, "lookup 100") {
		t.Fatalf("%s", joined)
	}
}

func TestApplyStatePlan(t *testing.T) {
	r := NewRunner(true)
	cmds := r.Plan(api.ApplyState{
		IPForward: true,
		Firewall: []api.FirewallRule{{
			ID: "x", Enabled: true, Backend: "nft", Table: "filter", Chain: "input",
			Protocol: "tcp", Dport: "22", Action: "accept",
		}},
		IPAddrs: []api.IPAddrSpec{{ID: "a", Enabled: true, Device: "lo", CIDR: "127.0.0.2/32"}},
	})
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip_forward") {
		t.Fatal("sysctl")
	}
	if !strings.Contains(joined, "ip addr replace") {
		t.Fatal("addr")
	}
	if !strings.Contains(joined, "dport 22") {
		t.Fatal("fw")
	}
}

// Rules must not accumulate across applies. The mechanism is an atomic table
// replace (declare empty, delete, redefine) in a single `nft -f` transaction,
// which supersedes the old per-chain flush.
func TestPlanFirewallReplacesTableAtomically(t *testing.T) {
	cmds := planFirewall([]api.FirewallRule{{
		ID: "fw1", Enabled: true, Backend: "nft",
		Table: "nat", Chain: "postrouting", Source: "10.77.0.4/32",
		OutIface: "gre-lab", Action: "masquerade",
	}}, nil, nil, nil)
	joined := strings.Join(cmds, "\n")
	di := strings.Index(joined, "delete table inet netpolicyd")
	ai := strings.Index(joined, "masquerade")
	if di < 0 || ai < 0 || di > ai {
		t.Fatalf("delete must precede the rules it replaces: delete=%d add=%d\n%s", di, ai, joined)
	}
	// One transaction, not one exec per rule — that per-rule loop was a
	// measured fork storm on thr-respina (1054 forks/10s).
	nftCmds := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, "nft ") {
			nftCmds++
		}
	}
	if nftCmds != 1 {
		t.Fatalf("expected exactly 1 nft command, got %d:\n%s", nftCmds, joined)
	}
}

func TestDedupeNATAndRules(t *testing.T) {
	nat := dedupeNAT([]api.NATSpec{
		{ID: "a", Enabled: true, Kind: "masquerade", SourceCIDR: "10.77.0.4/32", OutIface: "gre-lab"},
		{ID: "b", Enabled: true, Kind: "masquerade", SourceCIDR: "10.77.0.4/32", OutIface: "gre-lab"},
	})
	if len(nat) != 1 {
		t.Fatalf("nat dedupe got %d", len(nat))
	}
	cmds := planFirewall(nil, []api.NATSpec{
		{ID: "a", Enabled: true, Kind: "masquerade", SourceCIDR: "10.77.0.4/32", OutIface: "gre-lab", Comment: "egress-x"},
		{ID: "b", Enabled: true, Kind: "masquerade", SourceCIDR: "10.77.0.4/32", OutIface: "gre-lab", Comment: "egress-x"},
	}, nil, nil)
	n := 0
	for _, c := range cmds {
		if strings.Contains(c, "masquerade") && strings.Contains(c, "10.77.0.4") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected 1 masq cmd, got %d\n%s", n, strings.Join(cmds, "\n"))
	}
}

// Nothing may touch iptables any more, including the built-in chains the old
// backend was careful to avoid.
func TestNoIptablesCommandsEmitted(t *testing.T) {
	cmds := planFirewall([]api.FirewallRule{{
		ID: "m", Enabled: true, Backend: "iptables",
		Table: "nat", Chain: "postrouting", Action: "masquerade",
		Source: "10.0.0.0/8", OutIface: "ens18",
	}}, nil, nil, nil)
	for _, c := range cmds {
		if strings.HasPrefix(c, "iptables") || strings.Contains(c, "NETPOLICYD_") {
			t.Errorf("iptables command survived: %s", c)
		}
	}
}

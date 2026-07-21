package apply

import (
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestPlanIPAddrs(t *testing.T) {
	cmds := planIPAddrs([]api.IPAddrSpec{
		{Enabled: false, Device: "eth0", CIDR: "1.1.1.1/32"},
		{Enabled: true, Device: "gre-lab", CIDR: "10.0.0.1/24", Scope: "global"},
		{Enabled: true, Device: "wg0", CIDR: "fd00::1/64", Peer: "fd00::2"},
	})
	if len(cmds) != 2 {
		t.Fatalf("%v", cmds)
	}
	if !strings.Contains(cmds[0], "ip addr replace 10.0.0.1/24 dev gre-lab") {
		t.Fatal(cmds[0])
	}
	if !strings.Contains(cmds[1], "peer fd00::2") {
		t.Fatal(cmds[1])
	}
}

func TestPlanIPRules(t *testing.T) {
	cmds := planIPRules([]api.IPRuleSpec{
		{Enabled: true, Priority: 100, From: "10.0.0.1/32", Table: "100", Action: "lookup"},
		{Enabled: true, Priority: 200, Action: "blackhole", From: "1.2.3.4/32"},
		{Enabled: false, Table: "main"},
	})
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "ip rule add from 10.0.0.1/32") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "blackhole") {
		t.Fatal(joined)
	}
	// del then add
	if !strings.Contains(joined, "ip rule del") {
		t.Fatal("expected del for idempotency")
	}
}

func TestPlanLinks(t *testing.T) {
	up := true
	down := false
	cmds := planLinks([]api.LinkSpec{
		{Enabled: true, Name: "gre-lab", Up: &up, MTU: 1400},
		{Enabled: true, Name: "wg0", Up: &down},
		{Enabled: false, Name: "x"},
	})
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "mtu 1400") || !strings.Contains(joined, "gre-lab up") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "wg0 down") {
		t.Fatal(joined)
	}
}

func TestNormalizeCIDR(t *testing.T) {
	if normalizeCIDR("10.0.0.1") != "10.0.0.1/32" {
		t.Fatal(normalizeCIDR("10.0.0.1"))
	}
	if normalizeCIDR("10.0.0.0/8") != "10.0.0.0/8" {
		t.Fatal()
	}
	if normalizeCIDR("fd00::1") != "fd00::1/128" {
		t.Fatal(normalizeCIDR("fd00::1"))
	}
}

// An explicit IPRuleSpec inside the managed priority band must survive the
// prune. keepIPRule was built only from Policies, so the plan added the
// fail-closed egress guard (control plane emits it at priority 10500) and then
// deleted it again in the same run — the guard has never existed on a live
// node. That matters because an `ip rule` pointing at an EMPTY table does not
// fail: the lookup falls through to main, i.e. the node's own WAN. Observed on
// sky-ams-1, where table 883 holds no routes and the guard was absent.
func TestExplicitIPRuleSurvivesPrune(t *testing.T) {
	r := &Runner{Backend: BackendMock, TableBase: 100}
	cmds := r.Plan(api.ApplyState{
		IPRules: []api.IPRuleSpec{
			{Enabled: true, Priority: 10500, From: "10.98.1.2/32", Action: "blackhole"},
		},
		Policies: []api.PolicyRule{
			{Enabled: true, Action: api.ActionEgress, EgressName: "resid-zur",
				SourceCIDR: "10.98.1.3/32", Priority: 5},
		},
	})
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "blackhole") {
		t.Fatal("guard was never planned")
	}
	prune := ""
	for _, c := range cmds {
		if strings.Contains(c, "npd_keep=") {
			prune = c
		}
	}
	if prune == "" {
		t.Fatal("no prune command planned")
	}
	if !strings.Contains(prune, "10.98.1.2/32@10500") {
		t.Errorf("prune keep-list omits the explicit guard, so it is deleted right after being added:\n%s", prune)
	}
}

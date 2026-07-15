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

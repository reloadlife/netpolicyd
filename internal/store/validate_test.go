package store

import (
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// Trust-boundary regression: fields that reach `sh -c` must reject shell
// metacharacters, whitespace, and argument injection — while accepting the
// legitimate IP/CIDR/iface/port/sysctl values the daemon actually uses.
func TestValidationRejectsInjection(t *testing.T) {
	m := New()

	// sysctl command injection
	if _, err := m.UpsertSysctl(api.SysctlSpec{Key: "net.ipv4.ip_forward", Value: "1; touch /tmp/pwn"}); err == nil {
		t.Fatal("sysctl value injection accepted")
	}
	if _, err := m.UpsertSysctl(api.SysctlSpec{Key: "net.ipv4.ip_forward$(id)", Value: "1"}); err == nil {
		t.Fatal("sysctl key injection accepted")
	}
	// route dst injection
	if _, err := m.UpsertRoute(api.RouteSpec{Dst: "default; touch /tmp/pwn", Table: "main"}); err == nil {
		t.Fatal("route dst injection accepted")
	}
	// argument injection with NO shell metachars (space → extra tc/ip/nft args)
	if _, err := m.UpsertFirewall(api.FirewallRule{Chain: "forward", Action: "drop", OutIface: "eth0 -j ACCEPT"}); err == nil {
		t.Fatal("iface argument injection accepted")
	}
	if _, err := m.UpsertTC(api.TCSpec{Device: "eth0`reboot`", RateTxBps: 1000}); err == nil {
		t.Fatal("tc device injection accepted")
	}
	// PATCH must not bypass validation
	p, err := m.CreatePolicy(api.PolicyCreateRequest{
		Name: "ok", Action: api.ActionAllow,
		Subjects: []api.Subject{{Kind: "cidr", Value: "10.0.0.0/8"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	bad := "eth0; rm -rf /"
	if _, err := m.UpdatePolicy(p.ID, api.PolicyUpdateRequest{EgressName: &bad}); err == nil {
		t.Fatal("PATCH egress injection accepted (validation bypass)")
	}
}

// Regression: validation must not reject symbolic sysctl values. `fq` and `bbr`
// are the two most common sysctls on a shaping/gateway box and both worked
// before validation existed; an integer-only rule was a real regression.
func TestValidationAcceptsSymbolicSysctls(t *testing.T) {
	m := New()
	for _, c := range []struct{ k, v string }{
		{"net.core.default_qdisc", "fq"},
		{"net.ipv4.tcp_congestion_control", "bbr"},
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
	} {
		if _, err := m.UpsertSysctl(api.SysctlSpec{Key: c.k, Value: c.v}); err != nil {
			t.Errorf("legit sysctl %s=%s rejected: %v", c.k, c.v, err)
		}
	}
	// A value with a space or metachar still reaches `sh -c` unquoted — reject.
	for _, bad := range []string{"1; touch /tmp/pwn", "4096 87380 6291456", "fq$(id)"} {
		if _, err := m.UpsertSysctl(api.SysctlSpec{Key: "net.core.default_qdisc", Value: bad}); err == nil {
			t.Errorf("unsafe sysctl value accepted: %q", bad)
		}
	}
}

func TestValidationAcceptsLegit(t *testing.T) {
	m := New()
	cases := []func() error{
		func() error { _, e := m.UpsertSysctl(api.SysctlSpec{Key: "net.ipv4.ip_forward", Value: "1"}); return e },
		func() error {
			_, e := m.UpsertRoute(api.RouteSpec{Dst: "10.0.0.0/8", Gateway: "192.168.1.1", Device: "ens18", Table: "main"})
			return e
		},
		func() error {
			_, e := m.UpsertFirewall(api.FirewallRule{Chain: "forward", Action: "drop", Source: "10.0.0.0/8", Dport: "80", Protocol: "tcp"})
			return e
		},
		func() error {
			_, e := m.UpsertNAT(api.NATSpec{Kind: "masquerade", SourceCIDR: "10.0.0.0/8", OutIface: "ens18"})
			return e
		},
		func() error {
			_, e := m.UpsertTC(api.TCSpec{Device: "wg-lab", RateTxBps: 1_000_000, MatchKind: "src_cidr", MatchValue: "10.77.0.4/32,10.77.0.5/32"})
			return e
		},
		func() error { _, e := m.UpsertIPAddr(api.IPAddrSpec{Device: "gre-lab", CIDR: "10.77.0.1/24"}); return e },
	}
	for i, c := range cases {
		if err := c(); err != nil {
			t.Fatalf("legit input %d rejected: %v", i, err)
		}
	}
}

// Idempotency: the tc plan must emit explicit filter handles so repeated
// apply replaces rather than accumulates. (Regression for the u32 add-vs-replace bug.)
func TestValidationDport(t *testing.T) {
	m := New()
	// port range and list are legit; a space or metachar is not
	if _, err := m.UpsertFirewall(api.FirewallRule{Chain: "forward", Action: "accept", Dport: "1000:2000"}); err != nil {
		t.Fatalf("port range rejected: %v", err)
	}
	if _, err := m.UpsertFirewall(api.FirewallRule{Chain: "forward", Action: "accept", Dport: "80,443"}); err != nil {
		t.Fatalf("port list rejected: %v", err)
	}
	if _, err := m.UpsertFirewall(api.FirewallRule{Chain: "forward", Action: "accept", Dport: "80 -j DROP"}); err == nil {
		t.Fatal("port arg injection accepted")
	}
}

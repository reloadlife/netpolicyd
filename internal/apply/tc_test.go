package apply

import (
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestParseRateBitPS(t *testing.T) {
	cases := map[string]int64{
		"":         0,
		"0":        0,
		"50mbit":   50_000_000,
		"50M":      50_000_000,
		"1gbit":    1_000_000_000,
		"500kbit":  500_000,
		"1000000":  1_000_000,
		"1.5mbit":  1_500_000,
		"unlimited": 0,
	}
	for in, want := range cases {
		got, err := ParseRateBitPS(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Fatalf("%q: got %d want %d", in, got, want)
		}
	}
}

func TestFormatTCRate(t *testing.T) {
	if formatTCRate(1_000_000) != "1mbit" {
		t.Fatal(formatTCRate(1_000_000))
	}
	if formatTCRate(500_000) != "500kbit" {
		t.Fatal(formatTCRate(500_000))
	}
}

func TestPlanTC(t *testing.T) {
	rules := []api.TCSpec{{
		ID: "tc-aaaa", Name: "user4", Enabled: true,
		Device: "gre-lab", RateTxBps: 50_000_000, RateRxBps: 20_000_000,
		MatchKind: "src_cidr", MatchValue: "10.77.0.4/32",
	}}
	cmds := planTC(rules)
	if len(cmds) == 0 {
		t.Fatal("expected commands")
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"tc qdisc replace dev gre-lab root handle 1: htb",
		"htb rate 50mbit",
		"match ip src 10.77.0.4/32",
		"action police rate 20mbit",
		"ingress",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestPlanTCDisabledSkipped(t *testing.T) {
	cmds := planTC([]api.TCSpec{{
		ID: "x", Enabled: false, Device: "eth0", RateTxBps: 1e6, MatchKind: "any",
	}})
	if len(cmds) != 0 {
		t.Fatalf("got %v", cmds)
	}
}

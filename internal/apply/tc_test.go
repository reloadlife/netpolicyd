package apply

import (
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestParseRateBitPS(t *testing.T) {
	cases := map[string]int64{
		"":          0,
		"0":         0,
		"50mbit":    50_000_000,
		"50M":       50_000_000,
		"1gbit":     1_000_000_000,
		"500kbit":   500_000,
		"1000000":   1_000_000,
		"1.5mbit":   1_500_000,
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
		// root HTB is added only if missing (replace is not supported with children)
		"htb default 1",
		"htb rate 50mbit",
		"match ip src 10.77.0.4/32",
		"action police index", // shared police meter (account pool)
		"rate 20mbit",
		"ingress",
		// u32 filters must not use illegal "handle N:" form
		"u32 match ip src",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "handle 1e3:") && strings.Contains(joined, "u32 match") {
		// leaf sfq may use handle 1e3:; filters must not.
	}
	// Ensure filters do not use the illegal incomplete handle form "handle NNN:"
	for _, line := range cmds {
		if strings.Contains(line, "u32 match") && strings.Contains(line, "handle ") {
			// allow only full fw handles or nothing; reject "handle 123:"
			if strings.Contains(line, "handle ") && strings.Contains(line, ": u32") {
				t.Fatalf("illegal u32 handle form in: %s", line)
			}
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

func TestPlanTCMultiCIDRSharedPool(t *testing.T) {
	rules := []api.TCSpec{{
		ID: "tc-user-u1-wg0", Name: "speed-alice", Enabled: true,
		Device: "wg0", RateTxBps: 128_000_000, RateRxBps: 128_000_000,
		MatchKind: "src_cidr", MatchValue: "100.67.80.2/32,100.67.80.3/32,100.67.80.4/32",
	}}
	cmds := planTC(rules)
	joined := strings.Join(cmds, "\n")
	// One HTB class, three src filters → same flowid
	if strings.Count(joined, "htb rate 128mbit") != 1 {
		t.Fatalf("want one shared HTB class:\n%s", joined)
	}
	for _, ip := range []string{"100.67.80.2/32", "100.67.80.3/32", "100.67.80.4/32"} {
		if !strings.Contains(joined, "match ip src "+ip) {
			t.Fatalf("missing filter for %s in:\n%s", ip, joined)
		}
	}
	// All ingress filters share one police index
	if strings.Count(joined, "action police index") != 3 {
		t.Fatalf("want 3 police filters with shared index:\n%s", joined)
	}
	// Extract index — all should match
	idx := ""
	for _, line := range cmds {
		if !strings.Contains(line, "action police index") {
			continue
		}
		// ... action police index N rate ...
		parts := strings.Split(line, "action police index ")
		if len(parts) < 2 {
			continue
		}
		n := strings.Fields(parts[1])[0]
		if idx == "" {
			idx = n
		} else if n != idx {
			t.Fatalf("police index mismatch %s vs %s", idx, n)
		}
	}
	if idx == "" {
		t.Fatal("no police index")
	}
}

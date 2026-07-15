package apply

import (
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func TestAutoMasqSkippedWhenExplicitNATExists(t *testing.T) {
	r := NewRunner(true)
	cmds := r.Plan(api.ApplyState{
		IPForward: true,
		Policies: []api.PolicyRule{{
			ID: "pol-1", Name: "user4-via-gre-lab", Enabled: true,
			Action: api.ActionEgress, EgressName: "gre-lab",
			SourceCIDR: "10.77.0.4/32",
			Subjects:   []api.Subject{{Kind: "cidr", Value: "10.77.0.4/32"}},
		}},
		NAT: []api.NATSpec{{
			ID: "nat-1", Enabled: true, Kind: "masquerade",
			SourceCIDR: "10.77.0.4/32", OutIface: "gre-lab",
			Comment: "easy:return",
		}},
	})
	n := 0
	for _, c := range cmds {
		if strings.Contains(c, "masquerade") && strings.Contains(c, "10.77.0.4") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want 1 masq, got %d\n%s", n, strings.Join(cmds, "\n"))
	}
}

func TestRepeatedPlanSingleMasqFingerprint(t *testing.T) {
	r := NewRunner(true)
	st := api.ApplyState{
		Policies: []api.PolicyRule{{
			ID: "pol-1", Name: "user4-via-gre-lab", Enabled: true,
			Action: api.ActionEgress, EgressName: "gre-lab",
			SourceCIDR: "10.77.0.4/32",
			Subjects:   []api.Subject{{Kind: "cidr", Value: "10.77.0.4/32"}},
		}},
	}
	a := r.Plan(st)
	b := r.Plan(st)
	// plan is deterministic and contains flush + one masq
	countMasq := func(cmds []string) int {
		n := 0
		for _, c := range cmds {
			if strings.Contains(c, "masquerade") && strings.Contains(c, "10.77.0.4") {
				n++
			}
		}
		return n
	}
	if countMasq(a) != 1 || countMasq(b) != 1 {
		t.Fatalf("a=%d b=%d", countMasq(a), countMasq(b))
	}
	if !strings.Contains(strings.Join(a, "\n"), "flush chain inet netpolicyd postrouting") {
		t.Fatal("missing flush")
	}
}

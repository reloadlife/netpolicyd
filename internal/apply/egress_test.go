package apply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

func egressState() api.ApplyState {
	return api.ApplyState{
		Policies: []api.PolicyRule{{
			ID: "device-egress-dev-1", Name: "device-egress:iPhone→resid-chi",
			Enabled: true, Priority: 5, Action: api.ActionEgress,
			EgressName: "resid-chi", SourceCIDR: "100.67.80.15/32",
		}},
	}
}

// An egress policy must produce the forward accept, not just the route.
// Regression: 2026-07-19, where the route was correct and every packet died at
// the forward hook because the egress was not on a hand-maintained list.
func TestEgressPolicyEmitsForwardAccept(t *testing.T) {
	cmds := (&Runner{Backend: BackendMock, TableBase: 100}).Plan(egressState())
	joined := strings.Join(cmds, "\n")

	for _, want := range []string{
		`ip rule add from 100.67.80.15/32 table 100 priority 10005`,
		`ip saddr 100.67.80.15/32 accept`, // out via the egress
		`ip daddr 100.67.80.15/32 accept`, // return from the egress
		`oifname "resid-chi"`,
		`iifname "resid-chi"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan missing %q\n--- plan ---\n%s", want, joined)
		}
	}
}

// Every egress in the policy set gets accepts — adding a tunnel must not
// require editing anything else.
func TestEveryEgressGetsForwardAccept(t *testing.T) {
	s := api.ApplyState{}
	for i, eg := range []string{"zur0", "de0", "resid-chi", "resid-zur"} {
		s.Policies = append(s.Policies, api.PolicyRule{
			ID: "p" + eg, Enabled: true, Priority: i, Action: api.ActionEgress,
			EgressName: eg, SourceCIDR: "10.0.0.1/32",
		})
	}
	joined := strings.Join((&Runner{Backend: BackendMock, TableBase: 100}).Plan(s), "\n")
	for _, eg := range []string{"zur0", "de0", "resid-chi", "resid-zur"} {
		if !strings.Contains(joined, `oifname "`+eg+`" ip saddr 10.0.0.1/32 accept`) {
			t.Errorf("no forward accept for egress %q", eg)
		}
	}
}

func TestPruneIPRulesKeepList(t *testing.T) {
	got := pruneIPRules(map[string]bool{ipRuleKey("10.0.0.1", 10005): true})
	if !strings.Contains(got, "10.0.0.1/32@10005") {
		t.Errorf("keep-list missing normalized entry: %s", got)
	}
	// Must stay inside netpolicyd's own priority band.
	if !strings.Contains(got, "10000") || !strings.Contains(got, "10999") {
		t.Errorf("prune not bounded to managed band: %s", got)
	}
}

// The prune is a shell loop against live host state, so exercise it for real
// against a stub `ip`: stale rules go, desired rules and out-of-band rules stay.
func TestPruneIPRulesDeletesOnlyStaleInBand(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "deleted.log")

	// Stub `ip`, emitting what the real one emits. Critically, `ip rule show`
	// prints a host selector WITHOUT its prefix length — "from 10.0.0.1", never
	// "from 10.0.0.1/32". An earlier version of this stub printed "/32", which
	// no real host produces; the test passed while the prune deleted every
	// managed rule on thr-respina because the keep-list is normalized and so
	// never matched.
	stub := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-o\" ]; then\n" +
		"  echo '0:\tfrom all lookup local'\n" +
		"  echo '10005:\tfrom 100.67.80.15 lookup netpolicyd-resid-chi'\n" + // desired
		"  echo '10005:\tfrom 100.67.84.4 lookup netpolicyd-zur0'\n" + // stale
		"  echo '10005:\tfrom 10.98.2.3 lookup netpolicyd-resid-zur'\n" + // stale
		"  echo '10005:\tfrom 10.0.0.0/24 lookup netpolicyd-de0'\n" + // desired, real prefix
		"  echo '32766:\tfrom all lookup main'\n" + // out of band, must survive
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"rule\" ] && [ \"$2\" = \"del\" ]; then echo \"$4\" >> " + log + "; fi\n" +
		"exit 0\n"
	ipPath := filepath.Join(dir, "ip")
	if err := os.WriteFile(ipPath, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", "-c", pruneIPRules(map[string]bool{
		ipRuleKey("100.67.80.15/32", 10005): true,
		ipRuleKey("10.0.0.0/24", 10005):     true,
	}))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("prune failed: %v\n%s", err, out)
	}

	raw, _ := os.ReadFile(log)
	deleted := strings.Fields(string(raw))
	// Deletes pass the selector back exactly as `ip rule show` gave it.
	want := map[string]bool{"100.67.84.4": true, "10.98.2.3": true}
	if len(deleted) != len(want) {
		t.Fatalf("deleted %v, want exactly %v", deleted, want)
	}
	for _, d := range deleted {
		if !want[d] {
			t.Errorf("deleted %q which should have been kept", d)
		}
	}
}

func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("shellQuote(%q) = %s", "a'b", got)
	}
}

// An empty desired state must not prune. After a restart the control plane has
// not pushed yet, and "I do not know what should exist" is not "delete
// everything" — that distinction cost all 17 devices on thr-respina.
func TestNoPruneWhenDesiredIsEmpty(t *testing.T) {
	cmds := (&Runner{Backend: BackendMock, TableBase: 100}).Plan(api.ApplyState{})
	for _, c := range cmds {
		if strings.Contains(c, "npd_keep") {
			t.Fatalf("emitted a prune with no desired policies:\n%s", c)
		}
	}
}

// Table ids must not depend on policy order. When they drifted, `ip rule del`
// stopped matching, rules accumulated without bound (17 -> 32 -> 37 across two
// reconciles on thr-respina), and one VIP ended up with rules for four
// different egresses at once — silently exiting through an unselected tunnel.
func TestEgressTableIDsAreOrderIndependent(t *testing.T) {
	mk := func(names ...string) api.ApplyState {
		s := api.ApplyState{}
		for i, n := range names {
			s.Policies = append(s.Policies, api.PolicyRule{
				ID: "p" + n, Enabled: true, Priority: 5, Action: api.ActionEgress,
				EgressName: n, SourceCIDR: fmt.Sprintf("10.0.0.%d/32", i+1),
			})
		}
		return s
	}
	r := &Runner{Backend: BackendMock, TableBase: 100}

	tableFor := func(cmds []string, egress string) string {
		for _, c := range cmds {
			if strings.HasPrefix(c, "ip route replace default dev "+egress+" table ") {
				return c[strings.LastIndex(c, " ")+1:]
			}
		}
		return ""
	}

	a := r.Plan(mk("zur0", "de0", "resid-chi"))
	b := r.Plan(mk("resid-chi", "zur0", "de0"))
	for _, eg := range []string{"zur0", "de0", "resid-chi"} {
		ta, tb := tableFor(a, eg), tableFor(b, eg)
		if ta == "" || ta != tb {
			t.Errorf("egress %q got table %q in one order and %q in another", eg, ta, tb)
		}
	}
}

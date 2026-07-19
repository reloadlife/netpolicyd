package apply

import (
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

	// Stub `ip`: prints a fixed rule table, appends any delete to the log.
	stub := "#!/bin/sh\n" +
		"if [ \"$1\" = \"-o\" ]; then\n" +
		"  echo '0:\tfrom all lookup local'\n" +
		"  echo '10005:\tfrom 100.67.80.15/32 lookup netpolicyd-resid-chi'\n" + // desired
		"  echo '10005:\tfrom 100.67.84.4/32 lookup netpolicyd-zur0'\n" + // stale
		"  echo '10005:\tfrom 10.98.2.3/32 lookup netpolicyd-resid-zur'\n" + // stale
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
	}))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("prune failed: %v\n%s", err, out)
	}

	raw, _ := os.ReadFile(log)
	deleted := strings.Fields(string(raw))
	want := map[string]bool{"100.67.84.4/32": true, "10.98.2.3/32": true}
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

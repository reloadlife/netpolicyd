package apply

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// An egress must keep its table id when the set of selected egresses changes.
// Sorting alone was not enough: the set only holds egresses some device
// currently selects, so one device switching tunnels reshuffled every id below
// it and orphaned every existing rule — leaving one VIP with rules for two
// different egresses at once.
func TestEgressTableIDsSurviveSetChanges(t *testing.T) {
	dir := t.TempDir()
	rt := filepath.Join(dir, "rt_tables")
	if err := os.WriteFile(rt, []byte(
		"# reserved\n255\tlocal\n100\tnetpolicyd-bulg0\n101\tnetpolicyd-de0\n103\tnetpolicyd-zur0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := rtTablesPath
	rtTablesPath = rt
	defer func() { rtTablesPath = old }()

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

	// zur0 is registered as 103 and must stay 103 no matter what else appears.
	for _, set := range [][]string{
		{"zur0"},
		{"bulg0", "de0", "zur0"},
		{"de0", "ist0", "resid-chi", "resid-zur", "zur0"}, // new names appear
	} {
		if got := tableFor(r.Plan(mk(set...)), "zur0"); got != "103" {
			t.Errorf("zur0 got table %q with set %v, want 103 from rt_tables", got, set)
		}
	}
	// A brand-new egress must not steal an id already registered.
	got := tableFor(r.Plan(mk("ist0", "zur0")), "ist0")
	for _, taken := range []string{"100", "101", "103"} {
		if got == taken {
			t.Errorf("new egress ist0 took already-registered id %s", got)
		}
	}
}

// Switching a device's egress must remove the old rule, not add a second one
// beside it. Deleting by (selector, table) only matched a rule already pointing
// at the new table, so the previous rule survived at the same priority and won
// on first match — the device kept using its old tunnel while the database,
// the policy and the UI all said it had moved.
func TestEgressSwitchDeletesOldRuleBySelectorAndPriority(t *testing.T) {
	mk := func(egress string) api.ApplyState {
		return api.ApplyState{Policies: []api.PolicyRule{{
			ID: "d1", Enabled: true, Priority: 5, Action: api.ActionEgress,
			EgressName: egress, SourceCIDR: "100.67.80.15/32",
		}}}
	}
	r := &Runner{Backend: BackendMock, TableBase: 100}
	for _, eg := range []string{"resid-chi", "resid-zur"} {
		joined := strings.Join(r.Plan(mk(eg)), "\n")
		// The delete must not name a table, or it cannot remove a rule pointing
		// somewhere else.
		if strings.Contains(joined, "ip rule del from 100.67.80.15/32 table") {
			t.Errorf("[%s] delete is scoped to a table, so an egress switch leaks the old rule:\n%s", eg, joined)
		}
		if !strings.Contains(joined, "ip rule del from 100.67.80.15/32 priority 10005") {
			t.Errorf("[%s] no delete by selector+priority:\n%s", eg, joined)
		}
	}
}

// Switching egress must flush conntrack for that client, or established flows
// stay pinned to the old tunnel: their reply tuple still carries the old SNAT
// address and the nft flowtable offloads them past the routing decision. The
// user-visible symptom is "I changed my exit and nothing happened".
//
// Equally important: it must NOT flush when nothing changed, or every reconcile
// would tear down every connection on the node.
func TestConntrackFlushOnlyWhenEgressChanged(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	run := func(currentRule string) bool {
		dir := t.TempDir()
		log := filepath.Join(dir, "flushed.log")
		ipStub := "#!/bin/sh\nif [ \"$1\" = \"-o\" ]; then\n"
		if currentRule != "" {
			ipStub += "  echo '" + currentRule + "'\n"
		}
		ipStub += "fi\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(ipStub), 0o755); err != nil {
			t.Fatal(err)
		}
		ctStub := "#!/bin/sh\necho \"$@\" >> " + log + "\nexit 0\n"
		if err := os.WriteFile(filepath.Join(dir, "conntrack"), []byte(ctStub), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c",
			conntrackFlushOnEgressChange("100.67.80.15/32", 10005, 114, "resid-zur"))
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command failed: %v\n%s", err, out)
		}
		b, _ := os.ReadFile(log)
		return len(b) > 0
	}

	// Pointing at a different egress → must flush.
	if !run("10005:\tfrom 100.67.80.15 lookup netpolicyd-resid-chi") {
		t.Error("egress changed (resid-chi -> resid-zur) but conntrack was not flushed")
	}
	// Already correct, by name → must not flush.
	if run("10005:\tfrom 100.67.80.15 lookup netpolicyd-resid-zur") {
		t.Error("flushed conntrack when the egress had not changed (name form)")
	}
	// Already correct, by number (rt_tables has no name) → must not flush.
	if run("10005:\tfrom 100.67.80.15 lookup 114") {
		t.Error("flushed conntrack when the egress had not changed (numeric form)")
	}
	// No rule yet → nothing is pinned, must not flush.
	if run("") {
		t.Error("flushed conntrack on first install, dropping connections for no reason")
	}
}

// ActionDirect must produce ROUTING, not just a firewall verdict.
//
// It used to be a no-op: the control plane emitted an nft `accept` for the
// destination list plus a policy that only documented intent. An accept is a
// permission verdict and the routing decision was already made by the device's
// egress ip rule, so Iran-direct traffic was accepted straight down the tunnel
// and no destination-based ip rule existed on the node at all.
func TestDirectPolicyMarksAndRoutesViaMain(t *testing.T) {
	s := api.ApplyState{
		Policies: []api.PolicyRule{
			{
				ID: "eg", Enabled: true, Priority: 5, Action: api.ActionEgress,
				EgressName: "resid-zur", SourceCIDR: "100.67.80.15/32",
			},
			{
				ID: "direct", Enabled: true, Priority: 10, Action: api.ActionDirect,
				SourceCIDR:  "100.67.80.15/32",
				Destination: api.Destination{Kind: "iplist", Value: "iran"},
			},
		},
		IPLists: []api.IPList{{ID: "iplist-iran", Name: "iran", Entries: []string{"2.57.3.0/24"}}},
	}
	joined := strings.Join((&Runner{Backend: BackendMock, TableBase: 100}).Plan(s), "\n")

	if !strings.Contains(joined, "meta mark set") {
		t.Errorf("no mangle mark emitted:\n%s", joined)
	}
	// On an nft host the list compiles to a set reference; without nft it is
	// expanded per entry for the iptables backend. Either way the mark must be
	// constrained to the list's destinations and never match everything.
	if !strings.Contains(joined, "@npd_list_iran") && !strings.Contains(joined, "ip daddr 2.57.3.0/24") {
		t.Errorf("mark is not scoped to the destination list:\n%s", joined)
	}
	if !strings.Contains(joined, "mangle_prerouting") {
		t.Errorf("mark must land in mangle prerouting, before the forward routing decision:\n%s", joined)
	}
	if !strings.Contains(joined, "lookup main") {
		t.Errorf("no fwmark rule routing marked packets via main:\n%s", joined)
	}
	// The direct rule must sort ABOVE the per-device egress rule, or the egress
	// rule — which matches on source alone — wins first and direct never applies.
	di := strings.Index(joined, "ip rule add fwmark")
	ei := strings.Index(joined, "ip rule add from 100.67.80.15/32 table")
	if di < 0 || ei < 0 {
		t.Fatalf("missing one of the rules:\n%s", joined)
	}
	getPrio := func(line string) int {
		n, err := strconv.Atoi(line[strings.LastIndex(line, " ")+1:])
		if err != nil {
			t.Fatalf("cannot parse priority from %q: %v", line, err)
		}
		return n
	}
	dp := getPrio(strings.SplitN(joined[di:], "\n", 2)[0])
	ep := getPrio(strings.SplitN(joined[ei:], "\n", 2)[0])
	if dp >= ep {
		t.Errorf("direct rule priority %d must be numerically below egress %d to be evaluated first", dp, ep)
	}
}

// No destination list means nothing to route on — must not emit a bare fwmark
// rule that would send the source's entire traffic out main.
func TestDirectPolicyWithoutListEmitsNothing(t *testing.T) {
	s := api.ApplyState{Policies: []api.PolicyRule{{
		ID: "direct", Enabled: true, Priority: 10, Action: api.ActionDirect,
		SourceCIDR: "100.67.80.15/32", Destination: api.Destination{Kind: "any"},
	}}}
	joined := strings.Join((&Runner{Backend: BackendMock, TableBase: 100}).Plan(s), "\n")
	if strings.Contains(joined, "lookup main") || strings.Contains(joined, "meta mark set") {
		t.Errorf("emitted direct routing with no destination list:\n%s", joined)
	}
}

package apply

import (
	"regexp"
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// shellMeta is every character that changes meaning inside `sh -c`.
const shellMeta = "`|&$;()<>\"'\\ \t\n"

// Regression: comment / log-prefix are free-form user input that reaches
// `sh -c` via strings.Join. A denylist sanitizer previously let `, |, & and $
// through — a root command-injection sink. Whitelist only; nothing else.
func TestCommentIsNotAnInjectionSink(t *testing.T) {
	payloads := []string{
		"x|id", "x`id`", "x$(id)", "x&&id", "x;id", "x $(reboot)",
		"a'b\"c\\d", "x&id", "x>|/etc/passwd", "netpolicyd: ", "",
	}
	for _, p := range payloads {
		if got := sanitizeToken(p); strings.ContainsAny(got, shellMeta) {
			t.Errorf("sanitizeToken leaked a shell metacharacter: %q -> %q", p, got)
		}
		q := nftComment(p)
		if !strings.HasPrefix(q, `"`) || !strings.HasSuffix(q, `"`) {
			t.Errorf("nftComment must stay quoted: %q", q)
			continue
		}
		if inner := strings.Trim(q, `"`); strings.ContainsAny(inner, shellMeta) {
			t.Errorf("nftComment leaked a shell metacharacter: %q -> %q", p, q)
		}
		for _, line := range []string{
			nftRuleCmd(api.FirewallRule{Chain: "forward", Action: "drop", Enabled: true, Comment: p, Backend: "nft"}),
			nftRuleCmd(api.FirewallRule{Chain: "forward", Action: "log", Enabled: true, LogPrefix: p, Comment: p, Backend: "nft"}),
		} {
			if strings.ContainsAny(line, "`|&$;") {
				t.Errorf("injection reached emitted command: %q -> %s", p, line)
			}
		}
	}
}

var reU32Filter = regexp.MustCompile(`tc filter replace dev (\S+) protocol \S+ parent (\S+) prio (\d+) handle (\S+) u32`)

// Regression: a u32 filter's kernel identity is (dev,parent,protocol,prio)+node id.
// Deriving the node id and the prio from the same value (minor+i) made them
// correlated, so rule A's i-th filter aliased rule B's 0th when their minors
// were adjacent — `replace` then gave A's CIDR B's rate limit.
func TestU32FilterIdentityIsUnique(t *testing.T) {
	// two rule IDs whose allocated minors are adjacent — the worst case
	used := map[uint32]string{}
	minorOf := map[string]uint32{}
	for i := 0; i < 3000; i++ {
		id := "tc-" + itoaT(i)
		minorOf[id] = allocateTCMinor(id, used)
	}
	var idA, idB string
	for a, ma := range minorOf {
		for b, mb := range minorOf {
			if a != b && mb == ma+1 {
				idA, idB = a, b
				break
			}
		}
		if idA != "" {
			break
		}
	}
	if idA == "" {
		t.Skip("no adjacent minors in sample")
	}
	// P and P+1 overlap A's per-CIDR prio range with B's first filter.
	for _, p := range []int{0, 100, 500, 60000} {
		rules := []api.TCSpec{
			{ID: idA, Device: "eth0", Enabled: true, Priority: p, RateTxBps: 1_000_000,
				MatchKind: "src_cidr", MatchValue: "10.0.0.1/32,10.0.0.2/32,10.0.0.3/32"},
			{ID: idB, Device: "eth0", Enabled: true, Priority: p + 1, RateTxBps: 2_000_000,
				MatchKind: "src_cidr", MatchValue: "10.1.0.1/32,10.1.0.2/32"},
		}
		seen := map[string]string{}
		for _, line := range planTC(rules) {
			m := reU32Filter.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key := strings.Join(m[1:5], "|")
			if prev, ok := seen[key]; ok {
				t.Errorf("filter identity collision (prio base %d) %s:\n  %s\n  %s", p, key, prev, line)
			}
			seen[key] = line
		}
	}
}

// `replace` is only idempotent if the same rule set plans byte-identical commands.
func TestPlanTCIsDeterministic(t *testing.T) {
	rules := []api.TCSpec{
		{ID: "tc-a", Device: "eth0", Enabled: true, RateTxBps: 1_000_000,
			MatchKind: "src_cidr", MatchValue: "10.0.0.1/32,10.0.0.2/32"},
		{ID: "tc-b", Device: "eth0", Enabled: true, RateRxBps: 2_000_000, MatchKind: "fwmark", MatchValue: "0x5"},
	}
	if strings.Join(planTC(rules), "\n") != strings.Join(planTC(rules), "\n") {
		t.Fatal("planTC not deterministic — tc filter replace would not be idempotent")
	}
}

func itoaT(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

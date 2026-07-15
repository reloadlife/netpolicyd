package tui

import (
	"testing"

	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

func TestTruthy(t *testing.T) {
	for _, s := range []string{"y", "yes", "true", "1", "ON"} {
		if !truthy(s) {
			t.Fatalf("expected truthy %q", s)
		}
	}
	for _, s := range []string{"", "n", "no", "false", "0"} {
		if truthy(s) {
			t.Fatalf("expected falsy %q", s)
		}
	}
}

func TestTrunc(t *testing.T) {
	if got := trunc("hello", 10); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if got := trunc("hello-world", 6); got != "hello…" {
		t.Fatalf("got %q", got)
	}
}

func TestFormPolicyDefaults(t *testing.T) {
	f := newForm("t", policyFormFields(), map[string]string{
		"name": "x", "priority": "10", "enabled": "y",
		"subject_kind": "cidr", "subject_value": "10.0.0.1/32",
		"dest_kind": "any", "dest_value": "0.0.0.0/0",
		"action": "egress", "egress_name": "gre-lab",
	})
	v := f.Values()
	if v["name"] != "x" || v["action"] != "egress" || v["enabled"] != "y" {
		t.Fatalf("unexpected values: %#v", v)
	}
	if v["subject_kind"] != "cidr" {
		t.Fatalf("subject_kind=%q", v["subject_kind"])
	}
}

func TestSubjectsSummary(t *testing.T) {
	s := subjectsSummary([]pkgapi.Subject{{Kind: "cidr", Value: "10.0.0.1/32"}})
	if s != "cidr:10.0.0.1/32" {
		t.Fatalf("got %q", s)
	}
	if subjectsSummary(nil) != "-" {
		t.Fatal("empty")
	}
}

func TestDestSummary(t *testing.T) {
	if destSummary(pkgapi.Destination{}) != "any" {
		t.Fatal("empty dest")
	}
	if got := destSummary(pkgapi.Destination{Kind: "cidr", Value: "0.0.0.0/0"}); got != "cidr:0.0.0.0/0" {
		t.Fatalf("got %q", got)
	}
}

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/reloadlife/netpolicyd/internal/apply"
	"github.com/reloadlife/netpolicyd/internal/store"
	pkg "github.com/reloadlife/netpolicyd/pkg/api"
)

func testServer() *Server {
	return &Server{
		Store:   store.New(),
		Runner:  apply.NewRunner(true), // mock
		Token:   "test-token",
		Version: "test",
	}
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHealthzOpen(t *testing.T) {
	h := testServer().Handler()
	rr := doJSON(t, h, http.MethodGet, "/healthz", "", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestAuthRequired(t *testing.T) {
	h := testServer().Handler()
	rr := doJSON(t, h, http.MethodGet, "/v1/status", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rr.Code)
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/status", "test-token", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
}

func TestPolicyCreateAndList(t *testing.T) {
	h := testServer().Handler()
	rr := doJSON(t, h, http.MethodPost, "/v1/policies", "test-token", map[string]any{
		"name": "user4", "priority": 10, "action": "egress", "egress_name": "gre-lab",
		"source_cidr": "10.77.0.4/32",
		"subjects":    []map[string]string{{"kind": "cidr", "value": "10.77.0.4/32"}},
		"destination": map[string]string{"kind": "any", "value": "0.0.0.0/0"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Code, rr.Body.String())
	}
	var p pkg.PolicyRule
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.ID == "" {
		t.Fatal("empty id")
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/policies", "test-token", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
}

func TestIPListAndNATExpandApply(t *testing.T) {
	s := testServer()
	h := s.Handler()
	rr := doJSON(t, h, http.MethodPost, "/v1/ip/lists", "test-token", map[string]any{
		"name": "clients", "entries": []string{"10.77.0.4", "10.77.0.5/32"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/nat", "test-token", map[string]any{
		"kind": "masquerade", "source_list": "clients", "out_iface": "gre-lab",
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/apply?dry_run=1", "test-token", map[string]any{})
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var res pkg.ApplyResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	// Both list entries must get a masquerade rule, with no runaway duplicates.
	// nft rules now ship inside one batched `nft -f` transaction, so count rule
	// LINES across the plan rather than commands.
	masq := 0
	replace := false
	for _, c := range res.Commands {
		for _, ln := range strings.Split(c, "\n") {
			if containsAll(ln, "masquerade", "10.77.0.") {
				masq++
			}
		}
		if containsAll(c, "delete table", "netpolicyd") {
			replace = true
		}
	}
	if masq != 2 {
		t.Fatalf("want 2 masq rules, got %d\n%v", masq, res.Commands)
	}
	if !replace {
		t.Fatal("expected atomic nft table replace in plan")
	}
}

func TestOverviewAndStatus(t *testing.T) {
	h := testServer().Handler()
	rr := doJSON(t, h, http.MethodGet, "/v1/overview?skip_host=1", "test-token", nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var ov pkg.Overview
	if err := json.Unmarshal(rr.Body.Bytes(), &ov); err != nil {
		t.Fatal(err)
	}
	if ov.Status.Version != "test" {
		t.Fatal(ov.Status.Version)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !bytes.Contains([]byte(s), []byte(p)) {
			return false
		}
	}
	return true
}

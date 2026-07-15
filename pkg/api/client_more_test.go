package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientCRUDSurface(t *testing.T) {
	mux := http.NewServeMux()
	// minimal stubs
	mux.HandleFunc("/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode([]PolicyRule{})
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(PolicyRule{ID: "pol-1", Name: "n"})
		}
	})
	mux.HandleFunc("/v1/apply", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ApplyResult{OK: true, DryRun: r.URL.Query().Get("dry_run") == "1", Commands: []string{"true"}})
	})
	mux.HandleFunc("/v1/ip/lists", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]IPList{{ID: "l1", Name: "c", Entries: []string{"1.1.1.1/32"}}})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(IPList{ID: "l1", Name: "c"})
	})
	mux.HandleFunc("/v1/overview", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Overview{Status: Status{Version: "v", Backend: "mock"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewClient(srv.URL, WithToken("t"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := c.ListPolicies(ctx); err != nil {
		t.Fatal(err)
	}
	if p, err := c.CreatePolicy(ctx, PolicyCreateRequest{Name: "n", Action: ActionAllow, Subjects: []Subject{{Kind: "cidr", Value: "0.0.0.0/0"}}}); err != nil || p.ID == "" {
		t.Fatal(err, p)
	}
	if res, err := c.Apply(ctx, true); err != nil || !res.DryRun {
		t.Fatal(err, res)
	}
	if lists, err := c.ListIPLists(ctx); err != nil || len(lists) != 1 {
		t.Fatal(err, lists)
	}
	if ov, err := c.Overview(ctx, true); err != nil || ov.Status.Version != "v" {
		t.Fatal(err, ov)
	}
}

func TestNewClientEmpty(t *testing.T) {
	if _, err := NewClient(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestAPIErrorString(t *testing.T) {
	e := &APIError{Status: 400, Code: "bad_request", Message: "nope"}
	if e.Error() == "" {
		t.Fatal()
	}
	e2 := &APIError{Status: 500, Message: "x"}
	if e2.Error() == "" {
		t.Fatal()
	}
}

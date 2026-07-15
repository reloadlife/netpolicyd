package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientHealthAndError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"code": "unauthorized", "message": "bad token"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(Status{Version: "1", Backend: "mock"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := NewClient(srv.URL, WithToken("tok"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Version != "1" {
		t.Fatal(err, st)
	}

	bad, _ := NewClient(srv.URL, WithToken("wrong"))
	if _, err := bad.Status(ctx); err == nil {
		t.Fatal("expected auth error")
	}
}

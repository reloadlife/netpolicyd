package api

import (
	"encoding/json"
	"net/http"
	"testing"

	pkg "github.com/reloadlife/netpolicyd/pkg/api"
)

func TestFirewallTCRouteCRUD(t *testing.T) {
	h := testServer().Handler()
	tok := "test-token"

	rr := doJSON(t, h, http.MethodPost, "/v1/firewall", tok, map[string]any{
		"table": "filter", "chain": "input", "action": "accept",
		"protocol": "tcp", "dport": "22", "name": "ssh",
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	var fw pkg.FirewallRule
	_ = json.Unmarshal(rr.Body.Bytes(), &fw)

	rr = doJSON(t, h, http.MethodPost, "/v1/tc", tok, map[string]any{
		"device": "gre-lab", "rate_tx_bps": 1e6, "rate_rx_bps": 1e6,
		"match_kind": "src_cidr", "match_value": "10.0.0.1/32", "name": "cap",
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}

	rr = doJSON(t, h, http.MethodPost, "/v1/routes", tok, map[string]any{
		"table": "main", "dst": "default", "device": "ens18",
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	var rt pkg.RouteSpec
	_ = json.Unmarshal(rr.Body.Bytes(), &rt)

	rr = doJSON(t, h, http.MethodDelete, "/v1/firewall/"+fw.ID, tok, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatal(rr.Code)
	}
	rr = doJSON(t, h, http.MethodDelete, "/v1/routes/"+rt.ID, tok, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatal(rr.Code)
	}
}

func TestIPForwardAndSysctl(t *testing.T) {
	h := testServer().Handler()
	tok := "test-token"
	rr := doJSON(t, h, http.MethodPut, "/v1/sysctl/ip_forward", tok, map[string]bool{"enabled": true})
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodPost, "/v1/sysctl", tok, map[string]any{
		"key": "net.ipv4.conf.all.rp_filter", "value": "2", "managed": true,
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/v1/sysctl", tok, nil)
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var list []pkg.SysctlSpec
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list) < 1 {
		t.Fatal(list)
	}
}

func TestIPListEntriesAppend(t *testing.T) {
	h := testServer().Handler()
	tok := "test-token"
	rr := doJSON(t, h, http.MethodPost, "/v1/ip/lists", tok, map[string]any{
		"name": "crew", "entries": []string{"10.0.0.1"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatal(rr.Body.String())
	}
	var l pkg.IPList
	_ = json.Unmarshal(rr.Body.Bytes(), &l)
	rr = doJSON(t, h, http.MethodPost, "/v1/ip/lists/"+l.ID+"/entries", tok, map[string]any{
		"entries": []string{"10.0.0.2"},
		"text":    "10.0.0.3\n# skip\n10.0.0.4/32",
	})
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &l)
	if len(l.Entries) < 3 {
		t.Fatalf("%v", l.Entries)
	}
}

func TestDesiredAndMetrics(t *testing.T) {
	h := testServer().Handler()
	tok := "test-token"
	en := true
	rr := doJSON(t, h, http.MethodPut, "/v1/desired", tok, map[string]any{
		"generation": 3,
		"ip_forward": &en,
		"policies": []map[string]any{{
			"id": "pol-x", "name": "p", "priority": 1, "enabled": true,
			"action": "allow", "subjects": []map[string]string{{"kind": "cidr", "value": "10.0.0.0/8"}},
			"destination": map[string]string{"kind": "any", "value": "0.0.0.0/0"},
		}},
	})
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	rr = doJSON(t, h, http.MethodGet, "/metrics", "", nil)
	if rr.Code != 200 || !containsAll(rr.Body.String(), "netpolicyd_up") {
		t.Fatal(rr.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := testServer().Handler()
	// policies collection rejects DELETE
	rr := doJSON(t, h, http.MethodDelete, "/v1/policies", "test-token", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rr.Code)
	}
}

package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/reloadlife/netpolicyd/internal/apply"
	"github.com/reloadlife/netpolicyd/internal/host"
	"github.com/reloadlife/netpolicyd/internal/store"
	pkg "github.com/reloadlife/netpolicyd/pkg/api"
)

// Server is the netpolicyd HTTP API.
type Server struct {
	Store   *store.Memory
	Runner  *apply.Runner
	Token   string
	Version string
	applyMu sync.Mutex
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/readyz", s.healthz)
	mux.HandleFunc("/v1/version", s.auth(s.version))
	mux.HandleFunc("/v1/status", s.auth(s.status))
	mux.HandleFunc("/v1/policies", s.auth(s.policies))
	mux.HandleFunc("/v1/policies/", s.auth(s.policyOne))
	mux.HandleFunc("/v1/routes", s.auth(s.routes))
	mux.HandleFunc("/v1/routes/", s.auth(s.routeOne))
	mux.HandleFunc("/v1/nat", s.auth(s.nat))
	mux.HandleFunc("/v1/nat/", s.auth(s.natOne))
	mux.HandleFunc("/v1/forwards", s.auth(s.forwards))
	mux.HandleFunc("/v1/forwards/", s.auth(s.forwardOne))
	mux.HandleFunc("/v1/tc", s.auth(s.tcRules))
	mux.HandleFunc("/v1/tc/", s.auth(s.tcOne))
	mux.HandleFunc("/v1/firewall", s.auth(s.firewall))
	mux.HandleFunc("/v1/firewall/", s.auth(s.firewallOne))
	mux.HandleFunc("/v1/ip/addrs", s.auth(s.ipAddrs))
	mux.HandleFunc("/v1/ip/addrs/", s.auth(s.ipAddrOne))
	mux.HandleFunc("/v1/ip/rules", s.auth(s.ipRules))
	mux.HandleFunc("/v1/ip/rules/", s.auth(s.ipRuleOne))
	mux.HandleFunc("/v1/ip/links", s.auth(s.ipLinks))
	mux.HandleFunc("/v1/ip/links/", s.auth(s.ipLinkOne))
	mux.HandleFunc("/v1/ip/lists", s.auth(s.ipLists))
	mux.HandleFunc("/v1/ip/lists/", s.auth(s.ipListOne))
	mux.HandleFunc("/v1/desired", s.auth(s.desired))
	mux.HandleFunc("/v1/apply", s.auth(s.apply))
	mux.HandleFunc("/v1/sysctl/ip_forward", s.auth(s.ipForward))
	mux.HandleFunc("/v1/sysctl", s.auth(s.sysctls))
	mux.HandleFunc("/v1/sysctl/", s.auth(s.sysctlOne))
	// Live host firewall / routing dump for admin UI / TUI
	mux.HandleFunc("/v1/dataplane", s.auth(s.dataplane))
	mux.HandleFunc("/v1/traffic", s.auth(s.traffic))
	mux.HandleFunc("/v1/overview", s.auth(s.overview))
	mux.HandleFunc("/metrics", s.metrics)
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			h := r.Header.Get("Authorization")
			expected := "Bearer " + s.Token
			if subtle.ConstantTimeCompare([]byte(h), []byte(expected)) != 1 {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid token")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "service": "netpolicyd"})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"version": s.Version})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.buildStatus())
}

func (s *Server) buildStatus() pkg.Status {
	ipOK, nftOK, tcOK := apply.Detect()
	last, at, gen := s.Store.LastApply()
	c := s.Store.Counts()
	iptOK := hasBin("iptables") || hasBin("iptables-save")
	st := pkg.Status{
		Version:           s.Version,
		Backend:           string(s.Runner.Backend),
		IPForward:         s.Store.IPForward(),
		PolicyCount:       c.Policies,
		RouteCount:        c.Routes,
		NATCount:          c.NAT,
		ForwardCount:      c.Forwards,
		TCCount:           c.TC,
		FirewallCount:     c.Firewall,
		IPAddrCount:       c.IPAddrs,
		IPRuleCount:       c.IPRules,
		LinkCount:         c.Links,
		LastApplyOK:       last.OK,
		LastApplyAt:       formatTime(at),
		LastGeneration:    gen,
		NFTAvailable:      nftOK,
		TCAvailable:       tcOK,
		IPAvailable:       ipOK,
		IptablesAvailable: iptOK,
	}
	// Include last apply payload when we have commands
	if len(last.Commands) > 0 || last.Message != "" {
		cp := last
		st.LastApply = &cp
	}
	return st
}

func hasBin(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		if st, err := os.Stat(dir + "/" + name); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func (s *Server) dataplane(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, host.Collect())
}

func (s *Server) traffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, host.CollectTraffic())
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// ?skip_host=1 for lighter payload
	skipHost := r.URL.Query().Get("skip_host") == "1"
	ov := pkg.Overview{
		Status:   s.buildStatus(),
		Policies: s.Store.ListPolicies(),
		Routes:   s.Store.ListRoutes(),
		NAT:      s.Store.ListNAT(),
		Forwards: s.Store.ListForwards(),
		TC:       s.Store.ListTC(),
		Firewall: s.Store.ListFirewall(),
		IPAddrs:  s.Store.ListIPAddrs(),
		IPRules:  s.Store.ListIPRules(),
		Links:    s.Store.ListLinks(),
		Sysctls:  s.Store.ListSysctls(),
		IPLists:  s.Store.ListIPLists(),
	}
	if !skipHost {
		dp := host.Collect()
		ov.Dataplane = &dp
	}
	writeJSON(w, ov)
}

func (s *Server) policies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListPolicies())
	case http.MethodPost:
		var req pkg.PolicyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		p, err := s.Store.CreatePolicy(req)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		// auto-apply best-effort
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) policyOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/policies/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, ok := s.Store.GetPolicy(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		writeJSON(w, p)
	case http.MethodPatch:
		var req pkg.PolicyUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		p, err := s.Store.UpdatePolicy(id, req)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		writeJSON(w, p)
	case http.MethodDelete:
		if err := s.Store.DeletePolicy(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) routes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListRoutes())
	case http.MethodPost:
		var rt pkg.RouteSpec
		if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		rt.Enabled = true
		out, err := s.Store.UpsertRoute(rt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) routeOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/routes/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteRoute(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) nat(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListNAT())
	case http.MethodPost:
		var n pkg.NATSpec
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		n.Enabled = true
		out, err := s.Store.UpsertNAT(n)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) natOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/nat/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteNAT(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) forwards(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListForwards())
	case http.MethodPost:
		var f pkg.ForwardSpec
		if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		f.Enabled = true
		out, err := s.Store.UpsertForward(f)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) forwardOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/forwards/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteForward(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) tcRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListTC())
	case http.MethodPost:
		var t pkg.TCSpec
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		t.Enabled = true
		out, err := s.Store.UpsertTC(t)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) tcOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/tc/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteTC(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) desired(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var d pkg.DesiredState
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}
	if d.Policies != nil {
		s.Store.ReplacePolicies(d.Policies)
	}
	var errs []string
	for _, rt := range d.Routes {
		if _, err := s.Store.UpsertRoute(rt); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, n := range d.NAT {
		if _, err := s.Store.UpsertNAT(n); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, f := range d.Forwards {
		if _, err := s.Store.UpsertForward(f); err != nil {
			errs = append(errs, err.Error())
		}
	}
	// Replace, not merge — same as Policies above. Upserting let dead specs
	// accumulate: shapers for ended sessions and for interfaces that no longer
	// exist kept being re-applied every reconcile, erroring forever and hiding
	// the real failures. nil means "not sent", which must not wipe the set.
	if d.TC != nil {
		s.Store.ReplaceTC(d.TC)
	}
	if d.Firewall != nil {
		s.Store.ReplaceFirewall(d.Firewall)
	}
	for _, a := range d.IPAddrs {
		if _, err := s.Store.UpsertIPAddr(a); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if d.IPRules != nil {
		s.Store.ReplaceIPRules(d.IPRules)
	}
	for _, l := range d.Links {
		if _, err := s.Store.UpsertLink(l); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, sc := range d.Sysctls {
		if _, err := s.Store.UpsertSysctl(sc); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, l := range d.IPLists {
		if _, err := s.Store.UpsertIPList(l); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if d.IPForward != nil {
		s.Store.SetIPForward(*d.IPForward)
	}
	if len(errs) > 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", strings.Join(errs, "; "))
		return
	}
	res := s.doApply(false)
	res.Generation = d.Generation
	s.Store.SetLastApply(res, d.Generation)
	writeJSON(w, res)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	dry := r.URL.Query().Get("dry_run") == "1" || r.URL.Query().Get("dry_run") == "true"
	res := s.doApply(dry)
	writeJSON(w, res)
}

func (s *Server) doApply(dry bool) pkg.ApplyResult {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	res := s.Runner.Apply(s.Store.Snapshot(), dry)
	if !dry {
		_, _, gen := s.Store.LastApply()
		s.Store.SetLastApply(res, gen)
	}
	return res
}

func (s *Server) firewall(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListFirewall())
	case http.MethodPost:
		var rule pkg.FirewallRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		rule.Enabled = true
		out, err := s.Store.UpsertFirewall(rule)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) firewallOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/firewall/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteFirewall(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ipAddrs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListIPAddrs())
	case http.MethodPost:
		var a pkg.IPAddrSpec
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		a.Enabled = true
		out, err := s.Store.UpsertIPAddr(a)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ipAddrOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ip/addrs/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := s.Store.DeleteIPAddr(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	s.doApply(false)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ipRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListIPRules())
	case http.MethodPost:
		var rule pkg.IPRuleSpec
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		rule.Enabled = true
		out, err := s.Store.UpsertIPRule(rule)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ipRuleOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ip/rules/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := s.Store.DeleteIPRule(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	s.doApply(false)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ipLinks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListLinks())
	case http.MethodPost:
		var l pkg.LinkSpec
		if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		l.Enabled = true
		out, err := s.Store.UpsertLink(l)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ipLinkOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ip/links/")
	id = strings.Split(id, "/")[0]
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := s.Store.DeleteLink(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	s.doApply(false)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ipForward(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]bool{"ip_forward": s.Store.IPForward()})
	case http.MethodPut, http.MethodPost:
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		s.Store.SetIPForward(body.Enabled)
		// best-effort live sysctl
		if s.Runner.Backend == apply.BackendLive {
			val := "0"
			if body.Enabled {
				val = "1"
			}
			_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward="+val).Run()
		}
		writeJSON(w, map[string]bool{"ip_forward": body.Enabled})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ipLists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListIPLists())
	case http.MethodPost:
		var l pkg.IPList
		if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		out, err := s.Store.UpsertIPList(l)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) ipListOne(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ip/lists/")
	id = strings.Split(id, "/")[0]
	rest := strings.TrimPrefix(r.URL.Path, "/v1/ip/lists/"+id)
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id required")
		return
	}
	// POST /v1/ip/lists/{id}/entries — append entries
	if strings.HasPrefix(rest, "/entries") && r.Method == http.MethodPost {
		var body struct {
			Entries []string `json:"entries"`
			// also accept newline bulk
			Text string `json:"text,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		more := body.Entries
		if body.Text != "" {
			for _, line := range strings.Split(body.Text, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					more = append(more, line)
				}
			}
		}
		out, err := s.Store.AppendIPListEntries(id, more)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		writeJSON(w, out)
		return
	}
	switch r.Method {
	case http.MethodGet:
		l, ok := s.Store.GetIPList(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "not_found", "list not found")
			return
		}
		writeJSON(w, l)
	case http.MethodDelete:
		if err := s.Store.DeleteIPList(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) sysctls(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.Store.ListSysctls())
	case http.MethodPost:
		var sc pkg.SysctlSpec
		if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON")
			return
		}
		out, err := s.Store.UpsertSysctl(sc)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		s.doApply(false)
		writeJSONStatus(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) sysctlOne(w http.ResponseWriter, r *http.Request) {
	// /v1/sysctl/<key with dots> — path after prefix
	key := strings.TrimPrefix(r.URL.Path, "/v1/sysctl/")
	key = strings.Trim(key, "/")
	if key == "" || key == "ip_forward" {
		// ip_forward handled by dedicated route when exact; if hit here empty
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Store.DeleteSysctl(key); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		s.doApply(false)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	pols := s.Store.ListPolicies()
	enabled := 0
	for _, p := range pols {
		if p.Enabled {
			enabled++
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(
		"# HELP netpolicyd_up 1 if serving\n# TYPE netpolicyd_up gauge\nnetpolicyd_up 1\n" +
			"# HELP netpolicyd_policies Number of policy rules\n# TYPE netpolicyd_policies gauge\n" +
			"netpolicyd_policies " + itoa(len(pols)) + "\n" +
			"netpolicyd_policies_enabled " + itoa(enabled) + "\n",
	))
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Replace(strings.Replace(
		jsonNumber(n), "e+", "e", 1), ".0", "", 1))
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": errCode, "message": msg},
	})
}

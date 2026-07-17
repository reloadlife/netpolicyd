package store

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/reloadlife/netpolicyd/pkg/api"
)

// Memory is an in-process policy store (replace with sqlite later).
type Memory struct {
	mu       sync.RWMutex
	policies map[string]*api.PolicyRule
	routes   map[string]*api.RouteSpec
	nat      map[string]*api.NATSpec
	forwards map[string]*api.ForwardSpec
	tc       map[string]*api.TCSpec
	firewall map[string]*api.FirewallRule
	ipAddrs  map[string]*api.IPAddrSpec
	ipRules  map[string]*api.IPRuleSpec
	links    map[string]*api.LinkSpec
	sysctls  map[string]*api.SysctlSpec // key = sysctl key
	ipLists  map[string]*api.IPList     // key = id
	// apply bookkeeping
	lastApply   api.ApplyResult
	lastApplyAt time.Time
	lastGen     int64
	ipForward   bool
}

// Counts holds collection sizes for status without copying/sorting the store.
type Counts struct {
	Policies, Routes, NAT, Forwards, TC, Firewall, IPAddrs, IPRules, Links, Sysctls, IPLists int
}

func (m *Memory) Counts() Counts {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Counts{
		Policies: len(m.policies), Routes: len(m.routes), NAT: len(m.nat),
		Forwards: len(m.forwards), TC: len(m.tc), Firewall: len(m.firewall),
		IPAddrs: len(m.ipAddrs), IPRules: len(m.ipRules), Links: len(m.links),
		Sysctls: len(m.sysctls), IPLists: len(m.ipLists),
	}
}

func New() *Memory {
	return &Memory{
		policies:  make(map[string]*api.PolicyRule),
		routes:    make(map[string]*api.RouteSpec),
		nat:       make(map[string]*api.NATSpec),
		forwards:  make(map[string]*api.ForwardSpec),
		tc:        make(map[string]*api.TCSpec),
		firewall:  make(map[string]*api.FirewallRule),
		ipAddrs:   make(map[string]*api.IPAddrSpec),
		ipRules:   make(map[string]*api.IPRuleSpec),
		links:     make(map[string]*api.LinkSpec),
		sysctls:   make(map[string]*api.SysctlSpec),
		ipLists:   make(map[string]*api.IPList),
		ipForward: true, // default on for VPN gateway
	}
}

func (m *Memory) ListPolicies() []api.PolicyRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.PolicyRule, 0, len(m.policies))
	for _, p := range m.policies {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (m *Memory) GetPolicy(id string) (api.PolicyRule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[id]
	if !ok {
		return api.PolicyRule{}, false
	}
	return *p, true
}

func (m *Memory) CreatePolicy(req api.PolicyCreateRequest) (api.PolicyRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if req.Name == "" {
		return api.PolicyRule{}, fmt.Errorf("name required")
	}
	if req.Action == "" {
		return api.PolicyRule{}, fmt.Errorf("action required")
	}
	if len(req.Subjects) == 0 {
		return api.PolicyRule{}, fmt.Errorf("at least one subject required")
	}
	if req.Destination.Kind == "" {
		req.Destination = api.Destination{Kind: "any", Value: "0.0.0.0/0"}
	}
	en := true
	if req.Enabled != nil {
		en = *req.Enabled
	}
	if req.Action == api.ActionEgress && req.EgressName == "" {
		return api.PolicyRule{}, fmt.Errorf("egress_name required for action=egress")
	}
	now := time.Now().UTC()
	p := &api.PolicyRule{
		ID:          "pol-" + uuid.NewString()[:8],
		Priority:    req.Priority,
		Name:        req.Name,
		Enabled:     en,
		Subjects:    req.Subjects,
		Destination: req.Destination,
		Action:      req.Action,
		EgressName:  req.EgressName,
		Mark:        req.Mark,
		Table:       req.Table,
		SourceCIDR:  req.SourceCIDR,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if p.Priority == 0 {
		p.Priority = 100
	}
	if err := validatePolicy(*p); err != nil {
		return api.PolicyRule{}, err
	}
	m.policies[p.ID] = p
	return *p, nil
}

func (m *Memory) UpdatePolicy(id string, req api.PolicyUpdateRequest) (api.PolicyRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.policies[id]
	if !ok {
		return api.PolicyRule{}, fmt.Errorf("not found")
	}
	merged := *cur
	if req.Priority != nil {
		merged.Priority = *req.Priority
	}
	if req.Name != nil {
		merged.Name = *req.Name
	}
	if req.Enabled != nil {
		merged.Enabled = *req.Enabled
	}
	if req.Subjects != nil {
		merged.Subjects = req.Subjects
	}
	if req.Destination != nil {
		merged.Destination = *req.Destination
	}
	if req.Action != nil {
		merged.Action = *req.Action
	}
	if req.EgressName != nil {
		merged.EgressName = *req.EgressName
	}
	if req.Mark != nil {
		merged.Mark = *req.Mark
	}
	if req.Table != nil {
		merged.Table = *req.Table
	}
	if req.SourceCIDR != nil {
		merged.SourceCIDR = *req.SourceCIDR
	}
	if req.Description != nil {
		merged.Description = *req.Description
	}
	merged.UpdatedAt = time.Now().UTC()
	if err := validatePolicy(merged); err != nil {
		return api.PolicyRule{}, err
	}
	*cur = merged
	return *cur, nil
}

func (m *Memory) DeletePolicy(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policies[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.policies, id)
	return nil
}

func (m *Memory) ReplacePolicies(rules []api.PolicyRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = make(map[string]*api.PolicyRule, len(rules))
	for i := range rules {
		r := rules[i]
		if r.ID == "" {
			r.ID = "pol-" + uuid.NewString()[:8]
		}
		cp := r
		m.policies[cp.ID] = &cp
	}
}

func (m *Memory) ListRoutes() []api.RouteSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.RouteSpec, 0, len(m.routes))
	for _, r := range m.routes {
		out = append(out, *r)
	}
	return out
}

func (m *Memory) UpsertRoute(r api.RouteSpec) (api.RouteSpec, error) {
	if err := validateRoute(r); err != nil {
		return api.RouteSpec{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.ID == "" {
		r.ID = "rt-" + uuid.NewString()[:8]
	}
	cp := r
	m.routes[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteRoute(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.routes[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.routes, id)
	return nil
}

func (m *Memory) ListNAT() []api.NATSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.NATSpec, 0, len(m.nat))
	for _, n := range m.nat {
		out = append(out, *n)
	}
	return out
}

func (m *Memory) UpsertNAT(n api.NATSpec) (api.NATSpec, error) {
	if n.Kind == "" {
		n.Kind = "masquerade"
	}
	if err := validateNAT(n); err != nil {
		return api.NATSpec{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if n.ID == "" {
		n.ID = "nat-" + uuid.NewString()[:8]
	}
	cp := n
	m.nat[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteNAT(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nat[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.nat, id)
	return nil
}

func (m *Memory) ListForwards() []api.ForwardSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.ForwardSpec, 0, len(m.forwards))
	for _, f := range m.forwards {
		out = append(out, *f)
	}
	return out
}

func (m *Memory) UpsertForward(f api.ForwardSpec) (api.ForwardSpec, error) {
	if err := validateForward(f); err != nil {
		return api.ForwardSpec{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.ID == "" {
		f.ID = "fwd-" + uuid.NewString()[:8]
	}
	cp := f
	m.forwards[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteForward(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.forwards[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.forwards, id)
	return nil
}

func (m *Memory) ListTC() []api.TCSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.TCSpec, 0, len(m.tc))
	for _, t := range m.tc {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m *Memory) UpsertTC(t api.TCSpec) (api.TCSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.Device == "" {
		return api.TCSpec{}, fmt.Errorf("device required")
	}
	if t.RateTxBps <= 0 && t.RateRxBps <= 0 {
		return api.TCSpec{}, fmt.Errorf("rate_tx_bps or rate_rx_bps required")
	}
	if t.MatchKind == "" {
		t.MatchKind = "any"
	}
	switch t.MatchKind {
	case "any", "src_cidr", "dst_cidr", "fwmark":
	default:
		return api.TCSpec{}, fmt.Errorf("match_kind must be any|src_cidr|dst_cidr|fwmark")
	}
	if t.MatchKind != "any" && t.MatchValue == "" {
		return api.TCSpec{}, fmt.Errorf("match_value required for match_kind=%s", t.MatchKind)
	}
	if err := validateTC(t); err != nil {
		return api.TCSpec{}, err
	}
	if t.ID == "" {
		t.ID = "tc-" + uuid.NewString()[:8]
	}
	cp := t
	m.tc[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteTC(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tc[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.tc, id)
	return nil
}

func (m *Memory) ListFirewall() []api.FirewallRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.FirewallRule, 0, len(m.firewall))
	for _, r := range m.firewall {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m *Memory) UpsertFirewall(r api.FirewallRule) (api.FirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Table == "" {
		r.Table = "filter"
	}
	if r.Chain == "" {
		return api.FirewallRule{}, fmt.Errorf("chain required")
	}
	if r.Action == "" {
		return api.FirewallRule{}, fmt.Errorf("action required")
	}
	switch strings.ToLower(r.Table) {
	case "filter", "nat", "mangle", "raw":
	default:
		return api.FirewallRule{}, fmt.Errorf("table must be filter|nat|mangle|raw")
	}
	if r.Backend == "" {
		r.Backend = "auto"
	}
	if err := validateFirewall(r); err != nil {
		return api.FirewallRule{}, err
	}
	if r.ID == "" {
		r.ID = "fw-" + uuid.NewString()[:8]
	}
	cp := r
	m.firewall[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteFirewall(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.firewall[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.firewall, id)
	return nil
}

func (m *Memory) ListIPAddrs() []api.IPAddrSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.IPAddrSpec, 0, len(m.ipAddrs))
	for _, a := range m.ipAddrs {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].CIDR < out[j].CIDR
	})
	return out
}

func (m *Memory) UpsertIPAddr(a api.IPAddrSpec) (api.IPAddrSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a.Device == "" {
		return api.IPAddrSpec{}, fmt.Errorf("device required")
	}
	if a.CIDR == "" {
		return api.IPAddrSpec{}, fmt.Errorf("cidr required")
	}
	if err := validateIPAddr(a); err != nil {
		return api.IPAddrSpec{}, err
	}
	if a.ID == "" {
		a.ID = "addr-" + uuid.NewString()[:8]
	}
	cp := a
	m.ipAddrs[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteIPAddr(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ipAddrs[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.ipAddrs, id)
	return nil
}

func (m *Memory) ListIPRules() []api.IPRuleSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.IPRuleSpec, 0, len(m.ipRules))
	for _, r := range m.ipRules {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m *Memory) UpsertIPRule(r api.IPRuleSpec) (api.IPRuleSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Table == "" && (r.Action == "" || r.Action == "lookup") {
		return api.IPRuleSpec{}, fmt.Errorf("table required for lookup")
	}
	if r.Action == "" {
		r.Action = "lookup"
	}
	if err := validateIPRule(r); err != nil {
		return api.IPRuleSpec{}, err
	}
	if r.ID == "" {
		r.ID = "rule-" + uuid.NewString()[:8]
	}
	cp := r
	m.ipRules[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteIPRule(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ipRules[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.ipRules, id)
	return nil
}

func (m *Memory) ListLinks() []api.LinkSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.LinkSpec, 0, len(m.links))
	for _, l := range m.links {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Memory) UpsertLink(l api.LinkSpec) (api.LinkSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.Name == "" {
		return api.LinkSpec{}, fmt.Errorf("name required")
	}
	if err := validateLink(l); err != nil {
		return api.LinkSpec{}, err
	}
	if l.ID == "" {
		l.ID = "link-" + uuid.NewString()[:8]
	}
	cp := l
	m.links[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteLink(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.links[id]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.links, id)
	return nil
}

func (m *Memory) ListSysctls() []api.SysctlSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.SysctlSpec, 0, len(m.sysctls))
	for _, s := range m.sysctls {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (m *Memory) UpsertSysctl(s api.SysctlSpec) (api.SysctlSpec, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Key == "" {
		return api.SysctlSpec{}, fmt.Errorf("key required")
	}
	s.Managed = true
	if err := validateSysctl(s); err != nil {
		return api.SysctlSpec{}, err
	}
	cp := s
	m.sysctls[cp.Key] = &cp
	return cp, nil
}

func (m *Memory) DeleteSysctl(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sysctls[key]; !ok {
		return fmt.Errorf("not found")
	}
	delete(m.sysctls, key)
	return nil
}

func (m *Memory) ListIPLists() []api.IPList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]api.IPList, 0, len(m.ipLists))
	for _, l := range m.ipLists {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Memory) GetIPList(idOrName string) (api.IPList, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if l, ok := m.ipLists[idOrName]; ok {
		return *l, true
	}
	for _, l := range m.ipLists {
		if l.Name == idOrName {
			return *l, true
		}
	}
	return api.IPList{}, false
}

func (m *Memory) UpsertIPList(l api.IPList) (api.IPList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l.Name = strings.TrimSpace(l.Name)
	if l.Name == "" {
		return api.IPList{}, fmt.Errorf("name required")
	}
	// normalize entries
	var entries []string
	seen := map[string]bool{}
	for _, e := range l.Entries {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		entries = append(entries, e)
	}
	l.Entries = entries
	if err := validateIPList(l); err != nil {
		return api.IPList{}, err
	}
	// unique name
	for id, other := range m.ipLists {
		if other.Name == l.Name && (l.ID == "" || id != l.ID) {
			return api.IPList{}, fmt.Errorf("list name %q already exists", l.Name)
		}
	}
	if l.ID == "" {
		l.ID = "list-" + uuid.NewString()[:8]
	}
	cp := l
	m.ipLists[cp.ID] = &cp
	return cp, nil
}

func (m *Memory) DeleteIPList(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.ipLists[id]; !ok {
		// try by name
		for k, l := range m.ipLists {
			if l.Name == id {
				delete(m.ipLists, k)
				return nil
			}
		}
		return fmt.Errorf("not found")
	}
	delete(m.ipLists, id)
	return nil
}

// AppendIPListEntries adds entries to an existing list (by id or name).
func (m *Memory) AppendIPListEntries(idOrName string, more []string) (api.IPList, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var l *api.IPList
	if x, ok := m.ipLists[idOrName]; ok {
		l = x
	} else {
		for _, x := range m.ipLists {
			if x.Name == idOrName {
				l = x
				break
			}
		}
	}
	if l == nil {
		return api.IPList{}, fmt.Errorf("list not found")
	}
	seen := map[string]bool{}
	for _, e := range l.Entries {
		seen[e] = true
	}
	for _, e := range more {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		l.Entries = append(l.Entries, e)
	}
	return *l, nil
}

func (m *Memory) SetIPForward(v bool) { m.mu.Lock(); m.ipForward = v; m.mu.Unlock() }
func (m *Memory) IPForward() bool     { m.mu.RLock(); defer m.mu.RUnlock(); return m.ipForward }

func (m *Memory) SetLastApply(res api.ApplyResult, gen int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastApply = res
	m.lastApplyAt = time.Now().UTC()
	m.lastGen = gen
}

func (m *Memory) LastApply() (api.ApplyResult, time.Time, int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastApply, m.lastApplyAt, m.lastGen
}

// Snapshot returns full desired state for apply.
func (m *Memory) Snapshot() api.ApplyState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := api.ApplyState{IPForward: m.ipForward}
	for _, p := range m.policies {
		s.Policies = append(s.Policies, *p)
	}
	sort.Slice(s.Policies, func(i, j int) bool { return s.Policies[i].Priority < s.Policies[j].Priority })
	for _, r := range m.routes {
		s.Routes = append(s.Routes, *r)
	}
	for _, n := range m.nat {
		s.NAT = append(s.NAT, *n)
	}
	for _, f := range m.forwards {
		s.Forwards = append(s.Forwards, *f)
	}
	for _, t := range m.tc {
		s.TC = append(s.TC, *t)
	}
	for _, f := range m.firewall {
		s.Firewall = append(s.Firewall, *f)
	}
	sort.Slice(s.Firewall, func(i, j int) bool { return s.Firewall[i].Priority < s.Firewall[j].Priority })
	for _, a := range m.ipAddrs {
		s.IPAddrs = append(s.IPAddrs, *a)
	}
	for _, r := range m.ipRules {
		s.IPRules = append(s.IPRules, *r)
	}
	sort.Slice(s.IPRules, func(i, j int) bool { return s.IPRules[i].Priority < s.IPRules[j].Priority })
	for _, l := range m.links {
		s.Links = append(s.Links, *l)
	}
	for _, sc := range m.sysctls {
		s.Sysctls = append(s.Sysctls, *sc)
	}
	for _, l := range m.ipLists {
		s.IPLists = append(s.IPLists, *l)
	}
	return s
}

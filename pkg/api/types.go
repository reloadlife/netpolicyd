// Package api is the public HTTP contract for netpolicyd.
// Control plane and netpolicyctl should depend only on this surface.
package api

import "time"

// PolicyAction is what the rule does for matching traffic.
type PolicyAction string

const (
	ActionAllow   PolicyAction = "allow"
	ActionDeny    PolicyAction = "deny"
	ActionEgress  PolicyAction = "egress"  // force out a named egress tunnel
	ActionDirect  PolicyAction = "direct"  // main table / no special egress
	ActionMasq    PolicyAction = "masquerade"
	ActionForward PolicyAction = "forward"
)

// Subject identifies who the rule applies to (device, user, group, CIDR, iface).
type Subject struct {
	// Kind: device | user | group | cidr | iface | mark
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Destination is where traffic is going.
type Destination struct {
	// Kind: any | cidr | resource | host | dns | iplist
	//
	// "iplist" names an IPList by id or name and is how a policy expresses
	// "these destinations", which a single cidr cannot. Required for
	// ActionDirect to be routable: without it the policy can say "send this
	// source out the main table" but not for which destinations.
	Kind  string `json:"kind"`
	Value string `json:"value"` // e.g. 0.0.0.0/0, res-id, 10.0.0.5, iran
}

// PolicyRule is an ordered, per-node (or fleet-compiled) rule.
// Example: subject device:dev-4 → action egress via gre-lab.
type PolicyRule struct {
	ID          string       `json:"id"`
	Priority    int          `json:"priority"` // lower = earlier
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	Subjects    []Subject    `json:"subjects"`
	Destination Destination  `json:"destination"`
	Action      PolicyAction `json:"action"`
	// EgressName is the egress tunnel interface/name (gre-lab, wg-exit, …)
	// when Action is egress or masquerade.
	EgressName string `json:"egress_name,omitempty"`
	// Mark is optional fwmark for ip rule / tc class.
	Mark uint32 `json:"mark,omitempty"`
	// Table is the routing table id/name for egress steering.
	Table string `json:"table,omitempty"`
	// SourceCIDR optional override (client tunnel IP).
	SourceCIDR  string    `json:"source_cidr,omitempty"`
	Description string    `json:"description,omitempty"`
	HitCount    int64     `json:"hit_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PolicyCreateRequest creates a rule.
type PolicyCreateRequest struct {
	Priority    int          `json:"priority"`
	Name        string       `json:"name"`
	Enabled     *bool        `json:"enabled,omitempty"`
	Subjects    []Subject    `json:"subjects"`
	Destination Destination  `json:"destination"`
	Action      PolicyAction `json:"action"`
	EgressName  string       `json:"egress_name,omitempty"`
	Mark        uint32       `json:"mark,omitempty"`
	Table       string       `json:"table,omitempty"`
	SourceCIDR  string       `json:"source_cidr,omitempty"`
	Description string       `json:"description,omitempty"`
}

// PolicyUpdateRequest patches a rule.
type PolicyUpdateRequest struct {
	Priority    *int          `json:"priority,omitempty"`
	Name        *string       `json:"name,omitempty"`
	Enabled     *bool         `json:"enabled,omitempty"`
	Subjects    []Subject     `json:"subjects,omitempty"`
	Destination *Destination  `json:"destination,omitempty"`
	Action      *PolicyAction `json:"action,omitempty"`
	EgressName  *string       `json:"egress_name,omitempty"`
	Mark        *uint32       `json:"mark,omitempty"`
	Table       *string       `json:"table,omitempty"`
	SourceCIDR  *string       `json:"source_cidr,omitempty"`
	Description *string       `json:"description,omitempty"`
}

// RouteSpec is an explicit ip route managed by netpolicyd.
type RouteSpec struct {
	ID       string `json:"id"`
	Table    string `json:"table"` // main | 100 | egress-gre-lab
	Dst      string `json:"dst"`   // default | 0.0.0.0/0 | cidr
	Gateway  string `json:"gateway,omitempty"`
	Device   string `json:"device,omitempty"` // gre-lab, wg-exit, ens18
	Metric   int    `json:"metric,omitempty"`
	Protocol string `json:"protocol,omitempty"` // static | netpolicyd
	OnLink   bool   `json:"onlink,omitempty"`
	Enabled  bool   `json:"enabled"`
}

// NATSpec is masquerade / SNAT.
type NATSpec struct {
	ID         string `json:"id"`
	Enabled    bool   `json:"enabled"`
	// Kind: masquerade | snat
	Kind       string `json:"kind"`
	SourceCIDR string `json:"source_cidr,omitempty"` // clients
	// SourceList expands to one NAT rule per list entry at apply.
	SourceList string `json:"source_list,omitempty"`
	OutIface   string `json:"out_iface"`           // gre-lab, ens18
	ToSource   string `json:"to_source,omitempty"` // for snat
	Comment    string `json:"comment,omitempty"`
}

// ForwardSpec enables forwarding between ifaces / CIDRs.
type ForwardSpec struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	InIface string `json:"in_iface,omitempty"`
	OutIface string `json:"out_iface,omitempty"`
	Source  string `json:"source,omitempty"`
	Dest    string `json:"dest,omitempty"`
	Action  string `json:"action"` // accept | drop
}

// SysctlSpec is a managed sysctl (e.g. net.ipv4.ip_forward=1).
type SysctlSpec struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Managed bool   `json:"managed"`
}

// IPList is a named set of IPs/CIDRs used by easy/advanced rules.
// Example: list "clients" = ["10.77.0.0/24", "10.78.0.5/32"]
// Firewall/NAT rules can reference lists by name or id (source_list / dest_list).
type IPList struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"` // unique slug, e.g. clients
	Entries []string `json:"entries"`
	Comment string   `json:"comment,omitempty"`
}

// TCSpec is a Linux traffic-control bandwidth limit (HTB egress + ingress police).
// Rates are in bits/sec (e.g. 50_000_000 = 50 Mbit/s).
//
// Example: cap client 10.77.0.4 on gre-lab to 50 Mbit TX / 20 Mbit RX:
//
//	{device:"gre-lab", rate_tx_bps:50e6, rate_rx_bps:20e6, match_kind:"src_cidr", match_value:"10.77.0.4/32"}
//
// Account-shared pool (all device VIPs share one HTB class + one police):
//
//	match_kind:"src_cidr", match_value:"100.67.80.2/32,100.67.80.3/32"
type TCSpec struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
	// Device is the netdev to shape (required), e.g. gre-lab, ens18, wg0.
	Device string `json:"device"`
	// RateTxBps = egress (host → wire) HTB class limit; 0 = no TX limit.
	RateTxBps int64 `json:"rate_tx_bps"`
	// RateRxBps = ingress (wire → host) police; 0 = no RX limit.
	RateRxBps int64 `json:"rate_rx_bps"`
	// CeilingTxBps HTB ceil; 0 = same as RateTxBps.
	CeilingTxBps int64 `json:"ceiling_tx_bps,omitempty"`
	// MatchKind: any | src_cidr | dst_cidr | fwmark
	//   any       — all traffic on Device (default class only if no other match)
	//   src_cidr  — match source CIDR (typical client tunnel IP).
	//               MatchValue may be a comma/space-separated list of CIDRs;
	//               all share one HTB class and one police index (account pool).
	//   dst_cidr  — match destination CIDR (also multi-value capable)
	//   fwmark    — match skb mark (decimal or 0xhex in MatchValue)
	MatchKind  string `json:"match_kind"`
	MatchValue string `json:"match_value,omitempty"`
	// Priority for filter ordering (lower = earlier). 0 = derived from class minor.
	Priority int    `json:"priority,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// FirewallRule is a general-purpose filter/nat/mangle rule.
// Compiled to nft (preferred) and/or iptables depending on Backend and host tools.
//
// Example — allow SSH on ens18:
//
//	{table:"filter", chain:"input", in_iface:"ens18", protocol:"tcp", dport:"22", action:"accept"}
//
// Example — DNAT port 8443 → 10.77.0.4:443:
//
//	{table:"nat", chain:"prerouting", protocol:"tcp", dport:"8443", action:"dnat", to_destination:"10.77.0.4:443"}
type FirewallRule struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"` // lower = earlier
	// Family: inet (nft dual) | ip | ip6 — default inet for nft, ip for iptables
	Family string `json:"family,omitempty"`
	// Table: filter | nat | mangle | raw
	Table string `json:"table"`
	// Chain: input | forward | output | prerouting | postrouting | custom name
	Chain string `json:"chain"`
	// Match
	Source    string `json:"source,omitempty"`  // CIDR
	Dest      string `json:"dest,omitempty"`    // CIDR
	// SourceList / DestList: IP list name or id — expanded at apply into one rule per entry.
	SourceList string `json:"source_list,omitempty"`
	DestList   string `json:"dest_list,omitempty"`
	InIface    string `json:"in_iface,omitempty"`
	OutIface   string `json:"out_iface,omitempty"`
	Protocol   string `json:"protocol,omitempty"` // tcp|udp|icmp|icmpv6|all|…
	Sport      string `json:"sport,omitempty"`    // port or range a:b
	Dport      string `json:"dport,omitempty"`
	FwMark     uint32 `json:"fwmark,omitempty"`
	// CtState: conntrack match, e.g. "established,related" | "new" | "invalid"
	CtState string `json:"ct_state,omitempty"`
	// Action: accept|drop|reject|return|masquerade|snat|dnat|mark|log|redirect
	Action string `json:"action"`
	// Action parameters
	ToSource      string `json:"to_source,omitempty"`      // snat
	ToDestination string `json:"to_destination,omitempty"` // dnat host[:port]
	SetMark       uint32 `json:"set_mark,omitempty"`       // mark action
	LogPrefix     string `json:"log_prefix,omitempty"`
	Comment       string `json:"comment,omitempty"`
	// Backend: auto | nft | iptables — auto prefers nft when available
	Backend string `json:"backend,omitempty"`
}

// IPAddrSpec is a managed address on a netdev (`ip addr`).
type IPAddrSpec struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Device  string `json:"device"` // gre-lab, ens18
	// CIDR is host/prefix, e.g. 10.77.0.1/24 or fd00::1/64
	CIDR   string `json:"cidr"`
	// Peer for point-to-point (optional)
	Peer   string `json:"peer,omitempty"`
	// Broadcast optional
	Broadcast string `json:"broadcast,omitempty"`
	// Scope: global | link | host (default global)
	Scope string `json:"scope,omitempty"`
	// Label optional (eth0:1 style)
	Label   string `json:"label,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// IPRuleSpec is an explicit policy-routing rule (`ip rule`).
type IPRuleSpec struct {
	ID       string `json:"id"`
	Enabled  bool   `json:"enabled"`
	Priority int    `json:"priority"` // lower = earlier; 0 = auto 10000+
	// From / To selectors (CIDR); empty = any
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	Iif  string `json:"iif,omitempty"`
	Oif  string `json:"oif,omitempty"`
	// FwMark optional
	FwMark uint32 `json:"fwmark,omitempty"`
	// Table: main | local | default | numeric | name
	Table string `json:"table"`
	// Action: lookup (default) | blackhole | unreachable | prohibit
	Action  string `json:"action,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// LinkSpec manages netdev admin state / MTU (`ip link`).
type LinkSpec struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"` // when true, apply Up/MTU
	Name    string `json:"name"`    // device name
	// Up: administrative up when true, down when false (only if set)
	Up *bool `json:"up,omitempty"`
	// MTU 0 = leave unchanged
	MTU     int    `json:"mtu,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// DesiredState is what the control plane / agent pushes to netpolicyd.
type DesiredState struct {
	Generation int64          `json:"generation"`
	Policies   []PolicyRule   `json:"policies,omitempty"`
	Routes     []RouteSpec    `json:"routes,omitempty"`
	NAT        []NATSpec      `json:"nat,omitempty"`
	Forwards   []ForwardSpec  `json:"forwards,omitempty"`
	TC         []TCSpec       `json:"tc,omitempty"`
	Firewall   []FirewallRule `json:"firewall,omitempty"`
	IPAddrs    []IPAddrSpec   `json:"ip_addrs,omitempty"`
	IPRules    []IPRuleSpec   `json:"ip_rules,omitempty"`
	Links      []LinkSpec     `json:"links,omitempty"`
	Sysctls    []SysctlSpec   `json:"sysctls,omitempty"`
	IPLists    []IPList       `json:"ip_lists,omitempty"`
	// IPForward global toggle
	IPForward *bool `json:"ip_forward,omitempty"`
}

// ApplyState is the full desired dataplane snapshot for one reconcile.
type ApplyState struct {
	Policies  []PolicyRule
	Routes    []RouteSpec
	NAT       []NATSpec
	Forwards  []ForwardSpec
	TC        []TCSpec
	Firewall  []FirewallRule
	IPAddrs   []IPAddrSpec
	IPRules   []IPRuleSpec
	Links     []LinkSpec
	Sysctls   []SysctlSpec
	IPLists   []IPList
	IPForward bool
}

// ApplyResult is returned after reconcile.
type ApplyResult struct {
	OK         bool     `json:"ok"`
	DryRun     bool     `json:"dry_run"`
	Applied    int      `json:"applied"`
	Skipped    int      `json:"skipped"`
	Errors     []string `json:"errors,omitempty"`
	Commands   []string `json:"commands,omitempty"` // executed or planned
	Message    string   `json:"message,omitempty"`
	Generation int64    `json:"generation,omitempty"`
}

// Status is /v1/status summary.
type Status struct {
	Version        string `json:"version"`
	Backend        string `json:"backend"` // mock | live
	IPForward      bool   `json:"ip_forward"`
	PolicyCount    int    `json:"policy_count"`
	RouteCount     int    `json:"route_count"`
	NATCount       int    `json:"nat_count"`
	ForwardCount   int    `json:"forward_count"`
	TCCount        int    `json:"tc_count"`
	FirewallCount  int    `json:"firewall_count"`
	IPAddrCount    int    `json:"ip_addr_count"`
	IPRuleCount    int    `json:"ip_rule_count"`
	LinkCount      int    `json:"link_count"`
	LastApplyOK    bool   `json:"last_apply_ok"`
	LastApplyAt    string `json:"last_apply_at,omitempty"`
	LastGeneration int64  `json:"last_generation"`
	// LastApply is the most recent apply result (commands/errors).
	LastApply *ApplyResult `json:"last_apply,omitempty"`
	NFTAvailable       bool `json:"nft_available"`
	TCAvailable        bool `json:"tc_available"`
	IPAvailable        bool `json:"ip_available"`
	IptablesAvailable  bool `json:"iptables_available"`
}

// Overview is a single payload for the Policies admin page / TUI.
type Overview struct {
	Status   Status         `json:"status"`
	Policies []PolicyRule   `json:"policies"`
	Routes   []RouteSpec    `json:"routes"`
	NAT      []NATSpec      `json:"nat"`
	Forwards []ForwardSpec  `json:"forwards"`
	TC       []TCSpec       `json:"tc"`
	Firewall []FirewallRule `json:"firewall"`
	IPAddrs  []IPAddrSpec   `json:"ip_addrs"`
	IPRules  []IPRuleSpec   `json:"ip_rules"`
	Links    []LinkSpec     `json:"links"`
	Sysctls  []SysctlSpec   `json:"sysctls"`
	IPLists  []IPList       `json:"ip_lists"`
	// Dataplane is live host ip/nft/iptables dump.
	Dataplane *Dataplane `json:"dataplane,omitempty"`
}

// Dataplane is a point-in-time snapshot of host firewall/routing state.
type Dataplane struct {
	CollectedAt string `json:"collected_at"`

	IPAvailable        bool `json:"ip_available"`
	NFTAvailable       bool `json:"nft_available"`
	TCAvailable        bool `json:"tc_available"`
	IptablesAvailable  bool `json:"iptables_available"`
	IP6tablesAvailable bool `json:"ip6tables_available"`

	IPForward  string `json:"ip_forward,omitempty"`
	IP6Forward string `json:"ip6_forward,omitempty"`

	IPRules    []string `json:"ip_rules,omitempty"`
	IPRulesRaw string   `json:"ip_rules_raw,omitempty"`
	IPRulesErr string   `json:"ip_rules_error,omitempty"`

	IPAddrShow string `json:"ip_addr_show,omitempty"`
	IPLinkShow string `json:"ip_link_show,omitempty"`
	IPNeigh    string `json:"ip_neigh,omitempty"`

	IPRoutesMain   string            `json:"ip_routes_main,omitempty"`
	IPRoutesAll    string            `json:"ip_routes_all,omitempty"`
	IPRoutesAllErr string            `json:"ip_routes_error,omitempty"`
	IPRouteTables  map[string]string `json:"ip_route_tables,omitempty"`

	RTTables string `json:"rt_tables,omitempty"`

	NFTRuleset       string `json:"nft_ruleset,omitempty"`
	NFTRulesetErr    string `json:"nft_ruleset_error,omitempty"`
	NFTNetpolicyd    string `json:"nft_netpolicyd,omitempty"`
	NFTNetpolicydErr string `json:"nft_netpolicyd_error,omitempty"`

	IptablesSave    string `json:"iptables_save,omitempty"`
	IptablesSaveErr string `json:"iptables_save_error,omitempty"`
	IptablesList    string `json:"iptables_list,omitempty"`
	IptablesListErr string `json:"iptables_list_error,omitempty"`
	IP6tablesSave   string `json:"ip6tables_save,omitempty"`
	IP6tablesErr    string `json:"ip6tables_error,omitempty"`

	TCQdisc   string            `json:"tc_qdisc,omitempty"`
	TCClass   string            `json:"tc_class,omitempty"`
	TCFilter  string            `json:"tc_filter,omitempty"`
	// Per-device class/filter dumps for ifaces netpolicyd shapes.
	TCByDevice map[string]string `json:"tc_by_device,omitempty"`
	TCErr      string            `json:"tc_error,omitempty"`
}

// TrafficSnapshot is live throughput + connection inventory for the TUI.
type TrafficSnapshot struct {
	CollectedAt string  `json:"collected_at"`
	IntervalSec float64 `json:"interval_sec"` // seconds since previous sample (0 = first)
	SSAvailable bool    `json:"ss_available"`
	Error       string  `json:"error,omitempty"`

	// Interfaces from /proc/net/dev (+ rates from sample delta).
	Interfaces []IfaceTraffic `json:"interfaces,omitempty"`
	// Aggregates from active sockets (ss).
	ByIP   []IPTraffic   `json:"by_ip,omitempty"`
	ByPort []PortTraffic `json:"by_port,omitempty"`
	// Top connections (ESTAB preferred), with byte counters when ss -i available.
	Connections []ConnTraffic `json:"connections,omitempty"`

	// Totals
	TotalConns   int   `json:"total_conns"`
	Established  int   `json:"established"`
	Listen       int   `json:"listen"`
	TotalRxBps   float64 `json:"total_rx_bps"`
	TotalTxBps   float64 `json:"total_tx_bps"`
}

// IfaceTraffic is per-netdev counters and rates.
type IfaceTraffic struct {
	Name      string  `json:"name"`
	RxBytes   int64   `json:"rx_bytes"`
	TxBytes   int64   `json:"tx_bytes"`
	RxPackets int64   `json:"rx_packets"`
	TxPackets int64   `json:"tx_packets"`
	RxBps     float64 `json:"rx_bps"`
	TxBps     float64 `json:"tx_bps"`
	RxPps     float64 `json:"rx_pps"`
	TxPps     float64 `json:"tx_pps"`
}

// IPTraffic aggregates sockets by local or remote IP.
type IPTraffic struct {
	IP        string  `json:"ip"`
	Side      string  `json:"side"` // local | remote
	Conns     int     `json:"conns"`
	BytesSent int64   `json:"bytes_sent,omitempty"`
	BytesRecv int64   `json:"bytes_recv,omitempty"`
	SendBps   float64 `json:"send_bps,omitempty"` // from ss "send" when present
}

// PortTraffic aggregates by local or remote port + protocol.
type PortTraffic struct {
	Port      string `json:"port"`
	Proto     string `json:"proto"` // tcp | udp
	Side      string `json:"side"`  // local | remote
	Conns     int    `json:"conns"`
	BytesSent int64  `json:"bytes_sent,omitempty"`
	BytesRecv int64  `json:"bytes_recv,omitempty"`
}

// ConnTraffic is one socket row.
type ConnTraffic struct {
	Proto      string  `json:"proto"`
	State      string  `json:"state"`
	LocalIP    string  `json:"local_ip"`
	LocalPort  string  `json:"local_port"`
	RemoteIP   string  `json:"remote_ip"`
	RemotePort string  `json:"remote_port"`
	BytesSent  int64   `json:"bytes_sent,omitempty"`
	BytesRecv  int64   `json:"bytes_recv,omitempty"`
	SendBps    float64 `json:"send_bps,omitempty"`
}

// VersionInfo is /v1/version.
type VersionInfo struct {
	Version string `json:"version"`
}

// ErrorBody is the standard API error envelope.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

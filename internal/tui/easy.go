package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/reloadlife/netpolicyd/internal/apply"
	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

// Easy-mode tabs — plain-language, few fields.
const (
	easyHome     = 0
	easyFastpath = 1 // outbound: client → tunnel
	easyMasq     = 2 // easy masquerade (+ optional full return path)
	easyAccess   = 3 // allow / block ports & IPs (supports IP lists)
	easyLists    = 4 // named IP/CIDR lists
	easyConfig   = 5 // IP forward, routing, routes
	easySpeed    = 6
	easyTraffic  = 7 // live throughput: iface / ip / port / connections
	easyLive     = 8 // host dataplane dump
	easyCount    = 9

	// legacy aliases
	easyTunnel = easyFastpath
	easyReturn = easyMasq
)

// form kinds used only by easy wizards
const (
	formEasyEgress formKind = iota + 100
	formEasyAccess
	formEasySpeed
	formEasyReturn
	formEasyConfig
	formEasyMasq
	formEasyList
	formEasyListAdd
	formEasyRoute
	formEasyGateway
)

func (m *rootModel) setUIMode(easy bool) {
	if easy {
		m.uiEasy = true
		m.tab = easyHome
	} else {
		m.uiEasy = false
		m.tab = tabStatus
	}
	m.cursor = 0
	m.scroll = 0
	m.mode = modeList
	m.clearDetail()
	m.form.err = ""
}

func (m rootModel) toggleUIMode() (tea.Model, tea.Cmd) {
	m.setUIMode(!m.uiEasy)
	label := "advanced mode"
	if m.uiEasy {
		label = "easy mode"
	}
	m, flash := m.setFlash("switched to " + label)
	var fetch tea.Cmd
	m, fetch = m.beginFetch()
	return m, tea.Batch(flash, fetch)
}

func (m rootModel) easyTabCount() int { return easyCount }

func (m rootModel) easyRowCount() int {
	switch m.tab {
	case easyFastpath:
		return len(m.easyEgressList())
	case easyMasq:
		return len(m.easyReturnList())
	case easyAccess:
		return len(m.easyAccessList())
	case easyLists:
		return len(m.ipLists)
	case easyConfig:
		return len(m.routes) // show simple routes
	case easySpeed:
		return len(m.tc)
	case easyTraffic:
		return m.trafficRowCount()
	case easyLive:
		return m.planeLineCount()
	default:
		return 0
	}
}

func (m rootModel) easyListNames() []string {
	out := []string{"(none)"}
	for _, l := range m.ipLists {
		out = append(out, l.Name)
	}
	return out
}

// easyReturnList = NAT rules (return path masq/snat) + established firewall markers.
func (m rootModel) easyReturnList() []pkgapi.NATSpec {
	return m.nat
}

// easyEgressList = policies with action egress (the main “send via tunnel” story).
func (m rootModel) easyEgressList() []pkgapi.PolicyRule {
	var out []pkgapi.PolicyRule
	for _, p := range m.policies {
		if p.Action == pkgapi.ActionEgress {
			out = append(out, p)
		}
	}
	return out
}

// easyAccessList = simple allow/deny firewall rules (filter + accept/drop/reject).
func (m rootModel) easyAccessList() []pkgapi.FirewallRule {
	var out []pkgapi.FirewallRule
	for _, f := range m.firewall {
		act := strings.ToLower(f.Action)
		if f.Table == "filter" && (act == "accept" || act == "drop" || act == "reject") {
			out = append(out, f)
		}
	}
	return out
}

func (m rootModel) handleEasyListKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m, tea.Quit
	case "m", "M":
		return m.toggleUIMode()
	case "1":
		m.tab, m.cursor, m.scroll = easyHome, 0, 0
	case "2":
		m.tab, m.cursor, m.scroll = easyFastpath, 0, 0
	case "3":
		m.tab, m.cursor, m.scroll = easyMasq, 0, 0
	case "4":
		m.tab, m.cursor, m.scroll = easyAccess, 0, 0
	case "5":
		m.tab, m.cursor, m.scroll = easyLists, 0, 0
	case "6":
		m.tab, m.cursor, m.scroll = easyConfig, 0, 0
	case "7":
		m.tab, m.cursor, m.scroll = easySpeed, 0, 0
	case "8":
		m.tab, m.cursor, m.scroll = easyTraffic, 0, 0
		m.trafSec = trafSecIface
		var fetch tea.Cmd
		m, fetch = m.beginFetch()
		return m, fetch
	case "9":
		m.tab, m.cursor, m.scroll = easyLive, 0, 0
		var fetch tea.Cmd
		m, fetch = m.beginFetch()
		return m, fetch
	case "tab", "right":
		m.tab = (m.tab + 1) % easyCount
		m.cursor, m.scroll = 0, 0
		if m.tab == easyTraffic || m.tab == easyLive {
			var fetch tea.Cmd
			m, fetch = m.beginFetch()
			return m, fetch
		}
	case "shift+tab", "left", "h":
		m.tab = (m.tab + easyCount - 1) % easyCount
		m.cursor, m.scroll = 0, 0
		if m.tab == easyTraffic || m.tab == easyLive {
			var fetch tea.Cmd
			m, fetch = m.beginFetch()
			return m, fetch
		}
	case "[":
		if m.tab == easyTraffic {
			m.trafSec = (m.trafSec + 3) % 4
			m.cursor, m.scroll = 0, 0
		}
	case "]":
		if m.tab == easyTraffic {
			m.trafSec = (m.trafSec + 1) % 4
			m.cursor, m.scroll = 0, 0
		}
	case "j", "down":
		if m.tab == easyLive || m.tab == easyHome {
			m.scroll++
		} else if m.cursor < m.easyRowCount()-1 {
			m.cursor++
		}
	case "k", "up":
		if m.tab == easyLive || m.tab == easyHome {
			m.scroll = max(0, m.scroll-1)
		} else if m.cursor > 0 {
			m.cursor--
		}
	case "pgdown":
		if m.tab == easyLive {
			m.scroll += 10
		} else {
			m.cursor = max(0, min(m.easyRowCount()-1, m.cursor+10))
		}
	case "pgup":
		if m.tab == easyLive {
			m.scroll = max(0, m.scroll-10)
		} else {
			m.cursor = max(0, m.cursor-10)
		}
	case "r":
		m, fetch := m.beginFetch()
		return m, fetch
	case "a":
		return m.startMutate(doApply(m.cfg.Client, false))
	case "A":
		return m.startMutate(doApply(m.cfg.Client, true))
	case "f":
		// toggle / enable IP forward
		if m.tab == easyHome || m.tab == easyConfig {
			return m.startMutate(doSetIPForward(m.cfg.Client, !m.status.IPForward))
		}
	case "g":
		// enable gateway / IP routing
		if m.tab == easyConfig || m.tab == easyHome {
			return m.openEasyGateway()
		}
	case "p":
		if m.tab == easyConfig || m.tab == easyMasq {
			return m.startMutate(doUpsertSysctl(m.cfg.Client, pkgapi.SysctlSpec{
				Key: "net.ipv4.conf.all.rp_filter", Value: "2", Managed: true,
			}))
		}
	case "n":
		switch m.tab {
		case easyFastpath:
			return m.openEasyEgress()
		case easyMasq:
			return m.openEasyMasq()
		case easyAccess:
			return m.openEasyAccess()
		case easyLists:
			return m.openEasyListCreate()
		case easyConfig:
			return m.openEasyConfig()
		case easySpeed:
			return m.openEasySpeed()
		}
	case "i":
		// add IPs to selected list
		if m.tab == easyLists && m.cursor < len(m.ipLists) {
			return m.openEasyListAdd(m.ipLists[m.cursor])
		}
	case "u":
		// easy route
		if m.tab == easyConfig {
			return m.openEasyRoute()
		}
	case "b", "B":
		if m.tab == easyAccess || m.tab == easyHome {
			m.tab = easyAccess
			return m.openEasyAccessPreset("block", "to this host", "custom")
		}
	case "o", "O":
		if m.tab == easyAccess || m.tab == easyHome {
			m.tab = easyAccess
			return m.openEasyAccessPreset("allow", "to this host", "ssh (22/tcp)")
		}
	case "enter", " ":
		return m.openEasyDetail()
	case "D":
		return m.confirmEasyDelete()
	case "t":
		return m.easyToggleSelected()
	}
	return m, nil
}

func (m rootModel) openEasyDetail() (tea.Model, tea.Cmd) {
	switch m.tab {
	case easyFastpath:
		list := m.easyEgressList()
		if m.cursor < len(list) {
			p := list[m.cursor]
			m.detailPolicy = &p
			m.mode = modeDetail
		}
	case easyMasq:
		list := m.easyReturnList()
		if m.cursor < len(list) {
			n := list[m.cursor]
			m.detailNAT = &n
			m.mode = modeDetail
		}
	case easyLists:
		// show entries in detail-ish panel via flash note — use scroll list only
	case easyAccess:
		list := m.easyAccessList()
		if m.cursor < len(list) {
			f := list[m.cursor]
			m.detailFirewall = &f
			m.mode = modeDetail
		}
	case easySpeed:
		if m.cursor < len(m.tc) {
			t := m.tc[m.cursor]
			m.detailTC = &t
			m.mode = modeDetail
		}
	case easyHome:
		if m.lastApply != nil {
			m.mode = modeApply
			m.scroll = 0
		}
	}
	return m, nil
}

func (m rootModel) confirmEasyDelete() (tea.Model, tea.Cmd) {
	switch m.tab {
	case easyFastpath:
		list := m.easyEgressList()
		if m.cursor < len(list) {
			p := list[m.cursor]
			m.confirm = confirmDelPolicy
			m.confirmText = fmt.Sprintf("Remove fastpath “%s”?", p.Name)
			m.confirmArg = p.ID
			m.mode = modeConfirm
		}
	case easyMasq:
		list := m.easyReturnList()
		if m.cursor < len(list) {
			n := list[m.cursor]
			m.confirm = confirmDelNAT
			m.confirmText = fmt.Sprintf("Remove masq/NAT %s on %s?", n.Kind, n.OutIface)
			m.confirmArg = n.ID
			m.mode = modeConfirm
		}
	case easyLists:
		if m.cursor < len(m.ipLists) {
			l := m.ipLists[m.cursor]
			m.confirm = confirmDelIPList
			m.confirmText = fmt.Sprintf("Delete IP list “%s” (%d entries)?", l.Name, len(l.Entries))
			m.confirmArg = l.ID
			m.mode = modeConfirm
		}
	case easyAccess:
		list := m.easyAccessList()
		if m.cursor < len(list) {
			f := list[m.cursor]
			m.confirm = confirmDelFirewall
			m.confirmText = fmt.Sprintf("Remove access rule “%s”?", firstNonEmpty(f.Name, f.ID))
			m.confirmArg = f.ID
			m.mode = modeConfirm
		}
	case easySpeed:
		if m.cursor < len(m.tc) {
			t := m.tc[m.cursor]
			m.confirm = confirmDelTC
			m.confirmText = fmt.Sprintf("Remove speed limit “%s”?", firstNonEmpty(t.Name, t.ID))
			m.confirmArg = t.ID
			m.mode = modeConfirm
		}
	}
	return m, nil
}

func (m rootModel) easyToggleSelected() (tea.Model, tea.Cmd) {
	switch m.tab {
	case easyFastpath:
		list := m.easyEgressList()
		if m.cursor < len(list) {
			p := list[m.cursor]
			return m.startMutate(doTogglePolicy(m.cfg.Client, p.ID, !p.Enabled))
		}
	}
	return m, nil
}

// --- Easy forms ---

func easyEgressFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "e.g. user4-fastpath"},
		{Key: "who", Label: "Who (CIDR)", Hint: "client IP — 10.77.0.4/32"},
		{Key: "via", Label: "Via (out)", Hint: "gre-lab, wg-exit, ens18 — egress iface"},
		{Key: "ip_forward", Label: "IP forward", Kind: fieldBool, Hint: "turn on forwarding (needed for through-host)"},
		{Key: "with_return", Label: "+ Return NAT", Kind: fieldBool, Hint: "also set up masquerade on Via (return path)"},
	}
}

func easyReturnFields() []fieldDef {
	return []fieldDef{
		{Key: "who", Label: "Who (CIDR)", Hint: "client prefix that needs replies — 10.77.0.0/24"},
		{Key: "out", Label: "Out iface", Hint: "gre-lab / ens18 — where traffic leaves"},
		{Key: "kind", Label: "NAT kind", Kind: fieldSelect,
			Options: []string{"masquerade", "snat"},
			Hint:    "masquerade = hide behind out iface IP"},
		{Key: "to_source", Label: "SNAT addr", Hint: "only if kind=snat — public IP"},
		{Key: "established", Label: "Allow replies", Kind: fieldBool,
			Hint: "accept established,related on forward+input"},
		{Key: "rp_filter", Label: "Loose RPF", Kind: fieldBool,
			Hint: "rp_filter=2 so asymmetric return is accepted"},
		{Key: "name", Label: "Name", Hint: "optional label"},
	}
}

func easyConfigFields() []fieldDef {
	return []fieldDef{
		{Key: "ip_forward", Label: "IP forward", Kind: fieldBool, Hint: "net.ipv4.ip_forward"},
		{Key: "ip6_forward", Label: "IPv6 forward", Kind: fieldBool, Hint: "net.ipv6.conf.all.forwarding"},
		{Key: "rp_filter", Label: "rp_filter", Kind: fieldSelect,
			Options: []string{"leave", "strict (1)", "loose (2)", "off (0)"},
			Hint:    "loose recommended with tunnels / multi-path"},
		{Key: "rp_dev", Label: "rp_filter dev", Hint: "optional iface for per-dev rpf (e.g. gre-lab)"},
		{Key: "apply_now", Label: "Apply now", Kind: fieldBool, Hint: "run reconcile after save"},
	}
}

func easyAccessFields(listNames []string) []fieldDef {
	if len(listNames) == 0 {
		listNames = []string{"(none)"}
	}
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "optional — auto from intent + port/IP"},
		{Key: "do", Label: "Do", Kind: fieldSelect,
			Options: []string{"allow", "block"},
			Hint:    "allow = accept · block = drop"},
		{Key: "direction", Label: "Direction", Kind: fieldSelect,
			Options: []string{
				"to this host",
				"from this host",
				"through this host",
			},
			Hint: "where the packet is evaluated"},
		{Key: "service", Label: "Service", Kind: fieldSelect,
			Options: []string{
				"custom",
				"ssh (22/tcp)",
				"http (80/tcp)",
				"https (443/tcp)",
				"dns (53/udp)",
				"dns (53/tcp)",
				"rdp (3389/tcp)",
				"wireguard (51820/udp)",
				"openvpn (1194/udp)",
				"all traffic (any)",
			},
			Hint: "preset fills port+protocol"},
		{Key: "port", Label: "Port(s)", Hint: "22 · 80,443 · 8000-8100 · empty=any"},
		{Key: "protocol", Label: "Protocol", Kind: fieldSelect,
			Options: []string{"tcp", "udp", "icmp", "any"}},
		{Key: "from_list", Label: "From list", Kind: fieldSelect, Options: listNames,
			Hint: "IP list for source (overrides From IP if set)"},
		{Key: "from_ip", Label: "From IP", Hint: "or type IP/CIDR — 10.77.0.4"},
		{Key: "to_list", Label: "To list", Kind: fieldSelect, Options: listNames,
			Hint: "IP list for destination"},
		{Key: "to_ip", Label: "To IP", Hint: "or type dest CIDR"},
		{Key: "in_iface", Label: "In iface", Hint: "optional — wg0, gre-lab"},
		{Key: "out_iface", Label: "Out iface", Hint: "optional"},
	}
}

func easyMasqFields(listNames []string) []fieldDef {
	if len(listNames) == 0 {
		listNames = []string{"(none)"}
	}
	return []fieldDef{
		{Key: "who", Label: "Who (CIDR)", Hint: "10.77.0.0/24 — or leave empty if using list"},
		{Key: "who_list", Label: "Who list", Kind: fieldSelect, Options: listNames,
			Hint: "masquerade every IP/CIDR in this list"},
		{Key: "out", Label: "Out iface", Hint: "gre-lab · ens18 · wg0"},
		{Key: "full_return", Label: "Full return", Kind: fieldBool,
			Hint: "also established + loose rp_filter"},
		{Key: "name", Label: "Name", Hint: "optional"},
	}
}

func easyListCreateFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "List name", Hint: "clients · blocked · office"},
		{Key: "entries", Label: "IPs/CIDRs", Hint: "comma or space: 10.0.0.1, 10.1.0.0/24"},
		{Key: "comment", Label: "Comment", Hint: "optional"},
	}
}

func easyListAddFields() []fieldDef {
	return []fieldDef{
		{Key: "entries", Label: "Add IPs", Hint: "10.77.0.5  10.77.0.6/32  192.168.1.0/24"},
	}
}

func easyRouteFields() []fieldDef {
	return []fieldDef{
		{Key: "dst", Label: "Destination", Hint: "default · 0.0.0.0/0 · 10.0.0.0/8"},
		{Key: "via", Label: "Via gateway", Hint: "optional next hop IP"},
		{Key: "dev", Label: "Device", Hint: "gre-lab · ens18"},
		{Key: "table", Label: "Table", Hint: "main · 100"},
		{Key: "metric", Label: "Metric", Hint: "optional"},
	}
}

func easyGatewayFields() []fieldDef {
	return []fieldDef{
		{Key: "clients", Label: "Clients", Hint: "optional CIDR allowed to route through"},
		{Key: "in_iface", Label: "In iface", Hint: "optional — wg0"},
		{Key: "out_iface", Label: "Out iface", Hint: "optional — ens18 / gre-lab"},
	}
}

func easySpeedFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "e.g. user4-50m"},
		{Key: "who", Label: "Who (CIDR)", Hint: "10.77.0.4/32"},
		{Key: "device", Label: "On device", Hint: "gre-lab, wg0, ens18"},
		{Key: "rate_tx", Label: "Upload", Hint: "50mbit · 10M · 0=unlimited"},
		{Key: "rate_rx", Label: "Download", Hint: "50mbit · 0=unlimited"},
	}
}

func (m rootModel) openEasyEgress() (tea.Model, tea.Cmd) {
	m.form = newForm("Fastpath — send via tunnel", easyEgressFields(), map[string]string{
		"ip_forward": "y", "with_return": "y",
	})
	m.form.note = "Outbound fast path: ip rule + table default via tunnel. Optional return NAT."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyEgress
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyReturn() (tea.Model, tea.Cmd) {
	// Prefill from selected fastpath if any
	who, out := "", ""
	list := m.easyEgressList()
	if m.cursor < len(list) && m.tab == easyReturn {
		// ignore
	}
	if len(list) > 0 {
		p := list[0]
		who = p.SourceCIDR
		if who == "" && len(p.Subjects) > 0 {
			who = p.Subjects[0].Value
		}
		out = p.EgressName
	}
	m.form = newForm("Return path — replies work", easyReturnFields(), map[string]string{
		"who": who, "out": out, "kind": "masquerade",
		"established": "y", "rp_filter": "y",
	})
	m.form.note = "NAT out + allow established replies + loose reverse-path filter."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyReturn
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyConfig() (tea.Model, tea.Cmd) {
	fwd := "n"
	if m.status.IPForward {
		fwd = "y"
	}
	m.form = newForm("Host configuration", easyConfigFields(), map[string]string{
		"ip_forward": fwd, "ip6_forward": "y",
		"rp_filter": "loose (2)", "apply_now": "y",
	})
	m.form.note = "Kernel knobs for gateway duty. f toggles IP forward on Config/Home without a form."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyConfig
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyAccess() (tea.Model, tea.Cmd) {
	return m.openEasyAccessPreset("allow", "to this host", "custom")
}

// openEasyAccessPreset starts the access wizard with defaults (used by n / b / o keys).
func (m rootModel) openEasyAccessPreset(do, direction, service string) (tea.Model, tea.Cmd) {
	if do == "" {
		do = "allow"
	}
	if direction == "" {
		direction = "to this host"
	}
	if service == "" {
		service = "custom"
	}
	vals := map[string]string{
		"do": do, "direction": direction, "service": service, "protocol": "tcp",
		"from_list": "(none)", "to_list": "(none)",
	}
	if p, proto, ok := easyServicePreset(service); ok {
		vals["port"] = p
		vals["protocol"] = proto
	}
	m.form = newForm("Allow / block · ports & IPs & lists", easyAccessFields(m.easyListNames()), vals)
	m.form.note = "Use From list / To list for many IPs, or type a single From IP."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyAccess
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyMasq() (tea.Model, tea.Cmd) {
	m.form = newForm("Easy masquerade", easyMasqFields(m.easyListNames()), map[string]string{
		"who_list": "(none)", "full_return": "n",
	})
	m.form.note = "Hide source behind out iface. Who list = many nets at once."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyMasq
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyListCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New IP list", easyListCreateFields(), nil)
	m.form.note = "Name a set of IPs/CIDRs, then use it in Block/Allow or Masq."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyList
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyListAdd(l pkgapi.IPList) (tea.Model, tea.Cmd) {
	m.form = newForm("Add to list · "+l.Name, easyListAddFields(), nil)
	m.form.note = fmt.Sprintf("list has %d entries now", len(l.Entries))
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyListAdd
	m.formCreate = true
	m.editID = l.ID
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyRoute() (tea.Model, tea.Cmd) {
	m.form = newForm("Easy route", easyRouteFields(), map[string]string{
		"dst": "default", "table": "main",
	})
	m.form.note = "ip route replace …"
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyRoute
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasyGateway() (tea.Model, tea.Cmd) {
	m.form = newForm("Allow IP routing (gateway)", easyGatewayFields(), nil)
	m.form.note = "Turns on IP forward + established + optional client forward path."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasyGateway
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openEasySpeed() (tea.Model, tea.Cmd) {
	m.form = newForm("Speed limit", easySpeedFields(), map[string]string{
		"rate_tx": "50mbit", "rate_rx": "50mbit",
	})
	m.form.note = "Caps bandwidth for a client CIDR on a device (HTB + police)."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formEasySpeed
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) submitEasyForm() (tea.Model, tea.Cmd) {
	switch m.formKind {
	case formEasyEgress:
		return m.submitEasyEgress()
	case formEasyReturn, formEasyMasq:
		if m.formKind == formEasyMasq {
			return m.submitEasyMasq()
		}
		return m.submitEasyReturn()
	case formEasyConfig:
		return m.submitEasyConfig()
	case formEasyAccess:
		return m.submitEasyAccess()
	case formEasySpeed:
		return m.submitEasySpeed()
	case formEasyList:
		return m.submitEasyListCreate()
	case formEasyListAdd:
		return m.submitEasyListAdd()
	case formEasyRoute:
		return m.submitEasyRoute()
	case formEasyGateway:
		return m.submitEasyGateway()
	default:
		m.mode = modeList
		return m, nil
	}
}

func (m rootModel) submitEasyMasq() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	who := normalizeEasyIP(v["who"])
	whoList := v["who_list"]
	if whoList == "(none)" {
		whoList = ""
	}
	out := strings.TrimSpace(v["out"])
	if out == "" {
		m.form.err = "out iface required"
		return m, nil
	}
	if who == "" && whoList == "" {
		m.form.err = "set Who (CIDR) or Who list"
		return m, nil
	}
	name := strings.TrimSpace(v["name"])
	if name == "" {
		name = "masq-" + out
	}
	if truthy(v["full_return"]) {
		// reuse return bundle
		if who == "" && whoList != "" {
			// expand client-side to CIDR any for established rules; NAT uses list
			who = "0.0.0.0/0"
		}
		nat := pkgapi.NATSpec{
			Enabled: true, Kind: "masquerade",
			SourceCIDR: who, SourceList: whoList, OutIface: out,
			Comment: "easy:masq " + name,
		}
		// if only list, clear source cidr for expand
		if whoList != "" {
			nat.SourceCIDR = ""
		}
		fws := []pkgapi.FirewallRule{
			{Name: name + "-est-fwd", Enabled: true, Priority: 10, Backend: "auto",
				Table: "filter", Chain: "forward", Action: "accept", CtState: "established,related",
				Comment: "easy:return established"},
			{Name: name + "-est-in", Enabled: true, Priority: 10, Backend: "auto",
				Table: "filter", Chain: "input", Action: "accept", CtState: "established,related",
				Comment: "easy:return established"},
		}
		sys := []pkgapi.SysctlSpec{
			{Key: "net.ipv4.conf.all.rp_filter", Value: "2", Managed: true},
			{Key: "net.ipv4.conf.default.rp_filter", Value: "2", Managed: true},
		}
		return m.startMutate(doEasyReturnBundle(m.cfg.Client, nat, fws, sys))
	}
	nat := pkgapi.NATSpec{
		Enabled: true, Kind: "masquerade",
		SourceCIDR: who, SourceList: whoList, OutIface: out,
		Comment: "easy:masq " + name,
	}
	if whoList != "" {
		nat.SourceCIDR = ""
	}
	return m.startMutate(doCreateNAT(m.cfg.Client, nat))
}

func (m rootModel) submitEasyListCreate() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	name := strings.TrimSpace(v["name"])
	if name == "" {
		m.form.err = "list name required"
		return m, nil
	}
	entries := splitEasyListEntries(v["entries"])
	l := pkgapi.IPList{Name: name, Entries: entries, Comment: v["comment"]}
	return m.startMutate(doCreateIPList(m.cfg.Client, l))
}

func (m rootModel) submitEasyListAdd() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	entries := splitEasyListEntries(v["entries"])
	if len(entries) == 0 {
		m.form.err = "add at least one IP or CIDR"
		return m, nil
	}
	if m.editID == "" {
		m.form.err = "no list selected"
		return m, nil
	}
	return m.startMutate(doAppendIPList(m.cfg.Client, m.editID, entries))
}

func (m rootModel) submitEasyRoute() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	dst := strings.TrimSpace(v["dst"])
	if dst == "" {
		m.form.err = "destination required"
		return m, nil
	}
	metric, _ := parseIntField(v["metric"])
	table := strings.TrimSpace(v["table"])
	if table == "" {
		table = "main"
	}
	rt := pkgapi.RouteSpec{
		Dst: dst, Gateway: strings.TrimSpace(v["via"]), Device: strings.TrimSpace(v["dev"]),
		Table: table, Metric: metric, Enabled: true, Protocol: "netpolicyd",
	}
	return m.startMutate(doCreateRoute(m.cfg.Client, rt))
}

func (m rootModel) submitEasyGateway() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	clients := normalizeEasyIP(v["clients"])
	return m.startMutate(doEasyGateway(m.cfg.Client, clients,
		strings.TrimSpace(v["in_iface"]), strings.TrimSpace(v["out_iface"])))
}

func splitEasyListEntries(s string) []string {
	s = strings.ReplaceAll(s, "\n", ",")
	s = strings.ReplaceAll(s, ";", ",")
	s = strings.ReplaceAll(s, " ", ",")
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (m rootModel) submitEasyEgress() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	who := normalizeEasyIP(v["who"])
	via := strings.TrimSpace(v["via"])
	name := strings.TrimSpace(v["name"])
	if who == "" {
		m.form.err = "who (CIDR) is required — e.g. 10.77.0.4/32"
		return m, nil
	}
	if via == "" {
		m.form.err = "via (out iface) is required — e.g. gre-lab"
		return m, nil
	}
	if name == "" {
		name = "fastpath-" + via + "-" + strings.ReplaceAll(who, "/", "-")
	}
	en := true
	req := pkgapi.PolicyCreateRequest{
		Name: name, Priority: 100, Enabled: &en,
		Subjects:    []pkgapi.Subject{{Kind: "cidr", Value: who}},
		Destination: pkgapi.Destination{Kind: "any", Value: "0.0.0.0/0"},
		Action:      pkgapi.ActionEgress,
		EgressName:  via,
		SourceCIDR:  who,
		Description: "easy:fastpath via " + via,
	}
	var nat *pkgapi.NATSpec
	if truthy(v["with_return"]) {
		nat = &pkgapi.NATSpec{
			Enabled: true, Kind: "masquerade",
			SourceCIDR: who, OutIface: via,
			Comment: "easy:return for " + name,
		}
	}
	return m.startMutate(doEasyFastpathBundle(m.cfg.Client, req, truthy(v["ip_forward"]), nat))
}

func (m rootModel) submitEasyReturn() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	who := normalizeEasyIP(v["who"])
	out := strings.TrimSpace(v["out"])
	kind := v["kind"]
	if who == "" {
		m.form.err = "who (CIDR) required — clients that need replies"
		return m, nil
	}
	if out == "" {
		m.form.err = "out iface required"
		return m, nil
	}
	if kind == "snat" && strings.TrimSpace(v["to_source"]) == "" {
		m.form.err = "SNAT addr required when kind=snat"
		return m, nil
	}
	name := strings.TrimSpace(v["name"])
	if name == "" {
		name = "return-" + out
	}
	nat := pkgapi.NATSpec{
		Enabled: true, Kind: kind,
		SourceCIDR: who, OutIface: out,
		ToSource: strings.TrimSpace(v["to_source"]),
		Comment:  "easy:return " + name,
	}
	var fws []pkgapi.FirewallRule
	if truthy(v["established"]) {
		// high priority so replies always pass
		fws = append(fws,
			pkgapi.FirewallRule{
				Name: name + "-est-fwd", Enabled: true, Priority: 10,
				Backend: "auto", Table: "filter", Chain: "forward",
				Action: "accept", CtState: "established,related",
				Comment: "easy:return established forward",
			},
			pkgapi.FirewallRule{
				Name: name + "-est-in", Enabled: true, Priority: 10,
				Backend: "auto", Table: "filter", Chain: "input",
				Action: "accept", CtState: "established,related",
				Comment: "easy:return established input",
			},
			// allow forward from clients toward out (new sessions)
			pkgapi.FirewallRule{
				Name: name + "-fwd-clients", Enabled: true, Priority: 40,
				Backend: "auto", Table: "filter", Chain: "forward",
				Action: "accept", Source: who, OutIface: out,
				Comment: "easy:return forward clients out",
			},
		)
	}
	var sys []pkgapi.SysctlSpec
	if truthy(v["rp_filter"]) {
		sys = append(sys,
			pkgapi.SysctlSpec{Key: "net.ipv4.conf.all.rp_filter", Value: "2", Managed: true},
			pkgapi.SysctlSpec{Key: "net.ipv4.conf.default.rp_filter", Value: "2", Managed: true},
		)
		// per-device when possible
		sys = append(sys, pkgapi.SysctlSpec{
			Key: "net.ipv4.conf." + sanitizeSysctlDev(out) + ".rp_filter", Value: "2", Managed: true,
		})
	}
	return m.startMutate(doEasyReturnBundle(m.cfg.Client, nat, fws, sys))
}

func (m rootModel) submitEasyConfig() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	enableFwd := truthy(v["ip_forward"])
	// chain ops into one action
	return m.startMutate(doAction(func(ctx context.Context) error {
		c := m.cfg.Client
		if err := c.SetIPForward(ctx, enableFwd); err != nil {
			return err
		}
		if truthy(v["ip6_forward"]) {
			if _, err := c.UpsertSysctl(ctx, pkgapi.SysctlSpec{
				Key: "net.ipv6.conf.all.forwarding", Value: "1", Managed: true,
			}); err != nil {
				return err
			}
		} else {
			if _, err := c.UpsertSysctl(ctx, pkgapi.SysctlSpec{
				Key: "net.ipv6.conf.all.forwarding", Value: "0", Managed: true,
			}); err != nil {
				return err
			}
		}
		switch v["rp_filter"] {
		case "strict (1)", "loose (2)", "off (0)":
			val := "2"
			if strings.HasPrefix(v["rp_filter"], "strict") {
				val = "1"
			} else if strings.HasPrefix(v["rp_filter"], "off") {
				val = "0"
			}
			if _, err := c.UpsertSysctl(ctx, pkgapi.SysctlSpec{
				Key: "net.ipv4.conf.all.rp_filter", Value: val, Managed: true,
			}); err != nil {
				return err
			}
			if _, err := c.UpsertSysctl(ctx, pkgapi.SysctlSpec{
				Key: "net.ipv4.conf.default.rp_filter", Value: val, Managed: true,
			}); err != nil {
				return err
			}
			if dev := sanitizeSysctlDev(v["rp_dev"]); dev != "" {
				if _, err := c.UpsertSysctl(ctx, pkgapi.SysctlSpec{
					Key: "net.ipv4.conf." + dev + ".rp_filter", Value: val, Managed: true,
				}); err != nil {
					return err
				}
			}
		}
		if truthy(v["apply_now"]) {
			if _, err := c.Apply(ctx, false); err != nil {
				return err
			}
		}
		return nil
	}, "configuration saved"))
}

func sanitizeSysctlDev(dev string) string {
	dev = strings.TrimSpace(dev)
	// sysctl uses / for . in iface names with dots — keep simple alnum-_
	var b strings.Builder
	for _, r := range dev {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (m rootModel) submitEasyAccess() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	service := v["service"]
	portStr := strings.TrimSpace(v["port"])
	proto := strings.ToLower(strings.TrimSpace(v["protocol"]))

	// Service preset fills port/proto when not "custom".
	if p, pr, ok := easyServicePreset(service); ok {
		if strings.HasPrefix(strings.ToLower(service), "all traffic") {
			portStr = ""
			proto = "any"
		} else {
			if portStr == "" {
				portStr = p
			}
			proto = pr
		}
	}

	if proto == "any" || proto == "all" {
		proto = ""
	}
	fromIP := normalizeEasyIP(v["from_ip"])
	toIP := normalizeEasyIP(v["to_ip"])
	fromList := v["from_list"]
	toList := v["to_list"]
	if fromList == "(none)" {
		fromList = ""
	}
	if toList == "(none)" {
		toList = ""
	}
	inIf := strings.TrimSpace(v["in_iface"])
	outIf := strings.TrimSpace(v["out_iface"])
	name := strings.TrimSpace(v["name"])
	ports := splitEasyPorts(portStr)
	do := strings.ToLower(v["do"])
	if do == "" {
		do = "allow"
	}

	allTraffic := strings.HasPrefix(strings.ToLower(service), "all traffic")
	if !allTraffic && fromIP == "" && toIP == "" && fromList == "" && toList == "" && len(ports) == 0 && inIf == "" && outIf == "" {
		m.form.err = "set From/To IP or list, Port(s), iface — or pick a Service"
		return m, nil
	}
	if len(ports) > 0 && proto == "" {
		proto = "tcp"
	}
	if proto == "icmp" {
		ports = nil
	}

	action := "accept"
	if do == "block" {
		action = "drop"
	}
	chain := "input"
	switch v["direction"] {
	case "from this host":
		chain = "output"
	case "through this host":
		chain = "forward"
	}

	prio := 100
	if action == "drop" {
		prio = 50 // blocks before default allows
	}

	baseName := name
	if baseName == "" {
		baseName = easyAccessAutoName(do, chain, fromIP, toIP, ports, proto)
	}

	if len(ports) == 0 {
		ports = []string{""}
	}
	// If using lists, keep one rule per port with list refs (apply expands lists).
	rules := make([]pkgapi.FirewallRule, 0, len(ports))
	for _, port := range ports {
		n := baseName
		if len(ports) > 1 && port != "" {
			n = baseName + "-" + port
		}
		src, dst := fromIP, toIP
		if fromList != "" {
			src = ""
		}
		if toList != "" {
			dst = ""
		}
		rules = append(rules, pkgapi.FirewallRule{
			Name: n, Enabled: true, Priority: prio,
			Backend: "auto", Table: "filter", Chain: chain,
			Action: action, Protocol: proto,
			Source: src, Dest: dst, SourceList: fromList, DestList: toList,
			Dport: port, InIface: inIf, OutIface: outIf,
			Comment: "easy:" + do,
		})
	}
	if len(rules) == 1 {
		return m.startMutate(doCreateFirewall(m.cfg.Client, rules[0]))
	}
	return m.startMutate(doCreateFirewallMany(m.cfg.Client, rules))
}

// easyServicePreset maps Service select → port, protocol.
func easyServicePreset(service string) (port, proto string, ok bool) {
	s := strings.ToLower(strings.TrimSpace(service))
	switch {
	case s == "" || s == "custom":
		return "", "", false
	case strings.HasPrefix(s, "all traffic"):
		return "", "any", true
	case strings.HasPrefix(s, "ssh"):
		return "22", "tcp", true
	case strings.HasPrefix(s, "http ") || s == "http (80/tcp)":
		return "80", "tcp", true
	case strings.HasPrefix(s, "https"):
		return "443", "tcp", true
	case strings.Contains(s, "53/udp") || (strings.HasPrefix(s, "dns") && strings.Contains(s, "udp")):
		return "53", "udp", true
	case strings.Contains(s, "53/tcp") || (strings.HasPrefix(s, "dns") && strings.Contains(s, "tcp")):
		return "53", "tcp", true
	case strings.HasPrefix(s, "rdp"):
		return "3389", "tcp", true
	case strings.HasPrefix(s, "wireguard"):
		return "51820", "udp", true
	case strings.HasPrefix(s, "openvpn"):
		return "1194", "udp", true
	default:
		return "", "", false
	}
}

// splitEasyPorts parses "22", "80,443", "8000-8100", "22 80".
func splitEasyPorts(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || strings.EqualFold(s, "any") {
		return nil
	}
	// normalize separators
	s = strings.ReplaceAll(s, ";", ",")
	s = strings.ReplaceAll(s, " ", ",")
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// normalizeEasyIP accepts bare IP → /32, leaves CIDR, clears empty/any.
func normalizeEasyIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || strings.EqualFold(s, "any") || s == "0.0.0.0/0" {
		return ""
	}
	// bare IPv4 → /32
	if !strings.Contains(s, "/") && strings.Count(s, ":") == 0 && strings.Count(s, ".") == 3 {
		return s + "/32"
	}
	// bare IPv6 → /128 (no dots, has colon)
	if !strings.Contains(s, "/") && strings.Contains(s, ":") {
		return s + "/128"
	}
	return s
}

func easyAccessAutoName(do, chain, from, to string, ports []string, proto string) string {
	parts := []string{do, chain}
	if from != "" {
		parts = append(parts, "from-"+strings.ReplaceAll(from, "/", "-"))
	}
	if to != "" {
		parts = append(parts, "to-"+strings.ReplaceAll(to, "/", "-"))
	}
	if len(ports) == 1 && ports[0] != "" {
		parts = append(parts, ports[0])
	} else if len(ports) > 1 {
		parts = append(parts, "ports")
	}
	if proto != "" && proto != "tcp" {
		parts = append(parts, proto)
	}
	return strings.Join(parts, "-")
}

func (m rootModel) submitEasySpeed() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	who := strings.TrimSpace(v["who"])
	dev := strings.TrimSpace(v["device"])
	name := strings.TrimSpace(v["name"])
	if who == "" {
		m.form.err = "who (CIDR) is required"
		return m, nil
	}
	if dev == "" {
		m.form.err = "device is required"
		return m, nil
	}
	tx, err := apply.ParseRateBitPS(v["rate_tx"])
	if err != nil {
		m.form.err = "upload: " + err.Error()
		return m, nil
	}
	rx, err := apply.ParseRateBitPS(v["rate_rx"])
	if err != nil {
		m.form.err = "download: " + err.Error()
		return m, nil
	}
	if tx <= 0 && rx <= 0 {
		m.form.err = "set upload and/or download (e.g. 50mbit)"
		return m, nil
	}
	if name == "" {
		name = "limit-" + dev
	}
	t := pkgapi.TCSpec{
		Name: name, Device: dev, Enabled: true,
		RateTxBps: tx, RateRxBps: rx,
		MatchKind: "src_cidr", MatchValue: who,
		Comment: "easy:speed",
	}
	return m.startMutate(doCreateTC(m.cfg.Client, t))
}

// --- Easy views ---

func (m rootModel) renderEasyTabs() string {
	// Short labels keep one row on typical 80–120 col terminals.
	// Full names when wide enough.
	names := []string{"Home", "Path", "Masq", "Access", "Lists", "Cfg", "Speed", "Traf", "Live"}
	if m.width >= 110 {
		names = []string{"Home", "Fastpath", "Masq", "Block/Allow", "Lists", "Config", "Speed", "Traffic", "Live"}
	}
	parts := make([]string, len(names))
	for i, n := range names {
		label := fmt.Sprintf("%d %s", i+1, n)
		if i == m.tab {
			parts[i] = tabActive.Render(label)
		} else {
			parts[i] = tabInactive.Render(label)
		}
	}
	// Mode badge lives in the header ([EASY]) — do not append here (causes wrap).
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m rootModel) easyListHelp() string {
	base := "1-9 · j/k · n new · D delete · a apply · m advanced · q quit"
	switch m.tab {
	case easyHome:
		return "1-9 · f forward · g gateway · o allow · b block · a apply · m advanced"
	case easyFastpath:
		return base + " · n = client→tunnel fastpath"
	case easyMasq:
		return base + " · n = easy masquerade (list or CIDR)"
	case easyAccess:
		return "1-9 · n rule · o SSH · b block · lists OK · a apply · m advanced"
	case easyLists:
		return "1-9 · n new list · i add IPs · D delete list · a apply · m advanced"
	case easyConfig:
		return "1-9 · n sysctls · f forward · g routing · u route · p rpf · a apply"
	case easyTraffic:
		return "8 Traffic · [/] iface|ip|port|conn · j/k · r refresh (1s) · m advanced · q quit"
	case easyLive:
		return "9 Live · j/k scroll · r refresh · m advanced · q quit"
	default:
		return base
	}
}

func (m rootModel) viewEasyHome() string {
	st := m.status
	var b strings.Builder
	b.WriteString(titleStyle.Render("Easy mode"))
	b.WriteString(dimStyle.Render("  — common jobs only. Press "))
	b.WriteString(okStyle.Render("m"))
	b.WriteString(dimStyle.Render(" for advanced (full firewall / ip / nft)."))
	b.WriteString("\n\n")

	tool := func(name string, ok bool) string {
		if ok {
			return badgeUp.Render(" " + name + " ")
		}
		return badgeDown.Render(" " + name + " ")
	}
	fwd := badgeDown.Render(" IP forward OFF ")
	if st.IPForward {
		fwd = badgeUp.Render(" IP forward ON ")
	}

	body := strings.Builder{}
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Endpoint"), valueStyle.Render(m.cfg.Endpoint))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Backend"), valueStyle.Render(st.Backend))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Version"), valueStyle.Render(st.Version))
	fmt.Fprintf(&body, "\n%s\n", sectionStyle.Render("What is configured"))
	fmt.Fprintf(&body, "  Fastpath              %d\n", len(m.easyEgressList()))
	fmt.Fprintf(&body, "  Masq / NAT            %d\n", len(m.nat))
	fmt.Fprintf(&body, "  Access rules          %d\n", len(m.easyAccessList()))
	fmt.Fprintf(&body, "  IP lists              %d\n", len(m.ipLists))
	fmt.Fprintf(&body, "  Routes                %d\n", len(m.routes))
	fmt.Fprintf(&body, "  Sysctls               %d\n", len(m.sysctls))

	b.WriteString(panelStyle.Render(
		body.String() + "\n" +
			tool("ip", st.IPAvailable) + " " +
			tool("nft", st.NFTAvailable) + " " +
			tool("iptables", st.IptablesAvailable) + " " +
			tool("tc", st.TCAvailable) + "\n\n" +
			fwd + "\n\n" +
			helpStyle.Render("Everything easy") + "\n" +
			"  2 Fastpath   client → tunnel\n" +
			"  3 Masq       easy masquerade (CIDR or IP list)\n" +
			"  4 Block/Allow  ports, IPs, lists\n" +
			"  5 Lists      create IP groups, then use in rules\n" +
			"  6 Config     f=forward  g=routing  u=route  p=rpf\n" +
			"  8 Traffic    live RX/TX per iface · IP · port · conn\n" +
			"  a Apply now  ·  m Advanced\n",
	))
	if m.traffic != nil {
		b.WriteString("\n")
		b.WriteString(panelStyle.Render(m.viewTrafficSummary()))
	}

	if m.lastApply != nil && len(m.lastApply.Commands) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionStyle.Render("Last apply (enter for full)"))
		b.WriteString("\n")
		limit := 5
		for i, c := range m.lastApply.Commands {
			if i >= limit {
				b.WriteString(dimStyle.Render(fmt.Sprintf("  … +%d more", len(m.lastApply.Commands)-limit)))
				b.WriteString("\n")
				break
			}
			b.WriteString(dimStyle.Render("  " + trunc(c, max(40, m.width-6))))
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (m rootModel) viewEasyTunnel() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Fastpath — outbound"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Client CIDR → policy route → default via tunnel. Optional +Return NAT."))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-6s %-22s %-18s %-12s %s",
		"STATE", "NAME", "WHO", "VIA", "ID")))
	b.WriteString("\n")
	list := m.easyEgressList()
	for i, p := range list {
		state := badgeDown.Render("off")
		if p.Enabled {
			state = badgeUp.Render(" on")
		}
		who := subjectsSummary(p.Subjects)
		if p.SourceCIDR != "" {
			who = p.SourceCIDR
		}
		line := fmt.Sprintf("%s %-22s %-18s %-12s %s",
			state, trunc(p.Name, 22), trunc(who, 18), trunc(p.EgressName, 12), trunc(p.ID, 12))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(list) == 0 {
		b.WriteString(helpStyle.Render("(none yet — n: Who=10.77.0.4/32  Via=gre-lab  +Return NAT=on)"))
	}
	return b.String()
}

func (m rootModel) viewEasyReturn() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Easy masquerade"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("n = masq wizard (CIDR or IP list). Full return = established + loose RPF."))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-12s %-18s %-12s %s",
		"ID", "KIND", "SOURCE", "OUT", "COMMENT")))
	b.WriteString("\n")
	for i, n := range m.nat {
		src := n.SourceCIDR
		if n.SourceList != "" {
			src = "list:" + n.SourceList
		}
		line := fmt.Sprintf("%-12s %-12s %-18s %-12s %s",
			trunc(n.ID, 12), n.Kind, trunc(src, 18), trunc(n.OutIface, 12), trunc(n.Comment, 24))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.nat) == 0 {
		b.WriteString(helpStyle.Render("(none — n: Who=10.77.0.0/24  Out=gre-lab)"))
	}
	return b.String()
}

func (m rootModel) viewEasyLists() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("IP lists"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Named groups of IPs/CIDRs. Use in Masq (Who list) and Block/Allow (From/To list)."))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-14s %-8s %s", "NAME", "COUNT", "ENTRIES")))
	b.WriteString("\n")
	for i, l := range m.ipLists {
		ents := strings.Join(l.Entries, ", ")
		line := fmt.Sprintf("%-14s %-8d %s", trunc(l.Name, 14), len(l.Entries), trunc(ents, max(20, m.width-40)))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.ipLists) == 0 {
		b.WriteString(helpStyle.Render("(none — n: name=clients  IPs=10.77.0.1,10.77.0.2)"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  then: Masq Who list=clients  ·  Block From list=clients"))
	} else {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  i = add more IPs to selected list"))
	}
	return b.String()
}

func (m rootModel) viewEasyConfig() string {
	st := m.status
	var b strings.Builder
	b.WriteString(titleStyle.Render("Config · forward · routing · routes"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("f=IP forward  g=allow routing  u=add route  n=sysctls  p=loose rpf  a=apply"))
	b.WriteString("\n\n")

	fwd := badgeDown.Render(" OFF ")
	if st.IPForward {
		fwd = badgeUp.Render(" ON  ")
	}
	body := strings.Builder{}
	fmt.Fprintf(&body, "%s %s   %s\n", labelStyle.Render("IP forward"), fwd, dimStyle.Render("f toggles"))
	fmt.Fprintf(&body, "%s %s\n", labelStyle.Render("Gateway"), dimStyle.Render("g = forward + established + client path"))
	fmt.Fprintf(&body, "\n%s\n", sectionStyle.Render("Managed sysctls"))
	if len(m.sysctls) == 0 {
		fmt.Fprintf(&body, "  %s\n", dimStyle.Render("(none)"))
	}
	for _, sc := range m.sysctls {
		fmt.Fprintf(&body, "  %s = %s\n", sc.Key, sc.Value)
	}
	b.WriteString(panelStyle.Render(body.String()))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render("Routes (u = new)"))
	b.WriteString("\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-8s %-16s %-14s %s",
		"ID", "TABLE", "DST", "VIA", "DEV")))
	b.WriteString("\n")
	for i, rt := range m.routes {
		line := fmt.Sprintf("%-12s %-8s %-16s %-14s %s",
			trunc(rt.ID, 12), trunc(rt.Table, 8), trunc(rt.Dst, 16),
			trunc(firstNonEmpty(rt.Gateway, "-"), 14), trunc(rt.Device, 10))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.routes) == 0 {
		b.WriteString(helpStyle.Render("(no routes — u: dst=default dev=gre-lab)"))
	}
	return b.String()
}

func (m rootModel) viewEasyAccess() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Allow / block · ports & IPs"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Block an IP, open a port, or both.  n=new  o=allow SSH  b=block wizard"))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-6s %-8s %-6s %-10s %-16s %-14s %-10s %s",
		"DO", "WHERE", "PROTO", "PORT", "FROM", "TO", "IFACE", "NAME")))
	b.WriteString("\n")
	list := m.easyAccessList()
	for i, f := range list {
		intent := okStyle.Render("allow")
		if f.Action == "drop" || f.Action == "reject" {
			intent = errStyle.Render("block")
		}
		where := "to-host"
		switch f.Chain {
		case "forward":
			where = "through"
		case "output":
			where = "from-host"
		}
		iface := ""
		if f.InIface != "" || f.OutIface != "" {
			iface = trunc(f.InIface, 4) + "→" + trunc(f.OutIface, 4)
		} else {
			iface = "-"
		}
		// pad intent for selection (styles add width; use plain for sel line)
		intentPlain := "allow"
		if f.Action == "drop" || f.Action == "reject" {
			intentPlain = "block"
		}
		line := fmt.Sprintf("%-6s %-8s %-6s %-10s %-16s %-14s %-10s %s",
			intentPlain, where, trunc(firstNonEmpty(f.Protocol, "any"), 6),
			trunc(firstNonEmpty(f.Dport, "*"), 10),
			trunc(firstNonEmpty(f.Source, "any"), 16),
			trunc(firstNonEmpty(f.Dest, "any"), 14),
			trunc(iface, 10),
			trunc(f.Name, 18))
		if i == m.cursor {
			line = selStyle.Render(line)
		} else if intentPlain == "block" {
			line = errStyle.Render(line)
		}
		_ = intent
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(list) == 0 {
		b.WriteString(helpStyle.Render("(none yet)"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  n     full wizard (port + IP + direction)"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  o     quick allow SSH → this host"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  b     quick block wizard (set From IP to ban a client)"))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  e.g. block From=1.2.3.4 · allow Service=https · ports 80,443"))
	}
	return b.String()
}

func (m rootModel) viewEasySpeed() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Speed limits"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Cap upload/download for a client on a device. Rates like 50mbit."))
	b.WriteString("\n\n")
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-10s %-10s %-10s %-18s %s",
		"ID", "DEVICE", "UPLOAD", "DOWNLOAD", "WHO", "NAME")))
	b.WriteString("\n")
	for i, t := range m.tc {
		who := t.MatchValue
		if who == "" {
			who = t.MatchKind
		}
		line := fmt.Sprintf("%-12s %-10s %-10s %-10s %-18s %s",
			trunc(t.ID, 12), trunc(t.Device, 10),
			apply.FormatRateHuman(t.RateTxBps), apply.FormatRateHuman(t.RateRxBps),
			trunc(who, 18), trunc(t.Name, 16))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.tc) == 0 {
		b.WriteString(helpStyle.Render("(none yet — press n: Who + Device + 50mbit)"))
	}
	return b.String()
}

func (m rootModel) viewEasyLive() string {
	// Reuse dataplane but with a friendlier title and fewer sections preference
	var b strings.Builder
	b.WriteString(titleStyle.Render("Live host view"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Read-only kernel dump (nft/iptables/routes). For rates use 8 Traffic."))
	b.WriteString("\n\n")
	b.WriteString(m.viewDataplane())
	return b.String()
}

func (m rootModel) viewEasyMain() string {
	switch m.tab {
	case easyHome:
		return m.viewEasyHome()
	case easyFastpath:
		return m.viewEasyTunnel()
	case easyMasq:
		return m.viewEasyReturn()
	case easyAccess:
		return m.viewEasyAccess()
	case easyLists:
		return m.viewEasyLists()
	case easyConfig:
		return m.viewEasyConfig()
	case easySpeed:
		return m.viewEasySpeed()
	case easyTraffic:
		return m.viewTraffic()
	case easyLive:
		return m.viewEasyLive()
	default:
		return m.viewEasyHome()
	}
}

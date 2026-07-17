package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/reloadlife/netpolicyd/internal/apply"
	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

const (
	tabStatus   = 0
	tabPolicies = 1
	tabRoutes   = 2
	tabNAT      = 3
	tabForwards = 4
	tabFirewall = 5
	tabIP       = 6
	tabTC       = 7
	tabTraffic  = 8
	tabPlane    = 9
	tabCount    = 10

	// traffic sub-views
	trafSecIface = 0
	trafSecIP    = 1
	trafSecPort  = 2
	trafSecConn  = 3

	modeList    = 0
	modeForm    = 1
	modeDetail  = 2
	modeConfirm = 3
	modeApply   = 4 // last apply / dry-run result view

	ipSecAddrs = 0
	ipSecRules = 1
	ipSecLinks = 2
)

type formKind int

const (
	formNone formKind = iota
	formPolicy
	formRoute
	formNAT
	formForward
	formTC
	formFirewall
	formIPAddr
	formIPRule
	formLink
)

type confirmKind int

const (
	confirmNone confirmKind = iota
	confirmDelPolicy
	confirmDelRoute
	confirmDelNAT
	confirmDelForward
	confirmDelTC
	confirmDelFirewall
	confirmDelIPAddr
	confirmDelIPRule
	confirmDelLink
	confirmDelIPList
)

type rootModel struct {
	cfg    Config
	tab    int
	mode   int
	width  int
	height int
	// uiEasy is plain-language mode (default). Advanced shows full tabs.
	uiEasy bool

	status    pkgapi.Status
	policies  []pkgapi.PolicyRule
	routes    []pkgapi.RouteSpec
	nat       []pkgapi.NATSpec
	forwards  []pkgapi.ForwardSpec
	tc        []pkgapi.TCSpec
	firewall  []pkgapi.FirewallRule
	ipAddrs   []pkgapi.IPAddrSpec
	ipRules   []pkgapi.IPRuleSpec
	links     []pkgapi.LinkSpec
	sysctls   []pkgapi.SysctlSpec
	ipLists   []pkgapi.IPList
	dataplane *pkgapi.Dataplane
	traffic   *pkgapi.TrafficSnapshot
	cursor    int
	scroll    int
	ipSection int // addrs | rules | links
	listSec   int // 0=browse lists, 1=entries of selected list (easy)
	trafSec   int // iface | ip | port | conn

	err        string
	statusLine string
	flash      string

	form       formModel
	formKind   formKind
	formCreate bool
	editID     string

	confirm     confirmKind
	confirmText string
	confirmArg  string

	detailPolicy   *pkgapi.PolicyRule
	detailRoute    *pkgapi.RouteSpec
	detailNAT      *pkgapi.NATSpec
	detailFwd      *pkgapi.ForwardSpec
	detailTC       *pkgapi.TCSpec
	detailFirewall *pkgapi.FirewallRule
	detailIPAddr   *pkgapi.IPAddrSpec
	detailIPRule   *pkgapi.IPRuleSpec
	detailLink     *pkgapi.LinkSpec

	lastApply *pkgapi.ApplyResult

	fetchGen uint64
	fetching bool // a host/traffic dump is in flight — don't stack another
	busy     bool
	flashID  int
}

func newRootModel(cfg Config) rootModel {
	easy := true
	if cfg.EasyMode != nil {
		easy = *cfg.EasyMode
	}
	m := rootModel{cfg: cfg, statusLine: "connecting…", mode: modeList, uiEasy: easy}
	if easy {
		m.tab = easyHome
	} else {
		m.tab = tabStatus
	}
	return m
}

func (m rootModel) beginFetch() (rootModel, tea.Cmd) {
	if m.fetching {
		return m, nil // one in flight; the periodic tick re-arms later
	}
	m.fetching = true
	m.fetchGen++
	withHost, withTraffic := false, false
	if m.uiEasy {
		withHost = m.tab == easyLive || m.tab == easyHome || m.tab == easyConfig
		withTraffic = m.tab == easyTraffic || m.tab == easyHome
	} else {
		withHost = m.tab == tabPlane || m.tab == tabStatus
		withTraffic = m.tab == tabTraffic || m.tab == tabStatus
	}
	return m, fetchData(m.cfg.Client, m.fetchGen, withHost, withTraffic)
}

func (m rootModel) startMutate(cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	m.busy = true
	return m, cmd
}

func (m rootModel) setFlash(s string) (rootModel, tea.Cmd) {
	m.flashID++
	m.flash = s
	return m, flashClearCmd(m.flashID)
}

func (m rootModel) Init() tea.Cmd {
	return tea.Batch(fetchData(m.cfg.Client, m.fetchGen, true, true), tickCmd(m.cfg.RefreshInterval))
}

func (m rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.mode == modeForm {
			m.form.SetSize(msg.Width, m.formAreaHeight())
		}
		return m, nil

	case tickMsg:
		if m.mode == modeList || m.mode == modeDetail {
			m, fetch := m.beginFetch()
			// Faster refresh on traffic tab for live rates.
			iv := m.cfg.RefreshInterval
			if (!m.uiEasy && m.tab == tabTraffic) || (m.uiEasy && m.tab == easyTraffic) {
				if iv > time.Second {
					iv = time.Second
				}
			}
			return m, tea.Batch(fetch, tickCmd(iv))
		}
		return m, tickCmd(m.cfg.RefreshInterval)

	case flashClearMsg:
		if msg.id == m.flashID {
			m.flash = ""
		}
		return m, nil

	case dataMsg:
		m.fetching = false // clear for any response (matching or stale) so it can't stick
		if msg.gen != m.fetchGen {
			return m, nil
		}
		if msg.err != nil {
			m.err = msg.err.Error()
			m.statusLine = "error"
		} else {
			m.err = ""
			m.status = msg.status
			m.policies = msg.policies
			m.routes = msg.routes
			m.nat = msg.nat
			m.forwards = msg.forwards
			m.tc = msg.tc
			m.firewall = msg.firewall
			m.ipAddrs = msg.ipAddrs
			m.ipRules = msg.ipRules
			m.links = msg.links
			m.sysctls = msg.sysctls
			m.ipLists = msg.ipLists
			if msg.dataplane != nil {
				m.dataplane = msg.dataplane
			}
			if msg.traffic != nil {
				m.traffic = msg.traffic
			}
			if msg.status.LastApply != nil {
				m.lastApply = msg.status.LastApply
			}
			m.statusLine = "ok"
			if m.cursor >= m.rowCount() {
				m.cursor = max(0, m.rowCount()-1)
			}
			m.refreshDetail()
		}
		return m, nil

	case actionDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.err = msg.err.Error()
			m.statusLine = "error"
			return m, nil
		}
		m.err = ""
		if msg.toList {
			m.mode = modeList
			m.confirm = confirmNone
			m.clearDetail()
		}
		m, flashCmd := m.setFlash(msg.flash)
		cmds := []tea.Cmd{flashCmd}
		if msg.refresh {
			var fetch tea.Cmd
			m, fetch = m.beginFetch()
			cmds = append(cmds, fetch)
		}
		return m, tea.Batch(cmds...)

	case applyDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.err = msg.err.Error()
			m.statusLine = "error"
			return m, nil
		}
		m.err = ""
		m.lastApply = msg.result
		m.mode = modeApply
		m, flashCmd := m.setFlash(msg.flash)
		var fetch tea.Cmd
		m, fetch = m.beginFetch()
		return m, tea.Batch(flashCmd, fetch)

	case tea.KeyMsg:
		if m.mode == modeForm {
			return m.handleFormKeyAll(msg)
		}
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *rootModel) refreshDetail() {
	if m.mode != modeDetail {
		return
	}
	if m.detailPolicy != nil {
		for i := range m.policies {
			if m.policies[i].ID == m.detailPolicy.ID {
				p := m.policies[i]
				m.detailPolicy = &p
				return
			}
		}
	}
	if m.detailRoute != nil {
		for i := range m.routes {
			if m.routes[i].ID == m.detailRoute.ID {
				r := m.routes[i]
				m.detailRoute = &r
				return
			}
		}
	}
	if m.detailNAT != nil {
		for i := range m.nat {
			if m.nat[i].ID == m.detailNAT.ID {
				n := m.nat[i]
				m.detailNAT = &n
				return
			}
		}
	}
	if m.detailFwd != nil {
		for i := range m.forwards {
			if m.forwards[i].ID == m.detailFwd.ID {
				f := m.forwards[i]
				m.detailFwd = &f
				return
			}
		}
	}
	if m.detailTC != nil {
		for i := range m.tc {
			if m.tc[i].ID == m.detailTC.ID {
				t := m.tc[i]
				m.detailTC = &t
				return
			}
		}
	}
	if m.detailFirewall != nil {
		for i := range m.firewall {
			if m.firewall[i].ID == m.detailFirewall.ID {
				f := m.firewall[i]
				m.detailFirewall = &f
				return
			}
		}
	}
}

func (m *rootModel) clearDetail() {
	m.detailPolicy = nil
	m.detailRoute = nil
	m.detailNAT = nil
	m.detailFwd = nil
	m.detailTC = nil
	m.detailFirewall = nil
	m.detailIPAddr = nil
	m.detailIPRule = nil
	m.detailLink = nil
}

func (m rootModel) rowCount() int {
	if m.uiEasy {
		return m.easyRowCount()
	}
	switch m.tab {
	case tabPolicies:
		return len(m.policies)
	case tabRoutes:
		return len(m.routes)
	case tabNAT:
		return len(m.nat)
	case tabForwards:
		return len(m.forwards)
	case tabFirewall:
		return len(m.firewall)
	case tabIP:
		switch m.ipSection {
		case ipSecRules:
			return len(m.ipRules)
		case ipSecLinks:
			return len(m.links)
		default:
			return len(m.ipAddrs)
		}
	case tabTC:
		return len(m.tc)
	case tabTraffic:
		return m.trafficRowCount()
	case tabPlane:
		return m.planeLineCount()
	default:
		return 0
	}
}

func (m rootModel) formAreaHeight() int {
	h := m.height - 1
	if h < 10 {
		h = 10
	}
	return h
}

func (m rootModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.mode {
	case modeConfirm:
		return m.handleConfirm(key)
	case modeDetail:
		return m.handleDetailKey(key)
	case modeApply:
		if key == "esc" || key == "q" || key == "enter" {
			m.mode = modeList
		}
		if key == "j" || key == "down" {
			m.scroll++
		}
		if key == "k" || key == "up" {
			m.scroll = max(0, m.scroll-1)
		}
		return m, nil
	default:
		return m.handleListKey(key)
	}
}

func (m rootModel) handleConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y":
		if m.busy {
			return m, nil
		}
		switch m.confirm {
		case confirmDelPolicy:
			id, name := m.confirmArg, m.confirmText
			// confirmArg is id; name extracted from text is messy — store id only
			_ = name
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeletePolicy(m.cfg.Client, id, id))
		case confirmDelRoute:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteRoute(m.cfg.Client, id))
		case confirmDelNAT:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteNAT(m.cfg.Client, id))
		case confirmDelForward:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteForward(m.cfg.Client, id))
		case confirmDelTC:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteTC(m.cfg.Client, id))
		case confirmDelFirewall:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteFirewall(m.cfg.Client, id))
		case confirmDelIPAddr:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteIPAddr(m.cfg.Client, id))
		case confirmDelIPRule:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteIPRule(m.cfg.Client, id))
		case confirmDelLink:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteLink(m.cfg.Client, id))
		case confirmDelIPList:
			id := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteIPList(m.cfg.Client, id))
		}
	case "n", "N", "esc":
		m.confirm = confirmNone
		m.mode = modeList
	}
	return m, nil
}

func (m rootModel) handleFormKeyAll(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.mode = modeList
		m.form.err = ""
		return m, nil
	case "enter":
		return m.submitForm()
	}
	var cmd tea.Cmd
	m.form, cmd = m.form.Update(msg)
	return m, cmd
}

func (m rootModel) handleDetailKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "backspace":
		m.mode = modeList
		m.clearDetail()
	case "e":
		return m.openEditFromDetail()
	case "t":
		if m.detailPolicy != nil {
			return m.startMutate(doTogglePolicy(m.cfg.Client, m.detailPolicy.ID, !m.detailPolicy.Enabled))
		}
	case "D":
		return m.confirmDeleteFromDetail()
	case "j", "down":
		m.scroll++
	case "k", "up":
		m.scroll = max(0, m.scroll-1)
	}
	return m, nil
}

func (m rootModel) openEditFromDetail() (tea.Model, tea.Cmd) {
	if m.detailPolicy != nil {
		return m.openPolicyEdit(*m.detailPolicy)
	}
	// routes/nat/forwards: create-style edit not supported (upsert by re-create); skip
	return m, nil
}

func (m rootModel) confirmDeleteFromDetail() (tea.Model, tea.Cmd) {
	if m.detailPolicy != nil {
		m.confirm = confirmDelPolicy
		m.confirmText = fmt.Sprintf("Delete policy %s (%s)?", m.detailPolicy.Name, m.detailPolicy.ID)
		m.confirmArg = m.detailPolicy.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailRoute != nil {
		m.confirm = confirmDelRoute
		m.confirmText = fmt.Sprintf("Delete route %s → %s?", m.detailRoute.ID, m.detailRoute.Dst)
		m.confirmArg = m.detailRoute.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailNAT != nil {
		m.confirm = confirmDelNAT
		m.confirmText = fmt.Sprintf("Delete NAT %s (%s)?", m.detailNAT.ID, m.detailNAT.Kind)
		m.confirmArg = m.detailNAT.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailFwd != nil {
		m.confirm = confirmDelForward
		m.confirmText = fmt.Sprintf("Delete forward %s?", m.detailFwd.ID)
		m.confirmArg = m.detailFwd.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailTC != nil {
		m.confirm = confirmDelTC
		m.confirmText = fmt.Sprintf("Delete TC %s on %s?", m.detailTC.ID, m.detailTC.Device)
		m.confirmArg = m.detailTC.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailFirewall != nil {
		m.confirm = confirmDelFirewall
		m.confirmText = fmt.Sprintf("Delete firewall %s?", firstNonEmpty(m.detailFirewall.Name, m.detailFirewall.ID))
		m.confirmArg = m.detailFirewall.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailIPAddr != nil {
		m.confirm = confirmDelIPAddr
		m.confirmText = fmt.Sprintf("Delete address %s on %s?", m.detailIPAddr.CIDR, m.detailIPAddr.Device)
		m.confirmArg = m.detailIPAddr.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailIPRule != nil {
		m.confirm = confirmDelIPRule
		m.confirmText = fmt.Sprintf("Delete ip rule %s?", m.detailIPRule.ID)
		m.confirmArg = m.detailIPRule.ID
		m.mode = modeConfirm
		return m, nil
	}
	if m.detailLink != nil {
		m.confirm = confirmDelLink
		m.confirmText = fmt.Sprintf("Delete link config %s?", m.detailLink.Name)
		m.confirmArg = m.detailLink.ID
		m.mode = modeConfirm
		return m, nil
	}
	return m, nil
}

func (m rootModel) handleListKey(key string) (tea.Model, tea.Cmd) {
	if m.uiEasy {
		return m.handleEasyListKey(key)
	}
	switch key {
	case "q":
		return m, tea.Quit
	case "m", "M":
		return m.toggleUIMode()
	case "1":
		m.tab, m.cursor, m.scroll = tabStatus, 0, 0
	case "2":
		m.tab, m.cursor, m.scroll = tabPolicies, 0, 0
	case "3":
		m.tab, m.cursor, m.scroll = tabRoutes, 0, 0
	case "4":
		m.tab, m.cursor, m.scroll = tabNAT, 0, 0
	case "5":
		m.tab, m.cursor, m.scroll = tabForwards, 0, 0
	case "6":
		m.tab, m.cursor, m.scroll = tabFirewall, 0, 0
	case "7":
		m.tab, m.cursor, m.scroll = tabIP, 0, 0
	case "8":
		m.tab, m.cursor, m.scroll = tabTC, 0, 0
	case "9":
		m.tab, m.cursor, m.scroll = tabTraffic, 0, 0
		m, fetch := m.beginFetch()
		return m, fetch
	case "0":
		m.tab, m.cursor, m.scroll = tabPlane, 0, 0
		m, fetch := m.beginFetch()
		return m, fetch
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % tabCount
		m.cursor, m.scroll = 0, 0
		if m.tab == tabTraffic || m.tab == tabPlane {
			m, fetch := m.beginFetch()
			return m, fetch
		}
	case "shift+tab", "left", "h":
		m.tab = (m.tab + tabCount - 1) % tabCount
		m.cursor, m.scroll = 0, 0
		if m.tab == tabTraffic || m.tab == tabPlane {
			m, fetch := m.beginFetch()
			return m, fetch
		}
	case "[":
		if m.tab == tabIP {
			m.ipSection = (m.ipSection + 2) % 3
			m.cursor = 0
		}
		if m.tab == tabTraffic {
			m.trafSec = (m.trafSec + 3) % 4
			m.cursor, m.scroll = 0, 0
		}
	case "]":
		if m.tab == tabIP {
			m.ipSection = (m.ipSection + 1) % 3
			m.cursor = 0
		}
		if m.tab == tabTraffic {
			m.trafSec = (m.trafSec + 1) % 4
			m.cursor, m.scroll = 0, 0
		}
	case "j", "down":
		if m.tab == tabPlane || m.tab == tabStatus {
			m.scroll++
		} else if m.cursor < m.rowCount()-1 {
			m.cursor++
		}
	case "k", "up":
		if m.tab == tabPlane || m.tab == tabStatus {
			m.scroll = max(0, m.scroll-1)
		} else if m.cursor > 0 {
			m.cursor--
		}
	case "pgdown":
		if m.tab == tabPlane {
			m.scroll += 10
		} else {
			m.cursor = max(0, min(m.rowCount()-1, m.cursor+10))
		}
	case "pgup":
		if m.tab == tabPlane {
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
		if m.tab == tabStatus {
			return m.startMutate(doSetIPForward(m.cfg.Client, !m.status.IPForward))
		}
	case "n":
		switch m.tab {
		case tabPolicies:
			return m.openPolicyCreate()
		case tabRoutes:
			return m.openRouteCreate()
		case tabNAT:
			return m.openNATCreate()
		case tabForwards:
			return m.openForwardCreate()
		case tabFirewall:
			return m.openFirewallCreate()
		case tabIP:
			switch m.ipSection {
			case ipSecRules:
				return m.openIPRuleCreate()
			case ipSecLinks:
				return m.openLinkCreate()
			default:
				return m.openIPAddrCreate()
			}
		case tabTC:
			return m.openTCCreate()
		}
	case "enter", " ":
		return m.openDetailFromList()
	case "e":
		if m.tab == tabPolicies && m.cursor < len(m.policies) {
			return m.openPolicyEdit(m.policies[m.cursor])
		}
	case "t":
		if m.tab == tabPolicies && m.cursor < len(m.policies) {
			p := m.policies[m.cursor]
			return m.startMutate(doTogglePolicy(m.cfg.Client, p.ID, !p.Enabled))
		}
	case "D":
		return m.confirmDeleteFromList()
	}
	return m, nil
}

func (m rootModel) openDetailFromList() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabPolicies:
		if m.cursor < len(m.policies) {
			p := m.policies[m.cursor]
			m.detailPolicy = &p
			m.mode = modeDetail
			m.scroll = 0
		}
	case tabRoutes:
		if m.cursor < len(m.routes) {
			r := m.routes[m.cursor]
			m.detailRoute = &r
			m.mode = modeDetail
			m.scroll = 0
		}
	case tabNAT:
		if m.cursor < len(m.nat) {
			n := m.nat[m.cursor]
			m.detailNAT = &n
			m.mode = modeDetail
			m.scroll = 0
		}
	case tabForwards:
		if m.cursor < len(m.forwards) {
			f := m.forwards[m.cursor]
			m.detailFwd = &f
			m.mode = modeDetail
			m.scroll = 0
		}
	case tabTC:
		if m.cursor < len(m.tc) {
			t := m.tc[m.cursor]
			m.detailTC = &t
			m.mode = modeDetail
			m.scroll = 0
		}
	case tabFirewall:
		if m.cursor < len(m.firewall) {
			f := m.firewall[m.cursor]
			m.detailFirewall = &f
			m.mode = modeDetail
			m.scroll = 0
		}
	case tabIP:
		switch m.ipSection {
		case ipSecRules:
			if m.cursor < len(m.ipRules) {
				r := m.ipRules[m.cursor]
				m.detailIPRule = &r
				m.mode = modeDetail
			}
		case ipSecLinks:
			if m.cursor < len(m.links) {
				l := m.links[m.cursor]
				m.detailLink = &l
				m.mode = modeDetail
			}
		default:
			if m.cursor < len(m.ipAddrs) {
				a := m.ipAddrs[m.cursor]
				m.detailIPAddr = &a
				m.mode = modeDetail
			}
		}
	case tabStatus:
		if m.lastApply != nil {
			m.mode = modeApply
			m.scroll = 0
		}
	}
	return m, nil
}

func (m rootModel) confirmDeleteFromList() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabPolicies:
		if m.cursor < len(m.policies) {
			p := m.policies[m.cursor]
			m.confirm = confirmDelPolicy
			m.confirmText = fmt.Sprintf("Delete policy %s?", p.Name)
			m.confirmArg = p.ID
			m.mode = modeConfirm
		}
	case tabRoutes:
		if m.cursor < len(m.routes) {
			r := m.routes[m.cursor]
			m.confirm = confirmDelRoute
			m.confirmText = fmt.Sprintf("Delete route %s?", r.ID)
			m.confirmArg = r.ID
			m.mode = modeConfirm
		}
	case tabNAT:
		if m.cursor < len(m.nat) {
			n := m.nat[m.cursor]
			m.confirm = confirmDelNAT
			m.confirmText = fmt.Sprintf("Delete NAT %s?", n.ID)
			m.confirmArg = n.ID
			m.mode = modeConfirm
		}
	case tabForwards:
		if m.cursor < len(m.forwards) {
			f := m.forwards[m.cursor]
			m.confirm = confirmDelForward
			m.confirmText = fmt.Sprintf("Delete forward %s?", f.ID)
			m.confirmArg = f.ID
			m.mode = modeConfirm
		}
	case tabTC:
		if m.cursor < len(m.tc) {
			t := m.tc[m.cursor]
			m.confirm = confirmDelTC
			m.confirmText = fmt.Sprintf("Delete TC %s?", firstNonEmpty(t.Name, t.ID))
			m.confirmArg = t.ID
			m.mode = modeConfirm
		}
	case tabFirewall:
		if m.cursor < len(m.firewall) {
			f := m.firewall[m.cursor]
			m.confirm = confirmDelFirewall
			m.confirmText = fmt.Sprintf("Delete firewall %s?", firstNonEmpty(f.Name, f.ID))
			m.confirmArg = f.ID
			m.mode = modeConfirm
		}
	case tabIP:
		switch m.ipSection {
		case ipSecRules:
			if m.cursor < len(m.ipRules) {
				r := m.ipRules[m.cursor]
				m.confirm = confirmDelIPRule
				m.confirmText = fmt.Sprintf("Delete ip rule %s?", r.ID)
				m.confirmArg = r.ID
				m.mode = modeConfirm
			}
		case ipSecLinks:
			if m.cursor < len(m.links) {
				l := m.links[m.cursor]
				m.confirm = confirmDelLink
				m.confirmText = fmt.Sprintf("Delete link %s?", l.Name)
				m.confirmArg = l.ID
				m.mode = modeConfirm
			}
		default:
			if m.cursor < len(m.ipAddrs) {
				a := m.ipAddrs[m.cursor]
				m.confirm = confirmDelIPAddr
				m.confirmText = fmt.Sprintf("Delete %s on %s?", a.CIDR, a.Device)
				m.confirmArg = a.ID
				m.mode = modeConfirm
			}
		}
	}
	return m, nil
}

func (m rootModel) openPolicyCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New policy", policyFormFields(), map[string]string{
		"priority": "100", "enabled": "y",
		"subject_kind": "cidr", "dest_kind": "any", "dest_value": "0.0.0.0/0",
		"action": "egress",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formPolicy
	m.formCreate = true
	m.editID = ""
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openPolicyEdit(p pkgapi.PolicyRule) (tea.Model, tea.Cmd) {
	sk, sv := "cidr", ""
	if len(p.Subjects) > 0 {
		sk, sv = p.Subjects[0].Kind, p.Subjects[0].Value
	}
	dk, dv := p.Destination.Kind, p.Destination.Value
	if dk == "" {
		dk = "any"
	}
	en := "n"
	if p.Enabled {
		en = "y"
	}
	m.form = newForm("Edit "+p.Name, policyFormFields(), map[string]string{
		"name": p.Name, "priority": strconv.Itoa(p.Priority), "enabled": en,
		"subject_kind": sk, "subject_value": sv,
		"dest_kind": dk, "dest_value": dv,
		"action": string(p.Action), "egress_name": p.EgressName,
		"source_cidr": p.SourceCIDR, "table": p.Table,
		"mark": fmt.Sprintf("%d", p.Mark), "description": p.Description,
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formPolicy
	m.formCreate = false
	m.editID = p.ID
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openRouteCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New route", routeFormFields(), map[string]string{
		"table": "100", "dst": "default", "enabled": "y",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formRoute
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openNATCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New NAT rule", natFormFields(), map[string]string{
		"kind": "masquerade", "enabled": "y",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formNAT
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openForwardCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New forward rule", forwardFormFields(), map[string]string{
		"action": "accept", "enabled": "y",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formForward
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openTCCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New TC limit", tcFormFields(), map[string]string{
		"enabled": "y", "match_kind": "src_cidr", "rate_tx": "50mbit", "rate_rx": "50mbit",
	})
	m.form.note = "rates in bits/s (50mbit = 50 Mbps). HTB on TX, ingress police on RX."
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formTC
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openFirewallCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New firewall rule", firewallFormFields(), map[string]string{
		"enabled": "y", "priority": "100", "backend": "auto",
		"table": "filter", "chain": "forward", "action": "accept", "protocol": "tcp",
	})
	m.form.note = "backend auto → nft if available, else iptables"
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formFirewall
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openIPAddrCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New IP address", ipAddrFormFields(), map[string]string{
		"enabled": "y", "scope": "global",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formIPAddr
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openIPRuleCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New IP rule", ipRuleFormFields(), map[string]string{
		"enabled": "y", "action": "lookup", "table": "100", "priority": "11000",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formIPRule
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) openLinkCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("Link config", linkFormFields(), map[string]string{
		"enabled": "y", "up": "y",
	})
	m.form.SetSize(m.width, m.formAreaHeight())
	m.formKind = formLink
	m.formCreate = true
	m.mode = modeForm
	return m, m.form.Init()
}

func (m rootModel) submitForm() (tea.Model, tea.Cmd) {
	switch m.formKind {
	case formPolicy:
		return m.submitPolicyForm()
	case formRoute:
		return m.submitRouteForm()
	case formNAT:
		return m.submitNATForm()
	case formForward:
		return m.submitForwardForm()
	case formTC:
		return m.submitTCForm()
	case formFirewall:
		return m.submitFirewallForm()
	case formIPAddr:
		return m.submitIPAddrForm()
	case formIPRule:
		return m.submitIPRuleForm()
	case formLink:
		return m.submitLinkForm()
	case formEasyEgress, formEasyAccess, formEasySpeed, formEasyReturn, formEasyConfig,
		formEasyMasq, formEasyList, formEasyListAdd, formEasyRoute, formEasyGateway:
		return m.submitEasyForm()
	default:
		m.mode = modeList
		return m, nil
	}
}

func (m rootModel) submitPolicyForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	name := v["name"]
	if name == "" {
		m.form.err = "name is required"
		return m, nil
	}
	sv := v["subject_value"]
	if sv == "" {
		m.form.err = "subject value is required"
		return m, nil
	}
	action := pkgapi.PolicyAction(v["action"])
	if action == pkgapi.ActionEgress && v["egress_name"] == "" {
		m.form.err = "egress iface required for action=egress"
		return m, nil
	}
	pri, err := parseIntField(v["priority"])
	if err != nil {
		m.form.err = "invalid priority"
		return m, nil
	}
	if pri == 0 {
		pri = 100
	}
	mark, _ := parseUint32Field(v["mark"])
	en := truthy(v["enabled"])
	subj := []pkgapi.Subject{{Kind: v["subject_kind"], Value: sv}}
	dest := pkgapi.Destination{Kind: v["dest_kind"], Value: v["dest_value"]}
	if dest.Kind == "any" && dest.Value == "" {
		dest.Value = "0.0.0.0/0"
	}

	if m.formCreate {
		req := pkgapi.PolicyCreateRequest{
			Priority: pri, Name: name, Enabled: &en,
			Subjects: subj, Destination: dest, Action: action,
			EgressName: v["egress_name"], Mark: mark, Table: v["table"],
			SourceCIDR: v["source_cidr"], Description: v["description"],
		}
		return m.startMutate(doCreatePolicy(m.cfg.Client, req))
	}
	req := pkgapi.PolicyUpdateRequest{
		Priority: &pri, Name: &name, Enabled: &en,
		Subjects: subj, Destination: &dest, Action: &action,
		EgressName: strPtr(v["egress_name"]), Mark: &mark, Table: strPtr(v["table"]),
		SourceCIDR: strPtr(v["source_cidr"]), Description: strPtr(v["description"]),
	}
	return m.startMutate(doUpdatePolicy(m.cfg.Client, m.editID, req))
}

func (m rootModel) submitRouteForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["dst"] == "" {
		m.form.err = "destination is required"
		return m, nil
	}
	if v["table"] == "" {
		m.form.err = "table is required"
		return m, nil
	}
	metric, _ := parseIntField(v["metric"])
	rt := pkgapi.RouteSpec{
		Table: v["table"], Dst: v["dst"], Gateway: v["gateway"],
		Device: v["device"], Metric: metric, OnLink: truthy(v["onlink"]),
		Enabled: truthy(v["enabled"]), Protocol: "netpolicyd",
	}
	return m.startMutate(doCreateRoute(m.cfg.Client, rt))
}

func (m rootModel) submitNATForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["out_iface"] == "" {
		m.form.err = "out iface is required"
		return m, nil
	}
	n := pkgapi.NATSpec{
		Kind: v["kind"], SourceCIDR: v["source_cidr"], OutIface: v["out_iface"],
		ToSource: v["to_source"], Comment: v["comment"], Enabled: truthy(v["enabled"]),
	}
	return m.startMutate(doCreateNAT(m.cfg.Client, n))
}

func (m rootModel) submitForwardForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["action"] == "" {
		m.form.err = "action is required"
		return m, nil
	}
	f := pkgapi.ForwardSpec{
		Action: v["action"], InIface: v["in_iface"], OutIface: v["out_iface"],
		Source: v["source"], Dest: v["dest"], Enabled: truthy(v["enabled"]),
	}
	return m.startMutate(doCreateForward(m.cfg.Client, f))
}

func (m rootModel) submitTCForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["device"] == "" {
		m.form.err = "device is required"
		return m, nil
	}
	tx, err := apply.ParseRateBitPS(v["rate_tx"])
	if err != nil {
		m.form.err = "TX rate: " + err.Error()
		return m, nil
	}
	rx, err := apply.ParseRateBitPS(v["rate_rx"])
	if err != nil {
		m.form.err = "RX rate: " + err.Error()
		return m, nil
	}
	if tx <= 0 && rx <= 0 {
		m.form.err = "set TX and/or RX rate (e.g. 50mbit)"
		return m, nil
	}
	ceil, err := apply.ParseRateBitPS(v["ceil_tx"])
	if err != nil {
		m.form.err = "TX ceil: " + err.Error()
		return m, nil
	}
	mk := v["match_kind"]
	if mk == "" {
		mk = "any"
	}
	if mk != "any" && v["match_value"] == "" {
		m.form.err = "match value required for " + mk
		return m, nil
	}
	pri, _ := parseIntField(v["priority"])
	t := pkgapi.TCSpec{
		Name: v["name"], Device: v["device"], Enabled: truthy(v["enabled"]),
		RateTxBps: tx, RateRxBps: rx, CeilingTxBps: ceil,
		MatchKind: mk, MatchValue: v["match_value"],
		Priority: pri, Comment: v["comment"],
	}
	return m.startMutate(doCreateTC(m.cfg.Client, t))
}

func (m rootModel) submitFirewallForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["chain"] == "" || v["action"] == "" {
		m.form.err = "chain and action required"
		return m, nil
	}
	pri, _ := parseIntField(v["priority"])
	if pri == 0 {
		pri = 100
	}
	mark, _ := parseUint32Field(v["set_mark"])
	r := pkgapi.FirewallRule{
		Name: v["name"], Enabled: truthy(v["enabled"]), Priority: pri,
		Backend: v["backend"], Table: v["table"], Chain: v["chain"], Action: v["action"],
		Protocol: v["protocol"], Source: v["source"], Dest: v["dest"],
		InIface: v["in_iface"], OutIface: v["out_iface"],
		Sport: v["sport"], Dport: v["dport"],
		ToSource: v["to_source"], ToDestination: v["to_dest"],
		SetMark: mark, Comment: v["comment"],
	}
	return m.startMutate(doCreateFirewall(m.cfg.Client, r))
}

func (m rootModel) submitIPAddrForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["device"] == "" || v["cidr"] == "" {
		m.form.err = "device and cidr required"
		return m, nil
	}
	a := pkgapi.IPAddrSpec{
		Device: v["device"], CIDR: v["cidr"], Peer: v["peer"],
		Broadcast: v["broadcast"], Scope: v["scope"], Label: v["label"],
		Enabled: truthy(v["enabled"]),
	}
	return m.startMutate(doCreateIPAddr(m.cfg.Client, a))
}

func (m rootModel) submitIPRuleForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["action"] == "lookup" && v["table"] == "" {
		m.form.err = "table required for lookup"
		return m, nil
	}
	pri, _ := parseIntField(v["priority"])
	mark, _ := parseUint32Field(v["fwmark"])
	r := pkgapi.IPRuleSpec{
		Priority: pri, From: v["from"], To: v["to"], Iif: v["iif"], Oif: v["oif"],
		FwMark: mark, Table: v["table"], Action: v["action"], Comment: v["comment"],
		Enabled: truthy(v["enabled"]),
	}
	return m.startMutate(doCreateIPRule(m.cfg.Client, r))
}

func (m rootModel) submitLinkForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if v["name"] == "" {
		m.form.err = "name required"
		return m, nil
	}
	up := truthy(v["up"])
	mtu, _ := parseIntField(v["mtu"])
	l := pkgapi.LinkSpec{
		Name: v["name"], Up: &up, MTU: mtu, Comment: v["comment"],
		Enabled: truthy(v["enabled"]),
	}
	return m.startMutate(doCreateLink(m.cfg.Client, l))
}

func strPtr(s string) *string { return &s }

// ---- View ----

func (m rootModel) View() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 100
	}
	if h <= 0 {
		h = 30
	}

	st := m.status
	modeTag := "EASY"
	if !m.uiEasy {
		modeTag = "ADV"
	}
	status := fmt.Sprintf(" netpolicyctl [%s]  ·  %s  ·  %s  ·  %s ",
		modeTag, m.cfg.Endpoint, m.statusLine, st.Backend)
	if st.Version != "" {
		status = fmt.Sprintf(" netpolicyctl [%s]  ·  %s  ·  %s  ·  %s  ·  v%s ",
			modeTag, m.cfg.Endpoint, m.statusLine, st.Backend, st.Version)
	}
	if m.flash != "" {
		status += " ✓ " + m.flash + " "
	}
	if m.busy {
		status += " … "
	}
	header := statusStyle.Width(w).Render(status)

	footerHelp := m.chromeHelp()
	footer := helpStyle.Width(w).Background(cBarBg).Foreground(cBarFg).Padding(0, 1).Render(footerHelp)

	headerH := lipgloss.Height(header)
	footerH := lipgloss.Height(footer)
	mainH := h - headerH - footerH
	if mainH < 1 {
		mainH = 1
	}

	var mid string
	switch m.mode {
	case modeConfirm:
		mid = panelStyle.Width(w - 2).Height(mainH - 1).Render(
			warnStyle.Render("Confirm") + "\n\n" + m.confirmText + "\n\n" +
				helpStyle.Render("[y] yes   [n / esc] cancel"),
		)
	case modeForm:
		m.form.SetSize(w, mainH)
		mid = m.form.View()
	case modeDetail:
		mid = fillHeight(m.viewDetail(), w, mainH)
	case modeApply:
		mid = fillHeight(m.viewApplyResult(), w, mainH)
	default:
		var b strings.Builder
		if m.uiEasy {
			b.WriteString(m.renderEasyTabs())
		} else {
			b.WriteString(m.renderTabs())
		}
		b.WriteString("\n")
		if m.err != "" {
			b.WriteString(errStyle.Render("error: " + m.err))
			b.WriteString("\n")
		}
		b.WriteString("\n")
		if m.uiEasy {
			b.WriteString(m.viewEasyMain())
		} else {
			switch m.tab {
			case tabStatus:
				b.WriteString(m.viewStatus())
			case tabPolicies:
				b.WriteString(m.viewPolicies())
			case tabRoutes:
				b.WriteString(m.viewRoutes())
			case tabNAT:
				b.WriteString(m.viewNAT())
			case tabForwards:
				b.WriteString(m.viewForwards())
			case tabFirewall:
				b.WriteString(m.viewFirewall())
			case tabIP:
				b.WriteString(m.viewIP())
			case tabTC:
				b.WriteString(m.viewTC())
			case tabTraffic:
				b.WriteString(m.viewTraffic())
			case tabPlane:
				b.WriteString(m.viewDataplane())
			}
		}
		mid = fillHeight(b.String(), w, mainH)
	}

	mid = fillHeight(mid, w, mainH)
	return lipgloss.JoinVertical(lipgloss.Left, header, mid, footer)
}

func (m rootModel) chromeHelp() string {
	switch m.mode {
	case modeForm:
		return " tab/↑↓ fields  ·  ←/→ or space change  ·  enter save  ·  esc cancel "
	case modeConfirm:
		return " y confirm  ·  n/esc cancel "
	case modeDetail:
		return " esc back  ·  e edit  ·  t toggle  ·  D delete  ·  q quit "
	case modeApply:
		return " esc/enter back  ·  j/k scroll "
	default:
		return " " + m.listHelp() + " "
	}
}

func (m rootModel) listHelp() string {
	if m.uiEasy {
		return m.easyListHelp()
	}
	base := "1-9/0 tabs · j/k · enter · n new · r refresh · a apply · m easy · q quit"
	switch m.tab {
	case tabPolicies:
		return base + " · e edit · t toggle · D delete"
	case tabRoutes, tabNAT, tabForwards, tabTC, tabFirewall:
		return base + " · D delete"
	case tabIP:
		return base + " · [/] section (addrs/rules/links) · D delete"
	case tabTraffic:
		return "9 Traffic · [/] iface|ip|port|conn · j/k · r refresh (1s) · m easy · q quit"
	case tabStatus:
		return base + " · f toggle ip_forward · enter last apply"
	case tabPlane:
		return "0 Dataplane · j/k/pg scroll · r refresh · m easy · q quit"
	default:
		return base
	}
}

func (m rootModel) renderTabs() string {
	names := []string{"Status", "Pol", "Route", "NAT", "Fwd", "FW", "IP", "TC", "Traf", "Plane"}
	if m.width >= 120 {
		names = []string{"Status", "Policies", "Routes", "NAT", "Forwards", "Firewall", "IP", "TC", "Traffic", "Dataplane"}
	}
	parts := make([]string, len(names))
	for i, n := range names {
		// 1–9 then 0 for dataplane (key binding).
		num := i + 1
		if i == tabPlane {
			num = 0
		}
		label := fmt.Sprintf("%d %s", num, n)
		if i == m.tab {
			parts[i] = tabActive.Render(label)
		} else {
			parts[i] = tabInactive.Render(label)
		}
	}
	// Mode badge is in the header ([ADV]) — keep tabs on one row.
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m rootModel) viewStatus() string {
	st := m.status
	var b strings.Builder
	b.WriteString(titleStyle.Render("Daemon status"))
	b.WriteString("\n")

	tool := func(name string, ok bool) string {
		if ok {
			return badgeUp.Render(" " + name + " ")
		}
		return badgeDown.Render(" " + name + " ")
	}
	fwd := badgeDown.Render(" ip_forward OFF ")
	if st.IPForward {
		fwd = badgeUp.Render(" ip_forward ON ")
	}
	applyOK := badgeDown.Render(" last apply fail ")
	if st.LastApplyOK {
		applyOK = badgeUp.Render(" last apply ok ")
	} else if st.LastApplyAt == "" {
		applyOK = dimStyle.Render(" no apply yet ")
	}

	body := strings.Builder{}
	kv := func(k, v string) {
		fmt.Fprintf(&body, "%s %s\n", labelStyle.Render(k), valueStyle.Render(v))
	}
	kv("Version", st.Version)
	kv("Backend", st.Backend)
	kv("Policies", fmt.Sprintf("%d", st.PolicyCount))
	kv("Routes", fmt.Sprintf("%d", st.RouteCount))
	kv("NAT", fmt.Sprintf("%d", st.NATCount))
	kv("Forwards", fmt.Sprintf("%d", st.ForwardCount))
	kv("TC limits", fmt.Sprintf("%d", st.TCCount))
	kv("Firewall", fmt.Sprintf("%d", st.FirewallCount))
	kv("IP addrs/rules", fmt.Sprintf("%d / %d", st.IPAddrCount, st.IPRuleCount))
	kv("Links", fmt.Sprintf("%d", st.LinkCount))
	kv("Generation", fmt.Sprintf("%d", st.LastGeneration))
	kv("Last apply", firstNonEmpty(st.LastApplyAt, "—"))
	if st.LastApply != nil && st.LastApply.Message != "" {
		kv("Apply msg", st.LastApply.Message)
	}

	b.WriteString(panelStyle.Render(
		body.String() + "\n" +
			tool("ip", st.IPAvailable) + " " +
			tool("nft", st.NFTAvailable) + " " +
			tool("tc", st.TCAvailable) + " " +
			tool("iptables", st.IptablesAvailable) + "\n\n" +
			fwd + "  " + applyOK + "\n\n" +
			m.viewTrafficSummary() + "\n\n" +
			helpStyle.Render("f = toggle ip_forward   ·   a = apply   ·   A = dry-run   ·   enter = last apply"),
	))

	if m.lastApply != nil && len(m.lastApply.Commands) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionStyle.Render("Last apply commands (enter for full)"))
		b.WriteString("\n")
		limit := 8
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

func (m rootModel) viewPolicies() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-4s %-6s %-18s %-8s %-22s %-10s %s",
		"PRI", "STATE", "NAME", "ACTION", "SUBJECT", "EGRESS", "DEST")))
	b.WriteString("\n")
	for i, p := range m.policies {
		state := badgeDown.Render("off")
		if p.Enabled {
			state = badgeUp.Render(" on")
		}
		line := fmt.Sprintf("%-4d %s %-18s %-8s %-22s %-10s %s",
			p.Priority, state, trunc(p.Name, 18), string(p.Action),
			trunc(subjectsSummary(p.Subjects), 22), trunc(p.EgressName, 10),
			trunc(destSummary(p.Destination), 20))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.policies) == 0 {
		b.WriteString(helpStyle.Render("(no policies — press n to create, e.g. user → gre-lab egress)"))
	}
	return b.String()
}

func (m rootModel) viewRoutes() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-8s %-16s %-14s %-10s %6s %s",
		"ID", "TABLE", "DST", "VIA", "DEV", "METRIC", "STATE")))
	b.WriteString("\n")
	for i, r := range m.routes {
		state := dimStyle.Render("off")
		if r.Enabled {
			state = okStyle.Render("on")
		}
		via := r.Gateway
		if via == "" {
			via = "-"
		}
		line := fmt.Sprintf("%-12s %-8s %-16s %-14s %-10s %6d %s",
			trunc(r.ID, 12), trunc(r.Table, 8), trunc(r.Dst, 16),
			trunc(via, 14), trunc(r.Device, 10), r.Metric, state)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.routes) == 0 {
		b.WriteString(helpStyle.Render("(no explicit routes — press n; policies also create table routes)"))
	}
	return b.String()
}

func (m rootModel) viewNAT() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-12s %-18s %-12s %-14s %s",
		"ID", "KIND", "SOURCE", "OUT", "TO", "STATE")))
	b.WriteString("\n")
	for i, n := range m.nat {
		state := dimStyle.Render("off")
		if n.Enabled {
			state = okStyle.Render("on")
		}
		line := fmt.Sprintf("%-12s %-12s %-18s %-12s %-14s %s",
			trunc(n.ID, 12), n.Kind, trunc(n.SourceCIDR, 18),
			trunc(n.OutIface, 12), trunc(n.ToSource, 14), state)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.nat) == 0 {
		b.WriteString(helpStyle.Render("(no NAT rules — press n for masquerade/snat)"))
	}
	return b.String()
}

func (m rootModel) viewForwards() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-8s %-10s %-10s %-14s %-14s %s",
		"ID", "ACTION", "IN", "OUT", "SOURCE", "DEST", "STATE")))
	b.WriteString("\n")
	for i, f := range m.forwards {
		state := dimStyle.Render("off")
		if f.Enabled {
			state = okStyle.Render("on")
		}
		line := fmt.Sprintf("%-12s %-8s %-10s %-10s %-14s %-14s %s",
			trunc(f.ID, 12), f.Action, trunc(f.InIface, 10), trunc(f.OutIface, 10),
			trunc(f.Source, 14), trunc(f.Dest, 14), state)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.forwards) == 0 {
		b.WriteString(helpStyle.Render("(no forward rules — press n)"))
	}
	return b.String()
}

func (m rootModel) viewTC() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-10s %-10s %-10s %-12s %-18s %s",
		"ID", "DEVICE", "TX", "RX", "MATCH", "VALUE", "NAME")))
	b.WriteString("\n")
	for i, t := range m.tc {
		state := ""
		if !t.Enabled {
			state = dimStyle.Render(" off")
		}
		line := fmt.Sprintf("%-12s %-10s %-10s %-10s %-12s %-18s %s%s",
			trunc(t.ID, 12), trunc(t.Device, 10),
			apply.FormatRateHuman(t.RateTxBps), apply.FormatRateHuman(t.RateRxBps),
			trunc(t.MatchKind, 12), trunc(t.MatchValue, 18), trunc(t.Name, 16), state)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.tc) == 0 {
		b.WriteString(helpStyle.Render("(no TC limits — press n; HTB TX + ingress police RX, rates in bits/s)"))
	}
	return b.String()
}

func (m rootModel) viewFirewall() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-4s %-8s %-8s %-10s %-12s %-8s %-10s %-14s %s",
		"PRI", "BACKEND", "TABLE", "CHAIN", "ACTION", "PROTO", "IFACES", "MATCH", "NAME")))
	b.WriteString("\n")
	for i, f := range m.firewall {
		be := f.Backend
		if be == "" {
			be = "auto"
		}
		ifaces := ""
		if f.InIface != "" || f.OutIface != "" {
			ifaces = trunc(f.InIface, 4) + "→" + trunc(f.OutIface, 4)
		}
		match := ""
		if f.Source != "" {
			match += "s:" + trunc(f.Source, 10)
		}
		if f.Dest != "" {
			if match != "" {
				match += " "
			}
			match += "d:" + trunc(f.Dest, 10)
		}
		if f.Dport != "" {
			match += " :" + f.Dport
		}
		line := fmt.Sprintf("%-4d %-8s %-8s %-10s %-12s %-8s %-10s %-14s %s",
			f.Priority, trunc(be, 8), f.Table, f.Chain, f.Action,
			trunc(f.Protocol, 8), trunc(ifaces, 10), trunc(match, 14), trunc(f.Name, 16))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.firewall) == 0 {
		b.WriteString(helpStyle.Render("(no firewall rules — press n; nft preferred, iptables fallback)"))
	}
	return b.String()
}

func (m rootModel) viewIP() string {
	var b strings.Builder
	secs := []string{"addrs", "rules", "links"}
	for i, s := range secs {
		if i == m.ipSection {
			b.WriteString(tabActive.Render(" " + s + " "))
		} else {
			b.WriteString(tabInactive.Render(" " + s + " "))
		}
		b.WriteString(" ")
	}
	b.WriteString(dimStyle.Render("  [/] switch section"))
	b.WriteString("\n\n")

	switch m.ipSection {
	case ipSecRules:
		b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-6s %-16s %-12s %-8s %-10s %s",
			"ID", "PRIO", "FROM", "TO", "IIF", "TABLE", "ACTION")))
		b.WriteString("\n")
		for i, r := range m.ipRules {
			line := fmt.Sprintf("%-12s %-6d %-16s %-12s %-8s %-10s %s",
				trunc(r.ID, 12), r.Priority, trunc(firstNonEmpty(r.From, "all"), 16),
				trunc(firstNonEmpty(r.To, "-"), 12), trunc(r.Iif, 8), trunc(r.Table, 10), r.Action)
			if i == m.cursor {
				line = selStyle.Render(line)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		if len(m.ipRules) == 0 {
			b.WriteString(helpStyle.Render("(no ip rules — press n)"))
		}
	case ipSecLinks:
		b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-12s %-6s %6s %s",
			"ID", "NAME", "UP", "MTU", "COMMENT")))
		b.WriteString("\n")
		for i, l := range m.links {
			up := "-"
			if l.Up != nil {
				if *l.Up {
					up = "up"
				} else {
					up = "down"
				}
			}
			line := fmt.Sprintf("%-12s %-12s %-6s %6d %s",
				trunc(l.ID, 12), trunc(l.Name, 12), up, l.MTU, trunc(l.Comment, 20))
			if i == m.cursor {
				line = selStyle.Render(line)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		if len(m.links) == 0 {
			b.WriteString(helpStyle.Render("(no link configs — press n for mtu/up)"))
		}
	default:
		b.WriteString(headerStyle.Render(fmt.Sprintf("%-12s %-12s %-22s %-8s %s",
			"ID", "DEVICE", "CIDR", "SCOPE", "PEER")))
		b.WriteString("\n")
		for i, a := range m.ipAddrs {
			line := fmt.Sprintf("%-12s %-12s %-22s %-8s %s",
				trunc(a.ID, 12), trunc(a.Device, 12), trunc(a.CIDR, 22),
				firstNonEmpty(a.Scope, "global"), trunc(a.Peer, 18))
			if i == m.cursor {
				line = selStyle.Render(line)
			}
			b.WriteString(line)
			b.WriteString("\n")
		}
		if len(m.ipAddrs) == 0 {
			b.WriteString(helpStyle.Render("(no managed addresses — press n; ip addr replace)"))
		}
	}
	return b.String()
}

func (m rootModel) planeLines() []string {
	dp := m.dataplane
	if dp == nil {
		return []string{"(no dataplane yet — press r to refresh with host dump)"}
	}
	var lines []string
	add := func(s string) {
		for _, ln := range strings.Split(s, "\n") {
			lines = append(lines, ln)
		}
	}
	add(sectionStyle.Render("Collected  " + dp.CollectedAt))
	add(fmt.Sprintf("tools  ip=%v nft=%v tc=%v iptables=%v",
		dp.IPAvailable, dp.NFTAvailable, dp.TCAvailable, dp.IptablesAvailable))
	add(fmt.Sprintf("sysctl  ip_forward=%s  ip6_forward=%s", dp.IPForward, dp.IP6Forward))
	add("")
	if dp.IPLinkShow != "" {
		add(sectionStyle.Render("ip link"))
		add(dp.IPLinkShow)
		add("")
	}
	if dp.IPAddrShow != "" {
		add(sectionStyle.Render("ip addr"))
		add(dp.IPAddrShow)
		add("")
	}
	add(sectionStyle.Render("ip rule"))
	if dp.IPRulesErr != "" {
		add("err: " + dp.IPRulesErr)
	}
	if len(dp.IPRules) > 0 {
		add(strings.Join(dp.IPRules, "\n"))
	} else if dp.IPRulesRaw != "" {
		add(dp.IPRulesRaw)
	}
	add("")
	add(sectionStyle.Render("ip route (main)"))
	add(firstNonEmpty(dp.IPRoutesMain, "(empty)"))
	if len(dp.IPRouteTables) > 0 {
		add("")
		add(sectionStyle.Render("ip route (custom tables)"))
		for tid, body := range dp.IPRouteTables {
			add("--- table " + tid + " ---")
			add(body)
		}
	}
	add("")
	add(sectionStyle.Render("nft netpolicyd"))
	if dp.NFTNetpolicyd != "" {
		add(dp.NFTNetpolicyd)
	} else if dp.NFTNetpolicydErr != "" {
		add(dimStyle.Render(dp.NFTNetpolicydErr))
	} else {
		add(dimStyle.Render("(no inet netpolicyd table)"))
	}
	if dp.IptablesSave != "" || dp.IptablesList != "" {
		add("")
		add(sectionStyle.Render("iptables"))
		add(firstNonEmpty(dp.IptablesSave, dp.IptablesList))
	}
	if dp.TCQdisc != "" {
		add("")
		add(sectionStyle.Render("tc qdisc"))
		add(dp.TCQdisc)
	}
	if dp.TCClass != "" {
		add("")
		add(sectionStyle.Render("tc class"))
		add(dp.TCClass)
	}
	if len(dp.TCByDevice) > 0 {
		add("")
		add(sectionStyle.Render("tc by device"))
		for dev, body := range dp.TCByDevice {
			add("--- " + dev + " ---")
			add(body)
		}
	}
	return lines
}

func (m rootModel) planeLineCount() int { return len(m.planeLines()) }

func (m rootModel) viewDataplane() string {
	lines := m.planeLines()
	// viewport
	vis := max(8, m.height-8)
	start := m.scroll
	if start > len(lines) {
		start = max(0, len(lines)-1)
	}
	end := min(len(lines), start+vis)
	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("Live host dataplane  (%d-%d / %d)", start+1, end, len(lines))))
	b.WriteString("\n")
	for i := start; i < end; i++ {
		b.WriteString(lines[i])
		b.WriteString("\n")
	}
	if len(lines) == 0 {
		b.WriteString(helpStyle.Render("(empty)"))
	}
	return b.String()
}

func (m rootModel) viewDetail() string {
	var body strings.Builder
	kv := func(k, v string) {
		fmt.Fprintf(&body, "%s %s\n", labelStyle.Render(k), valueStyle.Render(v))
	}
	title := "Detail"
	if m.detailPolicy != nil {
		p := m.detailPolicy
		title = "Policy " + p.Name
		kv("ID", p.ID)
		kv("Priority", fmt.Sprintf("%d", p.Priority))
		kv("Enabled", fmt.Sprintf("%v", p.Enabled))
		kv("Subjects", subjectsSummary(p.Subjects))
		kv("Destination", destSummary(p.Destination))
		kv("Action", string(p.Action))
		kv("Egress", p.EgressName)
		kv("Source CIDR", p.SourceCIDR)
		kv("Table", p.Table)
		kv("Mark", fmt.Sprintf("%d", p.Mark))
		kv("Description", p.Description)
		kv("Created", p.CreatedAt.Format("2006-01-02 15:04:05"))
		kv("Updated", p.UpdatedAt.Format("2006-01-02 15:04:05"))
	} else if m.detailRoute != nil {
		r := m.detailRoute
		title = "Route " + r.ID
		kv("ID", r.ID)
		kv("Table", r.Table)
		kv("Dst", r.Dst)
		kv("Gateway", r.Gateway)
		kv("Device", r.Device)
		kv("Metric", fmt.Sprintf("%d", r.Metric))
		kv("OnLink", fmt.Sprintf("%v", r.OnLink))
		kv("Enabled", fmt.Sprintf("%v", r.Enabled))
		kv("Protocol", r.Protocol)
	} else if m.detailNAT != nil {
		n := m.detailNAT
		title = "NAT " + n.ID
		kv("ID", n.ID)
		kv("Kind", n.Kind)
		kv("Source", n.SourceCIDR)
		kv("Out iface", n.OutIface)
		kv("To source", n.ToSource)
		kv("Comment", n.Comment)
		kv("Enabled", fmt.Sprintf("%v", n.Enabled))
	} else if m.detailFwd != nil {
		f := m.detailFwd
		title = "Forward " + f.ID
		kv("ID", f.ID)
		kv("Action", f.Action)
		kv("In", f.InIface)
		kv("Out", f.OutIface)
		kv("Source", f.Source)
		kv("Dest", f.Dest)
		kv("Enabled", fmt.Sprintf("%v", f.Enabled))
	} else if m.detailTC != nil {
		t := m.detailTC
		title = "TC " + firstNonEmpty(t.Name, t.ID)
		kv("ID", t.ID)
		kv("Name", t.Name)
		kv("Device", t.Device)
		kv("Enabled", fmt.Sprintf("%v", t.Enabled))
		kv("TX rate", apply.FormatRateHuman(t.RateTxBps)+" (HTB egress)")
		kv("RX rate", apply.FormatRateHuman(t.RateRxBps)+" (ingress police)")
		if t.CeilingTxBps > 0 {
			kv("TX ceil", apply.FormatRateHuman(t.CeilingTxBps))
		}
		kv("Match", t.MatchKind+" "+t.MatchValue)
		kv("Priority", fmt.Sprintf("%d", t.Priority))
		kv("Comment", t.Comment)
	} else if m.detailFirewall != nil {
		f := m.detailFirewall
		title = "Firewall " + firstNonEmpty(f.Name, f.ID)
		kv("ID", f.ID)
		kv("Backend", firstNonEmpty(f.Backend, "auto"))
		kv("Table/Chain", f.Table+" / "+f.Chain)
		kv("Action", f.Action)
		kv("Protocol", f.Protocol)
		kv("Source", f.Source)
		kv("Dest", f.Dest)
		kv("In/Out", f.InIface+" / "+f.OutIface)
		kv("Ports", f.Sport+" → "+f.Dport)
		kv("To source", f.ToSource)
		kv("To dest", f.ToDestination)
		kv("Set mark", fmt.Sprintf("%d", f.SetMark))
		kv("Priority", fmt.Sprintf("%d", f.Priority))
		kv("Comment", f.Comment)
	} else if m.detailIPAddr != nil {
		a := m.detailIPAddr
		title = "Address " + a.CIDR
		kv("ID", a.ID)
		kv("Device", a.Device)
		kv("CIDR", a.CIDR)
		kv("Peer", a.Peer)
		kv("Scope", a.Scope)
		kv("Label", a.Label)
		kv("Enabled", fmt.Sprintf("%v", a.Enabled))
	} else if m.detailIPRule != nil {
		r := m.detailIPRule
		title = "IP rule " + r.ID
		kv("ID", r.ID)
		kv("Priority", fmt.Sprintf("%d", r.Priority))
		kv("From", r.From)
		kv("To", r.To)
		kv("Iif/Oif", r.Iif+" / "+r.Oif)
		kv("Fwmark", fmt.Sprintf("%d", r.FwMark))
		kv("Table", r.Table)
		kv("Action", r.Action)
		kv("Enabled", fmt.Sprintf("%v", r.Enabled))
	} else if m.detailLink != nil {
		l := m.detailLink
		title = "Link " + l.Name
		kv("ID", l.ID)
		kv("Name", l.Name)
		if l.Up != nil {
			kv("Up", fmt.Sprintf("%v", *l.Up))
		}
		kv("MTU", fmt.Sprintf("%d", l.MTU))
		kv("Comment", l.Comment)
	}
	help := helpStyle.Render("esc back · e edit · t toggle · D delete")
	content := titleStyle.Render(title) + "\n" + body.String() + "\n" + help
	if m.width > 10 {
		return panelStyle.Width(m.width - 4).Render(content)
	}
	return panelStyle.Render(content)
}

func (m rootModel) viewApplyResult() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Apply result"))
	b.WriteString("\n")
	if m.lastApply == nil {
		b.WriteString(helpStyle.Render("(no apply result)"))
		return b.String()
	}
	r := m.lastApply
	ok := errStyle.Render("FAIL")
	if r.OK {
		ok = okStyle.Render("OK")
	}
	dry := ""
	if r.DryRun {
		dry = warnStyle.Render(" dry-run")
	}
	fmt.Fprintf(&b, "  %s%s  applied=%d  skipped=%d  gen=%d\n", ok, dry, r.Applied, r.Skipped, r.Generation)
	if r.Message != "" {
		fmt.Fprintf(&b, "  %s\n", r.Message)
	}
	if len(r.Errors) > 0 {
		b.WriteString("\n")
		b.WriteString(errStyle.Render("Errors"))
		b.WriteString("\n")
		for _, e := range r.Errors {
			b.WriteString("  " + e + "\n")
		}
	}
	if len(r.Commands) > 0 {
		b.WriteString("\n")
		b.WriteString(sectionStyle.Render("Commands"))
		b.WriteString("\n")
		lines := r.Commands
		start := m.scroll
		if start >= len(lines) {
			start = max(0, len(lines)-1)
		}
		vis := max(6, m.height-14)
		end := min(len(lines), start+vis)
		for i := start; i < end; i++ {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  %s\n", lines[i])))
		}
		if end < len(lines) {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  … +%d more (j/k scroll)\n", len(lines)-end)))
		}
	}
	return panelStyle.Width(max(40, m.width-4)).Render(b.String())
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

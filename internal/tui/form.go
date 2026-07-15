package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	fieldText   = "text"
	fieldSelect = "select"
	fieldBool   = "bool"
)

type fieldDef struct {
	Key     string
	Label   string
	Hint    string
	Width   int
	Kind    string   // text | select | bool
	Options []string // select options
}

type formModel struct {
	title  string
	fields []fieldDef
	inputs []textinput.Model
	selIdx []int
	focus  int
	err    string
	width  int
	height int
	help   string
	note   string
}

func newForm(title string, fields []fieldDef, values map[string]string) formModel {
	inputs := make([]textinput.Model, len(fields))
	selIdx := make([]int, len(fields))
	for i, f := range fields {
		kind := f.Kind
		if kind == "" {
			kind = fieldText
		}
		fields[i].Kind = kind
		ti := textinput.New()
		ti.Placeholder = f.Hint
		w := f.Width
		if w <= 0 {
			w = 56
		}
		ti.CharLimit = 512
		ti.Width = w
		ti.Prompt = ""
		if values != nil {
			if v, ok := values[f.Key]; ok {
				switch kind {
				case fieldSelect:
					selIdx[i] = indexOf(f.Options, v)
					if selIdx[i] < 0 && len(f.Options) > 0 {
						selIdx[i] = 0
					}
				case fieldBool:
					if truthy(v) {
						selIdx[i] = 1
					}
				default:
					ti.SetValue(v)
				}
			}
		}
		inputs[i] = ti
	}
	f := formModel{title: title, fields: fields, inputs: inputs, selIdx: selIdx, focus: 0}
	_ = f.focusInput()
	return f
}

func indexOf(opts []string, v string) int {
	v = strings.TrimSpace(v)
	for i, o := range opts {
		if o == v {
			return i
		}
	}
	return -1
}

func (f formModel) Init() tea.Cmd { return textinput.Blink }

func (f formModel) Update(msg tea.Msg) (formModel, tea.Cmd) {
	if len(f.fields) == 0 {
		return f, nil
	}
	if f.focus < 0 || f.focus >= len(f.fields) {
		f.focus = 0
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			f.focus = (f.focus + 1) % len(f.fields)
			return f, f.focusInput()
		case "shift+tab", "up":
			f.focus = (f.focus + len(f.fields) - 1) % len(f.fields)
			return f, f.focusInput()
		case "left", "h":
			if f.fields[f.focus].Kind == fieldSelect || f.fields[f.focus].Kind == fieldBool {
				f.cycleSelect(f.focus, -1)
				return f, nil
			}
		case "right", "l", " ":
			if f.fields[f.focus].Kind == fieldSelect || f.fields[f.focus].Kind == fieldBool {
				f.cycleSelect(f.focus, +1)
				return f, nil
			}
		}
	}
	if f.fields[f.focus].Kind == fieldText {
		var cmd tea.Cmd
		f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
		return f, cmd
	}
	return f, nil
}

func (f *formModel) cycleSelect(i, delta int) {
	opts := f.fields[i].Options
	if f.fields[i].Kind == fieldBool {
		opts = []string{"n", "y"}
	}
	if len(opts) == 0 {
		return
	}
	f.selIdx[i] = (f.selIdx[i] + delta + len(opts)) % len(opts)
}

func (f *formModel) focusInput() tea.Cmd {
	for i := range f.inputs {
		if i == f.focus && f.fields[i].Kind == fieldText {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
	return textinput.Blink
}

func (f formModel) Values() map[string]string {
	out := make(map[string]string, len(f.fields))
	for i, field := range f.fields {
		switch field.Kind {
		case fieldSelect:
			if len(field.Options) > 0 {
				idx := f.selIdx[i]
				if idx < 0 || idx >= len(field.Options) {
					idx = 0
				}
				out[field.Key] = field.Options[idx]
			}
		case fieldBool:
			if f.selIdx[i] == 1 {
				out[field.Key] = "y"
			} else {
				out[field.Key] = "n"
			}
		default:
			out[field.Key] = strings.TrimSpace(f.inputs[i].Value())
		}
	}
	return out
}

func (f formModel) Get(key string) string { return f.Values()[key] }

func (f *formModel) SetSize(w, h int) {
	f.width = w
	f.height = h
	iw := w - 26
	if iw < 24 {
		iw = 24
	}
	if iw > 100 {
		iw = 100
	}
	for i := range f.inputs {
		f.inputs[i].Width = iw
	}
}

func (f formModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(f.title))
	b.WriteString("\n\n")
	if f.err != "" {
		b.WriteString(errStyle.Render("✗  " + f.err))
		b.WriteString("\n\n")
	}
	if f.note != "" {
		b.WriteString(okStyle.Render("  " + f.note))
		b.WriteString("\n\n")
	}
	for i, field := range f.fields {
		focused := i == f.focus
		var label string
		if focused {
			label = focusStyle.Render(fmt.Sprintf(" %-16s ", field.Label))
		} else {
			label = labelStyle.Width(18).Render(" " + field.Label)
		}
		var val string
		switch field.Kind {
		case fieldSelect:
			opts := field.Options
			if len(opts) == 0 {
				val = dimStyle.Render("(none)")
			} else {
				idx := f.selIdx[i]
				if idx < 0 || idx >= len(opts) {
					idx = 0
				}
				cur := opts[idx]
				if focused {
					val = selStyle.Render(" ◀ "+cur+" ▶ ") + dimStyle.Render(fmt.Sprintf(" %d/%d", idx+1, len(opts)))
				} else {
					val = valueStyle.Render(cur)
				}
			}
		case fieldBool:
			on := f.selIdx[i] == 1
			if focused {
				if on {
					val = okStyle.Render(" [ ON  ] ") + dimStyle.Render("space/←→ toggle")
				} else {
					val = dimStyle.Render(" [ off ] ") + dimStyle.Render("space/←→ toggle")
				}
			} else if on {
				val = okStyle.Render("on")
			} else {
				val = dimStyle.Render("off")
			}
		default:
			val = f.inputs[i].View()
		}
		b.WriteString(label)
		b.WriteString("  ")
		b.WriteString(val)
		b.WriteString("\n")
		if field.Hint != "" && focused {
			b.WriteString(dimStyle.Render("                    " + field.Hint))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	help := f.help
	if help == "" {
		help = "tab/↑↓ move  ·  ←/→ or space change  ·  enter save  ·  esc cancel"
	}
	b.WriteString(helpStyle.Render(help))

	inner := b.String()
	w := f.width
	if w < 40 {
		w = 80
	}
	box := panelStyle.Width(w - 2)
	if f.height > 6 {
		box = box.Height(f.height - 2)
	}
	return box.Render(inner)
}

func truthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes" || s == "true" || s == "1" || s == "on"
}

func fillHeight(content string, width, height int) string {
	if height < 1 {
		height = 1
	}
	if width < 1 {
		width = 1
	}
	style := lipgloss.NewStyle().Width(width).Height(height).MaxHeight(height)
	return style.Render(content)
}

// --- Field sets ---

func policyFormFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "e.g. user4-via-gre-lab"},
		{Key: "priority", Label: "Priority", Hint: "lower = earlier (default 100)"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
		{Key: "subject_kind", Label: "Subject kind", Kind: fieldSelect,
			Options: []string{"cidr", "device", "user", "group", "iface", "mark"},
			Hint:    "who the rule applies to"},
		{Key: "subject_value", Label: "Subject value", Hint: "10.77.0.4/32 or device id"},
		{Key: "dest_kind", Label: "Dest kind", Kind: fieldSelect,
			Options: []string{"any", "cidr", "resource", "host", "dns"},
			Hint:    "where traffic is going"},
		{Key: "dest_value", Label: "Dest value", Hint: "0.0.0.0/0 or host/cidr"},
		{Key: "action", Label: "Action", Kind: fieldSelect,
			Options: []string{"egress", "allow", "deny", "direct", "masquerade", "forward"},
			Hint:    "egress forces traffic out a tunnel"},
		{Key: "egress_name", Label: "Egress iface", Hint: "gre-lab, wg-exit, … (for egress/masq)"},
		{Key: "source_cidr", Label: "Source CIDR", Hint: "optional override, e.g. 10.77.0.4/32"},
		{Key: "table", Label: "Table", Hint: "routing table id/name, optional"},
		{Key: "mark", Label: "Fwmark", Hint: "0 = none"},
		{Key: "description", Label: "Description", Hint: "optional note"},
	}
}

func routeFormFields() []fieldDef {
	return []fieldDef{
		{Key: "table", Label: "Table", Hint: "main | 100 | egress-gre-lab"},
		{Key: "dst", Label: "Destination", Hint: "default | 0.0.0.0/0 | cidr"},
		{Key: "gateway", Label: "Gateway", Hint: "optional next hop"},
		{Key: "device", Label: "Device", Hint: "gre-lab, wg-exit, ens18"},
		{Key: "metric", Label: "Metric", Hint: "optional"},
		{Key: "onlink", Label: "On-link", Kind: fieldBool},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func natFormFields() []fieldDef {
	return []fieldDef{
		{Key: "kind", Label: "Kind", Kind: fieldSelect, Options: []string{"masquerade", "snat"}},
		{Key: "source_cidr", Label: "Source CIDR", Hint: "client prefix, e.g. 10.77.0.0/24"},
		{Key: "out_iface", Label: "Out iface", Hint: "gre-lab, ens18"},
		{Key: "to_source", Label: "To source", Hint: "SNAT address only"},
		{Key: "comment", Label: "Comment", Hint: "optional"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func forwardFormFields() []fieldDef {
	return []fieldDef{
		{Key: "action", Label: "Action", Kind: fieldSelect, Options: []string{"accept", "drop"}},
		{Key: "in_iface", Label: "In iface", Hint: "optional"},
		{Key: "out_iface", Label: "Out iface", Hint: "optional"},
		{Key: "source", Label: "Source", Hint: "CIDR optional"},
		{Key: "dest", Label: "Dest", Hint: "CIDR optional"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func tcFormFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "e.g. user4-50mbit"},
		{Key: "device", Label: "Device", Hint: "gre-lab, ens18, wg0 (required)"},
		{Key: "rate_tx", Label: "TX rate", Hint: "egress bits/s — 50mbit, 10M, 1000000"},
		{Key: "rate_rx", Label: "RX rate", Hint: "ingress bits/s — 20mbit or 0"},
		{Key: "ceil_tx", Label: "TX ceil", Hint: "optional HTB ceil (default = TX rate)"},
		{Key: "match_kind", Label: "Match", Kind: fieldSelect,
			Options: []string{"src_cidr", "dst_cidr", "fwmark", "any"},
			Hint:    "src_cidr for client tunnel IP"},
		{Key: "match_value", Label: "Match value", Hint: "10.77.0.4/32 or mark number"},
		{Key: "priority", Label: "Priority", Hint: "filter prio (0 = auto)"},
		{Key: "comment", Label: "Comment", Hint: "optional"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func firewallFormFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "optional label"},
		{Key: "priority", Label: "Priority", Hint: "lower = earlier (default 100)"},
		{Key: "backend", Label: "Backend", Kind: fieldSelect,
			Options: []string{"auto", "nft", "iptables"}},
		{Key: "table", Label: "Table", Kind: fieldSelect,
			Options: []string{"filter", "nat", "mangle", "raw"}},
		{Key: "chain", Label: "Chain", Kind: fieldSelect,
			Options: []string{"input", "forward", "output", "prerouting", "postrouting"}},
		{Key: "action", Label: "Action", Kind: fieldSelect,
			Options: []string{"accept", "drop", "reject", "return", "masquerade", "snat", "dnat", "mark", "log", "redirect"}},
		{Key: "protocol", Label: "Protocol", Hint: "tcp | udp | icmp | all"},
		{Key: "source", Label: "Source", Hint: "CIDR e.g. 10.77.0.0/24"},
		{Key: "dest", Label: "Dest", Hint: "CIDR"},
		{Key: "in_iface", Label: "In iface", Hint: "wg0, gre-lab"},
		{Key: "out_iface", Label: "Out iface", Hint: "ens18"},
		{Key: "sport", Label: "Sport", Hint: "port or range"},
		{Key: "dport", Label: "Dport", Hint: "22 or 8000:8100"},
		{Key: "to_source", Label: "To source", Hint: "SNAT address"},
		{Key: "to_dest", Label: "To dest", Hint: "DNAT host:port"},
		{Key: "set_mark", Label: "Set mark", Hint: "for action=mark"},
		{Key: "comment", Label: "Comment", Hint: "optional"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func ipAddrFormFields() []fieldDef {
	return []fieldDef{
		{Key: "device", Label: "Device", Hint: "gre-lab, ens18 (required)"},
		{Key: "cidr", Label: "CIDR", Hint: "10.77.0.1/24 or fd00::1/64"},
		{Key: "peer", Label: "Peer", Hint: "point-to-point peer optional"},
		{Key: "broadcast", Label: "Broadcast", Hint: "optional"},
		{Key: "scope", Label: "Scope", Kind: fieldSelect,
			Options: []string{"global", "link", "host"}},
		{Key: "label", Label: "Label", Hint: "optional eth0:1 style"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func ipRuleFormFields() []fieldDef {
	return []fieldDef{
		{Key: "priority", Label: "Priority", Hint: "lower = earlier (0 = auto)"},
		{Key: "from", Label: "From", Hint: "CIDR or empty=all"},
		{Key: "to", Label: "To", Hint: "CIDR optional"},
		{Key: "iif", Label: "Iif", Hint: "incoming iface"},
		{Key: "oif", Label: "Oif", Hint: "outgoing iface"},
		{Key: "fwmark", Label: "Fwmark", Hint: "0 = none"},
		{Key: "table", Label: "Table", Hint: "main | 100 | name"},
		{Key: "action", Label: "Action", Kind: fieldSelect,
			Options: []string{"lookup", "blackhole", "unreachable", "prohibit"}},
		{Key: "comment", Label: "Comment", Hint: "optional"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

func linkFormFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "device name e.g. gre-lab"},
		{Key: "up", Label: "Admin up", Kind: fieldBool},
		{Key: "mtu", Label: "MTU", Hint: "0 = unchanged"},
		{Key: "comment", Label: "Comment", Hint: "optional"},
		{Key: "enabled", Label: "Enabled", Kind: fieldBool},
	}
}

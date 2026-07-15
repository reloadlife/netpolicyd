package tui

import (
	"fmt"
	"strings"

	"github.com/reloadlife/netpolicyd/internal/host"
	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

func (m rootModel) trafficRowCount() int {
	t := m.traffic
	if t == nil {
		return 0
	}
	switch m.trafSec {
	case trafSecIP:
		return len(t.ByIP)
	case trafSecPort:
		return len(t.ByPort)
	case trafSecConn:
		return len(t.Connections)
	default:
		return len(t.Interfaces)
	}
}

func (m rootModel) trafficSecName() string {
	switch m.trafSec {
	case trafSecIP:
		return "by IP"
	case trafSecPort:
		return "by port"
	case trafSecConn:
		return "connections"
	default:
		return "interfaces"
	}
}

// viewTraffic is shared by advanced tabTraffic and easyTraffic.
func (m rootModel) viewTraffic() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Live traffic"))
	b.WriteString(dimStyle.Render("  ·  "))
	secs := []string{"iface", "ip", "port", "conn"}
	for i, s := range secs {
		if i == m.trafSec {
			b.WriteString(tabActive.Render(" " + s + " "))
		} else {
			b.WriteString(tabInactive.Render(" " + s + " "))
		}
		if i < len(secs)-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString(dimStyle.Render("  [/] section  ·  r refresh"))
	b.WriteString("\n")

	t := m.traffic
	if t == nil {
		b.WriteString("\n")
		b.WriteString(helpStyle.Render("loading… (open this tab and wait one refresh)"))
		return b.String()
	}
	if t.Error != "" {
		b.WriteString(errStyle.Render("warn: " + t.Error))
		b.WriteString("\n")
	}

	// summary strip
	iv := "first sample"
	if t.IntervalSec > 0 {
		iv = fmt.Sprintf("%.1fs sample", t.IntervalSec)
	}
	ss := "ss n/a"
	if t.SSAvailable {
		ss = fmt.Sprintf("%d conn · %d estab · %d listen", t.TotalConns, t.Established, t.Listen)
	}
	fmt.Fprintf(&b, "%s  %s  %s  %s\n\n",
		labelStyle.Render("RX "+host.FormatBitRate(t.TotalRxBps)),
		labelStyle.Render("TX "+host.FormatBitRate(t.TotalTxBps)),
		dimStyle.Render(iv),
		dimStyle.Render(ss),
	)

	switch m.trafSec {
	case trafSecIP:
		b.WriteString(m.viewTrafficByIP(t))
	case trafSecPort:
		b.WriteString(m.viewTrafficByPort(t))
	case trafSecConn:
		b.WriteString(m.viewTrafficConns(t))
	default:
		b.WriteString(m.viewTrafficIfaces(t))
	}
	return b.String()
}

func (m rootModel) viewTrafficIfaces(t *pkgapi.TrafficSnapshot) string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-14s %12s %12s %10s %10s %12s %12s",
		"IFACE", "RX rate", "TX rate", "RX pps", "TX pps", "RX total", "TX total")))
	b.WriteString("\n")
	for i, it := range t.Interfaces {
		line := fmt.Sprintf("%-14s %12s %12s %10.0f %10.0f %12s %12s",
			trunc(it.Name, 14),
			host.FormatBitRate(it.RxBps),
			host.FormatBitRate(it.TxBps),
			it.RxPps, it.TxPps,
			host.FormatBytesUI(it.RxBytes),
			host.FormatBytesUI(it.TxBytes),
		)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(t.Interfaces) == 0 {
		b.WriteString(helpStyle.Render("(no interfaces — rates need a second sample after ~1s)"))
	}
	return b.String()
}

func (m rootModel) viewTrafficByIP(t *pkgapi.TrafficSnapshot) string {
	var b strings.Builder
	if !t.SSAvailable {
		b.WriteString(helpStyle.Render("ss not found — install iproute2 for per-IP socket inventory"))
		return b.String()
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-6s %-40s %6s %12s %12s %12s",
		"SIDE", "IP", "CONNS", "SENT", "RECV", "SEND")))
	b.WriteString("\n")
	for i, row := range t.ByIP {
		line := fmt.Sprintf("%-6s %-40s %6d %12s %12s %12s",
			row.Side, trunc(row.IP, 40), row.Conns,
			host.FormatBytesUI(row.BytesSent),
			host.FormatBytesUI(row.BytesRecv),
			host.FormatBitRate(row.SendBps),
		)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(t.ByIP) == 0 {
		b.WriteString(helpStyle.Render("(no sockets)"))
	}
	return b.String()
}

func (m rootModel) viewTrafficByPort(t *pkgapi.TrafficSnapshot) string {
	var b strings.Builder
	if !t.SSAvailable {
		b.WriteString(helpStyle.Render("ss not found — install iproute2 for per-port inventory"))
		return b.String()
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-6s %-6s %-8s %6s %12s %12s",
		"SIDE", "PROTO", "PORT", "CONNS", "SENT", "RECV")))
	b.WriteString("\n")
	for i, row := range t.ByPort {
		line := fmt.Sprintf("%-6s %-6s %-8s %6d %12s %12s",
			row.Side, row.Proto, trunc(row.Port, 8), row.Conns,
			host.FormatBytesUI(row.BytesSent),
			host.FormatBytesUI(row.BytesRecv),
		)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(t.ByPort) == 0 {
		b.WriteString(helpStyle.Render("(no ports)"))
	}
	return b.String()
}

func (m rootModel) viewTrafficConns(t *pkgapi.TrafficSnapshot) string {
	var b strings.Builder
	if !t.SSAvailable {
		b.WriteString(helpStyle.Render("ss not found — install iproute2 for connection list"))
		return b.String()
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-5s %-10s %-22s %-22s %10s %10s %10s",
		"P", "STATE", "LOCAL", "REMOTE", "SENT", "RECV", "SEND")))
	b.WriteString("\n")
	for i, c := range t.Connections {
		local := c.LocalIP + ":" + c.LocalPort
		remote := c.RemoteIP + ":" + c.RemotePort
		line := fmt.Sprintf("%-5s %-10s %-22s %-22s %10s %10s %10s",
			trunc(c.Proto, 5), trunc(c.State, 10),
			trunc(local, 22), trunc(remote, 22),
			host.FormatBytesUI(c.BytesSent),
			host.FormatBytesUI(c.BytesRecv),
			host.FormatBitRate(c.SendBps),
		)
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(t.Connections) == 0 {
		b.WriteString(helpStyle.Render("(no connections)"))
	}
	return b.String()
}

// viewTrafficSummary is a compact strip for Status / Home.
func (m rootModel) viewTrafficSummary() string {
	t := m.traffic
	if t == nil {
		return dimStyle.Render("traffic: (open Traffic tab or wait refresh)")
	}
	return fmt.Sprintf("%s  %s  ·  %d conn / %d estab",
		labelStyle.Render("↓ "+host.FormatBitRate(t.TotalRxBps)),
		labelStyle.Render("↑ "+host.FormatBitRate(t.TotalTxBps)),
		t.TotalConns, t.Established,
	)
}

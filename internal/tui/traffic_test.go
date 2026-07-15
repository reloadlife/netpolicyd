package tui

import (
	"strings"
	"testing"

	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

func TestTrafficRowCount(t *testing.T) {
	m := rootModel{
		trafSec: trafSecIface,
		traffic: &pkgapi.TrafficSnapshot{
			Interfaces:  []pkgapi.IfaceTraffic{{Name: "eth0"}, {Name: "lo"}},
			ByIP:        []pkgapi.IPTraffic{{IP: "1.1.1.1"}},
			ByPort:      []pkgapi.PortTraffic{{Port: "22"}, {Port: "443"}},
			Connections: []pkgapi.ConnTraffic{{Proto: "tcp"}, {Proto: "tcp"}, {Proto: "udp"}},
		},
	}
	if m.trafficRowCount() != 2 {
		t.Fatalf("iface count %d", m.trafficRowCount())
	}
	m.trafSec = trafSecIP
	if m.trafficRowCount() != 1 {
		t.Fatal(m.trafficRowCount())
	}
	m.trafSec = trafSecPort
	if m.trafficRowCount() != 2 {
		t.Fatal(m.trafficRowCount())
	}
	m.trafSec = trafSecConn
	if m.trafficRowCount() != 3 {
		t.Fatal(m.trafficRowCount())
	}
	m.traffic = nil
	if m.trafficRowCount() != 0 {
		t.Fatal(m.trafficRowCount())
	}
}

func TestViewTrafficSections(t *testing.T) {
	m := rootModel{
		width: 120,
		traffic: &pkgapi.TrafficSnapshot{
			SSAvailable: true,
			TotalRxBps:  1e6,
			TotalTxBps:  2e6,
			Interfaces:  []pkgapi.IfaceTraffic{{Name: "eth0", RxBps: 1e6, TxBps: 2e6}},
			ByIP:        []pkgapi.IPTraffic{{IP: "10.0.0.1", Side: "local", Conns: 3}},
			ByPort:      []pkgapi.PortTraffic{{Port: "22", Proto: "tcp", Side: "local", Conns: 1}},
			Connections: []pkgapi.ConnTraffic{
				{Proto: "tcp", State: "ESTAB", LocalIP: "10.0.0.1", LocalPort: "22", RemoteIP: "1.2.3.4", RemotePort: "9"},
			},
		},
	}
	for _, sec := range []int{trafSecIface, trafSecIP, trafSecPort, trafSecConn} {
		m.trafSec = sec
		out := m.viewTraffic()
		if !strings.Contains(out, "Live traffic") {
			t.Fatalf("sec %d missing title: %s", sec, out)
		}
	}
	// empty / loading
	m.traffic = nil
	if !strings.Contains(m.viewTraffic(), "loading") {
		t.Fatal("expected loading")
	}
}

func TestEasyTrafficTabConstants(t *testing.T) {
	if easyTraffic != 7 || easyLive != 8 || easyCount != 9 {
		t.Fatalf("easyTraffic=%d easyLive=%d easyCount=%d", easyTraffic, easyLive, easyCount)
	}
	if tabTraffic != 8 || tabPlane != 9 || tabCount != 10 {
		t.Fatalf("tabTraffic=%d tabPlane=%d tabCount=%d", tabTraffic, tabPlane, tabCount)
	}
}

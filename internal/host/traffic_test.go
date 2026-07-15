package host

import (
	"strings"
	"testing"
	"time"

	pkg "github.com/reloadlife/netpolicyd/pkg/api"
)

func TestFormatBitRate(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "—"},
		{-1, "—"},
		{500, "500 bit/s"},
		{1500, "1.5 Kbit/s"},
		{2.5e6, "2.5 Mbit/s"},
		{1.2e9, "1.2 Gbit/s"},
	}
	for _, c := range cases {
		got := FormatBitRate(c.in)
		if got != c.want {
			t.Errorf("FormatBitRate(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestFormatBytesUI(t *testing.T) {
	if FormatBytesUI(0) != "—" {
		t.Fatal(FormatBytesUI(0))
	}
	if FormatBytesUI(500) != "500 B" {
		t.Fatal(FormatBytesUI(500))
	}
	if !strings.Contains(FormatBytesUI(1500), "KB") {
		t.Fatal(FormatBytesUI(1500))
	}
}

func TestSplitHostPort(t *testing.T) {
	h, p := splitHostPort("1.2.3.4:22")
	if h != "1.2.3.4" || p != "22" {
		t.Fatalf("%s %s", h, p)
	}
	h, p = splitHostPort("[::1]:443")
	if h != "::1" || p != "443" {
		t.Fatalf("%s %s", h, p)
	}
	h, p = splitHostPort("*")
	if h != "*" || p != "*" {
		t.Fatalf("%s %s", h, p)
	}
}

func TestParseSSPlain(t *testing.T) {
	in := `LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
ESTAB 0 0 10.0.0.1:22 10.0.0.2:50000
`
	rows := parseSSPlain(in, "tcp")
	if len(rows) != 2 {
		t.Fatalf("got %d", len(rows))
	}
	if rows[0].State != "LISTEN" || rows[0].LocalPort != "22" {
		t.Fatalf("%+v", rows[0])
	}
	if rows[1].RemoteIP != "10.0.0.2" || rows[1].RemotePort != "50000" {
		t.Fatalf("%+v", rows[1])
	}
}

func TestParseSSTINoStateColumn(t *testing.T) {
	// Real `ss -Hti state established` shape: no STATE field, info on next line.
	in := `0      0                  127.0.0.1:36070                    127.0.0.1:5432
 cubic wscale:7,7 bytes_sent:23185 bytes_received:19678 send 27.6Gbps
0      0               192.168.20.6:22                   100.64.90.13:58166
 cubic bytes_sent:1950173 bytes_received:228442 send 30Mbps
`
	rows := parseSSTI(in, "tcp", "ESTAB")
	if len(rows) != 2 {
		t.Fatalf("got %d rows: %+v", len(rows), rows)
	}
	if rows[0].LocalPort != "36070" || rows[0].RemotePort != "5432" {
		t.Fatalf("%+v", rows[0])
	}
	if rows[0].BytesSent != 23185 || rows[0].BytesRecv != 19678 {
		t.Fatalf("bytes %+v", rows[0])
	}
	if rows[0].SendBps < 1e9 {
		t.Fatalf("send bps %v", rows[0].SendBps)
	}
	if rows[1].LocalIP != "192.168.20.6" || rows[1].BytesSent != 1950173 {
		t.Fatalf("%+v", rows[1])
	}
}

func TestParseSSTIWithState(t *testing.T) {
	in := `ESTAB 0 0 10.0.0.1:22 1.2.3.4:9
 cubic bytes_sent:100 bytes_received:200 send 1Mbps
`
	rows := parseSSTI(in, "tcp", "ESTAB")
	if len(rows) != 1 || rows[0].State != "ESTAB" || rows[0].BytesSent != 100 {
		t.Fatalf("%+v", rows)
	}
}

func TestAggregateByIPPort(t *testing.T) {
	conns := []pkg.ConnTraffic{
		{Proto: "tcp", State: "ESTAB", LocalIP: "10.0.0.1", LocalPort: "22", RemoteIP: "1.1.1.1", RemotePort: "9", BytesSent: 100},
		{Proto: "tcp", State: "ESTAB", LocalIP: "10.0.0.1", LocalPort: "22", RemoteIP: "2.2.2.2", RemotePort: "9", BytesSent: 50},
	}
	ips := aggregateByIP(conns)
	if len(ips) < 2 {
		t.Fatalf("ips=%d", len(ips))
	}
	ports := aggregateByPort(conns)
	if len(ports) < 2 {
		t.Fatalf("ports=%d", len(ports))
	}
}

func TestCollectTrafficIfaces(t *testing.T) {
	// first sample (no rates)
	a := CollectTraffic()
	if len(a.Interfaces) == 0 && a.Error == "" {
		// possible on weird hosts; still ok if no error
	}
	time.Sleep(100 * time.Millisecond)
	b := CollectTraffic()
	if b.IntervalSec <= 0 {
		t.Fatalf("expected interval after second sample, got %v", b.IntervalSec)
	}
}

func TestParseRateToBps(t *testing.T) {
	if parseRateToBps("10", "Mbps") != 10e6 {
		t.Fatal(parseRateToBps("10", "Mbps"))
	}
	if parseRateToBps("1", "Gbps") != 1e9 {
		t.Fatal(parseRateToBps("1", "Gbps"))
	}
}

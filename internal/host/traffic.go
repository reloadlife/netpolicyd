package host

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	pkg "github.com/reloadlife/netpolicyd/pkg/api"
)

// ifaceSample is a single /proc/net/dev reading.
type ifaceSample struct {
	rxB, txB, rxP, txP int64
}

type trafficPrev struct {
	at     time.Time
	ifaces map[string]ifaceSample
}

var (
	trafficMu   sync.Mutex
	trafficLast trafficPrev
)

// CollectTraffic builds a live throughput + connection snapshot.
// Interface rates use delta vs previous CollectTraffic call (process-local).
func CollectTraffic() pkg.TrafficSnapshot {
	now := time.Now().UTC()
	snap := pkg.TrafficSnapshot{
		CollectedAt: now.Format(time.RFC3339),
		SSAvailable: hasBin("ss"),
	}

	// --- interfaces ---
	curIfaces, err := readProcNetDev()
	if err != nil {
		snap.Error = err.Error()
	}

	trafficMu.Lock()
	prev := trafficLast
	var interval float64
	if !prev.at.IsZero() {
		interval = now.Sub(prev.at).Seconds()
		if interval < 0.05 {
			interval = 0.05
		}
		snap.IntervalSec = interval
	}
	// rates
	var list []pkg.IfaceTraffic
	for name, cur := range curIfaces {
		it := pkg.IfaceTraffic{
			Name: name, RxBytes: cur.rxB, TxBytes: cur.txB,
			RxPackets: cur.rxP, TxPackets: cur.txP,
		}
		if interval > 0 {
			if p, ok := prev.ifaces[name]; ok {
				it.RxBps = float64(cur.rxB-p.rxB) * 8 / interval // bits/s
				it.TxBps = float64(cur.txB-p.txB) * 8 / interval
				it.RxPps = float64(cur.rxP-p.rxP) / interval
				it.TxPps = float64(cur.txP-p.txP) / interval
				if it.RxBps < 0 {
					it.RxBps = 0
				}
				if it.TxBps < 0 {
					it.TxBps = 0
				}
			}
		}
		// skip empty virtuals with zero forever unless named interesting
		if cur.rxB == 0 && cur.txB == 0 && !interestingIface(name) {
			continue
		}
		list = append(list, it)
		snap.TotalRxBps += it.RxBps
		snap.TotalTxBps += it.TxBps
	}
	sort.Slice(list, func(i, j int) bool {
		ai := list[i].RxBps + list[i].TxBps
		aj := list[j].RxBps + list[j].TxBps
		if ai != aj {
			return ai > aj
		}
		return list[i].Name < list[j].Name
	})
	snap.Interfaces = list
	trafficLast = trafficPrev{at: now, ifaces: curIfaces}
	trafficMu.Unlock()

	// --- sockets ---
	if snap.SSAvailable {
		conns, e := collectSS()
		if e != nil && snap.Error == "" {
			snap.Error = e.Error()
		}
		snap.Connections = conns
		for _, c := range conns {
			snap.TotalConns++
			st := strings.ToUpper(c.State)
			switch {
			case st == "ESTAB" || st == "ESTABLISHED":
				snap.Established++
			case st == "LISTEN":
				snap.Listen++
			}
		}
		snap.ByIP = aggregateByIP(conns)
		snap.ByPort = aggregateByPort(conns)
	}

	return snap
}

func interestingIface(name string) bool {
	switch name {
	case "lo", "docker0", "gre0", "gretap0", "erspan0", "sit0", "tunl0":
		return false
	}
	if strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
		return false
	}
	return true
}

func readProcNetDev() (map[string]ifaceSample, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return map[string]ifaceSample{}, err
	}
	defer f.Close()
	out := map[string]ifaceSample{}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // headers
		}
		line := strings.TrimSpace(sc.Text())
		// "ens18: 123 45 ..."
		col := strings.IndexByte(line, ':')
		if col < 0 {
			continue
		}
		name := strings.TrimSpace(line[:col])
		fields := strings.Fields(line[col+1:])
		if len(fields) < 16 {
			continue
		}
		// rx: bytes packets ... tx: bytes packets ...
		rxB, _ := strconv.ParseInt(fields[0], 10, 64)
		rxP, _ := strconv.ParseInt(fields[1], 10, 64)
		txB, _ := strconv.ParseInt(fields[8], 10, 64)
		txP, _ := strconv.ParseInt(fields[9], 10, 64)
		out[name] = ifaceSample{rxB: rxB, txB: txB, rxP: rxP, txP: txP}
	}
	return out, sc.Err()
}

var (
	reBytesSent = regexp.MustCompile(`bytes_sent:(\d+)`)
	reBytesRecv = regexp.MustCompile(`bytes_received:(\d+)`)
	reSendRate  = regexp.MustCompile(`\bsend\s+([0-9.]+)([kmgKMG]?bps)`)
)

// collectSS parses TCP/UDP sockets via ss. Prefer -i for byte counters on ESTAB.
func collectSS() ([]pkg.ConnTraffic, error) {
	// TCP with internal info (bytes) for established; then plain for listen/udp.
	var all []pkg.ConnTraffic
	richESTAB := 0
	// When filtered with "state established", ss omits the State column:
	//   Recv-Q Send-Q Local Peer
	// With -i, each socket is followed by a cubic/info line (bytes_sent, …).
	if out, err := runSS("-Hti", "state", "established"); err == nil {
		parsed := parseSSTI(out, "tcp", "ESTAB")
		all = append(all, parsed...)
		richESTAB = len(parsed)
	}
	// Full TCP table (state column present). Skip ESTAB if we already have rich rows.
	if out, err := runSS("-Htan"); err == nil {
		for _, c := range parseSSPlain(out, "tcp") {
			if richESTAB > 0 && (strings.EqualFold(c.State, "ESTAB") || strings.EqualFold(c.State, "ESTABLISHED")) {
				continue
			}
			all = append(all, c)
		}
	}
	if out, err := runSS("-Huan"); err == nil {
		all = append(all, parseSSPlain(out, "udp")...)
	}
	// sort: established with traffic first
	sort.Slice(all, func(i, j int) bool {
		ai := all[i].BytesSent + all[i].BytesRecv
		aj := all[j].BytesSent + all[j].BytesRecv
		if ai != aj {
			return ai > aj
		}
		return all[i].LocalPort < all[j].LocalPort
	})
	// cap list for API size
	const maxConns = 200
	if len(all) > maxConns {
		all = all[:maxConns]
	}
	return all, nil
}

func runSS(args ...string) (string, error) {
	bin := resolveBin("ss")
	if bin == "" {
		return "", os.ErrNotExist
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// parseSSTI parses `ss -Hti` interleaved lines (socket line + cubic/info line).
// defaultState is used when the State column is omitted (e.g. `ss … state established`).
func parseSSTI(out, proto, defaultState string) []pkg.ConnTraffic {
	var rows []pkg.ConnTraffic
	var cur *pkg.ConnTraffic
	flush := func() {
		if cur != nil {
			rows = append(rows, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Form A: STATE Recv-Q Send-Q Local Peer  (full table with -i)
		if len(fields) >= 5 && isSSState(fields[0]) {
			flush()
			c := pkg.ConnTraffic{Proto: proto, State: fields[0]}
			c.LocalIP, c.LocalPort = splitHostPort(fields[3])
			c.RemoteIP, c.RemotePort = splitHostPort(fields[4])
			cur = &c
			continue
		}
		// Form B: Recv-Q Send-Q Local Peer  (state filtered; first field is a number)
		if len(fields) >= 4 && looksLikeRecvQ(fields[0]) {
			flush()
			st := defaultState
			if st == "" {
				st = "ESTAB"
			}
			c := pkg.ConnTraffic{Proto: proto, State: st}
			c.LocalIP, c.LocalPort = splitHostPort(fields[2])
			c.RemoteIP, c.RemotePort = splitHostPort(fields[3])
			cur = &c
			continue
		}
		// info line (cubic … bytes_sent:… )
		if cur == nil {
			continue
		}
		if m := reBytesSent.FindStringSubmatch(line); len(m) == 2 {
			cur.BytesSent, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := reBytesRecv.FindStringSubmatch(line); len(m) == 2 {
			cur.BytesRecv, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := reSendRate.FindStringSubmatch(line); len(m) == 3 {
			cur.SendBps = parseRateToBps(m[1], m[2])
		}
	}
	flush()
	return rows
}

func looksLikeRecvQ(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseSSPlain(out, proto string) []pkg.ConnTraffic {
	var rows []pkg.ConnTraffic
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 {
			continue
		}
		if !isSSState(fields[0]) {
			continue
		}
		c := pkg.ConnTraffic{Proto: proto, State: fields[0]}
		// LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
		// ESTAB 0 0 1.2.3.4:5 6.7.8.9:10
		c.LocalIP, c.LocalPort = splitHostPort(fields[3])
		c.RemoteIP, c.RemotePort = splitHostPort(fields[4])
		rows = append(rows, c)
	}
	return rows
}

func isSSState(s string) bool {
	switch strings.ToUpper(s) {
	case "LISTEN", "ESTAB", "ESTABLISHED", "TIME-WAIT", "TIME_WAIT",
		"CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2", "SYN-SENT", "SYN-RECV",
		"LAST-ACK", "CLOSING", "UNCONN", "UNCONNECTED":
		return true
	default:
		return false
	}
}

func splitHostPort(s string) (host, port string) {
	s = strings.TrimSpace(s)
	if s == "*" || s == "" {
		return "*", "*"
	}
	// [v6]:port or v4:port or host:service
	if strings.HasPrefix(s, "[") {
		end := strings.LastIndex(s, "]")
		if end > 0 {
			host = s[1:end]
			rest := s[end+1:]
			port = strings.TrimPrefix(rest, ":")
			return host, port
		}
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

func parseRateToBps(num, unit string) float64 {
	v, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0
	}
	u := strings.ToLower(unit)
	switch {
	case strings.HasPrefix(u, "g"):
		return v * 1e9
	case strings.HasPrefix(u, "m"):
		return v * 1e6
	case strings.HasPrefix(u, "k"):
		return v * 1e3
	default:
		return v
	}
}

func aggregateByIP(conns []pkg.ConnTraffic) []pkg.IPTraffic {
	type key struct{ ip, side string }
	m := map[key]*pkg.IPTraffic{}
	add := func(ip, side string, c pkg.ConnTraffic) {
		if ip == "" || ip == "*" || ip == "0.0.0.0" || ip == "[::]" || ip == "::" {
			return
		}
		k := key{ip, side}
		if m[k] == nil {
			m[k] = &pkg.IPTraffic{IP: ip, Side: side}
		}
		m[k].Conns++
		m[k].BytesSent += c.BytesSent
		m[k].BytesRecv += c.BytesRecv
		if c.SendBps > m[k].SendBps {
			m[k].SendBps = c.SendBps
		}
	}
	for _, c := range conns {
		add(c.LocalIP, "local", c)
		add(c.RemoteIP, "remote", c)
	}
	out := make([]pkg.IPTraffic, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

func aggregateByPort(conns []pkg.ConnTraffic) []pkg.PortTraffic {
	type key struct{ port, proto, side string }
	m := map[key]*pkg.PortTraffic{}
	add := func(port, proto, side string, c pkg.ConnTraffic) {
		if port == "" || port == "*" {
			return
		}
		k := key{port, proto, side}
		if m[k] == nil {
			m[k] = &pkg.PortTraffic{Port: port, Proto: proto, Side: side}
		}
		m[k].Conns++
		m[k].BytesSent += c.BytesSent
		m[k].BytesRecv += c.BytesRecv
	}
	for _, c := range conns {
		add(c.LocalPort, c.Proto, "local", c)
		add(c.RemotePort, c.Proto, "remote", c)
	}
	out := make([]pkg.PortTraffic, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Conns != out[j].Conns {
			return out[i].Conns > out[j].Conns
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// FormatBitRate renders bits/s for UI.
func FormatBitRate(bps float64) string {
	if bps <= 0 {
		return "—"
	}
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.1f Gbit/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f Kbit/s", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bit/s", bps)
	}
}

// FormatBytesUI renders byte counts.
func FormatBytesUI(n int64) string {
	if n <= 0 {
		return "—"
	}
	f := float64(n)
	switch {
	case f >= 1e12:
		return fmt.Sprintf("%.1f TB", f/1e12)
	case f >= 1e9:
		return fmt.Sprintf("%.1f GB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1f MB", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1f KB", f/1e3)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

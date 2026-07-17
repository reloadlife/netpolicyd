// Package host scrapes live kernel networking state for the admin UI.
package host

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	pkg "github.com/reloadlife/netpolicyd/pkg/api"
)

// Dump is a point-in-time snapshot of host firewall/routing state.
// Alias of the public API type so HTTP and TUI share one shape.
type Dump = pkg.Dataplane

// Collect runs host tools (best-effort; missing tools populate *Err fields).
func Collect() Dump {
	d := Dump{
		CollectedAt:        time.Now().UTC().Format(time.RFC3339),
		IPAvailable:        hasBin("ip"),
		NFTAvailable:       hasBin("nft"),
		TCAvailable:        hasBin("tc"),
		IptablesAvailable:  hasBin("iptables") || hasBin("iptables-save"),
		IP6tablesAvailable: hasBin("ip6tables") || hasBin("ip6tables-save"),
		IPRouteTables:      map[string]string{},
	}

	d.IPForward = readSysctl("net.ipv4.ip_forward")
	d.IP6Forward = readSysctl("net.ipv6.conf.all.forwarding")

	if d.IPAvailable {
		if out, err := run("ip", "-br", "addr", "show"); err == nil {
			d.IPAddrShow = out
		} else if out, err := run("ip", "addr", "show"); err == nil {
			d.IPAddrShow = out
		}
		if out, err := run("ip", "-br", "link", "show"); err == nil {
			d.IPLinkShow = out
		} else if out, err := run("ip", "link", "show"); err == nil {
			d.IPLinkShow = out
		}
		if out, err := run("ip", "neigh", "show"); err == nil {
			d.IPNeigh = out
		}
		if out, err := run("ip", "rule", "list"); err != nil {
			d.IPRulesErr = err.Error()
			d.IPRulesRaw = out
		} else {
			d.IPRulesRaw = out
			d.IPRules = splitNonEmpty(out)
		}
		d.IPRoutesMain, _ = run("ip", "route", "show")
		if out, err := run("ip", "route", "show", "table", "all"); err != nil {
			d.IPRoutesAllErr = err.Error()
			d.IPRoutesAll = out
		} else {
			d.IPRoutesAll = out
		}
		// netpolicyd custom tables 100–120: parse the already-fetched
		// `table all` dump instead of forking `ip route` 21 more times.
		for id, routes := range parseRouteTables(d.IPRoutesAll) {
			d.IPRouteTables[id] = routes
		}
	}

	if b, err := os.ReadFile("/etc/iproute2/rt_tables"); err == nil {
		d.RTTables = string(b)
	}

	if d.NFTAvailable {
		if out, err := run("nft", "list", "ruleset"); err != nil {
			d.NFTRulesetErr = err.Error()
			d.NFTRuleset = out
		} else {
			d.NFTRuleset = out
		}
		if out, err := run("nft", "list", "table", "inet", "netpolicyd"); err != nil {
			d.NFTNetpolicydErr = err.Error()
			// empty table is fine
			if strings.TrimSpace(out) != "" {
				d.NFTNetpolicyd = out
			}
		} else {
			d.NFTNetpolicyd = out
		}
	} else {
		d.NFTRulesetErr = "nft not installed"
	}

	if hasBin("iptables-save") {
		if out, err := run("iptables-save"); err != nil {
			d.IptablesSaveErr = err.Error()
			d.IptablesSave = out
		} else {
			d.IptablesSave = out
		}
	} else if hasBin("iptables") {
		if out, err := run("iptables", "-L", "-n", "-v", "--line-numbers"); err != nil {
			d.IptablesListErr = err.Error()
			d.IptablesList = out
		} else {
			d.IptablesList = out
		}
		// also try -t nat
		if out, err := run("iptables", "-t", "nat", "-L", "-n", "-v", "--line-numbers"); err == nil {
			d.IptablesList += "\n# --- nat ---\n" + out
		}
		if out, err := run("iptables", "-t", "mangle", "-L", "-n", "-v", "--line-numbers"); err == nil {
			d.IptablesList += "\n# --- mangle ---\n" + out
		}
	} else {
		d.IptablesSaveErr = "iptables not installed"
	}

	if hasBin("ip6tables-save") {
		if out, err := run("ip6tables-save"); err != nil {
			d.IP6tablesErr = err.Error()
			d.IP6tablesSave = out
		} else {
			d.IP6tablesSave = out
		}
	}

	if d.TCAvailable {
		d.TCByDevice = map[string]string{}
		if out, err := run("tc", "qdisc", "show"); err != nil {
			d.TCErr = err.Error()
			d.TCQdisc = out
		} else {
			d.TCQdisc = out
		}
		if out, err := run("tc", "class", "show"); err == nil {
			d.TCClass = out
		}
		if out, err := run("tc", "filter", "show"); err == nil {
			d.TCFilter = out
		}
		// Per-device detail for ifaces that already have a qdisc
		for _, line := range splitNonEmpty(d.TCQdisc) {
			// "qdisc htb 1: dev gre-lab root …"
			dev := tcDevFromQdiscLine(line)
			if dev == "" {
				continue
			}
			if _, ok := d.TCByDevice[dev]; ok {
				continue
			}
			var b strings.Builder
			if out, err := run("tc", "qdisc", "show", "dev", dev); err == nil {
				b.WriteString("# qdisc\n")
				b.WriteString(out)
			}
			if out, err := run("tc", "class", "show", "dev", dev); err == nil && strings.TrimSpace(out) != "" {
				b.WriteString("\n# class\n")
				b.WriteString(out)
			}
			if out, err := run("tc", "filter", "show", "dev", dev); err == nil && strings.TrimSpace(out) != "" {
				b.WriteString("\n# filter\n")
				b.WriteString(out)
			}
			if out, err := run("tc", "filter", "show", "dev", dev, "parent", "ffff:"); err == nil && strings.TrimSpace(out) != "" {
				b.WriteString("\n# filter ingress\n")
				b.WriteString(out)
			}
			d.TCByDevice[dev] = b.String()
		}
	}

	return d
}

// parseRouteTables groups lines of `ip route show table all` by their
// `table <id>` token, keeping only numeric ids in [100,120] (netpolicyd's
// custom tables). Avoids forking `ip route` once per table id.
func parseRouteTables(routesAll string) map[string]string {
	byID := map[string][]string{}
	for _, line := range strings.Split(routesAll, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] != "table" {
				continue
			}
			id := fields[i+1]
			if isRouteTableID(id) {
				byID[id] = append(byID[id], line)
			}
			break
		}
	}
	out := make(map[string]string, len(byID))
	for id, lines := range byID {
		out[id] = strings.Join(lines, "\n")
	}
	return out
}

// isRouteTableID reports whether s is an all-digit id in [100,120].
func isRouteTableID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 100 && n <= 120
}

// tcDevFromQdiscLine extracts device name from `tc qdisc show` line.
func tcDevFromQdiscLine(line string) string {
	// formats: "qdisc htb 1: dev gre-lab root refcnt 2"
	parts := strings.Fields(line)
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "dev" {
			return parts[i+1]
		}
	}
	return ""
}

func hasBin(name string) bool {
	return resolveBin(name) != ""
}

// resolveBin finds a binary even when PATH omits /usr/sbin (common under services).
func resolveBin(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := dir + "/" + name
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func run(name string, args ...string) (string, error) {
	bin := resolveBin(name)
	if bin == "" {
		return "", os.ErrNotExist
	}
	cmd := exec.Command(bin, args...)
	// Ensure child also sees sbin
	cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readSysctl(key string) string {
	// try sysctl -n
	if out, err := run("sysctl", "-n", key); err == nil {
		return strings.TrimSpace(out)
	}
	// fallback /proc
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

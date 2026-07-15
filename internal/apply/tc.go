package apply

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// HTB layout (per device):
//
//	root HTB 1: default 1:1 (unlimited catch-all)
//	per-rule class 1:<minor>  minor in [0x10, 0xffe]
//	ingress qdisc ffff: + police for RX
const (
	tcRootHandle   = "1:"
	tcDefaultClass = "1:1"
	tcDefaultMinor = 1
	tcIngress      = "ffff:"
	tcMinorMin     = 0x10
	tcMinorMax     = 0xffe
)

// planTC appends tc qdisc/class/filter commands for managed limits.
func planTC(rules []api.TCSpec) []string {
	if len(rules) == 0 {
		return nil
	}
	// group enabled rules with any rate by device
	byDev := map[string][]api.TCSpec{}
	for _, r := range rules {
		if !r.Enabled || r.Device == "" {
			continue
		}
		if r.RateTxBps <= 0 && r.RateRxBps <= 0 {
			continue
		}
		byDev[r.Device] = append(byDev[r.Device], r)
	}
	if len(byDev) == 0 {
		return nil
	}
	devs := make([]string, 0, len(byDev))
	for d := range byDev {
		devs = append(devs, d)
	}
	sort.Strings(devs)

	var cmds []string
	for _, dev := range devs {
		list := byDev[dev]
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })

		needTX, needRX := false, false
		for _, r := range list {
			if r.RateTxBps > 0 {
				needTX = true
			}
			if r.RateRxBps > 0 {
				needRX = true
			}
		}
		if needTX {
			cmds = append(cmds,
				fmt.Sprintf("tc qdisc replace dev %s root handle %s htb default %d", dev, tcRootHandle, tcDefaultMinor),
				fmt.Sprintf("tc class replace dev %s parent %s classid %s htb rate 100gbit ceil 100gbit",
					dev, tcRootHandle, tcDefaultClass),
			)
		}
		if needRX {
			// replace is not always supported for ingress; del+add is noisier but works.
			cmds = append(cmds,
				fmt.Sprintf("tc qdisc del dev %s ingress 2>/dev/null || true", dev),
				fmt.Sprintf("tc qdisc add dev %s handle %s ingress 2>/dev/null || tc qdisc replace dev %s handle %s ingress",
					dev, tcIngress, dev, tcIngress),
			)
		}

		// Track minors used on this device to avoid collisions within the plan.
		used := map[uint32]string{}
		for _, r := range list {
			minor := allocateTCMinor(r.ID, used)
			used[minor] = r.ID
			cmds = append(cmds, planOneTC(dev, r, minor)...)
		}
	}
	return cmds
}

func planOneTC(dev string, r api.TCSpec, minor uint32) []string {
	var cmds []string
	classID := fmt.Sprintf("1:%x", minor)
	pref := r.Priority
	if pref <= 0 {
		pref = int(minor)
	}

	if r.RateTxBps > 0 {
		rate := formatTCRate(r.RateTxBps)
		ceil := rate
		if r.CeilingTxBps > 0 {
			ceil = formatTCRate(r.CeilingTxBps)
		}
		burst := formatTCBurst(r.RateTxBps)
		cmds = append(cmds, fmt.Sprintf(
			"tc class replace dev %s parent %s classid %s htb rate %s ceil %s burst %s cburst %s",
			dev, tcRootHandle, classID, rate, ceil, burst, burst,
		))
		cmds = append(cmds, fmt.Sprintf(
			"tc qdisc replace dev %s parent %s handle %x: sfq perturb 10",
			dev, classID, minor,
		))
		cmds = append(cmds, filterCmd(dev, tcRootHandle, pref, minor, r, classID, "")...)
	}

	if r.RateRxBps > 0 {
		rate := formatTCRate(r.RateRxBps)
		burst := formatTCBurst(r.RateRxBps)
		rxPref := pref + 1000
		police := fmt.Sprintf("action police rate %s burst %s drop", rate, burst)
		cmds = append(cmds, filterCmd(dev, tcIngress, rxPref, minor+0x8000, r, "", police)...)
	}
	return cmds
}

// filterCmd builds one or more tc filter replace lines.
// flowid is set for HTB egress; police is set for ingress.
func filterCmd(dev, parent string, pref int, handle uint32, r api.TCSpec, flowid, police string) []string {
	kind := strings.ToLower(strings.TrimSpace(r.MatchKind))
	value := strings.TrimSpace(r.MatchValue)
	tail := ""
	if flowid != "" {
		tail = " flowid " + flowid
	}
	if police != "" {
		tail = " " + police
	}
	switch kind {
	case "fwmark":
		if value == "" {
			return nil
		}
		// fw classifier: tc filter … protocol all handle <n> fw mark <mark> …
		return []string{fmt.Sprintf(
			"tc filter replace dev %s protocol all parent %s prio %d handle %d fw mark %s%s",
			dev, parent, pref, handle&0xffff, normalizeMark(value), tail,
		)}
	case "src_cidr":
		if value == "" {
			return nil
		}
		return []string{fmt.Sprintf(
			"tc filter replace dev %s protocol ip parent %s prio %d handle %d: u32 match ip src %s%s",
			dev, parent, pref, handle, ensureHostOrCIDR(value), tail,
		)}
	case "dst_cidr":
		if value == "" {
			return nil
		}
		return []string{fmt.Sprintf(
			"tc filter replace dev %s protocol ip parent %s prio %d handle %d: u32 match ip dst %s%s",
			dev, parent, pref, handle, ensureHostOrCIDR(value), tail,
		)}
	default: // any
		return []string{fmt.Sprintf(
			"tc filter replace dev %s protocol ip parent %s prio %d handle %d: u32 match u32 0 0%s",
			dev, parent, pref, handle, tail,
		)}
	}
}

func ensureHostOrCIDR(v string) string {
	if strings.Contains(v, "/") {
		return v
	}
	// bare IP → /32
	return v + "/32"
}

func normalizeMark(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		n, err := strconv.ParseUint(v[2:], 16, 32)
		if err == nil {
			return strconv.FormatUint(n, 10)
		}
	}
	return v
}

func allocateTCMinor(id string, used map[uint32]string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	base := h.Sum32()
	for i := uint32(0); i < (tcMinorMax - tcMinorMin + 1); i++ {
		m := tcMinorMin + (base+i)%(tcMinorMax-tcMinorMin+1)
		if m == tcDefaultMinor {
			continue
		}
		if owner, ok := used[m]; !ok || owner == id {
			return m
		}
	}
	return tcMinorMin
}

// formatTCRate formats bits/sec for tc (prefers kbit/mbit when aligned).
func formatTCRate(bps int64) string {
	if bps < 1 {
		bps = 1
	}
	if bps%1_000_000 == 0 {
		return strconv.FormatInt(bps/1_000_000, 10) + "mbit"
	}
	if bps%1000 == 0 {
		return strconv.FormatInt(bps/1000, 10) + "kbit"
	}
	return strconv.FormatInt(bps, 10) + "bit"
}

// formatTCBurst returns a reasonable HTB/police burst in bytes (~50ms, min 3200).
func formatTCBurst(bps int64) string {
	burst := bps / 8 / 20
	if burst < 3200 {
		burst = 3200
	}
	if burst > 16*1024*1024 {
		burst = 16 * 1024 * 1024
	}
	return strconv.FormatInt(burst, 10)
}

// ParseRateBitPS parses human rates: "10mbit", "1gbit", "500k", "1000000", "10M".
func ParseRateBitPS(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "unlimited" {
		return 0, nil
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "gbit") || strings.HasSuffix(s, "gbps"):
		mult = 1_000_000_000
		s = strings.TrimSuffix(strings.TrimSuffix(s, "gbit"), "gbps")
	case strings.HasSuffix(s, "mbit") || strings.HasSuffix(s, "mbps"):
		mult = 1_000_000
		s = strings.TrimSuffix(strings.TrimSuffix(s, "mbit"), "mbps")
	case strings.HasSuffix(s, "kbit") || strings.HasSuffix(s, "kbps"):
		mult = 1_000
		s = strings.TrimSuffix(strings.TrimSuffix(s, "kbit"), "kbps")
	case strings.HasSuffix(s, "bit") || strings.HasSuffix(s, "bps"):
		mult = 1
		s = strings.TrimSuffix(strings.TrimSuffix(s, "bit"), "bps")
	case strings.HasSuffix(s, "g"):
		mult = 1_000_000_000
		s = strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "m"):
		mult = 1_000_000
		s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "k"):
		mult = 1_000
		s = strings.TrimSuffix(s, "k")
	}
	s = strings.TrimSpace(s)
	// allow float like 1.5mbit
	if strings.Contains(s, ".") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid rate %q", s)
		}
		return int64(f * float64(mult)), nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate %q", s)
	}
	return n * mult, nil
}

// FormatRateHuman renders bits/sec as compact "50mbit" / "500kbit" / "1234bit".
func FormatRateHuman(bps int64) string {
	if bps <= 0 {
		return "—"
	}
	return formatTCRate(bps)
}

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
//
// Important: Linux often rejects `tc qdisc replace` on an existing HTB root
// ("Change operation not supported by specified qdisc") when children exist.
// We only *add* root/leaf qdiscs when missing, and always replace classes/filters.
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
			// Ensure HTB root exists. Never `replace` an existing HTB root —
			// kernels reject that when classes/sfq children are present.
			// If root is a different qdisc type, delete once then add HTB.
			cmds = append(cmds,
				fmt.Sprintf(
					`if tc qdisc show dev %s 2>/dev/null | grep -qE 'qdisc htb 1:'; then true; `+
						`elif tc qdisc show dev %s 2>/dev/null | grep -qE 'qdisc .+ root'; then `+
						`tc qdisc del dev %s root 2>/dev/null || true; tc qdisc add dev %s root handle 1: htb default 1; `+
						`else tc qdisc add dev %s root handle 1: htb default 1; fi`,
					dev, dev, dev, dev, dev,
				),
				// Unlimited default class (catch-all). replace is fine for classes.
				fmt.Sprintf("tc class replace dev %s parent %s classid %s htb rate 100gbit ceil 100gbit",
					dev, tcRootHandle, tcDefaultClass),
				// Also ensure a high-rate default leaf many hosts already use (1:999)
				// so traffic is not blackholed if the kernel still has default 0x999.
				fmt.Sprintf("tc class replace dev %s parent %s classid 1:999 htb rate 10gbit ceil 10gbit",
					dev, tcRootHandle),
			)
		}
		if needRX {
			// ingress: del+add is reliable; replace is flaky.
			cmds = append(cmds,
				fmt.Sprintf("tc qdisc del dev %s ingress 2>/dev/null || true", dev),
				fmt.Sprintf("tc qdisc add dev %s handle %s ingress", dev, tcIngress),
			)
		}

		// Track minors used on this device to avoid collisions within the plan.
		used := map[uint32]string{}
		// One node-id allocator per device: filter identity is scoped to the device.
		alloc := newU32Alloc()
		for _, r := range list {
			minor := allocateTCMinor(r.ID, used)
			used[minor] = r.ID
			cmds = append(cmds, planOneTC(dev, r, minor, alloc)...)
		}
	}
	return cmds
}

func planOneTC(dev string, r api.TCSpec, minor uint32, alloc *u32Alloc) []string {
	var cmds []string
	classID := fmt.Sprintf("1:%x", minor)
	pref := r.Priority
	if pref <= 0 {
		pref = int(minor)
	}
	// Keep prio in a safe range for tc (1..65535).
	if pref < 1 {
		pref = 1
	}
	if pref > 60000 {
		pref = 60000
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
		// SFQ leaf: add only if missing (replace fails on many kernels when SFQ exists).
		cmds = append(cmds, fmt.Sprintf(
			`tc qdisc show dev %s 2>/dev/null | grep -qE 'parent %s' || tc qdisc add dev %s parent %s handle %x: sfq perturb 10`,
			dev, classID, dev, classID, minor,
		))
		// Multiple src CIDRs → multiple filters → same HTB class (shared rate pool).
		cmds = append(cmds, filterCmd(dev, tcRootHandle, pref, r, classID, "", alloc)...)
	}

	if r.RateRxBps > 0 {
		rate := formatTCRate(r.RateRxBps)
		burst := formatTCBurst(r.RateRxBps)
		rxPref := pref + 1000
		if rxPref > 60000 {
			rxPref = 60000
		}
		// Shared police index so multi-CIDR filters share one meter (not N×rate).
		// Index space: 1..0xffff; derive from class minor for stability.
		policeIdx := (minor & 0x7fff)
		if policeIdx == 0 {
			policeIdx = 1
		}
		police := fmt.Sprintf("action police index %d rate %s burst %s drop", policeIdx, rate, burst)
		cmds = append(cmds, filterCmd(dev, tcIngress, rxPref, r, "", police, alloc)...)
	}
	return cmds
}

// splitMatchValues splits comma/space-separated CIDRs (account-shared pools).
func splitMatchValues(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	// Allow "a/32,b/32" or "a/32 b/32"
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// filterCmd builds one or more tc filter replace lines.
// flowid is set for HTB egress; police is set for ingress.
//
// src_cidr / dst_cidr MatchValue may list multiple CIDRs; each gets a filter
// with a distinct prio but the same flowid / police index (shared pool).
//
// u32 filters carry an explicit stable "handle 800::NN" so `tc filter replace`
// truly replaces instead of adding a new duplicate every reconcile (unbounded
// growth). Node ids come from alloc, which keeps them unique per (parent, prio)
// and independent of prio. The fw classifier takes the mark itself as its handle.
func filterCmd(dev, parent string, pref int, r api.TCSpec, flowid, police string, alloc *u32Alloc) []string {
	kind := strings.ToLower(strings.TrimSpace(r.MatchKind))
	value := strings.TrimSpace(r.MatchValue)
	tail := ""
	if flowid != "" {
		tail = " flowid " + flowid
	}
	if police != "" {
		tail = " " + police
	}
	// Unique prio per rule (filters are keyed by parent+prio+protocol).
	if pref < 1 {
		pref = 1
	}
	switch kind {
	case "fwmark":
		if value == "" {
			return nil
		}
		// fw classifier: the mark IS the handle; there is no "mark" keyword.
		return []string{fmt.Sprintf(
			"tc filter replace dev %s protocol all parent %s prio %d handle %s fw%s",
			dev, parent, pref, normalizeMark(value), tail,
		)}
	case "src_cidr":
		vals := splitMatchValues(value)
		if len(vals) == 0 {
			return nil
		}
		var out []string
		for i, v := range vals {
			p := pref + i
			if p > 60000 {
				p = 60000
			}
			nodeid := alloc.alloc(parent, p, fmt.Sprintf("%s#%d", r.ID, i))
			out = append(out, fmt.Sprintf(
				"tc filter replace dev %s protocol ip parent %s prio %d handle 800::%x u32 match ip src %s%s",
				dev, parent, p, nodeid, ensureHostOrCIDR(v), tail,
			))
		}
		return out
	case "dst_cidr":
		vals := splitMatchValues(value)
		if len(vals) == 0 {
			return nil
		}
		var out []string
		for i, v := range vals {
			p := pref + i
			if p > 60000 {
				p = 60000
			}
			nodeid := alloc.alloc(parent, p, fmt.Sprintf("%s#%d", r.ID, i))
			out = append(out, fmt.Sprintf(
				"tc filter replace dev %s protocol ip parent %s prio %d handle 800::%x u32 match ip dst %s%s",
				dev, parent, p, nodeid, ensureHostOrCIDR(v), tail,
			))
		}
		return out
	default: // any
		return []string{fmt.Sprintf(
			"tc filter replace dev %s protocol ip parent %s prio %d handle 800::%x u32 match u32 0 0%s",
			dev, parent, pref, alloc.alloc(parent, pref, r.ID+"#0"), tail,
		)}
	}
}

// u32Alloc hands out u32 filter node ids for `handle 800::NN`.
//
// A filter's kernel identity is (dev, parent, protocol, prio) + node id. Node
// ids MUST NOT be derived from the same value as prio: deriving both from
// minor+i made them perfectly correlated, so rule A's i-th filter aliased rule
// B's 0th whenever their minors were adjacent (reachable with default
// priorities) and `replace` silently gave A's CIDR B's rate limit.
//
// Node ids are seeded from the rule ID + CIDR index — independent of prio — and
// probed against the ids already used at the same (parent, prio). Deterministic
// for a given rule set, so repeated reconciles replace the same filter.
type u32Alloc struct{ used map[string]bool }

func newU32Alloc() *u32Alloc { return &u32Alloc{used: map[string]bool{}} }

func (a *u32Alloc) alloc(parent string, prio int, seed string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	base := h.Sum32()
	const span = 0xfff // node ids 1..0xfff
	for k := uint32(0); k < span; k++ {
		id := 1 + (base+k)%span
		key := fmt.Sprintf("%s|%d|%d", parent, prio, id)
		if !a.used[key] {
			a.used[key] = true
			return id
		}
	}
	return 1
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

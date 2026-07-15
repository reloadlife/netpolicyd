package apply

import (
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// listIndex maps id and name → list.
func listIndex(lists []api.IPList) map[string]api.IPList {
	idx := make(map[string]api.IPList, len(lists)*2)
	for _, l := range lists {
		idx[l.ID] = l
		if l.Name != "" {
			idx[l.Name] = l
		}
	}
	return idx
}

func listEntries(idx map[string]api.IPList, idOrName string) []string {
	idOrName = strings.TrimSpace(idOrName)
	if idOrName == "" {
		return nil
	}
	l, ok := idx[idOrName]
	if !ok {
		return nil
	}
	var out []string
	for _, e := range l.Entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// bare IPv4 → /32
		if !strings.Contains(e, "/") && strings.Count(e, ".") == 3 && !strings.Contains(e, ":") {
			e = e + "/32"
		}
		out = append(out, e)
	}
	return out
}

// expandFirewallLists turns SourceList/DestList into concrete Source/Dest rules.
// Cartesian product when both lists set; single-side expansion otherwise.
func expandFirewallLists(rules []api.FirewallRule, lists []api.IPList) []api.FirewallRule {
	idx := listIndex(lists)
	var out []api.FirewallRule
	for _, r := range rules {
		var srcs, dsts []string
		if r.SourceList != "" {
			srcs = listEntries(idx, r.SourceList)
			if len(srcs) == 0 {
				// unknown list — keep original (may fail empty match)
				srcs = []string{r.Source}
			}
		} else {
			srcs = []string{r.Source}
		}
		if r.DestList != "" {
			dsts = listEntries(idx, r.DestList)
			if len(dsts) == 0 {
				dsts = []string{r.Dest}
			}
		} else {
			dsts = []string{r.Dest}
		}
		if r.SourceList == "" && r.DestList == "" {
			out = append(out, r)
			continue
		}
		n := 0
		for _, s := range srcs {
			for _, d := range dsts {
				cp := r
				cp.Source = s
				cp.Dest = d
				cp.SourceList = ""
				cp.DestList = ""
				if n > 0 {
					cp.ID = r.ID + "-" + itoa(n)
					if cp.Name != "" {
						cp.Name = r.Name + "-" + itoa(n)
					}
				}
				out = append(out, cp)
				n++
			}
		}
	}
	return out
}

// expandNATLists expands SourceList on NAT specs.
func expandNATLists(nats []api.NATSpec, lists []api.IPList) []api.NATSpec {
	idx := listIndex(lists)
	var out []api.NATSpec
	for _, n := range nats {
		entries := listEntries(idx, n.SourceList)
		if len(entries) == 0 {
			out = append(out, n)
			continue
		}
		for i, e := range entries {
			cp := n
			cp.SourceCIDR = e
			cp.SourceList = ""
			if i > 0 {
				cp.ID = n.ID + "-" + itoa(i)
			}
			out = append(out, cp)
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

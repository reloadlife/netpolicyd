package store

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/reloadlife/netpolicyd/pkg/api"
)

// Trust-boundary validation. Every desired-state field that later reaches
// `sh -c` (internal/apply) or an nft/iptables/tc/ip argv is validated here,
// at the single choke point all HTTP handlers route through. Reject, don't
// sanitize: none of these fields legitimately contain shell metacharacters,
// whitespace, or extra tokens, so anything that does is an injection attempt.
//
// ponytail: field-class regexes + net.Parse, not a shell lexer. Upgrade to
// argv (drop `sh -c`) if a field ever needs to carry a space.

var (
	reIface   = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,15}$`)
	reSysctl  = regexp.MustCompile(`^[a-z0-9_./-]{1,128}$`)
	rePort    = regexp.MustCompile(`^[0-9]{1,5}([:-][0-9]{1,5})?(,[0-9]{1,5}([:-][0-9]{1,5})?)*$`)
	reProto   = regexp.MustCompile(`^[A-Za-z0-9]{1,16}$`)
	reTable   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)
	reCtState = regexp.MustCompile(`^[A-Za-z,]{1,64}$`)
	reToAddr  = regexp.MustCompile(`^[0-9A-Fa-f:.\[\]/-]{1,48}(:[0-9]{1,5})?$`)
	// Integers plus the symbolic values real sysctls take (net.core.default_qdisc=fq,
	// net.ipv4.tcp_congestion_control=bbr). No spaces: apply.go emits an unquoted
	// `sysctl -w k=v`, so a multi-value sysctl silently corrupts to its first element.
	reSysVal = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reMark   = regexp.MustCompile(`^(0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,10})(/(0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,10}))?$`)
)

// validIface checks a network device name (also accepts empty when allowed).
func validIface(field, v string, allowEmpty bool) error {
	if v == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s required", field)
	}
	if !reIface.MatchString(v) {
		return fmt.Errorf("invalid %s %q", field, v)
	}
	return nil
}

// validCIDR accepts "", "default"/"any"/"0.0.0.0/0", a bare IP, or a CIDR.
func validCIDR(field, v string, allowEmpty bool) error {
	v = strings.TrimSpace(v)
	if v == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s required", field)
	}
	switch strings.ToLower(v) {
	case "default", "any":
		return nil
	}
	if strings.Contains(v, "/") {
		if _, _, err := net.ParseCIDR(v); err != nil {
			return fmt.Errorf("invalid %s %q", field, v)
		}
		return nil
	}
	if net.ParseIP(v) == nil {
		return fmt.Errorf("invalid %s %q", field, v)
	}
	return nil
}

// validCIDRList validates comma/space-separated CIDRs (tc shared pools).
func validCIDRList(field, v string) error {
	for _, part := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if err := validCIDR(field, part, false); err != nil {
			return err
		}
	}
	return nil
}

func validMatch(field, v string, allowEmpty bool) error {
	if v == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s required", field)
	}
	if !reMark.MatchString(v) {
		return fmt.Errorf("invalid %s %q", field, v)
	}
	return nil
}

func validOpt(field, v string, re *regexp.Regexp) error {
	if v == "" {
		return nil
	}
	if !re.MatchString(v) {
		return fmt.Errorf("invalid %s %q", field, v)
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func validatePolicy(p api.PolicyRule) error {
	if err := firstErr(
		validIface("egress_name", p.EgressName, p.Action != api.ActionEgress),
		validCIDR("source_cidr", p.SourceCIDR, true),
		validOpt("table", p.Table, reTable),
	); err != nil {
		return err
	}
	for _, sub := range p.Subjects {
		if sub.Kind == "cidr" {
			if err := validCIDR("subject", sub.Value, true); err != nil {
				return err
			}
		}
	}
	if p.Destination.Kind == "cidr" || p.Destination.Kind == "any" {
		if err := validCIDR("destination", p.Destination.Value, true); err != nil {
			return err
		}
	}
	return nil
}

func validateRoute(r api.RouteSpec) error {
	return firstErr(
		validCIDR("dst", r.Dst, true),
		validCIDR("gateway", r.Gateway, true),
		validIface("device", r.Device, true),
		validOpt("table", r.Table, reTable),
	)
}

func validateNAT(n api.NATSpec) error {
	return firstErr(
		validCIDR("source_cidr", n.SourceCIDR, true),
		validIface("out_iface", n.OutIface, true),
		validOpt("to_source", n.ToSource, reToAddr),
	)
}

func validateForward(f api.ForwardSpec) error {
	return firstErr(
		validIface("in_iface", f.InIface, true),
		validIface("out_iface", f.OutIface, true),
		validCIDR("source", f.Source, true),
		validCIDR("dest", f.Dest, true),
	)
}

func validateFirewall(r api.FirewallRule) error {
	return firstErr(
		validCIDR("source", r.Source, true),
		validCIDR("dest", r.Dest, true),
		validIface("in_iface", r.InIface, true),
		validIface("out_iface", r.OutIface, true),
		validOpt("protocol", r.Protocol, reProto),
		validOpt("sport", r.Sport, rePort),
		validOpt("dport", r.Dport, rePort),
		validOpt("ct_state", r.CtState, reCtState),
		validOpt("to_source", r.ToSource, reToAddr),
		validOpt("to_destination", r.ToDestination, reToAddr),
	)
}

func validateIPAddr(a api.IPAddrSpec) error {
	return firstErr(
		validIface("device", a.Device, false),
		validCIDR("cidr", a.CIDR, false),
	)
}

func validateIPRule(r api.IPRuleSpec) error {
	return firstErr(
		validOpt("table", r.Table, reTable),
		validCIDR("from", r.From, true),
		validCIDR("to", r.To, true),
		validIface("iif", r.Iif, true),
		validIface("oif", r.Oif, true),
	)
}

func validateLink(l api.LinkSpec) error {
	return validIface("name", l.Name, false)
}

func validateSysctl(s api.SysctlSpec) error {
	if !reSysctl.MatchString(s.Key) {
		return fmt.Errorf("invalid sysctl key %q", s.Key)
	}
	if s.Value != "" && !reSysVal.MatchString(strings.TrimSpace(s.Value)) {
		return fmt.Errorf("invalid sysctl value %q (single token, no spaces)", s.Value)
	}
	return nil
}

func validateTC(t api.TCSpec) error {
	if err := validIface("device", t.Device, false); err != nil {
		return err
	}
	switch t.MatchKind {
	case "src_cidr", "dst_cidr":
		return validCIDRList("match_value", t.MatchValue)
	case "fwmark":
		return validMatch("match_value", t.MatchValue, false)
	}
	return nil
}

func validateIPList(l api.IPList) error {
	for _, e := range l.Entries {
		if err := validCIDR("entry", e, false); err != nil {
			return err
		}
	}
	return nil
}

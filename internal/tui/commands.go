package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

type tickMsg time.Time

type flashClearMsg struct{ id int }

type dataMsg struct {
	gen       uint64
	status    pkgapi.Status
	policies  []pkgapi.PolicyRule
	routes    []pkgapi.RouteSpec
	nat       []pkgapi.NATSpec
	forwards  []pkgapi.ForwardSpec
	tc        []pkgapi.TCSpec
	firewall  []pkgapi.FirewallRule
	ipAddrs   []pkgapi.IPAddrSpec
	ipRules   []pkgapi.IPRuleSpec
	links     []pkgapi.LinkSpec
	sysctls   []pkgapi.SysctlSpec
	ipLists   []pkgapi.IPList
	dataplane *pkgapi.Dataplane
	err       error
}

type actionDoneMsg struct {
	err     error
	flash   string
	refresh bool
	// optional: switch away from form/confirm
	toList bool
}

type applyDoneMsg struct {
	result *pkgapi.ApplyResult
	err    error
	flash  string
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func flashClearCmd(id int) tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return flashClearMsg{id: id} })
}

func fetchData(c *pkgapi.Client, gen uint64, withHost bool) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		msg := dataMsg{gen: gen}
		// Prefer overview; fall back to piece-wise if needed.
		ov, err := c.Overview(ctx, !withHost)
		if err != nil {
			// Soft path: status + lists
			st, serr := c.Status(ctx)
			if serr != nil {
				msg.err = err
				return msg
			}
			msg.status = *st
			if pols, e := c.ListPolicies(ctx); e == nil {
				msg.policies = pols
			}
			if rts, e := c.ListRoutes(ctx); e == nil {
				msg.routes = rts
			}
			if nats, e := c.ListNAT(ctx); e == nil {
				msg.nat = nats
			}
			if fwds, e := c.ListForwards(ctx); e == nil {
				msg.forwards = fwds
			}
			if tcs, e := c.ListTC(ctx); e == nil {
				msg.tc = tcs
			}
			if fwr, e := c.ListFirewall(ctx); e == nil {
				msg.firewall = fwr
			}
			if addrs, e := c.ListIPAddrs(ctx); e == nil {
				msg.ipAddrs = addrs
			}
			if rules, e := c.ListIPRules(ctx); e == nil {
				msg.ipRules = rules
			}
			if links, e := c.ListLinks(ctx); e == nil {
				msg.links = links
			}
			if sc, e := c.ListSysctls(ctx); e == nil {
				msg.sysctls = sc
			}
			if lists, e := c.ListIPLists(ctx); e == nil {
				msg.ipLists = lists
			}
			if withHost {
				if dp, e := c.Dataplane(ctx); e == nil {
					msg.dataplane = dp
				}
			}
			return msg
		}
		msg.status = ov.Status
		msg.policies = ov.Policies
		msg.routes = ov.Routes
		msg.nat = ov.NAT
		msg.forwards = ov.Forwards
		msg.tc = ov.TC
		msg.firewall = ov.Firewall
		msg.ipAddrs = ov.IPAddrs
		msg.ipRules = ov.IPRules
		msg.links = ov.Links
		msg.sysctls = ov.Sysctls
		msg.ipLists = ov.IPLists
		msg.dataplane = ov.Dataplane
		return msg
	}
}

func doAction(fn func(ctx context.Context) error, flash string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err := fn(ctx)
		return actionDoneMsg{err: err, flash: flash, refresh: err == nil, toList: err == nil}
	}
}

func doCreatePolicy(c *pkgapi.Client, req pkgapi.PolicyCreateRequest) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreatePolicy(ctx, req)
		return err
	}, "policy "+req.Name+" created")
}

func doUpdatePolicy(c *pkgapi.Client, id string, req pkgapi.PolicyUpdateRequest) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.UpdatePolicy(ctx, id, req)
		return err
	}, "policy updated")
}

func doDeletePolicy(c *pkgapi.Client, id, name string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeletePolicy(ctx, id)
	}, "deleted "+name)
}

func doTogglePolicy(c *pkgapi.Client, id string, enabled bool) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.UpdatePolicy(ctx, id, pkgapi.PolicyUpdateRequest{Enabled: &enabled})
		return err
	}, map[bool]string{true: "policy enabled", false: "policy disabled"}[enabled])
}

func doCreateRoute(c *pkgapi.Client, rt pkgapi.RouteSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateRoute(ctx, rt)
		return err
	}, "route created")
}

func doDeleteRoute(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteRoute(ctx, id)
	}, "route deleted")
}

func doCreateNAT(c *pkgapi.Client, n pkgapi.NATSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateNAT(ctx, n)
		return err
	}, "NAT rule created")
}

func doDeleteNAT(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteNAT(ctx, id)
	}, "NAT rule deleted")
}

func doCreateForward(c *pkgapi.Client, f pkgapi.ForwardSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateForward(ctx, f)
		return err
	}, "forward rule created")
}

func doDeleteForward(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteForward(ctx, id)
	}, "forward deleted")
}

func doCreateTC(c *pkgapi.Client, t pkgapi.TCSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateTC(ctx, t)
		return err
	}, "tc limit created")
}

func doDeleteTC(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteTC(ctx, id)
	}, "tc limit deleted")
}

func doCreateFirewall(c *pkgapi.Client, r pkgapi.FirewallRule) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateFirewall(ctx, r)
		return err
	}, "firewall rule created")
}

// doCreateFirewallMany creates several rules (e.g. multi-port easy access).
func doCreateFirewallMany(c *pkgapi.Client, rules []pkgapi.FirewallRule) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		for i := range rules {
			if _, err := c.CreateFirewall(ctx, rules[i]); err != nil {
				return err
			}
		}
		return nil
	}, fmt.Sprintf("%d access rule(s) created", len(rules)))
}

// doEasyReturnBundle sets up NAT + established + rp_filter for return path.
func doEasyReturnBundle(c *pkgapi.Client, nat pkgapi.NATSpec, fws []pkgapi.FirewallRule, sys []pkgapi.SysctlSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		if _, err := c.CreateNAT(ctx, nat); err != nil {
			return fmt.Errorf("nat: %w", err)
		}
		for i := range fws {
			if _, err := c.CreateFirewall(ctx, fws[i]); err != nil {
				return fmt.Errorf("firewall: %w", err)
			}
		}
		for _, sc := range sys {
			if _, err := c.UpsertSysctl(ctx, sc); err != nil {
				return fmt.Errorf("sysctl %s: %w", sc.Key, err)
			}
		}
		return nil
	}, "return path configured")
}

// doEasyFastpathBundle creates egress policy + optional ip_forward + optional linked masq.
func doEasyFastpathBundle(c *pkgapi.Client, pol pkgapi.PolicyCreateRequest, enableFwd bool, nat *pkgapi.NATSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		if enableFwd {
			if err := c.SetIPForward(ctx, true); err != nil {
				return fmt.Errorf("ip_forward: %w", err)
			}
		}
		if _, err := c.CreatePolicy(ctx, pol); err != nil {
			return err
		}
		if nat != nil {
			if _, err := c.CreateNAT(ctx, *nat); err != nil {
				return fmt.Errorf("nat: %w", err)
			}
		}
		return nil
	}, "fastpath configured")
}

func doUpsertSysctl(c *pkgapi.Client, sc pkgapi.SysctlSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.UpsertSysctl(ctx, sc)
		return err
	}, "sysctl "+sc.Key+"="+sc.Value)
}

func doCreateIPList(c *pkgapi.Client, l pkgapi.IPList) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateIPList(ctx, l)
		return err
	}, "list "+l.Name+" saved")
}

func doAppendIPList(c *pkgapi.Client, id string, entries []string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.AppendIPListEntries(ctx, id, entries)
		return err
	}, "IPs added to list")
}

func doDeleteIPList(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteIPList(ctx, id)
	}, "list deleted")
}

// doEasyGateway enables IP forward + established + optional client forward.
func doEasyGateway(c *pkgapi.Client, clientCIDR, inIf, outIf string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		if err := c.SetIPForward(ctx, true); err != nil {
			return err
		}
		// established
		for _, chain := range []string{"forward", "input"} {
			if _, err := c.CreateFirewall(ctx, pkgapi.FirewallRule{
				Name: "easy-gw-est-" + chain, Enabled: true, Priority: 10,
				Backend: "auto", Table: "filter", Chain: chain,
				Action: "accept", CtState: "established,related",
				Comment: "easy:gateway established",
			}); err != nil {
				return err
			}
		}
		if clientCIDR != "" || inIf != "" || outIf != "" {
			if _, err := c.CreateFirewall(ctx, pkgapi.FirewallRule{
				Name: "easy-gw-fwd", Enabled: true, Priority: 40,
				Backend: "auto", Table: "filter", Chain: "forward",
				Action: "accept", Source: clientCIDR, InIface: inIf, OutIface: outIf,
				Comment: "easy:gateway routing",
			}); err != nil {
				return err
			}
		}
		return nil
	}, "IP routing / gateway enabled")
}

func doDeleteFirewall(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteFirewall(ctx, id)
	}, "firewall rule deleted")
}

func doCreateIPAddr(c *pkgapi.Client, a pkgapi.IPAddrSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateIPAddr(ctx, a)
		return err
	}, "address added")
}

func doDeleteIPAddr(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteIPAddr(ctx, id)
	}, "address removed")
}

func doCreateIPRule(c *pkgapi.Client, r pkgapi.IPRuleSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateIPRule(ctx, r)
		return err
	}, "ip rule created")
}

func doDeleteIPRule(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteIPRule(ctx, id)
	}, "ip rule deleted")
}

func doCreateLink(c *pkgapi.Client, l pkgapi.LinkSpec) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateLink(ctx, l)
		return err
	}, "link config saved")
}

func doDeleteLink(c *pkgapi.Client, id string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteLink(ctx, id)
	}, "link config removed")
}

func doSetIPForward(c *pkgapi.Client, enabled bool) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.SetIPForward(ctx, enabled)
	}, map[bool]string{true: "ip_forward on", false: "ip_forward off"}[enabled])
}

func doApply(c *pkgapi.Client, dry bool) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := c.Apply(ctx, dry)
		flash := "apply complete"
		if dry {
			flash = "dry-run complete"
		}
		if res != nil && res.Message != "" {
			flash = res.Message
		}
		if res != nil {
			flash = fmt.Sprintf("%s · applied=%d skipped=%d", flash, res.Applied, res.Skipped)
		}
		return applyDoneMsg{result: res, err: err, flash: flash}
	}
}

func parseIntField(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

func parseUint32Field(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func subjectsSummary(ss []pkgapi.Subject) string {
	if len(ss) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ss))
	for _, s := range ss {
		parts = append(parts, s.Kind+":"+s.Value)
	}
	return strings.Join(parts, ",")
}

func destSummary(d pkgapi.Destination) string {
	if d.Kind == "" {
		return "any"
	}
	if d.Value == "" {
		return d.Kind
	}
	return d.Kind + ":" + d.Value
}

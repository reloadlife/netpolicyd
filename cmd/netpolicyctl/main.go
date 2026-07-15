// netpolicyctl — full-screen TUI (default) + CLI for netpolicyd.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/reloadlife/netpolicyd/internal/tui"
	pkgapi "github.com/reloadlife/netpolicyd/pkg/api"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		if err := runTUI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	switch os.Args[1] {
	case "tui", "ui":
		if err := runTUI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("netpolicyctl", version)
	case "status":
		cliStatus()
	case "policies":
		cliPolicies()
	case "routes":
		cliRoutes()
	case "nat":
		cliNAT()
	case "forwards":
		cliForwards()
	case "tc":
		cliTC()
	case "firewall", "fw":
		cliFirewall()
	case "ip":
		cliIP()
	case "lists", "list":
		cliLists()
	case "overview":
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) {
			return c.Overview(ctx, false)
		})
	case "dataplane":
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) {
			return c.Dataplane(ctx)
		})
	case "apply":
		dry := len(os.Args) > 2 && (os.Args[2] == "--dry-run" || os.Args[2] == "-n")
		cliJSON(func(ctx context.Context, c *pkgapi.Client) (any, error) {
			return c.Apply(ctx, dry)
		})
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		printHelp()
		os.Exit(2)
	}
}

func printHelp() {
	base := env("NETPOLICYCTL_URL", "http://127.0.0.1:51910")
	fmt.Fprintf(os.Stderr, `netpolicyctl — control netpolicyd (TUI + CLI)

Usage:
  netpolicyctl                 # full-screen TUI (default)
  netpolicyctl tui             # same
  netpolicyctl status
  netpolicyctl policies
  netpolicyctl routes
  netpolicyctl nat
  netpolicyctl forwards
  netpolicyctl tc
  netpolicyctl firewall
  netpolicyctl ip [addrs|rules|links]
  netpolicyctl lists
  netpolicyctl overview
  netpolicyctl dataplane
  netpolicyctl apply [--dry-run]
  netpolicyctl version

Env:
  NETPOLICYCTL_URL      default %s
  NETPOLICYCTL_TOKEN    default dev-token
  NETPOLICYCTL_REFRESH  TUI refresh seconds (default 2)
  NETPOLICYCTL_MODE     easy | advanced  (default easy; toggle in TUI with m)
`, base)
}

func runTUI() error {
	client, endpoint, err := loadClient()
	if err != nil {
		return err
	}
	refresh := 2 * time.Second
	if s := os.Getenv("NETPOLICYCTL_REFRESH"); s != "" {
		if n, err := time.ParseDuration(s + "s"); err == nil {
			refresh = n
		} else if d, err := time.ParseDuration(s); err == nil {
			refresh = d
		}
	}
	easy := true
	switch strings.ToLower(env("NETPOLICYCTL_MODE", "easy")) {
	case "advanced", "adv", "full":
		easy = false
	}
	// flag override: netpolicyctl tui --advanced / --easy
	for _, a := range os.Args[1:] {
		switch a {
		case "--advanced", "-A", "--adv":
			easy = false
		case "--easy", "-E":
			easy = true
		}
	}
	return tui.Run(tui.Config{
		Client:          client,
		Endpoint:        endpoint,
		RefreshInterval: refresh,
		EasyMode:        &easy,
	})
}

func loadClient() (*pkgapi.Client, string, error) {
	base := env("NETPOLICYCTL_URL", "http://127.0.0.1:51910")
	token := env("NETPOLICYCTL_TOKEN", "dev-token")
	c, err := pkgapi.NewClient(base, pkgapi.WithToken(token))
	if err != nil {
		return nil, "", err
	}
	return c, base, nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func mustClient() *pkgapi.Client {
	c, _, err := loadClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return c
}

func cliStatus() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := mustClient().Status(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printJSON(st)
}

func cliPolicies() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListPolicies(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PRI\tENABLED\tNAME\tACTION\tSUBJECT\tEGRESS\tID")
	for _, p := range list {
		subj := ""
		if len(p.Subjects) > 0 {
			subj = p.Subjects[0].Kind + ":" + p.Subjects[0].Value
		}
		fmt.Fprintf(w, "%d\t%v\t%s\t%s\t%s\t%s\t%s\n",
			p.Priority, p.Enabled, p.Name, p.Action, subj, p.EgressName, p.ID)
	}
	_ = w.Flush()
}

func cliRoutes() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListRoutes(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTABLE\tDST\tGW\tDEV\tMETRIC\tENABLED")
	for _, r := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%v\n",
			r.ID, r.Table, r.Dst, r.Gateway, r.Device, r.Metric, r.Enabled)
	}
	_ = w.Flush()
}

func cliNAT() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListNAT(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tKIND\tSOURCE\tOUT\tTO\tENABLED")
	for _, n := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%v\n",
			n.ID, n.Kind, n.SourceCIDR, n.OutIface, n.ToSource, n.Enabled)
	}
	_ = w.Flush()
}

func cliForwards() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListForwards(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tACTION\tIN\tOUT\tSOURCE\tDEST\tENABLED")
	for _, f := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n",
			f.ID, f.Action, f.InIface, f.OutIface, f.Source, f.Dest, f.Enabled)
	}
	_ = w.Flush()
}

func cliTC() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListTC(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tDEVICE\tTX_BPS\tRX_BPS\tMATCH\tVALUE\tNAME\tENABLED")
	for _, t := range list {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\t%s\t%v\n",
			t.ID, t.Device, t.RateTxBps, t.RateRxBps, t.MatchKind, t.MatchValue, t.Name, t.Enabled)
	}
	_ = w.Flush()
}

func cliFirewall() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListFirewall(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PRI\tBACKEND\tTABLE\tCHAIN\tACTION\tPROTO\tSOURCE\tDEST\tDPORT\tNAME")
	for _, f := range list {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Priority, f.Backend, f.Table, f.Chain, f.Action, f.Protocol,
			f.Source, f.Dest, f.Dport, f.Name)
	}
	_ = w.Flush()
}

func cliIP() {
	sub := "all"
	if len(os.Args) > 2 {
		sub = os.Args[2]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := mustClient()
	switch sub {
	case "addrs", "addr", "a":
		list, err := c.ListIPAddrs(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if wantsJSON() {
			printJSON(list)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tDEVICE\tCIDR\tSCOPE\tPEER")
		for _, a := range list {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.Device, a.CIDR, a.Scope, a.Peer)
		}
		_ = w.Flush()
	case "rules", "rule", "r":
		list, err := c.ListIPRules(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if wantsJSON() {
			printJSON(list)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tPRIO\tFROM\tTO\tIIF\tTABLE\tACTION")
		for _, r := range list {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
				r.ID, r.Priority, r.From, r.To, r.Iif, r.Table, r.Action)
		}
		_ = w.Flush()
	case "links", "link", "l":
		list, err := c.ListLinks(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if wantsJSON() {
			printJSON(list)
			return
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tUP\tMTU\tCOMMENT")
		for _, l := range list {
			up := "-"
			if l.Up != nil {
				up = fmt.Sprintf("%v", *l.Up)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", l.ID, l.Name, up, l.MTU, l.Comment)
		}
		_ = w.Flush()
	default:
		// dump all three as JSON objects
		addrs, _ := c.ListIPAddrs(ctx)
		rules, _ := c.ListIPRules(ctx)
		links, _ := c.ListLinks(ctx)
		printJSON(map[string]any{"addrs": addrs, "rules": rules, "links": links})
	}
}

func cliLists() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := mustClient().ListIPLists(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if wantsJSON() {
		printJSON(list)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tCOUNT\tENTRIES")
	for _, l := range list {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", l.ID, l.Name, len(l.Entries), strings.Join(l.Entries, ","))
	}
	_ = w.Flush()
}

func cliJSON(fn func(context.Context, *pkgapi.Client) (any, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := fn(ctx, mustClient())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	printJSON(out)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func wantsJSON() bool {
	for _, a := range os.Args[2:] {
		if a == "--json" || a == "-j" {
			return true
		}
	}
	return false
}

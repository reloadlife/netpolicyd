// Command netpolicyd is the host network policy daemon: routes, firewall, NAT, TC.
// Controlled over HTTP (Bearer auth). Companion CLI/TUI: netpolicyctl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/reloadlife/netpolicyd/internal/api"
	"github.com/reloadlife/netpolicyd/internal/apply"
	"github.com/reloadlife/netpolicyd/internal/store"
)

// version set via -ldflags
var version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}

	listen := flag.String("listen", "127.0.0.1:51910", "HTTP listen address")
	token := flag.String("token", "", "Bearer token for /v1/* (or env NETPOLICYD_TOKEN)")
	mock := flag.Bool("mock", false, "Force mock apply (do not exec ip/nft)")
	flag.Parse()

	tok := *token
	if tok == "" {
		tok = os.Getenv("NETPOLICYD_TOKEN")
	}
	if !isLoopback(*listen) && (tok == "" || tok == "dev-token") {
		log.Fatal("refusing to listen on a non-loopback address without a strong token: set NETPOLICYD_TOKEN")
	}
	if tok == "" {
		log.Printf("WARNING: no token set — /v1 auth is DISABLED (loopback only)")
	}

	// Auto-mock only when no ip binary (PATH may omit /usr/sbin; Detect checks sbin)
	ipOK, nftOK, tcOK := apply.Detect()
	forceMock := *mock || !ipOK
	if !nftOK {
		log.Printf("nft not found in PATH/sbin — NAT rules planned; ip still applies when available")
	}
	if ipOK {
		log.Printf("tools: ip=%v nft=%v tc=%v mock_flag=%v", ipOK, nftOK, tcOK, *mock)
	}

	st := store.New()
	runner := apply.NewRunner(forceMock)
	srv := &api.Server{
		Store:   st,
		Runner:  runner,
		Token:   tok,
		Version: version,
	}

	log.Printf("netpolicyd %s listening on %s backend=%s go=%s",
		version, *listen, runner.Backend, runtime.Version())
	srv2 := &http.Server{
		Addr:              *listen,
		Handler:           logRequest(srv.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv2.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// isLoopback reports whether addr binds ONLY to a loopback address.
//
// An empty host (":51910") binds every interface, so it is NOT loopback —
// treating it as loopback would let the fail-closed token check be bypassed
// on the most common wide-open listen form. Unparseable hosts fail closed too.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false // ":port" = all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Printf("%s %s", r.Method, r.URL.Path)
	})
}

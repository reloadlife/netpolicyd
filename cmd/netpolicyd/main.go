// Command netpolicyd is the host network policy daemon: routes, firewall, NAT, TC.
// Controlled over HTTP (Bearer auth). Companion CLI/TUI: netpolicyctl.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"

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
	token := flag.String("token", "dev-token", "Bearer token for /v1/*")
	mock := flag.Bool("mock", false, "Force mock apply (do not exec ip/nft)")
	flag.Parse()

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
		Token:   *token,
		Version: version,
	}

	log.Printf("netpolicyd %s listening on %s backend=%s go=%s",
		version, *listen, runner.Backend, runtime.Version())
	if err := http.ListenAndServe(*listen, logRequest(srv.Handler())); err != nil {
		log.Fatal(err)
	}
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Printf("%s %s", r.Method, r.URL.Path)
	})
}

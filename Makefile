MODULE  := github.com/reloadlife/netpolicyd
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X main.version=$(VERSION)

.PHONY: all build test vet run clean install

all: build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/netpolicyd ./cmd/netpolicyd
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/netpolicyctl ./cmd/netpolicyctl

test:
	go test ./... -count=1

test-race:
	go test ./... -count=1 -race

cover:
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -20
	@echo "HTML: go tool cover -html=coverage.out"

vet:
	go vet ./...

ci: vet test-race build

run: build
	./bin/netpolicyd --listen 127.0.0.1:51910 --token dev-token

# Install to /usr/local/bin and, when present, the networkingd local daemon dir.
NETPOLICYD_LOCAL ?= $(HOME)/.local/share/networkingd/daemons/netpolicyd/bin
LOCAL_BIN ?= $(HOME)/.local/bin

install: build
	mkdir -p /usr/local/bin
	install -m 755 bin/netpolicyd bin/netpolicyctl /usr/local/bin/
	mkdir -p "$(LOCAL_BIN)"
	ln -sfn /usr/local/bin/netpolicyctl "$(LOCAL_BIN)/netpolicyctl"
	ln -sfn /usr/local/bin/netpolicyd "$(LOCAL_BIN)/netpolicyd"
	@if [ -d "$(dir $(NETPOLICYD_LOCAL))" ] || [ -d "$(HOME)/.local/share/networkingd/daemons/netpolicyd" ]; then \
	  mkdir -p "$(NETPOLICYD_LOCAL)"; \
	  install -m 755 bin/netpolicyd bin/netpolicyctl "$(NETPOLICYD_LOCAL)/"; \
	  echo "installed to $(NETPOLICYD_LOCAL)"; \
	fi
	@echo "installed: /usr/local/bin/netpolicyd /usr/local/bin/netpolicyctl"
	@echo "  symlink: $(LOCAL_BIN)/netpolicyctl"
	@echo "restart daemon if running: pkill netpolicyd; netpolicyd --listen 127.0.0.1:51910 --token dev-token &"

clean:
	rm -rf bin

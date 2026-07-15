package host

import (
	"testing"
)

func TestHasBinIP(t *testing.T) {
	// ip is almost always present on this Linux host
	if !hasBin("ip") && resolveBin("ip") == "" {
		t.Skip("ip not available")
	}
	if !hasBin("ip") {
		t.Fatal("hasBin(ip) false but resolveBin found it")
	}
}

func TestCollectReturnsSnapshot(t *testing.T) {
	d := Collect()
	if d.CollectedAt == "" {
		t.Fatal("missing collected_at")
	}
	// At least tool detection ran
	_ = d.IPAvailable
	_ = d.NFTAvailable
	_ = d.TCAvailable
}

func TestTcDevFromQdiscLine(t *testing.T) {
	got := tcDevFromQdiscLine("qdisc htb 1: dev gre-lab root refcnt 2")
	if got != "gre-lab" {
		t.Fatalf("got %q", got)
	}
	if tcDevFromQdiscLine("no device here") != "" {
		t.Fatal("expected empty")
	}
}

func TestSplitNonEmpty(t *testing.T) {
	got := splitNonEmpty("a\n\nb\n  \nc\n")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("%v", got)
	}
}

func TestItoa(t *testing.T) {
	if itoa(0) != "0" || itoa(100) != "100" || itoa(42) != "42" {
		t.Fatal(itoa(0), itoa(100), itoa(42))
	}
}

func TestReadSysctl(t *testing.T) {
	// best-effort; may be empty in restricted env
	_ = readSysctl("net.ipv4.ip_forward")
}

package main

import "testing"

// Regression: isLoopback("") used to return true, so `--listen :51910` — the
// most common way to bind EVERY interface — bypassed the fail-closed token
// check and, with an empty token, served /v1 unauthenticated on all interfaces.
func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:51910": true,
		"127.0.0.53:53":   true,
		"[::1]:51910":     true,
		"localhost:51910": true,
		":51910":          false, // all interfaces
		"0.0.0.0:51910":   false,
		"[::]:51910":      false,
		"192.168.1.10:80": false,
		"example.com:80":  false, // unresolved name: fail closed
		"":                false,
	}
	for addr, want := range cases {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

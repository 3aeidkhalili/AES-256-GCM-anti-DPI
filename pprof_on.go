//go:build pprof

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

// startPprof exposes the standard Go profiling endpoints. Bind it to localhost and reach it
// over an SSH tunnel; there is no authentication in front of it.
func startPprof(addr string) {
	if addr == "" {
		return
	}
	go func() {
		log.Printf("pprof listening on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("pprof server stopped: %v", err)
		}
	}()
}

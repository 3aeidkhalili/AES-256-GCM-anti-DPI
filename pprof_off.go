//go:build !pprof

package main

import "log"

// startPprof is a no-op in the shipped binary. Wiring net/http/pprof in unconditionally
// would drag the whole HTTP stack into a program that otherwise speaks nothing but UDP,
// nearly tripling the binary. Build with `-tags pprof` (or `aestun.sh build amd64 pprof`)
// when a profile is actually needed.
func startPprof(addr string) {
	if addr != "" {
		log.Printf("pprof_addr is set but this binary was built without profiling support; rebuild with -tags pprof")
	}
}

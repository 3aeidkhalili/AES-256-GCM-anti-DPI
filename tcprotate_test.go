//go:build linux

package main

import (
	"net"
	"testing"
)

// tcp_rotate config: off unless enabled, sane default interval.
func TestTCPRotateConfigDefaults(t *testing.T) {
	var c TCPRotateConfig
	c.applyDefaults()
	if c.on() {
		t.Fatal("tcp_rotate must default to off")
	}
	if c.IntervalSec != 15 {
		t.Fatalf("default interval should be 15s, got %d", c.IntervalSec)
	}
	on := true
	c2 := TCPRotateConfig{Enabled: &on, IntervalSec: 20}
	c2.applyDefaults()
	if !c2.on() || c2.IntervalSec != 20 {
		t.Fatalf("explicit values not preserved: on=%v interval=%d", c2.on(), c2.IntervalSec)
	}
}

// The rotation-tolerant reader must treat a read error on a connection that has already been
// replaced (rotated out) as non-fatal, while a read error on the still-current connection is
// a genuine failure. This is what lets make-before-break rotation not tear the tunnel down.
func TestRotatedOut(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &tcpCarrier{}
	c.set(a)
	if c.rotatedOut(a) {
		t.Fatal("the active connection must not report as rotated out")
	}
	// Rotate: install a new connection. The old one is now superseded.
	d, e := net.Pipe()
	defer d.Close()
	defer e.Close()
	c.set(d)
	if !c.rotatedOut(a) {
		t.Fatal("a superseded connection must report as rotated out (error on it is expected)")
	}
	if c.rotatedOut(d) {
		t.Fatal("the new active connection must not report as rotated out")
	}
	// When there is no active connection, a read error is genuine (not a rotation).
	c.set(nil)
	if c.rotatedOut(a) {
		t.Fatal("with no active connection, nothing is 'rotated out' — the error is real")
	}
}

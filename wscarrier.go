//go:build linux

// The WebSocket carrier's runtime: the dialing end's connection manager and the listening end's
// accept loop. The protocol itself — framing, the upgrade, admission — is in ws.go; the stream
// machinery underneath (the active connection, its replacement, the pumps, the receive loop) is
// the TCP carrier's, which this carrier is a framing of.
package main

import (
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// wsUserTimeout bounds how long sent data may sit unacknowledged before the kernel gives the
// connection up. Without it, a path that silently swallows a connection in mid-flow — the shape of
// the cut measured on the reference link — leaves the socket "open" through the default ~15
// minutes of retransmission, and the carrier dead with it.
const wsUserTimeout = 30 * time.Second

// wsTuneConn applies the socket options every carrier connection gets, on either end.
func wsTuneConn(c net.Conn) {
	setTCPOpts(c)
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if rc, err := tc.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(wsUserTimeout/time.Millisecond))
		})
	}
}

func runWS(cfg *Config, t *Tunnel, tuns []*os.File) {
	c := &tcpCarrier{buf: make([]byte, maxPktSize), ws: true, wsClient: cfg.dials(), wrng: newCSPRNG()}
	if cfg.RateMbps > 0 {
		c.pacer = newPacer(cfg.RateMbps)
		log.Printf("carrier shaped to %.0f Mbit/s", cfg.RateMbps)
	}
	if cfg.dials() {
		d, err := newWSDialer(&cfg.WS, t.psk, wsTuneConn)
		if err != nil {
			log.Fatalf("ws: %v", err)
		}
		log.Printf("ws carrier: dialling %s", d.describe())
		go wsDialLoop(cfg, t, c, d)
	} else {
		s, err := newWSServer(&cfg.WS, t, wsTuneConn)
		if err != nil {
			log.Fatalf("ws: %v", err)
		}
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			log.Fatalf("ws listen failed: %v", err)
		}
		log.Printf("ws carrier: listening on %s, path %s, TLS and plain HTTP on the same port (certificate: %s)",
			cfg.Listen, s.path, s.certDesc)
		if cfg.Reverse {
			log.Printf("reverse: this end only answers connections the peer opens, and sends nothing until one authenticates")
		}
		go wsAcceptLoop(ln, s, c)
	}
	runStream(cfg, t, c, tuns)
}

// wsDialLoop keeps the dialing end connected. It dials, installs the connection, announces itself
// at once — the listener admits a connection on its first authenticated message, and should not
// have to wait for the next keepalive to get one — and then holds the connection until it dies,
// goes stale, or is due for rotation.
//
// Rotation is make-before-break, as with tcp_rotate: the replacement is dialled while the old
// connection still carries traffic, and only installing it retires the old one. Staleness is the
// case TCP itself is slowest to notice: a CDN can keep the dialer's leg of a connection open long
// after the leg to the origin has gone, so the socket is healthy and nothing arrives. The peer's
// keepalives are the heartbeat; idle_sec without one and the connection is replaced.
func wsDialLoop(cfg *Config, t *Tunnel, c *tcpCarrier, d *wsDialer) {
	rotate := time.Duration(cfg.WS.RotateSec) * time.Second
	idle := time.Duration(cfg.WS.IdleSec) * time.Second
	if rotate > 0 {
		log.Printf("ws: replacing the connection every ~%ds, make-before-break", cfg.WS.RotateSec)
	}
	s := newSealer()
	backoff := time.Second
	var fails int
	for {
		w, err := d.dial(15*time.Second, nil)
		if err != nil {
			fails++
			// Every failure while nothing is up, but only every tenth of a streak once the old
			// connection (still carrying traffic during a rotation) makes it less urgent.
			if c.current() == nil || fails%10 == 1 {
				log.Printf("ws dial failed: %v", err)
			}
			time.Sleep(jitter(backoff))
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if fails > 0 || c.current() == nil || rotate == 0 {
			log.Printf("ws connected: %s", d.describe())
		}
		fails, backoff = 0, time.Second
		done := c.set(w)
		if err := c.Send(t.sealInto(s, nil)); err != nil {
			log.Printf("ws: announcing this end failed: %v", err)
		}
		if !wsHold(t, c, w, done, rotate, idle) {
			time.Sleep(500 * time.Millisecond) // the connection died; a short breath before the redial
		}
	}
}

// wsHold waits on one installed connection. It returns true when the connection is due for
// rotation and is still up (the caller dials its replacement first), and false once it is gone.
func wsHold(t *Tunnel, c *tcpCarrier, w *wsConn, done chan struct{}, rotate, idle time.Duration) bool {
	since := time.Now()
	var due <-chan time.Time
	if rotate > 0 {
		tm := time.NewTimer(jitter(rotate))
		defer tm.Stop()
		due = tm.C
	}
	watch := time.NewTicker(5 * time.Second)
	defer watch.Stop()
	for {
		select {
		case <-done:
			if rotate == 0 {
				log.Printf("ws disconnected")
			}
			return false
		case <-due:
			return true
		case <-watch.C:
			if idle <= 0 {
				continue
			}
			last := time.Unix(atomic.LoadInt64(&t.lastRxUnix), 0)
			if last.Before(since) {
				last = since
			}
			if time.Since(last) > idle {
				log.Printf("ws: nothing authenticated from the peer for %s on this connection — replacing it", idle)
				if c.current() == w {
					c.set(nil)
				}
				return false
			}
		}
	}
}

// wsAcceptLoop admits connections on the listening end. Each handshake runs on its own goroutine,
// so a slow or silent client holds a slot, never the loop; a connection that authenticates
// replaces whatever the carrier had, exactly as a fresh TCP accept does.
func wsAcceptLoop(ln net.Listener, s *wsServer, c *tcpCarrier) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Printf("ws accept failed: %v", err)
			time.Sleep(time.Second)
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			raw.Close() // every slot is held by a handshake in progress; the peer will retry
			continue
		}
		go func() {
			defer func() { <-s.slots }()
			w, err := s.admit(raw)
			if err != nil {
				if err == errWSClosed {
					log.Printf("ws: %s upgraded on the tunnel path and closed without sending data (a ws-check?)", raw.RemoteAddr())
				}
				raw.Close()
				return
			}
			c.set(w)
			log.Printf("ws accepted: %s", w.via)
		}()
	}
}

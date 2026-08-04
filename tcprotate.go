//go:build linux

// TCP carrier connection rotation — the answer to Problem 3 from the live field test.
//
// The field test found that a TCP+TLS carrier, however perfectly it parses as HTTPS on the
// wire, gets volumetrically throttled to a blackhole within ~30 seconds on a real censored
// link: a single long-lived, high-rate TLS connection is anomalous on rate and lifetime alone,
// and no amount of disguise changes its rate. The DPI observer caught it (path.throttle ->
// path.blackhole) and UDP on the same link was untouched.
//
// The disguise cannot fix a rate-based decision, so this attacks the *lifetime* instead. The
// dialer rotates the carrier connection on a timer: it opens a fresh TCP connection (a new
// 5-tuple — a new source port every dial) and switches the carrier onto it before retiring the
// old one, "make before break". No single flow then lives long enough, or carries enough
// bytes, to cross whatever volume/duration threshold the throttle is watching. It is port
// hopping's idea applied to a stream: keep moving so the per-flow accounting never accumulates.
//
// The switch is not free — a few in-flight bytes are lost each rotation and the inner TCP
// retransmits them, a small blip every interval. That is a trade the throttled case makes
// gladly: a blip every 15 s beats a total blackhole. The interval is jittered so the rotation
// is not itself a clean periodic signature. Off by default; only meaningful with transport tcp.
package main

import (
	"log"
	"net"
	"time"
)

// tcpDialLoop is role a's carrier-connection manager. Without rotation it dials once and waits
// for the connection to be retired (the original behaviour). With tcp_rotate on it re-dials on
// a jittered timer, make-before-break, so the flow keeps moving to a fresh 5-tuple.
func tcpDialLoop(cfg *Config, t *Tunnel, c *tcpCarrier) {
	rotate := cfg.TCPRotate.on()
	interval := time.Duration(cfg.TCPRotate.IntervalSec) * time.Second
	if rotate {
		log.Printf("tcp carrier rotation on: a fresh connection every ~%ds (dodges volumetric throttling)", cfg.TCPRotate.IntervalSec)
	}
	for {
		// Dial the next connection. During this dial the *previous* connection (if any) is
		// still the active carrier, so traffic keeps flowing until the switch below — that is
		// the "make" of make-before-break.
		conn, err := net.DialTimeout("tcp", cfg.Peer, 15*time.Second)
		if err != nil {
			log.Printf("tcp dial failed: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		setTCPOpts(conn)
		// Open with a real ClientHello so the stream begins like a TLS connection, before any
		// application-data record goes out.
		if t.tlsShape {
			if _, err := conn.Write(buildTLSClientHelloRecord(cfg.SNI)); err != nil {
				log.Printf("tcp: TLS ClientHello write failed: %v", err)
				conn.Close()
				time.Sleep(time.Second)
				continue
			}
		}
		// Switch the carrier onto the new connection; this closes the previous one ("break").
		// The reader tolerates the resulting error on the old socket (tcpCarrier.rotatedOut).
		done := c.set(conn)
		if !rotate {
			log.Printf("tcp connected: %s", conn.RemoteAddr())
			<-done // no rotation: hold this connection until it is retired by a read error
			log.Printf("tcp disconnected")
			time.Sleep(1 * time.Second)
			continue
		}
		// Rotation: hold the connection for the (jittered) interval, then loop and dial a fresh
		// one — unless it dies on its own first, in which case reconnect immediately.
		select {
		case <-done:
			time.Sleep(500 * time.Millisecond)
		case <-time.After(jitter(interval)):
		}
	}
}

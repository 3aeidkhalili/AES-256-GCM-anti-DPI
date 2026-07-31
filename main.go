//go:build linux

// aestun — entry point and Linux-specific part (TUN creation, interface config, main loop).
// The protocol and crypto core lives in tunnel.go (OS-independent and testable), and the
// QUIC-shaped wire obfuscation in obfs.go.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// TUN (Linux) — no external dependency
// ---------------------------------------------------------------------------

type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

const (
	iffTun     = 0x0001
	iffNoPI    = 0x1000
	tunSetIff  = 0x400454ca
	devNetTun  = "/dev/net/tun"
	maxPktSize = 65535
)

// Read-loop resilience: a transient read error must not tear the tunnel down.
// We log and continue on errors, backing off briefly, and only exit if they
// persist (a permanent condition such as a closed device/socket), letting
// systemd restart us cleanly.
const (
	maxReadErrors  = 32
	readErrBackoff = 50 * time.Millisecond
)

func openTUN(name string) (*os.File, string, error) {
	f, err := os.OpenFile(devNetTun, os.O_RDWR, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w (are you running as root?)", devNetTun, err)
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, "", fmt.Errorf("TUNSETIFF: %v", errno)
	}
	got := string(bytes.TrimRight(req.Name[:], "\x00"))
	return f, got, nil
}

// ---------------------------------------------------------------------------
// Interface configuration via the ip command
// ---------------------------------------------------------------------------

func runCmd(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func configureIface(cfg *Config, ifname string) {
	if err := runCmd("ip", "link", "set", "dev", ifname, "mtu", strconv.Itoa(cfg.MTU)); err != nil {
		log.Printf("warning: setting MTU failed: %v", err)
	}
	if cfg.TxQueueLen > 0 {
		if err := runCmd("ip", "link", "set", "dev", ifname, "txqueuelen", strconv.Itoa(cfg.TxQueueLen)); err != nil {
			log.Printf("warning: setting txqueuelen failed: %v", err)
		}
	}
	if cfg.LocalIP != "" {
		if err := runCmd("ip", "addr", "add", cfg.LocalIP, "dev", ifname); err != nil {
			log.Printf("warning: adding address failed (may already exist): %v", err)
		}
	}
	if err := runCmd("ip", "link", "set", "dev", ifname, "up"); err != nil {
		log.Fatalf("bringing interface up failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Carrier — the transport under the tunnel. UDP and TCP differ only in how a
// sealed datagram gets to the peer, so both TUN pump loops are written once.
// ---------------------------------------------------------------------------

type carrier interface {
	// Send delivers one sealed datagram to the peer.
	Send(pkt []byte) error
	// Recv returns the next sealed datagram from the peer, blocking until one
	// arrives. Peer-address learning (UDP roaming) happens inside.
	Recv() ([]byte, error)
	Close() error
}

// --- UDP -------------------------------------------------------------------

type udpCarrier struct {
	conn *net.UDPConn
	t    *Tunnel
	buf  []byte
	// Source of the datagram most recently returned by Recv. Read by the caller only
	// after that datagram authenticates, so a forged packet can never move the peer.
	lastSrc *net.UDPAddr
}

func (u *udpCarrier) Send(pkt []byte) error {
	peer := u.t.getPeer()
	if peer == nil {
		return nil // peer address not known yet; nothing to do but drop
	}
	_, err := u.conn.WriteToUDP(pkt, peer)
	return err
}

func (u *udpCarrier) Recv() ([]byte, error) {
	n, src, err := u.conn.ReadFromUDP(u.buf)
	if err != nil {
		return nil, err
	}
	// Roaming is applied by the caller only after the packet authenticates, so a
	// forged packet cannot redirect the tunnel. Stash the source for that step.
	u.lastSrc = src
	return u.buf[:n], nil
}

func (u *udpCarrier) Close() error { return u.conn.Close() }

// --- TCP -------------------------------------------------------------------

// TCP is a stream, so datagram boundaries have to be restored explicitly:
// each sealed datagram goes out as a 2-byte big-endian length followed by the bytes.
type tcpCarrier struct {
	mu   sync.Mutex
	conn net.Conn
	// Closed when the connection it belongs to is retired, so the dialer can wait for
	// its own connection to end without racing against a replacement.
	done chan struct{}

	hdr [2]byte
	buf []byte
}

func setTCPOpts(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	// Nagle would coalesce small tunnel datagrams and add latency to every inner
	// connection's ACKs; keepalive lets a silently dropped path surface as an error
	// instead of a stall that never ends.
	tc.SetNoDelay(true)
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(30 * time.Second)
}

// set installs conn as the active connection (nil to clear) and returns the channel that
// closes when *this* connection is retired.
func (c *tcpCarrier) set(conn net.Conn) chan struct{} {
	c.mu.Lock()
	old, oldDone := c.conn, c.done
	c.conn = conn
	if conn != nil {
		c.done = make(chan struct{})
	} else {
		c.done = nil
	}
	newDone := c.done
	c.mu.Unlock()

	if oldDone != nil {
		close(oldDone)
	}
	if old != nil && old != conn {
		old.Close()
	}
	return newDone
}

func (c *tcpCarrier) current() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn
}

func (c *tcpCarrier) Send(pkt []byte) error {
	conn := c.current()
	if conn == nil {
		return nil // not connected yet; the inner protocols will retransmit
	}
	if len(pkt) > 65535 {
		return fmt.Errorf("datagram too large for framing: %d", len(pkt))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pkt)))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return nil // replaced under us; drop rather than write to a dead socket
	}
	if _, err := c.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(pkt)
	return err
}

func (c *tcpCarrier) Recv() ([]byte, error) {
	for {
		conn := c.current()
		if conn == nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if _, err := io.ReadFull(conn, c.hdr[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(c.hdr[:]))
		if n == 0 {
			continue
		}
		if cap(c.buf) < n {
			c.buf = make([]byte, n)
		}
		if _, err := io.ReadFull(conn, c.buf[:n]); err != nil {
			return nil, err
		}
		return c.buf[:n], nil
	}
}

func (c *tcpCarrier) Close() error {
	if conn := c.current(); conn != nil {
		return conn.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Keepalive
// ---------------------------------------------------------------------------

// jitter returns d scaled by a random factor in [0.6, 1.4]. A keepalive that fires on
// an exact period is a clean clock signature in a flow that is otherwise shapeless —
// the interval itself identifies the tunnel regardless of what the packets contain.
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(800))
	if err != nil {
		return d
	}
	return time.Duration(float64(d) * (0.6 + float64(n.Int64())/1000.0))
}

func keepaliveLoop(c carrier, t *Tunnel, seconds int) {
	base := time.Duration(seconds) * time.Second
	for {
		time.Sleep(jitter(base))
		if err := c.Send(t.seal(nil)); err != nil {
			log.Printf("keepalive send failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[aestun] ")

	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			log.Fatalf("rand: %v", err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k))
		return
	}

	cfgPath := flag.String("config", "/etc/aestun/config.json", "path to the JSON config file")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("reading config: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	cfg.applyDefaults()

	if cfg.Role != "a" && cfg.Role != "b" {
		log.Fatalf("role must be \"a\" or \"b\" (different on the two servers)")
	}
	if cfg.Transport != "udp" && cfg.Transport != "tcp" {
		log.Fatalf("transport must be \"udp\" or \"tcp\"")
	}
	if cfg.Obfs != "none" && cfg.Obfs != "quic" {
		log.Fatalf("obfs must be \"none\" or \"quic\"")
	}
	psk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.Key))
	if err != nil || len(psk) != 32 {
		log.Fatalf("key must be base64 of exactly 32 bytes (get one from `aestun keygen`)")
	}

	// TUN
	tun, ifname, err := openTUN(cfg.TunName)
	if err != nil {
		log.Fatalf("%v", err)
	}
	defer tun.Close()
	log.Printf("interface %s created", ifname)

	if *cfg.ManageIP {
		configureIface(&cfg, ifname)
	}

	t := newTunnel(&cfg, psk)
	t.ifname = ifname
	go t.writeStats(cfg.StatsPath)

	rekeyDesc := "static"
	if cfg.RekeyInterval > 0 {
		rekeyDesc = fmt.Sprintf("every %ds", cfg.RekeyInterval)
	}
	log.Printf("role=%s transport=%s obfs=%s listen=%s peer=%s mtu=%d pad_max=%d keepalive=%d rekey=%s",
		cfg.Role, cfg.Transport, cfg.Obfs, cfg.Listen, cfg.Peer, cfg.MTU, *cfg.PadMax, *cfg.Keepalive, rekeyDesc)

	if cfg.Transport == "tcp" {
		runTCP(&cfg, t, tun)
	} else {
		runUDP(&cfg, t, tun)
	}
}

// ---------------------------------------------------------------------------
// runUDP / runTCP
// ---------------------------------------------------------------------------

func runUDP(cfg *Config, t *Tunnel, tun *os.File) {
	laddr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		log.Fatalf("invalid listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("UDP listen failed: %v", err)
	}
	defer conn.Close()

	// Enlarge the socket buffers so traffic bursts are absorbed instead of dropped
	// (kernel UDP RcvbufErrors). The kernel caps these at net.core.rmem_max / wmem_max.
	if err := conn.SetReadBuffer(cfg.RcvBuf); err != nil {
		log.Printf("warning: SetReadBuffer(%d) failed: %v", cfg.RcvBuf, err)
	}
	if err := conn.SetWriteBuffer(cfg.SndBuf); err != nil {
		log.Printf("warning: SetWriteBuffer(%d) failed: %v", cfg.SndBuf, err)
	}

	if cfg.Peer != "" {
		paddr, err := net.ResolveUDPAddr("udp", cfg.Peer)
		if err != nil {
			log.Fatalf("invalid peer: %v", err)
		}
		t.setPeer(paddr)
	}

	c := &udpCarrier{conn: conn, t: t, buf: make([]byte, maxPktSize)}
	log.Printf("tunnel up - traffic ready to flow.")

	// Role a opens the flow, so it plays the client half of the synthetic handshake; role b
	// answers whatever Initial arrives (see the receive loop below).
	if t.obfs != nil && cfg.Role == "a" {
		if _, err := sendClientInitial(c, cfg.SNI); err != nil {
			log.Printf("warning: synthetic handshake failed: %v", err)
		} else {
			log.Printf("sent synthetic QUIC Initial (sni=%s)", cfg.SNI)
		}
	}

	if *cfg.Keepalive > 0 {
		go keepaliveLoop(c, t, *cfg.Keepalive)
	}
	go pumpTUNToCarrier(c, t, tun)

	errs := 0
	var lastInitialReply time.Time
	for {
		pkt, err := c.Recv()
		if err != nil {
			errs++
			if errs >= maxReadErrors {
				log.Fatalf("UDP read failing persistently: %v", err)
			}
			log.Printf("UDP read error (%d/%d): %v", errs, maxReadErrors, err)
			time.Sleep(readErrBackoff)
			continue
		}
		errs = 0
		// Handshake cover only ever appears with obfs on; without it the first byte is
		// random nonce material and this test would discard half of all real traffic.
		if t.obfs != nil && quicIsLongHeader(pkt) {
			// Continue the conversation under the connection ID the peer named, so the
			// 1-RTT packets belong to the handshake instead of looking unrelated to it.
			if _, scid, ok := quicParseLongCIDs(pkt); ok {
				t.obfs.adoptPeerCID(scid)
			}
			// Answer at most occasionally: an unauthenticated packet triggers this, so an
			// unthrottled reply would make the port an amplification source for anyone
			// willing to spray long-header datagrams at it.
			if cfg.Role == "b" && time.Since(lastInitialReply) > 30*time.Second {
				lastInitialReply = time.Now()
				if err := replyServerInitial(c, pkt); err != nil {
					log.Printf("warning: handshake reply failed: %v", err)
				}
			}
			continue
		}
		plain, ok := t.open(pkt)
		if !ok {
			continue // invalid/forged/replayed packet — dropped silently
		}
		// Only now, after the packet has authenticated, is the source trusted enough
		// to move the tunnel to it.
		if c.lastSrc != nil {
			t.maybeRoam(c.lastSrc)
		}
		if len(plain) == 0 {
			continue // keepalive packet — not written to TUN
		}
		if _, err := tun.Write(plain); err != nil {
			log.Printf("writing to TUN: %v", err)
		}
	}
}

func runTCP(cfg *Config, t *Tunnel, tun *os.File) {
	c := &tcpCarrier{buf: make([]byte, maxPktSize)}

	// Role a dials out, role b accepts. Whoever is behind the more restrictive network
	// should be the dialer; role a (the inside server) is that side by construction.
	if cfg.Role == "a" {
		go func() {
			for {
				conn, err := net.DialTimeout("tcp", cfg.Peer, 15*time.Second)
				if err != nil {
					log.Printf("tcp dial failed: %v", err)
					time.Sleep(3 * time.Second)
					continue
				}
				setTCPOpts(conn)
				log.Printf("tcp connected: %s", conn.RemoteAddr())
				// Wait for this connection specifically to be retired by the reader.
				<-c.set(conn)
				log.Printf("tcp disconnected")
				time.Sleep(1 * time.Second)
			}
		}()
	} else {
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			log.Fatalf("TCP listen failed: %v", err)
		}
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("tcp accept failed: %v", err)
					time.Sleep(time.Second)
					continue
				}
				setTCPOpts(conn)
				log.Printf("tcp accepted: %s", conn.RemoteAddr())
				// A new connection supersedes the old one: after a peer restart the
				// stale socket may never produce an error on this side.
				c.set(conn)
			}
		}()
	}

	log.Printf("tunnel up - traffic ready to flow.")
	if *cfg.Keepalive > 0 {
		go keepaliveLoop(c, t, *cfg.Keepalive)
	}
	go pumpTUNToCarrier(c, t, tun)

	for {
		pkt, err := c.Recv()
		if err != nil {
			// A stream error means the connection is gone; drop it and let the dialer
			// or the accept loop install a fresh one. Framing cannot resynchronise
			// mid-stream, so continuing on the same socket would corrupt every packet.
			c.set(nil)
			time.Sleep(readErrBackoff)
			continue
		}
		if t.obfs != nil && quicIsLongHeader(pkt) {
			continue
		}
		plain, ok := t.open(pkt)
		if !ok {
			continue
		}
		if len(plain) == 0 {
			continue
		}
		if _, err := tun.Write(plain); err != nil {
			log.Printf("writing to TUN: %v", err)
		}
	}
}

// pumpTUNToCarrier moves outbound IP packets from the TUN device onto the carrier.
func pumpTUNToCarrier(c carrier, t *Tunnel, tun *os.File) {
	buf := make([]byte, maxPktSize)
	errs := 0
	for {
		n, err := tun.Read(buf)
		if err != nil {
			errs++
			if errs >= maxReadErrors {
				log.Fatalf("TUN read failing persistently: %v", err)
			}
			log.Printf("TUN read error (%d/%d): %v", errs, maxReadErrors, err)
			time.Sleep(readErrBackoff)
			continue
		}
		errs = 0
		if n == 0 {
			continue
		}
		if err := c.Send(t.seal(buf[:n])); err != nil {
			log.Printf("carrier send failed: %v", err)
		}
	}
}

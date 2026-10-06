// WebSocket carrier — the tunnel as binary WebSocket messages, so that it can ride a CDN.
//
// Every other carrier talks to the peer's own address, and on the reference path that address
// is the problem: measured 2026-10-05, every flow the inside server opened toward the foreign
// server — UDP, ICMP or TCP, on any port — was cut after its first ~6 packets or 8688 bytes. No
// disguise changes the destination address. A CDN does: the inside server talks to the CDN's
// edge, an address it shares with a large slice of the ordinary web that a censor cannot block
// wholesale, and the edge carries the bytes on to the foreign server over a path the censor never
// sees. Cloudflare proxies WebSocket on every plan and on thirteen ports, and that is the target.
//
//	dialer --TLS, SNI=domain--> CDN edge --HTTP or HTTPS, same port--> listener (the origin)
//
// What crosses the censored link is an ordinary TLS connection to a CDN address carrying an
// HTTP/1.1 upgrade to WebSocket, then binary messages — one sealed tunnel datagram per message,
// the datagram unchanged. The tunnel's own AEAD still protects every byte end to end; the TLS layer
// is cover and transport, not the security boundary, which is why the edge that terminates it
// learns nothing it could use.
//
// Admission. The request path is a secret — derived from the key unless one is configured — but
// it is not what lets a connection carry the tunnel. The listener answers the upgrade and then
// waits for the first message, and only if that message opens under the tunnel key, fresh and not
// a replay, does the connection replace the carrier's current one. A request for any other path
// gets the 404 an ordinary web server would give and goes to the DPI observer; an upgrade on the
// right path whose first message does not authenticate is filed as what it is, someone who has the
// path but not the key. It is the stream version of the reverse UDP listener's rule: the peer is
// whoever first authenticates, and nobody else gets anything out of the port.
//
// The listener speaks TLS and plain HTTP on the same port, told apart by the first byte (0x16
// opens every TLS handshake and starts no HTTP method), so the origin works behind every
// Cloudflare SSL mode: Flexible (plain HTTP to the origin), Full (TLS with any certificate — a
// self-signed one is made at start-up) and Full (strict) (a certificate the operator supplies).
//
// It is a stream carrier and has the TCP carrier's costs: one lost segment stalls every inner
// connection until it is retransmitted. It is not a replacement for UDP where UDP works; it is for
// paths where nothing addressed to the peer gets through at all.
//
// Honest limits. The TLS ClientHello is Go's crypto/tls, not a browser's, so a JA3-style
// fingerprint tells it apart from Chrome. The CDN itself sees the WebSocket, its timing and its
// volume, though not the content. Cloudflare closes a WebSocket idle for 100 s, which the keepalive
// (25 s by default) stays well inside.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	wsOpCont   = 0x0
	wsOpText   = 0x1
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xA

	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // RFC 6455 §1.3

	// One message carries one sealed datagram, which never exceeds maxPktSize.
	wsMaxMessage = maxPktSize
	// The longest frame header: 2 bytes, an 8-byte extended length, a 4-byte mask.
	wsMaxFrameHeader = 14

	// Bounds on the HTTP phase: the head may not exceed this and must arrive within the timeout.
	wsMaxHead          = 16 << 10
	wsHandshakeTimeout = 15 * time.Second
	// How long an upgraded connection has to produce its first authenticated message. The dialer
	// sends one straight behind the upgrade, so this only ever runs out on a stranger.
	wsAdmitTimeout = 15 * time.Second
)

var (
	errWSProtocol = errors.New("websocket framing violated")
	errWSTooBig   = errors.New("websocket message larger than any tunnel datagram")
	errWSRejected = errors.New("websocket connection is not the peer")
	errWSClosed   = errors.New("websocket closed by the far end")
)

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

// checkWS refuses the combinations the WebSocket carrier cannot honour, and a dialing end with
// nowhere to dial — an error at start-up rather than a tunnel that never comes up.
func checkWS(c *Config) error {
	if c.Transport != "ws" {
		return nil
	}
	switch {
	case c.Obfs != obfsNone:
		return fmt.Errorf("transport \"ws\" carries the tunnel as WebSocket messages inside TLS to a CDN, "+
			"which is its disguise, and takes no obfs; set \"obfs\": %q on BOTH servers", obfsNone)
	case c.Hop.on():
		return fmt.Errorf("transport \"ws\" is one connection to a fixed CDN port, so port hopping cannot " +
			"apply; set \"hop\".\"enabled\" to false on BOTH servers")
	}
	if c.dials() {
		if _, err := parseWSURL(c.WS.URL); err != nil {
			return fmt.Errorf("transport \"ws\": this end dials, so \"ws\".\"url\" must be the CDN address, "+
				"e.g. wss://tunnel.example.com:8443 — %v", err)
		}
	}
	if p := c.WS.Path; p != "" && !strings.HasPrefix(p, "/") {
		return fmt.Errorf("\"ws\".\"path\" must start with \"/\", got %q", p)
	}
	return nil
}

func parseWSURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("it is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("the scheme must be ws or wss, not %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("it names no host")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
	}
	return u, nil
}

// wsDerivedPath is the request path both ends use when none is configured. Derived from the key,
// so the two agree without being told and nobody without the key can guess it; it reads like the
// opaque route an application puts in front of its WebSocket endpoint.
func wsDerivedPath(psk []byte) string {
	return "/" + hex.EncodeToString(hkdf(psk, nil, []byte("aestun-v1 ws-path"), 12))
}

// wsPath resolves the request path, the same way on both ends so one block serves both servers:
// a path in the URL, else the configured one, else the derived one. "/" counts as unset — a
// trailing slash typed out of habit must not split the two ends onto different paths.
func wsPath(c *WSConfig, psk []byte) string {
	if c.URL != "" {
		if u, err := url.Parse(c.URL); err == nil && u.Path != "" && u.Path != "/" {
			return u.EscapedPath()
		}
	}
	if c.Path != "" && c.Path != "/" {
		return c.Path
	}
	return wsDerivedPath(psk)
}

// ---------------------------------------------------------------------------
// framing (RFC 6455 §5)
// ---------------------------------------------------------------------------

// wsAppendFrame appends one unfragmented frame to dst. A client (rng non-nil) masks the payload
// with a fresh key, as the RFC requires of it and as a CDN in the middle may enforce; a server
// sends it bare.
func wsAppendFrame(dst []byte, op byte, payload []byte, rng *csprng) []byte {
	n := len(payload)
	var m byte
	if rng != nil {
		m = 0x80
	}
	dst = append(dst, 0x80|op)
	switch {
	case n < 126:
		dst = append(dst, m|byte(n))
	case n <= 0xffff:
		dst = append(dst, m|126, byte(n>>8), byte(n))
	default:
		dst = append(dst, m|127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if rng == nil {
		return append(dst, payload...)
	}
	var key [4]byte
	rng.read(key[:])
	dst = append(dst, key[:]...)
	start := len(dst)
	dst = append(dst, payload...)
	wsMask(dst[start:], key)
	return dst
}

// wsMask XORs b with the masking key, eight bytes at a time. Its own inverse.
func wsMask(b []byte, key [4]byte) {
	k := uint64(binary.LittleEndian.Uint32(key[:]))
	k |= k << 32
	i := 0
	for ; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], binary.LittleEndian.Uint64(b[i:])^k)
	}
	for ; i < len(b); i++ {
		b[i] ^= key[i&3]
	}
}

// wsReader parses frames off one connection. Not safe for concurrent use: the carrier's receive
// loop owns it. A payload it returns aliases its buffers and is valid until the next call.
type wsReader struct {
	br    *bufio.Reader
	msg   []byte // the data message being assembled
	msgOp byte   // that message's opcode while one is in progress, 0 between messages
	ctl   [125]byte
	hdr   [8]byte
}

// next returns the next complete data message, or the next control frame. Fragmented messages
// are reassembled; a control frame arriving in the middle of one is returned as it comes, and the
// message carries on assembling on the following calls, as the RFC allows.
func (r *wsReader) next() (byte, []byte, error) {
	for {
		if _, err := io.ReadFull(r.br, r.hdr[:2]); err != nil {
			return 0, nil, err
		}
		b0, b1 := r.hdr[0], r.hdr[1]
		if b0&0x70 != 0 {
			return 0, nil, errWSProtocol // RSV bits mean an extension, and none was negotiated
		}
		fin, op, masked := b0&0x80 != 0, b0&0x0f, b1&0x80 != 0
		n := uint64(b1 & 0x7f)
		switch n {
		case 126:
			if _, err := io.ReadFull(r.br, r.hdr[:2]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(r.hdr[:2]))
		case 127:
			if _, err := io.ReadFull(r.br, r.hdr[:8]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(r.hdr[:8])
		}
		var key [4]byte
		if masked {
			if _, err := io.ReadFull(r.br, key[:]); err != nil {
				return 0, nil, err
			}
		}
		if op >= wsOpClose {
			if !fin || n > 125 || op > wsOpPong {
				return 0, nil, errWSProtocol
			}
			p := r.ctl[:n]
			if _, err := io.ReadFull(r.br, p); err != nil {
				return 0, nil, err
			}
			if masked {
				wsMask(p, key)
			}
			return op, p, nil
		}
		switch {
		case op == wsOpCont && r.msgOp == 0, op != wsOpCont && r.msgOp != 0:
			return 0, nil, errWSProtocol // a continuation of nothing, or a new message inside one
		case op != wsOpCont:
			if op != wsOpText && op != wsOpBinary {
				return 0, nil, errWSProtocol // a reserved opcode
			}
			r.msgOp, r.msg = op, r.msg[:0]
		}
		if n > uint64(wsMaxMessage-len(r.msg)) {
			return 0, nil, errWSTooBig
		}
		start, end := len(r.msg), len(r.msg)+int(n)
		if cap(r.msg) < end {
			grown := make([]byte, end, max(end, 2*cap(r.msg), 2048))
			copy(grown, r.msg)
			r.msg = grown
		} else {
			r.msg = r.msg[:end]
		}
		if _, err := io.ReadFull(r.br, r.msg[start:]); err != nil {
			return 0, nil, err
		}
		if masked {
			wsMask(r.msg[start:], key)
		}
		if fin {
			op := r.msgOp
			r.msgOp = 0
			return op, r.msg, nil
		}
	}
}

// wsAccept is the Sec-WebSocket-Accept value that answers a Sec-WebSocket-Key.
func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// an upgraded connection
// ---------------------------------------------------------------------------

// wsConn is an upgraded connection: the transport (TLS or plain TCP), the buffered reader the
// HTTP head was read through — which may already hold the first frames — and the frame parser
// that carries on from it.
type wsConn struct {
	net.Conn
	lr     io.LimitedReader // bounds the HTTP head; lifted once the upgrade is done
	br     *bufio.Reader
	rd     wsReader
	first  []byte // a message already read during admission, delivered before anything else
	client bool   // this end dialled, so it masks what it sends
	via    string // where the connection goes or came from, for the log
}

func newWSConn(c net.Conn) *wsConn {
	w := &wsConn{Conn: c}
	w.lr = io.LimitedReader{R: c, N: wsMaxHead}
	w.br = bufio.NewReaderSize(&w.lr, 32<<10)
	w.rd.br = w.br
	return w
}

// Read serves the stream through the same buffer the head was read through, so nothing those
// reads pulled in early is lost.
func (w *wsConn) Read(p []byte) (int, error) { return w.br.Read(p) }

func (w *wsConn) upgraded() { w.lr.N = 1 << 62 }

// takeFirst hands out the admission message once.
func (w *wsConn) takeFirst() []byte {
	p := w.first
	w.first = nil
	return p
}

// peekConn lets admission look at the first byte without taking it from whoever reads next. The
// buffer is tiny on purpose: once it is drained, reads larger than it go straight to the socket.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) { return p.r.Read(b) }

// headerHasToken reports whether a comma-separated header carries a token, case-insensitively —
// "Connection: keep-alive, Upgrade" is an upgrade.
func headerHasToken(h textproto.MIMEHeader, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), token) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// dialing end
// ---------------------------------------------------------------------------

// wsDialer opens carrier connections for the dialing end.
type wsDialer struct {
	url *url.URL
	// The TCP addresses dialled: ws.connect's list, or the URL's host and port. Measured on the
	// reference path, one Cloudflare range passed where another on the same network did not, so
	// a list is tried in turn, starting from the one that worked last.
	addrs  []string
	good   atomic.Int32
	host   string // Host header
	target string // request-target: path and query
	origin string
	ua     string
	tlsCfg *tls.Config    // nil for ws://
	tune   func(net.Conn) // platform socket options; may be nil
}

func newWSDialer(c *WSConfig, psk []byte, tune func(net.Conn)) (*wsDialer, error) {
	u, err := parseWSURL(c.URL)
	if err != nil {
		return nil, err
	}
	defPort, httpScheme := "80", "http"
	if u.Scheme == "wss" {
		defPort, httpScheme = "443", "https"
	}
	port := u.Port()
	if port == "" {
		port = defPort
	}
	d := &wsDialer{url: u, ua: c.UserAgent, tune: tune}
	for _, a := range strings.FieldsFunc(c.Connect, func(r rune) bool { return r == ',' || r == ' ' }) {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(strings.Trim(a, "[]"), port) // an address without a port takes the URL's
		}
		d.addrs = append(d.addrs, a)
	}
	if len(d.addrs) == 0 {
		d.addrs = []string{net.JoinHostPort(u.Hostname(), port)}
	}
	// Host as a browser writes it: the default port left off, any other one kept.
	d.host = u.Hostname()
	if strings.Contains(d.host, ":") {
		d.host = "[" + d.host + "]"
	}
	if port != defPort {
		d.host += ":" + port
	}
	if c.Host != "" {
		d.host = c.Host
	}
	d.origin = httpScheme + "://" + d.host
	d.target = wsPath(c, psk)
	if u.RawQuery != "" {
		d.target += "?" + u.RawQuery
	}
	if u.Scheme == "wss" {
		sni := c.SNI
		if sni == "" {
			sni = u.Hostname()
		}
		d.tlsCfg = &tls.Config{
			ServerName: sni,
			// http/1.1 only: offered h2, a CDN would pick it, and WebSocket over HTTP/2 is a
			// different protocol (RFC 8441) this end does not speak.
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: c.Insecure,
			MinVersion:         tls.VersionTLS12,
		}
	}
	return d, nil
}

// describe is the dialer's one-line summary for the log: where it dials, and through which
// address when that is not simply the URL's host.
func (d *wsDialer) describe() string {
	via := ""
	if a := d.addrs[int(d.good.Load())]; len(d.addrs) > 1 || a != net.JoinHostPort(d.url.Hostname(), d.port()) {
		via = " via " + a
		if len(d.addrs) > 1 {
			via += fmt.Sprintf(" (%d of %d addresses)", int(d.good.Load())+1, len(d.addrs))
		}
	}
	return fmt.Sprintf("%s://%s%s%s", d.url.Scheme, d.host, d.target, via)
}

func (d *wsDialer) port() string {
	if p := d.url.Port(); p != "" {
		return p
	}
	if d.url.Scheme == "wss" {
		return "443"
	}
	return "80"
}

// wsStatusError is an HTTP exchange that completed without an upgrade. Through a CDN it is the
// most useful thing a failed dial can report: the status code says which leg failed.
type wsStatusError struct {
	code   int
	status string
	server string
	ray    string
}

func (e *wsStatusError) Error() string {
	s := "the upgrade was answered \"" + e.status + "\""
	var via []string
	if e.server != "" {
		via = append(via, "server: "+e.server)
	}
	if e.ray != "" {
		via = append(via, "cf-ray: "+e.ray)
	}
	if len(via) > 0 {
		s += " (" + strings.Join(via, ", ") + ")"
	}
	if h := wsStatusHint(e.code); h != "" {
		s += " — " + h
	}
	return s
}

// wsStatusHint says what an answer other than 101 means, in the order the legs are crossed.
func wsStatusHint(code int) string {
	switch code {
	case 301, 302, 307, 308:
		return "the CDN redirects plain HTTP to HTTPS: use a wss:// URL on one of its TLS ports (443, 2053, 2083, 2087, 2096, 8443)"
	case 400, 426:
		return "the CDN or the origin refused the upgrade — check that WebSockets are enabled for the zone (Cloudflare: Network > WebSockets)"
	case 403:
		return "forbidden: a CDN firewall, WAF or bot rule stopped the request"
	case 404:
		return "a web server answered, but not on the tunnel's path: the ends disagree on the path (or the key it is derived from), or another program owns that origin port"
	case 520:
		return "the origin answered something the CDN could not use"
	case 521:
		return "the CDN could not connect to the origin: nothing listens on that origin port, or the origin's firewall refuses the CDN's addresses"
	case 522, 524:
		return "the CDN timed out reaching the origin: a firewall drops the CDN's packets, or the DNS record points at the wrong address"
	case 523:
		return "the CDN has no route to the origin address in the DNS record"
	case 525:
		return "the CDN's TLS handshake with the origin failed (SSL mode Full/strict wants TLS on the origin port; this listener speaks it on its own port)"
	case 526:
		return "SSL mode Full (strict) rejects the origin's certificate: set ws.cert and ws.cert_key to a Cloudflare Origin CA certificate, or use mode Full"
	case 530:
		return "the CDN has no working origin for this host — is the DNS record proxied?"
	}
	return ""
}

// dial opens one connection and upgrades it, trying the addresses in turn from the last one that
// worked. Only a failure to reach the edge moves it on: once the upgrade has been answered, the
// edge is working and its status is about the origin, which another edge address would not change.
// trace, when set, is told each step as it completes; the carrier passes nil, and ws-check uses it
// to say where a failure happened.
func (d *wsDialer) dial(timeout time.Duration, trace func(string)) (*wsConn, error) {
	n := len(d.addrs)
	if n > 1 && timeout > 6*time.Second {
		timeout = 6 * time.Second // a list is worth walking quickly; one dead address must not stall the rest
	}
	first := int(d.good.Load())
	var errs []string
	for i := 0; i < n; i++ {
		k := (first + i) % n
		w, err := d.dialAddr(d.addrs[k], timeout, trace)
		if err == nil {
			d.good.Store(int32(k))
			return w, nil
		}
		var se *wsStatusError
		if errors.As(err, &se) || n == 1 {
			return nil, err
		}
		errs = append(errs, err.Error())
		if trace != nil {
			trace("         " + err.Error() + " — trying the next address")
		}
	}
	return nil, fmt.Errorf("no address reached the edge: %s", strings.Join(errs, "; "))
}

func (d *wsDialer) dialAddr(addr string, timeout time.Duration, trace func(string)) (*wsConn, error) {
	t0 := time.Now()
	step := func(format string, args ...any) {
		if trace != nil {
			trace(fmt.Sprintf("%6.1f ms  ", float64(time.Since(t0).Microseconds())/1000) + fmt.Sprintf(format, args...))
		}
	}
	nd := net.Dialer{Timeout: timeout}
	raw, err := nd.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	step("tcp connected to %s", raw.RemoteAddr())
	if d.tune != nil {
		d.tune(raw)
	}
	raw.SetDeadline(time.Now().Add(wsHandshakeTimeout))
	var conn net.Conn = raw
	if d.tlsCfg != nil {
		tc := tls.Client(raw, d.tlsCfg)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("tls with %s (sni %s): %w", addr, d.tlsCfg.ServerName, err)
		}
		st := tc.ConnectionState()
		if trace != nil {
			cert := "-"
			if len(st.PeerCertificates) > 0 {
				c := st.PeerCertificates[0]
				cert = fmt.Sprintf("%q issued by %q", c.Subject.CommonName, c.Issuer.CommonName)
			}
			step("tls %s, alpn %q, certificate %s", tls.VersionName(st.Version), st.NegotiatedProtocol, cert)
		}
		conn = tc
	}
	w := newWSConn(conn)
	w.client = true
	w.via = addr
	if err := d.upgrade(w); err != nil {
		conn.Close()
		return nil, err
	}
	step("upgraded to websocket")
	conn.SetDeadline(time.Time{})
	w.upgraded()
	return w, nil
}

func (d *wsDialer) upgrade(w *wsConn) error {
	var k [16]byte
	if _, err := rand.Read(k[:]); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(k[:])
	// The header set and order of a browser's upgrade request. Only the CDN ever sees it — it
	// travels inside TLS — but a request that reads like every other one draws no rule.
	req := "GET " + d.target + " HTTP/1.1\r\n" +
		"Host: " + d.host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Pragma: no-cache\r\n" +
		"Cache-Control: no-cache\r\n" +
		"User-Agent: " + d.ua + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Origin: " + d.origin + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Accept-Encoding: gzip, deflate, br, zstd\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n\r\n"
	if _, err := io.WriteString(w.Conn, req); err != nil {
		return err
	}
	tp := textproto.NewReader(w.br)
	line, err := tp.ReadLine()
	if err != nil {
		return fmt.Errorf("reading the upgrade response: %w", err)
	}
	proto, rest, _ := strings.Cut(line, " ")
	codeStr, _, _ := strings.Cut(rest, " ")
	code, err := strconv.Atoi(codeStr)
	if !strings.HasPrefix(proto, "HTTP/") || err != nil {
		return fmt.Errorf("not an HTTP response: %q", line)
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return fmt.Errorf("reading the upgrade response: %w", err)
	}
	if code != 101 {
		return &wsStatusError{code: code, status: rest, server: hdr.Get("Server"), ray: hdr.Get("Cf-Ray")}
	}
	if !headerHasToken(hdr, "Upgrade", "websocket") || !headerHasToken(hdr, "Connection", "upgrade") {
		return errors.New("answered 101 without a websocket upgrade")
	}
	if hdr.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return errors.New("the upgrade was answered with the wrong Sec-WebSocket-Accept")
	}
	return nil
}

// ---------------------------------------------------------------------------
// listening end
// ---------------------------------------------------------------------------

// wsServer admits connections to the carrier on the listening end.
type wsServer struct {
	t        *Tunnel
	path     string
	tlsCfg   *tls.Config
	certDesc string
	tune     func(net.Conn)
	// Handshakes in progress. Bounded so a flood of half-open connections costs a fixed number
	// of goroutines; the slot is held for the handshake only, not for the connection's life.
	slots chan struct{}
}

func newWSServer(c *WSConfig, t *Tunnel, tune func(net.Conn)) (*wsServer, error) {
	s := &wsServer{t: t, path: wsPath(c, t.psk), tune: tune, slots: make(chan struct{}, 256)}
	var cert tls.Certificate
	var err error
	if c.Cert != "" || c.CertKey != "" {
		cert, err = tls.LoadX509KeyPair(c.Cert, c.CertKey)
		if err != nil {
			return nil, fmt.Errorf("ws.cert/ws.cert_key: %w", err)
		}
		s.certDesc = c.Cert
	} else {
		name := wsCertName(c)
		if cert, err = wsSelfSigned(name); err != nil {
			return nil, err
		}
		s.certDesc = "self-signed for " + name
	}
	s.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	return s, nil
}

// wsCertName is the name a self-signed certificate is issued to: the domain, when the block
// names one. The CDN does not check it under SSL mode Full; it only has to look like a site's.
func wsCertName(c *WSConfig) string {
	if c.Host != "" {
		if h, _, err := net.SplitHostPort(c.Host); err == nil {
			return h
		}
		return c.Host
	}
	if u, err := parseWSURL(c.URL); err == nil {
		return u.Hostname()
	}
	return "localhost"
}

func wsSelfSigned(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// wsRequest is the part of an HTTP request admission looks at.
type wsRequest struct {
	line   string
	method string
	path   string // the request-target without its query
	host   string
	hdr    textproto.MIMEHeader
}

// readWSRequest reads a request head. On a malformed one it still returns what it read, so the
// observer can file the attempt with something to look at.
func readWSRequest(br *bufio.Reader) (*wsRequest, error) {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return &wsRequest{line: line}, err
	}
	method, rest, ok1 := strings.Cut(line, " ")
	target, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 || !strings.HasPrefix(proto, "HTTP/1.") {
		return &wsRequest{line: line}, errors.New("not an HTTP/1 request")
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return &wsRequest{line: line}, err
	}
	path, _, _ := strings.Cut(target, "?")
	return &wsRequest{line: line, method: method, path: path, host: hdr.Get("Host"), hdr: hdr}, nil
}

// upgradeKey returns the request's Sec-WebSocket-Key if it is a WebSocket upgrade on this end's
// path, and false for anything else.
func (s *wsServer) upgradeKey(r *wsRequest) (string, bool) {
	if r.method != "GET" || subtle.ConstantTimeCompare([]byte(r.path), []byte(s.path)) != 1 {
		return "", false
	}
	if !headerHasToken(r.hdr, "Upgrade", "websocket") || !headerHasToken(r.hdr, "Connection", "upgrade") ||
		r.hdr.Get("Sec-WebSocket-Version") != "13" {
		return "", false
	}
	key := r.hdr.Get("Sec-WebSocket-Key")
	if k, err := base64.StdEncoding.DecodeString(key); err != nil || len(k) != 16 {
		return "", false
	}
	return key, true
}

// wsNotFound is what anything other than the tunnel's upgrade gets: nginx's own 404, byte for
// byte apart from the date, so the port reads as an ordinary web server with nothing at that URL.
func wsNotFound() string {
	const body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n" +
		"<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	return "HTTP/1.1 404 Not Found\r\n" +
		"Server: nginx\r\n" +
		"Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
}

// addrPortOf turns a socket address into the observer's key, unmapped like every other source.
func addrPortOf(a net.Addr) netip.AddrPort {
	if ta, ok := a.(*net.TCPAddr); ok {
		return normAddrPort(ta.AddrPort())
	}
	return netip.AddrPort{}
}

func normAddrPort(a netip.AddrPort) netip.AddrPort {
	if !a.IsValid() {
		return a
	}
	return netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
}

// wsVisitor is who the request is really from. Behind a CDN the socket's address is the edge's,
// and the client's travels in a header — CF-Connecting-IP on Cloudflare. Headers can be forged by
// anyone who reaches the origin directly, so this is used for the log only, never for a decision.
func wsVisitor(h textproto.MIMEHeader, src netip.AddrPort) netip.AddrPort {
	for _, v := range []string{h.Get("Cf-Connecting-Ip"), h.Get("True-Client-Ip"), h.Get("X-Real-Ip"),
		strings.TrimSpace(strings.Split(h.Get("X-Forwarded-For"), ",")[0])} {
		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			return netip.AddrPortFrom(a.Unmap(), 0)
		}
	}
	return src
}

// admit takes one accepted connection through TLS (if its first byte asks for it), the HTTP
// upgrade and the first message, and returns it ready to carry the tunnel only if that message
// authenticated. Everything turned away is answered as an ordinary web server would answer it and
// filed with the DPI observer; the caller closes the socket.
func (s *wsServer) admit(raw net.Conn) (*wsConn, error) {
	if s.tune != nil {
		s.tune(raw)
	}
	raw.SetDeadline(time.Now().Add(wsHandshakeTimeout))
	src := addrPortOf(raw.RemoteAddr())
	pc := &peekConn{Conn: raw, r: bufio.NewReaderSize(raw, 16)}
	first, err := pc.r.Peek(1)
	if err != nil {
		return nil, err // closed without a byte: nothing worth filing
	}
	var conn net.Conn = pc
	if first[0] == 0x16 {
		sample, _ := pc.r.Peek(pc.r.Buffered())
		sample = append([]byte(nil), sample...)
		tc := tls.Server(pc, s.tlsCfg)
		if err := tc.Handshake(); err != nil {
			s.t.dpi.observeStranger(evScanUnauth, src, sample, 0, "")
			return nil, errWSRejected
		}
		conn = tc
	}
	w := newWSConn(conn)
	req, err := readWSRequest(w.br)
	if err != nil {
		if req.line != "" {
			s.t.dpi.observeStranger(evProbeHTTP, src, []byte(req.line), 0, "")
		}
		return nil, errWSRejected
	}
	visitor := wsVisitor(req.hdr, src)
	key, ok := s.upgradeKey(req)
	if !ok {
		io.WriteString(conn, wsNotFound())
		s.t.dpi.observeStranger(evProbeHTTP, visitor, []byte(req.line), 0, req.host)
		return nil, errWSRejected
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return nil, err
	}
	w.upgraded()
	conn.SetDeadline(time.Now().Add(wsAdmitTimeout))

	// The first message decides. Control frames before it are skipped; a close is a client that
	// only wanted to see the upgrade work (ws-check does exactly that) and is not filed as a probe.
	for {
		op, p, err := w.rd.next()
		if err != nil {
			s.t.dpi.observeStranger(evProbeWS, visitor, []byte(req.line), 0, req.host)
			return nil, errWSRejected
		}
		switch op {
		case wsOpClose:
			return nil, errWSClosed
		case wsOpBinary:
			if !s.t.authentic(newOpener(), p) {
				s.t.dpi.observeStranger(evProbeWS, visitor, p, 0, req.host)
				return nil, errWSRejected
			}
			w.first = p
			w.via = src.String()
			if visitor != src {
				w.via += " for " + visitor.Addr().String()
			}
			conn.SetDeadline(time.Time{})
			return w, nil
		}
	}
}

// ---------------------------------------------------------------------------
// ws-check: the dialing end's view of the path, without a tunnel
// ---------------------------------------------------------------------------

// wsCheck dials the way the carrier would and reports every step, then closes politely without
// sending the far end anything that could displace a running tunnel's connection. It is how an
// operator finds out which leg of dialer -> CDN -> origin is broken before switching a server over.
func wsCheck(c *WSConfig, psk []byte, out io.Writer) error {
	d, err := newWSDialer(c, psk, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "dialling %s\n", d.describe())
	w, err := d.dial(wsHandshakeTimeout, func(s string) { fmt.Fprintln(out, "  "+s) })
	if err != nil {
		return err
	}
	defer w.Close()
	var code [2]byte
	binary.BigEndian.PutUint16(code[:], 1000)
	io.WriteString(w.Conn, string(wsAppendFrame(nil, wsOpClose, code[:], newCSPRNG())))
	fmt.Fprintln(out, "OK: the upgrade reached a WebSocket listener on the tunnel's path.")
	return nil
}

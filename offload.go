//go:build linux

// Kernel offload for the carrier: UDP segmentation (GSO) on the way out, UDP receive
// coalescing (GRO) on the way in, and batched reads from the TUN device to feed them.
//
// Why this exists. After the cipher and allocation work, what was left on the packet path
// was almost entirely kernel: a read syscall per packet from the TUN device, a send syscall
// per packet to the socket, and the UDP output path walked once per datagram. Measured on
// the foreign endpoint saturating the link, that was ~87% of a core for ~194 Mbit/s, or
// roughly 45 microseconds a packet against 6.6 microseconds of actual encryption.
//
// The fix is not to make any of those steps faster but to stop doing them per packet:
//
//   - Outbound, consecutive datagrams of equal size are concatenated into one buffer and
//     handed to the kernel in a single sendmsg carrying a UDP_SEGMENT control message. The
//     kernel splits the buffer back into individual datagrams at the last possible moment,
//     so one syscall, one route lookup and one pass down the output path now cover up to 64
//     of them. Bulk traffic is exactly the case where this applies: every full-MTU packet
//     seals to the same length, so long runs of identical sizes are the norm.
//
//   - Inbound, UDP_GRO lets the kernel hand back several datagrams from one recvmsg, with a
//     control message naming the segment size so they can be split apart again.
//
//   - Feeding the outbound side needs more than one packet in hand at a time, so the TUN
//     pump does one blocking read and then drains whatever else is already queued with
//     non-blocking reads. Under load that fills a batch; when the link is quiet the drain
//     returns EAGAIN immediately and a single packet goes out on its own, so nothing is
//     ever delayed waiting for a batch to fill.
//
// None of this changes a single byte on the wire. The peer receives exactly the datagrams
// it received before, in the same order, at the same sizes — segmentation happens below
// IP and is invisible above it. Everything here degrades cleanly: if a kernel refuses the
// socket options, the code falls back to one datagram per syscall.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kernel accepts at most 64 segments per UDP_SEGMENT send (UDP_MAX_SEGMENTS), and the
// whole buffer still has to fit in one datagram's worth of address space.
const (
	maxGSOSegments = 64
	maxGSOBytes    = 61440
)

// ---------------------------------------------------------------------------
// socket setup
// ---------------------------------------------------------------------------

// enableGSO turns on UDP segmentation offload for sending. Returns false if the kernel
// will not have it, in which case the caller sends one datagram per syscall as before.
func enableGSO(conn *net.UDPConn) bool {
	ok := false
	if rc, err := conn.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			// Probing with a real segment size: some stacks accept the option only when
			// it is plausible. It is reset per-send via the control message anyway.
			if err := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, 0); err == nil {
				ok = true
			}
		})
	}
	return ok
}

// enableGRO asks the kernel to coalesce received datagrams.
func enableGRO(conn *net.UDPConn) bool {
	ok := false
	if rc, err := conn.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_GRO, 1); err == nil {
				ok = true
			}
		})
	}
	return ok
}

// gsoControl builds the UDP_SEGMENT control message for one send.
func gsoControl(buf []byte, segSize uint16) []byte {
	space := unix.CmsgSpace(2)
	if cap(buf) < space {
		buf = make([]byte, space)
	}
	buf = buf[:space]
	clear(buf)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(buf[unix.CmsgLen(0):], segSize)
	return buf
}

// parseGROSegment pulls the segment size out of the receive control messages. Zero means
// the kernel did not coalesce anything and the buffer holds exactly one datagram.
func parseGROSegment(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_UDP && m.Header.Type == unix.UDP_GRO && len(m.Data) >= 2 {
			return int(binary.NativeEndian.Uint16(m.Data[:2]))
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// outbound batching
// ---------------------------------------------------------------------------

// txBatch collects sealed datagrams so that a run of equally sized ones can leave in a
// single segmented send. A datagram whose size differs from the run in progress forces the
// run to be flushed first — the kernel requires every segment but the last to be the same
// length, and honouring that is what keeps the datagrams on the wire byte-identical to the
// unbatched path.
type txBatch struct {
	buf     []byte
	n       int
	segSize int
	count   int
	oob     []byte
	gso     bool
}

func newTxBatch(gso bool) *txBatch {
	return &txBatch{
		buf: make([]byte, maxGSOBytes+maxPktSize),
		oob: make([]byte, unix.CmsgSpace(2)),
		gso: gso,
	}
}

// add appends a sealed datagram, returning true if the batch must be flushed before the
// next one can join it.
func (b *txBatch) add(pkt []byte) (full bool) {
	if b.count == 0 {
		b.segSize = len(pkt)
	}
	copy(b.buf[b.n:], pkt)
	b.n += len(pkt)
	b.count++
	return b.count >= maxGSOSegments || b.n+b.segSize > maxGSOBytes
}

// wants reports whether pkt can join the current run without flushing it first.
func (b *txBatch) wants(pkt []byte) bool {
	return b.count == 0 || (b.gso && len(pkt) == b.segSize && b.count < maxGSOSegments && b.n+len(pkt) <= maxGSOBytes)
}

func (b *txBatch) reset() { b.n, b.count, b.segSize = 0, 0, 0 }

// ---------------------------------------------------------------------------
// TUN device: attach first, then let the runtime poll it
// ---------------------------------------------------------------------------

// openTUNNonblock opens /dev/net/tun, attaches it to an interface, and only then puts it
// into non-blocking mode and hands it to the os package.
//
// The order matters and the previous code had it the other way round. os.OpenFile registers
// the descriptor with the runtime's poller immediately, but a /dev/net/tun descriptor that
// has not yet been through TUNSETIFF is not attached to any device: Go's own test suite
// uses exactly this file as its example of a descriptor in a bad state. Registering it that
// early happened to work when the tunnel was the first pollable thing the process opened,
// and failed outright with "read /dev/net/tun: not pollable" when anything else — a pprof
// listener, say — initialised the poller first. Attaching the device before the descriptor
// is ever polled removes that ordering dependency, and gives us a descriptor that is
// genuinely non-blocking, which is what makes the batched drain below possible.
func openTUNNonblock(name string) (*os.File, string, error) {
	return openTUNQueue(name, 0)
}

// openTUNQueue opens one queue of a TUN device. extraFlags carries IFF_MULTI_QUEUE when the
// caller wants more than one; every queue of the same device is opened with the same name and
// the same flags, and the kernel hands each its own share of the traffic.
func openTUNQueue(name string, extraFlags uint16) (*os.File, string, error) {
	fd, err := syscall.Open(devNetTun, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", &os.PathError{Op: "open", Path: devNetTun, Err: err}
	}
	var req ifReq
	copy(req.Name[:], name)
	req.Flags = iffTun | iffNoPI | extraFlags
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff,
		uintptr(unsafe.Pointer(&req))); errno != 0 {
		syscall.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF: %v", errno)
	}
	got := string(bytes.TrimRight(req.Name[:], "\x00"))

	// Now that it is a real device, non-blocking mode is meaningful and the poller will
	// accept it. os.NewFile detects the flag and wires it up.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, "", err
	}
	f := os.NewFile(uintptr(fd), devNetTun)
	if f == nil {
		syscall.Close(fd)
		return nil, "", os.ErrInvalid
	}
	return f, got, nil
}

// iffMultiQueue is IFF_MULTI_QUEUE from linux/if_tun.h: the device may be opened several
// times over, each open becoming an independent queue the kernel load-balances across.
const iffMultiQueue = 0x0100

// openTUNMultiQueue opens n queues on one TUN device.
//
// Why this exists: the TUN device was the throughput ceiling, and it was a *software* one.
// A single reader goroutine doing read -> seal -> send is one core's worth of work no matter
// how many cores the box has, and on the reference link that capped a carrier at ~290 Mbit/s
// against a 2.12 Gbit/s path — while the device itself dropped 301210 packets in ten seconds
// because nothing was draining it fast enough. Changing the qdisc moved that by 4%; the queue
// was never the problem, the single reader was.
//
// Multi-queue is the kernel's own answer: N file descriptors on the same device, each with its
// own queue, distributed by flow hash. N readers then drain in parallel and every one of them
// gets a whole core to work with. Nothing on the wire changes.
//
// Degrades cleanly: a kernel without IFF_MULTI_QUEUE fails on the first open and the caller
// gets the single-queue device it has always had.
func openTUNMultiQueue(name string, n int) ([]*os.File, string, error) {
	if n < 1 {
		n = 1
	}
	if n == 1 {
		f, got, err := openTUNQueue(name, 0)
		if err != nil {
			return nil, "", err
		}
		return []*os.File{f}, got, nil
	}
	files := make([]*os.File, 0, n)
	var ifname string
	for i := 0; i < n; i++ {
		f, got, err := openTUNQueue(name, iffMultiQueue)
		if err != nil {
			for _, x := range files {
				x.Close()
			}
			if i == 0 {
				// The kernel will not do multi-queue at all; fall back to one plain queue.
				f1, got1, err1 := openTUNQueue(name, 0)
				if err1 != nil {
					return nil, "", err1
				}
				log.Printf("warning: TUN multi-queue unavailable (%v); using a single queue", err)
				return []*os.File{f1}, got1, nil
			}
			return nil, "", err
		}
		ifname = got
		files = append(files, f)
	}
	return files, ifname, nil
}

// tunReader wraps the device with a non-blocking drain used to fill a send batch.
type tunReader struct {
	f  *os.File
	rc syscall.RawConn
}

func newTunReader(f *os.File) *tunReader {
	t := &tunReader{f: f}
	if rc, err := f.SyscallConn(); err == nil {
		t.rc = rc
	}
	return t
}

// read blocks until a packet is available, via the runtime poller.
func (t *tunReader) read(p []byte) (int, error) { return t.f.Read(p) }

// tryRead returns the next queued packet without waiting. n == 0 with a nil error means
// nothing more is queued right now, which is the signal to send what we already have.
func (t *tunReader) tryRead(p []byte) (int, error) {
	if t.rc == nil {
		return 0, nil
	}
	var n int
	var errno syscall.Errno
	err := t.rc.Read(func(fd uintptr) bool {
		var e error
		n, e = syscall.Read(int(fd), p)
		if e != nil {
			if se, ok := e.(syscall.Errno); ok {
				errno = se
			} else {
				errno = syscall.EIO
			}
			n = 0
		}
		// Always "done": this is a deliberate single non-blocking attempt, so returning
		// false here would park the goroutine and defeat the whole point.
		return true
	})
	if err != nil {
		return 0, err
	}
	switch errno {
	case 0:
		return n, nil
	case syscall.EAGAIN, syscall.EINTR:
		return 0, nil // nothing queued
	default:
		return 0, errno
	}
}

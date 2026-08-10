//go:build linux

// sendmmsg / recvmmsg — many datagrams per syscall.
//
// offload.go solves this for the UDP carrier with UDP_SEGMENT and UDP_GRO: the kernel
// splits and merges datagrams below IP, so one syscall covers up to 64 of them. A raw
// ICMP socket has no such thing. Every echo request is its own packet with its own
// header and its own checksum, and nothing in the kernel will coalesce them.
//
// What is still available is the syscall multiplexer underneath: sendmmsg and recvmmsg
// carry an array of message headers, so N datagrams cost one entry into the kernel
// instead of N. The per-packet work (route lookup, output path) is still done N times —
// this is not GSO — but on the measured link the syscall boundary itself was the cost
// that mattered: a single-reader ICMP path lost 22829 packets to receive-buffer overflow
// at 400 Mbit/s while the network delivered 99.5% of them.
//
// x/sys/unix wraps sendmsg and recvmsg but not the vector forms, so the two thin wrappers
// here build the mmsghdr array by hand. The layout is checked at init: mmsghdr is a msghdr
// followed by a 32-bit length, and Go's natural struct padding reproduces the C layout on
// every architecture this builds for. If that assumption were ever wrong the wrappers
// refuse to run and the carrier falls back to one packet per syscall.
package main

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr mirrors struct mmsghdr from <sys/socket.h>.
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte // C pads mmsghdr back to msghdr's alignment on 64-bit
}

// mmsgOK reports whether the struct layout matches what the kernel expects. Go lays
// mmsghdr out identically to C on every supported architecture; this is a cheap guard
// against ever being wrong about that on a new one.
var mmsgOK = unsafe.Sizeof(mmsghdr{}) == unsafe.Sizeof(unix.Msghdr{})+8 &&
	unsafe.Offsetof(mmsghdr{}.len) == unsafe.Sizeof(unix.Msghdr{})

// mmsgBatch is the reusable scratch for one batch of messages: the header array, one
// iovec per message, and one sockaddr per message. Everything is allocated once and
// rewritten in place, so a batched send or receive allocates nothing.
//
// Not safe for concurrent use — the sender owns one, and each receive goroutine owns one.
type mmsgBatch struct {
	hdrs  []mmsghdr
	iovs  []unix.Iovec
	names []unix.RawSockaddrInet4
}

func newMmsgBatch(n int) *mmsgBatch {
	b := &mmsgBatch{
		hdrs:  make([]mmsghdr, n),
		iovs:  make([]unix.Iovec, n),
		names: make([]unix.RawSockaddrInet4, n),
	}
	for i := range b.hdrs {
		b.hdrs[i].hdr.Iov = &b.iovs[i]
		b.hdrs[i].hdr.SetIovlen(1)
		b.hdrs[i].hdr.Name = (*byte)(unsafe.Pointer(&b.names[i]))
		b.hdrs[i].hdr.Namelen = uint32(unsafe.Sizeof(b.names[i]))
	}
	return b
}

// setSend points message i at buf and addresses it to the given IPv4 peer.
func (b *mmsgBatch) setSend(i int, buf []byte, addr [4]byte) {
	b.iovs[i].Base = &buf[0]
	b.iovs[i].SetLen(len(buf))
	b.names[i].Family = unix.AF_INET
	b.names[i].Addr = addr
	b.names[i].Port = 0 // ICMP has no ports; the kernel ignores this field
	b.hdrs[i].hdr.Namelen = uint32(unsafe.Sizeof(b.names[i]))
	b.hdrs[i].hdr.Flags = 0
	b.hdrs[i].len = 0
}

// setRecv points message i at buf as receive space.
func (b *mmsgBatch) setRecv(i int, buf []byte) {
	b.iovs[i].Base = &buf[0]
	b.iovs[i].SetLen(len(buf))
	b.hdrs[i].hdr.Namelen = uint32(unsafe.Sizeof(b.names[i]))
	b.hdrs[i].hdr.Flags = 0
	b.hdrs[i].len = 0
}

// sendmmsg transmits the first n prepared messages. It returns how many the kernel
// accepted, which can be fewer than n — the caller must resend the remainder, exactly as
// with a short write.
func (b *mmsgBatch) sendmmsg(fd, n int) (int, error) {
	if !mmsgOK || n <= 0 {
		return 0, unix.ENOSYS
	}
	r, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&b.hdrs[0])), uintptr(n), 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// recvmmsg blocks until at least one message has arrived (MSG_WAITFORONE) and returns how
// many were filled in. Waiting for one rather than for the whole array is what keeps this
// from adding latency on a quiet link: the batching only happens when there is already a
// queue to batch.
func (b *mmsgBatch) recvmmsg(fd, n int) (int, error) {
	if !mmsgOK || n <= 0 {
		return 0, unix.ENOSYS
	}
	r, _, errno := unix.Syscall6(unix.SYS_RECVMMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&b.hdrs[0])), uintptr(n), unix.MSG_WAITFORONE, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

// msgLen is the byte count the kernel wrote into message i.
func (b *mmsgBatch) msgLen(i int) int { return int(b.hdrs[i].len) }

// msgAddr is the source address of received message i.
func (b *mmsgBatch) msgAddr(i int) [4]byte { return b.names[i].Addr }

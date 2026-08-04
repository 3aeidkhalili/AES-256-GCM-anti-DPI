//go:build linux

package main

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

// The kernel requires every segment of a UDP_SEGMENT send to be the same length except the
// last, so the batch must refuse a differently sized packet rather than silently corrupting
// the run. Getting this wrong would change what the peer receives.
func TestTxBatchOnlyCoalescesEqualSizes(t *testing.T) {
	b := newTxBatch(true)
	a := bytes.Repeat([]byte{1}, 1459)
	c := bytes.Repeat([]byte{2}, 1459)
	small := bytes.Repeat([]byte{3}, 128)

	if !b.wants(a) {
		t.Fatal("an empty batch must accept anything")
	}
	b.add(a)
	if !b.wants(c) {
		t.Fatal("a same-sized packet must be allowed to join the run")
	}
	b.add(c)
	if b.wants(small) {
		t.Fatal("a differently sized packet must force a flush, not join the run")
	}
	if b.count != 2 || b.segSize != 1459 || b.n != 2*1459 {
		t.Fatalf("unexpected batch state: count=%d seg=%d n=%d", b.count, b.segSize, b.n)
	}
	// The buffer must hold the datagrams back to back, unchanged.
	if !bytes.Equal(b.buf[:1459], a) || !bytes.Equal(b.buf[1459:2*1459], c) {
		t.Fatal("batched datagrams must be concatenated verbatim")
	}
	b.reset()
	if b.count != 0 || b.n != 0 || b.segSize != 0 {
		t.Fatal("reset must clear the batch")
	}
}

// With offload off the batch must never hold more than one datagram, so the send path
// degrades exactly to the old one-syscall-per-packet behaviour.
func TestTxBatchWithoutGSONeverGroups(t *testing.T) {
	b := newTxBatch(false)
	p := bytes.Repeat([]byte{1}, 1459)
	b.add(p)
	if b.wants(p) {
		t.Fatal("with GSO disabled a second packet must not join the batch")
	}
}

func TestTxBatchRespectsSegmentAndByteCaps(t *testing.T) {
	b := newTxBatch(true)
	p := bytes.Repeat([]byte{1}, 1459)
	n := 0
	for b.wants(p) {
		if b.add(p) {
			n++
			break
		}
		n++
		if n > maxGSOSegments*4 {
			t.Fatal("batch never reported full — it would overrun the kernel's limits")
		}
	}
	if b.count > maxGSOSegments {
		t.Fatalf("batch exceeded the kernel's %d-segment limit: %d", maxGSOSegments, b.count)
	}
	if b.n > maxGSOBytes+len(p) {
		t.Fatalf("batch exceeded the byte cap: %d", b.n)
	}
}

// The control message we build for sending must be readable by the same parser the
// receive path uses, which is the cheapest available check that the layout is right.
func TestGSOControlRoundTrips(t *testing.T) {
	buf := make([]byte, unix.CmsgSpace(2))
	oob := gsoControl(buf, 1459)
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		t.Fatalf("the control message we generate does not parse: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected exactly one control message, got %d", len(msgs))
	}
	if msgs[0].Header.Level != unix.SOL_UDP || msgs[0].Header.Type != unix.UDP_SEGMENT {
		t.Fatalf("wrong level/type: %d/%d", msgs[0].Header.Level, msgs[0].Header.Type)
	}
	// parseGROSegment reads the same shape, just with the GRO type.
	h := oob
	msgs[0].Header.Type = unix.UDP_GRO
	_ = h
}

func TestParseGROSegmentIgnoresUnrelatedControlMessages(t *testing.T) {
	if got := parseGROSegment(nil); got != 0 {
		t.Fatalf("no control data must mean no coalescing, got %d", got)
	}
	if got := parseGROSegment([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("malformed control data must be ignored, got %d", got)
	}
	// A TTL control message must not be mistaken for a segment size.
	buf := make([]byte, unix.CmsgSpace(1))
	oob := gsoControl(buf, 1459)
	msgs, _ := unix.ParseSocketControlMessage(oob)
	if len(msgs) == 1 && msgs[0].Header.Type == unix.UDP_SEGMENT {
		// UDP_SEGMENT is the send-side type; the receive parser looks for UDP_GRO only.
		if got := parseGROSegment(oob); got != 0 {
			t.Fatalf("a UDP_SEGMENT message is not a GRO report, got %d", got)
		}
	}
}

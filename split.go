//go:build linux

// Packet splitting — done where it is safe to do, which for an opaque encrypted carrier is
// not where the intuition points.
//
// zapret's most effective tricks against websites are `multisplit`/`fakeddisorder`: cut the
// plaintext TLS ClientHello across TCP segments so a stateful DPI cannot reassemble the SNI.
// That works because the DPI can see the plaintext it wants to match on. Here it cannot: the
// carrier payload is AEAD ciphertext, uniform random from the first byte, and the obfs layer
// already shapes datagram sizes. Splitting a *real* carrier datagram would mean inventing a
// reassembly protocol, changing the wire format, and adding head-of-line risk — all to
// scramble bytes a DPI already cannot read. That is cost with no matching benefit, so this
// module deliberately does not touch real traffic.
//
// What it does instead is the one split that is both safe and useful: it fragments the
// disposable desync fakes at the IP layer, the way zapret's `ipfrag2` does. The fakes are
// throwaway by construction (they die before the peer, and the peer discards any that arrive),
// so fragmenting them cannot cost a retransmission or stall a user. The payoff is on the DPI:
// a box that does not reassemble IP fragments sees only a truncated first fragment of the
// cover handshake — an even poorer thing to classify on — while a box that does reassemble
// sees the same legitimate QUIC Initial as before. Either way the real flow is untouched.
//
// IPv4 only, matching the injector. Off by default; only meaningful when desync is enabled.
package main

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// SplitConfig (struct + defaults) lives in tunnel.go next to Config.

// fragmentIPv4 splits a complete IPv4 datagram into two IP fragments at fragPos bytes into the
// IP payload (the transport header + data). fragPos must be a positive multiple of 8 strictly
// inside the payload. Returns ok=false when the packet cannot be split that way, so the caller
// falls back to sending it whole.
func fragmentIPv4(pkt []byte, fragPos int) (frag1, frag2 []byte, ok bool) {
	if len(pkt) < 20 {
		return nil, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return nil, nil, false
	}
	payloadLen := len(pkt) - ihl
	if fragPos <= 0 || fragPos%8 != 0 || fragPos >= payloadLen {
		return nil, nil, false
	}
	ipPayload := pkt[ihl:]

	mk := func(part []byte, offsetUnits int, moreFragments bool) []byte {
		out := make([]byte, ihl+len(part))
		copy(out, pkt[:ihl]) // inherit id, ttl, proto, addresses
		binary.BigEndian.PutUint16(out[2:4], uint16(ihl+len(part)))
		// Flags/fragment-offset field: clear DF, set MF as needed, put the 13-bit offset.
		frag := uint16(offsetUnits) & 0x1fff
		if moreFragments {
			frag |= 0x2000 // MF
		}
		binary.BigEndian.PutUint16(out[6:8], frag)
		out[10], out[11] = 0, 0 // zero the checksum before recomputing
		binary.BigEndian.PutUint16(out[10:12], inetChecksum(out[:ihl]))
		copy(out[ihl:], part)
		return out
	}

	frag1 = mk(ipPayload[:fragPos], 0, true)          // offset 0, more fragments follow
	frag2 = mk(ipPayload[fragPos:], fragPos/8, false) // offset fragPos/8, last fragment
	return frag1, frag2, true
}

// sendRawFake sends one built raw datagram, fragmenting it first when split is enabled and the
// packet is large enough to split usefully. A fragmentation that cannot be done cleanly falls
// back to a whole send, so enabling split never silently drops a fake.
func (a *desyncAgent) sendRawFake(raw []byte, sa *unix.SockaddrInet4) error {
	if a.splitOn {
		if f1, f2, ok := fragmentIPv4(raw, a.splitPos); ok {
			if err := unix.Sendto(a.fd, f1, 0, sa); err != nil {
				return err
			}
			return unix.Sendto(a.fd, f2, 0, sa)
		}
	}
	return unix.Sendto(a.fd, raw, 0, sa)
}

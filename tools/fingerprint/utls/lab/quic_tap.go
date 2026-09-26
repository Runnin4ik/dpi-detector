// The QUIC half of the stand: a UDP tap on the port the probe dials, relaying to
// a real host and printing every datagram in both directions.
//
//	lab --quic-tap-port 443 --quic-upstream discord.com:443
//
// The QUIC probe resolves its target and dials a fixed 443, so a stand that wants
// to see the Initial has to own that port - and unlike the TCP tap there is no
// local server to fall back on: a QUIC endpoint needs the handshake the probe
// never finishes, so the tap always relays to `--quic-upstream`.
//
// What this answers is the question a remote server cannot: the probe reports
// silence (`QUIC DROP`) while a stock client gets an HTTP/3 answer from the same
// address. Either the endpoint sent nothing, or it answered and the probe did not
// read it - and the difference decides whether the fault is in the ClientHello or
// in the receive path. Every datagram is therefore logged with its size, its
// direction and its readable header: a long header names the version and the
// packet type, a short header on the reply side where the client has no keys yet
// is a stateless reset, and a version 0 packet is version negotiation.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
)

// quicTap relays one client's datagrams to the upstream and back. The probe
// sends a flight and waits, so the first datagram from a new client address
// opens a connected socket that stays open for the replies.
type quicTap struct {
	upstream string
	mu       sync.Mutex
	clients  map[string]*net.UDPConn
}

func newQuicTap(upstream string) *quicTap {
	return &quicTap{upstream: upstream, clients: map[string]*net.UDPConn{}}
}

func (t *quicTap) socketFor(client net.Addr) (*net.UDPConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if conn, ok := t.clients[client.String()]; ok {
		return conn, nil
	}
	raddr, err := net.ResolveUDPAddr("udp", t.upstream)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	t.clients[client.String()] = conn
	return conn, nil
}

// runQuicTap listens on the tap port until the process is killed. A read error
// on one client's socket is logged and the socket dropped, so a probe that goes
// away does not stop the tap.
func runQuicTap(tapPort int, upstream string) {
	ln, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", tapPort))
	if err != nil {
		fatal(fmt.Errorf("quic tap listener: %w", err))
	}
	tap := newQuicTap(upstream)
	logf("[lab]", "quic tap listening %s -> %s (udp, IPv4)", ln.LocalAddr(), upstream)

	buf := make([]byte, 65535)
	for {
		n, from, err := ln.ReadFrom(buf)
		if err != nil {
			logf("[tap]", "read: %v", err)
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		logf("[tap]", "-> %d bytes to %s   %s", n, upstream, describeQuic(payload, false))
		up, err := tap.socketFor(from)
		if err != nil {
			logf("[tap]", "upstream socket: %v", err)
			continue
		}
		if _, err := up.Write(payload); err != nil {
			logf("[tap]", "forward: %v", err)
			continue
		}
		go func(up *net.UDPConn, client net.Addr) {
			reply := make([]byte, 65535)
			for {
				rn, err := up.Read(reply)
				if err != nil {
					return
				}
				logf("[tap]", "<- %d bytes from %s   %s", rn, upstream, describeQuic(reply[:rn], true))
				if _, err := ln.WriteTo(reply[:rn], client); err != nil {
					logf("[tap]", "send back: %v", err)
					return
				}
			}
		}(up, from)
	}
}

// describeQuic reads the fields that are in the clear: the header form, the
// version, the connection ID lengths, and the first bytes, which are what tells
// a stateless reset from a packet the probe could have decrypted.
func describeQuic(packet []byte, reply bool) string {
	if len(packet) == 0 {
		return "empty datagram"
	}
	head := packet[0]
	kind := "short header (1-RTT, or a stateless reset)"
	version := ""
	ids := ""
	if head&0x80 != 0 {
		if len(packet) < 7 {
			return fmt.Sprintf("truncated long header (%d bytes) %s", len(packet), hexHead(packet))
		}
		ver := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
		version = fmt.Sprintf(" version=0x%08x", ver)
		switch {
		case ver == 0:
			kind = "long header, VERSION NEGOTIATION"
		case head&0x30 == 0x00:
			kind = "long header, Initial"
		case head&0x30 == 0x10:
			kind = "long header, 0-RTT"
		case head&0x30 == 0x20:
			kind = "long header, Handshake"
		case head&0x30 == 0x30:
			kind = "long header, RETRY"
		}
		dcidLen := int(packet[5])
		if 6+dcidLen+1 <= len(packet) {
			scidLen := int(packet[6+dcidLen])
			ids = fmt.Sprintf(" dcid=%d scid=%d", dcidLen, scidLen)
		}
	} else if reply {
		kind = "short header: 1-RTT (we hold no keys) or a stateless reset"
	}
	return strings.TrimSpace(fmt.Sprintf("%s%s%s  first bytes %s", kind, version, ids, hexHead(packet)))
}

func hexHead(packet []byte) string {
	n := len(packet)
	if n > 24 {
		n = 24
	}
	return hex.EncodeToString(packet[:n])
}

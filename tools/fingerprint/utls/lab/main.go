// Command lab is the offline stand for the burst split: a TLS + HTTP/2 server
// the shaped client can be pointed at, and a TCP tap on the port the burst dials
// that prints what crossed it.
//
//	lab [--port 8443] [--tap-port 443] [--keylog keys.log] [--upstream host:port]
//	lab --quic-tap-port 443 --quic-upstream host:port
//
// The burst resolves its target itself and dials a fixed 443, so a stand that
// wants to see the handshake has to own that port: the tap accepts there, relays
// to the server on 8443, and logs every TLS record in both directions — the
// five-byte header, and the body in hex for as long as it is readable, which is
// the ClientHello and nothing after the server's first encrypted flight. What
// the remote servers cannot show is exactly this: whether a record the client
// dislikes arrives before its own Finished, whether a record is split across TCP
// segments, and whether a request was ever sent at all.
//
// The split this exists to explain: profiles whose ClientHello carries ALPS are
// refused by strict HTTP/2 servers while the same bytes from a bundled curl are
// accepted, and the echo services that compare the hellos see no difference. The
// stand removes the remote server from the question — if a shape is rejected
// here, Go's own handshake error names the reason; if it is not, the tap still
// has the record sequence for both profiles side by side.
//
// `--upstream` puts the real host back: the tap relays there instead of to the
// local server, so a client pointed at the tap (curl's
// `--connect-to host:443:127.0.0.1:443`, the example's `--connect-to`) is
// answered by that host while still sending the name it meant to. What that adds
// is the remote answer's own record layer — whether a refusal is an alert where
// the ServerHello would have been, or an alert that lands after the client's
// first flight, which is the difference between a decision made on the
// ClientHello and one made on what the client sent after it.
//
// Everything is stdlib: `net/http` serves HTTP/2 over TLS as soon as the config
// offers `h2`, and the certificate is drawn in-process, so there is no key
// material and no dependency to install. Both streams go to stdout, tagged
// `[tap]` and `[server]`, so one grep separates the wire from the server.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The record types a TLS record header can name. Only the first three can be
// read: an `application_data` record is ciphertext by definition, which is why
// the tap stops printing bodies once one arrives.
const (
	recordChangeCipherSpec = 20
	recordAlert            = 21
	recordHandshake        = 22
	recordApplicationData  = 23
)

// out serializes the two streams. The tap logs from two goroutines per
// connection and the server logs from its own, and a record's header line and
// its hex rows must not be interleaved with another record's — the sequence is
// the evidence, so it is written whole.
var out struct {
	mu sync.Mutex
	w  io.Writer
}

// logf writes one tagged event line. Every line the stand prints goes through
// here, so the two streams stay separable and a record cannot be split by
// another goroutine's output.
func logf(tag, format string, args ...any) {
	out.mu.Lock()
	defer out.mu.Unlock()
	fmt.Fprintf(out.w, "%s %s\n", tag, fmt.Sprintf(format, args...))
}

// logLines writes a group of lines under one lock. A record's header and its
// body rows are one event: the record sequence is what this stand is read for,
// and a second direction logging the header of its own record in the middle of
// that block would break the run of it.
func logLines(tag string, lines []string) {
	out.mu.Lock()
	defer out.mu.Unlock()
	for _, line := range lines {
		fmt.Fprintf(out.w, "%s %s\n", tag, line)
	}
}

// serverLog is the writer http.Server's own logger needs: the stdlib reports a
// refused handshake there and nowhere else, and that message names the cause
// ("remote error: tls: ...", "client sent an HTTP request to an HTTPS server"),
// which is half of what this stand is for. It is wrapped rather than handed
// stdout directly so its lines carry the `[server]` tag and take the same lock.
type serverLog struct{}

func (serverLog) Write(p []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	fmt.Fprintf(out.w, "[server] %s\n", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func main() {
	fs := flag.NewFlagSet("lab", flag.ExitOnError)
	keylogPath := fs.String("keylog", "keys.log",
		"append the NSS key log of every handshake to this file (CLIENT_RANDOM on TLS 1.2, the traffic secrets on TLS 1.3)")
	port := fs.Int("port", 8443, "port the TLS + HTTP/2 server listens on (loopback only)")
	tapPort := fs.Int("tap-port", 443, "port the tap listens on and relays to the server")
	upstream := fs.String("upstream", "",
		"relay to this host:port instead of the local server (e.g. www.google.com:443); the local server is then not started")
	quicTapPort := fs.Int("quic-tap-port", 0,
		"port the UDP (QUIC) tap listens on, relaying to --quic-upstream; 0 = no QUIC tap")
	quicUpstream := fs.String("quic-upstream", "",
		"the QUIC tap relays to this host:port (e.g. discord.com:443); required with --quic-tap-port")
	fs.Usage = usage
	if err := fs.Parse(os.Args[1:]); err != nil {
		return
	}
	if fs.NArg() != 0 {
		usage()
		os.Exit(2)
	}
	out.w = os.Stdout

	// The QUIC tap is a mode of its own: it has no local server (a QUIC endpoint
	// would need a handshake the probe never finishes), it takes a UDP port, and
	// it neither needs nor starts the TCP tap below.
	if *quicTapPort != 0 {
		if *quicUpstream == "" {
			fatal(fmt.Errorf("--quic-tap-port needs --quic-upstream host:port"))
		}
		runQuicTap(*quicTapPort, *quicUpstream)
		return
	}

	// The local server is the default: the tap relays to it and the stand is
	// self-contained. `--upstream` makes the stand a pure tap in front of a real
	// host — the client's own bytes and SNI, the real server's answer — and then
	// a local server would only be a listener nothing can reach.
	if *upstream == "" {
		serveLocal(*port, *keylogPath)
	} else {
		logf("[lab]", "upstream override: relaying to %s, no local server", *upstream)
	}

	var conns atomic.Int64
	for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", *tapPort), fmt.Sprintf("[::1]:%d", *tapPort)} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			fatal(fmt.Errorf("tap listener %s: %w", addr, err))
		}
		target := *upstream
		if target == "" {
			target = upstreamFor(ln.Addr(), *port)
		}
		logf("[lab]", "tap listening %s -> %s", ln.Addr(), target)
		go acceptLoop(ln, target, &conns)
	}

	select {}
}

// keylogOut keeps the key log open for the life of the process. A local variable
// would not do: `serveLocal` returns as soon as its listeners are up, so a
// deferred Close would shut the file under a running server — and an *os.File
// that goes unreachable is closed by its finalizer just as silently. Either way
// every handshake after the first fails with "KeyLogWriter: ... file already
// closed", which is a TLS failure the stand would then be blamed for.
var keylogOut *os.File

// serveLocal starts the stand's own TLS + HTTP/2 server on the loopback, both
// families, with a certificate drawn here and the key log the tap's connections
// are read back with.
func serveLocal(port int, keylogPath string) {
	cert, err := selfSigned()
	if err != nil {
		fatal(err)
	}
	// The key log is opened for append so a second run does not hide the first
	// handshake: Wireshark reads the whole file, and a lab stand gets restarted
	// far more often than it gets cleaned up.
	keylog, err := os.OpenFile(keylogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fatal(fmt.Errorf("keylog: %w", err))
	}
	keylogOut = keylog
	logf("[lab]", "keylog %s (append)", keylogPath)

	// The connection census: StateNew records that the tap's relay reached the
	// server, the handler counts the requests it carried, and StateClosed
	// reports both. A profile that is refused gets `requests=0` there, which is
	// the discriminator between a rejection at TLS and a rejection at HTTP.
	var census struct {
		mu     sync.Mutex
		byAddr map[string]int
	}
	census.byAddr = map[string]int{}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// ALPN is what makes net/http serve HTTP/2: with "h2" listed here, the
		// stdlib's bundled implementation is wired up at ServeTLS time, no
		// x/net/http2 and no h2c.
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
		KeyLogWriter: keylog,
		// The ClientHello is logged from a hook because it is the only place the
		// server can see the extension list; nothing is changed, so the
		// connection is handled by the config that was set up for HTTP/2.
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			logClientHello(chi)
			return nil, nil
		},
	}

	srv := &http.Server{
		TLSConfig: tlsCfg,
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serve(w, r, &census) }),
		// A client that goes quiet must not hold a connection forever; the burst
		// itself is done in seconds.
		ReadHeaderTimeout: 20 * time.Second,
		ErrorLog:          log.New(serverLog{}, "", 0),
		ConnState: func(c net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				census.mu.Lock()
				census.byAddr[c.RemoteAddr().String()] = 0
				census.mu.Unlock()
				logf("[server]", "conn new remote=%s", c.RemoteAddr())
			case http.StateClosed, http.StateHijacked:
				census.mu.Lock()
				requests := census.byAddr[c.RemoteAddr().String()]
				delete(census.byAddr, c.RemoteAddr().String())
				census.mu.Unlock()
				if requests == 0 {
					logf("[server]", "conn closed remote=%s requests=0 "+
						"(no request was ever handled here: the connection ended before HTTP/2 saw one)", c.RemoteAddr())
					return
				}
				logf("[server]", "conn closed remote=%s requests=%d", c.RemoteAddr(), requests)
			}
		},
	}

	for _, addr := range []string{fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("[::1]:%d", port)} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// One family is enough to serve; a host without IPv6 loopback
			// should not stop the stand.
			logf("[lab]", "server listener %s: %v", addr, err)
			continue
		}
		logf("[lab]", "server listening %s (tls+http2, cert self-signed for localhost)", ln.Addr())
		go func(ln net.Listener) {
			err := srv.ServeTLS(ln, "", "")
			logf("[lab]", "server on %s stopped: %v", ln.Addr(), err)
		}(ln)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lab is the offline stand for the burst split: a TLS + HTTP/2 server the client
can be pointed at, and a tap on the port the burst dials that prints what crossed
it.

	lab [--port 8443] [--tap-port 443] [--keylog keys.log] [--upstream host:port]

The server draws its own ECDSA P-256 certificate for localhost in-process and
serves HTTP/2 over TLS, so "dpi-detector -d localhost --burst ..." reaches an
answer with no network in the way. The tap listens where the burst dials and
relays to the server, printing one line per TLS record in each direction: the
direction, the five-byte header as type/version/length, a running index, the
bytes and the reads it took, and the body in hex for as long as it is readable.

--upstream replaces the local server with a real host: the tap then relays there,
so a client that dials the tap is answered by that host while still sending the
name it meant to (curl: --connect-to host:443:127.0.0.1:443). The client's own
bytes, the real server's answer, and the record layer between them — the one
comparison a stand with its own server cannot make.

Both streams share stdout, tagged:
  [tap]     the wire, both directions
  [server]  the ClientHello of each connection, each request with its headers and
            its ALPN/TLS/cipher, and the stdlib's handshake errors verbatim

A refused profile ends with a [server] line naming the reason and a request
census of zero; if no such line appears, the stand is more tolerant than the
remote server and that is the finding.

The QUIC probe dials UDP 443 and never finishes the handshake, so it gets a tap
of its own rather than the server above:

	lab --quic-tap-port 443 --quic-upstream discord.com:443

That tap relays every datagram to the named host and back, printing its size,
its direction and the fields that are in the clear: the header form, the version,
the connection ID lengths, and the first bytes. A reply line is what settles the
question the remote server cannot - a QUIC DROP next to a stock client's HTTP/3
answer means either the endpoint sent nothing or the probe did not read what it
sent, and a short-header reply, a Retry, a version-negotiation packet or silence
are told apart here. It listens on 127.0.0.1 (IPv4) and always relays: there is
no local QUIC server, because an endpoint would need the handshake the probe
deliberately stops short of.
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "lab: %v\n", err)
	os.Exit(1)
}

// selfSigned builds the certificate the server offers. ECDSA P-256 because it
// is what the profiles under test negotiate, and a certificate is only needed
// because the client insists on a handshake: the verifier under test accepts
// anything, so the SAN only has to be honest about the name.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// logClientHello records what the server saw in the hello. The extension list is
// the interesting part — it is where ALPS sits — but it is logged as a whole so
// a shape that differs in some other way is not missed.
func logClientHello(chi *tls.ClientHelloInfo) {
	remote := "unknown"
	if chi.Conn != nil {
		remote = chi.Conn.RemoteAddr().String()
	}
	logf("[server]", "clienthello remote=%s sni=%q alpn=%v versions=%v curves=%d ciphers=%d ext=%v notable=%s",
		remote, chi.ServerName, chi.SupportedProtos, versionNames(chi.SupportedVersions),
		len(chi.SupportedCurves), len(chi.CipherSuites), chi.Extensions, notableExtensions(chi.Extensions))
}

// serve logs the request before answering it. Every field asked of a request is
// on `r` or on `r.TLS`, and a request that reaches here is one that got past the
// handshake and HTTP/2 — which is why the census line at connection close is
// read together with this one.
func serve(w http.ResponseWriter, r *http.Request, census *struct {
	mu     sync.Mutex
	byAddr map[string]int
}) {
	census.mu.Lock()
	census.byAddr[r.RemoteAddr]++
	n := census.byAddr[r.RemoteAddr]
	census.mu.Unlock()

	logf("[server]", "request #%d remote=%s method=%s path=%q proto=%s alpn=%q tls=%s cipher=%s host=%q",
		n, r.RemoteAddr, r.Method, r.URL.RequestURI(), r.Proto, negotiatedALPN(r), tlsVersionName(r),
		negotiatedCipher(r), r.Host)
	// Sorted by the stdlib's own order is not stable across goroutines; the
	// header list is what the client sent, so it is printed as received.
	for name, values := range r.Header {
		for _, value := range values {
			logf("[server]", "request #%d header %s: %s", n, name, value)
		}
	}
	body := "lab-stand\n"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
	logf("[server]", "request #%d answered 200 %d bytes", n, len(body))
}

func negotiatedALPN(r *http.Request) string {
	if r.TLS == nil {
		return ""
	}
	return r.TLS.NegotiatedProtocol
}

func tlsVersionName(r *http.Request) string {
	if r.TLS == nil {
		return "plaintext"
	}
	switch r.TLS.Version {
	case tls.VersionTLS13:
		return "tls1.3"
	case tls.VersionTLS12:
		return "tls1.2"
	default:
		return fmt.Sprintf("0x%04x", r.TLS.Version)
	}
}

func negotiatedCipher(r *http.Request) string {
	if r.TLS == nil {
		return ""
	}
	return tls.CipherSuiteName(r.TLS.CipherSuite)
}

func versionNames(versions []uint16) []string {
	names := make([]string, 0, len(versions))
	for _, v := range versions {
		switch v {
		case tls.VersionTLS13:
			names = append(names, "1.3")
		case tls.VersionTLS12:
			names = append(names, "1.2")
		case tls.VersionTLS11:
			names = append(names, "1.1")
		case tls.VersionTLS10:
			names = append(names, "1.0")
		default:
			names = append(names, fmt.Sprintf("0x%04x", v))
		}
	}
	return names
}

// notableExtensions names the few extensions a shape is known by, so a grep for
// `alps` finds the hello that carries it without reading a list of decimals.
func notableExtensions(exts []uint16) string {
	names := map[uint16]string{
		0:     "server_name",
		16:    "alpn",
		18:    "sct",
		21:    "padding",
		41:    "pre_shared_key",
		42:    "early_data",
		43:    "supported_versions",
		44:    "cookie",
		45:    "psk_key_exchange_modes",
		51:    "key_share",
		17513: "application_settings",
		30032: "channel_id",
		65281: "renegotiation_info",
	}
	var found []string
	for _, ext := range exts {
		if name, ok := names[ext]; ok {
			found = append(found, fmt.Sprintf("%s(%d)", name, ext))
		}
	}
	if len(found) == 0 {
		return "none"
	}
	return strings.Join(found, ",")
}

// upstreamFor picks the server listener of the same family as the tap listener,
// so an IPv6 client is relayed over IPv6 loopback and a connection's family
// stays visible in the logs on both sides.
func upstreamFor(tapAddr net.Addr, port int) string {
	if host, _, err := net.SplitHostPort(tapAddr.String()); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.To4() == nil {
			return fmt.Sprintf("[::1]:%d", port)
		}
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func acceptLoop(ln net.Listener, upstream string, conns *atomic.Int64) {
	for {
		client, err := ln.Accept()
		if err != nil {
			logf("[tap]", "accept on %s: %v", ln.Addr(), err)
			return
		}
		go tap(conns.Add(1), client, upstream)
	}
}

// tap relays one connection and logs both directions. The two pumps are
// independent: a client that stops writing after its ClientHello still gets the
// server's flight logged, which is the case a rejection looks like.
func tap(id int64, client net.Conn, upstream string) {
	server, err := net.Dial("tcp", upstream)
	if err != nil {
		logf("[tap]", "conn %d dial %s: %v", id, upstream, err)
		client.Close()
		return
	}
	start := time.Now()
	logf("[tap]", "conn %d open %s -> %s relaying to %s", id, client.RemoteAddr(), client.LocalAddr(), upstream)
	toServer := &direction{connID: id, dir: "c->s", start: start}
	toClient := &direction{connID: id, dir: "s->c", start: start}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(toServer, client, server) }()
	go func() { defer wg.Done(); pump(toClient, server, client) }()
	wg.Wait()
	client.Close()
	server.Close()
	logf("[tap]", "conn %d closed bytes c->s=%d s->c=%d", id, toServer.total, toClient.total)
}

// pump copies one direction and hands every chunk to the record parser after it
// has been forwarded: the client under test must not be made to wait for a log
// line, and the copy is a plain read-then-write so the timing the stand shows is
// the timing the server produced.
func pump(d *direction, src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			d.total += int64(n)
			if _, werr := dst.Write(buf[:n]); werr != nil {
				logf("[tap]", "conn %d %s write failed after %d bytes: %v", d.connID, d.dir, d.total, werr)
				break
			}
			d.feed(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				logf("[tap]", "conn %d %s eof after %d bytes", d.connID, d.dir, d.total)
			} else {
				logf("[tap]", "conn %d %s read failed after %d bytes: %v", d.connID, d.dir, d.total, err)
			}
			break
		}
	}
	d.flush()
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	} else {
		dst.Close()
	}
}

// direction is one side of one tapped connection: a running record index, the
// bytes of the record being assembled, and the count of reads that have gone
// into it. `reads` is what makes a record split across TCP segments visible —
// one record, two reads, and the split is in the log rather than inferred.
type direction struct {
	connID int64
	dir    string
	start  time.Time
	index  int
	buf    []byte
	reads  int
	chunks int
	total  int64
	// encrypted is set by the first change_cipher_spec or application_data this
	// direction carries; see emit for why the content type cannot say it.
	encrypted bool
}

func (d *direction) feed(chunk []byte) {
	d.chunks++
	logf("[tap]", "conn %d %s chunk %d bytes=%d total=%d", d.connID, d.dir, d.chunks, len(chunk), d.total)
	d.reads++
	d.buf = append(d.buf, chunk...)
	for {
		if len(d.buf) < 5 {
			return
		}
		length := int(d.buf[3])<<8 | int(d.buf[4])
		if len(d.buf) < 5+length {
			return
		}
		d.emit(d.buf[:5+length], d.reads)
		// The remainder is copied down rather than resliced: the buffer is
		// long-lived and a moving base would grow it without bound.
		rest := len(d.buf) - (5 + length)
		if rest == 0 {
			d.buf = d.buf[:0]
			d.reads = 0
			continue
		}
		d.buf = append(d.buf[:0], d.buf[5+length:]...)
		// This same read delivered the start of the next record.
		d.reads = 1
	}
}

// emit prints one record. The body is printed in hex, and a handshake record's
// message list or an alert's code decoded, only while the body is still
// readable — and the content type is not enough to tell. TLS 1.3 seals every
// record as `application_data`, but TLS 1.2 keeps the handshake and alert
// content types on records that are already ciphertext, so a direction is taken
// to be encrypted from the first `change_cipher_spec` or `application_data` it
// carries: after that, a handshake-typed record is a sealed Finished and an
// alert-typed one is a sealed alert, and decoding either would print the
// server's objection as a nonsense message list.
func (d *direction) emit(record []byte, reads int) {
	d.index++
	length := int(record[3])<<8 | int(record[4])
	body := record[5:]
	elapsed := time.Since(d.start).Seconds() * 1000
	sealed := d.encrypted
	switch record[0] {
	case recordChangeCipherSpec, recordApplicationData:
		d.encrypted = true
	}
	readable := !sealed && record[0] != recordApplicationData
	note := ""
	if !readable {
		note = " encrypted"
	} else {
		switch record[0] {
		case recordHandshake:
			note = " msgs=" + handshakeMessages(body)
		case recordAlert:
			note = " alert=" + alertNames(body)
		}
	}
	lines := []string{fmt.Sprintf("conn %d %s record %d type=%s(%d) version=0x%02x%02x length=%d bytes=%d reads=%d t=+%.3fms%s",
		d.connID, d.dir, d.index, recordTypeName(record[0]), record[0], record[1], record[2],
		length, len(record), reads, elapsed, note)}
	if readable {
		const perRow = 32
		for off := 0; off < len(body); off += perRow {
			end := min(off+perRow, len(body))
			lines = append(lines, fmt.Sprintf("conn %d %s record %d body+%04x %s", d.connID, d.dir, d.index, off,
				hex.EncodeToString(body[off:end])))
		}
	}
	logLines("[tap]", lines)
}

// flush reports a record left half-read at EOF. A truncated record is a client
// (or server) that stopped mid-write, and it is the one case where the bytes on
// the wire explain a rejection that nothing else in the log does.
func (d *direction) flush() {
	if len(d.buf) == 0 {
		return
	}
	logf("[tap]", "conn %d %s PARTIAL record at end of stream: %d bytes pending reads=%d hex=%s",
		d.connID, d.dir, len(d.buf), d.reads, hex.EncodeToString(d.buf))
}

func recordTypeName(t byte) string {
	switch t {
	case recordChangeCipherSpec:
		return "change_cipher_spec"
	case recordAlert:
		return "alert"
	case recordHandshake:
		return "handshake"
	case recordApplicationData:
		return "application_data"
	default:
		return "unknown"
	}
}

// handshakeMessages lists the handshake messages in a plaintext record. The
// list is a convenience over the hex — a TLS 1.2 server flight is ServerHello,
// Certificate, ServerKeyExchange, ServerHelloDone, and a HelloRetryRequest is a
// lone ServerHello, which reads very differently here.
func handshakeMessages(body []byte) string {
	names := map[byte]string{
		0:   "hello_request",
		1:   "client_hello",
		2:   "server_hello",
		4:   "new_session_ticket",
		8:   "encrypted_extensions",
		11:  "certificate",
		12:  "server_key_exchange",
		13:  "certificate_request",
		14:  "server_hello_done",
		15:  "certificate_verify",
		16:  "client_key_exchange",
		20:  "finished",
		24:  "key_update",
		254: "message_hash",
	}
	var found []string
	for off := 0; off+4 <= len(body); {
		kind := body[off]
		size := int(body[off+1])<<16 | int(body[off+2])<<8 | int(body[off+3])
		name, ok := names[kind]
		if !ok {
			name = fmt.Sprintf("type_%d", kind)
		}
		found = append(found, fmt.Sprintf("%s(%d) len=%d", name, kind, size))
		// A record may hold part of a message, in which case the declared
		// length runs past the body and the listing stops where it can.
		if off+4+size > len(body) {
			found = append(found, "…truncated in this record")
			break
		}
		off += 4 + size
	}
	if len(found) == 0 {
		return "none"
	}
	return "[" + strings.Join(found, " ") + "]"
}

// alertNames decodes a plaintext alert. It is two bytes — level and description
// — and the description is the server's own name for its objection, which is
// what a `tls_alert` outcome in the harness reduces to a code otherwise.
func alertNames(body []byte) string {
	if len(body) < 2 {
		return fmt.Sprintf("short(%d bytes)", len(body))
	}
	levels := map[byte]string{1: "warning", 2: "fatal"}
	descriptions := map[byte]string{
		0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
		22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
		43: "unsupported_certificate", 46: "certificate_unknown", 47: "illegal_parameter",
		48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
		70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
		86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension",
		110: "unsupported_extension", 112: "unrecognized_name", 120: "no_application_protocol",
	}
	level, ok := levels[body[0]]
	if !ok {
		level = fmt.Sprintf("level_%d", body[0])
	}
	description, ok := descriptions[body[1]]
	if !ok {
		description = fmt.Sprintf("description_%d", body[1])
	}
	return fmt.Sprintf("%s(%d)/%s(%d)", level, body[0], description, body[1])
}

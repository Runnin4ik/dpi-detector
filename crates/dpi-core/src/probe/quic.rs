//! Test 2's QUIC column: one padded Initial per domain, and what answers it.
//!
//! The column asks the same host the TLS columns ask, on UDP 443, with one
//! 1200-byte Initial whose `CRYPTO` frame carries a browser-shaped ClientHello:
//! TLS 1.3 only, `h3` in ALPN, and the `quic_transport_parameters` extension
//! every endpoint requires (RFC 9000 §7.3) — without it a server answers
//! `TRANSPORT_PARAMETER_ERROR` and never starts the handshake. The shape is the
//! run's own fingerprint, so what goes out is the hello the other columns send,
//! minus the TCP record header.
//!
//! The Initial keys are derived from the connection ID this probe chose
//! (RFC 9001 §5.2), so the reply is readable without any TLS state. What the
//! verdict means:
//!
//! * `OK` — the endpoint decrypted this Initial and answered the handshake
//!   (a ServerHello, or a Retry whose integrity tag checked out). The UDP path
//!   to port 443 works, nothing filtered the Initial, and the endpoint's QUIC
//!   stack is running.
//! * `CLOSED` — it answered with a protected `CONNECTION_CLOSE` or a
//!   stateless reset: the path works, the handshake will not run.
//! * `VN` — version negotiation: the endpoint does not speak v1.
//! * `SPOOF` — a Retry whose integrity tag does not match, i.e. a packet
//!   that did not come from the endpoint.
//! * `DROP` — nothing came back, the silence `SYN DROP` is for TCP.
//!
//! A sixth state is not a verdict: the dash (`quic_unsupported`) is a row whose
//! endpoint serves no HTTP/3 at all, known before the probe from the shipped
//! `quic_unsupported.txt`, so no Initial is sent for it.
//!
//! What it does *not* say: that the site answers HTTP/3 with `:status 200`. That
//! needs the whole handshake and a request, which nothing in this tree drives —
//! the provider ships QUIC key material, but no TLS state is run over QUIC
//! (`docs/ADDING_A_PROFILE.md` §6) — and a domain whose QUIC endpoint is simply
//! absent is the ordinary case, not a finding: the column is read against the
//! TLS columns beside it.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::classify::{classify_connect_error_icmp, Detail, DpiStatus, ProbeStage};
use crate::config::AppConfig;
use crate::net::bind::udp_socket;
use crate::net::fingerprint::{
    sig_algs, HelloVariant, TlsFingerprint, EXT_APPLICATION_SETTINGS,
    EXT_APPLICATION_SETTINGS_NEW, EXT_SCT, EXT_SIGNATURE_ALGORITHMS, EXT_STATUS_REQUEST,
};
use crate::net::quic::{self, CryptoStream, Frame, ServerReply, SERVER_HELLO};
use crate::net::tls::{hello_record_for, TlsProfile, TlsVersion};

/// The QUIC transport-parameters extension (RFC 9000 §7.4.1 / RFC 9001 §8.2).
/// rustls emits it only on a QUIC connection, so it is injected as a raw
/// extension body — which is what the ClientHello-profile hook is for.
const EXT_TRANSPORT_PARAMETERS: u16 = 0x0039;

/// `initial_source_connection_id` (RFC 9000 §18.2): the one parameter an
/// endpoint must see, or it aborts with `TRANSPORT_PARAMETER_ERROR`.
const TP_INITIAL_SOURCE_CID: u64 = 0x0f;

/// The rest of the set, by RFC 9000 §18.2 identifier.
const TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const TP_INITIAL_MAX_DATA: u64 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;

/// What a browser's QUIC ClientHello advertises, measured from a Chrome capture
/// of `www.google.com` and `cloudflare.com` (`scripts/quic/tp_dump.py`):
/// idle timeout 30 s, 1472-byte datagrams, 15 MiB of connection credit, 6 MiB
/// per stream, 100 bidirectional and 103 unidirectional streams, and the RFC's
/// own default connection-ID limit of 2.
///
/// They are not decoration. RFC 9114 §6.2.1 requires an HTTP/3 client to let the
/// server open its control and QPACK streams, and a client that omits the set
/// leaves every limit at the RFC's zero default — measured against a stock
/// client with the limits zeroed: Cloudflare closes such a connection with
/// `Error opening control stream` (transport error 258, TLS alert 2) and Google
/// answers nothing at all.
const BROWSER_PARAMETERS: &[(u64, u64)] = &[
    (TP_MAX_IDLE_TIMEOUT, 30_000),
    (TP_MAX_UDP_PAYLOAD_SIZE, 1472),
    (TP_INITIAL_MAX_DATA, 15_728_640),
    (TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 6_291_456),
    (TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 6_291_456),
    (TP_INITIAL_MAX_STREAM_DATA_UNI, 6_291_456),
    (TP_INITIAL_MAX_STREAMS_BIDI, 100),
    (TP_INITIAL_MAX_STREAMS_UNI, 103),
    (TP_ACTIVE_CONNECTION_ID_LIMIT, 2),
];

/// Where a QUIC endpoint listens.
const QUIC_PORT: u16 = 443;

/// How many bytes a connection ID this probe generates has. Eight is what
/// browsers use, and it keeps the reply's header small.
const CID_LEN: usize = 8;

/// The largest reply this probe will read. A server's Initial is 1200 bytes at
/// most; the slack is for a coalesced Handshake packet in the same datagram.
const READ_BUF: usize = 2048;

/// How long the probe waits for an answer before repeating its Initial, and how
/// many times it repeats. RFC 9002 §6.2 sets the first timeout at twice the
/// initial round-trip estimate (333 ms, §6.2.1) while no sample exists and
/// doubles it after that — `0.67 s, 1.33 s, 2.67 s`, which is what aioquic's
/// `get_probe_timeout` computes and what a stock client was measured to send.
/// Three repeats inside the window is what the measured endpoints needed: an
/// edge that answers the first flight with a packet no key opens sent its
/// ServerHello only to a later one.
const PTO_FIRST: Duration = Duration::from_millis(666);
const MAX_RETRANSMITS: u32 = 3;

/// The shortest window a QUIC probe accepts, whatever `TIMEOUT` says. The ladder
/// above spends `1 + 2 + 4` PTOs before the last repeat goes out (4.66 s), and the
/// reply to that repeat needs a PTO of its own. A shorter window stops the probe
/// before its last repeat, and the verdict then describes the window instead of
/// the path: measured with a local `nfqws2` QUIC desync in front of the machine
/// (`fake:blob=quic_google:repeats=3`), the readable handshake arrived only after
/// the third repeat, and a 3 s window read the desync's own fake packets as
/// `CLOSED`/`quic_unreadable_reply`. Nine PTOs = the ladder's seven plus two for
/// the reply.
const MIN_WINDOW: Duration = PTO_FIRST.saturating_mul(9);

/// The window one QUIC probe gets: the configured timeout, never shorter than the
/// ladder the probe itself runs ([`MIN_WINDOW`]).
fn reply_window(timeout: f64) -> Duration {
    Duration::from_secs_f64(timeout.max(0.1)).max(MIN_WINDOW)
}

/// The QUIC column of one domain row.
#[derive(Debug, Clone)]
pub struct QuicCheck {
    pub status: DpiStatus,
    pub detail: Detail,
    pub elapsed: f64,
}

impl QuicCheck {
    /// The column as it stands before the probe ran, and what a row that is
    /// skipped (fake-IP, DNS failure) keeps.
    pub fn pending() -> Self {
        Self { status: DpiStatus::Unknown, detail: Detail::None, elapsed: 0.0 }
    }

    /// The cell of a row whose endpoint serves no HTTP/3 at all (the shipped
    /// `quic_unsupported.txt`): no Initial was sent, so there is nothing to time
    /// and nothing to explain — the dash is the whole verdict, and the summary
    /// counts the row out of this column's total.
    pub fn unsupported() -> Self {
        Self { status: DpiStatus::QuicUnsupported, detail: Detail::None, elapsed: 0.0 }
    }
}

/// The serialized transport parameters of RFC 9000 §18.2: the browser set above,
/// plus the client's own source connection ID, which an endpoint requires.
fn transport_parameters(scid: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for &(id, value) in BROWSER_PARAMETERS {
        quic::write_varint(&mut out, id);
        quic::write_varint(&mut out, quic::varint_len(value) as u64);
        quic::write_varint(&mut out, value);
    }
    quic::write_varint(&mut out, TP_INITIAL_SOURCE_CID);
    quic::write_varint(&mut out, scid.len() as u64);
    out.extend_from_slice(scid);
    out
}

/// The shape the column sends when the run's fingerprint is the rustls baseline.
///
/// The baseline hello has no profile for the ClientHello patch to edit, so the
/// transport parameters cannot be attached to it — and without them an endpoint
/// answers `TRANSPORT_PARAMETER_ERROR`, which would make the column report
/// `CLOSED` for every host that serves HTTP/3. The column is about the
/// browser's QUIC path, so a run on the baseline gets the newest Chrome's shape.
const BASELINE_SHAPE: TlsFingerprint = TlsFingerprint::Chrome146;

/// The ClientHello a QUIC endpoint can take: the run's shape, TLS 1.3 only,
/// `h3` in ALPN, and the transport parameters above.
///
/// The TCP record header is dropped: a QUIC `CRYPTO` frame carries the handshake
/// message itself (RFC 9001 §4.1.1), and the five bytes of TLS record framing
/// are not part of it.
fn quic_hello(fingerprint: TlsFingerprint, sni: &str, scid: &[u8]) -> Vec<u8> {
    let fingerprint = if fingerprint == TlsFingerprint::Rustls { BASELINE_SHAPE } else { fingerprint };
    let profile = TlsProfile {
        version: TlsVersion::Tls13,
        alpn: Some(vec![b"h3".to_vec()]),
        quic: true,
        ..TlsProfile::insecure(fingerprint)
    };
    let mut edits = vec![
        // A browser greases over TCP and not over QUIC (measured on a live
        // Chrome's QUIC hello), and the endpoints this column got wrong answer a
        // hello without GREASE and not this probe's.
        HelloVariant::NoGrease,
        HelloVariant::ExtBody(EXT_TRANSPORT_PARAMETERS, transport_parameters(scid)),
    ];
    // The shape is the TCP one, and two of its bodies are not what the same
    // browser sends over QUIC: `signature_algorithms` loses its trailing
    // `rsa_pkcs1_sha1` in the TCP hello, and application settings say `h2` there
    // and `h3` here.
    if let Some(sig_algs) = signature_algorithms_for_quic(fingerprint) {
        edits.push(sig_algs);
    }
    if let Some(alps) = application_settings_for_quic(fingerprint) {
        edits.push(alps);
    }
    // Unconditional: `status_request` is a typed rustls extension and is not in
    // the shape's raw list, while `DropExtension` suppresses exactly that kind
    // too — gating on `sends_extension` let it through, and the capture showed
    // the extension still on the wire.
    for id in TCP_ONLY_FOR_QUIC {
        edits.push(HelloVariant::DropExtension(*id));
    }
    let record = hello_record_for(&profile, Some(&HelloVariant::Chain(edits)), sni);
    record.get(5..).map(<[u8]>::to_vec).unwrap_or_default()
}

/// Extensions a Chrome **TCP** hello carries and its QUIC hello does not,
/// measured on a capture of a live Chrome's QUIC ClientHello
/// (`scripts/quic/tp_dump.py --extensions`): the status request (0x0005) and the
/// signed certificate timestamp (0x0012) are absent there, while the TCP shape in
/// this repository sends both.
///
/// Measured why it matters: `www.apkmirror.com` answers a Chrome hello — the same
/// two-datagram split, 1258-byte Initials — with the unreadable first packet and
/// then a readable ServerHello, and this probe with only the unreadable one. The
/// difference left in the hello was this pair.
const TCP_ONLY_FOR_QUIC: &[u16] = &[EXT_STATUS_REQUEST, EXT_SCT];

/// The application-settings body a browser sends **over QUIC**: `h3`, where the
/// same shape over TCP sends `h2`.
///
/// Measured against a live Chrome (`scripts/quic/tp_dump.py` on a capture of its
/// QUIC ClientHello): extension `0x44cd` carries `0003026833` — `h3` — while the
/// TCP shape in this repository carries `0003026832`. A QUIC hello that
/// advertises `h2` while negotiating `h3` is a shape no browser sends, and it is
/// the kind of lie an endpoint that parses the extension (Google's own) may
/// answer with a close.
///
/// Only a shape that already sends the extension is edited: Firefox, Safari and
/// Tor send none, and `ExtBody` would add one to them.
fn application_settings_for_quic(fingerprint: TlsFingerprint) -> Option<HelloVariant> {
    let id = [EXT_APPLICATION_SETTINGS, EXT_APPLICATION_SETTINGS_NEW]
        .into_iter()
        .find(|id| fingerprint.sends_raw_extension(*id))?;
    Some(HelloVariant::ExtBody(id, vec![0x00, 0x03, 0x02, b'h', b'3']))
}

/// The `signature_algorithms` body a browser sends **over QUIC**: the shape's own
/// list with the trailing `rsa_pkcs1_sha1` its TCP hello drops.
///
/// Measured on a live Chrome's QUIC ClientHello (`tp_dump.py --extensions`):
/// `0012 0403 0804 0401 0503 0805 0501 0806 0601 0201` — nine algorithms, where
/// the same shape over TCP sends those eight and stops. quinn's own hello, which
/// these endpoints do answer, carries the twenty-byte body as well, so this is a
/// list both working clients agree on and this probe did not.
///
/// Measured for Chrome; Firefox's QUIC hello has not been captured, so the edit
/// adds the value to whatever list the shape carries rather than pinning one.
fn signature_algorithms_for_quic(fingerprint: TlsFingerprint) -> Option<HelloVariant> {
    // The list comes from the shape's typed field, not from a raw body:
    // extension 13 is in no shape's `raw_exts`, so the earlier form of this
    // function — gated on `sends_extension` and reading `extension_body` —
    // returned `None` for every profile and this edit never reached the wire.
    let schemes = sig_algs(fingerprint);
    if schemes.is_empty() || schemes.contains(&0x0201) {
        return None;
    }
    // The body is a `u16` list length and then the code points; `0x0201` is
    // `rsa_pkcs1_sha1`, the value the browser appends last over QUIC.
    let mut out = Vec::with_capacity(2 + (schemes.len() + 1) * 2);
    out.extend_from_slice(&[0x00, 0x00]);
    for scheme in schemes {
        out.extend_from_slice(&scheme.to_be_bytes());
    }
    out.extend_from_slice(&[0x02, 0x01]);
    let list_len = (out.len() - 2) as u16;
    out[..2].copy_from_slice(&list_len.to_be_bytes());
    Some(HelloVariant::ExtBody(EXT_SIGNATURE_ALGORITHMS, out))
}

/// A fresh connection ID.
fn random_cid() -> [u8; CID_LEN] {
    let mut cid = [0u8; CID_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut cid);
    cid
}

/// The verdict a domain's datagrams add up to.
///
/// Kept apart from the socket so the ladder is testable on synthetic replies:
/// what a ServerHello, a close, a Retry or silence means does not depend on how
/// the bytes arrived.
#[derive(Debug, Default)]
struct Verdict {
    stream: CryptoStream,
    close: Option<u64>,
    retry: Option<bool>,
    reset: bool,
    negotiated: bool,
    answered: bool,
}

impl Verdict {
    /// Folds one reply in, returning true when nothing better can arrive.
    fn absorb(&mut self, reply: ServerReply) -> bool {
        match reply {
            ServerReply::Initial(frames) => {
                self.answered = true;
                for frame in frames {
                    match frame {
                        Frame::Crypto { offset, data } => self.stream.push(offset, &data),
                        Frame::ConnectionClose { error_code, .. } => {
                            self.close = Some(error_code);
                            return true;
                        }
                        _ => {}
                    }
                }
                self.stream.handshake_type().is_some() || self.close.is_some()
            }
            ServerReply::Retry { authenticated, .. } => {
                self.retry = Some(authenticated);
                true
            }
            ServerReply::VersionNegotiation { .. } => {
                self.negotiated = true;
                true
            }
            ServerReply::ShortHeader => {
                // Remembered, but not final: measured on `www.instagram.com`,
                // `www.facebook.com` and `www.messenger.com`, the endpoint sends
                // a short-header packet *before* the readable Initial that
                // carries its ServerHello — stopping here reported a stateless
                // reset for an endpoint that answers every client that waits.
                self.reset = true;
                false
            }
        }
    }

    /// Whether the question is answered: a Retry, a close, a version
    /// negotiation or a handshake message. An Initial that carries neither — a
    /// bare acknowledgement — and a short-header packet do **not** settle it, and
    /// that is measured: Cloudflare's edge answers the first flight with an
    /// acknowledgement alone and sends the ServerHello only to a repeat, so a
    /// probe that stops repeating when it sees an answer never sees the
    /// ServerHello (`www.apkmirror.com`), and Meta's edge sends a short-header
    /// packet before its readable Initial (`www.instagram.com`,
    /// `www.facebook.com`, `www.messenger.com`).
    fn settled(&self) -> bool {
        self.retry.is_some()
            || self.close.is_some()
            || self.negotiated
            || self.stream.handshake_type().is_some()
    }

    /// The verdict the collected replies add up to.
    fn finish(self) -> (DpiStatus, Detail) {
        // A Retry that does not authenticate is the one reply here that is a
        // finding rather than a state: only a party that saw the Initial can
        // compute the tag (RFC 9001 §5.8), so a bad one is an imitation.
        if let Some(authenticated) = self.retry {
            return if authenticated {
                (DpiStatus::QuicOk, Detail::QuicRetry)
            } else {
                (DpiStatus::QuicSpoof, Detail::QuicForgedRetry)
            };
        }
        if let Some(error_code) = self.close {
            return (DpiStatus::QuicClosed, Detail::QuicClose { error_code });
        }
        let hello = self.stream.assembled();
        if hello.first() == Some(&SERVER_HELLO) {
            // A HelloRetryRequest is a ServerHello whose random is a fixed
            // constant (RFC 8446 §4.1.4): still the endpoint answering the
            // handshake, only asking for another key share.
            return (DpiStatus::QuicOk, Detail::QuicServerHello);
        }
        if self.negotiated {
            return (DpiStatus::QuicVn, Detail::QuicVersionNegotiation);
        }
        if self.reset {
            return (DpiStatus::QuicClosed, Detail::QuicReset);
        }
        if self.answered {
            // Decrypted, and it carried neither a hello nor a close: rare enough
            // that the raw handshake type is more useful than a code of its own.
            let detail = match hello.first() {
                Some(kind) => Detail::Other(format!("quic: handshake message {kind:#04x}")),
                None => Detail::QuicAnsweredWithoutHandshake,
            };
            return (DpiStatus::QuicClosed, detail);
        }
        (DpiStatus::QuicDrop, Detail::QuicTimeout)
    }
}

/// One domain: resolve-free (the caller already has the IP), one Initial, and
/// the window the reply has to arrive in.
pub async fn check_domain_quic(
    domain: &str,
    target: IpAddr,
    cfg: &AppConfig,
) -> QuicCheck {
    let started = Instant::now();
    let timeout_dur = reply_window(cfg.timeout);
    let addr = SocketAddr::new(target, QUIC_PORT);
    let fingerprint = TlsFingerprint::from_config(cfg);
    match probe_addr(addr, domain, fingerprint, timeout_dur).await {
        Ok((status, detail)) => QuicCheck { status, detail, elapsed: started.elapsed().as_secs_f64() },
        Err((status, detail)) => QuicCheck { status, detail, elapsed: started.elapsed().as_secs_f64() },
    }
}

/// The verdict of a socket error on this path.
///
/// A UDP socket reports "nothing listens there" through the same errnos a TCP
/// one uses for a refused or reset connect — on Windows the ICMP
/// port-unreachable arrives as `ConnectionReset`, on Linux a *connected* socket
/// hands it to the next operation after the datagram that provoked it, so the
/// second packet of a flight is where a closed port surfaces. The classifier
/// reads all of them; what this adds is the mapping to this column's vocabulary,
/// and one copy of it: a `send` that failed used to be reported as a generic
/// error while the identical errno on the receive path read `REFUSED`.
fn quic_socket_verdict(
    error: &std::io::Error,
    icmp: Option<crate::classify::IcmpCode>,
) -> (DpiStatus, Detail) {
    let (status, detail) = classify_connect_error_icmp(error, icmp, 0, ProbeStage::TcpConnect);
    match status {
        DpiStatus::Refused | DpiStatus::TcpRst | DpiStatus::TcpAbort => {
            (DpiStatus::Refused, Detail::QuicPortUnreachable)
        }
        other => (other, detail),
    }
}

/// What a socket error does to a QUIC attempt.
///
/// Returns the verdict that ends the attempt, or `None` when the error is waited
/// out — with the verdict left in `pending` to be reported if nothing better
/// arrives. One class is waited out: the ICMP a *local* desync puts on this
/// socket. Its fake has to borrow the flow's 5-tuple to fool a filter, so the
/// ICMP for a TTL-carrying fake lands on the probe's own socket — and it says
/// nothing about the probe's datagrams, which carry a normal hop limit. Ending
/// the attempt on it read as `OS ERR` where the endpoint was about to answer.
fn on_socket_error(
    classified: (DpiStatus, Detail),
    pending: &mut Option<(DpiStatus, Detail)>,
) -> Option<(DpiStatus, Detail)> {
    if classified.1 == Detail::IcmpTimeExceeded {
        *pending = Some(classified);
        return None;
    }
    Some(classified)
}

/// One address: the datagram, the window, and the verdict.
///
/// `Err` is a transport failure — the socket's own error — and `Ok` a verdict
/// read off the wire. Silence is `Ok(QuicDrop)`: the two are told apart because
/// a caller with another address to try may want to, and because the timeout
/// window is what the two differ in.
async fn probe_addr(
    addr: SocketAddr,
    sni: &str,
    fingerprint: TlsFingerprint,
    timeout_dur: Duration,
) -> Result<(DpiStatus, Detail), (DpiStatus, Detail)> {
    let dcid = random_cid();
    let scid = random_cid();
    let keys = quic::InitialKeys::derive(&dcid)
        .map_err(|_| (DpiStatus::Err, Detail::Other("quic: key schedule".to_string())))?;
    // A name the resolver accepted but rustls refuses must become this row's
    // verdict, not a panic: `hello_record_for` aborts on it and this column hands
    // it the domain under test. `probe/domains.rs` reports the same failure the
    // same way, and both go through `net::tls::server_name` so they cannot drift.
    crate::net::tls::server_name(sni)
        .map_err(|error| (DpiStatus::Err, Detail::Other(format!("bad SNI: {error}"))))?;
    let hello = quic_hello(fingerprint, sni, &scid);
    let mut flight = quic::client_initials(&keys, &dcid, &scid, &hello, 0)
        .map_err(|error| (DpiStatus::Err, Detail::Other(error.to_string())))?;

    let socket = udp_socket(&addr)
        .await
        .map_err(|error| (DpiStatus::Err, Detail::Other(error.to_string())))?;
    // Connected, so the kernel hands the ICMP verdict of this destination to
    // this socket instead of to whoever reads next.
    socket.connect(addr).await.map_err(|error| quic_socket_verdict(&error, None))?;
    // A browser hello is bigger than one datagram, so the flight is usually two
    // or three packets; they go out in order, as the CRYPTO offsets expect.
    for datagram in &flight {
        socket.send(datagram).await.map_err(|error| quic_socket_verdict(&error, None))?;
    }

    // The watcher is opened before the first packet can fail, the way `dial_tcp`
    // does it: a verdict that arrives with the failure is too late to catch.
    crate::net::icmp_err::ensure_started();

    let deadline = Instant::now() + timeout_dur;
    let mut verdict = Verdict::default();
    let mut buf = vec![0u8; READ_BUF];
    let mut largest_pn = 0u64;
    // An endpoint is not obliged to answer the first Initial. Measured against
    // Cloudflare's edge, the first flight is met with a packet no key opens and
    // the ServerHello arrives only once the client repeats its Initial — which
    // every real client does on a loss timeout (RFC 9002 §6.2) and a probe that
    // sends once does not, so it reports silence for an endpoint that is
    // answering every browser on the same address.
    let mut next_pn = flight.len() as u64;
    let mut next_retransmit = Instant::now() + PTO_FIRST;
    let mut retransmits: u32 = 0;
    let mut unreadable: usize = 0;
    let mut path_error: Option<(DpiStatus, Detail)> = None;
    loop {
        let now = Instant::now();
        let left = deadline.saturating_duration_since(now);
        if left.is_zero() {
            break;
        }
        if retransmits < MAX_RETRANSMITS && !verdict.settled() && now >= next_retransmit {
            flight = quic::client_initials(&keys, &dcid, &scid, &hello, next_pn)
                .map_err(|error| (DpiStatus::Err, Detail::Other(error.to_string())))?;
            next_pn += flight.len() as u64;
            for datagram in &flight {
                // A send that fails mid-flight is not fatal: the window is still
                // open and the reply may already be on its way.
                let _ = socket.send(datagram).await;
            }
            retransmits += 1;
            next_retransmit = now + PTO_FIRST * (1 << retransmits);
        }
        // Once the retransmits are spent the only thing left is the window: waiting
        // on a `next_retransmit` that is already in the past would hand
        // `timeout(..)` a zero duration, and the loop would spin on `continue`
        // until the deadline, burning a runtime worker — there are two of them on
        // a router build.
        let until_retransmit = if retransmits >= MAX_RETRANSMITS {
            left
        } else {
            next_retransmit.saturating_duration_since(Instant::now()).min(left)
        };
        match tokio::time::timeout(until_retransmit, socket.recv(&mut buf)).await {
            // Either the window closed or it is time to repeat the flight; the
            // loop's own deadline check tells the two apart.
            Err(_) => continue,
            Ok(Ok(0)) => continue,
            Ok(Ok(len)) => {
                match quic::open_datagram(&keys, &dcid, &buf[..len], largest_pn) {
                    Ok(reply) => {
                        largest_pn = largest_pn.saturating_add(1);
                        if verdict.absorb(reply) {
                            break;
                        }
                    }
                    // Not ours to read — a stray datagram, or a packet the
                    // endpoint sent under keys this probe cannot derive. Counted,
                    // because "nothing came back" would be a false statement.
                    Err(_) => unreadable += 1,
                }
            }
            Ok(Err(error)) => {
                let icmp = crate::net::icmp_err::verdict_wait(addr.ip()).await;
                let classified = quic_socket_verdict(&error, icmp);
                if let Some(verdict) = on_socket_error(classified, &mut path_error) {
                    return Err(verdict);
                }
                continue;
            }
        }
    }
    let (mut status, mut detail) = verdict.finish();
    if status == DpiStatus::QuicDrop && unreadable > 0 {
        // The endpoint answered and the probe could not open the answer: the
        // path works, and "no reply to the Initial" would say the opposite.
        status = DpiStatus::QuicClosed;
        detail = Detail::QuicUnreadableReply;
    }
    if status == DpiStatus::QuicDrop {
        return Err((status, detail));
    }
    Ok((status, detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::quic::HELLO_RETRY_RANDOM;

    /// A ServerHello is `0x02`, its three-byte length, then the body: enough for
    /// the ladder, which reads the handshake type and the retry random.
    fn server_hello(random: [u8; 32]) -> Vec<u8> {
        let mut hello = vec![SERVER_HELLO, 0x00, 0x00, 0x2c, 0x03, 0x03];
        hello.extend_from_slice(&random);
        hello
    }

    #[test]
    fn the_quic_hello_leaves_the_legacy_session_id_empty() {
        // RFC 9001 §8.4: the compatibility-mode session id is prohibited in
        // QUIC, and a server treats a non-empty one as PROTOCOL_VIOLATION —
        // Cloudflare answers `illegal_parameter` (`CRYPTO_ERROR 0x12f`) instead
        // of a ServerHello. The byte after the 32-byte random is its length.
        let hello = quic_hello(TlsFingerprint::Chrome146, "example.com", &[0x5a; 8]);
        assert_eq!(hello[0], 0x01, "a ClientHello message");
        assert_eq!(hello[38], 0, "the QUIC hello's session id is empty");

        // The TCP shapes keep the 32-byte field, which is what a browser sends
        // over TCP and what every pinned byte test in `net::tls` expects.
        let record = hello_record_for(
            &TlsProfile::insecure(TlsFingerprint::Chrome146),
            None,
            "example.com",
        );
        assert_eq!(record[5 + 38], 32, "the TCP hello carries the compatibility id");
    }

    #[test]
    fn the_transport_parameters_carry_the_source_connection_id() {
        let params = transport_parameters(&[0xaa; 8]);
        let parsed = parse_parameters(&params);
        assert_eq!(parsed.get(&TP_INITIAL_SOURCE_CID), Some(&vec![0xaa; 8]));
    }

    /// RFC 9114 §6.2.1: an HTTP/3 client must let the server open its control and
    /// QPACK streams, which needs `initial_max_streams_uni` of at least three.
    /// Measured against a stock client with the limits zeroed: Cloudflare closes
    /// the connection with `Error opening control stream` and Google answers
    /// nothing, so a hello that omits the set is a broken hello.
    #[test]
    fn the_quic_hello_lets_the_server_open_its_control_stream() {
        let params = parse_parameters(&transport_parameters(&[0xaa; 8]));
        let uni = params.get(&TP_INITIAL_MAX_STREAMS_UNI).expect("the uni-stream credit");
        assert!(uni[0] >= 3, "an HTTP/3 server needs three unidirectional streams, got {}", uni[0]);
        assert!(params.contains_key(&TP_INITIAL_MAX_DATA), "no connection credit");
        assert!(params.contains_key(&TP_INITIAL_MAX_STREAM_DATA_UNI), "no stream credit");
    }

    /// A browser greases over TCP and does not over QUIC: a live Chrome's QUIC
    /// hello carries no GREASE value at all (RFC 8701), and the endpoints this
    /// column got wrong — `www.apkmirror.com`, `www.facebook.com`,
    /// `www.instagram.com` — answer a Chrome hello while they do not answer this
    /// probe's. quinn's own hello, which those endpoints *do* answer, carries none
    /// either, and it is the one feature absent from both working clients and
    /// present in ours.
    ///
    /// Measured with `scripts/quic/tp_dump.py --extensions` on a capture of each.
    #[test]
    fn the_quic_hello_carries_no_grease() {
        let hello = quic_hello(TlsFingerprint::Chrome146, "example.com", &[0x5a; 8]);
        let ciphers = crate::net::ja3::cipher_suites(&hello);
        assert!(!ciphers.is_empty(), "the hello must offer cipher suites");
        assert!(
            ciphers.iter().all(|suite| !crate::net::ja3::is_grease(*suite)),
            "a GREASE cipher suite over QUIC: {ciphers:04x?}"
        );
        let extensions = crate::net::ja3::extensions(&hello);
        assert!(
            extensions.iter().all(|(id, _)| !crate::net::ja3::is_grease(*id)),
            "a GREASE extension over QUIC: {extensions:04x?}"
        );
        // The two bodies that hold a *list* of code points, either of which a
        // GREASE value can hide in: `supported_groups` and `supported_versions`.
        for (id, body) in &extensions {
            let skip = match *id {
                crate::net::fingerprint::EXT_SUPPORTED_GROUPS => 2,
                crate::net::fingerprint::EXT_SUPPORTED_VERSIONS => 1,
                _ => continue,
            };
            let values: Vec<u16> = body
                .get(skip..)
                .unwrap_or_default()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect();
            assert!(
                values.iter().all(|value| !crate::net::ja3::is_grease(*value)),
                "a GREASE value inside extension {id:#06x}: {values:04x?}"
            );
        }
    }

    /// The QUIC hello's `signature_algorithms` is the browser's, one scheme longer
    /// than the same shape's TCP hello: a live Chrome sends nine
    /// (`0403 0804 0401 0503 0805 0501 0806 0601 0201`) over QUIC, where the TCP
    /// shape here sends the first eight and stops.
    ///
    /// This test is the one that was missing, and its absence is exactly why the
    /// edit could be dead for every profile: the body was read through
    /// `extension_body`, which sees only `raw_exts`, while extension 13 is a
    /// *typed* field of the record. The column then sent the TCP body while its
    /// own doc claimed the measured fix, and nothing failed.
    #[test]
    fn the_quic_hello_carries_the_browser_signature_algorithms() {
        let fingerprint = TlsFingerprint::Chrome146;
        let hello = quic_hello(fingerprint, "example.com", &[0x5a; 8]);
        let extensions = crate::net::ja3::extensions(&hello);
        let body = extensions
            .iter()
            .find(|(id, _)| *id == EXT_SIGNATURE_ALGORITHMS)
            .map(|(_, body)| *body)
            .expect("the QUIC hello carries signature_algorithms");
        let schemes: Vec<u16> = body[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();

        assert_eq!(
            u16::from_be_bytes([body[0], body[1]]) as usize,
            body.len() - 2,
            "the list length is the body's own"
        );
        assert_eq!(
            schemes.len(),
            sig_algs(fingerprint).len() + 1,
            "the QUIC list is the shape's plus rsa_pkcs1_sha1"
        );
        assert_eq!(schemes.last(), Some(&0x0201), "which a browser sends last");
        assert_eq!(
            &schemes[..schemes.len() - 1],
            sig_algs(fingerprint),
            "and the shape's own list, in its own order"
        );
    }

    /// A short-header packet is remembered, not final: measured on
    /// `www.instagram.com`, `www.facebook.com` and `www.messenger.com`, the
    /// endpoint sends one *before* the readable Initial that carries its
    /// ServerHello, so ending the exchange there reported a stateless reset for
    /// an endpoint that answers every client which waits.
    #[test]
    fn a_short_header_does_not_end_the_exchange() {
        let mut verdict = Verdict::default();
        assert!(!verdict.absorb(ServerReply::ShortHeader), "the exchange must keep going");
        assert_eq!(
            verdict.finish(),
            (DpiStatus::QuicClosed, Detail::QuicReset),
            "and the reset is still the verdict when nothing better arrives"
        );
    }

    /// An Initial that carries no handshake message does not settle it either, so
    /// the flight keeps repeating: Cloudflare's edge answers the first Initial
    /// with an acknowledgement alone and sends the ServerHello only to a repeat.
    #[test]
    fn an_initial_without_a_handshake_does_not_settle_the_question() {
        let mut verdict = Verdict::default();
        assert!(!verdict.absorb(ServerReply::Initial(Vec::new())), "nothing settled yet");
        assert!(!verdict.settled(), "the repeats must continue");
        assert!(verdict.answered, "it did answer — that is what the column reports");
    }

    /// The parameter list as `id -> value`, the way an endpoint reads it.
    fn parse_parameters(body: &[u8]) -> std::collections::HashMap<u64, Vec<u8>> {
        let mut out = std::collections::HashMap::new();
        let mut at = 0;
        while at < body.len() {
            let (id, next) = quic::read_varint(body, at).expect("an id");
            let (len, next) = quic::read_varint(body, next).expect("a length");
            out.insert(id, body[next..next + len as usize].to_vec());
            at = next + len as usize;
        }
        out
    }

    #[test]
    fn the_hello_is_a_tls13_h3_hello_carrying_the_transport_parameters() {
        // The whole trick in one assertion: the shape is the run's own, the ALPN
        // is h3, and extension 0x39 holds the parameter an endpoint requires.
        let scid = [0x5a; 8];
        let hello = quic_hello(TlsFingerprint::Chrome107, "example.com", &scid);
        assert_eq!(hello[0], 0x01, "a ClientHello message, with no record header");

        let extensions = crate::net::ja3::extensions(&hello);
        let body = |id: u16| -> Vec<u8> {
            extensions
                .iter()
                .find(|(ext_type, _)| *ext_type == id)
                .map(|(_, body)| body.to_vec())
                .unwrap_or_default()
        };
        assert_eq!(body(EXT_TRANSPORT_PARAMETERS), transport_parameters(&scid));
        // ALPN: a one-protocol list (length 3), that protocol being "h3".
        assert_eq!(body(0x0010), vec![0x00, 0x03, 0x02, b'h', b'3']);

        // Application settings over QUIC say h3, not the h2 the same shape sends
        // over TCP: a live Chrome's QUIC hello carries 0003026833 here, and the
        // capture of this probe's own hello carried 0003026832 before the edit.
        let chrome146 = quic_hello(TlsFingerprint::Chrome146, "example.com", &scid);
        let alps = crate::net::ja3::extensions(&chrome146)
            .iter()
            .find(|(id, _)| *id == EXT_APPLICATION_SETTINGS_NEW)
            .map(|(_, body)| body.to_vec())
            .expect("Chrome 146 sends the new application settings");
        assert_eq!(alps, vec![0x00, 0x03, 0x02, b'h', b'3'], "h2 over QUIC is a shape no browser sends");

        // Firefox sends no application settings over either transport, and the
        // edit must not add one: that would be a shape no client sends either.
        let firefox = quic_hello(TlsFingerprint::Firefox133, "example.com", &scid);
        assert!(
            !crate::net::ja3::extensions(&firefox)
                .iter()
                .any(|(id, _)| *id == EXT_APPLICATION_SETTINGS || *id == EXT_APPLICATION_SETTINGS_NEW),
            "a shape without ALPS must not grow one over QUIC"
        );

        // The TCP-only pair a live Chrome's QUIC hello does not carry: the status
        // request is a *typed* rustls extension, so a drop that only edits the raw
        // list leaves it on the wire (measured: it did).
        for id in TCP_ONLY_FOR_QUIC {
            assert!(
                !crate::net::ja3::extensions(&chrome146).iter().any(|(ext, _)| ext == id),
                "extension {id:#06x} belongs to the TCP shape, not the QUIC hello"
            );
        }

        // The baseline shape has no profile to edit, so the column substitutes a
        // browser one: without the parameters an endpoint would answer
        // TRANSPORT_PARAMETER_ERROR for every host.
        let baseline = quic_hello(TlsFingerprint::Rustls, "example.com", &scid);
        let baseline_ext = crate::net::ja3::extensions(&baseline);
        assert!(
            baseline_ext.iter().any(|(id, body)| *id == EXT_TRANSPORT_PARAMETERS
                && *body == transport_parameters(&scid).as_slice()),
            "the baseline falls back to a shape the parameters can be attached to"
        );
    }

    #[test]
    fn a_server_hello_is_ok_and_a_retry_request_still_is() {
        let mut verdict = Verdict::default();
        verdict.absorb(ServerReply::Initial(vec![Frame::Crypto {
            offset: 0,
            data: server_hello([0x11; 32]),
        }]));
        assert_eq!(verdict.finish(), (DpiStatus::QuicOk, Detail::QuicServerHello));

        let mut retried = Verdict::default();
        retried.absorb(ServerReply::Initial(vec![Frame::Crypto {
            offset: 0,
            data: server_hello(HELLO_RETRY_RANDOM),
        }]));
        assert_eq!(retried.finish(), (DpiStatus::QuicOk, Detail::QuicServerHello));
    }

    #[test]
    fn an_authenticated_retry_is_ok_and_a_forged_one_is_a_spoof() {
        let mut good = Verdict::default();
        good.absorb(ServerReply::Retry { token: b"token".to_vec(), authenticated: true });
        assert_eq!(good.finish(), (DpiStatus::QuicOk, Detail::QuicRetry));

        // A tag that does not match cannot have been computed by a party that
        // saw the Initial, so the packet is an imitation — the finding this test
        // exists for.
        let mut forged = Verdict::default();
        forged.absorb(ServerReply::Retry { token: b"token".to_vec(), authenticated: false });
        assert_eq!(forged.finish(), (DpiStatus::QuicSpoof, Detail::QuicForgedRetry));
    }

    #[test]
    fn a_close_keeps_its_error_code_and_silence_is_a_drop() {
        let mut closed = Verdict::default();
        closed.absorb(ServerReply::Initial(vec![Frame::ConnectionClose {
            error_code: 8,
            frame_type: Some(6),
            reason: "transport parameters required".to_string(),
        }]));
        assert_eq!(
            closed.finish(),
            (DpiStatus::QuicClosed, Detail::QuicClose { error_code: 8 })
        );

        assert_eq!(Verdict::default().finish(), (DpiStatus::QuicDrop, Detail::QuicTimeout));
    }

    #[test]
    fn a_negotiation_and_a_stateless_reset_have_their_own_verdicts() {
        let mut negotiated = Verdict::default();
        negotiated.absorb(ServerReply::VersionNegotiation { versions: vec![0, 0x6b33_43cf] });
        assert_eq!(negotiated.finish(), (DpiStatus::QuicVn, Detail::QuicVersionNegotiation));

        let mut reset = Verdict::default();
        reset.absorb(ServerReply::ShortHeader);
        assert_eq!(reset.finish(), (DpiStatus::QuicClosed, Detail::QuicReset));
    }

    #[test]
    fn a_close_outranks_a_server_hello_in_the_same_packet() {
        // A server may put a CRYPTO frame and a close in one Initial; the close
        // is the outcome.
        let mut verdict = Verdict::default();
        verdict.absorb(ServerReply::Initial(vec![
            Frame::Crypto { offset: 0, data: server_hello([0x22; 32]) },
            Frame::ConnectionClose { error_code: 0x0a, frame_type: None, reason: String::new() },
        ]));
        assert_eq!(
            verdict.finish(),
            (DpiStatus::QuicClosed, Detail::QuicClose { error_code: 0x0a })
        );
    }

    /// The socket path, without egress: a port with nothing on it answers with
    /// ICMP, and a port that answers nothing at all is the drop verdict.
    #[tokio::test]
    async fn a_closed_port_is_refused_and_a_silent_one_is_a_drop() {
        let timeout_dur = Duration::from_millis(400);

        // A port nobody listens on: bind, learn the number, drop the socket.
        let closed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("a local socket");
        let closed_addr = closed.local_addr().expect("an address");
        drop(closed);
        let refused = probe_addr(closed_addr, "example.com", TlsFingerprint::Chrome107, timeout_dur).await;
        assert_eq!(
            refused,
            Err((DpiStatus::Refused, Detail::QuicPortUnreachable)),
            "ICMP port-unreachable is the refused verdict"
        );

        // A port that is open and answers nothing: the drop verdict, and the
        // caller is told so it can try another address.
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("a local socket");
        let silent_addr = silent.local_addr().expect("an address");
        let dropped = probe_addr(silent_addr, "example.com", TlsFingerprint::Chrome107, timeout_dur).await;
        assert_eq!(dropped, Err((DpiStatus::QuicDrop, Detail::QuicTimeout)));
    }

    /// The window the probe takes must outlast the probe's own ladder: seven
    /// PTOs go before the last repeat is even sent, and the reply to it needs a
    /// PTO more. A `TIMEOUT` of 3 s used to end the probe at the second repeat.
    #[test]
    fn the_quic_window_outlasts_the_retransmit_ladder() {
        let ladder_end = PTO_FIRST * 7; // the 1 + 2 + 4 PTOs before the third repeat
        for asked in [1.0, 3.0, 8.0] {
            let window = reply_window(asked);
            assert!(
                window >= ladder_end + PTO_FIRST,
                "{asked}s asked, {window:?} granted, the ladder ends at {ladder_end:?}"
            );
        }
        // The floor raises a short timeout and never shortens a long one.
        assert_eq!(reply_window(60.0), Duration::from_secs(60));
    }

    /// An endpoint that answers the first flight with a packet no key opens and
    /// sends its ServerHello only later — the shape measured against Cloudflare's
    /// edge. Under a 3 s `TIMEOUT` the probe used to stop at the second repeat
    /// and report `CLOSED`/`quic_unreadable_reply`, which describes the window
    /// and not the endpoint: the ServerHello it never waited for is what a stock
    /// client gets. The floored window outlasts the ladder, so the reply lands.
    #[tokio::test]
    async fn a_late_server_hello_still_reads_ok_under_a_small_timeout() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("a local socket");
        let addr = server.local_addr().expect("an address");
        let started = Instant::now();
        let answering = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            let mut state: Option<(crate::net::quic::InitialKeys, Vec<u8>, Vec<u8>)> = None;
            while let Ok((len, from)) = server.recv_from(&mut buf).await {
                if len < 8 {
                    continue;
                }
                if state.is_none() {
                    // The client's destination connection ID is what both
                    // directions of the Initial keys come from (RFC 9001 §5.2),
                    // and its source ID is who the reply is addressed to.
                    let dcid_len = usize::from(buf[5]);
                    let dcid = buf[6..6 + dcid_len].to_vec();
                    let at = 6 + dcid_len;
                    let scid_len = usize::from(buf[at]);
                    let scid = buf[at + 1..at + 1 + scid_len].to_vec();
                    let keys = crate::net::quic::InitialKeys::derive(&dcid).expect("initial keys");
                    state = Some((keys, dcid, scid));
                }
                let (keys, dcid, scid) = state.as_ref().expect("just set");
                if started.elapsed() < Duration::from_secs(3) {
                    // A packet no key opens, counted as unreadable rather than
                    // as silence.
                    let mut junk = vec![0xc0u8; 1200];
                    junk[1..5].copy_from_slice(&crate::net::quic::VERSION_1.to_be_bytes());
                    let _ = server.send_to(&junk, from).await;
                    continue;
                }
                let hello = server_hello([0x11; 32]);
                let mut frames = vec![0x06]; // CRYPTO
                crate::net::quic::write_varint(&mut frames, 0);
                crate::net::quic::write_varint(&mut frames, hello.len() as u64);
                frames.extend_from_slice(&hello);
                let packet = crate::net::quic::seal_server_initial(keys, scid, dcid, 0, frames)
                    .expect("a sealed reply");
                let _ = server.send_to(&packet, from).await;
            }
        });

        let verdict = probe_addr(addr, "example.com", TlsFingerprint::Chrome107, reply_window(3.0)).await;
        answering.abort();
        assert_eq!(
            verdict,
            Ok((DpiStatus::QuicOk, Detail::QuicServerHello)),
            "the late ServerHello is what the window has to wait for"
        );
    }

    /// The ICMP a local desync's fake puts on this socket must not end the
    /// attempt: it is about the fake, not about the probe's datagrams, and
    /// ending on it read as `OS ERR` where the endpoint was about to answer.
    #[test]
    fn a_stray_icmp_does_not_end_the_quic_attempt() {
        let mut pending = None;
        assert!(on_socket_error(
            (DpiStatus::HostUnreach, Detail::IcmpTimeExceeded),
            &mut pending
        )
        .is_none());
        assert_eq!(pending, Some((DpiStatus::HostUnreach, Detail::IcmpTimeExceeded)));

        // A verdict the probe recognizes still ends it, and leaves nothing to
        // report in place of it.
        let mut pending = None;
        assert!(on_socket_error(
            (DpiStatus::Refused, Detail::QuicPortUnreachable),
            &mut pending
        )
        .is_some());
        assert_eq!(pending, None);
    }

    /// A closed port must read `REFUSED` whichever path noticed it.
    ///
    /// Linux hands a *connected* UDP socket the ICMP port-unreachable of the
    /// datagram that provoked it, so the second packet of a flight fails with
    /// `ECONNREFUSED` (111) — while the receive path classified the identical
    /// errno as `REFUSED` and the send path reported a generic `ERR`. Windows
    /// reports the same event as `ConnectionReset` (10054), which is why the
    /// mismatch never showed there. The numbers are asserted rather than the
    /// `ErrorKind`s because they are what the classifier keys on, and 111 is not
    /// a Windows errno at all.
    #[test]
    fn a_refused_socket_error_is_the_ports_verdict_not_a_generic_one() {
        for errno in [111, 10054] {
            let error = std::io::Error::from_raw_os_error(errno);
            let (status, detail) = quic_socket_verdict(&error, None);
            assert_eq!(status, DpiStatus::Refused, "errno {errno}");
            assert_eq!(detail, Detail::QuicPortUnreachable, "errno {errno}");
        }
    }
}

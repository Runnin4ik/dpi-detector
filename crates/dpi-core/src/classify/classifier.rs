use std::io;
use super::alert;
use super::detail::{AlertKind, Detail};
use super::stack;
use super::types::{ConnectionStage, DpiStatus, IcmpCode};

fn short_detail(msg: &str) -> String {
    let mut s: String = msg.chars().take(40).collect();
    s = s.replace(['\n', '\r'], " ");
    s.trim().to_string()
}

fn is_tls_stage(stage: ConnectionStage) -> bool {
    matches!(
        stage,
        ConnectionStage::TlsClientHelloSent | ConnectionStage::TlsHandshakeDone
    )
}

/// Messages about a protocol element our own TLS stack does not implement are
/// not evidence about the network. rustls words these with "certificate" (`got
/// CompressedCertificate when expecting Certificate`,
/// `UnknownCertificateExtension`), so without this they read as a certificate
/// interception — and, since rustls reports them the same way it reports a peer
/// that broke the protocol, they would also take a stack failure's name. Real
/// interference still lands in the alert, record and EOF branches.
fn is_unimplemented_element(msg_lower: &str) -> bool {
    [
        "unsupportedextension",
        "unsupported extension",
        "unknowncertificateextension",
        "unknown certificate extension",
        "compressedcertificate",
        "compressed certificate",
    ]
    .iter()
    .any(|m| msg_lower.contains(m))
}

/// The detail for a message nothing else classified: a named TLS-stack failure
/// carries the rustls name it was classified by, anything else keeps its own
/// words.
fn unclassified_detail(msg_lower: &str, raw: &str) -> Detail {
    if is_unimplemented_element(msg_lower) {
        return Detail::Other(short_detail(raw));
    }
    match stack::from_message(msg_lower) {
        Some(kind) => stack::detail_for(kind),
        None => Detail::Other(short_detail(raw)),
    }
}

/// The verdict for a message that reports a peer alert: the description it names
/// decides the detail.
///
/// `protocol_version` is the exception — a peer that refuses the version is
/// answering about the offer itself, so it reports as a block rather than as an
/// alert (see [`crate::classify::detail::AlertKind`]). A message that names no
/// description leaves `None` to the caller, which then reports the generic
/// alert.
fn alert_verdict(msg_lower: &str) -> Option<(DpiStatus, Detail)> {
    let kind = alert::from_message(msg_lower)?;
    let status = if kind == AlertKind::ProtocolVersion {
        DpiStatus::TlsBlock
    } else {
        DpiStatus::TlsAlert
    };
    Some((status, alert::detail_for(kind)))
}

/// Classifies an SSL/TLS error message into a status plus detail string: a
/// handshake reset, a spoofed or garbled record, a fatal alert, a certificate
/// failure, a premature EOF or a missing TLS 1.3. Anything unrecognised stays
/// `Unknown` with the error text shortened.
pub fn classify_ssl_error(
    err_msg: &str,
    bytes_read: usize,
    stage: ConnectionStage,
) -> (DpiStatus, Detail) {
    let msg = err_msg.to_ascii_lowercase();

    if msg.contains("pop from an empty deque") || msg.contains("brokenresourceerror") {
        return (DpiStatus::TlsRst, Detail::RstHello);
    }

    if msg.contains("wrong version number") || msg.contains("wrong_version_number") {
        return (DpiStatus::TlsSpoof, Detail::WrongVersion);
    }
    if ["record overflow", "oversized", "record layer failure", "decode error", "decoding error", "illegal parameter", "bad record", "invalid record"]
        .iter()
        .any(|m| msg.contains(m))
    {
        return (DpiStatus::TlsSpoof, Detail::GarbageData);
    }

    if msg.contains("unrecognized_name") || msg.contains("unrecognized name") {
        return (DpiStatus::TlsAlert, Detail::SniBlockUnrecognizedName);
    }
    if msg.contains("alert(") || msg.contains("fatal alert") || msg.contains("received alert") {
        if let Some(verdict) = alert_verdict(&msg) {
            return verdict;
        }
        return (DpiStatus::TlsAlert, Detail::FakeTlsAlert);
    }

    if msg.contains("protocol_version") || msg.contains("protocol version") {
        return (DpiStatus::TlsBlock, Detail::ProtocolVersionAlert);
    }
    if msg.contains("alert") && (msg.contains("handshake") || msg.contains("ssl") || msg.contains("tls") || msg.contains("certificate")) {
        if let Some(verdict) = alert_verdict(&msg) {
            return verdict;
        }
        return (DpiStatus::TlsAlert, Detail::FakeTlsAlert);
    }
    // A message about a protocol element our own TLS stack does not implement is
    // not evidence about the network (see `is_unimplemented_element`). Real
    // interference still lands in the branches above: a censor's spoofed
    // ServerHello arrives as a version/record/alert error.
    if is_unimplemented_element(&msg) {
        return (DpiStatus::Unknown, Detail::Other(short_detail(err_msg)));
    }

    if msg.contains("certificate") || msg.contains("unknown ca") || msg.contains("self-signed") || msg.contains("self signed") {
        if msg.contains("unable to get local issuer certificate") || msg.contains("unknownissuer") {
            return (DpiStatus::NoCa, Detail::NoRootCa);
        }
        if msg.contains("expired") {
            return (DpiStatus::TlsErr, Detail::CertExpired);
        }
        if msg.contains("self-signed") || msg.contains("self signed") {
            return (DpiStatus::TlsErr, Detail::SelfSigned);
        }
        if msg.contains("hostname") || msg.contains("not valid for") || msg.contains("name mismatch") {
            return (DpiStatus::TlsErr, Detail::HostnameMismatch);
        }
        return (DpiStatus::TlsErr, Detail::FakeCert);
    }

    if ["eof", "unexpected eof", "eof occurred", "operation did not complete", "want_read", "want read", "connection closed", "closed connection", "incomplete"]
        .iter()
        .any(|m| msg.contains(m))
    {
        // RST masked by OS as EOF during handshake in 99% of cases
        if bytes_read == 0 || stage == ConnectionStage::TlsClientHelloSent {
            return (DpiStatus::TlsRst, Detail::RstHello);
        }
        let detail = if bytes_read > 0 {
            Detail::TransferEof
        } else {
            Detail::HandshakeEof
        };
        return (DpiStatus::TlsEof, detail);
    }

    if msg.contains("no tls 1.3")
        || msg.contains("no tls1.3")
        || msg.contains("server has no tls 1.3")
        || msg.contains("servertlsversion")
        || msg.contains("server_tls_version")
        || msg.contains("tls_version_is_different")
        || msg.contains("peer is incompatible")
    {
        return (DpiStatus::NoTls13, Detail::NoTls13);
    }

    (DpiStatus::Unknown, unclassified_detail(&msg, err_msg))
}

fn dns_failure_text(msg: &str) -> bool {
    const MARKERS: &[&str] = &[
        "failed to lookup", "name resolution", "nodename nor servname",
        "name or service not known", "no such host", "host not found",
        "getaddrinfo", "dns", "resolve",
    ];
    MARKERS.iter().any(|m| msg.contains(m))
}

/// The verdict for a timeout at `stage`.
///
/// Both the message-text path and the OS-code path land here: a `WSAETIMEDOUT`
/// (10060) on a reading stage is the same drop as one whose text said "timed
/// out", and while the two branches were written separately the code path had
/// lost the `sending_data` / `reading_data` arms, so the same condition was
/// reported as a bare `Timeout` on one path and as `SendTimeout`/`ReadTimeout`
/// on the other.
fn timeout_at_stage(stage: &str) -> (DpiStatus, Detail) {
    match stage {
        "tls_handshake" => (DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout),
        "tcp_connect" => (DpiStatus::SynDropped, Detail::TcpSynTimeout),
        "sending_data" => (DpiStatus::SendTimeout, Detail::SendTimeout),
        "reading_data" => (DpiStatus::ReadTimeout, Detail::ReadTimeout),
        _ => (DpiStatus::Timeout, Detail::TimeoutStage { stage: stage.to_string() }),
    }
}

/// The errno values of the unreachable family, taken from the platform.
///
/// These are the only two the classifier needs as numbers. Refused, reset,
/// aborted and timed out all arrive as their own stable `ErrorKind` on every
/// platform, but `io::ErrorKind::HostUnreachable`/`NetworkUnreachable` are
/// behind `io_error_more`, so these two rested on the message text — and a
/// wording the check does not spell falls through to `os_err`.
///
/// The numbers are not portable and must not be written down by hand: Linux
/// keeps its own table for MIPS (148/128), SPARC (65/51), PA-RISC (242/229) and
/// Alpha, while the rest of the architectures share the generic one (113/101);
/// macOS has its own (65/51). `libc` knows the target's table, so the Unix side
/// asks it. Windows is the exception: a socket error there is a `WSA*` code,
/// which `libc` does not carry — it has the CRT's `errno` values (110/118),
/// a different number space — so those two stay written out.
#[cfg(windows)]
const NET_UNREACH: i32 = 10051; // WSAENETUNREACH
#[cfg(not(windows))]
const NET_UNREACH: i32 = libc::ENETUNREACH;
#[cfg(windows)]
const HOST_UNREACH: i32 = 10065; // WSAEHOSTUNREACH
#[cfg(not(windows))]
const HOST_UNREACH: i32 = libc::EHOSTUNREACH;
#[cfg(windows)]
const NET_DOWN: i32 = 10050; // WSAENETDOWN
#[cfg(not(windows))]
const NET_DOWN: i32 = libc::ENETDOWN;
#[cfg(windows)]
const HOST_DOWN: i32 = 10064; // WSAEHOSTDOWN
#[cfg(not(windows))]
const HOST_DOWN: i32 = libc::EHOSTDOWN;

/// Classifies a TCP connection error: pool exhaustion, timeouts, DNS failures,
/// TLS alerts surfacing inside connect errors, refusals, resets, aborts and
/// unreachable hosts/routes.
/// `stage` is one of "tcp_connect", "tls_handshake", "tls_connected",
/// "sending_data", "reading_data" and picks the stage-specific verdict.
pub fn classify_connect_error_full(
    err_msg: &str,
    raw_os_error: Option<i32>,
    kind: Option<io::ErrorKind>,
    bytes_read: usize,
    stage: &str,
) -> (DpiStatus, Detail) {
    let full = err_msg.to_ascii_lowercase();

    if full.contains("pool timeout") || full.contains("pool exhausted") || full.contains("connection pool") {
        return (DpiStatus::PoolTimeout, Detail::PoolTimeout);
    }

    if full.contains("connect timeout") || full.contains("connection timed out") || full.contains("timed out") || full.contains("timeout") {
        return timeout_at_stage(stage);
    }

    // DNS resolution failures (socket.gaierror equivalent)
    if dns_failure_text(&full) {
        if full.contains("no such host") || full.contains("not found") || full.contains("noname") || full.contains("nxdomain") {
            return (DpiStatus::DnsFail, Detail::DomainNotFound);
        }
        if full.contains("again") || full.contains("timeout") || full.contains("unavailable") {
            return (DpiStatus::DnsFail, Detail::DnsTimeoutUnavailable);
        }
        return (DpiStatus::DnsFail, Detail::DnsError);
    }

    // TLS alerts surfacing inside connect errors (DPI)
    if full.contains("sslv3_alert") || full.contains("ssl alert") || (full.contains("alert") && full.contains("handshake")) {
        if let Some(verdict) = alert_verdict(&full) {
            return verdict;
        }
        return (DpiStatus::TlsAlert, Detail::FakeTlsAlert);
    }
    if full.contains("certificate") || full.contains("unknown ca") {
        let (s, d) = classify_ssl_error(err_msg, bytes_read, ConnectionStage::TlsClientHelloSent);
        if s != DpiStatus::Unknown {
            return (s, d);
        }
    }

    let refused = kind == Some(io::ErrorKind::ConnectionRefused)
        || matches!(raw_os_error, Some(111) | Some(10061))
        || full.contains("refused")
        || full.contains("all connection attempts failed");
    if refused {
        return (DpiStatus::Refused, Detail::ConnRefused);
    }

    let reset = kind == Some(io::ErrorKind::ConnectionReset)
        || matches!(raw_os_error, Some(104) | Some(10054) | Some(54))
        || full.contains("connection reset")
        || full.contains("reset by peer")
        || full.contains("broken pipe")
        || full.contains("brokenpipe");
    if reset {
        return match stage {
            "tls_handshake" => (DpiStatus::TlsRst, Detail::RstHello),
            "tls_connected" => (DpiStatus::TlsRst, Detail::RstAfterHandshake),
            _ => (DpiStatus::TcpRst, Detail::ConnReset),
        };
    }

    let aborted = kind == Some(io::ErrorKind::ConnectionAborted)
        || matches!(raw_os_error, Some(103) | Some(10053))
        || full.contains("connection aborted")
        || full.contains("software caused connection abort");
    if aborted {
        return match stage {
            "tls_handshake" | "tls_connected" => {
                (DpiStatus::TlsAbort, Detail::Aborted)
            }
            _ => (DpiStatus::TcpAbort, Detail::TcpAborted),
        };
    }

    let timed_out = kind == Some(io::ErrorKind::TimedOut)
        || matches!(raw_os_error, Some(110) | Some(10060))
        || full.contains("timed out");
    if timed_out {
        return timeout_at_stage(stage);
    }

    if matches!(raw_os_error, Some(NET_UNREACH) | Some(NET_DOWN)) || full.contains("network is unreachable") || full.contains("network is down") {
        return (DpiStatus::NetUnreach, Detail::NetUnreach);
    }
    if matches!(raw_os_error, Some(HOST_UNREACH) | Some(HOST_DOWN)) || full.contains("no route to host") || full.contains("host is down") {
        return (DpiStatus::HostUnreach, Detail::HostUnreach);
    }

    if let Some(code) = raw_os_error {
        return (DpiStatus::OsErr, Detail::Other(format!("OS errno {}", code)));
    }

    (DpiStatus::Unknown, unclassified_detail(&full, err_msg))
}

/// Classifies a connect failure, refining the unreachable family with the ICMP
/// message the kernel queued for it.
///
/// `EHOSTUNREACH` is one errno for a whole family of ICMP verdicts: "host
/// unreachable", "host administratively prohibited" — what a provider's filter
/// answers with — and the rest of the destination-unreachable codes all arrive
/// as the same number. A caller that has the queued message passes it in; a
/// caller that does not gets the errno's own verdict.
pub fn classify_connect_error_icmp(
    err: &io::Error,
    icmp: Option<IcmpCode>,
    bytes_read: usize,
    stage: &str,
) -> (DpiStatus, Detail) {
    let (status, detail) = classify_connect_error_full(
        &err.to_string(),
        err.raw_os_error(),
        Some(err.kind()),
        bytes_read,
        stage,
    );
    let refined = match (icmp, status) {
        (Some(code), DpiStatus::HostUnreach | DpiStatus::NetUnreach)
            if code == IcmpCode::ADMIN_PROHIBITED =>
        {
            Detail::IcmpAdminProhibited
        }
        _ => detail,
    };
    (status, refined)
}

/// Legacy io::Error-based entry point (stage unknown → tcp_connect).
pub fn classify_connect_error(err: Option<&io::Error>, is_timeout: bool) -> (DpiStatus, Detail) {
    if is_timeout {
        return (DpiStatus::SynDropped, Detail::TcpSynTimeout);
    }
    match err {
        Some(e) => {
            let msg = e.to_string();
            classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tcp_connect")
        }
        None => (DpiStatus::Unknown, Detail::UnknownConnectionFailure),
    }
}

/// Classifies a TLS / L7 error using the connection stage and byte counters.
pub fn classify_tls_error(
    stage: ConnectionStage,
    bytes_sent: usize,
    bytes_recv: usize,
    err_msg: &str,
    is_timeout: bool,
) -> (DpiStatus, Detail) {
    if is_timeout {
        if stage == ConnectionStage::TlsClientHelloSent || (bytes_sent > 0 && bytes_recv == 0) {
            return (
                DpiStatus::TlsDropped,
                Detail::TlsDropHandshake,
            );
        }
        return (DpiStatus::Timeout, Detail::TimeoutConn);
    }

    let stage_name = if is_tls_stage(stage) || stage == ConnectionStage::TcpConnected {
        if stage == ConnectionStage::TcpConnected {
            "tls_handshake"
        } else if stage == ConnectionStage::TlsHandshakeDone {
            "tls_connected"
        } else {
            "tls_handshake"
        }
    } else if stage == ConnectionStage::HttpPayload {
        "tls_connected"
    } else {
        "tcp_connect"
    };

    // First try SSL-specific classification for alert/cert/spoof texts
    let (ssl_status, ssl_detail) = classify_ssl_error(err_msg, bytes_recv, stage);
    if ssl_status != DpiStatus::Unknown {
        return (ssl_status, ssl_detail);
    }

    let (status, detail) =
        classify_connect_error_full(err_msg, None, None, bytes_recv, stage_name);

    // A reset/EOF after ClientHello with zero bytes back is a DPI SNI RST,
    // even when the OS masks it as a generic error.
    if status == DpiStatus::Unknown {
        let lower = err_msg.to_ascii_lowercase();
        if (stage == ConnectionStage::TlsClientHelloSent || (bytes_sent > 0 && bytes_recv == 0))
            && (lower.contains("reset")
                || lower.contains("eof")
                || lower.contains("closed")
                || lower.contains("abort")
                || lower.contains("broken pipe")
                || lower.contains("10054")
                || lower.contains(" 104"))
        {
            return (
                DpiStatus::TlsRst,
                Detail::TlsRstHello,
            );
        }

        // The stack's own wording survives as a detail; anything else keeps its
        // own words under the TLS label.
        return match stack::from_message(&lower) {
            Some(kind) if !is_unimplemented_element(&lower) => {
                (DpiStatus::Unknown, stack::detail_for(kind))
            }
            _ => (DpiStatus::Unknown, Detail::Other(format!("TLS error: {}", short_detail(err_msg)))),
        };
    }
    (status, detail)
}

/// Classifies an HTTP-layer read failure, i.e. one raised while reading the
/// response body ("reading_data"). `raw_os_error`/`kind` come from the `io::Error`
/// at the end of the hyper error chain: Windows localizes that message
/// ("Удаленный хост принудительно разорвал существующее подключение" is
/// WSAECONNRESET), so the numeric code is the signal classification can trust.
pub fn classify_read_error(
    err_msg: &str,
    raw_os_error: Option<i32>,
    kind: Option<io::ErrorKind>,
    bytes_read: usize,
) -> (DpiStatus, Detail) {
    let (status, detail) =
        classify_connect_error_full(err_msg, raw_os_error, kind, bytes_read, "reading_data");
    if status == DpiStatus::Unknown {
        return (DpiStatus::Unknown, unclassified_detail(&err_msg.to_ascii_lowercase(), err_msg));
    }
    (status, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OS message for WSAECONNRESET is localized ("Удаленный хост
    /// принудительно разорвал существующее подключение" on a Russian Windows),
    /// so the numeric code and the `ErrorKind` from the error chain - not the
    /// text - are what identify a reset. Dropping them, as the hyper wrappers
    /// used to, turned a plain RST into `UNKNOWN` plus the raw system text.
    #[test]
    fn test_reset_classified_from_os_code_not_text() {
        let localized =
            "connection error | Удаленный хост принудительно разорвал существующее подключение";
        let (s, d) =
            classify_read_error(localized, Some(10054), Some(io::ErrorKind::ConnectionReset), 0);
        assert_eq!(s, DpiStatus::TcpRst);
        assert_eq!(d, Detail::ConnReset);

        let (s, _) = classify_read_error(localized, None, None, 0);
        assert_eq!(s, DpiStatus::Unknown, "the localized text alone is unrecognisable");
    }

    #[test]
    fn test_classify_connect_error() {
        let err = io::Error::from_raw_os_error(111);
        let (s, _) = classify_connect_error(Some(&err), false);
        assert_eq!(s, DpiStatus::Refused);

        let (s, _) = classify_connect_error(None, true);
        assert_eq!(s, DpiStatus::SynDropped);
    }

    #[test]
    fn test_classify_ssl_error() {
        let (s, _) = classify_ssl_error(
            "tls: server returned wrong version number",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::TlsSpoof);

        let (s, _) = classify_ssl_error(
            "ssl alert handshake failure",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::TlsAlert);

        let (s, _) = classify_ssl_error(
            "certificate verify failed: self-signed",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::TlsErr);

        let (s, _) = classify_ssl_error(
            "certificate verify failed: unable to get local issuer certificate",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::NoCa);

        let (s, d) = classify_ssl_error(
            "peer is incompatible: ServerTlsVersionIsDifferent(Tls12)",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::NoTls13);
        assert_eq!(d, Detail::NoTls13);

        let (s, _) = classify_ssl_error(
            "unexpected EOF",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::TlsRst);
    }

    #[test]
    fn test_a_named_alert_carries_its_description() {
        let (s, d) = classify_ssl_error(
            "connection error | received fatal alert: UnexpectedMessage",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!((s, d.code().as_ref()), (DpiStatus::TlsAlert, "alert_unexpected_message"));

        let (s, d) = classify_ssl_error(
            "received fatal alert: IllegalParameter",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!((s, d.code().as_ref()), (DpiStatus::TlsAlert, "alert_illegal_parameter"));

        // A peer that refuses the version is answering about the offer itself,
        // so that description stays a block rather than an alert.
        let (s, d) = classify_ssl_error(
            "received fatal alert: ProtocolVersion",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!((s, d.code().as_ref()), (DpiStatus::TlsBlock, "protocol_version_alert"));

        // A named description reached through the connect-error path takes the
        // same detail as through the ssl error one.
        let (s, d) = classify_connect_error_full(
            "sslv3 alert bad certificate",
            None,
            None,
            0,
            "tls_handshake",
        );
        assert_eq!((s, d.code().as_ref()), (DpiStatus::TlsAlert, "alert_bad_certificate"));

        // An alert whose description the peer did not name keeps the generic one.
        let (s, d) =
            classify_ssl_error("fatal alert received", 0, ConnectionStage::TlsClientHelloSent);
        assert_eq!((s, d.code().as_ref()), (DpiStatus::TlsAlert, "fake_tls_alert"));
    }

    #[test]
    fn test_engine_protocol_errors_are_not_interception() {
        // rustls words its own unimplemented-element errors with "certificate"
        // (`got CompressedCertificate when expecting Certificate`,
        // `UnknownCertificateExtension`). Those must stay unclassified instead of
        // being reported as a certificate error, while real certificate failures
        // keep their verdict (covered above).
        for msg in [
            "received unexpected handshake message: got CompressedCertificate when expecting Certificate or CertificateRequest",
            "received corrupt message of type UnknownCertificateExtension",
        ] {
            let (s, d) = classify_ssl_error(msg, 0, ConnectionStage::TlsClientHelloSent);
            assert_eq!(s, DpiStatus::Unknown, "{msg} -> {}", d.code());
            // Our stack lacking a feature is not a peer failure: the message
            // keeps its own words instead of taking a stack failure's name.
            assert!(matches!(d, Detail::Other(_)), "{msg} -> {}", d.code());
        }

        // A peer that broke the protocol is a stack failure the reader can name,
        // but still not evidence of interception: the status stays Unknown.
        let (s, d) = classify_ssl_error(
            "peer misbehaved: UnsolicitedServerHelloExtension",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!((s, d.code().as_ref()), (DpiStatus::Unknown, "tls_peer_misbehaved"));
    }

    /// A record that will not decrypt is the signature of an injected or
    /// rewritten record, and it used to reach the table as the rustls sentence
    /// in English. It now carries the stack failure's name; the status stays
    /// Unknown because a buggy server produces the same message.
    #[test]
    fn test_a_stack_failure_is_named_not_quoted() {
        let observed = "connection error | cannot decrypt peer's message";
        let (s, d) = classify_read_error(observed, None, None, 0);
        assert_eq!((s, d.code().as_ref()), (DpiStatus::Unknown, "tls_decrypt_error"));

        // The same wording through the TLS path keeps the same detail.
        let (s, d) = classify_tls_error(
            ConnectionStage::TlsClientHelloSent,
            100,
            0,
            observed,
            false,
        );
        assert_eq!((s, d.code().as_ref()), (DpiStatus::Unknown, "tls_decrypt_error"));

        // A message naming nothing known keeps its own words.
        let (s, d) = classify_read_error("connection error | oops", None, None, 0);
        assert_eq!(s, DpiStatus::Unknown);
        assert_eq!(d.code().as_ref(), "connection error | oops");
    }

    #[test]
    fn test_stage_aware_reset() {
        let (s, _) = classify_connect_error_full(
            "Connection reset by peer (os error 104)",
            Some(104),
            None,
            0,
            "tls_handshake",
        );
        assert_eq!(s, DpiStatus::TlsRst);

        let (s, _) = classify_connect_error_full(
            "Connection reset by peer (os error 104)",
            Some(104),
            None,
            0,
            "tcp_connect",
        );
        assert_eq!(s, DpiStatus::TcpRst);
    }

    /// An OS timeout carries no "timeout" in its text on Windows (WSAETIMEDOUT
    /// is "A connection attempt failed because the connected party did not
    /// properly respond…"), so the OS-code path has to reach the same verdict as
    /// the text path — including the send/read stages, which the second branch
    /// used to collapse into a bare `Timeout`.
    #[test]
    fn test_os_timeout_keeps_the_stage() {
        let (s, _) = classify_connect_error_full(
            "connection error",
            Some(10060),
            None,
            0,
            "reading_data",
        );
        assert_eq!(s, DpiStatus::ReadTimeout);

        let (s, _) = classify_connect_error_full(
            "connection error",
            Some(110),
            Some(io::ErrorKind::TimedOut),
            0,
            "sending_data",
        );
        assert_eq!(s, DpiStatus::SendTimeout);

        let (s, _) = classify_connect_error_full(
            "connection error",
            Some(10060),
            None,
            0,
            "tls_handshake",
        );
        assert_eq!(s, DpiStatus::TlsDropped);
    }

    #[test]
    fn test_dns_fail() {
        let (s, _) = classify_connect_error_full(
            "failed to lookup address information",
            None,
            None,
            0,
            "tcp_connect",
        );
        assert_eq!(s, DpiStatus::DnsFail);
    }

    /// The unreachable family is decided by the errno alone: Rust has no stable
    /// `ErrorKind` for either case, so a bare code with no message must still
    /// reach the status instead of falling through to `OsErr`.
    #[test]
    fn unreachable_errnos_classify_without_a_message() {
        let (s, d) = classify_connect_error_full("", Some(NET_UNREACH), None, 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::NetUnreach, Detail::NetUnreach));
        let (s, d) = classify_connect_error_full("", Some(HOST_UNREACH), None, 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::HostUnreach, Detail::HostUnreach));
    }

    /// "Down" is the same family as "unreachable" — the network or the host is
    /// not there at all. A router with a flapping uplink meets `ENETDOWN`, and
    /// reading it as an anonymous OS error hides the one thing a reader needs.
    #[test]
    fn down_and_unreachable_share_a_status() {
        let (s, d) = classify_connect_error_full("", Some(NET_DOWN), None, 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::NetUnreach, Detail::NetUnreach));
        let (s, d) = classify_connect_error_full("", Some(HOST_DOWN), None, 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::HostUnreach, Detail::HostUnreach));
        let (s, _) = classify_connect_error_full("Network is down (os error 100)", None, None, 0, "tcp_connect");
        assert_eq!(s, DpiStatus::NetUnreach);
    }

    /// `EHOSTUNREACH` on its own cannot say whether the route or a filter
    /// refused the flow; the queued ICMP message can, and only the
    /// administratively prohibited code earns its own detail.
    #[test]
    fn the_queued_icmp_message_refines_an_unreachable_host() {
        let err = io::Error::from_raw_os_error(HOST_UNREACH);

        let (s, d) =
            classify_connect_error_icmp(&err, Some(IcmpCode::ADMIN_PROHIBITED), 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::HostUnreach, Detail::IcmpAdminProhibited));

        let host_unreachable = IcmpCode { icmp_type: 3, icmp_code: 1 };
        let (s, d) = classify_connect_error_icmp(&err, Some(host_unreachable), 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::HostUnreach, Detail::HostUnreach));

        let (s, d) = classify_connect_error_icmp(&err, None, 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::HostUnreach, Detail::HostUnreach));
    }

    /// The message refines an unreachable verdict and nothing else: a reset that
    /// happens to carry an ICMP message is still a reset.
    #[test]
    fn a_queued_message_does_not_override_another_verdict() {
        let err = io::Error::from_raw_os_error(104);
        let (s, d) =
            classify_connect_error_icmp(&err, Some(IcmpCode::ADMIN_PROHIBITED), 0, "tcp_connect");
        assert_eq!((s, d), (DpiStatus::TcpRst, Detail::ConnReset));
    }

    /// The routers are MIPS, where the numbers are 148 and 128 and not the 113
    /// and 101 of the generic table. Asserted against `libc` rather than
    /// hardcoded, so this also checks that the constants come from the target.
    #[cfg(any(target_arch = "mips", target_arch = "mips64"))]
    #[test]
    fn the_mips_table_is_the_one_the_routers_use() {
        assert_eq!(libc::EHOSTUNREACH, 148);
        assert_eq!(libc::ENETUNREACH, 128);
        let (s, _) = classify_connect_error_full("", Some(148), None, 0, "tcp_connect");
        assert_eq!(s, DpiStatus::HostUnreach);
        let (s, _) = classify_connect_error_full("", Some(128), None, 0, "tcp_connect");
        assert_eq!(s, DpiStatus::NetUnreach);
    }
}


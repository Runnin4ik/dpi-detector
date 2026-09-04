use std::io;
use super::constants::*;
use super::types::{ConnectionStage, DpiStatus};

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

/// Classifies an SSL/TLS error message (mirrors Python `classify_ssl_error`).
pub fn classify_ssl_error(
    err_msg: &str,
    bytes_read: usize,
    stage: ConnectionStage,
) -> (DpiStatus, String) {
    let msg = err_msg.to_ascii_lowercase();

    if msg.contains("pop from an empty deque") || msg.contains("brokenresourceerror") {
        return (DpiStatus::TlsRst, DET_RST_HELLO.into());
    }

    if msg.contains("wrong version number") || msg.contains("wrong_version_number") {
        return (DpiStatus::TlsSpoof, DET_WRONG_VERSION.into());
    }
    if ["record overflow", "oversized", "record layer failure", "decode error", "decoding error", "illegal parameter", "bad record", "invalid record"]
        .iter()
        .any(|m| msg.contains(m))
    {
        return (DpiStatus::TlsSpoof, DET_GARBAGE_DATA.into());
    }

    if msg.contains("unrecognized_name") || msg.contains("unrecognized name") {
        return (DpiStatus::TlsAlert, DET_SNI_BLOCK_UNREC.into());
    }
    if msg.contains("alert(") || msg.contains("fatal alert") || msg.contains("received alert") {
        if msg.contains("handshakefailure") || msg.contains("handshake failure") {
            return (DpiStatus::TlsAlert, DET_DPI_ALERT_HS_FAIL.into());
        }
        if msg.contains("unrecognized_name") || msg.contains("unrecognized name") {
            return (DpiStatus::TlsAlert, DET_SNI_BLOCK_UNREC.into());
        }
        if msg.contains("protocol_version") || msg.contains("protocol version") {
            return (DpiStatus::TlsBlock, DET_PROTOCOL_VERSION_ALERT.into());
        }
        return (DpiStatus::TlsAlert, DET_FAKE_TLS_ALERT.into());
    }

    if msg.contains("protocol_version") || msg.contains("protocol version") {
        return (DpiStatus::TlsBlock, DET_PROTOCOL_VERSION_ALERT.into());
    }
    if msg.contains("alert") && (msg.contains("handshake") || msg.contains("ssl") || msg.contains("tls") || msg.contains("certificate")) {
        return (DpiStatus::TlsAlert, DET_FAKE_TLS_ALERT.into());
    }
    if msg.contains("certificate") || msg.contains("unknown ca") || msg.contains("self-signed") || msg.contains("self signed") {
        if msg.contains("unable to get local issuer certificate") || msg.contains("unknownissuer") {
            return (DpiStatus::NoCa, DET_NO_ROOT_CA.into());
        }
        if msg.contains("expired") {
            return (DpiStatus::TlsMitm, DET_CERT_EXPIRED.into());
        }
        if msg.contains("self-signed") || msg.contains("self signed") {
            return (DpiStatus::TlsMitm, DET_SELF_SIGNED.into());
        }
        if msg.contains("hostname") || msg.contains("not valid for") || msg.contains("name mismatch") {
            return (DpiStatus::TlsMitm, DET_HOSTNAME_MISMATCH.into());
        }
        return (DpiStatus::TlsMitm, DET_FAKE_CERT.into());
    }

    if ["eof", "unexpected eof", "eof occurred", "operation did not complete", "want_read", "want read", "connection closed", "closed connection", "incomplete"]
        .iter()
        .any(|m| msg.contains(m))
    {
        // RST masked by OS as EOF during handshake in 99% of cases
        if bytes_read == 0 || stage == ConnectionStage::TlsClientHelloSent {
            return (DpiStatus::TlsRst, DET_RST_HELLO.into());
        }
        let detail = if bytes_read > 0 {
            DET_TRANSFER_EOF
        } else {
            DET_HANDSHAKE_EOF
        };
        return (DpiStatus::TlsEof, detail.into());
    }

    if msg.contains("no tls 1.3") || msg.contains("no tls1.3") || msg.contains("server has no tls 1.3") {
        return (DpiStatus::NoTls13, DET_NO_TLS13.into());
    }

    (DpiStatus::Unknown, short_detail(err_msg))
}

fn dns_failure_text(msg: &str) -> bool {
    const MARKERS: &[&str] = &[
        "failed to lookup", "name resolution", "nodename nor servname",
        "name or service not known", "no such host", "host not found",
        "getaddrinfo", "dns", "resolve",
    ];
    MARKERS.iter().any(|m| msg.contains(m))
}

/// Classifies a TCP connection error (mirrors Python `classify_connect_error`).
/// `stage` uses Python stage names: "tcp_connect", "tls_handshake",
/// "tls_connected", "sending_data", "reading_data".
pub fn classify_connect_error_full(
    err_msg: &str,
    raw_os_error: Option<i32>,
    kind: Option<io::ErrorKind>,
    bytes_read: usize,
    stage: &str,
) -> (DpiStatus, String) {
    let full = err_msg.to_ascii_lowercase();

    if full.contains("pool timeout") || full.contains("pool exhausted") || full.contains("connection pool") {
        return (DpiStatus::PoolTimeout, DET_POOL_TIMEOUT.into());
    }

    if full.contains("connect timeout") || full.contains("connection timed out") || full.contains("timed out") || full.contains("timeout") {
        return match stage {
            "tls_handshake" => (DpiStatus::TlsDropped, DET_TLS_HANDSHAKE_TIMEOUT.into()),
            "tcp_connect" => (DpiStatus::SynDropped, DET_TCP_SYN_TIMEOUT.into()),
            "sending_data" => (DpiStatus::SendTimeout, DET_SEND_TIMEOUT.into()),
            "reading_data" => (DpiStatus::ReadTimeout, DET_READ_TIMEOUT.into()),
            _ => (DpiStatus::Timeout, format!("Timeout ({})", stage)),
        };
    }

    // DNS resolution failures (socket.gaierror equivalent)
    if dns_failure_text(&full) {
        if full.contains("no such host") || full.contains("not found") || full.contains("noname") || full.contains("nxdomain") {
            return (DpiStatus::DnsFail, DET_DOMAIN_NOT_FOUND.into());
        }
        if full.contains("again") || full.contains("timeout") || full.contains("unavailable") {
            return (DpiStatus::DnsFail, DET_DNS_TIMEOUT_UNAVAIL.into());
        }
        return (DpiStatus::DnsFail, DET_DNS_ERROR.into());
    }

    // TLS alerts surfacing inside connect errors (DPI)
    if full.contains("sslv3_alert") || full.contains("ssl alert") || (full.contains("alert") && full.contains("handshake")) {
        if full.contains("handshake_failure") || full.contains("handshake failure") {
            return (DpiStatus::TlsAlert, "Handshake alert".into());
        }
        if full.contains("unrecognized_name") {
            return (DpiStatus::TlsAlert, "SNI alert".into());
        }
        if full.contains("protocol_version") {
            return (DpiStatus::TlsAlert, "Version alert".into());
        }
        return (DpiStatus::TlsAlert, "TLS alert".into());
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
        return (DpiStatus::Refused, DET_CONN_REFUSED.into());
    }

    let reset = kind == Some(io::ErrorKind::ConnectionReset)
        || matches!(raw_os_error, Some(104) | Some(10054) | Some(54))
        || full.contains("connection reset")
        || full.contains("reset by peer")
        || full.contains("broken pipe")
        || full.contains("brokenpipe");
    if reset {
        return match stage {
            "tls_handshake" => (DpiStatus::TlsRst, DET_RST_HELLO.into()),
            "tls_connected" => (DpiStatus::TlsRst, DET_RST_AFTER_HANDSHAKE.into()),
            _ => (DpiStatus::TcpRst, DET_CONN_RESET.into()),
        };
    }

    let aborted = kind == Some(io::ErrorKind::ConnectionAborted)
        || matches!(raw_os_error, Some(103) | Some(10053))
        || full.contains("connection aborted")
        || full.contains("software caused connection abort");
    if aborted {
        return match stage {
            "tls_handshake" | "tls_connected" => {
                (DpiStatus::TlsAbort, DET_ABORTED.into())
            }
            _ => (DpiStatus::TcpAbort, DET_TCP_ABORTED.into()),
        };
    }

    let timed_out = kind == Some(io::ErrorKind::TimedOut)
        || matches!(raw_os_error, Some(110) | Some(10060))
        || full.contains("timed out");
    if timed_out {
        return match stage {
            "tls_handshake" => (DpiStatus::TlsDropped, DET_TLS_HANDSHAKE_TIMEOUT.into()),
            "tcp_connect" => (DpiStatus::SynDropped, DET_TCP_SYN_TIMEOUT.into()),
            _ => (DpiStatus::Timeout, format!("Timeout ({})", stage)),
        };
    }

    if matches!(raw_os_error, Some(101) | Some(10051)) || full.contains("network is unreachable") {
        return (DpiStatus::NetUnreach, DET_NET_UNREACH.into());
    }
    if matches!(raw_os_error, Some(113) | Some(10065)) || full.contains("no route to host") {
        return (DpiStatus::HostUnreach, DET_HOST_UNREACH.into());
    }

    if let Some(code) = raw_os_error {
        return (DpiStatus::OsErr, format!("OS errno {}", code));
    }

    (DpiStatus::Unknown, short_detail(err_msg))
}

/// Legacy io::Error-based entry point (stage unknown → tcp_connect).
pub fn classify_connect_error(err: Option<&io::Error>, is_timeout: bool) -> (DpiStatus, String) {
    if is_timeout {
        return (DpiStatus::SynDropped, DET_TCP_SYN_TIMEOUT.into());
    }
    match err {
        Some(e) => {
            let msg = e.to_string();
            classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tcp_connect")
        }
        None => (DpiStatus::Unknown, "Unknown connection failure".into()),
    }
}

/// Classifies a TLS / L7 error using the connection stage and byte counters.
pub fn classify_tls_error(
    stage: ConnectionStage,
    bytes_sent: usize,
    bytes_recv: usize,
    err_msg: &str,
    is_timeout: bool,
) -> (DpiStatus, String) {
    if is_timeout {
        if stage == ConnectionStage::TlsClientHelloSent || (bytes_sent > 0 && bytes_recv == 0) {
            return (
                DpiStatus::TlsDropped,
                DET_TLS_DROP_HANDSHAKE.into(),
            );
        }
        return (DpiStatus::Timeout, DET_TIMEOUT_CONN.into());
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
    if status == DpiStatus::Unknown
        && (stage == ConnectionStage::TlsClientHelloSent || (bytes_sent > 0 && bytes_recv == 0))
    {
        let lower = err_msg.to_ascii_lowercase();
        if lower.contains("reset")
            || lower.contains("eof")
            || lower.contains("closed")
            || lower.contains("abort")
            || lower.contains("broken pipe")
            || lower.contains("10054")
            || lower.contains(" 104")
        {
            return (
                DpiStatus::TlsRst,
                DET_TLS_RST_HELLO.into(),
            );
        }
    }

    if status == DpiStatus::Unknown {
        return (DpiStatus::Unknown, format!("TLS error: {}", short_detail(err_msg)));
    }
    (status, detail)
}

/// Classifies HTTP-layer failures (mirrors Python `classify_read_error`
/// for the reading_data stage).
pub fn classify_read_error(err_msg: &str, bytes_read: usize) -> (DpiStatus, String) {
    let (status, detail) =
        classify_connect_error_full(err_msg, None, None, bytes_read, "reading_data");
    if status == DpiStatus::Unknown {
        return (DpiStatus::Unknown, short_detail(err_msg));
    }
    (status, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(s, DpiStatus::TlsMitm);

        let (s, _) = classify_ssl_error(
            "certificate verify failed: unable to get local issuer certificate",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::NoCa);

        let (s, _) = classify_ssl_error(
            "unexpected EOF",
            0,
            ConnectionStage::TlsClientHelloSent,
        );
        assert_eq!(s, DpiStatus::TlsRst);
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
}

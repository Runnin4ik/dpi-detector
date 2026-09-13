//! What a probe observed, as a value instead of a string.
//!
//! Classification used to compare Russian prose (`detail.contains(" at ")`) and
//! the renderer re-derived it by parsing markers out of the string. A detail is now an
//! enum: classification matches variants, `code()` is the machine token that
//! `--json` carries, and the interface layer renders it through an exhaustive
//! `match` (a missing translation is a compile error, not a test failure).
//!
//! Codes are snake_case, and the composed details keep their shape:
//! `read_timeout_at_24kb`, `timeout_20kb`, `timeout_reading_data`, `http_403`,
//! `elapsed_300ms`. Free text from the OS or the TLS stack keeps its own words
//! ([`Detail::Other`]) — it is appended after an already-localized label.

use std::borrow::Cow;

use serde::{Deserialize, Serialize, Serializer};

/// A diagnostic detail. Unit variants carry only prose (rendered by the
/// binary's `i18n::detail_text`); the rest carry the measurement they describe.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Detail {
    /// Nothing to report: the probe passed, or the check did not run.
    #[default]
    None,

    // ─── TCP / TLS stage failures ───
    /// Reset while the ClientHello was on the wire (or right after connect).
    RstHello,
    /// The peer closed the connection right after the ClientHello.
    StreamEofHello,
    /// Reset during connect.
    StreamRstConnect,
    /// ClientHello sent, handshake timed out with nothing received.
    TlsDropHandshake,
    /// Connect timed out.
    TimeoutConn,
    /// Reset after the ClientHello.
    TlsRstHello,

    // ─── TLS alerts and handshake responses ───
    WrongVersion,
    GarbageData,
    /// `unrecognized_name` alert — the SNI itself was rejected.
    SniBlockUnrecognizedName,
    /// `handshake_failure` right after the ClientHello.
    DpiAlertHandshakeFailure,
    ProtocolVersionAlert,
    FakeTlsAlert,
    AlertHandshake,
    AlertSni,
    AlertVersion,
    AlertTls,

    // ─── Certificates ───
    NoRootCa,
    CertExpired,
    SelfSigned,
    HostnameMismatch,
    FakeCert,

    // ─── Transfer endings ───
    TransferEof,
    HandshakeEof,
    NoTls13,

    // ─── Timeouts ───
    PoolTimeout,
    TlsHandshakeTimeout,
    TcpSynTimeout,
    /// Short form used by the Telegram DC ping column.
    SynTimeoutShort,
    SendTimeout,
    ReadTimeout,
    /// `Timeout` used as a word inside a composed detail.
    TimeoutWord,
    /// `Read timeout` used as a word inside a composed detail.
    ReadTimeoutWord,
    /// The same word in the 16–20 KB table, which heads columns in title case.
    ReadTimeoutWordCaps,
    /// `Write Timeout` used as a word inside a composed detail.
    WriteTimeoutWord,

    // ─── DNS ───
    DomainNotFound,
    DnsTimeoutUnavailable,
    DnsError,

    // ─── Connect / transport errors ───
    ConnRefused,
    RstAfterHandshake,
    ConnReset,
    Aborted,
    TcpAborted,
    NetUnreach,
    HostUnreach,
    UnknownConnectionFailure,
    Ipv6Unsupported,
    Ipv6NotSupportedShort,

    // ─── Composed ───
    /// `<head> at <n>KB`: the offset the transfer died at (16–20 KB test).
    AtKb { head: Box<Detail>, kb: f64 },
    /// `<head> <n>KB`: how much got through before the timeout (test 2).
    Kb { head: Box<Detail>, kb: f64 },
    /// `Timeout (<stage>)` for a stage with no dedicated variant.
    TimeoutStage { stage: String },
    /// The resolver answered with an ISP blockpage (`-> <ip>`).
    IspBlockpage { arrow: bool, ip: String },
    /// The resolver answered with a loopback/private address (`-> <ip>`).
    LocalIp { ip: String },
    /// An HTTP status line.
    HttpStatus(u16),
    /// How long a successful check took.
    Elapsed(f64),

    /// Free text (OS error, TLS library message) — not translated.
    Other(String),
}

impl Detail {
    /// The machine token. `--json` carries exactly this; it never changes with
    /// `--lang`.
    pub fn code(&self) -> Cow<'static, str> {
        use Detail::*;
        match self {
            None => Cow::Borrowed(""),
            RstHello => Cow::Borrowed("tcp_rst_on_client_hello"),
            StreamEofHello => Cow::Borrowed("dpi_closed_after_client_hello"),
            StreamRstConnect => Cow::Borrowed("tcp_rst_on_connect"),
            TlsDropHandshake => Cow::Borrowed("tls_drop_handshake"),
            TimeoutConn => Cow::Borrowed("timeout_connection"),
            TlsRstHello => Cow::Borrowed("tls_rst_after_client_hello"),
            WrongVersion => Cow::Borrowed("response_spoofing_wrong_version"),
            GarbageData => Cow::Borrowed("response_spoofing_garbage_data"),
            SniBlockUnrecognizedName => Cow::Borrowed("sni_block_unrecognized_name"),
            DpiAlertHandshakeFailure => Cow::Borrowed("dpi_alert_handshake_failure"),
            ProtocolVersionAlert => Cow::Borrowed("protocol_version_alert"),
            FakeTlsAlert => Cow::Borrowed("fake_tls_alert"),
            AlertHandshake => Cow::Borrowed("handshake_alert"),
            AlertSni => Cow::Borrowed("sni_alert"),
            AlertVersion => Cow::Borrowed("version_alert"),
            AlertTls => Cow::Borrowed("tls_alert"),
            NoRootCa => Cow::Borrowed("no_root_certificates"),
            CertExpired => Cow::Borrowed("cert_expired"),
            SelfSigned => Cow::Borrowed("self_signed_cert"),
            HostnameMismatch => Cow::Borrowed("hostname_mismatch"),
            FakeCert => Cow::Borrowed("cert_spoofing"),
            TransferEof => Cow::Borrowed("transfer_eof"),
            HandshakeEof => Cow::Borrowed("handshake_eof"),
            NoTls13 => Cow::Borrowed("server_has_no_tls13"),
            PoolTimeout => Cow::Borrowed("socket_pool_timeout"),
            TlsHandshakeTimeout => Cow::Borrowed("tls_handshake_timeout"),
            TcpSynTimeout => Cow::Borrowed("tcp_syn_timeout"),
            SynTimeoutShort => Cow::Borrowed("syn_timeout"),
            SendTimeout => Cow::Borrowed("send_timeout"),
            ReadTimeout => Cow::Borrowed("read_timeout"),
            TimeoutWord => Cow::Borrowed("timeout"),
            ReadTimeoutWord | ReadTimeoutWordCaps => Cow::Borrowed("read_timeout_word"),
            WriteTimeoutWord => Cow::Borrowed("write_timeout_word"),
            DomainNotFound => Cow::Borrowed("domain_not_found"),
            DnsTimeoutUnavailable => Cow::Borrowed("dns_timeout_unavailable"),
            DnsError => Cow::Borrowed("dns_error"),
            ConnRefused => Cow::Borrowed("tcp_connection_refused"),
            RstAfterHandshake => Cow::Borrowed("tcp_rst_after_handshake"),
            ConnReset => Cow::Borrowed("tcp_connection_reset"),
            Aborted => Cow::Borrowed("connection_aborted"),
            TcpAborted => Cow::Borrowed("tcp_connection_aborted"),
            NetUnreach => Cow::Borrowed("net_unreachable"),
            HostUnreach => Cow::Borrowed("host_unreachable"),
            UnknownConnectionFailure => Cow::Borrowed("unknown_connection_failure"),
            Ipv6Unsupported => Cow::Borrowed("ipv6_unsupported"),
            Ipv6NotSupportedShort => Cow::Borrowed("ipv6_not_supported"),
            AtKb { head, kb } => Cow::Owned(format!("{}_at_{}", head.code(), kb_token(*kb))),
            Kb { head, kb } => Cow::Owned(format!("{}_{}", head.code(), kb_token(*kb))),
            TimeoutStage { stage } => Cow::Owned(format!("timeout_{}", stage)),
            IspBlockpage { .. } => Cow::Borrowed("isp_blockpage"),
            LocalIp { .. } => Cow::Borrowed("local_ip"),
            HttpStatus(code) => Cow::Owned(format!("http_{}", code)),
            Elapsed(secs) => Cow::Owned(format!("elapsed_{}ms", (secs * 1000.0).round() as u64)),
            Other(text) => Cow::Owned(text.clone()),
        }
    }

    /// True for [`Detail::None`], so call sites read better than `matches!` on
    /// the empty case.
    pub fn is_none(&self) -> bool {
        matches!(self, Detail::None)
    }

    /// Wraps a detail into the `KB` offset form for a transfer that died at
    /// `kb` kilobytes.
    pub fn at_kb(head: Detail, kb: f64) -> Self {
        Detail::AtKb { head: Box::new(head), kb }
    }
}

/// `24` for a whole kilobyte count, `24.4` otherwise: the 16–20 KB test counts
/// whole marks, test 2 measures what got through.
fn kb_token(kb: f64) -> String {
    if kb.fract() == 0.0 {
        format!("{}kb", kb as u64)
    } else {
        format!("{:.1}kb", kb)
    }
}

/// Same rule as [`kb_token`], for display text: the unit is a protocol unit and
/// stays `KB` in every language (Rule 4).
pub fn kb_display(kb: f64) -> String {
    if kb.fract() == 0.0 {
        format!("{}KB", kb as u64)
    } else {
        format!("{:.1}KB", kb)
    }
}

/// `--json` carries the code, never the prose.
impl Serialize for Detail {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.code())
    }
}

/// Details are read back from `--json` for round-trips in tests and tooling.
impl<'de> Deserialize<'de> for Detail {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Detail::Other(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_snake_case_and_distinct() {
        let all = [
            Detail::RstHello,
            Detail::StreamEofHello,
            Detail::TlsDropHandshake,
            Detail::TlsHandshakeTimeout,
            Detail::ReadTimeout,
            Detail::ReadTimeoutWord,
            Detail::WriteTimeoutWord,
            Detail::TimeoutWord,
            Detail::HttpStatus(403),
            Detail::Elapsed(0.3),
        ];
        for d in &all {
            let code = d.code();
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code:?} is not a snake_case token"
            );
        }
        assert_eq!(Detail::HttpStatus(403).code(), "http_403");
        assert_eq!(Detail::Elapsed(0.3).code(), "elapsed_300ms");
        assert_eq!(Detail::None.code(), "");
    }

    #[test]
    fn composed_codes_keep_the_offset() {
        // Whole kilobytes from the 16–20 KB test, measured ones from test 2.
        let at = Detail::at_kb(Detail::TcpAborted, 16.0);
        assert_eq!(at.code(), "tcp_connection_aborted_at_16kb");
        let measured = Detail::Kb { head: Box::new(Detail::TimeoutWord), kb: 20.4 };
        assert_eq!(measured.code(), "timeout_20.4kb");
        assert_eq!(Detail::TimeoutStage { stage: "reading_data".into() }.code(), "timeout_reading_data");
    }
}

//! What a probe observed, as a value instead of a string.
//!
//! Classification used to compare Russian prose (`detail.contains(" at ")`) and
//! the renderer re-derived it by parsing markers out of the string. A detail is now an
//! enum: classification matches variants, `code()` is the machine token that
//! `--json` carries, and the interface layer renders it through an exhaustive
//! `match` (a missing translation is a compile error, not a test failure).
//!
//! Codes are snake_case, and the composed details keep their shape:
//! `read_timeout_at_24kb`, `timeout_reading_data`, `http_403`, `elapsed_300ms`.
//! Free text from the OS or the TLS stack keeps its own words
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
    /// The peer closed the connection right after the ClientHello: the read
    /// returned EOF, where [`Detail::RstHello`] saw a reset. Both are `TlsRst`
    /// with nothing received, so the detail is the only place the wire fact
    /// survives — see `classify/stream.rs`.
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
    /// A peer alert that named its description: the code is
    /// `alert_<description>` (`alert_illegal_parameter`).
    Alert(AlertKind),
    /// A TLS-stack failure that is not an alert from the peer: our own TLS layer
    /// refused the bytes it received — `cannot decrypt peer's message`, `peer
    /// misbehaved: …`. The code is `tls_<kind>`.
    StackFailure(StackKind),

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
    /// `Timeout` used as a word inside a composed detail.
    TimeoutWord,
    /// `Read timeout` used as a word inside a composed detail.
    ReadTimeoutWord,
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
    /// ICMP destination-unreachable / administratively prohibited: the flow was
    /// refused by policy somewhere on the path — in practice a provider's
    /// filter. Kept apart from [`Detail::HostUnreach`] because the two arrive as
    /// the same errno.
    IcmpAdminProhibited,
    UnknownConnectionFailure,
    Ipv6Unsupported,

    // ─── QUIC Initial (test 2) ───
    /// The endpoint answered the QUIC handshake: a ServerHello, or the
    /// HelloRetryRequest that asks for another key share.
    QuicServerHello,
    /// The endpoint answered with a Retry, and its integrity tag checked out
    /// (RFC 9001 §5.8) — so the packet came from the endpoint and not from a
    /// router that decided to imitate one.
    QuicRetry,
    /// A Retry whose integrity tag does not match: only a party that saw the
    /// Initial can compute that tag, so this packet was made by something else
    /// on the path.
    QuicForgedRetry,
    /// The endpoint closed the connection at the QUIC layer. `error_code` is the
    /// transport error of RFC 9000 §20.1 (`8` is
    /// `TRANSPORT_PARAMETER_ERROR`, which is what a server answers a ClientHello
    /// that is not a QUIC one with) or the application's own code in the
    /// application-close form.
    QuicClose { error_code: u64 },
    /// A stateless reset (RFC 9000 §10.3): something answered with no state for
    /// this connection, which a fresh Initial should never meet.
    QuicReset,
    /// The endpoint does not speak v1 and listed the versions it does.
    QuicVersionNegotiation,
    /// Nothing answered the Initial inside the window.
    QuicTimeout,
    /// Something answered the Initial and the reply did not open under the
    /// connection's own Initial keys: measured against Cloudflare's edge, the
    /// packet a first flight meets looks like an Initial (long header, a source
    /// connection ID, a length field) and decrypts under no key the client can
    /// derive — a stock client ignores it and waits for the next flight, and so
    /// does this probe. The path works; the handshake does not start.
    QuicUnreadableReply,
    /// The reply opened, and it carried no handshake data at all — an
    /// acknowledgement and padding, no `CRYPTO` frame — for the whole window,
    /// repeats included. The path works and the endpoint answered; it did not
    /// answer the handshake.
    QuicAnsweredWithoutHandshake,
    /// ICMP said nothing listens on the UDP port.
    QuicPortUnreachable,

    // ─── Composed ───
    /// `<head> at <n>KB`: how far the transfer got — the whole kilobytes the
    /// 16–20 KB test counts, the measured ones test 2 reports.
    AtKb { head: Box<Detail>, kb: f64 },
    /// `Timeout (<stage>)` for a stage with no dedicated variant.
    TimeoutStage { stage: String },
    /// The resolver answered with an ISP blockpage (`-> <ip>`).
    IspBlockpage { arrow: bool, ip: String },
    /// The resolver answered with a loopback/private address (`-> <ip>`).
    LocalIp { ip: String },
    /// The peer redirected to `host`: on the same site family the verdict stays
    /// OK, a foreign one is a red `REDIR`.
    Redirect { host: String },
    /// A hop to `https` on the same host: `-> https`, or `301 -> https` when the
    /// status that carried it is known.
    UpgradeHttps { status: Option<u16> },
    /// An HTTP status line.
    HttpStatus(u16),
    /// How long a successful check took.
    Elapsed(f64),

    /// Free text (OS error, TLS library message) — not translated.
    Other(String),
}

/// One TLS alert description, as the peer that sent the alert named it.
///
/// A peer that refuses a handshake says *why* in the alert's description, and
/// the difference is the diagnosis: `unrecognised_name` is the SNI itself being
/// refused, `handshake_failure` a cipher or version mismatch, `illegal_parameter`
/// a hello the peer could not parse, `internal_error` a server-side fault.
///
/// The names are the IANA registrations (RFC 8446 §6.2, RFC 6066 for
/// `no_application_protocol`, RFC 9001 for `encrypted_client_hello_required`),
/// snake_case. They are protocol tokens, so they stay Latin in every language
/// (Rule 4) and `--json` carries them unchanged inside the detail code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    DecryptionFailed,
    RecordOverflow,
    DecompressionFailure,
    HandshakeFailure,
    NoCertificate,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ExportRestriction,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    InappropriateFallback,
    UserCanceled,
    NoRenegotiation,
    MissingExtension,
    UnsupportedExtension,
    CertificateUnobtainable,
    UnrecognisedName,
    BadCertificateStatusResponse,
    BadCertificateHashValue,
    UnknownPskIdentity,
    CertificateRequired,
    NoApplicationProtocol,
    EncryptedClientHelloRequired,
}

impl AlertKind {
    /// The IANA name, snake_case: the token a [`Detail::Alert`]'s code carries
    /// after `alert_`.
    pub fn code(self) -> &'static str {
        use AlertKind::*;
        match self {
            CloseNotify => "close_notify",
            UnexpectedMessage => "unexpected_message",
            BadRecordMac => "bad_record_mac",
            DecryptionFailed => "decryption_failed",
            RecordOverflow => "record_overflow",
            DecompressionFailure => "decompression_failure",
            HandshakeFailure => "handshake_failure",
            NoCertificate => "no_certificate",
            BadCertificate => "bad_certificate",
            UnsupportedCertificate => "unsupported_certificate",
            CertificateRevoked => "certificate_revoked",
            CertificateExpired => "certificate_expired",
            CertificateUnknown => "certificate_unknown",
            IllegalParameter => "illegal_parameter",
            UnknownCa => "unknown_ca",
            AccessDenied => "access_denied",
            DecodeError => "decode_error",
            DecryptError => "decrypt_error",
            ExportRestriction => "export_restriction",
            ProtocolVersion => "protocol_version",
            InsufficientSecurity => "insufficient_security",
            InternalError => "internal_error",
            InappropriateFallback => "inappropriate_fallback",
            UserCanceled => "user_canceled",
            NoRenegotiation => "no_renegotiation",
            MissingExtension => "missing_extension",
            UnsupportedExtension => "unsupported_extension",
            CertificateUnobtainable => "certificate_unobtainable",
            UnrecognisedName => "unrecognised_name",
            BadCertificateStatusResponse => "bad_certificate_status_response",
            BadCertificateHashValue => "bad_certificate_hash_value",
            UnknownPskIdentity => "unknown_psk_identity",
            CertificateRequired => "certificate_required",
            NoApplicationProtocol => "no_application_protocol",
            EncryptedClientHelloRequired => "encrypted_client_hello_required",
        }
    }
}

/// One failure of our own TLS stack over bytes the peer sent, named as rustls
/// names it.
///
/// These are the messages a middlebox leaves behind when it rewrites or injects
/// records: a record that does not decrypt, a message that arrived out of order,
/// a peer that broke the protocol. rustls words each one differently and the
/// difference is the diagnosis, so they are values, not free text — the free
/// text would be English prose inside a Russian table, and it changes with the
/// rustls version, which no test can pin.
///
/// The names are rustls's own [`Error`] variants, snake_case (see
/// `vendor/rustls/src/error.rs`). They are protocol tokens, so they stay Latin
/// in every language (Rule 4) and `--json` carries them inside the detail code
/// after `tls_`.
///
/// [`Error`]: https://docs.rs/rustls/latest/rustls/enum.Error.html
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackKind {
    /// `cannot decrypt peer's message`: a record we could not open.
    DecryptError,
    /// `received corrupt message of type …`.
    InvalidMessage,
    /// `received unexpected message: got … when expecting …`.
    InappropriateMessage,
    /// `received unexpected handshake message: got … when expecting …`.
    InappropriateHandshakeMessage,
    /// `peer misbehaved: …`.
    PeerMisbehaved,
    /// `peer doesn't support any known protocol`: no ALPN in common.
    NoApplicationProtocol,
}

impl StackKind {
    /// The rustls name, snake_case: the token a [`Detail::StackFailure`]'s code
    /// carries after `tls_`.
    pub fn code(self) -> &'static str {
        use StackKind::*;
        match self {
            DecryptError => "decrypt_error",
            InvalidMessage => "invalid_message",
            InappropriateMessage => "inappropriate_message",
            InappropriateHandshakeMessage => "inappropriate_handshake_message",
            PeerMisbehaved => "peer_misbehaved",
            NoApplicationProtocol => "no_application_protocol",
        }
    }
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
            Alert(kind) => Cow::Owned(format!("alert_{}", kind.code())),
            StackFailure(kind) => Cow::Owned(format!("tls_{}", kind.code())),
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
            TimeoutWord => Cow::Borrowed("timeout"),
            ReadTimeoutWord => Cow::Borrowed("read_timeout_word"),
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
            IcmpAdminProhibited => Cow::Borrowed("icmp_admin_prohibited"),
            UnknownConnectionFailure => Cow::Borrowed("unknown_connection_failure"),
            Ipv6Unsupported => Cow::Borrowed("ipv6_unsupported"),
            QuicServerHello => Cow::Borrowed("quic_server_hello"),
            QuicRetry => Cow::Borrowed("quic_retry"),
            QuicForgedRetry => Cow::Borrowed("quic_forged_retry"),
            QuicClose { error_code } => Cow::Owned(format!("quic_close_{error_code}")),
            QuicReset => Cow::Borrowed("quic_stateless_reset"),
            QuicVersionNegotiation => Cow::Borrowed("quic_version_negotiation"),
            QuicTimeout => Cow::Borrowed("quic_timeout"),
            QuicUnreadableReply => Cow::Borrowed("quic_unreadable_reply"),
            QuicAnsweredWithoutHandshake => Cow::Borrowed("quic_answered_without_handshake"),
            QuicPortUnreachable => Cow::Borrowed("quic_port_unreachable"),
            AtKb { head, kb } => Cow::Owned(format!("{}_at_{}", head.code(), kb_token(*kb))),
            TimeoutStage { stage } => Cow::Owned(format!("timeout_{}", stage)),
            IspBlockpage { .. } => Cow::Borrowed("isp_blockpage"),
            LocalIp { .. } => Cow::Borrowed("local_ip"),
            Redirect { .. } => Cow::Borrowed("redirect_to_host"),
            UpgradeHttps { .. } => Cow::Borrowed("upgrade_https"),
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

/// Same rule as `kb_token`, for display text: the unit is a protocol unit and
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

/// Required by [`ProbeMetrics`](crate::classify::types::ProbeMetrics), which
/// derives `Deserialize`; nothing in this tree reads one back.
///
/// A detail that comes back is [`Detail::Other`] carrying the code, so the
/// machine contract survives a round trip — `code()` of what is read equals
/// `code()` of what was written, for every variant — while the variant itself
/// does not. Reconstructing the variants here would be a second table to keep in
/// step with [`Detail::code`], and one table is the point of having codes.
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
            Detail::ReadTimeoutWord,
            Detail::WriteTimeoutWord,
            Detail::TimeoutWord,
            Detail::HttpStatus(403),
            Detail::Elapsed(0.3),
            Detail::Alert(AlertKind::IllegalParameter),
            Detail::Alert(AlertKind::BadCertificateStatusResponse),
            Detail::StackFailure(StackKind::DecryptError),
            Detail::StackFailure(StackKind::InappropriateHandshakeMessage),
            Detail::Redirect { host: "example.com".into() },
            Detail::UpgradeHttps { status: Some(301) },
            Detail::UpgradeHttps { status: None },
        ];
        for d in &all {
            let code = d.code();
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code:?} is not a snake_case token"
            );
        }
        assert_eq!(Detail::HttpStatus(403).code(), "http_403");
        assert_eq!(Detail::StackFailure(StackKind::DecryptError).code(), "tls_decrypt_error");
        assert_eq!(
            Detail::StackFailure(StackKind::InappropriateHandshakeMessage).code(),
            "tls_inappropriate_handshake_message"
        );
        assert_eq!(Detail::Redirect { host: "example.com".into() }.code(), "redirect_to_host");
        assert_eq!(Detail::UpgradeHttps { status: Some(301) }.code(), "upgrade_https");
        assert_eq!(Detail::Elapsed(0.3).code(), "elapsed_300ms");
        assert_eq!(Detail::None.code(), "");
    }

    #[test]
    fn composed_codes_keep_the_offset() {
        // Whole kilobytes from the 16–20 KB test, measured ones from test 2.
        let at = Detail::at_kb(Detail::TcpAborted, 16.0);
        assert_eq!(at.code(), "tcp_connection_aborted_at_16kb");
        let measured = Detail::at_kb(Detail::TimeoutWord, 20.4);
        assert_eq!(measured.code(), "timeout_at_20.4kb");
        assert_eq!(Detail::TimeoutStage { stage: "reading_data".into() }.code(), "timeout_reading_data");
    }

    /// Every stage the timeout path can name, and the `--json` code each one
    /// composes to. `timeout_at_stage` writes one of `ProbeStage::as_str()`'s
    /// tokens into `Detail::TimeoutStage`, and `code()` spells it
    /// `timeout_<stage>`, so the stage word is half of a frozen machine channel
    /// — one pinned example (`timeout_reading_data`) let the other four be
    /// renamed in silence. The set is listed one by one because the enum cannot
    /// be iterated; a lost variant fails here as a name that no longer resolves,
    /// which is the compile-time half of the pin.
    #[test]
    fn every_timeout_stage_keeps_its_code() {
        use crate::classify::types::ProbeStage;
        for (stage, code) in [
            (ProbeStage::TcpConnect, "timeout_tcp_connect"),
            (ProbeStage::TlsHandshake, "timeout_tls_handshake"),
            (ProbeStage::TlsConnected, "timeout_tls_connected"),
            (ProbeStage::SendingData, "timeout_sending_data"),
            (ProbeStage::ReadingData, "timeout_reading_data"),
        ] {
            let detail = Detail::TimeoutStage { stage: stage.as_str().to_string() };
            assert_eq!(detail.code(), code, "stage {}", stage.as_str());
        }
    }
}

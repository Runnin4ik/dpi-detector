use serde::{Deserialize, Serialize};

use super::detail::Detail;

/// Where a live probe connection has got to, as the byte-counting tracker walks
/// it: a position in a connection that is still open.
///
/// This is NOT the vocabulary a failure is classified with — [`ProbeStage`] is,
/// and the two deliberately do not share a representation. Three of this enum's
/// tokens spell the neighbouring place differently (`tcp_connected` vs
/// `tcp_connect`, `tls_handshake_done` vs `tls_connected`/`tls_handshake`,
/// `http_payload` vs `sending_data`/`reading_data`), because they answer
/// different questions: this one is "how far did it get", the other is "which
/// question is the classifier answering". It is also serialized (it is
/// `ProbeMetrics::stage`), so it is a representation and not an internal
/// detail; merging the two would put the classifier's arms over stages that are
/// not failure sites, and each type names the other here instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStage {
    #[default]
    Init,
    TcpConnecting,
    TcpConnected,
    TlsClientHelloSent,
    TlsHandshakeDone,
    HttpPayload,
}

impl ConnectionStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::TcpConnecting => "tcp_connecting",
            Self::TcpConnected => "tcp_connected",
            Self::TlsClientHelloSent => "tls_client_hello_sent",
            Self::TlsHandshakeDone => "tls_handshake_done",
            Self::HttpPayload => "http_payload",
        }
    }
}

/// The stage a `DnsError::ConnectFault` names, for the resolver sessions that
/// report their own progress words.
///
/// It is a vocabulary of its own only in spelling: three of the four words name
/// a place [`ProbeStage`] already has (`connected` is its `tls_connected`), and
/// [`ProbeStage::of_fault_stage`] is the bridge between them. `resolve` is the
/// caller's own case — the endpoint's own name lookup is a DNS verdict, not a
/// transport one. Before this type the words were string literals in
/// `dns/doh.rs`, `dns/dot.rs` and `dns/resolve.rs`, and the wildcard arm of that
/// bridge decided what an unknown word meant, so a typo classified as `UNKNOWN`
/// in silence.
///
/// `as_str()` is what `DnsError`'s `Display` interpolates (`connection failed at
/// stage resolve: ...`); these are not `--json` tokens — `ProbeStage` is the
/// vocabulary those are composed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectStage {
    /// The endpoint's own name lookup, before any socket was opened.
    Resolve,
    /// The TCP connect: a SYN that was never answered.
    TcpConnect,
    /// Inside the TLS handshake, up to and including the ALPN exchange.
    TlsHandshake,
    /// The socket is up and the session's own protocol could not start — the
    /// HTTP/2 or HTTP/1.1 handshake of a DoH endpoint.
    Connected,
}

impl ConnectStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::TcpConnect => "tcp_connect",
            Self::TlsHandshake => "tls_handshake",
            Self::Connected => "connected",
        }
    }
}

impl std::fmt::Display for ConnectStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a connection was when it failed, as the classifier asks it.
///
/// This is the stage
/// [`classify_connect_error_full`](crate::classify::classifier::classify_connect_error_full)
/// decides its verdict with: the failure is read at the place it happened, so a
/// reset inside the handshake and the same reset after it are different
/// verdicts, and a timeout at `sending_data` says which half of the transfer
/// stalled. It is not [`ConnectionStage`] — that one is a live position the
/// tracker counts bytes between, and it spells three of the same places
/// differently; the classifier never sees a byte count, only the failure. A
/// `&str` here was the defect: the vocabulary lived in doc comments and
/// hand-written literals, so `tls_connected` could be handled on the reset path
/// and silently missed on the timeout path.
///
/// `as_str()` is the token `--json` carries: `Detail::TimeoutStage` composes its
/// code out of it (`timeout_tls_connected`), so these five strings are frozen
/// exactly like a status token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStage {
    /// The TCP connect itself: a SYN that was never answered.
    TcpConnect,
    /// Inside the handshake, up to and including the ClientHello exchange.
    TlsHandshake,
    /// The handshake is done and the request — or its answer — never came.
    TlsConnected,
    /// The request is on the wire and the peer stopped reading.
    SendingData,
    /// The answer is being read and the peer stopped writing.
    ReadingData,
}

impl ProbeStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp_connect",
            Self::TlsHandshake => "tls_handshake",
            Self::TlsConnected => "tls_connected",
            Self::SendingData => "sending_data",
            Self::ReadingData => "reading_data",
        }
    }

    /// The stage a [`ConnectStage`] names in this enum's own vocabulary.
    ///
    /// Only the words that name the same place map over: `connected` is
    /// `tls_connected`. `resolve` is the caller's own case (a DNS verdict, not a
    /// transport one) and is the one stage that answers `None`, which the caller
    /// answers for itself. The match has no wildcard, so a stage added to
    /// `dns::types` is a compile error here rather than a silent `UNKNOWN`.
    pub fn of_fault_stage(stage: ConnectStage) -> Option<Self> {
        match stage {
            ConnectStage::Connected => Some(Self::TlsConnected),
            ConnectStage::TcpConnect => Some(Self::TcpConnect),
            ConnectStage::TlsHandshake => Some(Self::TlsHandshake),
            ConnectStage::Resolve => None,
        }
    }
}

/// An ICMP type/code pair, as the kernel reports it for a failed connection.
///
/// The errno cannot carry this on its own: `EHOSTUNREACH` is the same number for
/// "host unreachable", "administratively prohibited" and the rest of the
/// destination-unreachable family, and the difference decides whether the report
/// blames the route or a filter on the path. A platform that hands the message
/// over (Linux, through `IP_RECVERR`) fills this in; where it does not, the
/// verdict stays the errno's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpCode {
    pub icmp_type: u8,
    pub icmp_code: u8,
}

impl IcmpCode {
    /// Destination unreachable / administratively prohibited: something on the
    /// path refused the flow by policy — in practice a provider's filter.
    pub const ADMIN_PROHIBITED: Self = Self { icmp_type: 3, icmp_code: 13 };
}

/// Probe statuses. `display_label()` is the Latin uppercase badge (Rule 4 — the
/// same in every language), `as_str()` is the snake_case token `--json` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpiStatus {
    Ok,
    /// Redirect (301/302) to a foreign host: red `REDIR`, not ok — the badge
    /// colour depends on the target host, and the `--json` token is `redir`
    /// (Rule 5), never the internal variant name.
    #[serde(rename = "redir")]
    RedirSuspect,
    Blocked,
    IspPage,
    LocalIp,
    Timeout,
    SendTimeout,
    ReadTimeout,
    PoolTimeout,
    /// Rule 5: the wire token is the `as_str()` one, which names the probe rather
    /// than the variant. Without this the derived name (`tcp16_detected`) reaches
    /// anything that serializes a `DpiStatus` whole.
    #[serde(rename = "detected")]
    Tcp16Detected,
    TcpRst,
    TcpAbort,
    TlsRst,
    TlsAbort,
    TlsDropped,
    TlsAlert,
    TlsBlock,
    /// The certificate the server presented cannot be the site's: unknown CA,
    /// expired, wrong hostname, or a self-signed substitute. The `Detail` names
    /// which one; the badge says only that TLS stopped here. It is deliberately
    /// not called `MITM`: a substituted certificate is what an intermediary
    /// leaves behind, but the same verdict comes from a stale certificate on the
    /// real server (`cert_expired` — UncensoredDNS answered that way for months),
    /// so the word read as a finding no matter which one it was.
    TlsErr,
    /// Rule 5: `no_ca_bundle`, not the derived `no_ca` — the badge says the same
    /// thing and the two have to agree.
    #[serde(rename = "no_ca_bundle")]
    NoCa,
    TlsSpoof,
    TlsEof,
    /// Rule 5: `tcp16_20`, the window the connection died in, not the derived
    /// `tcp16_range`.
    #[serde(rename = "tcp16_20")]
    Tcp16Range,
    NoTls13,
    SynDropped,
    Refused,
    NetUnreach,
    HostUnreach,
    OsErr,
    DnsFail,
    DnsFake,
    /// Rule 5: the DNS token is the resolver vocabulary's own spelling —
    /// `nxdomain` — not the derived `nx_domain`.
    #[serde(rename = "nxdomain")]
    NxDomain,
    /// The QUIC endpoint answered the Initial and the handshake can proceed: a
    /// ServerHello, a HelloRetryRequest, or a Retry whose integrity tag checked
    /// out. It says the UDP path to port 443 works and the endpoint's QUIC stack
    /// is running — not that the site answered HTTP/3, which needs a request.
    QuicOk,
    /// The endpoint answered with a protected `CONNECTION_CLOSE`, or with a
    /// stateless reset: something on the other side holds the Initial keys (or
    /// has no state for this connection), so the path is not filtered, but the
    /// handshake will not run.
    QuicClosed,
    /// Version negotiation: the endpoint does not speak v1, and lists what it
    /// does. The path works; the probe's version does not.
    QuicVn,
    /// A Retry whose integrity tag does not match (RFC 9001 §5.8): the packet
    /// cannot have been computed by a party that saw the Initial, so something
    /// on the path answered in the endpoint's place.
    QuicSpoof,
    /// Nothing came back within the window: the silence `SYN DROP` is for TCP.
    QuicDrop,
    Err,
    Unknown,
}

impl DpiStatus {
    /// Every variant, in declaration order.
    ///
    /// The enum cannot be iterated, and a check that has to see all of it — the
    /// binary's legend coverage test — walks this. Keep it in step with the
    /// enum: a variant added above and not added here is simply not checked.
    pub const ALL: &'static [DpiStatus] = &[
        DpiStatus::Ok,
        DpiStatus::RedirSuspect,
        DpiStatus::Blocked,
        DpiStatus::IspPage,
        DpiStatus::LocalIp,
        DpiStatus::Timeout,
        DpiStatus::SendTimeout,
        DpiStatus::ReadTimeout,
        DpiStatus::PoolTimeout,
        DpiStatus::Tcp16Detected,
        DpiStatus::TcpRst,
        DpiStatus::TcpAbort,
        DpiStatus::TlsRst,
        DpiStatus::TlsAbort,
        DpiStatus::TlsDropped,
        DpiStatus::TlsAlert,
        DpiStatus::TlsBlock,
        DpiStatus::TlsErr,
        DpiStatus::NoCa,
        DpiStatus::TlsSpoof,
        DpiStatus::TlsEof,
        DpiStatus::Tcp16Range,
        DpiStatus::NoTls13,
        DpiStatus::SynDropped,
        DpiStatus::Refused,
        DpiStatus::NetUnreach,
        DpiStatus::HostUnreach,
        DpiStatus::OsErr,
        DpiStatus::DnsFail,
        DpiStatus::DnsFake,
        DpiStatus::NxDomain,
        DpiStatus::QuicOk,
        DpiStatus::QuicClosed,
        DpiStatus::QuicVn,
        DpiStatus::QuicSpoof,
        DpiStatus::QuicDrop,
        DpiStatus::Err,
        DpiStatus::Unknown,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::RedirSuspect => "redir",
            Self::Blocked => "blocked",
            Self::IspPage => "isp_page",
            Self::LocalIp => "local_ip",
            Self::Timeout => "timeout",
            Self::SendTimeout => "send_timeout",
            Self::ReadTimeout => "read_timeout",
            Self::PoolTimeout => "pool_timeout",
            Self::Tcp16Detected => "detected",
            Self::TcpRst => "tcp_rst",
            Self::TcpAbort => "tcp_abort",
            Self::TlsRst => "tls_rst",
            Self::TlsAbort => "tls_abort",
            Self::TlsDropped => "tls_dropped",
            Self::TlsAlert => "tls_alert",
            Self::TlsBlock => "tls_block",
            Self::TlsErr => "tls_err",
            Self::NoCa => "no_ca_bundle",
            Self::TlsSpoof => "tls_spoof",
            Self::Tcp16Range => "tcp16_20",
            Self::TlsEof => "tls_eof",
            Self::NoTls13 => "no_tls13",
            Self::SynDropped => "syn_dropped",
            Self::Refused => "refused",
            Self::NetUnreach => "net_unreach",
            Self::HostUnreach => "host_unreach",
            Self::OsErr => "os_err",
            Self::DnsFail => "dns_fail",
            Self::DnsFake => "dns_fake",
            Self::NxDomain => "nxdomain",
            Self::QuicOk => "quic_ok",
            Self::QuicClosed => "quic_closed",
            Self::QuicVn => "quic_vn",
            Self::QuicSpoof => "quic_spoof",
            Self::QuicDrop => "quic_drop",
            Self::Err => "err",
            Self::Unknown => "unknown",
        }
    }

    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::RedirSuspect => "REDIR",
            Self::Blocked => "BLOCKED",
            Self::IspPage => "ISP PAGE",
            Self::LocalIp => "LOCAL IP",
            Self::Timeout => "TIMEOUT",
            Self::SendTimeout => "SEND TIMEOUT",
            Self::ReadTimeout => "TIMEOUT",
            Self::PoolTimeout => "POOL TIMEOUT",
            Self::Tcp16Detected => "DETECTED",
            Self::TcpRst => "TCP RST",
            Self::TcpAbort => "TCP ABORT",
            Self::TlsRst => "TLS RST",
            Self::TlsAbort => "TLS ABORT",
            Self::TlsDropped => "TLS DROP",
            Self::TlsAlert => "TLS ALERT",
            Self::Tcp16Range => "16KB DROP",
            Self::TlsBlock => "TLS BLOCK",
            Self::TlsErr => "TLS ERR",
            Self::NoCa => "NO CA BUNDLE",
            Self::TlsSpoof => "TLS SPOOF",
            Self::TlsEof => "TLS EOF",
            Self::NoTls13 => "NO TLS1.3",
            Self::SynDropped => "SYN DROP",
            Self::Refused => "REFUSED",
            Self::NetUnreach => "NET UNREACH",
            Self::HostUnreach => "HOST UNREACH",
            Self::OsErr => "OS ERR",
            Self::DnsFail => "DNS FAIL",
            Self::DnsFake => "DNS FAKE",
            Self::NxDomain => "NXDOMAIN",
            Self::QuicOk => "OK",
            Self::QuicClosed => "CLOSED",
            Self::QuicVn => "VN",
            Self::QuicSpoof => "SPOOF",
            Self::QuicDrop => "DROP",
            Self::Err => "ERR",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// True only for a plain `OK`. A redirect to the same host/subdomain is
    /// classified `Ok` at the probe; a foreign one lands here as `RedirSuspect`
    /// (red `REDIR`) and is not ok.
    pub fn is_ok_status(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            Self::Blocked
                | Self::IspPage
                | Self::Tcp16Detected
                | Self::Tcp16Range
                | Self::TlsRst
                | Self::TlsAbort
                | Self::TlsAlert
                | Self::TlsBlock
                | Self::TlsErr
                | Self::TlsSpoof
                | Self::TlsEof
                | Self::TcpRst
                | Self::TcpAbort
                | Self::DnsFake
                | Self::SynDropped
                | Self::TlsDropped
                // Silence on the QUIC Initial is the same class of verdict as
                // silence on a SYN: nothing answered, which is what a filter and
                // a dead endpoint both look like from here.
                | Self::QuicDrop
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeMetrics {
    pub status: DpiStatus,
    pub stage: ConnectionStage,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub duration_ms: u64,
    pub detail: Detail,
}

impl Default for ProbeMetrics {
    fn default() -> Self {
        Self {
            status: DpiStatus::Unknown,
            stage: ConnectionStage::Init,
            bytes_sent: 0,
            bytes_recv: 0,
            duration_ms: 0,
            detail: Detail::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five stage tokens are wire-visible: `Detail::TimeoutStage` composes
    /// its `--json` code out of one of them (`timeout_tls_connected`), so a
    /// rename here silently renames a machine channel. Pinned one by one — the
    /// enum cannot be iterated, and a rename is exactly what this catches.
    #[test]
    fn the_probe_stage_tokens_are_the_frozen_ones() {
        for (stage, token) in [
            (ProbeStage::TcpConnect, "tcp_connect"),
            (ProbeStage::TlsHandshake, "tls_handshake"),
            (ProbeStage::TlsConnected, "tls_connected"),
            (ProbeStage::SendingData, "sending_data"),
            (ProbeStage::ReadingData, "reading_data"),
        ] {
            assert_eq!(stage.as_str(), token);
        }
    }

    /// The three words `of_fault_stage` maps, and the one it must not: `resolve`
    /// is the caller's own verdict, not a transport stage, and a stage the map
    /// does not know cannot be invented here — the match has no wildcard.
    #[test]
    fn of_fault_stage_maps_only_the_shared_places() {
        assert_eq!(ProbeStage::of_fault_stage(ConnectStage::Connected), Some(ProbeStage::TlsConnected));
        assert_eq!(ProbeStage::of_fault_stage(ConnectStage::TcpConnect), Some(ProbeStage::TcpConnect));
        assert_eq!(ProbeStage::of_fault_stage(ConnectStage::TlsHandshake), Some(ProbeStage::TlsHandshake));
        assert_eq!(ProbeStage::of_fault_stage(ConnectStage::Resolve), None);
    }

    /// Rule 5: the `--json` token of a redirect to a foreign host is `redir` —
    /// the internal variant name never reaches the wire — and both directions of
    /// the mapping agree with `as_str()`.
    #[test]
    fn foreign_redirect_serializes_as_redir() {
        assert_eq!(DpiStatus::RedirSuspect.as_str(), "redir");
        assert_eq!(serde_json::to_string(&DpiStatus::RedirSuspect).unwrap(), "\"redir\"");
        assert_eq!(serde_json::from_str::<DpiStatus>("\"redir\"").unwrap(), DpiStatus::RedirSuspect);
        // Badge stays canonical Latin (Rule 4); a suspect redirect is neither
        // ok nor a censorship verdict.
        assert_eq!(DpiStatus::RedirSuspect.display_label(), "REDIR");
        assert!(!DpiStatus::RedirSuspect.is_ok_status());
        assert!(!DpiStatus::RedirSuspect.is_blocked());
    }

    /// Rule 5: serde and `as_str()` must agree on the wire token. Four variants
    /// had drifted — `--json` carries `as_str()`, so a `DpiStatus` serialized
    /// anywhere else said `tcp16_range`, `no_ca`, `nx_domain` or
    /// `tcp16_detected` where the documented token was something else. Pinned one
    /// by one: the enum cannot be iterated, and a list that rots is worse than
    /// none, so the ones that drifted are the ones named here.
    #[test]
    fn the_wire_token_is_the_same_through_serde() {
        for (status, token) in [
            (DpiStatus::Tcp16Range, "tcp16_20"),
            (DpiStatus::Tcp16Detected, "detected"),
            (DpiStatus::NoCa, "no_ca_bundle"),
            (DpiStatus::NxDomain, "nxdomain"),
            (DpiStatus::RedirSuspect, "redir"),
            (DpiStatus::TlsErr, "tls_err"),
        ] {
            assert_eq!(status.as_str(), token);
            assert_eq!(
                serde_json::to_string(&status).expect("a status serializes"),
                format!("\"{token}\"")
            );
        }
    }

    /// One badge for the fat window outside test 3 — `16KB DROP` — and `DETECTED`
    /// for test 3 itself, which sends rather than reads. The window is carried by
    /// the detail (`READ TIMEOUT at N KB`), not by the badge, and a connection
    /// that dies before the window is a plain timeout, so `TCP16 DROP` is gone.
    #[test]
    fn the_fat_window_has_one_badge_outside_test_3() {
        assert_eq!(DpiStatus::Tcp16Range.display_label(), "16KB DROP");
        assert_eq!(DpiStatus::Tcp16Detected.display_label(), "DETECTED");
        assert_eq!(DpiStatus::Tcp16Range.as_str(), "tcp16_20");
        assert_eq!(
            serde_json::to_string(&DpiStatus::Tcp16Range).unwrap(),
            "\"tcp16_20\""
        );
        assert!(DpiStatus::Tcp16Range.is_blocked());
        assert!(DpiStatus::Tcp16Detected.is_blocked());
    }
}

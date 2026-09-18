use serde::{Deserialize, Serialize};

use super::detail::Detail;

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
    /// Rule 5: the DNS tokens are the resolver vocabulary's own spellings —
    /// `nxdomain`, `fakeip` — not the derived `nx_domain`/`fake_ip`.
    #[serde(rename = "nxdomain")]
    NxDomain,
    DnsHijacked,
    #[serde(rename = "fakeip")]
    FakeIp,
    HttpBlocked,
    Unreachable,
    Err,
    Unknown,
}

impl DpiStatus {
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
            Self::DnsHijacked => "dns_hijacked",
            Self::FakeIp => "fakeip",
            Self::HttpBlocked => "http_blocked",
            Self::Unreachable => "unreachable",
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
            Self::DnsHijacked => "DNS HIJACK",
            Self::FakeIp => "FAKE IP",
            Self::HttpBlocked => "HTTP BLOCK",
            Self::Unreachable => "UNREACHABLE",
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
                | Self::HttpBlocked
                | Self::DnsHijacked
                | Self::FakeIp
                | Self::DnsFake
                | Self::SynDropped
                | Self::TlsDropped
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

    /// Rule 5: serde and `as_str()` must agree on the wire token. Five variants
    /// had drifted — `--json` carries `as_str()`, so a `DpiStatus` serialized
    /// anywhere else said `tcp16_range`, `no_ca`, `nx_domain`, `fake_ip` or
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
            (DpiStatus::FakeIp, "fakeip"),
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

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
    Tcp16Detected,
    TcpRst,
    TcpAbort,
    TlsRst,
    TlsAbort,
    TlsDropped,
    TlsAlert,
    TlsBlock,
    TlsMitm,
    NoCa,
    TlsSpoof,
    TlsEof,
    Tcp16Range,
    NoTls13,
    SynDropped,
    Refused,
    NetUnreach,
    HostUnreach,
    OsErr,
    DnsFail,
    DnsFake,
    NxDomain,
    DnsHijacked,
    FakeIp,
    HttpBlocked,
    Tcp16Dropped,
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
            Self::TlsMitm => "tls_mitm",
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
            Self::Tcp16Dropped => "tcp16_dropped",
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
            Self::Tcp16Range => "TCP16-20",
            Self::TlsBlock => "TLS BLOCK",
            Self::TlsMitm => "TLS MITM",
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
            Self::Tcp16Dropped => "TCP16 DROP",
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
                | Self::Tcp16Dropped
                | Self::Tcp16Range
                | Self::TlsRst
                | Self::TlsAbort
                | Self::TlsAlert
                | Self::TlsBlock
                | Self::TlsMitm
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
}

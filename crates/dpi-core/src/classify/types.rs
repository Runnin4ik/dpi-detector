use serde::{Deserialize, Serialize};

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

/// Canonical probe statuses. `display_label()` mirrors the Python
/// `ProbeStatus` badges 1:1 (Latin uppercase, never translated).
/// `as_str()` is the stable machine-readable snake_case contract for --json.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpiStatus {
    Ok,
    Redir,
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
            Self::Redir => "redir",
            Self::RedirSuspect => "redir_suspect",
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
            Self::Redir => "REDIR",
            Self::RedirSuspect => "REDIR",
            Self::Blocked => "BLOCKED",
            Self::IspPage => "ISP PAGE",
            Self::LocalIp => "LOCAL IP",
            Self::Timeout => "TIMEOUT",
            Self::SendTimeout => "SEND TIMEOUT",
            Self::ReadTimeout => "READ TIMEOUT",
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

    /// Mirrors Python `ProbeStatus.is_ok`: green OK or legitimate redirect.
    /// A suspicious (foreign-domain) redirect is NOT ok.
    pub fn is_ok_status(&self) -> bool {
        matches!(self, Self::Ok | Self::Redir)
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
    pub detail: String,
}

impl Default for ProbeMetrics {
    fn default() -> Self {
        Self {
            status: DpiStatus::Unknown,
            stage: ConnectionStage::Init,
            bytes_sent: 0,
            bytes_recv: 0,
            duration_ms: 0,
            detail: String::new(),
        }
    }
}

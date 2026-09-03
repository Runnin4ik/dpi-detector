use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    TXT(Vec<String>),
    Other { rtype: u16, data: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub tx_id: u16,
    pub flags: u16,
    pub rcode: u8,
    pub answers: Vec<DnsRecord>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("truncated packet: length {0}")]
    Truncated(usize),
    #[error("invalid DNS header")]
    InvalidHeader,
    #[error("DNS query name too long (>253 chars)")]
    NameTooLong,
    #[error("DNS label too long (>63 chars)")]
    LabelTooLong,
    #[error("invalid label pointer loop or out of bounds at offset {0}")]
    InvalidPointer(usize),
    #[error("DNS name compression recursion limit exceeded")]
    PointerLoop,
    #[error("NXDOMAIN (domain does not exist)")]
    NxDomain,
    #[error("DNS server returned error rcode {0}")]
    ServerFailure(u8),
    #[error("mismatched transaction ID: expected {expected:#06x}, got {actual:#06x}")]
    MismatchedTxId { expected: u16, actual: u16 },
    #[error("unsupported record data")]
    UnsupportedRdata,
    #[error("network I/O error: {0}")]
    Io(String),
    #[error("connection failed at stage {stage}: {detail}")]
    ConnectFault { stage: &'static str, detail: String },
    #[error("query timeout")]
    Timeout,
    #[error("SOCKS5 error: {0}")]
    Socks5(String),
    #[error("DoH HTTP error: status {0}")]
    DohHttp(u16),
}

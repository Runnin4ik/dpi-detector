use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

use crate::classify::types::ConnectStage;

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

impl DnsResponse {
    /// The A/AAAA answers, in response order. Every resolver path (UDP, DoT,
    /// both DoH entries) answers with exactly this list, so the walk lives here
    /// rather than once per transport.
    pub fn collect_ips(&self) -> Vec<IpAddr> {
        self.answers
            .iter()
            .filter_map(|ans| match ans {
                DnsRecord::A(v4) => Some(IpAddr::V4(*v4)),
                DnsRecord::AAAA(v6) => Some(IpAddr::V6(*v6)),
                _ => None,
            })
            .collect()
    }
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
    /// A transport step failed before the exchange: `stage` is the place it
    /// happened, `detail` the raw cause, and `code`/`kind` the OS-level facts the
    /// message may not carry (Windows localizes it: `WSAECONNRESET` reads
    /// "Удаленный хост принудительно разорвал …"). Those two are what the
    /// classifier keys on, so keeping them is what makes a DNS endpoint's
    /// failure read the same way a domain's does — one classifier, two callers,
    /// identical inputs. `None` means the producer had no `io::Error` behind the
    /// fault (a budget it measured itself). The stage is a [`ConnectStage`] — a
    /// closed vocabulary, not a hand-written word — so the classifier maps it by
    /// variant and `--json` never sees it.
    #[error("connection failed at stage {stage}: {detail}")]
    ConnectFault {
        stage: ConnectStage,
        detail: String,
        code: Option<i32>,
        kind: Option<std::io::ErrorKind>,
    },
    #[error("query timeout")]
    Timeout,
    #[error("SOCKS5 error: {0}")]
    Socks5(String),
    #[error("DoH HTTP error: status {0}")]
    DohHttp(u16),
}

impl DnsError {
    /// A fault built from the `io::Error` that raised it: the message goes to
    /// the report, the code and kind to the classifier. Every producer that has
    /// the error in hand uses this, so neither fact is dropped on the way to the
    /// verdict — which is what kept the DNS test's classification apart from the
    /// domain test's.
    pub fn connect_fault(stage: ConnectStage, err: &std::io::Error) -> Self {
        DnsError::ConnectFault {
            stage,
            detail: err.to_string(),
            code: err.raw_os_error(),
            kind: Some(err.kind()),
        }
    }

    /// A fault with no `io::Error` behind it — a timeout or a missing address the
    /// caller decided itself. `code`/`kind` stay `None`, so the classifier reads
    /// the message and never invents an OS verdict.
    pub fn connect_fault_text(stage: ConnectStage, detail: &str) -> Self {
        DnsError::ConnectFault {
            stage,
            detail: detail.to_string(),
            code: None,
            kind: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four stage words are what `DnsError`'s own message carries, and they
    /// used to be hand-written at every producer. Pinned one by one: a lost word
    /// fails to compile here, a renamed one fails the assert, and the message
    /// the format string spells is pinned with it.
    #[test]
    fn connect_fault_stage_words_are_frozen() {
        for (stage, word) in [
            (ConnectStage::Resolve, "resolve"),
            (ConnectStage::TcpConnect, "tcp_connect"),
            (ConnectStage::TlsHandshake, "tls_handshake"),
            (ConnectStage::Connected, "connected"),
        ] {
            assert_eq!(stage.as_str(), word);
            assert_eq!(
                DnsError::ConnectFault {
                    stage,
                    detail: "x".to_string(),
                    code: None,
                    kind: None,
                }
                .to_string(),
                format!("connection failed at stage {word}: x")
            );
        }
    }
}

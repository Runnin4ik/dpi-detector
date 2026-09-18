//! DoT (DNS over TLS, RFC 7858) probing.
//!
//! Strict CA validation (`TlsProfile::verifying`), one TLS connection
//! per server, sequential queries with the 2-byte length prefix.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::resolve::resolve_host;
use super::types::DnsError;
use super::wire::{build_dns_query, parse_dns_response, QTYPE_A};
use crate::net::tcp::set_no_delay;
use crate::net::tls::{create_tls_config, TlsProfile};

/// Splits a DoT endpoint `'host[:port]'` (default 853). Supports IPv6 literals.
pub fn split_dot_endpoint(addr: &str) -> (String, u16) {
    let s = addr.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let tail = &rest[end + 1..];
            if let Some(port_str) = tail.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host, port);
                }
            }
            return (host, 853);
        }
        return (rest.to_string(), 853);
    }
    if s.matches(':').count() >= 2 {
        return (s.to_string(), 853);
    }
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (s.to_string(), 853)
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// A single reused DoT/TLS connection to one resolver.
pub struct DotSession {
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    timeout_dur: Duration,
}

impl DotSession {
    /// Connects with strict certificate validation (SNI = hostname,
    /// IP-SAN for literals) against the bundled WebPKI root store.
    pub async fn connect(host: &str, port: u16, timeout_dur: Duration) -> Result<Self, DnsError> {
        // Resolve to the target IP first; a resolve failure aborts the server
        // with DNS FAIL, no silent fallback to another address.
        let connect_host = if is_ip_literal(host) {
            host.to_string()
        } else {
            let addrs_vec: Vec<std::net::SocketAddr> =
                timeout(timeout_dur, resolve_host(host, port, timeout_dur))
                    .await
                    .map_err(|_| DnsError::ConnectFault {
                        stage: "resolve",
                        detail: "lookup timed out".to_string(),
                    })?
                    .map_err(|e| DnsError::ConnectFault {
                        stage: "resolve",
                        detail: e.to_string(),
                    })?;
            let addr = addrs_vec
                .iter()
                .find(|a| a.is_ipv4())
                .copied()
                .or_else(|| addrs_vec.first().copied())
                .ok_or_else(|| DnsError::ConnectFault {
                    stage: "resolve",
                    detail: "no address".to_string(),
                })?;
            addr.ip().to_string()
        };

        let addr: SocketAddr = format!("{}:{}", connect_host, port)
            .parse()
            .map_err(|e| DnsError::Io(format!("bad DoT address: {}", e)))?;
        let tcp = timeout(timeout_dur, crate::net::bind::tcp_connect(&addr))
            .await
            .map_err(|_| DnsError::ConnectFault {
                stage: "tcp_connect",
                detail: "connect timed out".to_string(),
            })?
            .map_err(|e| DnsError::ConnectFault {
                stage: "tcp_connect",
                detail: e.to_string(),
            })?;
        set_no_delay(&tcp);
        let connector = TlsConnector::from(create_tls_config(&TlsProfile::verifying()));
        let server_name = ServerName::try_from(host.to_string())
            .or_else(|_| {
                host.parse::<IpAddr>()
                    .map(rustls::pki_types::IpAddr::from)
                    .map(ServerName::IpAddress)
                    .map_err(|_| DnsError::Io(format!("bad DoT SNI: {}", host)))
            })
            .map_err(|e: DnsError| e.to_string())
            .map_err(DnsError::Io)?;

        let tls = timeout(timeout_dur, connector.connect(server_name, tcp))
            .await
            .map_err(|_| DnsError::ConnectFault {
                stage: "tls_handshake",
                detail: "handshake timed out".to_string(),
            })?
            .map_err(|e| DnsError::ConnectFault {
                stage: "tls_handshake",
                detail: e.to_string(),
            })?;
        Ok(Self { tls, timeout_dur })
    }

    /// Sends one query over the reused connection (length-prefixed wire).
    pub async fn query(&mut self, domain: &str) -> Result<(Vec<IpAddr>, f64), DnsError> {
        let tx_id = rand::random::<u16>();
        let q = build_dns_query(domain, QTYPE_A, Some(tx_id))?;
        let timeout_dur = self.timeout_dur;

        let execute = async {
            let start = Instant::now();
            let mut packet = Vec::with_capacity(2 + q.len());
            packet.extend_from_slice(&(q.len() as u16).to_be_bytes());
            packet.extend_from_slice(&q);
            self.tls
                .write_all(&packet)
                .await
                .map_err(|e| DnsError::Io(format!("DoT write failed: {}", e)))?;
            self.tls
                .flush()
                .await
                .map_err(|e| DnsError::Io(format!("DoT flush failed: {}", e)))?;

            let mut len_buf = [0u8; 2];
            self.tls
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| DnsError::Io(format!("DoT read len failed: {}", e)))?;
            let n = u16::from_be_bytes(len_buf) as usize;
            if n == 0 || n > 4096 {
                return Err(DnsError::Io(format!("DoT bad length: {}", n)));
            }
            let mut buf = vec![0u8; n];
            self.tls
                .read_exact(&mut buf)
                .await
                .map_err(|e| DnsError::Io(format!("DoT read body failed: {}", e)))?;
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let parsed = parse_dns_response(&buf, Some(tx_id))?;
            Ok((parsed.collect_ips(), latency_ms))
        };

        timeout(timeout_dur, execute)
            .await
            .map_err(|_| DnsError::Timeout)?
    }
}

/// One-shot DoT query (connect + single question).
pub async fn probe_dot(
    host: &str,
    port: u16,
    domain: &str,
    timeout_dur: Duration,
) -> Result<(Vec<IpAddr>, f64), DnsError> {
    let mut session = DotSession::connect(host, port, timeout_dur).await?;
    session.query(domain).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_dot_endpoint() {
        assert_eq!(split_dot_endpoint("dns.google"), ("dns.google".to_string(), 853));
        assert_eq!(split_dot_endpoint("dns.google:8853"), ("dns.google".to_string(), 8853));
        assert_eq!(split_dot_endpoint("[2001:db8::1]"), ("2001:db8::1".to_string(), 853));
        assert_eq!(split_dot_endpoint("2001:db8::1"), ("2001:db8::1".to_string(), 853));
    }

}

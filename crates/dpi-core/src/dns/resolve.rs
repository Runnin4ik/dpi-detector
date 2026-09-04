//! Bootstrap hostname resolution for systems without a working resolver.
//!
//! The musl system resolver reads only `/etc/resolv.conf`, which does not
//! exist on Android/Termux — there every domain-based probe (DoH, DoT,
//! domain/TLS checks) fails while IP-literal traffic works fine.
//! `resolve_host` keeps the system resolver first (local DNS, VPN and router
//! dnsmasq keep working; zero behavior change on desktops) and falls back to
//! its own plain A-query over UDP to hardcoded bootstrap resolvers, reusing
//! `probe_udp_dns` (UDP to an IP literal needs no resolution at all).
//!
//! Trust note: the first non-empty bootstrap answer wins. A network that
//! hijacks UDP/53 to public resolvers could feed a stub IP, but the follow-up
//! TLS handshake still verifies the hostname (SNI/cert), so a lie surfaces
//! as a TLS-stage failure, never as silent success.
//!
//! Limitation: the fallback resolves A records only; IPv6-mode verdicts on
//! such systems report "no IPv6" even when AAAA records exist.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::timeout;

use super::types::DnsError;
use super::udp::probe_udp_dns;

/// Bootstrap resolvers (IP literals — usable without any resolution).
const BOOTSTRAP_RESOLVERS: &[&str] = &["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"];

/// Resolve `host:port` like `tokio::net::lookup_host`, with a self-contained
/// UDP bootstrap fallback when the system resolver fails or comes back empty.
pub async fn resolve_host(
    host: &str,
    port: u16,
    timeout_dur: Duration,
) -> Result<Vec<SocketAddr>, DnsError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let system = timeout(
        timeout_dur,
        tokio::net::lookup_host(format!("{}:{}", host, port)),
    )
    .await;
    if let Ok(Ok(addrs)) = system {
        let found: Vec<SocketAddr> = addrs.collect();
        if !found.is_empty() {
            return Ok(found);
        }
    }
    // System resolver broken (Android) or refused: ask bootstraps directly.
    // A fast NXDOMAIN/empty answer returns immediately; only silent servers
    // burn the per-attempt budget.
    let mut last_err = DnsError::ConnectFault {
        stage: "resolve",
        detail: "no address".to_string(),
    };
    for entry in BOOTSTRAP_RESOLVERS {
        let Ok(server) = entry.parse::<SocketAddr>() else {
            continue;
        };
        match timeout(timeout_dur, probe_udp_dns(server, host, timeout_dur, None)).await {
            Ok(Ok((ips, _))) => {
                if ips.is_empty() {
                    return Err(DnsError::ConnectFault {
                        stage: "resolve",
                        detail: "no address".to_string(),
                    });
                }
                return Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect());
            }
            Ok(Err(e)) => last_err = e,
            Err(_) => {
                last_err = DnsError::ConnectFault {
                    stage: "resolve",
                    detail: "bootstrap timed out".to_string(),
                }
            }
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn literal_needs_no_resolution() {
        let addrs = resolve_host("8.8.8.8", 443, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(addrs, vec![SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 443)]);
    }

    #[tokio::test]
    async fn localhost_uses_system_resolver() {
        let addrs = resolve_host("localhost", 80, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(addrs
            .iter()
            .any(|a| a.ip() == IpAddr::from([127, 0, 0, 1])));
    }
}

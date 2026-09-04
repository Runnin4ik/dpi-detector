//! Layered hostname resolution for systems without a working resolver.
//!
//! The musl system resolver reads only `/etc/resolv.conf`, which does not
//! exist on Android/Termux — there every domain-based probe (DoH, DoT,
//! domain/TLS checks) fails while IP-literal traffic works fine.
//! `resolve_host` layers like other portable tools (browsers, AdGuard,
//! CoreDNS) do:
//! 1. system resolver (local DNS, VPN and router dnsmasq keep working;
//!    zero behavior change on desktops);
//! 2. OS-configured servers — on Android, `net.dns*` properties, which carry
//!    the WiFi-router DNS (DHCP), the carrier DNS and the VPN-client DNS,
//!    read via a `getprop` subprocess (a static musl binary cannot call the
//!    bionic system-properties API);
//! 3. hardcoded well-known resolvers, last resort only (UDP to an IP literal
//!    needs no resolution at all).
//!
//! Trust note: the first non-empty fallback answer wins. A network that
//! hijacks UDP/53 could feed a stub IP, but the follow-up TLS handshake
//! still verifies the hostname (SNI/cert), so a lie surfaces as a TLS-stage
//! failure, never as silent success.
//!
//! Limitation: the fallback resolves A records only; IPv6-mode verdicts on
//! such systems report "no IPv6" even when AAAA records exist.

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

use super::types::DnsError;
use super::udp::probe_udp_dns;

/// Last-resort resolvers (IP literals — usable without any resolution).
const BOOTSTRAP_RESOLVERS: &[&str] = &["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"];

/// OS-configured DNS servers, process-lifetime cache (empty off-Android).
static OS_DNS_CACHE: OnceLock<Vec<IpAddr>> = OnceLock::new();

/// Parse `getprop` output (`[net.dns1]: [192.168.1.1]`) into server IPs.
fn parse_getprop_dns(output: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        // Key must be exactly `[net.dns<N>]` (numeric id, no per-network suffix).
        let Some(rest) = line.strip_prefix("[net.dns") else {
            continue;
        };
        let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || rest.as_bytes().get(digits) != Some(&b']') {
            continue;
        }
        // Value is the last bracket group: `[net.dns1]: [192.168.1.1]`.
        let Some(bracketed) = line.rsplit('[').next() else {
            continue;
        };
        let value = bracketed.strip_suffix(']').unwrap_or(bracketed).trim();
        if value.is_empty() {
            continue;
        }
        let literal = value.split('%').next().unwrap_or(value);
        if let Ok(ip) = literal.parse::<IpAddr>() {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }
    servers
}

/// OS-configured DNS servers via `getprop net.dns*` (Android only; empty
/// elsewhere). A hung helper is capped; failures mean "no OS DNS".
async fn os_dns_servers() -> Vec<IpAddr> {
    if let Some(cached) = OS_DNS_CACHE.get() {
        return cached.clone();
    }
    let mut servers = Vec::new();
    let output = timeout(Duration::from_secs(2), Command::new("getprop").output()).await;
    if let Ok(Ok(out)) = output {
        servers = parse_getprop_dns(&String::from_utf8_lossy(&out.stdout));
    }
    let _ = OS_DNS_CACHE.set(servers.clone());
    servers
}

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
    // System resolver broken (Android) or refused: OS-configured servers
    // first (router/carrier/VPN DNS), hardcoded last resort. A fast
    // NXDOMAIN/empty answer returns immediately; only silent servers burn
    // the per-attempt budget.
    let mut servers: Vec<SocketAddr> = os_dns_servers()
        .await
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 53))
        .collect();
    for entry in BOOTSTRAP_RESOLVERS {
        if let Ok(server) = entry.parse::<SocketAddr>() {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    let mut last_err = DnsError::ConnectFault {
        stage: "resolve",
        detail: "no address".to_string(),
    };
    for server in servers {
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
                    detail: "fallback timed out".to_string(),
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
        assert_eq!(
            addrs,
            vec![SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 443)]
        );
    }

    #[tokio::test]
    async fn localhost_uses_system_resolver() {
        let addrs = resolve_host("localhost", 80, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(addrs.iter().any(|a| a.ip() == IpAddr::from([127, 0, 0, 1])));
    }
    #[test]
    fn getprop_parses_android_dns() {
        let sample = "[net.dns1]: [192.168.1.1]\n\
                      [net.dns2]: [8.8.8.8]\n\
                      [net.dns3]: []\n\
                      [net.dns4]: []\n\
                      [net.dns1.wlan0]: [10.0.0.1]\n\
                      [ro.build.id]: [UP1A]\n";
        assert_eq!(
            parse_getprop_dns(sample),
            vec![IpAddr::from([192, 168, 1, 1]), IpAddr::from([8, 8, 8, 8]),]
        );
    }

    #[test]
    fn getprop_parses_ipv6_with_zone() {
        let sample = "[net.dns1]: [fe80::1%wlan0]\n[net.dns1]: [fe80::1%wlan0]\n";
        assert_eq!(
            parse_getprop_dns(sample),
            vec![IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1])]
        );
    }
}

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::time::timeout;

use super::socks::{associate_socks5_udp, unwrap_socks_udp, wrap_socks_udp, SocksProxyConfig};
use super::types::DnsError;
use super::wire::{build_dns_query, parse_dns_response, QTYPE_A};

/// Probes a DNS resolver over UDP, measuring latency and returning resolved IP addresses.
pub async fn probe_udp_dns(
    server: SocketAddr,
    domain: &str,
    timeout_dur: Duration,
    socks_proxy: Option<&SocksProxyConfig>,
) -> Result<(Vec<IpAddr>, f64), DnsError> {
    let tx_id = rand::random::<u16>();
    let query_data = build_dns_query(domain, QTYPE_A, Some(tx_id))?;

    let start = Instant::now();

    let resp_bytes = if let Some(proxy) = socks_proxy {
        // Run via SOCKS5 UDP relay
        let (relay_addr, _tcp_stream) = associate_socks5_udp(proxy, timeout_dur).await?;
        let socket = crate::net::bind::udp_socket(&relay_addr)
            .await
            .map_err(|e| DnsError::Io(e.to_string()))?;

        let wrapped = wrap_socks_udp(server, &query_data);
        socket
            .send_to(&wrapped, relay_addr)
            .await
            .map_err(|e| DnsError::Io(e.to_string()))?;

        let mut buf = [0u8; 4096];
        let (len, _from) = timeout(timeout_dur, socket.recv_from(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e.to_string()))?;

        let unwrapped = unwrap_socks_udp(&buf[..len])?;
        unwrapped.to_vec()
    } else {
        // Direct UDP
        let socket = crate::net::bind::udp_socket(&server)
            .await
            .map_err(|e| DnsError::Io(e.to_string()))?;

        socket
            .send_to(&query_data, server)
            .await
            .map_err(|e| DnsError::Io(e.to_string()))?;

        let mut buf = [0u8; 4096];
        let (len, _from) = timeout(timeout_dur, socket.recv_from(&mut buf))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| DnsError::Io(e.to_string()))?;

        buf[..len].to_vec()
    };

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    let response = parse_dns_response(&resp_bytes, Some(tx_id))?;
    Ok((response.collect_ips(), latency_ms))
}

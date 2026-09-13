//! Public IPv4/IPv6 discovery: race the configured echo endpoints and keep
//! the first answer of the right family that is not a private address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::net::http_client::http_get_text;

#[derive(Debug, Clone, Default)]
pub struct PublicIps {
    pub v4: Option<(Ipv4Addr, u64)>,
    pub v6: Option<(Ipv6Addr, u64)>,
}

/// Fetches public IPv4 and IPv6 addresses concurrently with latency in milliseconds.
/// Endpoint lists come from config (IP4/IP6_LOOKUP_URLS).
pub async fn fetch_public_ips(v4_urls: &[String], v6_urls: &[String], timeout_dur: Duration) -> PublicIps {
    /// All endpoints race; the first valid (right family, non-private)
    /// answer wins, and TTLB is measured from the shared start.
    async fn first_valid(urls: &[String], want_v6: bool, timeout_dur: Duration) -> Option<(IpAddr, u64)> {
        let t0 = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for ep in urls {
            let url = ep.clone();
            set.spawn(async move {
                match http_get_text(&url, timeout_dur).await {
                    Ok(text) => {
                        let cand = text.trim();
                        if let Ok(ip) = IpAddr::from_str(cand) {
                            let ok_ver = ip.is_ipv6() == want_v6;
                            if ok_ver && !is_private_lookup_ip(&ip) {
                                return Some(ip);
                            }
                        }
                        None
                    }
                    _ => None,
                }
            });
        }
        while let Some(r) = set.join_next().await {
            if let Ok(Some(ip)) = r {
                set.abort_all();
                return Some((ip, t0.elapsed().as_millis() as u64));
            }
        }
        None
    }
    let (v4_res, v6_res) =
        tokio::join!(first_valid(v4_urls, false, timeout_dur), first_valid(v6_urls, true, timeout_dur));
    let v4 = match v4_res {
        Some((IpAddr::V4(v4), ms)) => Some((v4, ms)),
        _ => None,
    };
    let v6 = match v6_res {
        Some((IpAddr::V6(v6), ms)) => Some((v6, ms)),
        _ => None,
    };
    PublicIps { v4, v6 }
}

/// Private-address filter: RFC1918 for v4, unique-local (fc00::/7) for v6.
fn is_private_lookup_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

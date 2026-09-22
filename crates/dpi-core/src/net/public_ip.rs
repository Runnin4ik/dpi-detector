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
                            if ok_ver && !is_unusable_as_external(&ip) {
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

/// Whether an address can never be the machine's external address, so a lookup
/// answering it is not an answer at all.
///
/// RFC1918 and unique-local were the whole filter when a lookup could only come
/// back with a private address. A fake-ip client (xray, sing-box, Amnezia) adds
/// `198.18.0.0/15` — the benchmarking range it answers every name with until the
/// tunnel carries the flow — and an intercepted lookup can answer loopback,
/// link-local or a documentation address just as well. What is *not* rejected:
/// `100.64.0.0/10`, because a carrier-grade NAT really is how a mobile line
/// reaches the internet, and that address is the machine's external one.
fn is_unusable_as_external(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let unique_local = (segments[0] & 0xfe00) == 0xfc00;
            let link_local = (segments[0] & 0xffc0) == 0xfe80;
            // 2001:db8::/32, RFC 3849. `Ipv6Addr::is_documentation` is unstable,
            // so the prefix is checked by hand, like the two above.
            let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || unique_local
                || link_local
                || documentation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lookup accepts a real external address and rejects everything a
    /// fake-ip client, a local filter or a stub page can answer with.
    #[test]
    fn an_external_lookup_rejects_everything_that_is_not_one() {
        let unusable = [
            "198.18.5.4",       // fake-ip range
            "198.19.255.255",   // its top
            "127.0.0.1",
            "169.254.1.1",
            "10.1.2.3",
            "192.168.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "192.0.2.1",        // RFC 5737 documentation
            "::1",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
        ];
        for text in unusable {
            let ip: IpAddr = text.parse().expect("the fixture parses");
            assert!(is_unusable_as_external(&ip), "{text} was accepted");
        }

        let usable = [
            "8.8.8.8",
            "198.20.0.1",       // one past the fake-ip range
            "100.64.0.1",       // carrier-grade NAT: a real external address
            "2606:4700::1",
        ];
        for text in usable {
            let ip: IpAddr = text.parse().expect("the fixture parses");
            assert!(!is_unusable_as_external(&ip), "{text} was rejected");
        }
    }
}

//! Host network facts: the DNS servers of the active adapter, its name and
//! the default gateway. Windows reads the registry, other targets read
//! `/etc/resolv.conf`, `/proc/net/route` and `.wslconfig`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
#[cfg(target_os = "windows")]
use std::time::Duration;

mod bypass;
pub mod intercept;
mod os;

pub use bypass::detect_bypass_tools;

/// Where the nameservers of the active adapter came from. This is the closed set
/// the panel branches on: a source the producers cannot name is a source the
/// panel cannot render, and a token spelled by hand in two files was a typo away
/// from silently dropping that branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsSource {
    /// Written into the resolver configuration: registry `NameServer`, or a
    /// `nameserver` line in `/etc/resolv.conf`.
    Static,
    /// Handed out by DHCP: registry `DhcpNameServer`, `Dhcpv6DNSServers` or
    /// `ProfileNameServer`.
    Dhcp,
    /// The WSL host resolver (`10.255.255.254` under WSL2 NAT).
    Wsl,
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsInfo {
    /// Flat active + other_static list (machine JSON contract), active entries first.
    pub nameservers: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
    /// (server, where it came from) on the active interface.
    pub active: Vec<(String, DnsSource)>,
    pub active_name: Option<String>,
    pub active_ip: Option<String>,
    /// (server, adapter name) static entries on other live adapters.
    pub other_static: Vec<(String, String)>,
    /// server -> DoH template ("doh" when auto) from Dnscache settings.
    pub doh: HashMap<String, String>,
    /// e.g. "Windows 11 (26200)".
    pub os: Option<String>,
    pub wsl_net: Option<String>,
    /// Upstream resolver IP + " (org)".
    pub upstream: Option<String>,
    /// "Резолвер роутера" or "Upstream VPN".
    pub upstream_label: Option<String>,
    pub fallback: bool,
}

/// Two-letter country code → regional-indicator flag emoji; empty for anything else.
pub fn flag_emoji(cc: &str) -> String {
    let cc = cc.trim().to_uppercase();
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    cc.chars()
        .map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)).unwrap_or(c))
        .collect()
}

/// True when the adapter name contains a known TUN/VPN marker.
pub fn is_tun_name(name: &str) -> bool {
    let n = name.to_lowercase();
    ["tun", "xray", "sing-box", "singbox", "wireguard", "warp", "tailscale", "zerotier", "mullvad"]
        .iter()
        .any(|m| n.contains(m))
}

/// True when the first 16-bit segment of an address is in `2000::/3` — the
/// global-unicast block, as opposed to link-local, unique-local or loopback.
/// Split out of [`ipv6_supported`] so the predicate itself is testable without
/// a socket, a route or a network.
fn is_global_unicast(v6: Ipv6Addr) -> bool {
    v6.segments()[0] & 0xe000 == 0x2000
}

/// Returns true if the system has a globally routable IPv6 address (2000::/3).
pub fn ipv6_supported() -> bool {
    let targets = [
        "[2001:4860:4860::8888]:53",
        "[2606:4700:4700::1111]:53",
        "[2620:fe::fe]:53",
    ];
    for target in targets {
        if let Ok(addr) = target.parse::<std::net::SocketAddr>() {
            if let Ok(socket) = std::net::UdpSocket::bind("[::]:0") {
                if socket.connect(addr).is_ok() {
                    if let Ok(local_addr) = socket.local_addr() {
                        if let std::net::IpAddr::V6(v6) = local_addr.ip() {
                            if is_global_unicast(v6) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Runs a helper process and returns its stdout, or `None` when the timeout expires.
///
/// Windows-only: it exists for `tasklist` and `route print`, while the POSIX
/// paths read `/proc` and `/etc/resolv.conf` directly — Entware's BusyBox `ps`
/// takes neither `-e` nor `-o` anyway.
#[cfg(target_os = "windows")]
fn run_cmd(program: &str, args: &[&str], timeout_dur: Duration) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let prog = program.to_string();
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    std::thread::spawn(move || {
        let out = std::process::Command::new(prog).args(&owned).output();
        let _ = tx.send(out);
    });
    match rx.recv_timeout(timeout_dur) {
        Ok(Ok(o)) => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        _ => None,
    }
}

/// Discovers system DNS nameservers and default gateway.
/// Registry on Windows; resolv.conf, /proc/net/route and `.wslconfig` elsewhere.
pub fn get_system_dns() -> SystemDnsInfo {
    os::system_dns()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flat list is the machine JSON contract (`runner.rs` copies it into
    /// the report): active entries first, deduped. A host without DNS makes the
    /// assertions vacuous, which is right — what is pinned is the shape of the
    /// report, not this machine's configuration.
    #[test]
    fn test_get_system_dns() {
        let info = get_system_dns();
        let mut active: Vec<IpAddr> = Vec::new();
        for (ip, _) in &info.active {
            if let Ok(addr) = ip.parse::<IpAddr>() {
                if !active.contains(&addr) {
                    active.push(addr);
                }
            }
        }
        assert!(
            info.nameservers.starts_with(&active),
            "active nameservers {:?} do not open the flat list {:?}",
            active,
            info.nameservers
        );
        let mut unique = info.nameservers.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            info.nameservers.len(),
            "the flat nameserver list repeats an address: {:?}",
            info.nameservers
        );
    }

    #[test]
    fn test_flag_emoji() {
        assert_eq!(flag_emoji("ru"), "🇷🇺");
        assert_eq!(flag_emoji("x"), "");
        assert_eq!(flag_emoji(""), "");
        assert!(is_tun_name("Wintun Userspace Tunnel"));
        assert!(!is_tun_name("Ethernet0"));
    }

    /// The verdict `ipv6_supported` reports rests on this predicate alone: the
    /// socket only says which source address the host would use, and the mask
    /// decides whether that address is global. Link-local, unique-local and
    /// loopback must all read as "no global IPv6", or the panel claims a
    /// globally routable address the host cannot reach.
    #[test]
    fn test_global_unicast_prefix() {
        let global = |s: &str| {
            is_global_unicast(s.parse::<Ipv6Addr>().expect("documentation address"))
        };
        assert!(global("2001:4860:4860::8888"));
        assert!(global("2606:4700:4700::1111"));
        assert!(global("3fff::1"));
        assert!(!global("fe80::1"));
        assert!(!global("fd00::1"));
        assert!(!global("::1"));
        assert!(!global("::ffff:192.0.2.1"));
    }
}

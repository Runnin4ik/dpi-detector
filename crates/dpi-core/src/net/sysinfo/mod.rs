//! Host network facts: the DNS servers of the active adapter, its name and
//! the default gateway. Windows reads the registry, other targets read
//! `/etc/resolv.conf`, `/proc/net/route` and `.wslconfig`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

mod bypass;
mod os;

pub use bypass::detect_bypass_tools;

#[derive(Debug, Clone, Default)]
pub struct SystemDnsInfo {
    /// Flat active + other_static list (machine JSON contract), active entries first.
    pub nameservers: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
    /// (server, "static"|"dhcp"|"wsl") on the active interface.
    pub active: Vec<(String, String)>,
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
                            let first = v6.segments()[0];
                            // Check 2000::/3 (global unicast)
                            if (first & 0xe000) == 0x2000 {
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

    #[test]
    fn test_get_system_dns() {
        let info = get_system_dns();
        println!("Discovered nameservers: {:?}", info.nameservers);
        println!("Discovered gateway: {:?}", info.gateway);
        println!("Active adapters: {:?}", info.active);
    }

    #[test]
    fn test_flag_emoji() {
        assert_eq!(flag_emoji("ru"), "🇷🇺");
        assert_eq!(flag_emoji("x"), "");
        assert_eq!(flag_emoji(""), "");
        assert!(is_tun_name("Wintun Userspace Tunnel"));
        assert!(!is_tun_name("Ethernet0"));
    }

    #[test]
    fn test_ipv6_supported() {
        let supported = ipv6_supported();
        println!("IPv6 globally supported: {}", supported);
    }
}

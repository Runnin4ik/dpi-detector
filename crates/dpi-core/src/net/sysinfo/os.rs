//! Platform half of `get_system_dns`: the Windows registry readers and the
//! Windows `route print` default route, plus the POSIX filesystem path.

#[cfg(target_os = "windows")]
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
#[cfg(not(target_os = "windows"))]
use std::net::Ipv4Addr;
#[cfg(target_os = "windows")]
use std::net::Ipv6Addr;
#[cfg(target_os = "windows")]
use std::time::Duration;
#[cfg(target_os = "windows")]
use winreg::enums::{HKEY_LOCAL_MACHINE, REG_BINARY};
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[cfg(target_os = "windows")]
use super::run_cmd;
use super::SystemDnsInfo;

/// Registry bases: IPv4 and IPv6 interface keys, plus the network-class GUID map.
#[cfg(target_os = "windows")]
const TCPIP_BASE: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
#[cfg(target_os = "windows")]
const TCPIP6_BASE: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
#[cfg(target_os = "windows")]
const NET_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

#[cfg(target_os = "windows")]
fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

/// One registry value that Windows may store as either a single string or a
/// list of them: an empty vector when the value is absent.
#[cfg(target_os = "windows")]
fn reg_strings(key: &RegKey, name: &str) -> Vec<String> {
    if let Ok(s) = key.get_value::<String, _>(name) {
        vec![s]
    } else {
        key.get_value::<Vec<String>, _>(name).unwrap_or_default()
    }
}

/// Lowercased GUIDs of the adapters that exist in the network-class registry.
#[cfg(target_os = "windows")]
fn live_adapter_guids() -> HashSet<String> {
    let mut guids = HashSet::new();
    if let Ok(key) = hklm().open_subkey(NET_CLASS) {
        for name in key.enum_keys().flatten() {
            guids.insert(name.to_lowercase());
        }
    }
    guids
}

/// Lowercase GUID -> adapter name, from each adapter key's Connection subkey.
#[cfg(target_os = "windows")]
fn adapter_names() -> HashMap<String, String> {
    let mut names = HashMap::new();
    if let Ok(key) = hklm().open_subkey(NET_CLASS) {
        for guid in key.enum_keys().flatten() {
            let path = format!("{}\\Connection", guid);
            if let Ok(ck) = key.open_subkey(&path) {
                if let Ok(name) = ck.get_value::<String, _>("Name") {
                    names.insert(guid.to_lowercase(), name);
                }
            }
        }
    }
    names
}

/// Real Windows build number via registry (`CurrentBuildNumber`).
/// Never the manifest-masked API; 0 when unreadable.
#[cfg(target_os = "windows")]
fn windows_build() -> u32 {
    if let Ok(k) = hklm().open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
        for val in ["CurrentBuildNumber", "CurrentBuild"] {
            if let Ok(s) = k.get_value::<String, _>(val) {
                if let Ok(n) = s.trim().parse::<u32>() {
                    return n;
                }
            }
            if let Ok(n) = k.get_value::<u32, _>(val) {
                return n;
            }
        }
    }
    0
}

/// Windows marketing name for a build number.
#[cfg(target_os = "windows")]
fn windows_version_name(build: u32) -> &'static str {
    if build >= 22000 {
        "Windows 11"
    } else if build >= 20348 {
        "Windows Server 2022"
    } else if build >= 10240 {
        "Windows 10"
    } else if build >= 9600 {
        "Windows 8.1"
    } else if build >= 9200 {
        "Windows 8"
    } else {
        "Windows 7"
    }
}

/// System DoH map: resolver IP -> template URL, from the Dnscache interface
/// settings ("doh" when the template is missing); empty below build 20348 or
/// when the DNS-client policy disables DoH.
#[cfg(target_os = "windows")]
fn windows_doh(build: u32) -> HashMap<String, String> {
    let mut doh = HashMap::new();
    if build < 20348 {
        return doh;
    }
    if let Ok(k) = hklm().open_subkey(r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient") {
        if let Ok(policy) = k.get_value::<u32, _>("DoHPolicy") {
            if policy == 1 {
                return doh;
            }
        }
    }
    let base = r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters";
    if let Ok(key) = hklm().open_subkey(base) {
        for guid in key.enum_keys().flatten() {
            for folder in ["Doh", "Doh6"] {
                let path = format!("{}\\{}\\DohInterfaceSettings\\{}", base, guid, folder);
                if let Ok(dk) = hklm().open_subkey(&path) {
                    for ip in dk.enum_keys().flatten() {
                        let ipath = format!("{}\\{}", path, ip);
                        if let Ok(ik) = hklm().open_subkey(&ipath) {
                            let flags: u64 = ik
                                .get_value::<u32, _>("DohFlags")
                                .map(u64::from)
                                .or_else(|_| ik.get_value::<u64, _>("DohFlags"))
                                .unwrap_or(0);
                            if flags & 0x0003 != 0 {
                                let tmpl = ik.get_value::<String, _>("DohTemplate").unwrap_or_default();
                                doh.insert(ip, if tmpl.is_empty() { "doh".to_string() } else { tmpl });
                            }
                        }
                    }
                }
            }
        }
    }
    doh
}

#[cfg(target_os = "windows")]
fn split_list(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// DNS of one interface: [(server, "static"|"dhcp")], from its IPv4 and IPv6 keys.
#[cfg(target_os = "windows")]
fn read_dns_entries(guid: &str) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    for base in [TCPIP_BASE, TCPIP6_BASE] {
        let path = format!("{}\\{}", base, guid);
        let key = match hklm().open_subkey(&path) {
            Ok(k) => k,
            Err(_) => continue,
        };
        for (val, src) in [
            ("NameServer", "static"),
            ("DhcpNameServer", "dhcp"),
            ("Dhcpv6DNSServers", "dhcp"),
            ("ProfileNameServer", "dhcp"),
        ] {
            let mut cand: Vec<String> =
                reg_strings(&key, val).iter().flat_map(|s| split_list(s)).collect();
            if cand.is_empty() {
                if let Ok(rv) = key.get_raw_value(val) {
                    if rv.vtype == REG_BINARY {
                        for chunk in rv.bytes.chunks(16) {
                            if chunk.len() == 16 {
                                if let Ok(arr) = <&[u8; 16]>::try_from(chunk) {
                                    cand.push(Ipv6Addr::from(*arr).to_string());
                                }
                            }
                        }
                    }
                }
            }
            for s in cand {
                if !s.is_empty() && !entries.iter().any(|e| e.0 == s) {
                    entries.push((s, src.to_string()));
                }
            }
        }
    }
    entries
}

/// Default route with the lowest metric: (gateway, iface_ip) from `route print`,
/// or empty strings when there is none.
#[cfg(target_os = "windows")]
fn default_route() -> (String, String) {
    let out = match run_cmd("route", &["print", "0.0.0.0"], Duration::from_secs(5)) {
        Some(o) => o,
        None => return (String::new(), String::new()),
    };
    let cut = out.find("Persistent Routes").unwrap_or(out.len());
    let mut best: Option<(String, String, u32)> = None;
    for line in out[..cut].lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() == 5 && p[0] == "0.0.0.0" && p[1] == "0.0.0.0" {
            if let Ok(metric) = p[4].parse::<u32>() {
                let better = best.as_ref().is_none_or(|b| metric < b.2);
                if better {
                    best = Some((p[2].to_string(), p[3].to_string(), metric));
                }
            }
        }
    }
    best.map_or((String::new(), String::new()), |b| (b.0, b.1))
}

/// GUID of the default-route owner via registry gateway/IP match.
#[cfg(target_os = "windows")]
fn adapter_for_route(gw: &str, iface_ip: &str, live: &HashSet<String>) -> String {
    if let Ok(key) = hklm().open_subkey(TCPIP_BASE) {
        for sub in key.enum_keys().flatten() {
            let sub_l = sub.to_lowercase();
            if !live.contains(&sub_l) {
                continue;
            }
            if let Ok(k) = key.open_subkey(&sub) {
                if !gw.is_empty() {
                    for val in ["DhcpDefaultGateway", "DefaultGateway"] {
                        let raw = reg_strings(&k, val);
                        for entry in raw {
                            if entry.split(',').next().unwrap_or("").trim() == gw {
                                return sub_l;
                            }
                        }
                    }
                }
                if !iface_ip.is_empty() {
                    for val in ["DhcpIPAddress", "IPAddress"] {
                        let raw = reg_strings(&k, val);
                        for entry in raw {
                            if entry.split(',').next().unwrap_or("").trim() == iface_ip {
                                return sub_l;
                            }
                        }
                    }
                }
            }
        }
    }
    String::new()
}

/// GUID of the active adapter.
/// Registry match first; fallback scans live interfaces for a gateway value,
/// preferring the route gateway. No netsh subprocess: the registry carries no
/// per-interface metric, so ties break by sorted GUID (deterministic).
#[cfg(target_os = "windows")]
fn active_adapter_guid(live: &HashSet<String>, gw: &str, iface_ip: &str) -> String {
    let (gw, iface_ip) = if gw.is_empty() && iface_ip.is_empty() {
        let (g, i) = default_route();
        (g, i)
    } else {
        (gw.to_string(), iface_ip.to_string())
    };
    if !gw.is_empty() || !iface_ip.is_empty() {
        let g = adapter_for_route(&gw, &iface_ip, live);
        if !g.is_empty() {
            return g;
        }
    }
    let mut guids: Vec<&String> = live.iter().collect();
    guids.sort();
    let mut first = String::new();
    for g in guids {
        let gg = interface_gateway(g);
        if gg.is_empty() {
            continue;
        }
        if !gw.is_empty() && gg == gw {
            return (*g).clone();
        }
        if first.is_empty() {
            first = (*g).clone();
        }
    }
    first
}

/// First gateway value of one interface, read straight from its registry key.
#[cfg(target_os = "windows")]
fn interface_gateway(guid: &str) -> String {
    if let Ok(key) = hklm().open_subkey(TCPIP_BASE) {
        if let Ok(k) = key.open_subkey(guid) {
            for val in ["DhcpDefaultGateway", "DefaultGateway"] {
                for entry in reg_strings(&k, val) {
                    let first = entry.split(',').next().unwrap_or("").trim();
                    if !first.is_empty() {
                        return first.to_string();
                    }
                }
            }
        }
    }
    String::new()
}

/// Flat display/JSON nameserver list: active + other_static, deduped.
fn flat_nameservers(info: &SystemDnsInfo) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for (ip, _) in info.active.iter().chain(info.other_static.iter()) {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

/// Windows: interface DNS from the registry, gateway from `route print`.
#[cfg(target_os = "windows")]
pub(super) fn system_dns() -> SystemDnsInfo {
    let mut info = SystemDnsInfo::default();
    let build = windows_build();
    if build != 0 {
        info.os = Some(format!("{} ({})", windows_version_name(build), build));
    }
    info.doh = windows_doh(build);
    let live = live_adapter_guids();
    if live.is_empty() {
        return info;
    }
    let (gw, iface_ip) = default_route();
    if let Ok(ip) = gw.parse::<IpAddr>() {
        info.gateway = Some(ip);
    }
    let names = adapter_names();
    let active_guid = active_adapter_guid(&live, &gw, &iface_ip);
    if !active_guid.is_empty() {
        info.active = read_dns_entries(&active_guid);
        info.active_name = names.get(&active_guid).cloned();
        if !iface_ip.is_empty() {
            info.active_ip = Some(iface_ip);
        }
        if !info.active.is_empty() {
            let mut shown: HashSet<String> = info.active.iter().map(|e| e.0.clone()).collect();
            let mut guids: Vec<&String> = live.iter().collect();
            guids.sort();
            for g in guids {
                if *g == active_guid {
                    continue;
                }
                for (ip, _) in read_dns_entries(g) {
                    if !shown.contains(&ip) {
                        let name = names.get(g).cloned().unwrap_or_else(|| format!("{{{}}}", &g[..8.min(g.len())]));
                        info.other_static.push((ip.clone(), name));
                        shown.insert(ip);
                    }
                }
            }
            info.nameservers = flat_nameservers(&info);
            return info;
        }
    }
    info.fallback = true;
    let mut guids: Vec<&String> = live.iter().collect();
    guids.sort();
    for g in guids {
        for (ip, src) in read_dns_entries(g) {
            if !info.active.iter().any(|e| e.0 == ip) {
                info.active.push((ip, src));
            }
        }
    }
    info.nameservers = flat_nameservers(&info);
    info
}

/// POSIX: `/etc/resolv.conf` nameservers, `/proc/net/route` gateway, WSL
/// networking mode from `.wslconfig`.
#[cfg(not(target_os = "windows"))]
pub(super) fn system_dns() -> SystemDnsInfo {
    let mut info = SystemDnsInfo::default();
    let is_wsl = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.to_lowercase().contains("microsoft"))
        .unwrap_or(false);
    if is_wsl {
        let mode = wsl_net_mode();
        if !mode.is_empty() {
            info.wsl_net = Some(mode);
        }
    }
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 2 && p[0] == "nameserver" && !info.active.iter().any(|e| e.0 == p[1]) {
                let src = if is_wsl && p[1] == "10.255.255.254" { "wsl" } else { "static" };
                info.active.push((p[1].to_string(), src.to_string()));
            }
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[1] == "00000000" {
                if let Ok(hex) = u32::from_str_radix(parts[2], 16) {
                    info.gateway = Some(IpAddr::V4(Ipv4Addr::from(hex.to_be())));
                    break;
                }
            }
        }
    }
    info.fallback = true;
    info.nameservers = flat_nameservers(&info);
    info
}

/// `[wsl2]` networkingMode from the Windows-side `.wslconfig` ("nat" by default),
/// with " + dnsTunneling" appended when that option is on.
#[cfg(not(target_os = "windows"))]
fn wsl_net_mode() -> String {
    let mut cfg = String::new();
    if let Ok(home) = std::env::var("USERPROFILE") {
        if home.len() >= 3 && home.as_bytes()[1] == b':' {
            let drive = home[..1].to_lowercase();
            let rest = home[2..].replace('\\', "/");
            cfg = format!("/mnt/{}/{}/.wslconfig", drive, rest);
            if !std::path::Path::new(&cfg).exists() {
                cfg.clear();
            }
        }
    }
    if cfg.is_empty() {
        if let Ok(dir) = std::fs::read_dir("/mnt/c/Users") {
            for e in dir.flatten() {
                let p = format!("{}/.wslconfig", e.path().display());
                if std::path::Path::new(&p).exists() {
                    cfg = p;
                    break;
                }
            }
        }
    }
    if cfg.is_empty() {
        return String::new();
    }
    let text = std::fs::read_to_string(&cfg).unwrap_or_default();
    let mut in_wsl2 = false;
    let mut mode = "nat".to_string();
    let mut tunnel = false;
    for line in text.lines() {
        let s = line.trim();
        if s.to_lowercase() == "[wsl2]" {
            in_wsl2 = true;
            continue;
        }
        if in_wsl2 && s.starts_with('[') {
            in_wsl2 = false;
        }
        if !in_wsl2 || !s.contains('=') {
            continue;
        }
        let mut kv = s.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim().to_lowercase();
        let v = kv.next().unwrap_or("").trim().to_lowercase();
        if k == "networkingmode" {
            mode = v;
        } else if k == "dnstunneling" {
            tunnel = matches!(v.as_str(), "true" | "1" | "yes");
        }
    }
    if tunnel {
        format!("{} + dnsTunneling", mode)
    } else {
        mode
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn test_split_list() {
        assert_eq!(split_list("1.1.1.1, 8.8.8.8  9.9.9.9"), vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        assert!(split_list("").is_empty());
    }
}

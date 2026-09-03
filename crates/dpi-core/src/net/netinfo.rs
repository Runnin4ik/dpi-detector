use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};
#[cfg(target_os = "windows")]
use winreg::enums::{HKEY_LOCAL_MACHINE, REG_BINARY};
#[cfg(target_os = "windows")]
use winreg::RegKey;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::dns::query_doh_txt;
use crate::net::tls::create_verifying_tls_config;

#[derive(Debug, Clone, Default)]
pub struct PublicIps {
    pub v4: Option<(Ipv4Addr, u64)>,
    pub v6: Option<(Ipv6Addr, u64)>,
}

#[derive(Debug, Clone, Default)]
pub struct IpCymruInfo {
    pub asn: String,
    /// None = answer missing (renders red "timeout", mirrors setdefault).
    pub subnet: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SystemDnsInfo {
    /// Flat active + other_static list (machine JSON contract; mirrors display order).
    pub nameservers: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
    /// (server, "static"|"dhcp"|"wsl") on the active interface (mirrors `active`).
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

/// Two-letter country code → flag emoji (mirrors `_flag_emoji`).
pub fn flag_emoji(cc: &str) -> String {
    let cc = cc.trim().to_uppercase();
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    cc.chars()
        .map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)).unwrap_or(c))
        .collect()
}

/// True for TUN/VPN adapter names (mirrors `_is_tun_name`).
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

/// Simple, pure-Rust HTTP/HTTPS GET returning text content (capped at 64 KB).
pub async fn http_get_text(url_str: &str, timeout_dur: Duration) -> Result<String, String> {
    // Mirrors httpx follow_redirects=True + status 200 check.
    let mut url = Url::parse(url_str).map_err(|e| format!("Invalid URL: {}", e))?;
    for _ in 0..4 {
        let (status, location, body) = http_get_once(&url, timeout_dur).await?;
        if (300..400).contains(&status) {
            if let Some(loc) = location {
                url = url.join(&loc).map_err(|e| format!("Bad redirect: {}", e))?;
                continue;
            }
        }
        if status != 200 {
            return Err(format!("HTTP status {}", status));
        }
        return String::from_utf8(body).map_err(|e| format!("Non-UTF8 response: {}", e));
    }
    Err("Too many redirects".to_string())
}

async fn http_get_once(url: &Url, timeout_dur: Duration) -> Result<(u16, Option<String>, Vec<u8>), String> {
    let host = url.host_str().ok_or_else(|| "Missing host in URL".to_string())?.to_string();
    let is_https = url.scheme() == "https";
    let port = url.port().unwrap_or(if is_https { 443 } else { 80 });
    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };

    let execute = async {
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("Connect to {} failed: {}", addr, e))?;

        let req = Request::builder()
            .method(Method::GET)
            .uri(path_and_query)
            .header(HOST, &host)
            .header(USER_AGENT, concat!("dpi-detector/", env!("CARGO_PKG_VERSION")))
            .header(ACCEPT, "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;

        if is_https {
            let tls_config = create_verifying_tls_config();
            let connector = TlsConnector::from(tls_config);
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| format!("Invalid TLS server name: {}", e))?;

            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("TLS connect failed: {}", e))?;

            request_once(TokioIo::new(tls_stream), req).await
        } else {
            request_once(TokioIo::new(tcp), req).await
        }
    };

    timeout(timeout_dur, execute)
        .await
        .map_err(|_| "HTTP request timeout".to_string())?
}

/// One HTTP/1.1 request round-trip over any connected stream.
async fn request_once<T>(
    io: TokioIo<T>,
    req: Request<Empty<Bytes>>,
) -> Result<(u16, Option<String>, Vec<u8>), String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP/1.1 handshake failed: {}", e))?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes().to_vec();
    Ok((status, location, body))
}


/// Fetches public IPv4 and IPv6 addresses concurrently with latency in milliseconds.
/// Endpoint lists come from config (IP4/IP6_LOOKUP_URLS).
pub async fn fetch_public_ips(v4_urls: &[String], v6_urls: &[String], timeout_dur: Duration) -> PublicIps {
    /// Python `_lookup_first`: all endpoints race; first valid (right family,
    /// non-private) wins; TTLB is measured from the shared start.
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

/// Mirrors `not ip_obj.is_private`: RFC1918 for v4, unique-local for v6.
fn is_private_lookup_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}


/// Resolves IP ASN, subnet, country code, and Org name via Team Cymru reverse-DNS TXT query over DoH.
pub async fn fetch_ip_cymru(
    ip: &IpAddr,
    doh_servers: &[String],
    timeout_dur: Duration,
) -> Option<IpCymruInfo> {
    // Try each configured Cymru DoH server until one answers (mirrors config fallback chain)
    let fallbacks = ["https://cloudflare-dns.com/dns-query".to_string()];
    let servers: Vec<&str> = if doh_servers.is_empty() {
        fallbacks.iter().map(|s| s.as_str()).collect()
    } else {
        doh_servers.iter().map(|s| s.as_str()).collect()
    };
    for doh in servers {
        if let Some(info) = fetch_ip_cymru_one(ip, doh, timeout_dur).await {
            return Some(info);
        }
    }
    None
}
fn split_txt_fields(txt: &str) -> Vec<&str> {
    txt.trim_matches('"').split('|').map(|s| s.trim()).collect()
}

fn parts_empty(txt: &str) -> bool {
    split_txt_fields(txt).is_empty()
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Cymru origin answer ("AS | subnet | CC | ...") -> (asn, subnet, cc).
/// Mirrors the origin-query parsing in `_fetch_ip_info`.
fn parse_cymru_origin(txt: &str) -> (String, Option<String>, Option<String>) {
    let parts = split_txt_fields(txt);
    let asn = parts.first().unwrap_or(&"").split_whitespace().next().unwrap_or("").to_string();
    let mut subnet: Option<String> = None;
    let mut cc: Option<String> = None;
    for f in parts.iter().skip(1) {
        if f.contains('/') {
            subnet = Some((*f).to_string());
        } else if f.len() == 2 && f.bytes().all(|b| b.is_ascii_uppercase()) {
            cc = Some((*f).to_string());
        }
    }
    (asn, subnet, cc)
}
/// AS-name query TXT -> org name with the allocation-date guard.
fn parse_cymru_as_name(txt: &str) -> String {
    let fields = split_txt_fields(txt);
    let name = if fields.len() >= 3 { fields.last().copied().unwrap_or("") } else { fields.first().copied().unwrap_or("") };
    let org = collapse_ws(name);
    if org.is_empty() || is_cymru_date(&org) {
        String::new()
    } else {
        org
    }
}

/// Allocation-date stub ("2024-01-31") means "no org name".
fn is_cymru_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(|c| c.is_ascii_digit())
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[8..].iter().all(|c| c.is_ascii_digit())
}

async fn fetch_ip_cymru_one(
    ip: &IpAddr,
    doh: &str,
    timeout_dur: Duration,
) -> Option<IpCymruInfo> {

    let origin_query = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::new();
            for seg in v6.segments() {
                for i in (0..4).rev() {
                    let nibble = (seg >> (i * 4)) & 0x0f;
                    nibbles.push(format!("{:x}", nibble));
                }
            }
            nibbles.reverse();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    };

    let txt_records = query_doh_txt(doh, &origin_query, timeout_dur).await.ok()?;
    let first_txt = txt_records.first()?;
    let (asn, subnet, country) = parse_cymru_origin(first_txt);
    if parts_empty(first_txt) || asn.is_empty() {
        return None;
    }

    let mut org: Option<String> = None;
    if !asn.is_empty() {
        let as_query = format!("AS{}.asn.cymru.com", asn);
        if let Ok(as_txts) = query_doh_txt(doh, &as_query, timeout_dur).await {
            if let Some(as_first) = as_txts.first() {
                org = Some(parse_cymru_as_name(as_first));
            }
        }
    }

    Some(IpCymruInfo {
        asn,
        subnet,
        country,
        org,
    })
}

/// Detects running local bypass / proxy tools.
/// Signatures come from config (BYPASS_TOOLS): (display name, lowercase patterns).
pub fn detect_bypass_tools(signatures: &[(String, Vec<String>)]) -> Vec<String> {

    let mut running_processes = HashSet::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(text) = run_cmd("tasklist", &["/FO", "CSV", "/NH"], Duration::from_secs(5)) {
            for line in text.lines() {
                if let Some(first_col) = line.split(',').next() {
                    let mut name = first_col.trim_matches('"').trim().to_lowercase();
                    if name.ends_with(".exe") {
                        name.truncate(name.len() - 4);
                    }
                    running_processes.insert(name);
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(text) = run_cmd("ps", &["-e", "-o", "comm="], Duration::from_secs(5)) {
            for line in text.lines() {
                let name = line.trim().to_lowercase();
                if !name.is_empty() {
                    running_processes.insert(name);
                }
            }
        }
    }

    let mut detected = Vec::new();
    for (tool_name, patterns) in signatures {
        for pattern in patterns {
            if running_processes.contains(pattern.as_str()) {
                detected.push(tool_name.clone());
                break;
            }
        }
    }

    detected
}

/// Registry bases (mirror `system_check.py`).
#[cfg(target_os = "windows")]
const TCPIP_BASE: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
#[cfg(target_os = "windows")]
const TCPIP6_BASE: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
#[cfg(target_os = "windows")]
const NET_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// Runs a helper process with a timeout (mirrors `subprocess.run(..., timeout=5)`).
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


#[cfg(target_os = "windows")]
fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

/// GUIDs of really existing adapters (mirrors `_live_adapter_guids`).
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

/// GUID (lowercase) -> adapter name (mirrors `_adapter_names`).
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
/// Never the manifest-masked API (mirrors `_windows_build`); 0 when unreadable.
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

/// Windows marketing name by build (mirrors `_windows_version_name`).
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

/// System DoH map: server -> template (mirrors `_windows_doh`).
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

/// DNS of one interface: [(server, "static"|"dhcp")] (mirrors `_read_dns_entries`).
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
            let mut cand: Vec<String> = Vec::new();
            if let Ok(s) = key.get_value::<String, _>(val) {
                cand.extend(split_list(&s));
            } else if let Ok(v) = key.get_value::<Vec<String>, _>(val) {
                for item in &v {
                    cand.extend(split_list(item));
                }
            } else if let Ok(rv) = key.get_raw_value(val) {
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
            for s in cand {
                if !s.is_empty() && !entries.iter().any(|e| e.0 == s) {
                    entries.push((s, src.to_string()));
                }
            }
        }
    }
    entries
}

/// Default route with the lowest metric: (gateway, iface_ip) (mirrors `_default_route`).
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

/// GUID of the default-route owner via registry gateway/IP match
/// (mirrors `_adapter_for_route`).
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
                        let mut raw: Vec<String> = Vec::new();
                        if let Ok(s) = k.get_value::<String, _>(val) {
                            raw.push(s);
                        } else if let Ok(v) = k.get_value::<Vec<String>, _>(val) {
                            raw.extend(v);
                        }
                        for entry in raw {
                            if entry.split(',').next().unwrap_or("").trim() == gw {
                                return sub_l;
                            }
                        }
                    }
                }
                if !iface_ip.is_empty() {
                    for val in ["DhcpIPAddress", "IPAddress"] {
                        let mut raw: Vec<String> = Vec::new();
                        if let Ok(s) = k.get_value::<String, _>(val) {
                            raw.push(s);
                        } else if let Ok(v) = k.get_value::<Vec<String>, _>(val) {
                            raw.extend(v);
                        }
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

/// GUID of the active adapter (mirrors `_active_adapter_guid`).
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

/// First gateway value of one interface (registry scan replacing `_netsh_sections`).
#[cfg(target_os = "windows")]
fn interface_gateway(guid: &str) -> String {
    if let Ok(key) = hklm().open_subkey(TCPIP_BASE) {
        if let Ok(k) = key.open_subkey(guid) {
            for val in ["DhcpDefaultGateway", "DefaultGateway"] {
                if let Ok(s) = k.get_value::<String, _>(val) {
                    let first = s.split(',').next().unwrap_or("").trim();
                    if !first.is_empty() {
                        return first.to_string();
                    }
                } else if let Ok(v) = k.get_value::<Vec<String>, _>(val) {
                    for entry in &v {
                        let first = entry.split(',').next().unwrap_or("").trim();
                        if !first.is_empty() {
                            return first.to_string();
                        }
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

/// Discovers system DNS nameservers and default gateway.
/// Mirrors `get_system_dns` (registry on Windows, resolv.conf elsewhere).
pub fn get_system_dns() -> SystemDnsInfo {
    #[cfg(target_os = "windows")]
    {
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
    #[cfg(not(target_os = "windows"))]
    {
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
}

/// `.wslconfig` network mode on the Windows side (mirrors `_wsl_net_mode`).
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
    fn test_detect_bypass_tools() {
        let sigs = vec![("xray".to_string(), vec!["xray".to_string()])];
        let tools = detect_bypass_tools(&sigs);
        println!("Detected bypass tools: {:?}", tools);
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
    fn test_parse_cymru_origin() {
        let (asn, sub, cc) = parse_cymru_origin("\"100 | 10.0.0.0/8 | US | EXAMPLE |\"");
        assert_eq!((asn.as_str(), sub.as_deref(), cc.as_deref()), ("100", Some("10.0.0.0/8"), Some("US")));
        let (asn, sub, cc) = parse_cymru_origin("\"200 |  |  |\"");
        assert_eq!(asn, "200");
        assert_eq!((sub, cc), (None, None));
        // last field of each kind wins, like the Python loop
        let (_, sub, cc) = parse_cymru_origin("\"300 | 1.0.0.0/8 | XY | 2.0.0.0/8 | ZZ |\"");
        assert_eq!((sub.as_deref(), cc.as_deref()), (Some("2.0.0.0/8"), Some("ZZ")));
    }

    #[test]
    fn test_parse_cymru_as_name() {
        assert_eq!(parse_cymru_as_name("\"65001 | US | ARIN | 2000-01-01 | EXAMPLE ORG\""), "EXAMPLE ORG");
        assert_eq!(parse_cymru_as_name("\"100 | AS100 | 2024-01-31\""), "");
        assert_eq!(parse_cymru_as_name("\"LONELY\""), "LONELY");
        assert!(is_cymru_date("2024-01-31"));
        assert!(!is_cymru_date("EXAMPLE"));
    }

    #[test]
    fn test_split_list() {
        assert_eq!(split_list("1.1.1.1, 8.8.8.8  9.9.9.9"), vec!["1.1.1.1", "8.8.8.8", "9.9.9.9"]);
        assert!(split_list("").is_empty());
    }

    #[test]
    fn test_ipv6_supported() {
        let supported = ipv6_supported();
        println!("IPv6 globally supported: {}", supported);
    }
}

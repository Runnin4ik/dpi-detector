//! Test 2: domain availability — DNS resolve + TLS 1.3 + TLS 1.2 + HTTP.
//!
//! Mirrors `core/tls_scanner.py` + `cli/runners.py::run_domains_test`:
//! phase 0 resolves every domain (family from config), marks ISP stubs,
//! phases 1–2 probe TLS 1.3 / TLS 1.2 with SNI pinned to the resolved IP,
//! phase 3 checks plain-HTTP injection. Result rows are
//! (domain, http, tls1.2, tls1.3, details) like the Python table.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::header::{ACCEPT, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_ssl_error, ConnectionStage, DpiStatus,
    DET_DOMAIN_NOT_FOUND, DET_IPV6_UNSUPPORTED, DET_ISP_STUB_ARROW, DET_ISP_STUB_SPACE,
    DET_KB_SUFFIX, DET_LOCAL_IP_ARROW, DET_READ_TIMEOUT_WORD, DET_RST_HELLO, DET_TCP_SYN_TIMEOUT,
    DET_TIMEOUT_WORD, DET_TLS_HANDSHAKE_TIMEOUT,
};
use crate::config::AppConfig;
use crate::dns::resolve_host;
use crate::PhaseProgress;
use crate::probe::connector::RustlsConnector;
use crate::probe::http::{negotiated_h2, HttpRequest, HttpSender};
use crate::probe::DpiTlsConnector;

const BODY_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    pub fn from_config(ip_version: &str) -> Self {
        if ip_version == "ipv6" {
            Self::V6
        } else {
            Self::V4
        }
    }
}

/// Resolves a domain to one IP of the requested family (up to 2 attempts,
/// mirrors `get_resolved_ip`).
pub async fn resolve_ip(domain: &str, family: IpFamily) -> Option<IpAddr> {
    // System resolver first, UDP bootstrap fallback (Android has no resolv.conf).
    const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
    let want_v6 = family == IpFamily::V6;
    for attempt in 0..2 {
        if attempt == 1 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if let Ok(addrs) = resolve_host(domain, 443, RESOLVE_TIMEOUT).await {
            for addr in addrs {
                let is_v6 = addr.ip().is_ipv6();
                if is_v6 == want_v6 {
                    return Some(addr.ip());
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeIpType {
    FakeIp,
    Isp,
    Local,
    Clean,
}

/// Mirrors `get_fake_ip_type`: 198.18.0.0/15 → fakeip, 100.64.0.0/10 → isp,
/// loopback/private/link-local/unspecified → local.
pub fn fake_ip_type(ip: &IpAddr) -> FakeIpType {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 198.18.0.0/15 (Fake-IP)
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return FakeIpType::FakeIp;
            }
            // 100.64.0.0/10 (CGNAT / ISP stubs)
            if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
                return FakeIpType::Isp;
            }
            if v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() {
                return FakeIpType::Local;
            }
            FakeIpType::Clean
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            if v6.is_loopback()
                || v6.is_unspecified()
                || (seg0 & 0xffc0) == 0xfe80
                || (seg0 & 0xfe00) == 0xfc00
                || v6.to_ipv4_mapped().map(|v4| v4.is_private()).unwrap_or(false)
            {
                return FakeIpType::Local;
            }
            FakeIpType::Clean
        }
    }
}

pub fn is_local_or_relay_ip(ip: &IpAddr) -> bool {
    !matches!(fake_ip_type(ip), FakeIpType::Clean)
}

fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

fn parse_host(url_or_host: &str) -> String {
    let mut s = url_or_host.trim().to_ascii_lowercase();
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    if let Some(idx) = s.find(['/', '?', '#']) {
        s = s[..idx].to_string();
    }
    // Strip :port (but not bare IPv6)
    if s.matches(':').count() == 1 {
        if let Some(idx) = s.rfind(':') {
            let port = &s[idx + 1..];
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                s = s[..idx].to_string();
            }
        }
    }
    s.trim_matches(|c| c == '.' || c == '[' || c == ']').to_string()
}

/// Resolves a `Location` against the probe's base URL the way
/// `urllib.parse.urljoin` does for the shapes a redirect uses, so the redirect
/// is judged against the host it really goes to:
///   `https://host/x`  - absolute, used as is;
///   `//host/x`        - protocol-relative: scheme from the base, host from the
///                       Location (a foreign host here is NOT a local path);
///   `/x`, `x`, `?q`   - relative: stays on the base scheme and host.
fn resolve_location(base: &str, location: &str) -> String {
    let scheme = base.split("://").next().unwrap_or("https");
    if location.contains("://") {
        return location.to_string();
    }
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{}://{}", scheme, rest);
    }
    let host = parse_host(base);
    if location.starts_with('/') {
        format!("{}://{}{}", scheme, host, location)
    } else {
        format!("{}://{}/{}", scheme, host, location)
    }
}

/// Classifies an HTTP redirect (mirrors `_check_tls_single` /
/// `check_http_injection` redirect branches).
pub fn classify_redirect(
    domain: &str,
    base_url: &str,
    status: u16,
    location: &str,
    http_phase: bool,
) -> (DpiStatus, String) {
    let resolved = resolve_location(base_url, location);

    let loc_host_raw = parse_host(&resolved);
    let loc_host = loc_host_raw.to_ascii_lowercase();
    let scheme_https = resolved.to_ascii_lowercase().starts_with("https");
    let norm_loc = strip_www(&loc_host).to_string();
    let norm_dom = strip_www(&domain.to_ascii_lowercase()).to_string();
    let same_host = norm_loc == norm_dom || norm_loc.ends_with(&format!(".{}", norm_dom));
    let short_host: String = loc_host.chars().take(30).collect();

    if http_phase {
        if same_host && scheme_https {
            return (DpiStatus::Ok, format!("{} → https", status));
        }
        if same_host {
            // Same domain (or a subdomain) is a normal redirect: OK, not a badge
            // of its own. Only a foreign domain is flagged, as a red REDIR.
            return (DpiStatus::Ok, format!("{}", status));
        }
        return (DpiStatus::RedirSuspect, format!("→ {}", short_host));
    }

    if same_host && scheme_https {
        return (DpiStatus::Ok, "→ https".to_string());
    }
    if same_host {
        return (DpiStatus::Ok, format!("→ {}", short_host));
    }
    (DpiStatus::RedirSuspect, format!("→ {}", short_host))
}

#[derive(Debug, Clone)]
pub struct TlsCheck {
    pub status: DpiStatus,
    pub detail: String,
    pub elapsed: f64,
}

#[derive(Debug, Clone)]
pub struct HttpCheck {
    pub status: DpiStatus,
    pub detail: String,
}

/// Extracts (message, os code, kind) from a hyper error chain. The trailing
/// `io::Error` is the only element that carries the OS code, and Windows
/// localizes its message, so the code - not the text - is the signal the
/// classifier can rely on.
fn hyper_err_info(e: &hyper::Error) -> (String, Option<i32>, Option<std::io::ErrorKind>) {
    let msg = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        if let Some(io_err) = s.downcast_ref::<std::io::Error>() {
            let mut full = msg.clone();
            full.push_str(&format!(" | {}", io_err));
            return (full, io_err.raw_os_error(), Some(io_err.kind()));
        }
        source = std::error::Error::source(s);
    }
    (msg, None, None)
}

fn inner_hyper(
    e: &hyper::Error,
    stage: &str,
    bytes: usize,
    min_kb: u64,
    max_kb: u64,
) -> (DpiStatus, String) {
    let (msg, os_code, os_kind) = hyper_err_info(e);
    let lower = msg.to_ascii_lowercase();

    // Read timeout inside the fat window → TCP16-20 signature
    if (e.is_timeout() || lower.contains("timed out")) && stage == "reading_data" {
        let kb = bytes as f64 / 1024.0;
        if kb >= min_kb as f64 && kb <= max_kb as f64 {
            return (DpiStatus::Tcp16Range, format!("{} {:.1}{}", DET_TIMEOUT_WORD, kb, DET_KB_SUFFIX));
        }
        if bytes > 0 {
            return (DpiStatus::ReadTimeout, format!("{} {:.1}{}", DET_READ_TIMEOUT_WORD, kb, DET_KB_SUFFIX));
        }
        return (DpiStatus::ReadTimeout, DET_READ_TIMEOUT_WORD.into());
    }

    let (s, d) = classify_ssl_error(&msg, bytes, ConnectionStage::TlsClientHelloSent);
    if s != DpiStatus::Unknown {
        return (s, d);
    }
    classify_connect_error_full(&msg, os_code, os_kind, bytes, stage)
}

/// Single TLS check against `target` with SNI/host = `domain`
/// (mirrors `_check_tls_single`).
pub async fn check_domain_tls(
    domain: &str,
    target: IpAddr,
    tls12_only: bool,
    cfg: &AppConfig,
) -> TlsCheck {
    let start = Instant::now();
    let total_timeout = Duration::from_secs_f64(cfg.connect_timeout + cfg.read_timeout);
    let stage = Arc::new(Mutex::new("tcp_connect".to_string()));
    let addr = SocketAddr::new(target, 443);

    let fut = async {
        let tcp = match timeout(Duration::from_secs_f64(cfg.connect_timeout), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                s
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                let (s, d) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tcp_connect");
                return (s, d, 0usize);
            }
            Err(_) => {
                return (DpiStatus::SynDropped, DET_TCP_SYN_TIMEOUT.to_string(), 0usize);
            }
        };

        // TLS handshake (version-pinned client)
        *stage.lock() = "tls_handshake".to_string();
        let fingerprint = cfg.fingerprint();
        let rustls_conn = if tls12_only {
            RustlsConnector::new_insecure_tls12_with(fingerprint)
        } else {
            RustlsConnector::new_insecure_tls13_with(fingerprint)
        };
        let server_name = match ServerName::try_from(domain.to_string()) {
            Ok(n) => n,
            Err(e) => {
                return (DpiStatus::Err, format!("bad SNI: {}", e), 0usize);
            }
        };
        let tracker = crate::classify::DpiProbeTracker::new();
        let probe_stream = crate::classify::DpiProbeStream::new(tcp, tracker.clone());
        let tls_stream = match timeout(
            Duration::from_secs_f64(cfg.connect_timeout),
            rustls_conn.connect(server_name, probe_stream),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let st = tracker.state.lock();
                if let Some(s) = st.last_status {
                    let d = st.last_error_msg.clone().unwrap_or_else(|| DET_RST_HELLO.to_string());
                    return (s, d, 0usize);
                }
                drop(st);
                let msg = e.to_string();
                let (s, d) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tls_handshake");
                if s != DpiStatus::Unknown {
                    return (s, d, 0usize);
                }
                let (s2, d2) = classify_ssl_error(&msg, 0, ConnectionStage::TlsClientHelloSent);
                return (s2, d2, 0usize);
            }
            Err(_) => {
                return (DpiStatus::TlsDropped, DET_TLS_HANDSHAKE_TIMEOUT.to_string(), 0usize);
            }
        };

        *stage.lock() = "tls_connected".to_string();
        let alpn_h2 = negotiated_h2(&tls_stream);
        let io = TokioIo::new(tls_stream);
        let mut sender = match HttpSender::handshake(io, alpn_h2).await {
            Ok(sender) => sender,
            Err(e) => {
                let (s, d) = inner_hyper(&e, "tls_connected", 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
        };

        // GET with Host = domain, fresh socket per probe (Connection: close)
        let req = HttpRequest {
            method: Method::GET,
            host: domain,
            path: "/",
            user_agent: cfg.user_agent.as_str(),
            headers: vec![
                ("Accept-Encoding", "identity".to_string()),
                ("Connection", "close".to_string()),
            ],
        };

        *stage.lock() = "sending_data".to_string();
        let resp = match timeout(Duration::from_secs_f64(cfg.read_timeout), sender.send(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let st = stage.lock().clone();
                let (s, d) = inner_hyper(&e, &st, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return (s, d, 0usize);
            }
            Err(_) => {
                return (DpiStatus::ReadTimeout, DET_READ_TIMEOUT_WORD.to_string(), 0usize);
            }
        };

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if status == 451 {
            return (DpiStatus::Blocked, "HTTP 451".to_string(), 0usize);
        }
        if !location.is_empty() && (300..400).contains(&status) {
            let (s, d) = classify_redirect(domain, &format!("https://{}", domain), status, &location, false);
            return (s, d, 0usize);
        }
        if (300..400).contains(&status) {
            // A 3xx with no Location points nowhere foreign: normal, like a
            // same-host redirect.
            return (DpiStatus::Ok, String::new(), 0usize);
        }

        // Read body capped at 64 KB
        *stage.lock() = "reading_data".to_string();
        let mut body = resp.into_body();
        let mut bytes_read: usize = 0;
        loop {
            match timeout(Duration::from_secs_f64(cfg.read_timeout), body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        bytes_read += data.len();
                        if bytes_read >= BODY_CAP {
                            break;
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    let (s, d) = inner_hyper(&e, "reading_data", bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                    return (s, d, bytes_read);
                }
                Ok(None) => break,
                Err(_) => {
                    let kb = bytes_read as f64 / 1024.0;
                    if kb >= cfg.tcp_block_min_kb as f64 && kb <= cfg.tcp_block_max_kb as f64 {
                        return (DpiStatus::Tcp16Range, format!("{} {:.1}{}", DET_TIMEOUT_WORD, kb, DET_KB_SUFFIX), bytes_read);
                    }
                    if bytes_read > 0 {
                        return (DpiStatus::ReadTimeout, format!("{} {:.1}{}", DET_READ_TIMEOUT_WORD, kb, DET_KB_SUFFIX), bytes_read);
                    }
                    return (DpiStatus::ReadTimeout, DET_READ_TIMEOUT_WORD.to_string(), bytes_read);
                }
            }
        }

        if (200..500).contains(&status) {
            (DpiStatus::Ok, String::new(), bytes_read)
        } else {
            (DpiStatus::Ok, format!("HTTP {}", status), bytes_read)
        }
    };

    match timeout(total_timeout, fut).await {
        Ok((s, d, _)) => TlsCheck { status: s, detail: d, elapsed: start.elapsed().as_secs_f64() },
        Err(_) => {
            let st = stage.lock().clone();
            let (s, d) = match st.as_str() {
                "tls_handshake" => (DpiStatus::TlsDropped, DET_TLS_HANDSHAKE_TIMEOUT.to_string()),
                "tcp_connect" => (DpiStatus::SynDropped, DET_TCP_SYN_TIMEOUT.to_string()),
                _ => (DpiStatus::ReadTimeout, DET_READ_TIMEOUT_WORD.to_string()),
            };
            TlsCheck { status: s, detail: d, elapsed: start.elapsed().as_secs_f64() }
        }
    }
}


/// Plain-HTTP injection check (mirrors `check_http_injection`): HEAD to
/// port 80 of the resolved IP with Host = domain.
pub async fn check_http_injection(
    domain: &str,
    target: Option<IpAddr>,
    cfg: &AppConfig,
    stub_ips: &HashSet<IpAddr>,
) -> HttpCheck {
    if let Some(ip) = target {
        if stub_ips.contains(&ip) {
            return HttpCheck {
                status: DpiStatus::IspPage,
                detail: format!("{}{}", DET_ISP_STUB_SPACE, ip),
            };
        }
    }
    let total_timeout = Duration::from_secs_f64(cfg.connect_timeout + cfg.read_timeout);
    let domain_owned = domain.to_string();

    let fut = async {
        let host_ip = match target {
            Some(ip) => ip,
            None => match resolve_ip(domain_owned.as_str(), IpFamily::V4).await {
                Some(ip) => ip,
                None => {
                    return HttpCheck { status: DpiStatus::DnsFail, detail: DET_DOMAIN_NOT_FOUND.to_string() };
                }
            },
        };
        let addr = SocketAddr::new(host_ip, 80);
        let tcp = match timeout(Duration::from_secs_f64(cfg.connect_timeout), TcpStream::connect(&addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                s
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                let (s, d) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tcp_connect");
                return HttpCheck { status: s, detail: d };
            }
            Err(_) => {
                return HttpCheck { status: DpiStatus::SynDropped, detail: DET_TCP_SYN_TIMEOUT.to_string() };
            }
        };

        let io = TokioIo::new(tcp);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(v) => v,
            Err(e) => {
                let (s, d) = inner_hyper(&e, "tcp_connect", 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return HttpCheck { status: s, detail: d };
            }
        };
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::HEAD)
            .uri("/")
            .header(HOST, domain_owned.as_str())
            .header(USER_AGENT, cfg.user_agent.as_str())
            .header(ACCEPT, "*/*")
            .header("Connection", "close")
            .body(http_body_util::Full::new(Bytes::new()))
            .expect("valid request");

        let resp = match timeout(Duration::from_secs_f64(cfg.read_timeout), sender.send_request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let msg = e.to_string().to_ascii_lowercase();
                if e.is_timeout() || msg.contains("timed out") {
                    let kind = if msg.contains("write") {
                        DpiStatus::SendTimeout
                    } else if msg.contains("pool") {
                        DpiStatus::PoolTimeout
                    } else {
                        DpiStatus::ReadTimeout
                    };
                    return HttpCheck { status: kind, detail: DET_TIMEOUT_WORD.to_string() };
                }
                let (s, d) = inner_hyper(&e, "reading_data", 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return HttpCheck { status: s, detail: d };
            }
            Err(_) => {
                return HttpCheck { status: DpiStatus::ReadTimeout, detail: DET_TIMEOUT_WORD.to_string() };
            }
        };

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if status == 451 {
            return HttpCheck { status: DpiStatus::Blocked, detail: "HTTP 451".to_string() };
        }
        if !location.is_empty() && (300..400).contains(&status) {
            let (s, d) = classify_redirect(&domain_owned, &format!("http://{}", domain_owned), status, &location, true);
            return HttpCheck { status: s, detail: d };
        }
        if (300..400).contains(&status) {
            return HttpCheck { status: DpiStatus::Ok, detail: format!("{}", status) };
        }
        HttpCheck { status: DpiStatus::Ok, detail: format!("{}", status) }
    };

    match timeout(total_timeout, fut).await {
        Ok(r) => r,
        Err(_) => HttpCheck { status: DpiStatus::ReadTimeout, detail: DET_TIMEOUT_WORD.to_string() },
    }
}

#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub domain: String,
    pub resolved: Option<IpAddr>,
    /// None = DNS FAIL, Some(true) = stub/fake, Some(false) = clean
    pub dns_fake: Option<bool>,
    pub t13: TlsCheck,
    pub t12: TlsCheck,
    pub http: HttpCheck,
}

impl DomainEntry {
    fn pending(domain: String, resolved: Option<IpAddr>, dns_fake: Option<bool>) -> Self {
        let dash = TlsCheck { status: DpiStatus::Unknown, detail: "—".to_string(), elapsed: 0.0 };
        Self {
            domain,
            resolved,
            dns_fake,
            t13: dash.clone(),
            t12: dash,
            http: HttpCheck { status: DpiStatus::Unknown, detail: "—".to_string() },
        }
    }
}

/// Phase 0: resolve every domain (mirrors `_resolve_worker`).
pub async fn resolve_all(
    domains: &[String],
    family: IpFamily,
    stub_ips: &HashSet<IpAddr>,
    sem: &Arc<Semaphore>,
    phases: Option<PhaseProgress>,
) -> Vec<DomainEntry> {
    let tick = phases
        .as_ref()
        .map(|p| (p.on_phase)(crate::PhaseId::DomainDns, domains.len()));
    let mut handles = Vec::new();
    for domain in domains {
        let domain = domain.clone();
        let sem = Arc::clone(sem);
        let stub_ips = stub_ips.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let clean_domain = parse_host(&domain);
            let resolved = resolve_ip(&clean_domain, family).await;
            // IPv6 mode: IPv4 fallback distinguishes NXDOMAIN from no-v6
            let v4_fallback = if resolved.is_none() && family == IpFamily::V6 {
                resolve_ip(&domain, IpFamily::V4).await
            } else {
                None
            };
            match resolved {
                None => {
                    let mut e = DomainEntry::pending(domain, None, None);
                    let detail = if v4_fallback.is_some() {
                        DET_IPV6_UNSUPPORTED
                    } else {
                        DET_DOMAIN_NOT_FOUND
                    };
                    e.t13 = TlsCheck { status: DpiStatus::DnsFail, detail: detail.into(), elapsed: 0.0 };
                    e.t12 = e.t13.clone();
                    e.http = HttpCheck { status: DpiStatus::DnsFail, detail: detail.into() };
                    e
                }
                Some(ip) => {
                    let mut ftype = fake_ip_type(&ip);
                    if ftype != FakeIpType::FakeIp && stub_ips.contains(&ip) {
                        ftype = FakeIpType::Isp;
                    }
                    match ftype {
                        FakeIpType::Isp => {
                            let mut e = DomainEntry::pending(domain, Some(ip), Some(true));
                            let detail = format!("{}{}", DET_ISP_STUB_ARROW, ip);
                            e.t13 = TlsCheck { status: DpiStatus::DnsFake, detail: detail.clone(), elapsed: 0.0 };
                            e.t12 = e.t13.clone();
                            e.http = HttpCheck { status: DpiStatus::DnsFake, detail };
                            e
                        }
                        FakeIpType::Local => {
                            let mut e = DomainEntry::pending(domain, Some(ip), Some(true));
                            let detail = format!("{}{}", DET_LOCAL_IP_ARROW, ip);
                            e.t13 = TlsCheck { status: DpiStatus::LocalIp, detail: detail.clone(), elapsed: 0.0 };
                            e.t12 = e.t13.clone();
                            e.http = HttpCheck { status: DpiStatus::LocalIp, detail };
                            e
                        }
                        _ => DomainEntry::pending(domain, Some(ip), Some(false)),
                    }
                }
            }
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        let done = h.await;
        if let Some(t) = tick.as_ref() {
            t();
        }
        if let Ok(e) = done {
            out.push(e);
        }
    }
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    out
}
pub async fn check_tls_all(
    entries: &mut [DomainEntry],
    tls12_only: bool,
    cfg: &AppConfig,
    sem: &Arc<Semaphore>,
    phases: Option<PhaseProgress>,
) {
    let total = entries.iter().filter(|e| e.dns_fake == Some(false)).count();
    let pid = if tls12_only { crate::PhaseId::DomainTls12 } else { crate::PhaseId::DomainTls13 };
    let tick = phases.as_ref().map(|p| (p.on_phase)(pid, total));
    let mut handles = Vec::new();
    for (idx, e) in entries.iter().enumerate() {
        if e.dns_fake != Some(false) {
            continue;
        }
        let domain = e.domain.clone();
        let target = e.resolved.unwrap();
        let cfg = cfg.clone();
        let sem = Arc::clone(sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let r = check_domain_tls(&domain, target, tls12_only, &cfg).await;
            (idx, r)
        }));
    }
    for h in handles {
        let done = h.await;
        if let Some(t) = tick.as_ref() {
            t();
        }
        if let Ok((idx, r)) = done {
            if tls12_only {
                entries[idx].t12 = r;
            } else {
                entries[idx].t13 = r;
            }
        }
    }
}

/// HTTP phase for all clean entries (mirrors `_http_worker`).
pub async fn check_http_all(
    entries: &mut [DomainEntry],
    cfg: &AppConfig,
    stub_ips: &HashSet<IpAddr>,
    sem: &Arc<Semaphore>,
    phases: Option<PhaseProgress>,
) {
    let total = entries.iter().filter(|e| e.dns_fake == Some(false)).count();
    let tick = phases
        .as_ref()
        .map(|p| (p.on_phase)(crate::PhaseId::DomainHttp, total));
    let mut handles = Vec::new();
    for (idx, e) in entries.iter().enumerate() {
        if e.dns_fake != Some(false) {
            continue;
        }
        let domain = e.domain.clone();
        let target = e.resolved;
        let cfg = cfg.clone();
        let sem = Arc::clone(sem);
        let stub_ips = stub_ips.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let r = check_http_injection(&domain, target, &cfg, &stub_ips).await;
            (idx, r)
        }));
    }
    for h in handles {
        let done = h.await;
        if let Some(t) = tick.as_ref() {
            t();
        }
        if let Ok((idx, r)) = done {
            entries[idx].http = r;
        }
    }
}

/// Silently collects provider stub IPs (mirrors `collect_stub_ips_silently`):
/// IPs returned for ≥ `threshold` distinct domains.
pub async fn collect_stub_ips(
    cfg: &AppConfig,
) -> HashSet<IpAddr> {
    let check_domains = &cfg.dns_check_domains;
    let timeout_dur = Duration::from_secs(2);
    let mut ip_counts: HashMap<IpAddr, usize> = HashMap::new();

    for entry in &cfg.dns_udp_servers {
        if entry.is_empty() {
            continue;
        }
        let server_ip = &entry[0];
        let Ok(server_addr) = format!("{}:53", server_ip).parse::<SocketAddr>() else {
            continue;
        };

        let mut answered = false;
        for domain in check_domains {
            if let Ok((ips, _)) = crate::dns::udp::probe_udp_dns(server_addr, domain, timeout_dur, None).await {
                if !ips.is_empty() {
                    answered = true;
                    for ip in ips {
                        *ip_counts.entry(ip).or_insert(0) += 1;
                    }
                }
            }
        }
        if answered {
            break;
        }
    }

    let threshold = (cfg.dns_stub_threshold as usize).max(2);
    ip_counts
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .map(|(ip, _)| ip)
        .collect()
}

fn col_ok(status: DpiStatus) -> bool {
    status.is_ok_status()
}

fn col_ok_t12(status: DpiStatus) -> bool {
    matches!(status, DpiStatus::Ok | DpiStatus::NoTls13)
}

#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    pub total: usize,
    pub ok: usize,
    pub timeout: usize,
    pub dns_fail: usize,
    pub blocked: usize,
    pub http_ok: usize,
    pub t12_ok: usize,
    pub t13_ok: usize,
}

fn is_timeout_status(s: DpiStatus) -> bool {
    matches!(
        s,
        DpiStatus::Timeout | DpiStatus::ReadTimeout | DpiStatus::SendTimeout | DpiStatus::PoolTimeout
    )
}

pub fn domain_stats(entries: &[DomainEntry]) -> DomainStats {
    let is_ok_t13 = |e: &DomainEntry| col_ok(e.t13.status) || e.t13.status == DpiStatus::NoTls13;
    let is_ok_t12 = |e: &DomainEntry| col_ok(e.t12.status) || e.t12.status == DpiStatus::NoTls13;
    DomainStats {
        total: entries.len(),
        ok: entries.iter().filter(|e| col_ok(e.t13.status) || col_ok(e.t12.status)).count(),
        timeout: entries
            .iter()
            .filter(|e| is_timeout_status(e.t13.status) || is_timeout_status(e.t12.status))
            .count(),
        dns_fail: entries.iter().filter(|e| e.t13.status == DpiStatus::DnsFail).count(),
        blocked: entries
            .iter()
            .filter(|e| {
                e.http.status.is_blocked() || e.t12.status.is_blocked() || e.t13.status.is_blocked()
            })
            .count(),
        http_ok: entries.iter().filter(|e| col_ok(e.http.status)).count(),
        t12_ok: entries.iter().filter(|e| is_ok_t12(e)).count(),
        t13_ok: entries.iter().filter(|e| is_ok_t13(e)).count(),
    }
}

/// Builds the (http, t12, t13, details) cells (mirrors `build_domain_row`).
pub fn build_domain_row(e: &DomainEntry) -> (DpiStatus, DpiStatus, DpiStatus, String) {
    let http_ok = col_ok(e.http.status);
    let t12_ok = col_ok_t12(e.t12.status);
    let t13_ok = col_ok_t12(e.t13.status);

    let mut problems: Vec<(&str, String)> = Vec::new();
    if !http_ok && !e.http.detail.is_empty() && e.http.detail != "—" {
        let hd = e.http.detail.strip_prefix("HTTP ").unwrap_or(&e.http.detail).trim();
        let is_timeout = is_timeout_status(e.http.status)
            || hd.eq_ignore_ascii_case("timeout")
            || hd.eq_ignore_ascii_case("read timeout");
        if !is_timeout {
            problems.push(("HTTP", hd.to_string()));
        }
    }
    if !t12_ok && !e.t12.detail.is_empty() && e.t12.detail != "—" {
        let d = e.t12.detail.trim();
        if !d.eq_ignore_ascii_case("timeout") && !d.eq_ignore_ascii_case("read timeout") {
            problems.push(("T1.2", d.to_string()));
        }
    }
    if !t13_ok && !e.t13.detail.is_empty() && e.t13.detail != "—" {
        let d = e.t13.detail.trim();
        if !d.eq_ignore_ascii_case("timeout") && !d.eq_ignore_ascii_case("read timeout") {
            problems.push(("T1.3", d.to_string()));
        }
    }

    let mut details: Vec<String> = Vec::new();
    if problems.len() == 1 {
        details.push(problems[0].1.clone());
    } else {
        let mut grouped: HashMap<String, Vec<&str>> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        for (proto, d) in &problems {
            if !grouped.contains_key(d) {
                order.push(d.clone());
            }
            grouped.entry(d.clone()).or_default().push(proto);
        }
        for d in order {
            let protos = &grouped[&d];
            if protos.len() == 1 {
                details.push(format!("{}:{}", protos[0], d));
            } else {
                details.push(d);
            }
        }
    }

    if t12_ok && t13_ok {
        let mut times: Vec<f64> = Vec::new();
        if e.t12.elapsed > 0.0 {
            times.push(e.t12.elapsed);
        }
        if e.t13.elapsed > 0.0 {
            times.push(e.t13.elapsed);
        }
        if let Some(min) = times.iter().cloned().reduce(f64::min) {
            details.clear();
            details.push(format!("{:.1}s", min));
        }
    }

    (e.http.status, e.t12.status, e.t13.status, details.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_type() {
        assert_eq!(fake_ip_type(&"198.18.5.4".parse().unwrap()), FakeIpType::FakeIp);
        assert_eq!(fake_ip_type(&"100.64.0.5".parse().unwrap()), FakeIpType::Isp);
        assert_eq!(fake_ip_type(&"192.168.1.1".parse().unwrap()), FakeIpType::Local);
        assert_eq!(fake_ip_type(&"8.8.8.8".parse().unwrap()), FakeIpType::Clean);
    }
    #[test]
    fn test_build_domain_row_http_timeout_tls_ok_shows_time() {
        let mut entry = DomainEntry::pending("browserleaks.com".to_string(), None, None);
        entry.http = HttpCheck { status: DpiStatus::ReadTimeout, detail: DET_TIMEOUT_WORD.to_string() };
        entry.t12 = TlsCheck { status: DpiStatus::Ok, detail: String::new(), elapsed: 0.35 };
        entry.t13 = TlsCheck { status: DpiStatus::Ok, detail: String::new(), elapsed: 0.28 };

        let (http_s, t12_s, t13_s, details) = build_domain_row(&entry);
        assert_eq!(http_s, DpiStatus::ReadTimeout);
        assert_eq!(http_s.display_label(), "TIMEOUT");
        assert_eq!(t12_s, DpiStatus::Ok);
        assert_eq!(t13_s, DpiStatus::Ok);
        assert_eq!(details, "0.3s"); // Shows elapsed time, no "Timeout"
    }

    #[test]
    fn test_build_domain_row_http_timeout_tls_rst_omits_http_timeout() {
        let mut entry = DomainEntry::pending("danbooru.donmai.us".to_string(), None, None);
        entry.http = HttpCheck { status: DpiStatus::ReadTimeout, detail: DET_TIMEOUT_WORD.to_string() };
        entry.t12 = TlsCheck { status: DpiStatus::TlsRst, detail: "TCP RST on ClientHello".to_string(), elapsed: 0.1 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsRst, detail: "TCP RST on ClientHello".to_string(), elapsed: 0.1 };

        let (http_s, t12_s, t13_s, details) = build_domain_row(&entry);
        assert_eq!(http_s, DpiStatus::ReadTimeout);
        assert_eq!(http_s.display_label(), "TIMEOUT");
        assert_eq!(t12_s, DpiStatus::TlsRst);
        assert_eq!(t13_s, DpiStatus::TlsRst);
        // Only TLS RST is shown, NO "HTTP:Timeout"
        assert_eq!(details, "TCP RST on ClientHello");
    }

    #[test]
    fn test_build_domain_row_tls_drop_omits_http_timeout() {
        let mut entry = DomainEntry::pending("discord.com".to_string(), None, None);
        entry.http = HttpCheck { status: DpiStatus::ReadTimeout, detail: DET_TIMEOUT_WORD.to_string() };
        entry.t12 = TlsCheck { status: DpiStatus::TlsDropped, detail: DET_TLS_HANDSHAKE_TIMEOUT.to_string(), elapsed: 5.0 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsDropped, detail: DET_TLS_HANDSHAKE_TIMEOUT.to_string(), elapsed: 5.0 };

        let (http_s, t12_s, t13_s, details) = build_domain_row(&entry);
        assert_eq!(http_s, DpiStatus::ReadTimeout);
        assert_eq!(http_s.display_label(), "TIMEOUT");
        assert_eq!(t12_s, DpiStatus::TlsDropped);
        assert_eq!(t13_s, DpiStatus::TlsDropped);
        // Only TLS Handshake timeout is shown, NO "HTTP:Timeout"
        assert_eq!(details, "TLS Handshake timeout");
    }

    #[test]
    fn test_classify_redirect_same_https() {
        let (s, d) = classify_redirect("example.com", "https://example.com", 301, "https://example.com/", false);
        assert_eq!(s, DpiStatus::Ok);
        assert_eq!(d, "→ https");
    }

    #[test]
    fn test_classify_redirect_foreign() {
        let (s, d) = classify_redirect("example.com", "https://example.com", 302, "https://evil.com/block", false);
        assert_eq!(s, DpiStatus::RedirSuspect);
        assert!(d.contains("evil.com"));
    }

    #[test]
    fn test_classify_redirect_http_phase() {
        let (s, d) = classify_redirect("example.com", "http://example.com", 301, "https://example.com/", true);
        assert_eq!(s, DpiStatus::Ok);
        assert_eq!(d, "301 → https");
    }

    /// Same-host-or-subdomain redirects read as a plain `OK`, a redirect to
    /// another domain is a red `REDIR` (`RedirSuspect`, not counted as ok), and
    /// a protocol-relative `Location` belongs to the host it names - it is not a
    /// path on the base host. Host resolution matches the Python original
    /// (`urljoin` + `_strip_www` in `_check_tls_single` / `check_http_injection`).
    #[test]
    fn test_classify_redirect_matrix() {
        // (base, status, location, expected status, expected detail)
        let cases: &[(&str, u16, &str, DpiStatus, &str)] = &[
            ("https://holod.media", 301, "https://holod.media/", DpiStatus::Ok, "→ https"),
            ("https://holod.media", 301, "/en/", DpiStatus::Ok, "→ https"),
            ("https://holod.media", 301, "index.html", DpiStatus::Ok, "→ https"),
            ("https://holod.media", 301, "?q=1", DpiStatus::Ok, "→ https"),
            ("https://holod.media", 301, "https://sub.holod.media/x", DpiStatus::Ok, "→ https"),
            ("https://holod.media", 302, "http://holod.media/x", DpiStatus::Ok, "→ holod.media"),
            ("http://holod.media", 301, "https://holod.media/", DpiStatus::Ok, "301 → https"),
            ("http://holod.media", 301, "https://sub.holod.media/x", DpiStatus::Ok, "301 → https"),
            ("http://holod.media", 301, "http://holod.media/x", DpiStatus::Ok, "301"),
            ("http://holod.media", 301, "/en/", DpiStatus::Ok, "301"),
            ("http://holod.media", 301, "index.html", DpiStatus::Ok, "301"),
            ("http://holod.media", 301, "?q=1", DpiStatus::Ok, "301"),
            ("https://holod.media", 302, "//evil.com/block", DpiStatus::RedirSuspect, "→ evil.com"),
            ("http://holod.media", 302, "//evil.com/block", DpiStatus::RedirSuspect, "→ evil.com"),
            ("https://holod.media", 302, "https://evil.com/block", DpiStatus::RedirSuspect, "→ evil.com"),
            ("https://holod.media", 302, "https://not-holod.media/", DpiStatus::RedirSuspect, "→ not-holod.media"),
            ("https://holod.media", 302, "https://holod.media.evil.com/", DpiStatus::RedirSuspect, "→ holod.media.evil.com"),
        ];
        for (base, status, location, want, detail) in cases {
            let http_phase = base.starts_with("http:");
            let (s, d) = classify_redirect("holod.media", base, *status, location, http_phase);
            assert_eq!(s, *want, "{base} + {location} -> {d}");
            assert_eq!(d, *detail, "{base} + {location}");
            // A legitimate redirect counts as success, a foreign one does not.
            assert_eq!(s.is_ok_status(), *want != DpiStatus::RedirSuspect, "{base} + {location}");
        }
    }
}

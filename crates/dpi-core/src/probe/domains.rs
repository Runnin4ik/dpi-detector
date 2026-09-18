//! Test 2: domain availability — DNS resolve + TLS 1.3 + TLS 1.2 + HTTP.
//!
//! Phase 0 resolves every domain (family from config) and marks ISP stubs;
//! phases 1–2 probe TLS 1.3 / TLS 1.2 with SNI pinned to the resolved IP;
//! phase 3 checks plain-HTTP injection. Result rows are
//! (domain, http, tls1.2, tls1.3, details).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::Bytes;
use hyper::header::HOST;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_connect_error_icmp, classify_ssl_error, ConnectionStage,
    Detail, DpiStatus,
};
use crate::config::AppConfig;
use crate::dns::resolve_host;
use crate::PhaseProgress;
use crate::probe::connector::RustlsConnector;
use crate::net::fingerprint::http_identity;
use crate::probe::http::{
    check_http, classify_redirect, inner_hyper, parse_host, request_headers,
};
use crate::probe::connector::DpiTlsConnector;
use crate::net::tcp::{dial_tcp, DialError};
use crate::net::tls::TlsProfile;

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

/// Resolves a domain to one IP of the requested family: up to 2 attempts
/// (200 ms apart, 10 s timeout each), returning the first address of that family.
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

/// Classifies a resolved address: 198.18.0.0/15 → fakeip, 100.64.0.0/10 → isp,
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

#[derive(Debug, Clone)]
pub struct TlsCheck {
    pub status: DpiStatus,
    pub detail: Detail,
    pub elapsed: f64,
}

#[derive(Debug, Clone)]
pub struct HttpCheck {
    pub status: DpiStatus,
    pub detail: Detail,
}

/// Single TLS check against `target` with SNI/host = `domain`: TCP connect, a
/// version-pinned handshake (TLS 1.2 or 1.3), then GET `/` reading up to 64 KB of body.
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
        let tcp = match dial_tcp(&addr, Duration::from_secs_f64(cfg.connect_timeout)).await {
            Ok(s) => s,
            Err(DialError::Io { error, icmp }) => {
                let (s, d) = classify_connect_error_icmp(&error, icmp, 0, "tcp_connect");
                return (s, d, 0usize);
            }
            Err(DialError::Timeout) => {
                return (DpiStatus::SynDropped, Detail::TcpSynTimeout, 0usize);
            }
        };

        // TLS handshake (version-pinned client)
        *stage.lock() = "tls_handshake".to_string();
        let fingerprint = cfg.fingerprint();
        let profile = if tls12_only {
            TlsProfile::insecure(fingerprint).tls12()
        } else {
            TlsProfile::insecure(fingerprint).tls13()
        };
        let rustls_conn = RustlsConnector::from(profile);
        let server_name = match ServerName::try_from(domain.to_string()) {
            Ok(n) => n,
            Err(e) => {
                return (DpiStatus::Err, Detail::Other(format!("bad SNI: {}", e)), 0usize);
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
                    let d = st.last_error_msg.clone().unwrap_or(Detail::RstHello);
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
                return (DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout, 0usize);
            }
        };

        *stage.lock() = "tls_connected".to_string();
        // Test 2 counts the bytes a connection carries before it is cut, so it
        // never negotiates a Content-Encoding.
        check_http(tls_stream, domain, cfg, fingerprint, &stage, true).await
    };

    match timeout(total_timeout, fut).await {
        Ok((s, d, _)) => TlsCheck { status: s, detail: d, elapsed: start.elapsed().as_secs_f64() },
        Err(_) => {
            let st = stage.lock().clone();
            let (s, d) = match st.as_str() {
                "tls_handshake" => (DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout),
                "tcp_connect" => (DpiStatus::SynDropped, Detail::TcpSynTimeout),
                _ => (DpiStatus::ReadTimeout, Detail::ReadTimeoutWord),
            };
            TlsCheck { status: s, detail: d, elapsed: start.elapsed().as_secs_f64() }
        }
    }
}


/// Plain-HTTP injection check: HEAD to port 80 of the resolved IP with
/// Host = domain; a known provider stub IP short-circuits to `IspPage`.
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
                detail: Detail::IspBlockpage { arrow: false, ip: ip.to_string() },
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
                    return HttpCheck { status: DpiStatus::DnsFail, detail: Detail::DomainNotFound };
                }
            },
        };
        let addr = SocketAddr::new(host_ip, 80);
        let tcp = match dial_tcp(&addr, Duration::from_secs_f64(cfg.connect_timeout)).await {
            Ok(s) => s,
            Err(DialError::Io { error, icmp }) => {
                let (s, d) = classify_connect_error_icmp(&error, icmp, 0, "tcp_connect");
                return HttpCheck { status: s, detail: d };
            }
            Err(DialError::Timeout) => {
                return HttpCheck { status: DpiStatus::SynDropped, detail: Detail::TcpSynTimeout };
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

        // Plain HTTP (port 80) fallback: the same identity the TLS probes send,
        // with `Connection: close` so the response ends with an EOF.
        let identity = http_identity(cfg.fingerprint());
        let mut builder = Request::builder()
            .method(Method::HEAD)
            .uri("/")
            .header(HOST, domain_owned.as_str());
        for (name, value) in request_headers(
            &identity,
            cfg.user_agent_for(cfg.fingerprint()),
            [("Connection", "close".to_string())],
            true,
        ) {
            builder = builder.header(name, value);
        }
        let req = builder
            .body(http_body_util::Full::new(Bytes::new()))
            // The method, URI, headers and body above are all constant: this
            // request cannot fail to build.
            .expect("constant HEAD request");

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
                    return HttpCheck { status: kind, detail: Detail::TimeoutWord };
                }
                let (s, d) = inner_hyper(&e, "reading_data", 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return HttpCheck { status: s, detail: d };
            }
            Err(_) => {
                return HttpCheck { status: DpiStatus::ReadTimeout, detail: Detail::TimeoutWord };
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
            return HttpCheck { status: DpiStatus::Blocked, detail: Detail::HttpStatus(451) };
        }
        if !location.is_empty() && (300..400).contains(&status) {
            let (s, d) = classify_redirect(&domain_owned, &format!("http://{}", domain_owned), status, &location, true);
            return HttpCheck { status: s, detail: d };
        }
        if (300..400).contains(&status) {
            return HttpCheck { status: DpiStatus::Ok, detail: Detail::HttpStatus(status) };
        }
        HttpCheck { status: DpiStatus::Ok, detail: Detail::HttpStatus(status) }
    };

    match timeout(total_timeout, fut).await {
        Ok(r) => r,
        Err(_) => HttpCheck { status: DpiStatus::ReadTimeout, detail: Detail::TimeoutWord },
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
        let dash = TlsCheck { status: DpiStatus::Unknown, detail: Detail::None, elapsed: 0.0 };
        Self {
            domain,
            resolved,
            dns_fake,
            t13: dash.clone(),
            t12: dash,
            http: HttpCheck { status: DpiStatus::Unknown, detail: Detail::None },
        }
    }
}

/// Phase 0: resolves every domain under the semaphore (IPv6 mode re-probes over IPv4
/// to tell "IPv6 unsupported" from "domain not found") and records its IP and fake-IP class.
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
            let _permit = crate::probe::permit(&sem).await;
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
                        Detail::Ipv6Unsupported
                    } else {
                        Detail::DomainNotFound
                    };
                    e.t13 = TlsCheck { status: DpiStatus::DnsFail, detail: detail.clone(), elapsed: 0.0 };
                    e.t12 = e.t13.clone();
                    e.http = HttpCheck { status: DpiStatus::DnsFail, detail };
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
                            let detail = Detail::IspBlockpage { arrow: true, ip: ip.to_string() };
                            e.t13 = TlsCheck { status: DpiStatus::DnsFake, detail: detail.clone(), elapsed: 0.0 };
                            e.t12 = e.t13.clone();
                            e.http = HttpCheck { status: DpiStatus::DnsFake, detail };
                            e
                        }
                        FakeIpType::Local => {
                            let mut e = DomainEntry::pending(domain, Some(ip), Some(true));
                            let detail = Detail::LocalIp { ip: ip.to_string() };
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
        // The loop above skips every entry whose DNS answer is missing or fake.
        let Some(target) = e.resolved else { continue };
        let cfg = cfg.clone();
        let sem = Arc::clone(sem);
        handles.push(tokio::spawn(async move {
            let _permit = crate::probe::permit(&sem).await;
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

/// HTTP phase: runs the plain-HTTP injection check for every entry that resolved to a
/// clean IP (fake-IP and stub rows are skipped) and stores the result back into the row.
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
            let _permit = crate::probe::permit(&sem).await;
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

/// Silently collects provider stub IPs: queries the configured UDP resolvers (2 s
/// timeout each, stopping at the first that answers) and keeps the IPs returned
/// for at least `max(dns_stub_threshold, 2)` distinct domains.
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

/// One line of a domain row's detail cell: an optional protocol tag (Latin in
/// every language, Rule 4) and the detail itself.
pub type DetailLine = (Option<&'static str>, Detail);

/// Details that describe "nothing came back in time" rather than a verdict: they
/// are dropped from a row's detail cell (the badge already says `TIMEOUT`).
fn is_timeout_detail(detail: &Detail) -> bool {
    matches!(
        detail,
        Detail::TimeoutWord
            | Detail::ReadTimeoutWord
            | Detail::ReadTimeoutWordCaps
            | Detail::ReadTimeout
            | Detail::TimeoutStage { .. }
            | Detail::Kb { .. }
            | Detail::AtKb { .. }
    )
}

/// Builds the (http, t12, t13, details) cells: each failing protocol contributes a
/// detail (timeouts dropped), and two passing TLS columns collapse to the best time.
pub fn build_domain_row(e: &DomainEntry) -> (DpiStatus, DpiStatus, DpiStatus, Vec<DetailLine>) {
    let http_ok = col_ok(e.http.status);
    let t12_ok = col_ok_t12(e.t12.status);
    let t13_ok = col_ok_t12(e.t13.status);

    let mut problems: Vec<(&'static str, Detail)> = Vec::new();
    if !http_ok
        && !e.http.detail.is_none()
        && !is_timeout_detail(&e.http.detail)
        && !is_timeout_status(e.http.status)
    {
        problems.push(("HTTP", e.http.detail.clone()));
    }
    if !t12_ok && e.t12.detail != Detail::None && !is_timeout_detail(&e.t12.detail) {
        problems.push(("T1.2", e.t12.detail.clone()));
    }
    if !t13_ok && e.t13.detail != Detail::None && !is_timeout_detail(&e.t13.detail) {
        problems.push(("T1.3", e.t13.detail.clone()));
    }

    let mut details: Vec<DetailLine> = Vec::new();
    if problems.len() == 1 {
        details.push((None, problems[0].1.clone()));
    } else {
        // Same detail from several protocols shares one line; a single one keeps
        // its protocol tag so the reader knows which stage failed.
        let mut grouped: Vec<(Detail, Vec<&'static str>)> = Vec::new();
        for (proto, d) in &problems {
            match grouped.iter_mut().find(|(g, _)| g == d) {
                Some((_, protos)) => protos.push(proto),
                None => grouped.push((d.clone(), vec![proto])),
            }
        }
        for (detail, protos) in grouped {
            let tag = if protos.len() == 1 { Some(protos[0]) } else { None };
            details.push((tag, detail));
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
            details.push((None, Detail::Elapsed(min)));
        }
    }

    (e.http.status, e.t12.status, e.t13.status, details)
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
        entry.http = HttpCheck { status: DpiStatus::ReadTimeout, detail: Detail::TimeoutWord };
        entry.t12 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.35 };
        entry.t13 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.28 };

        let (http_s, t12_s, t13_s, details) = build_domain_row(&entry);
        assert_eq!(http_s, DpiStatus::ReadTimeout);
        assert_eq!(http_s.display_label(), "TIMEOUT");
        assert_eq!(t12_s, DpiStatus::Ok);
        assert_eq!(t13_s, DpiStatus::Ok);
        assert_eq!(details, vec![(None, Detail::Elapsed(0.28))]); // Elapsed time, no "Timeout"
    }

    #[test]
    fn test_build_domain_row_http_timeout_tls_rst_omits_http_timeout() {
        let mut entry = DomainEntry::pending("danbooru.donmai.us".to_string(), None, None);
        entry.http = HttpCheck { status: DpiStatus::ReadTimeout, detail: Detail::TimeoutWord };
        entry.t12 = TlsCheck { status: DpiStatus::TlsRst, detail: Detail::RstHello, elapsed: 0.1 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsRst, detail: Detail::RstHello, elapsed: 0.1 };

        let (http_s, t12_s, t13_s, details) = build_domain_row(&entry);
        assert_eq!(http_s, DpiStatus::ReadTimeout);
        assert_eq!(http_s.display_label(), "TIMEOUT");
        assert_eq!(t12_s, DpiStatus::TlsRst);
        assert_eq!(t13_s, DpiStatus::TlsRst);
        // Only TLS RST is shown, NO "HTTP:Timeout"
        assert_eq!(details, vec![(None, Detail::RstHello)]);
    }

    #[test]
    fn test_build_domain_row_tls_drop_omits_http_timeout() {
        let mut entry = DomainEntry::pending("discord.com".to_string(), None, None);
        entry.http = HttpCheck { status: DpiStatus::ReadTimeout, detail: Detail::TimeoutWord };
        entry.t12 = TlsCheck { status: DpiStatus::TlsDropped, detail: Detail::TlsHandshakeTimeout, elapsed: 5.0 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsDropped, detail: Detail::TlsHandshakeTimeout, elapsed: 5.0 };

        let (http_s, t12_s, t13_s, details) = build_domain_row(&entry);
        assert_eq!(http_s, DpiStatus::ReadTimeout);
        assert_eq!(http_s.display_label(), "TIMEOUT");
        assert_eq!(t12_s, DpiStatus::TlsDropped);
        assert_eq!(t13_s, DpiStatus::TlsDropped);
        // Only TLS Handshake timeout is shown, NO "HTTP:Timeout"
        assert_eq!(details, vec![(None, Detail::TlsHandshakeTimeout)]);
    }

    #[test]
    fn test_classify_redirect_same_https() {
        let (s, d) = classify_redirect("example.com", "https://example.com", 301, "https://example.com/", false);
        assert_eq!(s, DpiStatus::Ok);
        assert_eq!(d, Detail::UpgradeHttps { status: None });
    }

    #[test]
    fn test_classify_redirect_foreign() {
        let (s, d) = classify_redirect("example.com", "https://example.com", 302, "https://evil.com/block", false);
        assert_eq!(s, DpiStatus::RedirSuspect);
        assert_eq!(d, Detail::Redirect { host: "evil.com".to_string() });
    }

    #[test]
    fn test_classify_redirect_http_phase() {
        let (s, d) = classify_redirect("example.com", "http://example.com", 301, "https://example.com/", true);
        assert_eq!(s, DpiStatus::Ok);
        assert_eq!(d, Detail::UpgradeHttps { status: Some(301) });
    }

    /// The rule the table reads by: a redirect that stays inside one site family
    /// is a normal `OK`, whatever the direction — a subdomain spelling out the
    /// main domain (`www.holod.media` → `holod.media`) and the main domain
    /// naming a subdomain (`holod.media` → `cdn.holod.media`) are both the site
    /// itself. Only a name outside the family is a red `REDIR`.
    #[test]
    fn test_a_subdomain_redirect_inside_the_same_site_is_ok() {
        let cases: &[(&str, &str, DpiStatus, &str)] = &[
            // (requested domain, Location, expected status, expected redirect host when foreign)
            ("www.holod.media", "https://holod.media/x", DpiStatus::Ok, ""),
            ("holod.media", "https://www.holod.media/x", DpiStatus::Ok, ""),
            ("holod.media", "https://cdn.holod.media/x", DpiStatus::Ok, ""),
            ("m.holod.media", "https://holod.media/x", DpiStatus::Ok, ""),
            ("www.holod.media", "http://holod.media/x", DpiStatus::Ok, ""),
            // Two subdomains of one site are that site, not a redirect away.
            ("m.youtube.com", "https://www.youtube.com/x", DpiStatus::Ok, ""),
            ("www.youtube.com", "https://m.youtube.com/x", DpiStatus::Ok, ""),
            ("a.example.co.uk", "https://b.example.co.uk/x", DpiStatus::Ok, ""),
            // A two-label host has no parent site: its "parent" is a TLD, and
            // reading `com` as the site would make every `.com` host one site.
            ("youtube.com", "https://example.com/x", DpiStatus::RedirSuspect, "example.com"),
            ("m.youtube.com", "https://www.google.com/x", DpiStatus::RedirSuspect, "www.google.com"),
            // A different registrable domain is not the same site, however it
            // reads, and a declared exception does not make one: the pairs in
            // `REDIRECT_EXCEPTIONS` are exact, not families.
            ("www.instagram.com", "https://www.messenger.com/x", DpiStatus::RedirSuspect, "www.messenger.com"),
            ("holod.media", "https://not-holod.media/x", DpiStatus::RedirSuspect, "not-holod.media"),
            ("holod.media", "https://holod.media.evil.com/x", DpiStatus::RedirSuspect, "holod.media.evil.com"),
        ];
        for (domain, location, want, foreign) in cases {
            let (s, d) = classify_redirect(domain, &format!("https://{domain}"), 301, location, false);
            assert_eq!(s, *want, "{domain} + {location} -> {}", d.code());
            if *want == DpiStatus::RedirSuspect {
                assert_eq!(d, Detail::Redirect { host: (*foreign).to_string() }, "{domain} + {location}");
            }
        }
    }

    /// The exception list is a pair list, not a family: the Meta sign-in hop
    /// (`www.messenger.com` → `www.facebook.com`, `www.instagram.com` →
    /// `www.facebook.com`) is a redirect the sites themselves make and reads
    /// `OK`, while the same hop the other way round, a hop from either of them
    /// somewhere else, and a host that merely looks like one of them all keep
    /// the default `REDIR`.
    #[test]
    fn test_a_declared_exception_reads_ok_and_only_that_pair_does() {
        let cases: &[(&str, &str, bool, DpiStatus)] = &[
            // (requested domain, Location, http phase, expected status)
            ("www.messenger.com", "https://www.facebook.com/", false, DpiStatus::Ok),
            ("www.messenger.com", "https://www.facebook.com/", true, DpiStatus::Ok),
            ("messenger.com", "https://www.facebook.com/x", false, DpiStatus::Ok),
            ("www.instagram.com", "https://www.facebook.com/", false, DpiStatus::Ok),
            ("www.instagram.com", "https://www.facebook.com/", true, DpiStatus::Ok),
            ("instagram.com", "https://www.facebook.com/x", false, DpiStatus::Ok),
            // The pair is directional, and it names two hosts, not two sites.
            ("www.facebook.com", "https://www.messenger.com/", false, DpiStatus::RedirSuspect),
            ("www.facebook.com", "https://www.instagram.com/", false, DpiStatus::RedirSuspect),
            ("www.messenger.com", "https://www.instagram.com/", false, DpiStatus::RedirSuspect),
            ("www.instagram.com", "https://www.messenger.com/", false, DpiStatus::RedirSuspect),
            ("www.messenger.com", "https://www.google.com/", false, DpiStatus::RedirSuspect),
            ("www.messenger.com", "https://www.facebook.com.evil.com/", false, DpiStatus::RedirSuspect),
            ("notmessenger.com", "https://www.facebook.com/", false, DpiStatus::RedirSuspect),
        ];
        for (domain, location, http_phase, want) in cases {
            let base = format!("http{}://{domain}", if *http_phase { "" } else { "s" });
            let (s, d) = classify_redirect(domain, &base, 301, location, *http_phase);
            assert_eq!(s, *want, "{domain} + {location} (http_phase {http_phase}) -> {}", d.code());
        }
        // The exception still reports where the browser was sent.
        let (s, d) = classify_redirect("www.messenger.com", "https://www.messenger.com/", 301, "https://www.facebook.com/", false);
        assert_eq!(s, DpiStatus::Ok);
        assert_eq!(d, Detail::Redirect { host: "www.facebook.com".to_string() });
    }

    /// Same-host-or-subdomain redirects read as a plain `OK`, a redirect to
    /// another domain is a red `REDIR` (`RedirSuspect`, not counted as ok), and
    /// a protocol-relative `Location` belongs to the host it names - it is not a
    /// path on the base host. Host comparison is case-insensitive and ignores a
    /// leading `www.` on both sides.
    #[test]
    fn test_classify_redirect_matrix() {
        // (base, status, location, expected status, expected detail)
        let cases: &[(&str, u16, &str, DpiStatus, Detail)] = &[
            ("https://holod.media", 301, "https://holod.media/", DpiStatus::Ok, Detail::UpgradeHttps { status: None }),
            ("https://holod.media", 301, "/en/", DpiStatus::Ok, Detail::UpgradeHttps { status: None }),
            ("https://holod.media", 301, "index.html", DpiStatus::Ok, Detail::UpgradeHttps { status: None }),
            ("https://holod.media", 301, "?q=1", DpiStatus::Ok, Detail::UpgradeHttps { status: None }),
            ("https://holod.media", 301, "https://sub.holod.media/x", DpiStatus::Ok, Detail::UpgradeHttps { status: None }),
            ("https://holod.media", 302, "http://holod.media/x", DpiStatus::Ok, Detail::Redirect { host: "holod.media".into() }),
            ("http://holod.media", 301, "https://holod.media/", DpiStatus::Ok, Detail::UpgradeHttps { status: Some(301) }),
            ("http://holod.media", 301, "https://sub.holod.media/x", DpiStatus::Ok, Detail::UpgradeHttps { status: Some(301) }),
            ("http://holod.media", 301, "http://holod.media/x", DpiStatus::Ok, Detail::HttpStatus(301)),
            ("http://holod.media", 301, "/en/", DpiStatus::Ok, Detail::HttpStatus(301)),
            ("http://holod.media", 301, "index.html", DpiStatus::Ok, Detail::HttpStatus(301)),
            ("http://holod.media", 301, "?q=1", DpiStatus::Ok, Detail::HttpStatus(301)),
            ("https://holod.media", 302, "//evil.com/block", DpiStatus::RedirSuspect, Detail::Redirect { host: "evil.com".into() }),
            ("http://holod.media", 302, "//evil.com/block", DpiStatus::RedirSuspect, Detail::Redirect { host: "evil.com".into() }),
            ("https://holod.media", 302, "https://evil.com/block", DpiStatus::RedirSuspect, Detail::Redirect { host: "evil.com".into() }),
            ("https://holod.media", 302, "https://not-holod.media/", DpiStatus::RedirSuspect, Detail::Redirect { host: "not-holod.media".into() }),
            ("https://holod.media", 302, "https://holod.media.evil.com/", DpiStatus::RedirSuspect, Detail::Redirect { host: "holod.media.evil.com".into() }),
        ];
        for (base, status, location, want, detail) in cases {
            let http_phase = base.starts_with("http:");
            let (s, d) = classify_redirect("holod.media", base, *status, location, http_phase);
            assert_eq!(s, *want, "{base} + {location} -> {}", d.code());
            assert_eq!(&d, detail, "{base} + {location}");
            // A legitimate redirect counts as success, a foreign one does not.
            assert_eq!(s.is_ok_status(), *want != DpiStatus::RedirSuspect, "{base} + {location}");
        }
    }
}

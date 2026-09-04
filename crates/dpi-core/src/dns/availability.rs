//! Test 1: DNS availability + hijack detection (mirrors
//! `core/dns_scanner.py::check_dns_availability` + `core/dns/render.py`).
//!
//! Two-phase UDP scheme: phase A probes trusted domains (liveness + ping),
//! phase B probes forbidden domains only on live servers and compares UDP
//! answers against the DoH/DoT truth. Silence on a forbidden domain counts
//! as substitution, not unavailability. Egress resolvers are fingerprinted
//! via `whoami.akamai.net` + Team Cymru org names.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use super::doh::DohSession;
use super::dot::DotSession;
use super::socks::SocksProxyConfig;
use super::types::DnsError;
use crate::config::AppConfig;
use crate::PhaseProgress;
use crate::net::netinfo::fetch_ip_cymru;
use crate::probe::domains::fake_ip_type;

// ─── Helpers (mirror core/dns/stubs.py + render.py) ──────────────────────────

pub fn brand(name: &str) -> String {
    name.split(" (").next().unwrap_or(name).trim().to_string()
}


/// Provider sort key: popular → others (alpha) → Russian last.
pub fn dns_name_sort_key(name: &str) -> (u8, usize, String) {
    const POPULAR: &[&str] = &["google", "cloudflare", "quad9", "adguard"];
    const RU: &[&str] = &["xbox", "comss", "yandex", "geohide", "msk", "нсди"];
    let low = name.to_lowercase();
    for (i, p) in POPULAR.iter().enumerate() {
        if low.starts_with(p) {
            return (0, i, low);
        }
    }
    for (i, p) in RU.iter().enumerate() {
        if low.starts_with(p) {
            return (2, i, low);
        }
    }
    (1, 0, low)
}

pub fn known_resolver(org_or_name: &str, known: &[String]) -> bool {
    let low = org_or_name.to_lowercase();
    known.iter().any(|tok| low.contains(&tok.to_lowercase()))
}

pub fn net24(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}", s[0], s[1], s[2])
        }
    }
}

pub fn org_label(org: &str) -> String {
    org.split(" - ").next().unwrap_or(org).trim().to_string()
}

/// Maps a session/query error to a display token, mirroring Python
/// `classify_connect_error` / `classify_read_error` stages.
pub fn connect_fail_label(err: &DnsError) -> &'static str {
    match err {
        DnsError::Timeout => "TIMEOUT",
        DnsError::ConnectFault { stage, detail } => {
            if *stage == "resolve" {
                return "DNS FAIL";
            }
            let norm_stage = match *stage {
                "connected" => "tls_connected",
                s => s,
            };
            let (status, _) = crate::classify::classify_connect_error_full(detail, None, None, 0, norm_stage);
            if status != crate::classify::DpiStatus::Unknown {
                status.display_label()
            } else {
                "TIMEOUT"
            }
        }
        // Non-staged errors (bad URL/SNI/length; HTTP status is handled by callers).
        DnsError::Io(msg) => {
            let m = msg.to_lowercase();
            if m.contains("resolve")
                || m.contains("no address")
                || m.contains("invalid")
                || m.contains("bad ")
            {
                "DNS FAIL"
            } else {
                "TIMEOUT"
            }
        }
        _ => "TIMEOUT",
    }
}

/// First error wins (mirrors Python `_record_fail` / `setdefault`).
fn record_fail(report: &mut DnsAvailReport, key: &ProbeKey, label: &str) {
    report
        .fail_reasons
        .entry(key.clone())
        .or_insert_with(|| label.to_string());
}

/// All-None latency map for an aborted server (mirrors `dict.fromkeys(...)`).
fn lat_none(domains: &[String]) -> std::collections::HashMap<String, Option<f64>> {
    domains.iter().map(|d| (d.clone(), None)).collect()
}

pub fn is_fake_ip(ip: &IpAddr) -> bool {
    matches!(fake_ip_type(ip), crate::probe::domains::FakeIpType::FakeIp)
}

// ─── Probe data model ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeKind {
    Udp,
    DohWire,
    Dot,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    pub kind: ProbeKind,
    pub addr: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub enum DnsAnswer {
    Ips(Vec<IpAddr>),
    NxDomain,
}

#[derive(Debug, Clone, Default)]
pub struct DnsAvailStats {
    pub doh_ok: usize,
    pub doh_total: usize,
    pub dot_ok: usize,
    pub dot_total: usize,
    pub udp_ok: usize,
    pub udp_total: usize,
    pub hijacked_brands: Vec<String>,
    pub resolvers_total: usize,
    pub subst_sub: usize,
    pub subst_total: usize,
    pub fakeip_sub: usize,
    pub fakeip_total: usize,
    pub top_stub: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsAvailReport {
    pub allowed: Vec<String>,
    pub forbidden: Vec<String>,
    pub timeout_secs: f64,
    pub udp_servers: Vec<(String, String, u16)>,
    pub doh_servers: Vec<(String, String, u16)>,
    pub dot_servers: Vec<(String, String, u16)>,
    /// (kind, addr, name) → domain → latency ms (None = fail)
    pub raw: HashMap<ProbeKey, HashMap<String, Option<f64>>>,
    /// (kind, addr, name) → fail label (e.g. "DNS FAIL", "TIMEOUT")
    pub fail_reasons: HashMap<ProbeKey, String>,
    /// (kind, addr, name, domain) → parsed answer
    pub udp_answers: HashMap<(ProbeKey, String), DnsAnswer>,
    pub doh_answers: HashMap<(ProbeKey, String), DnsAnswer>,
    pub dot_answers: HashMap<(ProbeKey, String), DnsAnswer>,
    /// (addr, name) → egress IP from whoami.akamai.net
    pub egress: HashMap<(String, String), Option<IpAddr>>,
    /// egress IP string → org label
    pub org_names: HashMap<String, String>,
    pub all_names: Vec<String>,
    pub non_socks_proxy_warn: bool,
    pub stats: DnsAvailStats,
    pub skipped_no_servers: bool,
}

// ─── Engine ───────────────────────────────────────────────────────────────────

fn answer_of(res: Result<(Vec<IpAddr>, f64), DnsError>) -> (Option<f64>, Option<DnsAnswer>) {
    match res {
        Ok((ips, lat)) => (Some(lat), Some(DnsAnswer::Ips(ips))),
        Err(DnsError::NxDomain) | Err(DnsError::ServerFailure(3)) => (None, Some(DnsAnswer::NxDomain)),
        Err(_) => (None, None),
    }
}

pub async fn check_dns_availability(cfg: &AppConfig, phases: Option<PhaseProgress>) -> DnsAvailReport {
    let servers = cfg.availability_servers();
    let allowed = if cfg.dns_availability_domains.is_empty() {
        vec!["vk.ru".to_string(), "gosuslugi.ru".to_string()]
    } else {
        cfg.dns_availability_domains.clone()
    };
    let forbidden = cfg.dns_check_domains.clone();
    let timeout_dur = Duration::from_secs_f64(cfg.dns_availability_timeout);

    let mut udp_servers = Vec::new();
    let mut doh_servers = Vec::new();
    let mut dot_servers = Vec::new();
    for s in servers {
        match s.kind.as_str() {
            "udp" => udp_servers.push((s.addr, s.name, s.port)),
            "doh_wire" | "doh_json" => doh_servers.push((s.addr, s.name, s.port)),
            "dot" => dot_servers.push((s.addr, s.name, s.port)),
            _ => {}
        }
    }

    let mut report = DnsAvailReport {
        allowed: allowed.clone(),
        forbidden: forbidden.clone(),
        timeout_secs: cfg.dns_availability_timeout,
        udp_servers: udp_servers.clone(),
        doh_servers: doh_servers.clone(),
        dot_servers: dot_servers.clone(),
        ..Default::default()
    };

    if udp_servers.is_empty() && doh_servers.is_empty() && dot_servers.is_empty() {
        report.skipped_no_servers = true;
        return report;
    }
    let total = udp_servers.len() + doh_servers.len() + dot_servers.len();
    let tick = phases
        .as_ref()
        .map(|p| (p.on_phase)("Проверка серверов...".to_string(), total, false));

    // Proxy: only SOCKS5 supports UDP relay
    let proxy_raw = cfg.effective_proxy().map(|s| s.to_string());
    let mut socks_proxy: Option<SocksProxyConfig> = None;
    if let Some(ref p) = proxy_raw {
        match super::socks::parse_socks_proxy(p) {
            Ok(c) => socks_proxy = Some(c),
            Err(_) => report.non_socks_proxy_warn = true,
        }
    }

    let probe_gate = Arc::new(Semaphore::new(cfg.dns_probe_concurrency.max(1)));
    let udp_sem = Arc::new(Semaphore::new(cfg.dns_udp_concurrency.max(1)));
    let doh_sem = Arc::new(Semaphore::new(cfg.dns_doh_concurrency.max(1)));
    let egress_sem = Arc::new(Semaphore::new(cfg.dns_egress_concurrency.max(1)));

    // ── UDP probes (phase A → phase B) ──
    {
        let mut handles = Vec::new();
        for (addr, name, port) in &udp_servers {
            let (addr, name, port) = (addr.clone(), name.clone(), *port);
            let allowed = allowed.clone();
            let forbidden = forbidden.clone();
            let gate = Arc::clone(&probe_gate);
            let udp_sem = Arc::clone(&udp_sem);
            let egress_sem = Arc::clone(&egress_sem);
            let socks_proxy = socks_proxy.clone();
            handles.push(tokio::spawn(async move {
                let _g = gate.acquire().await.unwrap();
                let server: SocketAddr = format!("{}:{}", addr, port)
                    .parse()
                    .unwrap_or(SocketAddr::from(([0, 0, 0, 0], port)));
                let key = ProbeKey { kind: ProbeKind::Udp, addr: addr.clone(), name: name.clone() };

                let mut lat: HashMap<String, Option<f64>> = HashMap::new();
                let mut answers: Vec<((ProbeKey, String), DnsAnswer)> = Vec::new();

                // Phase A: trusted domains
                let mut a_handles = Vec::new();
                for d in &allowed {
                    let d = d.clone();
                    let udp_sem = Arc::clone(&udp_sem);
                    let socks_proxy = socks_proxy.clone();
                    a_handles.push(tokio::spawn(async move {
                        let _p = udp_sem.acquire().await.unwrap();
                        let r = super::udp::probe_udp_dns(server, &d, timeout_dur, socks_proxy.as_ref()).await;
                        (d, r)
                    }));
                }
                let mut alive = false;
                for h in a_handles {
                    if let Ok((d, r)) = h.await {
                        let (l, a) = answer_of(r);
                        if l.is_some() {
                            alive = true;
                        }
                        if let Some(ans) = a {
                            answers.push(((key.clone(), d.clone()), ans));
                        }
                        lat.insert(d, l);
                    }
                }
                // Phase B: forbidden domains on live servers only
                if alive {
                    let mut b_handles = Vec::new();
                    for d in &forbidden {
                        let d = d.clone();
                        let udp_sem = Arc::clone(&udp_sem);
                        let socks_proxy = socks_proxy.clone();
                        b_handles.push(tokio::spawn(async move {
                            let _p = udp_sem.acquire().await.unwrap();
                            let r = super::udp::probe_udp_dns(server, &d, timeout_dur, socks_proxy.as_ref()).await;
                            (d, r)
                        }));
                    }
                    for h in b_handles {
                        if let Ok((d, r)) = h.await {
                            let (l, a) = answer_of(r);
                            if let Some(ans) = a {
                                answers.push(((key.clone(), d.clone()), ans));
                            }
                            lat.insert(d, l);
                        }
                    }
                }

                // Egress: whoami.akamai.net with one retry
                let _e = egress_sem.acquire().await.unwrap();
                let mut egress_ip = None;
                for _ in 0..2 {
                    match super::udp::probe_udp_dns(server, "whoami.akamai.net", timeout_dur, socks_proxy.as_ref()).await {
                        Ok((ips, _)) => {
                            if let Some(ip) = ips.first() {
                                egress_ip = Some(*ip);
                                break;
                            }
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
                (key, lat, answers, egress_ip)
            }));
        }
        for h in handles {
            if let Some(t) = tick.as_ref() {
                t();
            }
            if let Ok((key, lat, answers, egress_ip)) = h.await {
                report.egress.insert((key.addr.clone(), key.name.clone()), egress_ip);
                for (k, a) in answers {
                    report.udp_answers.insert(k, a);
                }
                report.raw.insert(key, lat);
            }
        }
    }

    // ── DoH wire probes (truth), one connection per server, sequential ──
    {
        let mut handles = Vec::new();
        for (addr, name, port) in &doh_servers {
            let (addr, name, _port) = (addr.clone(), name.clone(), *port);
            let forbidden = forbidden.clone();
            let gate = Arc::clone(&probe_gate);
            let doh_sem = Arc::clone(&doh_sem);
            handles.push(tokio::spawn(async move {
                let _g = gate.acquire().await.unwrap();
                let key = ProbeKey { kind: ProbeKind::DohWire, addr: addr.clone(), name: name.clone() };
                // Outer cap (mirrors `wait_for(_do_probe(), timeout * 2 + 3.0)`).
                let cap = Duration::from_secs_f64(timeout_dur.as_secs_f64() * 2.0 + 3.0);
                let probe = async {
                    let mut session = match DohSession::connect(&addr, timeout_dur).await {
                        Ok(s) => s,
                        Err(e) => {
                            return (HashMap::new(), Vec::new(), Some(connect_fail_label(&e).to_string()));
                        }
                    };
                    // Warmup is non-critical for DoH (mirrors Python: warms up HTTP/2 stream).
                    let warmup = forbidden.first().cloned().unwrap_or_else(|| "google.com".to_string());
                    let _ = session.query(&warmup, timeout_dur).await;

                    let mut lat = HashMap::new();
                    let mut answers = Vec::new();
                    let mut first_fail: Option<String> = None;
                    for d in &forbidden {
                        let _p = doh_sem.acquire().await.unwrap();
                        // One retry with jitter (mirrors Python attempt loop)
                        let mut res = session.query(d, timeout_dur).await;
                        if res.is_err() {
                            let jitter = (rand::random::<u8>() as f64) / 255.0 * 0.7;
                            tokio::time::sleep(Duration::from_secs_f64(0.3 + jitter)).await;
                            res = session.query(d, timeout_dur).await;
                        }
                        // First connection-class error wins (mirrors `_record_fail`).
                        if first_fail.is_none() {
                            if let Err(e) = &res {
                                if matches!(e, DnsError::Timeout | DnsError::Io(_) | DnsError::ConnectFault { .. }) {
                                    first_fail = Some(connect_fail_label(e).to_string());
                                }
                            }
                        }
                        let (l, a) = answer_of(res);
                        if let Some(ans) = a {
                            answers.push(((key.clone(), d.clone()), ans));
                        }
                        lat.insert(d.clone(), l);
                    }
                    (lat, answers, first_fail)
                };
                match tokio::time::timeout(cap, probe).await {
                    Ok((lat, answers, fail)) => (key, lat, answers, fail),
                    Err(_) => (key, lat_none(&forbidden), Vec::new(), Some("TIMEOUT".to_string())),
                }
            }));
        }
        for h in handles {
            if let Some(t) = tick.as_ref() {
                t();
            }
            if let Ok((key, lat, answers, fail)) = h.await {
                if let Some(f) = fail {
                    record_fail(&mut report, &key, &f);
                }
                for (k, a) in answers {
                    report.doh_answers.insert(k, a);
                }
                report.raw.insert(key, lat);
            }
        }
    }

    // ── DoT probes ──
    {
        let mut handles = Vec::new();
        for (addr, name, port) in &dot_servers {
            let (addr, name, port) = (addr.clone(), name.clone(), *port);
            let forbidden = forbidden.clone();
            let gate = Arc::clone(&probe_gate);
            handles.push(tokio::spawn(async move {
                let _g = gate.acquire().await.unwrap();
                let key = ProbeKey { kind: ProbeKind::Dot, addr: addr.clone(), name: name.clone() };
                // Outer cap (mirrors `wait_for(_do_probe(), timeout * 2 + 3.0)`).
                let cap = Duration::from_secs_f64(timeout_dur.as_secs_f64() * 2.0 + 3.0);
                let probe = async {
                    let (host, mut ep_port) = super::dot::split_dot_endpoint(&addr);
                    if port != 853 {
                        ep_port = port;
                    }
                    let mut session = match DotSession::connect(&host, ep_port, timeout_dur).await {
                        Ok(s) => s,
                        Err(e) => {
                            return (HashMap::new(), Vec::new(), Some(connect_fail_label(&e).to_string()));
                        }
                    };
                    // Warmup is fatal (mirrors Python: warmup + queries abort
                    // the whole server with the first error recorded).
                    let warmup = forbidden.first().cloned().unwrap_or_else(|| "google.com".to_string());
                    if let Err(e) = session.query(&warmup).await {
                        return (HashMap::new(), Vec::new(), Some(connect_fail_label(&e).to_string()));
                    }

                    let mut lat = HashMap::new();
                    let mut answers = Vec::new();
                    // Per-query errors stay silent (mirrors Python `_one`).
                    for d in &forbidden {
                        let res = session.query(d).await;
                        let (l, a) = answer_of(res);
                        if let Some(ans) = a {
                            answers.push(((key.clone(), d.clone()), ans));
                        }
                        lat.insert(d.clone(), l);
                    }
                    let none: Option<String> = None;
                    (lat, answers, none)
                };
                match tokio::time::timeout(cap, probe).await {
                    Ok((lat, answers, fail)) => (key, lat, answers, fail),
                    Err(_) => (key, lat_none(&forbidden), Vec::new(), Some("TIMEOUT".to_string())),
                }
            }));
        }
        for h in handles {
            if let Some(t) = tick.as_ref() {
                t();
            }
            if let Ok((key, lat, answers, fail)) = h.await {
                if let Some(f) = fail {
                    record_fail(&mut report, &key, &f);
                }
                for (k, a) in answers {
                    report.dot_answers.insert(k, a);
                }
                report.raw.insert(key, lat);
            }
        }
    }

    // ── Org names for egress IPs (Team Cymru over DoH) ──
    {
        let unique: HashSet<IpAddr> = report.egress.values().filter_map(|v| *v).collect();
        let asn_sem = Arc::new(Semaphore::new(cfg.dns_asn_concurrency.max(1)));
        let mut handles = Vec::new();
        for ip in unique {
            let asn_sem = Arc::clone(&asn_sem);
            let cymru = cfg.cymru_doh_servers.clone();
            handles.push(tokio::spawn(async move {
                let _p = asn_sem.acquire().await.unwrap();
                let info = fetch_ip_cymru(&ip, &cymru, Duration::from_secs(5)).await;
                (ip, info.and_then(|i| i.org).unwrap_or_default())
            }));
        }
        for h in handles {
            if let Ok((ip, org)) = h.await {
                if !org.is_empty() {
                    report.org_names.insert(ip.to_string(), org);
                }
            }
        }
    }

    // ── Provider order + stats ──
    let mut names: Vec<String> = {
        let mut seen = HashSet::new();
        let mut v = Vec::new();
        for (a, n, _) in doh_servers.iter().chain(udp_servers.iter()).chain(dot_servers.iter()) {
            let _ = a;
            if seen.insert(n.clone()) {
                v.push(n.clone());
            }
        }
        v
    };
    names.sort_by_key(|a| dns_name_sort_key(a));
    report.all_names = names;

    report.stats = compute_stats(&report, cfg);
    report
}

fn truth_ips(report: &DnsAvailReport) -> HashMap<String, HashSet<IpAddr>> {
    let mut truth: HashMap<String, HashSet<IpAddr>> = HashMap::new();
    for ((key, domain), ans) in report.doh_answers.iter().chain(report.dot_answers.iter()) {
        if key.kind != ProbeKind::DohWire && key.kind != ProbeKind::Dot {
            continue;
        }
        if let DnsAnswer::Ips(ips) = ans {
            let real: Vec<IpAddr> = ips.iter().copied().filter(|ip| !is_fake_ip(ip)).collect();
            if !real.is_empty() {
                truth.entry(domain.clone()).or_default().extend(real);
            }
        }
    }
    truth
}

fn udp_alive(report: &DnsAvailReport, addr: &str, name: &str) -> bool {
    let key = ProbeKey { kind: ProbeKind::Udp, addr: addr.to_string(), name: name.to_string() };
    match report.raw.get(&key) {
        Some(dm) => report.allowed.iter().any(|d| dm.get(d).copied().flatten().is_some()),
        None => false,
    }
}

fn udp_ips(report: &DnsAvailReport, addr: &str, name: &str, domain: &str) -> HashSet<IpAddr> {
    let key = ProbeKey { kind: ProbeKind::Udp, addr: addr.to_string(), name: name.to_string() };
    match report.udp_answers.get(&(key, domain.to_string())) {
        Some(DnsAnswer::Ips(ips)) => ips.iter().copied().collect(),
        _ => HashSet::new(),
    }
}

/// (judged, substituted) per UDP server.
pub fn subst_counts(report: &DnsAvailReport, addr: &str, name: &str) -> (usize, usize) {
    if !udp_alive(report, addr, name) {
        return (0, 0);
    }
    let truth = truth_ips(report);
    let mut judged = 0;
    let mut sub = 0;
    for d in &report.forbidden {
        let t = match truth.get(d) {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        judged += 1;
        if udp_ips(report, addr, name, d).intersection(t).next().is_none() {
            sub += 1;
        }
    }
    (judged, sub)
}

fn fakeip_sub(report: &DnsAvailReport, addr: &str, name: &str) -> usize {
    let mut n = 0;
    for d in &report.forbidden {
        let ips = udp_ips(report, addr, name, d);
        if !ips.is_empty() && ips.iter().any(is_fake_ip) {
            n += 1;
        }
    }
    n
}

fn compute_stats(report: &DnsAvailReport, cfg: &AppConfig) -> DnsAvailStats {
    let doh_ok = report.doh_servers.iter().filter(|(a, n, _)| {
        let key = ProbeKey { kind: ProbeKind::DohWire, addr: a.clone(), name: n.clone() };
        report.raw.get(&key).map(|dm| dm.values().any(|v| v.is_some())).unwrap_or(false)
    }).count();
    let udp_ok = report.udp_servers.iter().filter(|(a, n, _)| udp_alive(report, a, n)).count();
    let dot_ok = report.dot_servers.iter().filter(|(a, n, _)| {
        let key = ProbeKey { kind: ProbeKind::Dot, addr: a.clone(), name: n.clone() };
        report.raw.get(&key).map(|dm| dm.values().any(|v| v.is_some())).unwrap_or(false)
    }).count();

    // Hijacked brands: egress /24 shared by ≥2 brands, unknown org, non-domestic
    let mut net_brands: HashMap<String, HashSet<String>> = HashMap::new();
    for ((eaddr, ename), eip) in &report.egress {
        let ip = match eip {
            Some(ip) => ip,
            None => continue,
        };
        if *ip == IpAddr::from([0, 0, 0, 0]) || is_fake_ip(ip) {
            continue;
        }
        net_brands.entry(net24(ip)).or_default().insert(brand(ename));
        let _ = eaddr;
    }
    let is_hijacked = |ip: &IpAddr| net_brands.get(&net24(ip)).map(|s| s.len() >= 2).unwrap_or(false);

    let mut hi = HashSet::new();
    for (name, addrs) in udp_by_name(report) {
        for a in addrs {
            let eip = report.egress.get(&(a.clone(), name.clone())).copied().flatten();
            if let Some(eip) = eip {
                let org = report.org_names.get(&eip.to_string()).cloned().unwrap_or_default();
                // NOTE: no domestic exemption (unlike Python): a hijacked
                // MSK-IX/NSDI answer must be visible, not silently shielded.
                if is_hijacked(&eip)
                    && !known_resolver(&org_label(&org), &cfg.dns_known_resolver_names)
                {
                    hi.insert(brand(&name));
                }
            }
        }
    }

    let resolvers_total = udp_by_name(report)
        .keys()
        .map(|n| brand(n))
        .collect::<HashSet<_>>()
        .len();

    let mut subst_sub = 0;
    let mut subst_total = 0;
    for (name, addrs) in udp_by_name(report) {
        for a in addrs {
            let (j, s) = subst_counts(report, &a, &name);
            if j > 0 {
                subst_total += 1;
                if s > 0 {
                    subst_sub += 1;
                }
            }
        }
    }

    let mut stub_counts: HashMap<IpAddr, usize> = HashMap::new();
    let truth = truth_ips(report);
    for (name, addrs) in udp_by_name(report) {
        for a in addrs {
            if !udp_alive(report, &a, &name) {
                continue;
            }
            for d in &report.forbidden {
                let t = match truth.get(d) {
                    Some(t) if !t.is_empty() => t,
                    _ => continue,
                };
                let uips = udp_ips(report, &a, &name, d);
                if !uips.is_empty() && uips.intersection(t).next().is_none() {
                    for ip in uips {
                        *stub_counts.entry(ip).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    // Stub IPs are answers repeated across ≥ threshold resolvers (mirrors
    // Python `DNS_STUB_THRESHOLD` in core/dns/stubs.py).
    let stub_min = cfg.dns_stub_threshold.max(1) as usize;
    let top_stub = stub_counts
        .into_iter()
        .filter(|(_, c)| *c >= stub_min)
        .max_by_key(|(_, c)| *c)
        .map(|(ip, _)| ip.to_string());

    let mut fakeip_count = 0;
    for (name, addrs) in udp_by_name(report) {
        for a in addrs {
            let (j, _) = subst_counts(report, &a, &name);
            if j > 0 && fakeip_sub(report, &a, &name) > 0 {
                fakeip_count += 1;
            }
        }
    }

    DnsAvailStats {
        doh_ok,
        doh_total: report.doh_servers.len(),
        dot_ok,
        dot_total: report.dot_servers.len(),
        udp_ok,
        udp_total: report.udp_servers.len(),
        hijacked_brands: {
            let mut v: Vec<String> = hi.into_iter().collect();
            v.sort();
            v
        },
        resolvers_total,
        subst_sub,
        subst_total,
        fakeip_sub: fakeip_count,
        fakeip_total: subst_total,
        top_stub,
    }
}

fn udp_by_name(report: &DnsAvailReport) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for (a, n, _) in &report.udp_servers {
        m.entry(n.clone()).or_default().push(a.clone());
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brand_sort() {
        assert_eq!(brand("AdGuard (F)"), "AdGuard");
        let mut v = vec!["Yandex".to_string(), "Google".to_string(), "Other".to_string()];
        v.sort_by(|a, b| dns_name_sort_key(a).cmp(&dns_name_sort_key(b)));
        assert_eq!(v[0], "Google");
        assert_eq!(v[2], "Yandex");
    }

    #[test]
    fn test_net24() {
        assert_eq!(net24(&"1.2.3.4".parse().unwrap()), "1.2.3");
    }

    /// Display tokens mirror Python `classify_connect_error` stages.
    #[test]
    fn test_connect_fail_label() {
        use super::super::types::DnsError;
        assert_eq!(connect_fail_label(&DnsError::Timeout), "TIMEOUT");
        let fault = |stage: &'static str, detail: &str| DnsError::ConnectFault {
            stage,
            detail: detail.to_string(),
        };
        assert_eq!(connect_fail_label(&fault("resolve", "lookup failed")), "DNS FAIL");
        assert_eq!(connect_fail_label(&fault("tcp_connect", "connect timed out")), "SYN DROP");
        assert_eq!(
            connect_fail_label(&fault("tcp_connect", "connection reset by peer (os error 104)")),
            "TCP RST"
        );
        assert_eq!(
            connect_fail_label(&fault("tcp_connect", "network is unreachable (os error 101)")),
            "NET UNREACH"
        );
        assert_eq!(
            connect_fail_label(&fault("tls_handshake", "handshake timed out")),
            "TLS DROP"
        );
        assert_eq!(
            connect_fail_label(&fault("tls_handshake", "connection reset by peer")),
            "TLS RST"
        );
        assert_eq!(
            connect_fail_label(&fault("tls_handshake", "tls alert handshake failure")),
            "TLS ALERT"
        );
        assert_eq!(connect_fail_label(&fault("connected", "timeout")), "TIMEOUT");
        assert_eq!(connect_fail_label(&fault("connected", "connection reset")), "TLS RST");
        assert_eq!(
            connect_fail_label(&DnsError::Io("DoH resolve failed: dns error".to_string())),
            "DNS FAIL"
        );
        assert_eq!(
            connect_fail_label(&fault("tls_handshake", "certificate verify failed: self-signed")),
            "TLS MITM"
        );
        assert_eq!(
            connect_fail_label(&fault("tls_handshake", "certificate verify failed: unable to get local issuer certificate")),
            "NO CA BUNDLE"
        );
    }
}

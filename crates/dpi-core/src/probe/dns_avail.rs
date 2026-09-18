//! Test 1: DNS availability + hijack detection.
//!
//! Three probe blocks run concurrently over disjoint server lists: UDP, the
//! DoH `doh_wire` endpoints and DoT. UDP is what is being judged; the two
//! encrypted transports measure the same forbidden domains over TLS to supply
//! the truth its answers are compared against.
//!
//! Two-phase UDP scheme: phase A probes trusted domains (liveness + ping),
//! phase B probes forbidden domains only on live servers and compares UDP
//! answers against the DoH/DoT truth. Silence on a forbidden domain counts
//! as substitution, not unavailability. Egress resolvers are fingerprinted
//! via `whoami.akamai.net` + Team Cymru org names.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};

use crate::dns::doh::DohSession;
use crate::dns::dot::DotSession;
use crate::dns::socks::SocksProxyConfig;
use crate::dns::types::DnsError;
use crate::config::AppConfig;
use crate::{PhaseProgress, ProgressBlock};
use crate::probe::cymru::fetch_ip_cymru;
use crate::probe::domains::fake_ip_type;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Window for the DoH warmup query. Its result is thrown away — it only opens
/// the HTTP/2 stream — while on a server that answers nothing a full-budget
/// warmup would spend half the probe cap before the first real query.
const DOH_WARMUP: Duration = Duration::from_millis(1500);

/// Whether a query that starts now, with a full `window` ahead of it, still
/// fits in the probe's `budget` (seconds). When it does not, the probe stops
/// starting new work: the outer cap cancels the whole future and takes every
/// answer collected so far with it, so a partial result beats a cancelled one.
fn fits_in_budget(elapsed: Duration, window: Duration, budget_secs: f64) -> bool {
    elapsed.as_secs_f64() + window.as_secs_f64() <= budget_secs
}

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

/// Maps a session/query error to a display token: a staged transport error
/// surfaces as its classification label (SYN DROP / TLS DROP, …), a resolve
/// failure or malformed request as DNS FAIL, and everything else as TIMEOUT.
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

/// First error wins: the earliest failure reason recorded for a key is kept,
/// later ones for the same key are dropped.
fn record_fail(report: &mut DnsAvailReport, key: &ProbeKey, label: &str) {
    report
        .fail_reasons
        .entry(key.clone())
        .or_insert_with(|| label.to_string());
}

/// All-None latency map for an aborted server: every domain is present with no
/// timing recorded.
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
    /// Configured truth IPs (`DNS_TRUTH_FALLBACK`), used only for domains the
    /// live DoH/DoT probes could not answer.
    pub truth_fallback: HashMap<String, Vec<IpAddr>>,
    /// True when at least one domain fell back to the configured IPs, so the
    /// rendered report can say the reference was not measured here.
    pub truth_fallback_used: bool,
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

/// Outcome of one UDP query task: the domain and its probe result.
type UdpQueryResult = (String, Result<(Vec<IpAddr>, f64), DnsError>);

/// Spawns one UDP query task per domain, bounded by the server's query gate.
/// With `tx` (phase A) each result is streamed to the caller, which reacts to
/// the first answer; without it (phase B) the result comes back through the
/// handle. Either way the result is moved, never copied.
fn spawn_udp_queries(
    server: SocketAddr,
    domains: &[String],
    timeout_dur: Duration,
    gate: &Arc<Semaphore>,
    socks_proxy: Option<&SocksProxyConfig>,
    tx: Option<mpsc::Sender<UdpQueryResult>>,
) -> Vec<tokio::task::JoinHandle<Option<UdpQueryResult>>> {
    let mut handles = Vec::with_capacity(domains.len());
    for d in domains {
        let d = d.clone();
        let gate = Arc::clone(gate);
        let socks_proxy = socks_proxy.cloned();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            let _p = crate::probe::permit(&gate).await;
            let r = crate::dns::udp::probe_udp_dns(server, &d, timeout_dur, socks_proxy.as_ref()).await;
            match tx {
                Some(tx) => {
                    let _ = tx.send((d, r)).await;
                    None
                }
                None => Some((d, r)),
            }
        }));
    }
    handles
}

/// Resolver egress fingerprint (`whoami.akamai.net`), one retry. The first
/// attempt uses a short window — the retry exists for a single lost packet, not
/// for slow resolvers — while the retry keeps the full budget, so no answer
/// that would have been captured is lost. A silent resolver therefore costs
/// `2s + 0.2s + timeout` instead of `2*timeout`.
async fn probe_egress(
    server: SocketAddr,
    timeout_dur: Duration,
    socks_proxy: Option<&SocksProxyConfig>,
) -> Option<IpAddr> {
    const FIRST_ATTEMPT: Duration = Duration::from_secs(2);
    let mut egress_ip = None;
    for attempt in 0..2 {
        let window = if attempt == 0 { timeout_dur.min(FIRST_ATTEMPT) } else { timeout_dur };
        match crate::dns::udp::probe_udp_dns(server, "whoami.akamai.net", window, socks_proxy).await {
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
    egress_ip
}

/// Downscales a configured concurrency gate to what the local CPU can
/// sustain in parallel TLS handshakes (pure-Rust crypto, no acceleration
/// on MIPS/weak ARM cores). Downscale-only: never raises explicit values,
/// strong machines keep their configured limits.
/// Proven: 20-wide gates starve a 2-core MIPS box into 5s tail timeouts
/// (DoT TIMEOUTs that vanish at 6-wide); x86 is unaffected in verdicts.
fn auto_gate(configured: usize) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    gate_for(configured, cpus)
}

/// Hardware threads from which the CPU stops being the bottleneck: at or above
/// this the configured value is honored exactly, so a desktop is never silently
/// cut down. Below it one weak core starves on many concurrent handshakes and
/// reports its own starvation as censorship, so the value is capped at
/// `cores × 2` (floor 4, the measured MIPS-safe width). Weak-hardware
/// protection stays where it was proven to matter — routers, phones, old
/// laptops — without second-guessing a desktop.
///
/// The threshold is deliberately not tuned on a desktop: interleaved runs on a
/// 12-thread box (24 vs 50 vs 100) could not separate the settings from the
/// network's own flakiness (DoT swung 7/34..33/34 at every width), so the CPU
/// term stays a weak-device protection rather than a measured x86 gain.
const AUTO_GATE_MIN_CPUS: usize = 8;

fn gate_for(configured: usize, cpus: usize) -> usize {
    if cpus >= AUTO_GATE_MIN_CPUS {
        configured.max(1)
    } else {
        configured.min((cpus * 2).max(4)).max(1)
    }
}

/// `concurrency` is the run-wide limit (TUI "Concurrency" / `--concurrency` /
/// `MAX_CONCURRENT`) shared with the other tests: every probe in flight holds
/// one slot of it, so at no point do more requests — TLS handshakes included —
/// run in parallel than that value allows.
pub async fn check_dns_availability(
    cfg: &AppConfig,
    phases: Option<PhaseProgress>,
    concurrency: usize,
) -> DnsAvailReport {
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
    // Test 1 runs its four blocks concurrently (they share one gate), so the
    // live line reports all of them at once — a single sequential counter would
    // misrepresent the run and freeze whenever one unit is slow.
    let block_tick = phases.as_ref().map(|p| {
        let mut blocks: Vec<(ProgressBlock, usize)> = Vec::new();
        if !udp_servers.is_empty() {
            blocks.push((ProgressBlock::Udp, udp_servers.len()));
            blocks.push((ProgressBlock::Egress, udp_servers.len()));
        }
        if !doh_servers.is_empty() {
            blocks.push((ProgressBlock::Doh, doh_servers.len()));
        }
        if !dot_servers.is_empty() {
            blocks.push((ProgressBlock::Dot, dot_servers.len()));
        }
        (p.on_blocks)(crate::PhaseId::DnsAvailability, &blocks)
    });

    // Proxy: only SOCKS5 supports UDP relay
    let proxy_raw = cfg.effective_proxy().map(|s| s.to_string());
    let mut socks_proxy: Option<SocksProxyConfig> = None;
    if let Some(ref p) = proxy_raw {
        match crate::dns::socks::parse_socks_proxy(p) {
            Ok(c) => socks_proxy = Some(c),
            Err(_) => report.non_socks_proxy_warn = true,
        }
    }


    // One budget for every probe in flight: UDP, DoH, DoT and the Cymru ASN
    // lookups all spend it, so the run never has more requests (and therefore
    // TLS handshakes) in flight than the user's concurrency setting allows.
    // `auto_gate` still downscales it on weak CPUs, never raises it.
    let dns_gate = auto_gate(concurrency.max(1));
    let probe_gate = Arc::new(Semaphore::new(dns_gate));
    let egress_sem = Arc::new(Semaphore::new(auto_gate(cfg.dns_egress_concurrency.max(1))));

    // ── Spawn all three probe blocks before the first await ──
    // UDP, DoH and DoT are mutually independent — they fill disjoint maps and
    // are compared only later, in `truth_ips` — so spawning them together
    // keeps the shared gate busy on block tails instead of idling them.
    let udp_handles = {
        let mut handles = Vec::new();
        for (addr, name, port) in &udp_servers {
            let (addr, name, port) = (addr.clone(), name.clone(), *port);
            let allowed = allowed.clone();
            let forbidden = forbidden.clone();
            let gate = Arc::clone(&probe_gate);
            let egress_sem = Arc::clone(&egress_sem);
            let socks_proxy = socks_proxy.clone();
            // Per-server query gate: one server's queries never queue behind
            // another server's probes.
            let udp_gate = Arc::new(Semaphore::new(dns_gate));
            let block_tick = block_tick.clone();
            handles.push(tokio::spawn(async move {
                let server: SocketAddr = format!("{}:{}", addr, port)
                    .parse()
                    .unwrap_or(SocketAddr::from(([0, 0, 0, 0], port)));
                let key = ProbeKey { kind: ProbeKind::Udp, addr: addr.clone(), name: name.clone() };

                // Egress fingerprint runs concurrently with phases A/B under its
                // own gate: a silent resolver must not hold a probe slot for its
                // whoami retries.
                let egress_task = {
                    let socks_proxy = socks_proxy.clone();
                    let egress_sem = Arc::clone(&egress_sem);
                    let tick = block_tick.clone();
                    tokio::spawn(async move {
                        let _e = crate::probe::permit(&egress_sem).await;
                        let ip = probe_egress(server, timeout_dur, socks_proxy.as_ref()).await;
                        if let Some(t) = &tick {
                            t(ProgressBlock::Egress);
                        }
                        ip
                    })
                };

                let mut lat: HashMap<String, Option<f64>> = HashMap::new();
                let mut answers: Vec<((ProbeKey, String), DnsAnswer)> = Vec::new();
                {
                    let _g = crate::probe::permit(&gate).await;

                    // Phase A: trusted domains, fanned out per server. Phase B
                    // fires as soon as ANY trusted domain answers — liveness is
                    // `any(l.is_some())`, so waiting for a silent sibling only
                    // delays the substitution phase. Late phase-A results are
                    // still collected for the latency table.
                    let (a_tx, mut a_rx) = mpsc::channel::<UdpQueryResult>(allowed.len().max(1));
                    let _ = spawn_udp_queries(
                        server,
                        &allowed,
                        timeout_dur,
                        &udp_gate,
                        socks_proxy.as_ref(),
                        Some(a_tx),
                    );

                    let mut alive = false;
                    let mut b_handles = Vec::new();
                    for _ in 0..allowed.len() {
                        let Some((d, r)) = a_rx.recv().await else { break };
                        let (l, a) = answer_of(r);
                        if l.is_some() {
                            alive = true;
                        }
                        if let Some(ans) = a {
                            answers.push(((key.clone(), d.clone()), ans));
                        }
                        lat.insert(d, l);
                        // Phase B: forbidden domains on live servers only.
                        if alive && b_handles.is_empty() && !forbidden.is_empty() {
                            b_handles = spawn_udp_queries(
                                server,
                                &forbidden,
                                timeout_dur,
                                &udp_gate,
                                socks_proxy.as_ref(),
                                None,
                            );
                        }
                    }
                    for h in b_handles {
                        if let Ok(Some((d, r))) = h.await {
                            let (l, a) = answer_of(r);
                            if let Some(ans) = a {
                                answers.push(((key.clone(), d.clone()), ans));
                            }
                            lat.insert(d, l);
                        }
                    }
                }

                // The server's own probes are done here (and its gate slot is
                // released); the egress fingerprint keeps running on its own
                // budget and advances the EGRESS counter by itself.
                if let Some(t) = &block_tick {
                    t(ProgressBlock::Udp);
                }

                let egress_ip = egress_task.await.unwrap_or(None);
                (key, lat, answers, egress_ip)
            }));
        }
        handles
    };

    // ── DoH wire probes (truth), one connection per server, sequential ──
    let doh_handles = {
        let mut handles = Vec::new();
        for (addr, name, port) in &doh_servers {
            let (addr, name, _port) = (addr.clone(), name.clone(), *port);
            let forbidden = forbidden.clone();
            let gate = Arc::clone(&probe_gate);
            // Per-server query gate: queries are sequential on this server's
            // single connection, so bounding them per server (instead of
            // globally) keeps one server's retries from stalling the others.
            // Its width is the run-wide concurrency, like every other gate here.
            let doh_sem = Arc::new(Semaphore::new(dns_gate));
            let block_tick = block_tick.clone();
            handles.push(tokio::spawn(async move {
                let _g = crate::probe::permit(&gate).await;
                let key = ProbeKey { kind: ProbeKind::DohWire, addr: addr.clone(), name: name.clone() };
                // Outer cap: twice the query window plus 3 s of slack.
                let cap = Duration::from_secs_f64(timeout_dur.as_secs_f64() * 2.0 + 3.0);
                let cap_secs = cap.as_secs_f64();
                let probe = async {
                    // The cap is only a backstop: reaching it cancels the probe
                    // and discards everything it already answered, so the loop
                    // below stops starting work that no longer fits the budget.
                    let started = Instant::now();
                    let mut session = match DohSession::connect(&addr, timeout_dur).await {
                        Ok(s) => s,
                        Err(e) => {
                            return (HashMap::new(), Vec::new(), Some(connect_fail_label(&e).to_string()));
                        }
                    };
                    // Warmup is non-critical for DoH (it only warms up the HTTP/2
                    // stream) and its answer is discarded, so on HTTP/2 it gets a
                    // short window of its own. On HTTP/1.1 the full window stays:
                    // dropping a request there kills the whole connection, so a
                    // cut-short warmup would take every answer after it down.
                    let warmup = forbidden.first().cloned().unwrap_or_else(|| "google.com".to_string());
                    let warmup_window = if session.is_h2() { timeout_dur.min(DOH_WARMUP) } else { timeout_dur };
                    let _ = session.query(&warmup, warmup_window).await;

                    let mut lat = HashMap::new();
                    let mut answers = Vec::new();
                    let mut first_fail: Option<String> = None;
                    // Once the transport is gone, no further request can be
                    // answered: hyper tears down an HTTP/1.1 connection whose
                    // response future was dropped, and reports it through
                    // `is_closed`. Retrying there only burns the jitter sleep,
                    // so the remaining domains are recorded as failures.
                    let mut dead = false;
                    for d in &forbidden {
                        if dead {
                            lat.insert(d.clone(), None);
                            continue;
                        }
                        // A query whose window cannot fit would be cancelled with
                        // the answers collected so far; keep them instead.
                        if !fits_in_budget(started.elapsed(), timeout_dur, cap_secs) {
                            lat.insert(d.clone(), None);
                            continue;
                        }
                        let _p = crate::probe::permit(&doh_sem).await;
                        // One retry after a jittered 0.3–1.0 s pause, unless the
                        // connection is closed or the window no longer fits.
                        let mut res = session.query(d, timeout_dur).await;
                        if res.is_err()
                            && !session.is_closed()
                            && fits_in_budget(started.elapsed(), timeout_dur, cap_secs)
                        {
                            let jitter = (rand::random::<u8>() as f64) / 255.0 * 0.7;
                            tokio::time::sleep(Duration::from_secs_f64(0.3 + jitter)).await;
                            res = session.query(d, timeout_dur).await;
                        }
                        // First connection-class error wins; later ones do not
                        // overwrite it.
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
                        dead = session.is_closed();
                    }
                    (lat, answers, first_fail)
                };
                let out = match tokio::time::timeout(cap, probe).await {
                    Ok((lat, answers, fail)) => (key, lat, answers, fail),
                    Err(_) => (key, lat_none(&forbidden), Vec::new(), Some("TIMEOUT".to_string())),
                };
                if let Some(t) = &block_tick {
                    t(ProgressBlock::Doh);
                }
                out
            }));
        }
        handles
    };

    // ── DoT probes ──
    let dot_handles = {
        let mut handles = Vec::new();
        for (addr, name, port) in &dot_servers {
            let (addr, name, port) = (addr.clone(), name.clone(), *port);
            let forbidden = forbidden.clone();
            let gate = Arc::clone(&probe_gate);
            let block_tick = block_tick.clone();
            handles.push(tokio::spawn(async move {
                let _g = crate::probe::permit(&gate).await;
                let key = ProbeKey { kind: ProbeKind::Dot, addr: addr.clone(), name: name.clone() };
                // Outer cap: twice the query window plus 3 s of slack.
                let cap = Duration::from_secs_f64(timeout_dur.as_secs_f64() * 2.0 + 3.0);
                let cap_secs = cap.as_secs_f64();
                let probe = async {
                    // Same backstop as the DoH probe: stop before the cap so the
                    // answers already collected survive.
                    let started = Instant::now();
                    let (host, mut ep_port) = crate::dns::dot::split_dot_endpoint(&addr);
                    if port != 853 {
                        ep_port = port;
                    }
                    let mut session = match DotSession::connect(&host, ep_port, timeout_dur).await {
                        Ok(s) => s,
                        Err(e) => {
                            return (HashMap::new(), Vec::new(), Some(connect_fail_label(&e).to_string()));
                        }
                    };
                    // Warmup is fatal — its error aborts the whole server with
                    // that error recorded — so it keeps the full window:
                    // shortening it would turn a slow server into a dead one.
                    let warmup = forbidden.first().cloned().unwrap_or_else(|| "google.com".to_string());
                    if let Err(e) = session.query(&warmup).await {
                        return (HashMap::new(), Vec::new(), Some(connect_fail_label(&e).to_string()));
                    }

                    let mut lat = HashMap::new();
                    let mut answers = Vec::new();
                    // Per-query errors stay silent and only leave that domain
                    // unanswered, but a stream-level I/O error is terminal: the
                    // peer is gone, so the remaining domains can only fail.
                    let mut dead = false;
                    for d in &forbidden {
                        if dead {
                            lat.insert(d.clone(), None);
                            continue;
                        }
                        if !fits_in_budget(started.elapsed(), timeout_dur, cap_secs) {
                            lat.insert(d.clone(), None);
                            continue;
                        }
                        let res = session.query(d).await;
                        dead = matches!(&res, Err(DnsError::Io(_)));
                        let (l, a) = answer_of(res);
                        if let Some(ans) = a {
                            answers.push(((key.clone(), d.clone()), ans));
                        }
                        lat.insert(d.clone(), l);
                    }
                    let none: Option<String> = None;
                    (lat, answers, none)
                };
                let out = match tokio::time::timeout(cap, probe).await {
                    Ok((lat, answers, fail)) => (key, lat, answers, fail),
                    Err(_) => (key, lat_none(&forbidden), Vec::new(), Some("TIMEOUT".to_string())),
                };
                if let Some(t) = &block_tick {
                    t(ProgressBlock::Dot);
                }
                out
            }));
        }
        handles
    };

    // ── UDP results (phase A/B finished) ──
    for h in udp_handles {
        if let Ok((key, lat, answers, egress_ip)) = h.await {
            report.egress.insert((key.addr.clone(), key.name.clone()), egress_ip);
            for (k, a) in answers {
                report.udp_answers.insert(k, a);
            }
            report.raw.insert(key, lat);
        }
    }

    // ── Org names for egress IPs (Team Cymru over DoH) ──
    // Spawned as soon as the UDP block knows the egress IPs, so the lookups
    // overlap with the DoH/DoT probes. They are TLS requests like the probes,
    // so they spend the same gate; `DNS_ASN_CONCURRENCY` only tightens them.
    let org_handles: Vec<_> = {
        let unique: HashSet<IpAddr> = report.egress.values().filter_map(|v| *v).collect();
        let asn_sem = Arc::new(Semaphore::new(auto_gate(cfg.dns_asn_concurrency.max(1))));
        unique
            .into_iter()
            .map(|ip| {
                let asn_sem = Arc::clone(&asn_sem);
                let budget = Arc::clone(&probe_gate);
                let cymru = cfg.cymru_doh_servers.clone();
                tokio::spawn(async move {
                    let _p = crate::probe::permit(&asn_sem).await;
                    let _b = crate::probe::permit(&budget).await;
                    let info = fetch_ip_cymru(&ip, &cymru, Duration::from_secs(5)).await;
                    (ip, info.and_then(|i| i.org).unwrap_or_default())
                })
            })
            .collect()
    };

    // ── DoH results ──
    for h in doh_handles {
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

    // ── DoT results ──
    for h in dot_handles {
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

    // ── Org names for egress IPs (Team Cymru over DoH): lookups already ran
    // in the background during the DoH/DoT probes. ──
    for h in org_handles {
        if let Ok((ip, org)) = h.await {
            if !org.is_empty() {
                report.org_names.insert(ip.to_string(), org);
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

    // Configured reference, used only where the network could not provide one:
    // on a fully blocked path (no encrypted DNS at all) the comparison would
    // otherwise have nothing to compare against.
    report.truth_fallback = cfg
        .dns_truth_fallback
        .iter()
        .map(|(domain, ips)| {
            let parsed: Vec<IpAddr> = ips.iter().filter_map(|s| s.parse().ok()).collect();
            (domain.clone(), parsed)
        })
        .filter(|(_, ips): &(String, Vec<IpAddr>)| !ips.is_empty())
        .collect();
    let live = live_truth(&report);
    report.truth_fallback_used = report
        .truth_fallback
        .keys()
        .any(|d| live.get(d).is_none_or(|s| s.is_empty()));

    report.stats = compute_stats(&report, cfg);
    report
}

/// Truth measured on this network: what the DoH/DoT probes answered.
fn live_truth(report: &DnsAvailReport) -> HashMap<String, HashSet<IpAddr>> {
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

/// Reference used for the substitution comparison: the measured truth, plus
/// the configured fallback for domains that nothing measured. The fallback
/// never extends a measured set — mixing a stale IP into a live one would
/// weaken the comparison instead of filling a gap.
fn truth_ips(report: &DnsAvailReport) -> HashMap<String, HashSet<IpAddr>> {
    let mut truth = live_truth(report);
    for (domain, ips) in &report.truth_fallback {
        let slot = truth.entry(domain.clone()).or_default();
        if slot.is_empty() {
            slot.extend(ips.iter().copied());
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

/// (judged, substituted) per UDP server. Public entry point for renderers:
/// rebuilds the truth map on every call.
pub fn subst_counts(report: &DnsAvailReport, addr: &str, name: &str) -> (usize, usize) {
    subst_counts_with(report, &truth_ips(report), addr, name)
}

/// Same, against an already-built truth map, so the stats pass can compute
/// the truth once instead of once per server.
fn subst_counts_with(
    report: &DnsAvailReport,
    truth: &HashMap<String, HashSet<IpAddr>>,
    addr: &str,
    name: &str,
) -> (usize, usize) {
    if !udp_alive(report, addr, name) {
        return (0, 0);
    }
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
        // MSK-IX and НСДИ are the stand-in itself: the /24 a run meets them on
        // is the host other brands' answers come back from, which is what the
        // check below notices — but they are the ones doing the answering, not
        // brands whose answers were replaced. The list is config data
        // (`DNS_HIJACK_EXEMPT_RESOLVERS`), so it changes without a rebuild.
        if known_resolver(&brand(&name), &cfg.dns_hijack_exempt_resolvers) {
            continue;
        }
        for a in addrs {
            let eip = report.egress.get(&(a.clone(), name.clone())).copied().flatten();
            if let Some(eip) = eip {
                let org = report.org_names.get(&eip.to_string()).cloned().unwrap_or_default();
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

    // One walk over the live UDP servers fills the substitution, fake-IP and
    // stub-IP tallies; the truth map is built once instead of per server.
    let truth = truth_ips(report);
    let mut subst_sub = 0;
    let mut subst_total = 0;
    let mut fakeip_count = 0;
    let mut stub_counts: HashMap<IpAddr, usize> = HashMap::new();
    for (name, addrs) in udp_by_name(report) {
        for a in addrs {
            if !udp_alive(report, &a, &name) {
                continue;
            }
            let (judged, sub) = subst_counts_with(report, &truth, &a, &name);
            if judged == 0 {
                continue;
            }
            subst_total += 1;
            if sub > 0 {
                subst_sub += 1;
            }
            if fakeip_sub(report, &a, &name) > 0 {
                fakeip_count += 1;
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
    // Stub IPs are addresses that at least `dns_stub_threshold` resolvers hand
    // out in place of the truth; only the most frequent one is reported.
    let stub_min = cfg.dns_stub_threshold.max(1) as usize;
    let top_stub = stub_counts
        .into_iter()
        .filter(|(_, c)| *c >= stub_min)
        .max_by_key(|(_, c)| *c)
        .map(|(ip, _)| ip.to_string());

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

    /// auto_gate is downscale-only and portable: never exceeds the
    /// configured value, never stalls to zero, regardless of CPU count.
    #[test]
    fn test_auto_gate_bounds() {
        assert!(auto_gate(20) <= 20);
        assert!(auto_gate(100) <= 100);
        assert!(auto_gate(1) >= 1);
        assert!(auto_gate(20) >= 1);
        // Explicit low values pass through untouched: `auto_gate` only ever
        // shrinks, and its CPU term never drops below 4.
        assert_eq!(auto_gate(1), 1);
        assert_eq!(auto_gate(2), 2);
    }

    /// The gate protects weak CPUs only. A desktop must get exactly what the
    /// user asked for, or a configured 50 would silently become 24.
    #[test]
    fn test_gate_honors_configured_on_strong_cpus() {
        assert_eq!(gate_for(50, 12), 50);
        assert_eq!(gate_for(100, 8), 100);
        assert_eq!(gate_for(1, 16), 1);
        // Below the threshold the proven formula stays: `cores × 2`, floor 4.
        assert_eq!(gate_for(100, 4), 8);
        assert_eq!(gate_for(100, 2), 4);
        assert_eq!(gate_for(100, 1), 4);
        assert_eq!(gate_for(3, 2), 3);
        assert_eq!(gate_for(0, 12), 1);
        assert_eq!(gate_for(0, 2), 1);
    }

    /// The configured fallback exists for networks where every encrypted
    /// resolver is blocked. It fills a missing measurement and never extends a
    /// measured one: a stale configured IP inside a live set would weaken the
    /// comparison instead of helping it.
    #[test]
    fn test_fallback_truth_only_fills_gaps() {
        let key = |addr: &str| ProbeKey {
            kind: ProbeKind::DohWire,
            addr: addr.to_string(),
            name: "Server".to_string(),
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut report = DnsAvailReport::default();
        report.doh_answers.insert(
            (key("https://a/dns-query"), "measured.example".to_string()),
            DnsAnswer::Ips(vec![ip("203.0.113.5")]),
        );
        report.truth_fallback.insert("measured.example".to_string(), vec![ip("198.51.100.9")]);
        report.truth_fallback.insert("blind.example".to_string(), vec![ip("198.51.100.7")]);

        let truth = truth_ips(&report);
        assert_eq!(truth["measured.example"], HashSet::from([ip("203.0.113.5")]));
        assert_eq!(truth["blind.example"], HashSet::from([ip("198.51.100.7")]));
    }

    #[test]
    fn test_brand_sort() {
        assert_eq!(brand("AdGuard (F)"), "AdGuard");
        let mut v = ["Yandex".to_string(), "Google".to_string(), "Other".to_string()];
        v.sort_by_key(|a| dns_name_sort_key(a));
        assert_eq!(v[0], "Google");
        assert_eq!(v[2], "Yandex");
    }

    #[test]
    fn test_net24() {
        assert_eq!(net24(&"1.2.3.4".parse().unwrap()), "1.2.3");
    }

    /// The probe cap cancels the future instead of truncating it, so everything
    /// collected up to that moment is lost. This check is what keeps it, and its
    /// boundary decides whether the last query is allowed to start.
    #[test]
    fn test_fits_in_budget_boundary() {
        let budget = 23.0; // 2×10 + 3, the DoH/DoT cap
        let window = Duration::from_secs(10);
        // Exactly one more full window fits.
        assert!(fits_in_budget(Duration::from_secs(13), window, budget));
        // One millisecond less does not: starting would be cancelled mid-flight.
        assert!(!fits_in_budget(
            Duration::from_secs(13) + Duration::from_millis(1),
            window,
            budget
        ));
        assert!(!fits_in_budget(Duration::from_secs(23), window, budget));
        assert!(fits_in_budget(Duration::ZERO, window, budget));
    }

    /// Each staged fault surfaces as the classifier's label for that stage.
    #[test]
    fn test_connect_fail_label() {
        use crate::dns::types::DnsError;
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

    /// The summary names brands whose answers were replaced, not the host that
    /// replaced them: a resolver on `DNS_HIJACK_EXEMPT_RESOLVERS` stays out of
    /// the list even when the /24 it exits through is shared with another brand,
    /// which is exactly the shape the check reads as a stand-in.
    #[test]
    fn an_exempt_resolver_is_not_reported_as_hijacked() {
        let cfg = AppConfig::default();
        let mut report = DnsAvailReport {
            udp_servers: vec![
                ("192.0.2.10".to_string(), "MSK-IX".to_string(), 53),
                ("192.0.2.11".to_string(), "Watchdog".to_string(), 53),
                ("192.0.2.12".to_string(), "НСДИ".to_string(), 53),
            ],
            ..DnsAvailReport::default()
        };
        // Two brands exiting through one /24: the hijack check fires for both.
        for (addr, name, egress) in [
            ("192.0.2.10", "MSK-IX", "198.51.100.7"),
            ("192.0.2.11", "Watchdog", "198.51.100.8"),
        ] {
            report.egress.insert(
                (addr.to_string(), name.to_string()),
                Some(egress.parse().unwrap()),
            );
        }
        assert_eq!(
            compute_stats(&report, &cfg).hijacked_brands,
            vec!["Watchdog".to_string()],
            "only the brand that is not the stand-in"
        );
    }
}

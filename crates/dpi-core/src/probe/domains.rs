//! Test 2: domain availability — DNS resolve + TLS 1.3 + TLS 1.2 + HTTP + QUIC.
//!
//! One task per domain. It resolves first (with the IPv6 fallback that tells
//! "no IPv6" from "no such host"), and the moment its own lookup returns it
//! starts that row's probes: the QUIC Initial goes out beside the TCP chain, and
//! TLS 1.3, TLS 1.2 and plain HTTP follow one another against the resolved
//! address with SNI pinned to it. Every probe takes a permit from the run's own
//! gate, so the columns advance together instead of one after another, and a step
//! that hangs costs one permit rather than the rest of its column
//! ([`check_domains`]). Result rows are (domain, http, tls1.2, tls1.3, quic,
//! details).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::body::Bytes;
use hyper::header::HOST;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_connect_error_icmp, classify_ssl_error, ConnectionStage,
    Detail, DpiStatus, ProbeStage,
};
use crate::config::AppConfig;
use crate::dns::resolve_host;
use crate::PhaseProgress;
use crate::ProgressTick;
use crate::net::connector::RustlsConnector;
use crate::net::fingerprint::{http_identity, TlsFingerprint};
use crate::net::http::{
    check_http, classify_redirect, fat_read_verdict, inner_hyper, parse_host, request_headers, BODY_CAP,
};
use crate::net::connector::DpiTlsConnector;
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
    /// Seconds the leg took. Stamped by `check_http_injection`, which owns the
    /// clock: the verdicts the leg builds on the way out carry a zero until then.
    pub elapsed: f64,
}

impl HttpCheck {
    /// One verdict of the leg while it is being built.
    fn at(status: DpiStatus, detail: Detail) -> Self {
        Self { status, detail, elapsed: 0.0 }
    }
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
    let total_timeout = Duration::from_secs_f64(cfg.timeout * 2.0);
    let stage = Arc::new(Mutex::new(ProbeStage::TcpConnect));
    let addr = SocketAddr::new(target, 443);

    let fut = async {
        let tcp = match dial_tcp(&addr, Duration::from_secs_f64(cfg.timeout)).await {
            Ok(stream) => stream,
            Err(DialError::Io { error, icmp }) => {
                let (status, detail) = classify_connect_error_icmp(&error, icmp, 0, ProbeStage::TcpConnect);
                return (status, detail, 0usize);
            }
            Err(DialError::Timeout) => {
                return (DpiStatus::SynDropped, Detail::TcpSynTimeout, 0usize);
            }
        };

        // TLS handshake (version-pinned client)
        *stage.lock() = ProbeStage::TlsHandshake;
        let fingerprint = TlsFingerprint::from_config(cfg);
        let profile = if tls12_only {
            TlsProfile::insecure(fingerprint).tls12()
        } else {
            TlsProfile::insecure(fingerprint).tls13()
        };
        let rustls_conn = RustlsConnector::from(profile);
        let server_name = match crate::net::tls::server_name(domain) {
            Ok(n) => n,
            Err(e) => {
                return (DpiStatus::Err, Detail::Other(format!("bad SNI: {}", e)), 0usize);
            }
        };
        let tracker = crate::classify::DpiProbeTracker::new();
        let probe_stream = crate::classify::DpiProbeStream::new(tcp, tracker.clone());
        let tls_stream = match timeout(
            Duration::from_secs_f64(cfg.timeout),
            rustls_conn.connect(server_name, probe_stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                let st = tracker.state.lock();
                if let Some(status) = st.last_status {
                    let detail = st.last_error_msg.clone().unwrap_or(Detail::RstHello);
                    return (status, detail, 0usize);
                }
                drop(st);
                let msg = e.to_string();
                let (status, detail) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, ProbeStage::TlsHandshake);
                if status != DpiStatus::Unknown {
                    return (status, detail, 0usize);
                }
                let (ssl_status, ssl_detail) = classify_ssl_error(&msg, 0, ConnectionStage::TlsClientHelloSent);
                return (ssl_status, ssl_detail, 0usize);
            }
            Err(_) => {
                return (DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout, 0usize);
            }
        };

        *stage.lock() = ProbeStage::TlsConnected;
        // Test 2 counts the bytes a connection carries before it is cut, so it
        // never negotiates a Content-Encoding.
        check_http(tls_stream, domain, cfg, fingerprint, &stage, true).await
    };

    match timeout(total_timeout, fut).await {
        Ok((status, detail, _)) => TlsCheck { status, detail, elapsed: start.elapsed().as_secs_f64() },
        Err(_) => {
            // An outer timeout is a failure of whatever stage the check had
            // reached, read the same way the classifier reads it: the two dial
            // stages have verdicts of their own, and everything past the
            // handshake is the read that never finished. `ProbeStage` is `Copy`,
            // so the guard is held only for the read.
            let (status, detail) = match *stage.lock() {
                ProbeStage::TlsHandshake => (DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout),
                ProbeStage::TcpConnect => (DpiStatus::SynDropped, Detail::TcpSynTimeout),
                ProbeStage::TlsConnected | ProbeStage::SendingData | ProbeStage::ReadingData => {
                    (DpiStatus::ReadTimeout, Detail::ReadTimeoutWord)
                }
            };
            TlsCheck { status, detail, elapsed: start.elapsed().as_secs_f64() }
        }
    }
}


/// Plain-HTTP injection check: GET to `port` of the resolved IP with
/// Host = domain; a known provider stub IP short-circuits to `IspPage`.
///
/// The request is a GET rather than a HEAD because the answer differs: a censor
/// that intercepts plain HTTP answers a HEAD with a synthetic "go to https"
/// bounce on the same host — a normal redirect by every rule this tool has —
/// while the same GET gets the blockpage, on a foreign host. Measured against a
/// live lawfilter: HEAD `301 → https://<site>/`, GET
/// `307 → http://lawfilter.ertelecom.ru/`.
///
/// The port is a parameter because test 2 checks 80 and a test cannot bind it.
pub async fn check_http_injection(
    domain: &str,
    target: Option<IpAddr>,
    cfg: &AppConfig,
    stub_ips: &HashSet<IpAddr>,
    port: u16,
) -> HttpCheck {
    let started = Instant::now();
    if let Some(ip) = target
        && stub_ips.contains(&ip)
    {
        return HttpCheck {
            status: DpiStatus::IspPage,
            detail: Detail::IspBlockpage { arrow: false, ip: ip.to_string() },
            elapsed: started.elapsed().as_secs_f64(),
        };
    }
    let total_timeout = Duration::from_secs_f64(cfg.timeout * 2.0);
    let domain_owned = domain.to_string();

    let fut = async {
        let host_ip = match target {
            Some(ip) => ip,
            None => match resolve_ip(domain_owned.as_str(), IpFamily::V4).await {
                Some(ip) => ip,
                None => {
                    return HttpCheck::at(DpiStatus::DnsFail, Detail::DomainNotFound);
                }
            },
        };
        let addr = SocketAddr::new(host_ip, port);
        let tcp = match dial_tcp(&addr, Duration::from_secs_f64(cfg.timeout)).await {
            Ok(stream) => stream,
            Err(DialError::Io { error, icmp }) => {
                let (status, detail) = classify_connect_error_icmp(&error, icmp, 0, ProbeStage::TcpConnect);
                return HttpCheck::at(status, detail);
            }
            Err(DialError::Timeout) => {
                return HttpCheck::at(DpiStatus::SynDropped, Detail::TcpSynTimeout);
            }
        };

        let io = TokioIo::new(tcp);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(v) => v,
            Err(e) => {
                let (status, detail) = inner_hyper(&e, ProbeStage::TcpConnect, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return HttpCheck::at(status, detail);
            }
        };
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Plain HTTP (port 80) fallback: the same identity the TLS probes send,
        // with `Connection: close` so the response ends with an EOF.
        let identity = http_identity(TlsFingerprint::from_config(cfg));
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(HOST, domain_owned.as_str());
        for (name, value) in request_headers(
            &identity,
            TlsFingerprint::user_agent_for(cfg, TlsFingerprint::from_config(cfg)),
            [("Connection", "close".into())],
            true,
        ) {
            builder = builder.header(name, value.as_ref());
        }
        // The header list carries the profile's identity and the configured
        // `USER_AGENT`, and `http` refuses a value holding a control byte (a
        // `USER_AGENT: |` block scalar ends in a newline); the URI comes from a
        // domain that is only trimmed, never validated. `panic = "abort"` would
        // take the whole run down, so report the failure instead.
        let req = match builder.body(http_body_util::Full::new(Bytes::new())) {
            Ok(req) => req,
            Err(e) => {
                return HttpCheck::at(
                    DpiStatus::Err,
                    Detail::Other(format!("bad request: {}", e)),
                );
            }
        };

        let resp = match timeout(Duration::from_secs_f64(cfg.timeout), sender.send_request(req)).await {
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
                    return HttpCheck::at(
                        kind,
                        if kind == DpiStatus::SendTimeout {
                            Detail::at_kb(Detail::WriteTimeoutWord, 0.0)
                        } else {
                            Detail::at_kb(Detail::ReadTimeoutWord, 0.0)
                        },
                    );
                }
                let (status, detail) = inner_hyper(&e, ProbeStage::ReadingData, 0, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                return HttpCheck::at(status, detail);
            }
            Err(_) => {
                return HttpCheck::at(
                    DpiStatus::ReadTimeout,
                    Detail::at_kb(Detail::ReadTimeoutWord, 0.0),
                );
            }
        };

        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // The body is read for the reason test 3 reads one: a DPI that cuts a
        // transfer cuts it inside a window of the stream, and where it died is
        // the verdict. A redirect carries a line of HTML, so on every other
        // answer this costs a frame or two, and a body that is not cut ends at
        // EOF or at the shared cap.
        let mut body = resp.into_body();
        let mut bytes_read: usize = 0;
        loop {
            match timeout(Duration::from_secs_f64(cfg.timeout), body.frame()).await {
                Ok(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        bytes_read += data.len();
                        if bytes_read >= BODY_CAP {
                            break;
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    let (status, detail) =
                        inner_hyper(&e, ProbeStage::ReadingData, bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                    return HttpCheck::at(status, detail);
                }
                Ok(None) => break,
                Err(_) => {
                    let (status, detail) = fat_read_verdict(bytes_read, cfg.tcp_block_min_kb, cfg.tcp_block_max_kb);
                    return HttpCheck::at(status, detail);
                }
            }
        }

        if status == 451 {
            return HttpCheck::at(DpiStatus::Blocked, Detail::HttpStatus(451));
        }
        if !location.is_empty() && (300..400).contains(&status) {
            let (status, detail) = classify_redirect(&domain_owned, &format!("http://{}", domain_owned), status, &location, true);
            return HttpCheck::at(status, detail);
        }
        if (300..400).contains(&status) {
            return HttpCheck::at(DpiStatus::Ok, Detail::HttpStatus(status));
        }
        HttpCheck::at(DpiStatus::Ok, Detail::HttpStatus(status))
    };

    let mut check = match timeout(total_timeout, fut).await {
        Ok(r) => r,
        Err(_) => HttpCheck::at(
            DpiStatus::ReadTimeout,
            Detail::at_kb(Detail::ReadTimeoutWord, 0.0),
        ),
    };
    check.elapsed = started.elapsed().as_secs_f64();
    check
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
    /// The QUIC column (test 2's fourth protocol, UDP 443).
    pub quic: crate::probe::quic::QuicCheck,
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
            http: HttpCheck::at(DpiStatus::Unknown, Detail::None),
            quic: crate::probe::quic::QuicCheck::pending(),
        }
    }
}

/// Whether the QUIC column probes this host at all: a host listed in
/// `quic_unsupported.txt` serves no HTTP/3, so its cell is a dash and the column
/// counts it nowhere. The list holds hosts, the row may hold a URL path
/// (`domains.txt` does for `x.com`), and DNS names are case-insensitive.
pub fn quic_applicable(domain: &str, unsupported: &[String]) -> bool {
    let host = parse_host(domain);
    !unsupported.iter().any(|h| h.eq_ignore_ascii_case(&host))
}

/// The QUIC cell of a row whose probe never ran because the DNS phase already
/// decided the row: a DNS failure (NXDOMAIN or v6-unsupported), an ISP stub
/// answer, or a local/relay address.
///
/// It carries the same status and the same detail as the row's TLS and HTTP
/// cells. `Unknown`, which is what the row held before, is not a verdict: the
/// TUI paints it red (`dpi-detector`'s `widgets::status_color`) and `--json`
/// writes `"unknown"` beside a `"dns_fail"` that describes the whole row.
/// `build_domain_row` groups lines by detail, so reusing the sibling detail
/// also keeps one reason on one line instead of adding a second `QUIC` line.
///
/// A row that is resolved cleanly does not come through here: it keeps
/// [`QuicCheck::pending`](crate::probe::quic::QuicCheck::pending) until the row's
/// own pipeline walks up to the QUIC step (`check_domains`).
fn skipped_quic(status: DpiStatus, detail: Detail) -> crate::probe::quic::QuicCheck {
    crate::probe::quic::QuicCheck { status, detail, elapsed: 0.0 }
}

/// The row as DNS leaves it: the address, the fake-IP class, and — for a row no
/// protocol probe can run against — the verdict all four protocol columns carry.
///
/// `v4_fallback` is whether a second lookup over IPv4 answered a host IPv6 could
/// not resolve: that reads "no IPv6 here", not "no such host". An ISP stub-IP or
/// a local/relay address is `Some(true)`, a clean answer `Some(false)`, and no
/// answer at all `None`.
fn entry_for(
    domain: &str,
    resolved: Option<IpAddr>,
    v4_fallback: bool,
    stub_ips: &HashSet<IpAddr>,
) -> DomainEntry {
    let Some(ip) = resolved else {
        let mut e = DomainEntry::pending(domain.to_string(), None, None);
        let detail = if v4_fallback { Detail::Ipv6Unsupported } else { Detail::DomainNotFound };
        e.t13 = TlsCheck { status: DpiStatus::DnsFail, detail: detail.clone(), elapsed: 0.0 };
        e.t12 = e.t13.clone();
        e.http = HttpCheck::at(DpiStatus::DnsFail, detail);
        e.quic = skipped_quic(DpiStatus::DnsFail, e.http.detail.clone());
        return e;
    };
    let mut ftype = fake_ip_type(&ip);
    if ftype != FakeIpType::FakeIp && stub_ips.contains(&ip) {
        ftype = FakeIpType::Isp;
    }
    match ftype {
        FakeIpType::Isp => {
            let mut e = DomainEntry::pending(domain.to_string(), Some(ip), Some(true));
            let detail = Detail::IspBlockpage { arrow: true, ip: ip.to_string() };
            e.t13 = TlsCheck { status: DpiStatus::DnsFake, detail: detail.clone(), elapsed: 0.0 };
            e.t12 = e.t13.clone();
            e.http = HttpCheck::at(DpiStatus::DnsFake, detail);
            e.quic = skipped_quic(DpiStatus::DnsFake, e.http.detail.clone());
            e
        }
        FakeIpType::Local => {
            let mut e = DomainEntry::pending(domain.to_string(), Some(ip), Some(true));
            let detail = Detail::LocalIp { ip: ip.to_string() };
            e.t13 = TlsCheck { status: DpiStatus::LocalIp, detail: detail.clone(), elapsed: 0.0 };
            e.t12 = e.t13.clone();
            e.http = HttpCheck::at(DpiStatus::LocalIp, detail);
            e.quic = skipped_quic(DpiStatus::LocalIp, e.http.detail.clone());
            e
        }
        _ => DomainEntry::pending(domain.to_string(), Some(ip), Some(false)),
    }
}

/// The five column counters of one run, all declared before the first probe goes
/// out: the columns no longer run one after another, so there is no "its stage
/// started" moment to declare one at.
#[derive(Clone)]
struct Ticks {
    dns: Option<ProgressTick>,
    t13: Option<ProgressTick>,
    t12: Option<ProgressTick>,
    http: Option<ProgressTick>,
    quic: Option<ProgressTick>,
}

impl Ticks {
    /// `total` is every row; `quic_total` is the rows whose endpoint serves
    /// HTTP/3 at all — the QUIC column is the one counter that does not run over
    /// the whole list, because a host that serves no HTTP/3 cannot move it.
    fn declare(phases: Option<&PhaseProgress>, total: usize, quic_total: usize) -> Self {
        let Some(p) = phases else {
            return Self { dns: None, t13: None, t12: None, http: None, quic: None };
        };
        Self {
            dns: Some((p.on_phase)(crate::PhaseId::DomainDns, total)),
            t13: Some((p.on_phase)(crate::PhaseId::DomainTls13, total)),
            t12: Some((p.on_phase)(crate::PhaseId::DomainTls12, total)),
            http: Some((p.on_phase)(crate::PhaseId::DomainHttp, total)),
            quic: Some((p.on_phase)(crate::PhaseId::DomainQuic, quic_total)),
        }
    }

    /// One tick, if this run is drawing a live line at all.
    fn fire(&self, tick: &Option<ProgressTick>) {
        if let Some(t) = tick.as_ref() {
            t();
        }
    }
}

/// Test 2's whole run — resolve, TLS 1.3, TLS 1.2, HTTP, QUIC — pipelined per
/// domain instead of one barrier per column.
///
/// One task walks one domain from its own resolve to its last verdict. The
/// resolve comes first because every other step needs the address it returns;
/// from there the row's QUIC Initial runs beside its TCP chain, and the chain's
/// three steps — TLS 1.3, TLS 1.2, HTTP — follow one another, each holding one
/// permit for as long as the probe takes. The tasks themselves run at once and
/// every probe takes a permit from the same gate, so a domain that hangs in one
/// step holds one permit rather than the column: the permits it and its
/// neighbours release are picked up by whichever probe needs one next. The gate
/// therefore stays as full as the work allows, and no column waits for the
/// slowest probe of the column before it.
///
/// Every column counts `domains.len()` except QUIC, which counts the rows whose
/// endpoint serves HTTP/3 at all (`quic_unsupported.txt` is what says so): a row
/// DNS already settled (NXDOMAIN, an ISP stub, a local address) is decided by
/// that verdict, and the columns it never reached are decided by it too.
/// `--json` and the table still carry the per-row detail, which is where "this
/// row was never probed" is readable.
///
/// The rows come back sorted by domain, the order the table prints them in.
pub async fn check_domains(
    domains: &[String],
    family: IpFamily,
    cfg: &AppConfig,
    stub_ips: &HashSet<IpAddr>,
    unsupported: &[String],
    sem: &Arc<Semaphore>,
    phases: Option<PhaseProgress>,
) -> Vec<DomainEntry> {
    // One config and one stub set for every task: each clone carries the whole
    // DNS server list, and the clones pile up while the tasks wait on the gate
    // (`probe/whitelist.rs` shares them the same way).
    let cfg = Arc::new(cfg.clone());
    let stub_ips = Arc::new(stub_ips.clone());
    let unsupported = Arc::new(unsupported.to_vec());
    let quic_total = domains.iter().filter(|d| quic_applicable(d, &unsupported)).count();
    let ticks = Ticks::declare(phases.as_ref(), domains.len(), quic_total);
    let mut handles = Vec::new();
    for domain in domains {
        let domain = domain.clone();
        let cfg = Arc::clone(&cfg);
        let stub_ips = Arc::clone(&stub_ips);
        let unsupported = Arc::clone(&unsupported);
        let sem = Arc::clone(sem);
        let ticks = ticks.clone();
        handles.push(tokio::spawn(async move {
            probe_domain(domain, family, &cfg, &stub_ips, &unsupported, &sem, &ticks).await
        }));
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(e) = h.await {
            out.push(e);
        }
    }
    out.sort_by(|a, b| a.domain.cmp(&b.domain));
    out
}

/// One domain's walk down the five columns, one permit per probe.
async fn probe_domain(
    domain: String,
    family: IpFamily,
    cfg: &Arc<AppConfig>,
    stub_ips: &Arc<HashSet<IpAddr>>,
    unsupported: &Arc<Vec<String>>,
    sem: &Arc<Semaphore>,
    ticks: &Ticks,
) -> DomainEntry {
    let applicable = quic_applicable(&domain, unsupported);
    let mut entry = {
        let _permit = crate::probe::permit(sem).await;
        let clean_domain = parse_host(&domain);
        let resolved = resolve_ip(&clean_domain, family).await;
        // IPv6 mode: an IPv4 fallback tells "IPv6 unsupported" from "not found".
        let v4_fallback = if resolved.is_none() && family == IpFamily::V6 {
            resolve_ip(&domain, IpFamily::V4).await.is_some()
        } else {
            false
        };
        entry_for(&domain, resolved, v4_fallback, stub_ips)
    };
    ticks.fire(&ticks.dns);
    let target = match (entry.dns_fake, entry.resolved) {
        (Some(false), Some(ip)) => ip,
        // A row DNS already settled has no peer to probe: `entry_for` wrote the
        // verdict its four protocol columns carry, and they are decided by it.
        _ => {
            for tick in [&ticks.t13, &ticks.t12, &ticks.http] {
                ticks.fire(tick);
            }
            // The QUIC cell carries the DNS verdict, and whether that is a tick
            // of the QUIC column is the column's own total to decide: a host that
            // serves no HTTP/3 is outside it.
            if applicable {
                ticks.fire(&ticks.quic);
            }
            return entry;
        }
    };
    // The QUIC Initial does not wait for the TCP columns: it needs the resolved
    // address and nothing else, so it goes out with its row's TLS probes instead
    // of after them. A host that drops the TCP side spends one timeout per TCP
    // step in series; the UDP probe spends its own window alongside them, and the
    // column ticks from inside the task (`Ticks`).
    let quic = start_quic(&domain, target, applicable, cfg, sem, ticks, &mut entry);
    entry.t13 = {
        let _permit = crate::probe::permit(sem).await;
        check_domain_tls(&domain, target, false, cfg).await
    };
    ticks.fire(&ticks.t13);
    entry.t12 = {
        let _permit = crate::probe::permit(sem).await;
        check_domain_tls(&domain, target, true, cfg).await
    };
    ticks.fire(&ticks.t12);
    entry.http = {
        let _permit = crate::probe::permit(sem).await;
        check_http_injection(&domain, Some(target), cfg, stub_ips, 80).await
    };
    ticks.fire(&ticks.http);
    // A join error (panic or a shut-down runtime) leaves the cell `Unknown`, the
    // same state a row no probe reached is drawn in.
    if let Some(handle) = quic {
        entry.quic = handle.await.unwrap_or_else(|_| crate::probe::quic::QuicCheck::pending());
    }
    entry
}

/// The row's QUIC step: an Initial beside the row's TCP probes when the column
/// counts the row, the dash when the endpoint serves no HTTP/3.
///
/// The tick belongs to the counted rows alone, which is why the decision lives
/// in one place: the column's total is the applicable rows, and a dashed row
/// that moved the counter is what made a 35-domain run print `QUIC 35/21`.
fn start_quic(
    domain: &str,
    target: IpAddr,
    applicable: bool,
    cfg: &Arc<AppConfig>,
    sem: &Arc<Semaphore>,
    ticks: &Ticks,
    entry: &mut DomainEntry,
) -> Option<tokio::task::JoinHandle<crate::probe::quic::QuicCheck>> {
    if !applicable {
        entry.quic = crate::probe::quic::QuicCheck::unsupported();
        return None;
    }
    Some(tokio::spawn({
        let domain = domain.to_string();
        let cfg = Arc::clone(cfg);
        let sem = Arc::clone(sem);
        let ticks = ticks.clone();
        async move {
            let _permit = crate::probe::permit(&sem).await;
            let check = crate::probe::quic::check_domain_quic(&domain, target, &cfg).await;
            ticks.fire(&ticks.quic);
            check
        }
    }))
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
            if let Ok((ips, _)) = crate::dns::udp::probe_udp_dns(server_addr, domain, timeout_dur, None).await
                && !ips.is_empty()
            {
                answered = true;
                for ip in ips {
                    *ip_counts.entry(ip).or_insert(0) += 1;
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
    /// The rows whose QUIC Initial got an answer (`QuicOk`): a closed or silent
    /// endpoint is a verdict, not a pass, and `is_ok_status` knows only `Ok`.
    pub quic_ok: usize,
    /// The rows the QUIC column applies to at all: `total` minus the hosts whose
    /// endpoint serves no HTTP/3 (`quic_unsupported.txt`). The column's own
    /// denominator — a dash is not a failure and must not sit in a ratio.
    pub quic_total: usize,
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
        quic_ok: entries.iter().filter(|e| e.quic.status == DpiStatus::QuicOk).count(),
        quic_total: entries
            .iter()
            .filter(|e| e.quic.status != DpiStatus::QuicUnsupported)
            .count(),
    }
}

/// One line of a domain row's detail cell.
#[derive(Debug, Clone, PartialEq)]
pub enum DetailLine {
    /// An optional protocol tag (Latin in every language, Rule 4) and the detail
    /// it explains.
    Tagged(Option<&'static str>, Detail),
    /// Every protocol of the row passed: the four stage timings, in the order
    /// the columns are printed — HTTP, TLS 1.2, TLS 1.3, QUIC.
    Timings([f64; 4]),
}

/// Details that describe "nothing came back in time" rather than a verdict: they
/// are dropped from a row's detail cell (the badge already says `TIMEOUT`).
fn is_timeout_detail(detail: &Detail) -> bool {
    matches!(
        detail,
        Detail::TimeoutWord
            | Detail::ReadTimeoutWord
            | Detail::TimeoutStage { .. }
            | Detail::AtKb { .. }
    )
}

/// Builds the (http, t12, t13, quic, details) cells: each failing protocol
/// contributes a detail (timeouts dropped), and two passing TLS columns collapse
/// to the best time.
///
/// The QUIC column joins them on the same terms as the others: a verdict that is
/// not `OK` names its reason, and only a row where every protocol passed
/// collapses to the elapsed time.
pub fn build_domain_row(e: &DomainEntry) -> (DpiStatus, DpiStatus, DpiStatus, DpiStatus, Vec<DetailLine>) {
    let http_ok = col_ok(e.http.status);
    let t12_ok = col_ok_t12(e.t12.status);
    let t13_ok = col_ok_t12(e.t13.status);
    // `Unknown` is "not measured" and `QuicUnsupported` is "not applicable":
    // neither is a failure, so a row whose QUIC probe did not run must not hide
    // the elapsed time of the columns that did.
    let quic_failed = !matches!(
        e.quic.status,
        DpiStatus::Unknown | DpiStatus::QuicOk | DpiStatus::QuicUnsupported
    );

    let mut problems: Vec<(&'static str, Detail)> = Vec::new();
    if !http_ok
        && !e.http.detail.is_none()
        && !is_timeout_detail(&e.http.detail)
        && !is_timeout_status(e.http.status)
    {
        problems.push(("HTTP", e.http.detail.clone()));
    }
    // `DROP` keeps its line: unlike the TLS timeouts, the badge does not say
    // why nothing came back, and "no reply to the Initial" is the whole finding.
    if quic_failed && e.quic.detail != Detail::None {
        problems.push(("QUIC", e.quic.detail.clone()));
    }

    // TLS 1.2 and 1.3 are one stage while they agree — one `TLS:` line says it
    // once — and two stages the moment they disagree: a reader looking at
    // `TLS RST` beside `DROP` has to know which version did what, so each line
    // then carries its own version and a shared detail is not folded across them.
    let mut details: Vec<DetailLine> = Vec::new();
    let tls_agree = e.t12.status == e.t13.status && e.t12.detail == e.t13.detail;
    if tls_agree {
        if !t12_ok && e.t12.detail != Detail::None && !is_timeout_detail(&e.t12.detail) {
            details.push(DetailLine::Tagged(Some("TLS"), e.t12.detail.clone()));
        }
    } else {
        if !t12_ok && e.t12.detail != Detail::None && !is_timeout_detail(&e.t12.detail) {
            details.push(DetailLine::Tagged(Some("TLS12"), e.t12.detail.clone()));
        }
        if !t13_ok && e.t13.detail != Detail::None && !is_timeout_detail(&e.t13.detail) {
            details.push(DetailLine::Tagged(Some("TLS13"), e.t13.detail.clone()));
        }
    }

    if details.is_empty() && problems.len() == 1 {
        details.push(DetailLine::Tagged(None, problems[0].1.clone()));
    } else if !problems.is_empty() {
        // Same detail from several protocols shares one line; a single one keeps
        // its protocol tag so the reader knows which stage failed.
        let mut grouped: Vec<(Detail, Vec<&'static str>)> = Vec::new();
        for (proto, detail) in &problems {
            match grouped.iter_mut().find(|(known, _)| known == detail) {
                Some((_, protos)) => protos.push(proto),
                None => grouped.push((detail.clone(), vec![proto])),
            }
        }
        for (detail, protos) in grouped {
            let tag = if protos.len() == 1 { Some(protos[0]) } else { None };
            details.push(DetailLine::Tagged(tag, detail));
        }
    }

    // Everything passed: the cell is the four stage timings and nothing else,
    // one per column in the order the table prints them. `Unknown` is not a pass
    // — a QUIC probe that never ran leaves the row without a timing line rather
    // than with a zero in it.
    if http_ok && t12_ok && t13_ok && e.quic.status == DpiStatus::QuicOk {
        details.clear();
        details.push(DetailLine::Timings([e.http.elapsed, e.t12.elapsed, e.t13.elapsed, e.quic.elapsed]));
    } else if t12_ok && t13_ok && !quic_failed {
        // One protocol is missing its pass but TLS is not it: the best TLS time
        // stands alone, as it did before the four-timing line.
        let mut times: Vec<f64> = Vec::new();
        if e.t12.elapsed > 0.0 {
            times.push(e.t12.elapsed);
        }
        if e.t13.elapsed > 0.0 {
            times.push(e.t13.elapsed);
        }
        if let Some(min) = times.iter().cloned().reduce(f64::min) {
            details.clear();
            details.push(DetailLine::Tagged(Some("TLS"), Detail::Elapsed(min)));
        }
    }

    (e.http.status, e.t12.status, e.t13.status, e.quic.status, details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_fake_ip_type() {
        assert_eq!(fake_ip_type(&"198.18.5.4".parse().unwrap()), FakeIpType::FakeIp);
        assert_eq!(fake_ip_type(&"100.64.0.5".parse().unwrap()), FakeIpType::Isp);
        assert_eq!(fake_ip_type(&"192.168.1.1".parse().unwrap()), FakeIpType::Local);
        assert_eq!(fake_ip_type(&"8.8.8.8".parse().unwrap()), FakeIpType::Clean);
    }

    /// A row the QUIC column dashes is not one of its units: the column's total
    /// is the rows whose endpoint serves HTTP/3, so a tick fired for a dashed row
    /// is what made a 35-domain run print `QUIC 35/21`. Regression: the dashed
    /// branch ticked, and the counter ran past its total by the number of
    /// `quic_unsupported.txt` rows in the list.
    #[test]
    fn the_dashed_row_does_not_move_the_quic_counter() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ticked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&ticked);
        let phases = PhaseProgress {
            on_phase: Arc::new(move |phase: crate::PhaseId, _total: usize| {
                let counter = Arc::clone(&counter);
                Arc::new(move || {
                    if phase == crate::PhaseId::DomainQuic {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                })
            }),
            on_blocks: Arc::new(|_, _| Arc::new(|_| {})),
        };
        // The whole run is this one row, and the column counts none of it.
        let ticks = Ticks::declare(Some(&phases), 1, 0);
        let mut entry = entry_for(
            "www.canva.com",
            Some("203.0.113.7".parse().unwrap()),
            false,
            &HashSet::new(),
        );
        let cfg = Arc::new(AppConfig::default());
        let sem = Arc::new(Semaphore::new(1));

        let started = start_quic(
            "www.canva.com",
            "203.0.113.7".parse().unwrap(),
            false,
            &cfg,
            &sem,
            &ticks,
            &mut entry,
        );

        assert!(started.is_none(), "a dashed row starts no Initial");
        assert_eq!(entry.quic.status, DpiStatus::QuicUnsupported);
        assert_eq!(
            ticked.load(Ordering::Relaxed),
            0,
            "the dash is not a unit of the QUIC column"
        );
    }

    /// The dash is decided before any probe goes out: the list holds hosts, a row
    /// may hold a URL path (`domains.txt` does for `x.com`), and DNS names are
    /// case-insensitive.
    #[test]
    fn test_quic_applicable_matches_the_host_part() {
        let list = vec!["www.canva.com".to_string(), "www.dw.com".to_string()];
        assert!(!quic_applicable("www.canva.com", &list));
        assert!(!quic_applicable("WWW.Canva.COM", &list));
        assert!(!quic_applicable("www.canva.com/some/path", &list));
        assert!(!quic_applicable("x.com/i/api/1.1/graphql/user_flow.json", &["x.com".to_string()]));
        assert!(quic_applicable("danbooru.donmai.us", &list));
        // A host is matched whole: a lookalike is a different host.
        assert!(quic_applicable("www.canva.com.evil.example", &list));
        assert!(quic_applicable("www.canva.com", &[]));
    }

    /// The dash is neither a pass nor a failure: it stays out of the column's
    /// ratio and out of the details cell, while a row that answered still counts.
    #[test]
    fn test_quic_unsupported_stays_out_of_the_column() {
        let answered = |domain: &str| {
            let mut e = entry_for(
                domain,
                Some("203.0.113.7".parse().unwrap()),
                false,
                &HashSet::new(),
            );
            e.http = HttpCheck::at(DpiStatus::Ok, Detail::HttpStatus(200));
            e.t13 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.31 };
            e.t12 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.32 };
            e
        };

        let mut dashed = answered("www.canva.com");
        dashed.quic = crate::probe::quic::QuicCheck::unsupported();
        let (_, _, _, quic, details) = build_domain_row(&dashed);
        assert_eq!(quic, DpiStatus::QuicUnsupported);
        // No `QUIC` problem line and no four-timing line with a zero in the QUIC
        // slot: the best TLS time stands alone, as it does for a missing pass.
        assert_eq!(details, vec![DetailLine::Tagged(Some("TLS"), Detail::Elapsed(0.31))]);

        let mut ok = answered("danbooru.donmai.us");
        ok.quic.status = DpiStatus::QuicOk;
        ok.quic.detail = Detail::QuicServerHello;
        ok.quic.elapsed = 0.54;

        let stats = domain_stats(&[dashed, ok]);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.quic_ok, 1);
        assert_eq!(stats.quic_total, 1, "the dash is not a row the QUIC column can answer");
    }

    /// The row DNS hands to the pipeline, and the one rule the pipeline reads off
    /// it: `Some(false)` is the only class with a peer of its own to probe.
    ///
    /// The other three are decided before a probe could run, and every protocol
    /// column carries the verdict that decided them — `Unknown` there would
    /// paint the row red and write `"unknown"` into `--json` beside the
    /// `dns_fail` that describes the whole row.
    #[test]
    fn test_entry_for_decides_every_row_dns_can_settle() {
        let none: HashSet<IpAddr> = HashSet::new();

        // No answer at all: the four columns carry the DNS failure.
        let miss = entry_for("gone.example", None, false, &none);
        assert_eq!(miss.dns_fake, None);
        assert_eq!(miss.resolved, None);
        assert_eq!(miss.t13.status, DpiStatus::DnsFail);
        assert_eq!(miss.t12.status, DpiStatus::DnsFail);
        assert_eq!(miss.http.status, DpiStatus::DnsFail);
        assert_eq!(miss.quic.status, DpiStatus::DnsFail);
        assert_eq!(miss.http.detail, Detail::DomainNotFound);
        assert_eq!(miss.quic.detail, miss.http.detail);

        // The IPv4 fallback answered: "no IPv6 here", not "no such host".
        let v6 = entry_for("v6.example", None, true, &none);
        assert_eq!(v6.http.detail, Detail::Ipv6Unsupported);

        // An ISP stub address (CGNAT), and a clean-class address the resolver
        // handed out for many domains — the stub set overrides the class.
        let stub = entry_for("stub.example", Some("100.64.0.5".parse().unwrap()), false, &none);
        assert_eq!(stub.dns_fake, Some(true));
        assert_eq!(stub.t13.status, DpiStatus::DnsFake);
        assert_eq!(stub.quic.status, DpiStatus::DnsFake);
        assert_eq!(stub.quic.detail, stub.http.detail);
        let counted: HashSet<IpAddr> = ["203.0.113.7".parse().unwrap()].into_iter().collect();
        let shared = entry_for("shared.example", Some("203.0.113.7".parse().unwrap()), false, &counted);
        assert_eq!(shared.dns_fake, Some(true));
        assert_eq!(shared.t13.status, DpiStatus::DnsFake);

        // A local or relay address: the reply is our own box, not the site.
        let local = entry_for("local.example", Some("192.168.1.1".parse().unwrap()), false, &none);
        assert_eq!(local.dns_fake, Some(true));
        assert_eq!(local.t13.status, DpiStatus::LocalIp);
        assert_eq!(local.http.detail, Detail::LocalIp { ip: "192.168.1.1".to_string() });

        // A real address: nothing settled, every column waits for its probe.
        let real = entry_for("real.example", Some("203.0.113.7".parse().unwrap()), false, &none);
        assert_eq!(real.dns_fake, Some(false));
        assert_eq!(real.t13.status, DpiStatus::Unknown);
        assert_eq!(real.t12.status, DpiStatus::Unknown);
        assert_eq!(real.http.status, DpiStatus::Unknown);
        assert_eq!(real.quic.status, DpiStatus::Unknown);
    }

    #[test]
    fn test_build_domain_row_http_timeout_tls_ok_shows_time() {
        let mut entry = DomainEntry::pending("browserleaks.com".to_string(), None, None);
        entry.http = HttpCheck::at(DpiStatus::ReadTimeout, Detail::TimeoutWord);
        entry.t12 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.35 };
        entry.t13 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.28 };

        let (http, tls12, tls13, _quic, details) = build_domain_row(&entry);
        assert_eq!(http, DpiStatus::ReadTimeout);
        assert_eq!(http.display_label(), "TIMEOUT");
        assert_eq!(tls12, DpiStatus::Ok);
        assert_eq!(tls13, DpiStatus::Ok);
        // The HTTP leg failed, so the cell is the failing reason — not timings.
        assert_eq!(details, vec![DetailLine::Tagged(Some("TLS"), Detail::Elapsed(0.28))]);
    }

    /// Every protocol passed: the cell is the four stage timings, in the columns'
    /// order (HTTP, TLS 1.2, TLS 1.3, QUIC) and with nothing else in it.
    #[test]
    fn test_build_domain_row_all_ok_shows_the_four_stage_timings() {
        let mut entry = DomainEntry::pending("www.google.com".to_string(), None, None);
        entry.http = HttpCheck { status: DpiStatus::Ok, detail: Detail::HttpStatus(200), elapsed: 0.21 };
        entry.t12 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.32 };
        entry.t13 = TlsCheck { status: DpiStatus::Ok, detail: Detail::None, elapsed: 0.43 };
        entry.quic = crate::probe::quic::QuicCheck {
            status: DpiStatus::QuicOk,
            detail: Detail::QuicServerHello,
            elapsed: 0.54,
        };

        let (_http, _tls12, _tls13, _quic, details) = build_domain_row(&entry);
        assert_eq!(details, vec![DetailLine::Timings([0.21, 0.32, 0.43, 0.54])]);

        // A QUIC endpoint that answered with a close is not a pass: the row keeps
        // its per-protocol lines instead of a timing line.
        entry.quic.status = DpiStatus::QuicClosed;
        let (_http, _tls12, _tls13, _quic, details) = build_domain_row(&entry);
        assert!(
            details.iter().all(|line| matches!(line, DetailLine::Tagged(..))),
            "{details:?}"
        );
    }

    #[test]
    fn test_build_domain_row_http_timeout_tls_rst_omits_http_timeout() {
        let mut entry = DomainEntry::pending("danbooru.donmai.us".to_string(), None, None);
        entry.http = HttpCheck::at(DpiStatus::ReadTimeout, Detail::TimeoutWord);
        entry.t12 = TlsCheck { status: DpiStatus::TlsRst, detail: Detail::RstHello, elapsed: 0.1 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsRst, detail: Detail::RstHello, elapsed: 0.1 };

        let (http, tls12, tls13, _quic, details) = build_domain_row(&entry);
        assert_eq!(http, DpiStatus::ReadTimeout);
        assert_eq!(http.display_label(), "TIMEOUT");
        assert_eq!(tls12, DpiStatus::TlsRst);
        assert_eq!(tls13, DpiStatus::TlsRst);
        // Only TLS RST is shown, NO "HTTP:Timeout" — and the versions agree, so
        // one `TLS:` line carries it.
        assert_eq!(details, vec![DetailLine::Tagged(Some("TLS"), Detail::RstHello)]);
    }

    #[test]
    fn test_build_domain_row_tls_drop_omits_http_timeout() {
        let mut entry = DomainEntry::pending("discord.com".to_string(), None, None);
        entry.http = HttpCheck::at(DpiStatus::ReadTimeout, Detail::TimeoutWord);
        entry.t12 = TlsCheck { status: DpiStatus::TlsDropped, detail: Detail::TlsHandshakeTimeout, elapsed: 5.0 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsDropped, detail: Detail::TlsHandshakeTimeout, elapsed: 5.0 };

        let (http, tls12, tls13, _quic, details) = build_domain_row(&entry);
        assert_eq!(http, DpiStatus::ReadTimeout);
        assert_eq!(http.display_label(), "TIMEOUT");
        assert_eq!(tls12, DpiStatus::TlsDropped);
        assert_eq!(tls13, DpiStatus::TlsDropped);
        // Only TLS Handshake timeout is shown, NO "HTTP:Timeout" — the two
        // versions agree, so the line is tagged once.
        assert_eq!(details, vec![DetailLine::Tagged(Some("TLS"), Detail::TlsHandshakeTimeout)]);
    }

    #[test]
    fn test_tls_versions_that_disagree_keep_their_own_tags() {
        // The other half of the rule: with the versions apart, a shared `TLS:`
        // line would hide which one failed — the columns say `TLS RST` beside
        // `DROP`, and the detail has to say which is which.
        let mut entry = DomainEntry::pending("example.test".to_string(), None, None);
        entry.http = HttpCheck::at(DpiStatus::Ok, Detail::None);
        entry.t12 = TlsCheck { status: DpiStatus::TlsRst, detail: Detail::RstHello, elapsed: 0.1 };
        entry.t13 = TlsCheck { status: DpiStatus::TlsDropped, detail: Detail::TlsHandshakeTimeout, elapsed: 5.0 };

        let (_http, _t12, _t13, _quic, details) = build_domain_row(&entry);
        assert_eq!(
            details,
            vec![
                DetailLine::Tagged(Some("TLS12"), Detail::RstHello),
                DetailLine::Tagged(Some("TLS13"), Detail::TlsHandshakeTimeout),
            ]
        );
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

    /// A local plain-HTTP server answering one request, for the leg's tests.
    ///
    /// Port 80 is not a port a test may bind, which is why the leg takes its
    /// port: this stands in for the far end, censor or site.
    async fn serve_once(
        head: &'static [u8],
        body: Option<(usize, Duration)>,
    ) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let addr = listener.local_addr().expect("its address");
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("one connection");
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.expect("a request");
            let seen = String::from_utf8_lossy(&buf[..n]).to_string();
            sock.write_all(head).await.expect("the response head");
            if let Some((len, stall)) = body {
                sock.write_all(&vec![b'x'; len]).await.expect("the body");
                sock.flush().await.expect("a flush");
                tokio::time::sleep(stall).await;
            }
            seen
        });
        (addr, handle)
    }

    /// The window and the timeouts the leg reads from the config, short enough
    /// that a stalling server does not hold the suite.
    fn test_cfg(timeout: f64) -> AppConfig {
        AppConfig::from_yaml_str(&format!(
            "TIMEOUT: {timeout}\nTCP_BLOCK_MIN_KB: 12\nTCP_BLOCK_MAX_KB: 36\n"
        ))
    }

    #[tokio::test]
    async fn test_the_plain_http_leg_asks_with_get_and_a_complete_body_is_ok() {
        // The failure this pins: the leg sent a HEAD, and a censor answers a
        // HEAD with a synthetic "go to https" bounce instead of its blockpage.
        // The server here records what arrived, so a return to HEAD fails the
        // test rather than quietly changing what the far end answers.
        let (addr, seen) = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", Some((2, Duration::ZERO))).await;
        let cfg = test_cfg(2.0);
        let check = check_http_injection("example.test", Some(addr.ip()), &cfg, &HashSet::new(), addr.port()).await;
        assert_eq!(check.status, DpiStatus::Ok);
        assert_eq!(check.detail.code(), "http_200");
        let request = seen.await.expect("the server saw a request");
        assert!(request.starts_with("GET / HTTP/1.1\r\n"), "{request}");
        assert!(request.to_ascii_lowercase().contains("host: example.test"), "{request}");
    }

    #[tokio::test]
    async fn test_a_transfer_cut_inside_the_window_is_the_16kb_badge() {
        // The failure this pins: a DPI that lets the headers through and then
        // cuts the body — the block test 3 measures on its own stream — was
        // invisible to test 2, which read no body at all and called the answer
        // OK. The server sends 20 KB of the 40 KB it promised, then goes quiet.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n";
        let (addr, _seen) = serve_once(head, Some((20 * 1024, Duration::from_secs(30)))).await;
        let cfg = test_cfg(0.3);
        let check = check_http_injection("example.test", Some(addr.ip()), &cfg, &HashSet::new(), addr.port()).await;
        assert_eq!(check.status, DpiStatus::Tcp16Range);
        assert_eq!(check.status.display_label(), "16KB DROP");
        assert_eq!(check.detail.code(), "read_timeout_word_at_20kb");
    }

    #[tokio::test]
    async fn test_a_foreign_redirect_over_plain_http_is_a_suspect() {
        // What the fix is for: the blockpage a censor serves to a GET is a
        // redirect to a host that is not the site, and that must read as REDIR
        // rather than OK. This is the shape the live lawfilter answers with.
        let response =
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://lawfilter.ertelecom.ru/\r\nContent-Length: 0\r\n\r\n";
        let (addr, _seen) = serve_once(response, None).await;
        let cfg = test_cfg(2.0);
        let check = check_http_injection("example.test", Some(addr.ip()), &cfg, &HashSet::new(), addr.port()).await;
        assert_eq!(check.status, DpiStatus::RedirSuspect);
        assert_eq!(check.detail.code(), "redirect_to_host");
        assert!(!check.status.is_ok_status(), "a foreign redirect is not an OK");
    }
}

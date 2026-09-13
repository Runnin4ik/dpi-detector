//! Test 7: simultaneous-handshake stress per SNI.
//!
//! Reproduces the class of throttling where a handful of handshakes with one
//! fingerprint makes a site unreachable for a while: every attempt is its own
//! TCP connection carrying a full (non-resumed) ClientHello of the selected
//! profile, and the handshakes are released together through a barrier, so they
//! are simultaneous rather than merely concurrent. What the test reports is how
//! many of the N were answered and the classified verdict of each that was not.
//!
//! The probes of test 2 answer "is this site reachable"; this one answers "does
//! the act of asking N times change the answer", which needs the attempts to be
//! indistinguishable except for their simultaneity — hence the barrier, the
//! fresh session per attempt, and no HTTP request on top.
//!
//! Profiles are fired **one at a time over the whole target list**: every host
//! is probed with the first shape to the end before any host sees the second.
//! Hosts inside one shape may overlap (bounded by the caller), but two shapes
//! are never in flight together — a block one shape triggers would otherwise be
//! read into the other shape's column.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{Barrier, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_ssl_error, ConnectionStage, DpiProbeStream, DpiProbeTracker,
    DpiStatus, DET_RST_HELLO, DET_TCP_SYN_TIMEOUT, DET_TLS_HANDSHAKE_TIMEOUT,
};
use crate::config::AppConfig;
use crate::net::fingerprint::TlsFingerprint;
use crate::probe::connector::{DpiTlsConnector, RustlsConnector};
use crate::probe::domains::{resolve_ip, IpFamily};
use crate::net::tcp::{dial_tcp, DialError};

/// Port every attempt dials (the probes' TLS column uses the same one).
pub const BURST_PORT: u16 = 443;
/// Bounds of the simultaneous-request count. Two is the smallest number that
/// can differ from a single probe; the upper bound keeps a stray keystroke from
/// turning the test into a flood.
pub const BURST_MIN_ATTEMPTS: usize = 2;
pub const BURST_MAX_ATTEMPTS: usize = 16;
pub const BURST_DEFAULT_ATTEMPTS: usize = 4;
/// Bounds of the per-attempt timeout, in whole seconds.
pub const BURST_MIN_TIMEOUT_SECS: u64 = 1;
pub const BURST_MAX_TIMEOUT_SECS: u64 = 60;
pub const BURST_DEFAULT_TIMEOUT_SECS: u64 = 8;

/// The TLS version the burst handshakes are pinned to.
///
/// Pinned, not negotiated: the column of the report answers "does this shape get
/// answered over TLS 1.2 / over TLS 1.3", so the config offers exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BurstTlsVersion {
    #[default]
    Tls13,
    Tls12,
}

impl BurstTlsVersion {
    /// Canonical token for the report and the screen (rule 4, never translated).
    pub fn token(self) -> &'static str {
        match self {
            Self::Tls13 => "TLS 1.3",
            Self::Tls12 => "TLS 1.2",
        }
    }

    /// Machine value for the JSON payload and the CLI.
    pub fn code(self) -> &'static str {
        match self {
            Self::Tls13 => "1.3",
            Self::Tls12 => "1.2",
        }
    }

    /// Parses a CLI/config value. `None` for anything unknown.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().trim_start_matches("tls").trim_start_matches(['v', ' ']) {
            "1.3" | "13" => Some(Self::Tls13),
            "1.2" | "12" => Some(Self::Tls12),
            _ => None,
        }
    }
}

/// What the burst offers in ALPN.
///
/// `Http2` is the browsers' own list (`h2, http/1.1`), `Http11` asks for
/// HTTP/1.1 alone. The handshake is all test 7 sends, so this shapes the
/// ClientHello (and JA4's ALPN field) without a request following it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BurstAlpn {
    #[default]
    Http2,
    Http11,
}

impl BurstAlpn {
    /// Canonical token for the report and the screen (rule 4, never translated).
    pub fn token(self) -> &'static str {
        match self {
            Self::Http2 => "h2",
            Self::Http11 => "http/1.1",
        }
    }

    /// The ALPN list this choice offers, `None` meaning "the profile's own".
    pub fn offered(self) -> Option<Vec<Vec<u8>>> {
        match self {
            Self::Http2 => None,
            Self::Http11 => Some(vec![b"http/1.1".to_vec()]),
        }
    }

    /// Parses a CLI/screen value. `None` for anything unknown.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "h2" | "http2" | "http/2" => Some(Self::Http2),
            "http1.1" | "http/1.1" | "h1" | "http" => Some(Self::Http11),
            _ => None,
        }
    }
}

/// What to fire: how many simultaneous handshakes, how long each may take, which
/// TLS version and ALPN they offer, and with which ClientHello shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstSettings {
    pub attempts: usize,
    pub timeout: Duration,
    /// Pinned TLS version of every handshake in the run.
    pub tls: BurstTlsVersion,
    /// ALPN list the run offers.
    pub alpn: BurstAlpn,
    /// One round per profile over the whole target list, in this order: the
    /// shapes are never interleaved, so a block triggered by one of them cannot
    /// be read as the next one's.
    pub profiles: Vec<TlsFingerprint>,
}

/// One host of a run: what goes into the SNI, and the address to dial when it is
/// already known (the suite's earlier phases, or a test stand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstTarget {
    pub domain: String,
    pub address: Option<SocketAddr>,
}

impl BurstTarget {
    /// A host that still has to be resolved when the run starts.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            address: None,
        }
    }
}

impl Default for BurstSettings {
    fn default() -> Self {
        Self {
            attempts: BURST_DEFAULT_ATTEMPTS,
            timeout: Duration::from_secs(BURST_DEFAULT_TIMEOUT_SECS),
            tls: BurstTlsVersion::default(),
            alpn: BurstAlpn::default(),
            profiles: TlsFingerprint::ALL.to_vec(),
        }
    }
}

impl BurstSettings {
    /// Clamps interactive input into the range the test stays meaningful in.
    pub fn clamped(
        attempts: usize,
        timeout_secs: u64,
        tls: BurstTlsVersion,
        alpn: BurstAlpn,
        profiles: Vec<TlsFingerprint>,
    ) -> Self {
        Self {
            attempts: attempts.clamp(BURST_MIN_ATTEMPTS, BURST_MAX_ATTEMPTS),
            timeout: Duration::from_secs(timeout_secs.clamp(BURST_MIN_TIMEOUT_SECS, BURST_MAX_TIMEOUT_SECS)),
            tls,
            alpn,
            profiles: if profiles.is_empty() {
                TlsFingerprint::ALL.to_vec()
            } else {
                profiles
            },
        }
    }
}

/// One handshake attempt: its verdict, why, and how long it took.
#[derive(Debug, Clone)]
pub struct BurstAttempt {
    pub status: DpiStatus,
    pub detail: String,
    pub ms: u64,
}

/// Every attempt of one profile against one host.
#[derive(Debug, Clone)]
pub struct BurstProfileReport {
    pub fingerprint: TlsFingerprint,
    pub attempts: Vec<BurstAttempt>,
}

impl BurstProfileReport {
    /// Attempts the target answered (a completed handshake).
    pub fn answered(&self) -> usize {
        self.attempts.iter().filter(|a| a.status.is_ok_status()).count()
    }

    /// Attempts that got nothing back.
    pub fn lost(&self) -> usize {
        self.attempts.len() - self.answered()
    }

    /// The failure a reader needs: the most frequent one, `None` when nothing
    /// failed. Ties resolve to the first seen, so the row is stable.
    pub fn dominant_failure(&self) -> Option<(DpiStatus, &str, usize)> {
        let mut counts: Vec<(DpiStatus, &str, usize)> = Vec::new();
        for attempt in self.attempts.iter().filter(|a| !a.status.is_ok_status()) {
            match counts
                .iter_mut()
                .find(|(status, detail, _)| *status == attempt.status && *detail == attempt.detail.as_str())
            {
                Some(entry) => entry.2 += 1,
                None => counts.push((attempt.status, attempt.detail.as_str(), 1)),
            }
        }
        let mut best: Option<(DpiStatus, &str, usize)> = None;
        for entry in counts {
            if best.map(|(_, _, count)| entry.2 > count).unwrap_or(true) {
                best = Some(entry);
            }
        }
        best
    }
}

/// One host: its resolved address (when resolution worked) and one report per
/// profile that was fired at it.
#[derive(Debug, Clone)]
pub struct BurstReport {
    pub domain: String,
    pub resolved: Option<IpAddr>,
    pub profiles: Vec<BurstProfileReport>,
}

impl BurstReport {
    pub fn total(&self) -> usize {
        self.profiles.iter().map(|p| p.attempts.len()).sum()
    }

    pub fn answered(&self) -> usize {
        self.profiles.iter().map(|p| p.answered()).sum()
    }

    pub fn lost(&self) -> usize {
        self.total() - self.answered()
    }

    /// A host that lost at least one attempt in any profile.
    pub fn has_losses(&self) -> bool {
        self.profiles.iter().any(|p| p.lost() > 0)
    }

    /// The failure to show in one row per host: the most frequent one across
    /// every profile, `None` when every attempt was answered.
    pub fn dominant_failure(&self) -> Option<(DpiStatus, String, usize)> {
        let mut counts: Vec<(DpiStatus, String, usize)> = Vec::new();
        for profile in &self.profiles {
            for attempt in profile.attempts.iter().filter(|a| !a.status.is_ok_status()) {
                match counts
                    .iter_mut()
                    .find(|(status, detail, _)| *status == attempt.status && *detail == attempt.detail)
                {
                    Some(entry) => entry.2 += 1,
                    None => counts.push((attempt.status, attempt.detail.clone(), 1)),
                }
            }
        }
        let mut best: Option<(DpiStatus, String, usize)> = None;
        for entry in counts {
            if best.as_ref().map(|(_, _, count)| entry.2 > *count).unwrap_or(true) {
                best = Some(entry);
            }
        }
        best
    }
}

/// Follows a burst round by round. The runner draws its live line from this;
/// the no-op implementation below lets tests and library callers ignore it.
pub trait BurstObserver {
    /// A profile round starts: `index` (0-based) of `total` shapes is about to
    /// be fired at `hosts` resolved targets.
    fn round_started(
        &self,
        _fingerprint: TlsFingerprint,
        _index: usize,
        _total: usize,
        _hosts: usize,
    ) {
    }

    /// One host finished its round, answered or not.
    fn host_finished(&self) {}
}

impl BurstObserver for () {}

/// Fires every profile at every target, one profile at a time.
///
/// The outer loop is the profile: all targets are probed with the first shape,
/// then all of them with the second, and so on. Targets inside one shape run
/// concurrently, `concurrency` at a time like the rest of the suite, so a round
/// takes about as long as its slowest host — what must not happen is two shapes
/// being in flight together, because a block one of them triggers would then be
/// read as the other's result.
pub async fn burst_targets(
    cfg: &AppConfig,
    targets: &[BurstTarget],
    settings: &BurstSettings,
    concurrency: usize,
    observer: &dyn BurstObserver,
) -> Vec<BurstReport> {
    let gate = Arc::new(Semaphore::new(concurrency.max(1)));
    let addresses = resolve_targets(cfg, targets, &gate).await;
    let mut reports: Vec<BurstReport> = targets
        .iter()
        .zip(&addresses)
        .map(|(target, address)| BurstReport {
            domain: target.domain.clone(),
            resolved: address.map(|address| address.ip()),
            profiles: Vec::new(),
        })
        .collect();

    // Unresolved hosts are not probed, so they must not count towards the
    // round's total either.
    let hosts = addresses.iter().filter(|address| address.is_some()).count();
    for (index, &fingerprint) in settings.profiles.iter().enumerate() {
        observer.round_started(fingerprint, index, settings.profiles.len(), hosts);
        let mut rounds = JoinSet::new();
        for (index, target) in targets.iter().enumerate() {
            let Some(address) = addresses[index] else {
                continue;
            };
            let domain = target.domain.clone();
            let settings = settings.clone();
            let gate = Arc::clone(&gate);
            rounds.spawn(async move {
                let _permit = gate.acquire().await;
                let report = burst_profile(&address, &domain, fingerprint, &settings).await;
                (index, report)
            });
        }
        while let Some(joined) = rounds.join_next().await {
            observer.host_finished();
            if let Ok((index, report)) = joined {
                reports[index].profiles.push(report);
            }
        }
    }

    reports
}

/// Resolves every target that came without an address, so the profile rounds
/// share one lookup per host instead of repeating it for every shape.
async fn resolve_targets(
    cfg: &AppConfig,
    targets: &[BurstTarget],
    gate: &Arc<Semaphore>,
) -> Vec<Option<SocketAddr>> {
    let mut addresses: Vec<Option<SocketAddr>> = vec![None; targets.len()];
    let mut lookups = JoinSet::new();
    for (index, target) in targets.iter().enumerate() {
        if let Some(address) = target.address {
            addresses[index] = Some(address);
            continue;
        }
        let domain = target.domain.clone();
        let cfg = cfg.clone();
        let gate = Arc::clone(gate);
        lookups.spawn(async move {
            let _permit = gate.acquire().await;
            let address = resolve_ip(&domain, IpFamily::from_config(&cfg.ip_version))
                .await
                .map(|ip| SocketAddr::new(ip, BURST_PORT));
            (index, address)
        });
    }
    while let Some(joined) = lookups.join_next().await {
        if let Ok((index, address)) = joined {
            addresses[index] = address;
        }
    }
    addresses
}

/// One profile's round against one address: connect every attempt, then release
/// the handshakes together.
pub async fn burst_profile(
    addr: &SocketAddr,
    domain: &str,
    fingerprint: TlsFingerprint,
    settings: &BurstSettings,
) -> BurstProfileReport {
    let attempts = settings.attempts;
    let mut slots: Vec<Option<BurstAttempt>> = (0..attempts).map(|_| None).collect();

    // Phase 1 — one TCP connection per attempt, dialled in parallel.
    let mut connected: Vec<(usize, DpiProbeStream<TcpStream>, DpiProbeTracker)> = Vec::with_capacity(attempts);
    let mut dials = JoinSet::new();
    for index in 0..attempts {
        let addr = *addr;
        let limit = settings.timeout;
        dials.spawn(async move { (index, connect_attempt(addr, limit).await) });
    }
    while let Some(joined) = dials.join_next().await {
        if let Ok((index, Ok((stream, tracker)))) = joined {
            connected.push((index, stream, tracker));
        } else if let Ok((index, Err(attempt))) = joined {
            slots[index] = Some(attempt);
        }
    }

    // Phase 2 — the handshakes start together. Only the connections that came up
    // join the barrier, so one refused dial cannot deadlock the rest.
    if !connected.is_empty() {
        let connector = Arc::new(RustlsConnector::new_insecure_versioned_with(
            fingerprint,
            settings.tls == BurstTlsVersion::Tls12,
            settings.alpn.offered(),
        ));
        let gate = Arc::new(Barrier::new(connected.len()));
        let mut handshakes = JoinSet::new();
        for (index, stream, tracker) in connected {
            let connector = Arc::clone(&connector);
            let gate = Arc::clone(&gate);
            let name = domain.to_string();
            let limit = settings.timeout;
            handshakes
                .spawn(async move { (index, handshake_attempt(connector, name, stream, tracker, gate, limit).await) });
        }
        while let Some(joined) = handshakes.join_next().await {
            if let Ok((index, attempt)) = joined {
                slots[index] = Some(attempt);
            }
        }
    }

    let attempts = slots
        .into_iter()
        .map(|slot| {
            slot.unwrap_or(BurstAttempt {
                status: DpiStatus::Err,
                detail: "attempt aborted".to_string(),
                ms: 0,
            })
        })
        .collect();
    BurstProfileReport { fingerprint, attempts }
}

/// Dials one attempt, classifying a failed connect exactly like the probes do.
async fn connect_attempt(
    addr: SocketAddr,
    limit: Duration,
) -> Result<(DpiProbeStream<TcpStream>, DpiProbeTracker), BurstAttempt> {
    let started = Instant::now();
    let ms = |started: Instant| started.elapsed().as_millis() as u64;
    match dial_tcp(&addr, limit).await {
        Ok(stream) => {
            let tracker = DpiProbeTracker::new();
            Ok((DpiProbeStream::new(stream, tracker.clone()), tracker))
        }
        Err(DialError::Io(e)) => {
            let msg = e.to_string();
            let (status, detail) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tcp_connect");
            Err(BurstAttempt { status, detail, ms: ms(started) })
        }
        Err(DialError::Timeout) => Err(BurstAttempt {
            status: DpiStatus::SynDropped,
            detail: DET_TCP_SYN_TIMEOUT.to_string(),
            ms: ms(started),
        }),
    }
}

/// Waits for the gate, then runs the handshake; the clock starts at the gate so
/// the reported duration is the handshake, not the queueing in front of it.
async fn handshake_attempt(
    connector: Arc<RustlsConnector>,
    domain: String,
    stream: DpiProbeStream<TcpStream>,
    tracker: DpiProbeTracker,
    gate: Arc<Barrier>,
    limit: Duration,
) -> BurstAttempt {
    gate.wait().await;
    let started = Instant::now();
    let elapsed = |started: Instant| started.elapsed().as_millis() as u64;
    let server_name = match ServerName::try_from(domain) {
        Ok(name) => name,
        Err(e) => {
            return BurstAttempt {
                status: DpiStatus::Err,
                detail: format!("bad SNI: {}", e),
                ms: elapsed(started),
            }
        }
    };
    match timeout(limit, connector.connect(server_name, stream)).await {
        Ok(Ok(_)) => BurstAttempt {
            status: DpiStatus::Ok,
            detail: String::new(),
            ms: elapsed(started),
        },
        Ok(Err(e)) => {
            // Same order as `check_domain_tls`: the stream wrapper sees a reset
            // or a premature EOF that the error alone would not name.
            let st = tracker.state.lock();
            if let Some(status) = st.last_status {
                let detail = st.last_error_msg.clone().unwrap_or_else(|| DET_RST_HELLO.to_string());
                return BurstAttempt { status, detail, ms: elapsed(started) };
            }
            drop(st);
            let msg = e.to_string();
            let (status, detail) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tls_handshake");
            if status != DpiStatus::Unknown {
                return BurstAttempt { status, detail, ms: elapsed(started) };
            }
            let (status, detail) = classify_ssl_error(&msg, 0, ConnectionStage::TlsClientHelloSent);
            BurstAttempt { status, detail, ms: elapsed(started) }
        }
        Err(_) => BurstAttempt {
            status: DpiStatus::TlsDropped,
            detail: DET_TLS_HANDSHAKE_TIMEOUT.to_string(),
            ms: elapsed(started),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use parking_lot::Mutex;
    use tokio::net::TcpListener;

    use super::*;

    fn settings(attempts: usize, timeout_ms: u64, profiles: Vec<TlsFingerprint>) -> BurstSettings {
        BurstSettings {
            attempts,
            timeout: Duration::from_millis(timeout_ms),
            profiles,
            ..BurstSettings::default()
        }
    }

    /// A listener that accepts and immediately closes: every attempt must come
    /// back classified (one report per attempt, no hangs) with nothing answered.
    #[tokio::test]
    async fn every_attempt_is_reported_when_the_peer_resets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move {
            for _ in 0..3 {
                if let Ok((stream, _)) = listener.accept().await {
                    drop(stream);
                }
            }
        });

        let report = burst_profile(&addr, "example.com", TlsFingerprint::Rustls, &settings(3, 3000, vec![])).await;
        let _ = accept.await;

        assert_eq!(report.attempts.len(), 3);
        assert_eq!(report.answered(), 0);
        assert_eq!(report.lost(), 3);
        for attempt in &report.attempts {
            assert_ne!(attempt.status, DpiStatus::Unknown, "{:?}", attempt);
            assert!(!attempt.detail.is_empty());
        }
    }

    /// A peer that accepts and then stays silent must be reported as a handshake
    /// timeout — not as a hang, and not as a connect failure.
    #[tokio::test]
    async fn a_silent_peer_times_out_as_tls_dropped() {
        // Bound but never accepted: the dial completes through the backlog and
        // the ClientHello goes unanswered.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let started = Instant::now();
        let report = burst_profile(&addr, "example.com", TlsFingerprint::Rustls, &settings(2, 400, vec![])).await;
        let elapsed = started.elapsed();
        drop(listener);

        assert_eq!(report.attempts.len(), 2);
        for attempt in &report.attempts {
            assert_eq!(attempt.status, DpiStatus::TlsDropped, "{:?}", attempt);
            assert_eq!(attempt.detail, DET_TLS_HANDSHAKE_TIMEOUT);
        }
        // Both attempts spend their 400 ms at the same time: serialized, the
        // round would need 800 ms, and that difference is the whole point.
        assert!(elapsed < Duration::from_millis(700), "round took {elapsed:?}");
    }

    /// Nothing answers the dial. Windows may either refuse the loopback SYN or
    /// drop it silently, so the assertion is on the invariant: every attempt
    /// comes back as a connect verdict with a reason, nothing is counted as an
    /// answer, and the round stays inside its budget.
    #[tokio::test]
    async fn a_dead_dial_is_reported_as_a_connect_verdict() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);

        let started = Instant::now();
        let report = burst_profile(&addr, "example.com", TlsFingerprint::Rustls, &settings(2, 2000, vec![])).await;
        let elapsed = started.elapsed();

        assert_eq!(report.attempts.len(), 2);
        assert_eq!(report.answered(), 0);
        let first = report.attempts[0].status;
        for attempt in &report.attempts {
            assert!(
                matches!(attempt.status, DpiStatus::Refused | DpiStatus::TcpRst | DpiStatus::SynDropped),
                "{:?}",
                attempt
            );
            assert!(!attempt.detail.is_empty());
            // One local condition, one verdict: the attempts do not disagree.
            assert_eq!(attempt.status, first, "{:?}", report.attempts);
        }
        assert!(elapsed < Duration::from_secs(3), "round took {elapsed:?}");
    }

    /// The JA3 of the hello a profile writes through the connector test 7 uses.
    ///
    /// Extension order is not part of the comparison: rustls shuffles it on
    /// every handshake (the Firefox/Chrome/Safari shapes pin their own order
    /// through the vendored profile), so only the cipher list is stable enough to
    /// name a shape arriving at a stand.
    fn hello_ciphers(fingerprint: TlsFingerprint) -> String {
        let config = crate::net::tls::create_insecure_dpi_tls_config_tls13_with(fingerprint);
        let name = ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        let ja3 = crate::net::ja3::client_hello_ja3(&buf);
        ja3.split(',').nth(1).expect("cipher list").to_string()
    }

    /// What the stands see: which shapes are open right now (keyed by stand and
    /// connection, since every stand numbers its own), whether two of them were
    /// ever open together, and any hello that was neither of the two (which would
    /// mean the stand is not looking at what the test thinks it is).
    #[derive(Clone, Default)]
    struct Witness {
        open: OpenRuns,
        overlapped: Arc<AtomicBool>,
        unexpected: Arc<Mutex<Vec<String>>>,
    }

    /// Open runs as (stand, connection) pairs with the shape each one proved.
    type OpenRuns = Arc<Mutex<Vec<((usize, usize), TlsFingerprint)>>>;

    /// Accepts `count` ClientHellos, names each shape by its cipher list and
    /// holds it open for `hold`. Two of these with different holds are how the
    /// ordering test makes one target's round outlast the other's.
    async fn stand(
        tag: usize,
        listener: TcpListener,
        count: usize,
        hold: Duration,
        ciphers: (String, String),
        witness: Witness,
    ) {
        use tokio::io::AsyncReadExt;

        for connection in 0..count {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut record = vec![0u8; 5];
            if stream.read_exact(&mut record).await.is_err() {
                continue;
            }
            let length = u16::from_be_bytes([record[3], record[4]]) as usize;
            record.resize(5 + length, 0);
            if stream.read_exact(&mut record[5..]).await.is_err() {
                continue;
            }
            let ja3 = crate::net::ja3::client_hello_ja3(&record);
            let sent = ja3.split(',').nth(1).unwrap_or_default();
            let profile = if sent == ciphers.0 {
                TlsFingerprint::Rustls
            } else if sent == ciphers.1 {
                TlsFingerprint::Chrome
            } else {
                witness.unexpected.lock().push(ja3);
                continue;
            };
            {
                let mut open = witness.open.lock();
                if open.iter().any(|(_, other)| *other != profile) {
                    witness.overlapped.store(true, Ordering::SeqCst);
                }
                open.push(((tag, connection), profile));
            }
            tokio::time::sleep(hold).await;
            witness.open.lock().retain(|((open_tag, open_connection), _)| {
                (*open_tag, *open_connection) != (tag, connection)
            });
        }
    }

    /// Two shapes must never be in flight at the same time, however many targets
    /// a run has: every target is probed with the first shape before any target
    /// sees the second.
    ///
    /// The stands are what makes the property observable: the first target holds
    /// every connection it accepts, the second closes at once, so a run that let
    /// hosts drift apart would put the fast target on the second shape while the
    /// slow one is still on the first — which is exactly what `overlapped`
    /// records (and what the previous host-major loop did).
    #[tokio::test]
    async fn profiles_are_fired_one_after_another_across_targets() {
        let slow_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let fast_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let slow_addr = slow_listener.local_addr().expect("addr");
        let fast_addr = fast_listener.local_addr().expect("addr");

        let ciphers = (hello_ciphers(TlsFingerprint::Rustls), hello_ciphers(TlsFingerprint::Chrome));
        let witness = Witness::default();
        let slow = tokio::spawn(stand(
            0,
            slow_listener,
            4,
            Duration::from_millis(300),
            ciphers.clone(),
            witness.clone(),
        ));
        let fast = tokio::spawn(stand(1, fast_listener, 4, Duration::from_millis(5), ciphers, witness.clone()));

        let targets = vec![
            BurstTarget { domain: "slow.example".to_string(), address: Some(slow_addr) },
            BurstTarget { domain: "fast.example".to_string(), address: Some(fast_addr) },
        ];
        let plan = settings(2, 4000, vec![TlsFingerprint::Rustls, TlsFingerprint::Chrome]);
        // The live line the runner draws comes from the observer: a round must
        // be announced once, in the order the profiles are fired, or the line
        // would name a shape that is not on the wire.
        #[derive(Default)]
        struct Rounds {
            started: std::sync::Mutex<Vec<(TlsFingerprint, usize, usize, usize)>>,
            finished: std::sync::atomic::AtomicUsize,
        }
        impl BurstObserver for Rounds {
            fn round_started(&self, fp: TlsFingerprint, index: usize, total: usize, hosts: usize) {
                self.started.lock().expect("lock").push((fp, index, total, hosts));
            }
            fn host_finished(&self) {
                self.finished.fetch_add(1, Ordering::SeqCst);
            }
        }
        let rounds = Rounds::default();
        let reports = burst_targets(&AppConfig::default(), &targets, &plan, 4, &rounds).await;

        slow.await.expect("slow stand");
        fast.await.expect("fast stand");

        assert!(
            witness.unexpected.lock().is_empty(),
            "unexpected ClientHellos: {:?}",
            witness.unexpected.lock()
        );
        assert!(!witness.overlapped.load(Ordering::SeqCst), "two shapes were in flight at the same time");
        assert_eq!(
            *rounds.started.lock().expect("lock"),
            vec![
                (TlsFingerprint::Rustls, 0, 2, 2),
                (TlsFingerprint::Chrome, 1, 2, 2),
            ]
        );
        assert_eq!(rounds.finished.load(Ordering::SeqCst), 4, "one tick per host per round");
        assert_eq!(reports.len(), 2);
        for report in &reports {
            let shapes: Vec<TlsFingerprint> = report.profiles.iter().map(|p| p.fingerprint).collect();
            assert_eq!(shapes, vec![TlsFingerprint::Rustls, TlsFingerprint::Chrome], "{report:?}");
            for profile in &report.profiles {
                assert_eq!(profile.attempts.len(), 2);
            }
        }
    }

    #[test]
    fn settings_are_clamped_into_the_meaningful_range() {
        let axes = (BurstTlsVersion::Tls13, BurstAlpn::Http2);
        assert_eq!(BurstSettings::clamped(0, 0, axes.0, axes.1, vec![]).attempts, BURST_MIN_ATTEMPTS);
        assert_eq!(BurstSettings::clamped(99, 999, axes.0, axes.1, vec![]).attempts, BURST_MAX_ATTEMPTS);
        assert_eq!(
            BurstSettings::clamped(4, 0, axes.0, axes.1, vec![]).timeout,
            Duration::from_secs(BURST_MIN_TIMEOUT_SECS)
        );
        assert_eq!(
            BurstSettings::clamped(4, 999, axes.0, axes.1, vec![]).timeout,
            Duration::from_secs(BURST_MAX_TIMEOUT_SECS)
        );
        // An empty profile set means "no preference", not "run nothing".
        assert_eq!(
            BurstSettings::clamped(4, 8, axes.0, axes.1, vec![]).profiles,
            TlsFingerprint::ALL.to_vec()
        );
        // The axes survive clamping untouched.
        let kept = BurstSettings::clamped(4, 8, BurstTlsVersion::Tls12, BurstAlpn::Http11, vec![]);
        assert_eq!((kept.tls, kept.alpn), (BurstTlsVersion::Tls12, BurstAlpn::Http11));
        assert_eq!(BurstSettings::default().attempts, BURST_DEFAULT_ATTEMPTS);
        // Defaults keep what the probes send today: TLS 1.3 and the profile's own
        // `h2, http/1.1`.
        let default = BurstSettings::default();
        assert_eq!((default.tls, default.alpn), (BurstTlsVersion::Tls13, BurstAlpn::Http2));
        assert!(default.alpn.offered().is_none());
    }

    /// The two axes are what the screen and the CLI offer, so both spellings of
    /// each value must parse — and nothing else may.
    #[test]
    fn burst_axes_parse_their_values() {
        for value in ["1.3", "13", "tls1.3", "TLS 1.3"] {
            assert_eq!(BurstTlsVersion::parse(value), Some(BurstTlsVersion::Tls13), "{value}");
        }
        for value in ["1.2", "12", "tls1.2", "TLS 1.2"] {
            assert_eq!(BurstTlsVersion::parse(value), Some(BurstTlsVersion::Tls12), "{value}");
        }
        assert_eq!(BurstTlsVersion::parse("1.1"), None);
        assert_eq!(BurstTlsVersion::parse(""), None);

        for value in ["h2", "http2", "HTTP/2"] {
            assert_eq!(BurstAlpn::parse(value), Some(BurstAlpn::Http2), "{value}");
        }
        for value in ["http/1.1", "http1.1", "h1", "http"] {
            assert_eq!(BurstAlpn::parse(value), Some(BurstAlpn::Http11), "{value}");
        }
        assert_eq!(BurstAlpn::parse("h3"), None);
        assert_eq!(BurstAlpn::parse(""), None);

        // The HTTP/1.1 choice is the one that has to replace the profile's list.
        assert_eq!(BurstAlpn::Http11.offered(), Some(vec![b"http/1.1".to_vec()]));
        assert_eq!(BurstAlpn::Http2.token(), "h2");
        assert_eq!(BurstAlpn::Http11.token(), "http/1.1");
        assert_eq!(BurstTlsVersion::Tls13.code(), "1.3");
        assert_eq!(BurstTlsVersion::Tls12.token(), "TLS 1.2");
    }

    #[test]
    fn dominant_failure_picks_the_frequent_one() {
        let report = BurstProfileReport {
            fingerprint: TlsFingerprint::Chrome,
            attempts: vec![
                BurstAttempt { status: DpiStatus::Ok, detail: String::new(), ms: 10 },
                BurstAttempt { status: DpiStatus::TlsRst, detail: "TCP RST on ClientHello".into(), ms: 11 },
                BurstAttempt { status: DpiStatus::TlsRst, detail: "TCP RST on ClientHello".into(), ms: 12 },
                BurstAttempt { status: DpiStatus::TlsDropped, detail: "TLS Handshake timeout".into(), ms: 900 },
            ],
        };
        assert_eq!(report.answered(), 1);
        assert_eq!(report.lost(), 3);
        let (status, detail, count) = report.dominant_failure().expect("failures");
        assert_eq!((status, detail, count), (DpiStatus::TlsRst, "TCP RST on ClientHello", 2));

        let clean = BurstProfileReport {
            fingerprint: TlsFingerprint::Custom,
            attempts: vec![BurstAttempt { status: DpiStatus::Ok, detail: String::new(), ms: 10 }],
        };
        assert!(clean.dominant_failure().is_none());
        let report = BurstReport {
            domain: "example.com".into(),
            resolved: None,
            profiles: vec![clean],
        };
        assert!(!report.has_losses());
        assert!(report.dominant_failure().is_none());
    }

    /// Across profiles the row shows the failure that happened most often.
    #[test]
    fn report_dominant_failure_spans_profiles() {
        let profile = |fingerprint, statuses: Vec<DpiStatus>| BurstProfileReport {
            fingerprint,
            attempts: statuses
                .into_iter()
                .map(|status| BurstAttempt {
                    status,
                    detail: status.display_label().to_string(),
                    ms: 1,
                })
                .collect(),
        };
        let report = BurstReport {
            domain: "example.com".into(),
            resolved: None,
            profiles: vec![
                profile(TlsFingerprint::Rustls, vec![DpiStatus::TlsDropped, DpiStatus::TlsDropped]),
                profile(
                    TlsFingerprint::Chrome,
                    vec![DpiStatus::TlsRst, DpiStatus::TlsDropped, DpiStatus::Ok],
                ),
            ],
        };
        assert!(report.has_losses());
        assert_eq!(report.answered(), 1);
        assert_eq!(report.total(), 5);
        let (status, detail, count) = report.dominant_failure().expect("failures");
        assert_eq!((status, detail.as_str(), count), (DpiStatus::TlsDropped, "TLS DROP", 3));
    }
}

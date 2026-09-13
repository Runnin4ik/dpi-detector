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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Barrier;
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

/// What to fire: how many simultaneous handshakes, how long each may take, and
/// with which ClientHello shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstSettings {
    pub attempts: usize,
    pub timeout: Duration,
    /// One round per profile, run one after another (never interleaved, so a
    /// block triggered by one profile cannot be read as the next one's).
    pub profiles: Vec<TlsFingerprint>,
}

impl Default for BurstSettings {
    fn default() -> Self {
        Self {
            attempts: BURST_DEFAULT_ATTEMPTS,
            timeout: Duration::from_secs(BURST_DEFAULT_TIMEOUT_SECS),
            profiles: TlsFingerprint::ALL.to_vec(),
        }
    }
}

impl BurstSettings {
    /// Clamps interactive input into the range the test stays meaningful in.
    pub fn clamped(attempts: usize, timeout_secs: u64, profiles: Vec<TlsFingerprint>) -> Self {
        Self {
            attempts: attempts.clamp(BURST_MIN_ATTEMPTS, BURST_MAX_ATTEMPTS),
            timeout: Duration::from_secs(timeout_secs.clamp(BURST_MIN_TIMEOUT_SECS, BURST_MAX_TIMEOUT_SECS)),
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

/// Fires every profile at one host, in the order given.
///
/// `target` lets the caller reuse the address test 2 already resolved (and the
/// stub-IP decision that came with it); without it the host is resolved here.
pub async fn burst_domain(
    cfg: &AppConfig,
    domain: &str,
    target: Option<IpAddr>,
    settings: &BurstSettings,
) -> BurstReport {
    let resolved = match target {
        Some(ip) => Some(ip),
        None => resolve_ip(domain, IpFamily::from_config(&cfg.ip_version)).await,
    };
    let Some(ip) = resolved else {
        return BurstReport {
            domain: domain.to_string(),
            resolved: None,
            profiles: Vec::new(),
        };
    };
    let addr = SocketAddr::new(ip, BURST_PORT);
    let mut profiles = Vec::with_capacity(settings.profiles.len());
    for &fingerprint in &settings.profiles {
        profiles.push(burst_profile(&addr, domain, fingerprint, settings).await);
    }
    BurstReport {
        domain: domain.to_string(),
        resolved: Some(ip),
        profiles,
    }
}

/// One profile's round against one address: connect every attempt, then release
/// the handshakes together.
async fn burst_profile(
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
        let connector = Arc::new(RustlsConnector::new_insecure_tls13_with(fingerprint));
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
    match timeout(limit, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            let tracker = DpiProbeTracker::new();
            Ok((DpiProbeStream::new(stream, tracker.clone()), tracker))
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            let (status, detail) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tcp_connect");
            Err(BurstAttempt { status, detail, ms: ms(started) })
        }
        Err(_) => Err(BurstAttempt {
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
    use super::*;
    use tokio::net::TcpListener;

    fn settings(attempts: usize, timeout_ms: u64, profiles: Vec<TlsFingerprint>) -> BurstSettings {
        BurstSettings {
            attempts,
            timeout: Duration::from_millis(timeout_ms),
            profiles,
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

    #[test]
    fn settings_are_clamped_into_the_meaningful_range() {
        assert_eq!(BurstSettings::clamped(0, 0, vec![]).attempts, BURST_MIN_ATTEMPTS);
        assert_eq!(BurstSettings::clamped(99, 999, vec![]).attempts, BURST_MAX_ATTEMPTS);
        assert_eq!(BurstSettings::clamped(4, 0, vec![]).timeout, Duration::from_secs(BURST_MIN_TIMEOUT_SECS));
        assert_eq!(BurstSettings::clamped(4, 999, vec![]).timeout, Duration::from_secs(BURST_MAX_TIMEOUT_SECS));
        // An empty profile set means "no preference", not "run nothing".
        assert_eq!(BurstSettings::clamped(4, 8, vec![]).profiles, TlsFingerprint::ALL.to_vec());
        assert_eq!(BurstSettings::default().attempts, BURST_DEFAULT_ATTEMPTS);
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

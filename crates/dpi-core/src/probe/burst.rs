//! Test 6: repeated-attempt stress per SNI.
//!
//! Reproduces the class of throttling where a handful of connections with one
//! fingerprint makes a site unreachable for a while: every attempt is its own
//! TCP connection carrying a full (non-resumed) ClientHello of the selected
//! profile, and then one `GET /` over whatever protocol the handshake
//! negotiated. What the test reports is how many of the N came back whole and
//! the classified verdict of each that did not.
//!
//! The attempts of a round are **launched 20 ms apart and overlap**: the trigger
//! this test reproduces watches a rate (several connection attempts inside a
//! window of a few hundred milliseconds), so attempts spread over the length of a
//! slow link never reach it — but a round fired at a single instant is answered
//! before the block can land, letting all of them through and hiding the block
//! until the next run. The small delay keeps the round inside any plausible
//! window (five attempts span 80 ms) while leaving the block room to land between
//! two starts; the attempt it lands on is the verdict the report shows.
//!
//! The handshake alone is not the whole story: a shape can be answered and then
//! cut, redirected or blocked the moment the request goes out, which is the
//! behaviour the test exists to catch. The request is identical for every shape
//! (the profile only changes the client's identity), so the attempts stay
//! comparable.
//!
//! The probes of test 2 answer "is this site reachable"; this one answers "does
//! the act of asking N times change the answer", which needs a fresh session per
//! attempt and the same request for every shape — the shape and the count of
//! previous attempts must be the only differences between two attempts.
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
use rustls::ProtocolVersion;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, classify_ssl_error, ConnectionStage, DpiProbeStream, DpiProbeTracker,
    Detail, DpiStatus,
};
use crate::config::AppConfig;
use crate::net::fingerprint::TlsFingerprint;
use crate::probe::connector::{DpiTlsConnector, RustlsConnector};
use crate::probe::domains::{resolve_ip, IpFamily};
use crate::probe::http::check_http;
use parking_lot::Mutex;
use crate::net::tcp::{dial_tcp, DialError};
use crate::net::tls::TlsProfile;

/// Port every attempt dials (the probes' TLS column uses the same one).
pub const BURST_PORT: u16 = 443;
/// Bounds of the per-round attempt count — the connections one shape fires at
/// one host, launched [`BURST_LAUNCH_GAP`] apart. Two is the smallest number that can differ from
/// a single probe; the upper bound keeps a stray keystroke from turning the test
/// into a flood. The default sits one above the commonest throttle (a link that
/// cuts the fourth connection): at four, the run ends exactly where the answer
/// starts.
pub const BURST_MIN_ATTEMPTS: usize = 2;
pub const BURST_MAX_ATTEMPTS: usize = 16;
pub const BURST_DEFAULT_ATTEMPTS: usize = 5;
/// Delay between the starts of two consecutive attempts of one round.
///
/// The attempts of a round overlap. The trigger this test reproduces is a *rate*
/// — several connection attempts inside a window of a few hundred milliseconds —
/// and a round that waits for each attempt to finish before starting the next
/// never reaches that rate on anything but a fast link. Firing them all at once
/// answers the wrong question the other way round: every attempt is already
/// established by the time the block lands, so the whole round passes and the
/// block only shows up in the *next* one.
///
/// 20 ms keeps a five-attempt round inside any window a trigger would plausibly
/// use (80 ms end to end), while still leaving the block room to land *between*
/// two starts — which is what makes the refusal visible in the run that caused
/// it, at the index of the attempt it landed on.
pub const BURST_LAUNCH_GAP: Duration = Duration::from_millis(20);
/// Bounds of the per-attempt timeout, in whole seconds.
pub const BURST_MIN_TIMEOUT_SECS: u64 = 1;
pub const BURST_MAX_TIMEOUT_SECS: u64 = 60;
pub const BURST_DEFAULT_TIMEOUT_SECS: u64 = 8;

/// Which TLS the run asks for.
///
/// `Tls13And12` is the browser's own offer: Chrome, Safari and Firefox all offer
/// 1.2 and 1.3 together, so this axis sends the profile's real hello — the same
/// one tests 3 and 4 send — and then requires the answer to be 1.3
/// ([`answered`]). It is the default because it is the shape a browser puts on
/// the wire.
///
/// `Tls13Only` and `Tls12Only` are deliberately clients that offer one version
/// alone: a hello offering both is never answered with 1.2, so nothing else can
/// ask whether a 1.2 handshake survives on this network — and a middlebox that
/// treats a one-version hello differently from a browser's is exactly what the
/// 1.3-only axis looks for. Same trade as test 2's two columns, whose builders
/// these are. See [`offer_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BurstTlsVersion {
    #[default]
    Tls13And12,
    Tls13Only,
    Tls12Only,
}

impl BurstTlsVersion {
    /// Canonical token for the report and the screen (rule 4, never translated).
    pub fn token(self) -> &'static str {
        match self {
            Self::Tls13And12 => "TLS 1.3+1.2",
            Self::Tls13Only => "TLS 1.3",
            Self::Tls12Only => "TLS 1.2",
        }
    }

    /// Machine value for the JSON payload and the CLI.
    pub fn code(self) -> &'static str {
        match self {
            Self::Tls13And12 => "1.3+1.2",
            Self::Tls13Only => "1.3",
            Self::Tls12Only => "1.2",
        }
    }

    /// Parses a CLI/config value. `None` for anything unknown.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        let value = value.trim_start_matches("tls").trim_start_matches(['v', ' ']);
        match value {
            "1.3+1.2" | "1.2+1.3" | "13+12" | "both" | "any" => Some(Self::Tls13And12),
            "1.3" | "13" => Some(Self::Tls13Only),
            "1.2" | "12" => Some(Self::Tls12Only),
            _ => None,
        }
    }
}

/// What the burst offers in ALPN.
///
/// `Http2` is the browsers' own list (`h2, http/1.1`), `Http11` asks for
/// HTTP/1.1 alone. It shapes the ClientHello (and JA4's ALPN field), and it
/// decides which client speaks the request that follows the handshake.
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

/// What to fire: how many overlapping handshakes, how long each may take, which
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

/// What every attempt of one round shares: the shape being fired, the axis it
/// asks for, and the config the request phase reads its timeouts from.
#[derive(Clone)]
struct Round {
    fingerprint: TlsFingerprint,
    axis: BurstTlsVersion,
    cfg: AppConfig,
}

/// One attempt — handshake then `GET /`: its verdict, why, and how long it took.
#[derive(Debug, Clone)]
pub struct BurstAttempt {
    pub status: DpiStatus,
    pub detail: Detail,
    pub ms: u64,
}

/// Every attempt of one profile against one host.
#[derive(Debug, Clone)]
pub struct BurstProfileReport {
    pub fingerprint: TlsFingerprint,
    pub attempts: Vec<BurstAttempt>,
}

impl BurstProfileReport {
    /// Attempts that came back whole: the handshake was answered *and* the
    /// request returned something the probes call OK. A row that handshook and
    /// then got nothing back is a lost attempt, not an answered one.
    pub fn answered(&self) -> usize {
        self.attempts.iter().filter(|a| a.status.is_ok_status()).count()
    }

    /// Attempts that got nothing back.
    pub fn lost(&self) -> usize {
        self.attempts.len() - self.answered()
    }

    /// Every failure of this profile, grouped by the status it produced: most
    /// frequent first, ties in the order the statuses were first seen, empty
    /// when nothing failed. Grouping by status is what a row displays — the
    /// detail behind it stays in the JSON.
    pub fn failure_counts(&self) -> Vec<(DpiStatus, usize)> {
        group_failures(self.attempts.iter().map(|a| a.status))
    }
}

/// The failures among `statuses`, grouped by status and ordered the way every
/// detail row reads them: most frequent first. The sort is stable, so two
/// statuses with the same count keep the order they were first seen in and the
/// same input always renders the same row.
fn group_failures(statuses: impl Iterator<Item = DpiStatus>) -> Vec<(DpiStatus, usize)> {
    let mut counts: Vec<(DpiStatus, usize)> = Vec::new();
    for status in statuses.filter(|s| !s.is_ok_status()) {
        match counts.iter_mut().find(|(seen, _)| *seen == status) {
            Some(entry) => entry.1 += 1,
            None => counts.push((status, 1)),
        }
    }
    counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    counts
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

    /// Every failure of this host across every profile, grouped by status and
    /// ordered like a detail row: most frequent first, ties in the order the
    /// statuses were first seen, empty when every attempt was answered.
    pub fn failure_counts(&self) -> Vec<(DpiStatus, usize)> {
        group_failures(self.profiles.iter().flat_map(|p| p.attempts.iter()).map(|a| a.status))
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

    /// One host's round landed, with every attempt it produced.
    ///
    /// The live line counts hosts and ignores this; a trace prints the attempts
    /// the moment they exist, which is what turns "SAFARI 0/4" into a status and
    /// a millisecond count per attempt. A caller that wants neither implements
    /// nothing.
    fn host_probed(
        &self,
        _fingerprint: TlsFingerprint,
        _domain: &str,
        _report: &BurstProfileReport,
    ) {
    }
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
            let cfg = cfg.clone();
            rounds.spawn(async move {
                let _permit = gate.acquire().await;
                let report = burst_profile(&address, &domain, fingerprint, &settings, &cfg).await;
                (index, report)
            });
        }
        while let Some(joined) = rounds.join_next().await {
            observer.host_finished();
            if let Ok((index, report)) = joined {
                observer.host_probed(fingerprint, &targets[index].domain, &report);
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

/// One profile's round against one address: the first attempt goes out at once
/// and every next one [`BURST_LAUNCH_GAP`] later, so the whole round overlaps
/// without being a single instant.
///
/// Overlapping is the measurement. The attempts have to be close enough together
/// to reach the rate a throttling trigger watches for — on a slow link, a round
/// that waits for each attempt to finish never gets there — and far enough apart
/// that the block, once triggered, lands *between* two starts instead of after
/// all of them. Three attempts is the shortest run that can show it: the first
/// two answer, the third is refused, and `M/N` reads 2.
pub async fn burst_profile(
    addr: &SocketAddr,
    domain: &str,
    fingerprint: TlsFingerprint,
    settings: &BurstSettings,
    cfg: &AppConfig,
) -> BurstProfileReport {
    let mut profile = offer_for(settings.tls, fingerprint);
    if let Some(alpn) = settings.alpn.offered() {
        profile = profile.alpn(alpn);
    }
    let round = Arc::new(Round { fingerprint, axis: settings.tls, cfg: cfg.clone() });

    let mut launches = JoinSet::new();
    for index in 0..settings.attempts {
        let addr = *addr;
        let domain = domain.to_string();
        // A connector per attempt, not per round. The `ClientConfig` owns the
        // session-ticket store, so one shared connector lets the third attempt
        // resume the session the first one opened — and a resumed hello carries a
        // PSK and a different extension set, which is not the shape this round
        // claims to measure. `create_tls_config` documents the same reasoning for
        // the probes: a private store per connection is what keeps one probe's
        // ticket out of the next probe's ClientHello.
        let profile = profile.clone();
        let round = Arc::clone(&round);
        let limit = settings.timeout;
        launches.spawn(async move {
            // The clock, not the previous attempt's completion: this is what
            // keeps the round inside a rate window on a slow link.
            if index > 0 {
                tokio::time::sleep(BURST_LAUNCH_GAP * index as u32).await;
            }
            let connector = RustlsConnector::from(profile);
            let attempt = match connect_attempt(addr, limit).await {
                Ok((stream, tracker)) => {
                    handshake_attempt(&connector, &domain, stream, tracker, limit, &round).await
                }
                // A dial that never came up is this attempt's whole result.
                Err(attempt) => attempt,
            };
            (index, attempt)
        });
    }

    // Collected by launch order, which is the order the report prints them in:
    // the k-th line is the k-th connection that went out, not the k-th that
    // finished.
    let mut slots: Vec<Option<BurstAttempt>> = (0..settings.attempts).map(|_| None).collect();
    while let Some(joined) = launches.join_next().await {
        if let Ok((index, attempt)) = joined {
            slots[index] = Some(attempt);
        }
    }
    let attempts = slots
        .into_iter()
        .map(|slot| {
            slot.unwrap_or(BurstAttempt {
                status: DpiStatus::Err,
                detail: Detail::Other("attempt aborted".to_string()),
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
            detail: Detail::TcpSynTimeout,
            ms: ms(started),
        }),
    }
}

/// The TLS offer one axis of the run presents.
///
/// [`BurstTlsVersion::Tls13And12`] is the *browser's own* hello: Chrome, Safari
/// and Firefox all offer 1.2 and 1.3 together, so a hello pinned to 1.3 would be
/// a shape no client sends — and when the test asks whether *this shape* is
/// blocked, the offer has to be the real one (pinned to 1.3 the extension body
/// reads `[GREASE, 0x0304]` instead of `[GREASE, 0x0304, 0x0303]`, and the
/// padding that fills the hello to 512 bytes is two bytes short of the
/// browser's). The handshake still has to come back 1.3 — see [`answered`].
///
/// The two pinned axes are synthetic on purpose, and they are test 2's two
/// columns: a client that offers both versions is never answered with 1.2, so
/// only a 1.2-only hello can ask whether a 1.2 handshake survives — and only a
/// 1.3-only hello can ask whether a middlebox treats a one-version offer
/// differently from the browser's.
fn offer_for(axis: BurstTlsVersion, fingerprint: TlsFingerprint) -> TlsProfile {
    match axis {
        BurstTlsVersion::Tls13And12 => TlsProfile::insecure(fingerprint),
        BurstTlsVersion::Tls13Only => TlsProfile::insecure(fingerprint).tls13(),
        BurstTlsVersion::Tls12Only => TlsProfile::insecure(fingerprint).tls12(),
    }
}

/// What a *completed* handshake means for the axis that asked for it.
///
/// The browser-offer axis offers both versions, so a peer that answers 1.2
/// answered — but not with what the axis is about, and reporting it as plain
/// success would hide a downgrade. `NoTls13` is the same verdict the classifier
/// reaches when a server turns out not to speak 1.3, and the badge already says
/// so. The pinned axes cannot negotiate the other version at all, so anything
/// that completes there is the answer they asked for; a peer that cannot speak
/// it fails the handshake instead, and the classifier reports that as
/// `NoTls13` on its own.
fn answered(axis: BurstTlsVersion, negotiated: Option<ProtocolVersion>) -> (DpiStatus, Detail) {
    match (axis, negotiated) {
        (BurstTlsVersion::Tls13And12, Some(ProtocolVersion::TLSv1_2)) => {
            (DpiStatus::NoTls13, Detail::NoTls13)
        }
        _ => (DpiStatus::Ok, Detail::None),
    }
}

/// Runs the attempt: the handshake, and — when it completes — the request under
/// `cfg.read_timeout` ([`check_http`]). The clock covers the whole attempt, dial
/// excluded: what the reported duration compares across attempts is the answer
/// the host gave, not how long the previous one took.
async fn handshake_attempt(
    connector: &RustlsConnector,
    domain: &str,
    stream: DpiProbeStream<TcpStream>,
    tracker: DpiProbeTracker,
    limit: Duration,
    round: &Round,
) -> BurstAttempt {
    let Round { fingerprint, axis, cfg } = round;
    let (fingerprint, axis) = (*fingerprint, *axis);
    let started = Instant::now();
    let elapsed = |started: Instant| started.elapsed().as_millis() as u64;
    let server_name = match ServerName::try_from(domain.to_string()) {
        Ok(name) => name,
        Err(e) => {
            return BurstAttempt {
                status: DpiStatus::Err,
                detail: Detail::Other(format!("bad SNI: {}", e)),
                ms: elapsed(started),
            }
        }
    };
    match timeout(limit, connector.connect(server_name, stream)).await {
        Ok(Ok(stream)) => {
            let negotiated = stream.get_ref().1.protocol_version();
            let stage = Arc::new(Mutex::new("tls_connected".to_string()));
            // The request is the second half of the attempt. A shape can be
            // answered and then cut, redirected or blocked the moment the
            // request goes out, and that is exactly what the test is for.
            let http = match timeout(
                Duration::from_secs_f64(cfg.read_timeout),
                check_http(stream, domain, cfg, fingerprint, &stage),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => (DpiStatus::ReadTimeout, Detail::ReadTimeoutWord, 0),
            };
            let (axis_status, axis_detail) = answered(axis, negotiated);
            // A peer that answered the browser's offer with 1.2 answered, but
            // not with what the axis is about: that outranks the request's own
            // verdict, since it explains why the run is not measuring 1.3.
            let (status, detail, _) = match axis_status {
                DpiStatus::Ok => http,
                _ => (axis_status, axis_detail, 0),
            };
            BurstAttempt { status, detail, ms: elapsed(started) }
        }
        Ok(Err(e)) => {
            // Same order as `check_domain_tls`: the stream wrapper sees a reset
            // or a premature EOF that the error alone would not name.
            let st = tracker.state.lock();
            if let Some(status) = st.last_status {
                let detail = st.last_error_msg.clone().unwrap_or(Detail::RstHello);
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
            detail: Detail::TlsHandshakeTimeout,
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

        let report = burst_profile(&addr, "example.com", TlsFingerprint::Rustls, &settings(3, 3000, vec![]), &AppConfig::default()).await;
        let _ = accept.await;

        assert_eq!(report.attempts.len(), 3);
        assert_eq!(report.answered(), 0);
        assert_eq!(report.lost(), 3);
        for attempt in &report.attempts {
            assert_ne!(attempt.status, DpiStatus::Unknown, "{:?}", attempt);
            assert!(!attempt.detail.is_none());
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
        let report = burst_profile(&addr, "example.com", TlsFingerprint::Rustls, &settings(2, 400, vec![]), &AppConfig::default()).await;
        let elapsed = started.elapsed();
        drop(listener);

        assert_eq!(report.attempts.len(), 2);
        for attempt in &report.attempts {
            assert_eq!(attempt.status, DpiStatus::TlsDropped, "{:?}", attempt);
            assert_eq!(attempt.detail, Detail::TlsHandshakeTimeout);
        }
        // Every attempt pays its own 400 ms, and the round is not the sum of
        // them: the attempts overlap, so the second is already waiting when the
        // first gives up and the round costs about one timeout. One after
        // another it would need 800 ms, which is what the upper bound rules out.
        assert!(elapsed >= Duration::from_millis(400), "round took {elapsed:?}");
        assert!(elapsed < Duration::from_millis(780), "round took {elapsed:?}");
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
        let report = burst_profile(&addr, "example.com", TlsFingerprint::Rustls, &settings(2, 2000, vec![]), &AppConfig::default()).await;
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
            assert!(!attempt.detail.is_none());
            // One local condition, one verdict: the attempts do not disagree.
            assert_eq!(attempt.status, first, "{:?}", report.attempts);
        }
        // Dead dials come back at once, so the round's budget is the slowest of
        // the two plus the 20 ms between them — the assertion is that it ends, not
        // that it ends fast.
        assert!(elapsed < Duration::from_millis(5200), "round took {elapsed:?}");
    }

    /// The browser-offer axis sends the browser's own offer — both versions in
    /// the list — because test 6 asks whether a *browser shape* gets blocked, and
    /// a hello pinned to 1.3 is a shape no browser sends. The two pinned axes are
    /// test 2's builders: a client offering both is never answered with 1.2, so
    /// only a 1.2-only hello can ask whether such a handshake survives, and only
    /// a 1.3-only one can ask whether a one-version offer is treated differently.
    /// A peer that answers the browser offer with 1.2 answered, but not with what
    /// the axis is about, and must not be reported as a plain success.
    #[test]
    fn the_tls13_axis_offers_both_versions_and_answers_a_downgrade() {
        let chrome = TlsFingerprint::Chrome;
        assert_eq!(
            offer_for(BurstTlsVersion::Tls13And12, chrome).version,
            crate::net::tls::TlsVersion::Any
        );
        assert_eq!(
            offer_for(BurstTlsVersion::Tls13Only, chrome).version,
            crate::net::tls::TlsVersion::Tls13
        );
        assert_eq!(
            offer_for(BurstTlsVersion::Tls12Only, chrome).version,
            crate::net::tls::TlsVersion::Tls12
        );

        assert_eq!(answered(BurstTlsVersion::Tls13And12, None), (DpiStatus::Ok, Detail::None));
        assert_eq!(
            answered(BurstTlsVersion::Tls13And12, Some(ProtocolVersion::TLSv1_3)),
            (DpiStatus::Ok, Detail::None)
        );
        assert_eq!(
            answered(BurstTlsVersion::Tls13And12, Some(ProtocolVersion::TLSv1_2)),
            (DpiStatus::NoTls13, Detail::NoTls13)
        );
        assert_eq!(
            answered(BurstTlsVersion::Tls12Only, Some(ProtocolVersion::TLSv1_2)),
            (DpiStatus::Ok, Detail::None)
        );
        // A pinned axis cannot reach the other version, so a completed handshake
        // there is the answer it asked for.
        assert_eq!(
            answered(BurstTlsVersion::Tls13Only, Some(ProtocolVersion::TLSv1_3)),
            (DpiStatus::Ok, Detail::None)
        );
        assert_eq!(
            answered(BurstTlsVersion::Tls12Only, Some(ProtocolVersion::TLSv1_3)),
            (DpiStatus::Ok, Detail::None)
        );
    }

    /// The cipher list of the hello a profile writes on `axis` — the same
    /// [`offer_for`] the run builds, so a stand names a shape by what the run
    /// actually sent, not by what a hand-built profile would have sent.
    ///
    /// Extension order is not part of the comparison: rustls shuffles it on
    /// every handshake (the Firefox/Chrome/Safari shapes pin their own order
    /// through the vendored profile), so only the cipher list is stable enough to
    /// name a shape arriving at a stand.
    fn hello_ciphers(fingerprint: TlsFingerprint, axis: BurstTlsVersion) -> String {
        let config = crate::net::tls::create_tls_config(&offer_for(axis, fingerprint));
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

        let axis = BurstTlsVersion::default();
        let ciphers = (hello_ciphers(TlsFingerprint::Rustls, axis), hello_ciphers(TlsFingerprint::Chrome, axis));
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
            probed: std::sync::Mutex<Vec<String>>,
        }
        impl BurstObserver for Rounds {
            fn round_started(&self, fp: TlsFingerprint, index: usize, total: usize, hosts: usize) {
                self.started.lock().expect("lock").push((fp, index, total, hosts));
            }
            fn host_finished(&self) {
                self.finished.fetch_add(1, Ordering::SeqCst);
            }
            fn host_probed(&self, fp: TlsFingerprint, domain: &str, report: &BurstProfileReport) {
                self.probed
                    .lock()
                    .expect("lock")
                    .push(format!("{} {domain} x{}", fp.code(), report.attempts.len()));
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
        // The trace reads this: every host's round arrives once per shape, with
        // the attempts it produced — silent hosts are not silently dropped.
        let mut probed = rounds.probed.lock().expect("lock").clone();
        probed.sort();
        assert_eq!(
            probed,
            vec![
                "chrome fast.example x2",
                "chrome slow.example x2",
                "rustls fast.example x2",
                "rustls slow.example x2",
            ]
        );
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
        let axes = (BurstTlsVersion::Tls13And12, BurstAlpn::Http2);
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
        let kept = BurstSettings::clamped(4, 8, BurstTlsVersion::Tls12Only, BurstAlpn::Http11, vec![]);
        assert_eq!((kept.tls, kept.alpn), (BurstTlsVersion::Tls12Only, BurstAlpn::Http11));
        assert_eq!(BurstSettings::default().attempts, BURST_DEFAULT_ATTEMPTS);
        // Defaults keep what a browser sends: both versions, and the profile's
        // own `h2, http/1.1`.
        let default = BurstSettings::default();
        assert_eq!((default.tls, default.alpn), (BurstTlsVersion::Tls13And12, BurstAlpn::Http2));
        assert!(default.alpn.offered().is_none());
    }

    /// The axes are what the screen and the CLI offer, so every spelling of every
    /// value must parse — and nothing else may.
    #[test]
    fn burst_axes_parse_their_values() {
        for value in ["1.3+1.2", "1.2+1.3", "tls1.3+1.2", "TLS 1.3+1.2", "both"] {
            assert_eq!(
                BurstTlsVersion::parse(value),
                Some(BurstTlsVersion::Tls13And12),
                "{value}"
            );
        }
        for value in ["1.3", "13", "tls1.3", "TLS 1.3"] {
            assert_eq!(BurstTlsVersion::parse(value), Some(BurstTlsVersion::Tls13Only), "{value}");
        }
        for value in ["1.2", "12", "tls1.2", "TLS 1.2"] {
            assert_eq!(BurstTlsVersion::parse(value), Some(BurstTlsVersion::Tls12Only), "{value}");
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
        assert_eq!(BurstTlsVersion::Tls13And12.code(), "1.3+1.2");
        assert_eq!(BurstTlsVersion::Tls13Only.code(), "1.3");
        assert_eq!(BurstTlsVersion::Tls12Only.token(), "TLS 1.2");
        assert_eq!(BurstTlsVersion::Tls13And12.token(), "TLS 1.3+1.2");
    }

    /// Grouping is by status, not by the detail behind it, and the order is by
    /// count with ties in the order the statuses first appeared.
    #[test]
    fn failure_counts_group_by_status_and_order_by_count() {
        let report = BurstProfileReport {
            fingerprint: TlsFingerprint::Chrome,
            attempts: vec![
                BurstAttempt { status: DpiStatus::Ok, detail: Detail::None, ms: 10 },
                BurstAttempt { status: DpiStatus::TlsRst, detail: Detail::RstHello, ms: 11 },
                BurstAttempt { status: DpiStatus::SynDropped, detail: Detail::None, ms: 900 },
                // Same status, another detail: one group, not two.
                BurstAttempt {
                    status: DpiStatus::TlsRst,
                    detail: Detail::TlsHandshakeTimeout,
                    ms: 12,
                },
                BurstAttempt { status: DpiStatus::TcpRst, detail: Detail::RstHello, ms: 13 },
            ],
        };
        assert_eq!(report.answered(), 1);
        assert_eq!(report.lost(), 4);
        assert_eq!(
            report.failure_counts(),
            vec![(DpiStatus::TlsRst, 2), (DpiStatus::SynDropped, 1), (DpiStatus::TcpRst, 1)]
        );

        let clean = BurstProfileReport {
            fingerprint: TlsFingerprint::Firefox,
            attempts: vec![BurstAttempt { status: DpiStatus::Ok, detail: Detail::None, ms: 10 }],
        };
        assert!(clean.failure_counts().is_empty());
        let report = BurstReport {
            domain: "example.com".into(),
            resolved: None,
            profiles: vec![clean],
        };
        assert!(!report.has_losses());
        assert!(report.failure_counts().is_empty());
    }

    /// A host that lost its handshakes to more than one middlebox shows every
    /// group, not just the loudest one.
    #[test]
    fn report_failure_counts_span_profiles_and_keep_every_group() {
        let profile = |fingerprint, statuses: Vec<DpiStatus>| BurstProfileReport {
            fingerprint,
            attempts: statuses
                .into_iter()
                .map(|status| BurstAttempt {
                    status,
                    detail: Detail::Other(status.display_label().to_string()),
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
        assert_eq!(
            report.failure_counts(),
            vec![(DpiStatus::TlsDropped, 3), (DpiStatus::TlsRst, 1)]
        );
    }
}

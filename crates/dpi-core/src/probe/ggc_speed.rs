//! Test 7: the throughput of the YouTube delivery node the player is steered
//! to, measured from outside the browser.
//!
//! The player is handed a signed URL that names a cluster's delivery node, so
//! throughput is a property of that node, not of "YouTube". The test does what
//! the player does and then what the player is never asked to do — point the
//! same signed URL at each address of that cluster and time the bytes.
//!
//! Minting: the watch page carries the Innertube API key, the client version
//! and a visitor id; `youtubei/v1/player` answers `streamingData` for the
//! configured video. The WEB client wants a PO token and answers
//! `UNPLAYABLE`, the Android and iOS clients answer 400, and the VR client
//! answers with direct URLs and no cookies at all — so it is the one asked.
//! The URLs it returns carry no session, which is what makes the ranged
//! `GET` below a measurement rather than a replay.
//!
//! Measuring: two facts, both measured on this line, decide the request's
//! shape.
//!
//! * The media path answers only a browser's TLS hello. The same URL over this
//!   build's rustls default is answered with silence, over Chrome's hello with
//!   the bytes, so the fetch carries `MEDIA_FINGERPRINT`.
//! * The URL names one cluster. Its own addresses serve it — two of the same
//!   operator's answered a range at 1.96 and 4.9 MB/s — and a node of another
//!   network answers 400. A target is therefore always an address that serves
//!   the hostname the URL carries, never an arbitrary delivery node.
//!
//! One measured answer reads as an error and is not: a cluster address may
//! answer `302` and steer the request elsewhere. The row reports that status
//! rather than following it, because what the row measures is the address it
//! names — a redirect means "not here", and following it would report the
//! target as if it were the address asked.
//!
//! Walking: the URL names the cluster, not an address, so every address of
//! the node's block can be asked whether it serves that URL. The walk is
//! opt-in (`GGC_SCAN_PREFIX`), because it is a scan of the operator's network:
//! a node of this cluster answers `2xx` (it serves) or `3xx` (it steers the
//! request on), a node of another network answers `400`, and anything that
//! does not finish the handshake is not a delivery node. What the walk finds
//! is measured like the two addresses the run already had.
//!
//! Naming: the steering hands out one `<index>---<cluster>` name and the
//! cluster's other named nodes answer to `rr1---<cluster>`, `rr2---<cluster>` …
//! — the index is the node. Resolving those is a handful of DNS queries and no
//! traffic to any address, so it runs before the walk; the measured cluster
//! named `rr1`…`rr3` and nothing above, while the rest of its nodes answered
//! without a name at all, which is why the two passes complement each other.

use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::classify::{
    classify_connect_error_full, DpiProbeStream, DpiProbeTracker, Detail, DpiStatus, ProbeStage,
};
use crate::config::AppConfig;
use crate::net::connector::{DpiTlsConnector, RustlsConnector};
use crate::net::fingerprint::{http_identity, TlsFingerprint};
use crate::net::http::request_headers;
use crate::net::tcp::dial_tcp;
use crate::net::tls::{server_name, TlsProfile};
use crate::probe::domains::{resolve_ip, IpFamily};
use crate::probe::permit;

/// The page the Innertube values are read off.
const PAGE_URL: &str = "https://www.youtube.com/watch?v=";

/// The player endpoint. The key is the page's own, appended at the call site.
const PLAYER_URL: &str = "https://www.youtube.com/youtubei/v1/player?key=";

/// The client the URL is minted for: the only one left that answers with
/// direct URLs and needs neither a PO token nor a cookie jar.
const VR_CLIENT: &str = "ANDROID_VR";
const VR_CLIENT_ID: &str = "28";
const VR_CLIENT_VERSION: &str = "1.60.19";

/// The watch page runs past a megabyte, and the cap is here rather than in the
/// control-plane client because that client's megabyte belongs to a public-IP
/// echo. A page that does not fit is a page this test cannot read.
const PAGE_CAP: usize = 4 << 20;

/// How much of the stream one measurement asks for. A megabyte is ten times
/// what the player's goodput probe asks and still one request on any line.
const SPEED_BYTES: u64 = 1 << 20;

/// The deadline over one measurement, whole: connect, handshake, request and
/// body. The run's own `TIMEOUT` is sized for a handshake, and a slow line is
/// the very thing this test exists to report rather than to cut off.
const SPEED_TIMEOUT: Duration = Duration::from_secs(20);

/// How much of the stream the walk asks for: one byte answers "does this
/// address serve this cluster", and a node that serves sends it at once.
const SCAN_BYTES: u64 = 1;

/// The deadline over one walk probe. Shorter than a measurement on purpose: a
/// node that needs longer than this is exactly the stall the row reports, and
/// the walk must not spend a measurement's budget on every dead address.
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

/// Probes in flight at once during a walk. The walk talks to addresses the
/// operator may not own, so it is deliberately slower than the run's own
/// parallelism allows.
const SCAN_CONCURRENCY: usize = 16;

/// The whole walk's budget. A block with silent addresses would otherwise
/// hold the run for minutes; the walk reports how far it got.
const SCAN_BUDGET: Duration = Duration::from_secs(180);

/// How many sibling indexes [`name_variants`] asks for. The measured cluster
/// answered to `rr1`…`rr3` and nothing above, so sixteen is a wide ceiling
/// that still costs a handful of DNS queries rather than a scan.
const NAME_VARIANTS_MAX: u8 = 16;

/// The hello the media path answers. Chrome's is not decoration: a
/// non-browser client is answered with silence on this path.
const MEDIA_FINGERPRINT: TlsFingerprint = TlsFingerprint::Chrome150;

/// The client version a media URL's `cver` is checked against is the
/// impersonated browser's, so the page and the player are asked with the same
/// hello the media is fetched with.
fn browser_fingerprint() -> TlsFingerprint {
    MEDIA_FINGERPRINT
}

/// Why [`mint`] returned no URL.
#[derive(Debug, thiserror::Error)]
pub enum SpeedError {
    /// The watch page could not be fetched.
    #[error("watch page: {0}")]
    Page(String),
    /// The page answered but one of the three Innertube values was not in it.
    #[error("watch page carries no {0}")]
    Ytcfg(&'static str),
    /// The player endpoint did not answer, or answered without streaming data.
    #[error("player: {0}")]
    Player(String),
    /// The player answered but named no format with a direct URL.
    #[error("no direct media URL: {0}")]
    NoMedia(String),
}

/// Where a measured address sits relative to the URL the player was handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedNode {
    /// The address the URL's own hostname resolves to: the node Google picked.
    UrlNode,
    /// The address behind the cluster's `r1.<cluster>` name, which the
    /// redirector reports as where this address is steered.
    MappedCluster,
    /// An address of the URL node's block that answered the walk.
    Scanned,
    /// An address the cluster's sibling names resolved to: the steering named
    /// one node, and `rr1---<cluster>`, `rr2---<cluster>` … resolve to the
    /// others.
    Named,
}

impl SpeedNode {
    /// The wire token. Rule 5 keeps the machine payload language-independent,
    /// and this word is the row's whole identity there.
    pub fn token(self) -> &'static str {
        match self {
            Self::UrlNode => "url",
            Self::MappedCluster => "mapped",
            Self::Scanned => "scan",
            Self::Named => "named",
        }
    }
}

/// One address to measure, with the hostname the URL carries: the hostname is
/// the SNI and the `Host` header, and it is what a node has to serve.
#[derive(Debug, Clone)]
pub struct SpeedTarget {
    pub host: String,
    pub address: Option<std::net::IpAddr>,
    pub node: SpeedNode,
    /// The DNS name that resolved to this address, when an address came from
    /// the cluster's sibling names (`rr1---<cluster>`). The request still
    /// carries [`Self::host`]: the name is how the address was found, not what
    /// is asked of it.
    pub name: Option<String>,
}

/// One walk's outcome: the block it asked, how many addresses it reached, and
/// the addresses that answered for the URL's hostname.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// The block, as `192.0.2.0/24`.
    pub prefix: String,
    /// How many addresses the walk asked.
    pub scanned: usize,
    /// Whether the walk covered its whole block. A walk stopped at the
    /// three-minute budget reports the addresses it did ask, so a short count
    /// is not read as "the block holds no more nodes".
    pub complete: bool,
    /// The addresses that answered, ascending. They are measured like the two
    /// addresses the run already had.
    pub targets: Vec<SpeedTarget>,
}

/// One ranged fetch: how long the answer took to start, how long it took, and
/// how many bytes arrived.
#[derive(Debug, Clone)]
pub struct SpeedAttempt {
    pub status: DpiStatus,
    pub detail: Detail,
    pub bytes: u64,
    /// Time to the response headers, in milliseconds.
    pub ttfb_ms: Option<u64>,
    /// Time to the end of the body, in milliseconds.
    pub ms: u64,
    /// The host a `3xx` pointed at, when the answer was a redirect.
    ///
    /// The chain is the finding: a local node may answer `302` and hand the
    /// request to another network, and the host is what says which. Only the
    /// host is kept — the rest of the `Location` is a signed token, and a
    /// report has no use for it.
    pub location_host: Option<String>,
}

impl SpeedAttempt {
    /// Megabytes per second over the transfer, or `None` when nothing arrived.
    ///
    /// The row exists to compare nodes on one line, so the unit is the one a
    /// reader already has a feel for: a megabyte is what a segment carries and
    /// a second is what the deadline measures. A cut transfer keeps the bytes
    /// that did arrive, and the rate then says how fast the byte ran out.
    pub fn mb_per_sec(&self) -> Option<f64> {
        if self.bytes == 0 || self.ms == 0 {
            return None;
        }
        Some(self.bytes as f64 / (self.ms as f64 / 1_000.0) / 1_000_000.0)
    }

    fn failed(status: DpiStatus, detail: Detail) -> Self {
        Self {
            status,
            detail,
            bytes: 0,
            ttfb_ms: None,
            ms: 0,
            location_host: None,
        }
    }
}

/// The signed URL one run measures, with the parts a target needs.
#[derive(Debug, Clone)]
pub struct MediaSource {
    /// The hostname the URL names; every target is measured under it.
    pub host: String,
    /// Path and query exactly as the player received them.
    pub path_and_query: String,
    pub itag: u64,
    pub content_length: Option<u64>,
}

/// Finds `"<name>":"<value>"` in a page and returns the value.
///
/// The page is a document, not a protocol, so this is a scan and not a
/// parser: the three values are plain JSON string members of `ytcfg`, they
/// never carry an escape, and a page that changed shape fails [`mint`] with
/// the name it could not find.
fn json_string(page: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\":\"");
    let start = page.find(&needle)? + needle.len();
    let rest = &page[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Mints a signed media URL through the page and the player endpoint.
///
/// Takes one permit per request, like every probe: the page and the player
/// are two requests on the run's own gate.
pub async fn mint(cfg: &AppConfig, sem: &Semaphore) -> Result<MediaSource, SpeedError> {
    let fingerprint = browser_fingerprint();
    let video = cfg.ggc_speed_video_id.as_str();
    let page_url = format!("{PAGE_URL}{video}");
    let page = fetch_text(cfg, &page_url, fingerprint, &[], None, PAGE_CAP, sem)
        .await
        .map_err(SpeedError::Page)?;

    let key = json_string(&page, "INNERTUBE_API_KEY")
        .ok_or(SpeedError::Ytcfg("INNERTUBE_API_KEY"))?;
    let visitor = json_string(&page, "VISITOR_DATA").ok_or(SpeedError::Ytcfg("VISITOR_DATA"))?;

    let body = serde_json::json!({
        "context": {"client": {
            "clientName": VR_CLIENT,
            "clientVersion": VR_CLIENT_VERSION,
            "hl": "en",
            "gl": "US",
            "visitorData": visitor,
        }},
        "videoId": video,
        "contentCheckOk": true,
        "racyCheckOk": true,
    });
    let headers = [
        ("content-type", "application/json"),
        ("x-youtube-client-name", VR_CLIENT_ID),
        ("x-youtube-client-version", VR_CLIENT_VERSION),
        ("x-goog-visitor-id", visitor.as_str()),
    ];
    let url = format!("{PLAYER_URL}{key}&prettyPrint=false");
    let answer = fetch_text(cfg, &url, fingerprint, &headers, Some(body.to_string().into_bytes()), PAGE_CAP, sem)
        .await
        .map_err(SpeedError::Player)?;

    let parsed: Value = serde_json::from_str(&answer)
        .map_err(|e| SpeedError::Player(format!("not JSON: {e}")))?;
    let status = parsed
        .pointer("/playabilityStatus/status")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let formats = parsed
        .pointer("/streamingData/adaptiveFormats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let best = formats
        .iter()
        .filter(|f| f.get("url").and_then(Value::as_str).is_some())
        .max_by_key(|f| f.get("contentLength").and_then(Value::as_str).and_then(|c| c.parse::<u64>().ok()).unwrap_or(0))
        .ok_or_else(|| {
            SpeedError::NoMedia(format!(
                "playability {status}, {} formats, none with a direct url",
                formats.len()
            ))
        })?;

    let url = best.get("url").and_then(Value::as_str).unwrap_or_default();
    let parsed_url = url::Url::parse(url).map_err(|e| SpeedError::NoMedia(format!("{e}")))?;
    let path_and_query = match parsed_url.query() {
        Some(query) => format!("{}?{query}", parsed_url.path()),
        None => parsed_url.path().to_string(),
    };
    Ok(MediaSource {
        host: parsed_url.host_str().unwrap_or_default().to_string(),
        path_and_query,
        itag: best.get("itag").and_then(Value::as_u64).unwrap_or(0),
        content_length: best
            .get("contentLength")
            .and_then(Value::as_str)
            .and_then(|c| c.parse::<u64>().ok()),
    })
}

/// Measures one target: a ranged `GET` of the signed URL under the browser's
/// hello, counting bytes as they arrive.
///
/// The address is the only thing a target changes: the SNI and the `Host`
/// header stay the URL's own, which is what a node of that cluster serves.
pub async fn measure(
    cfg: &AppConfig,
    source: &MediaSource,
    target: &SpeedTarget,
    sem: &Semaphore,
) -> SpeedAttempt {
    fetch(cfg, source, target, SPEED_BYTES, SPEED_TIMEOUT, sem).await
}

/// The fetch both a measurement and a walk probe use: a ranged `GET` of the
/// signed URL under the browser's hello, counting bytes as they arrive.
async fn fetch(
    cfg: &AppConfig,
    source: &MediaSource,
    target: &SpeedTarget,
    limit: u64,
    deadline: Duration,
    sem: &Semaphore,
) -> SpeedAttempt {
    let Some(ip) = target.address else {
        // A name that did not resolve cannot be measured; the row says so.
        return SpeedAttempt::failed(DpiStatus::Err, Detail::Other("address did not resolve".into()));
    };
    let _permit = permit(sem).await;
    let addr = std::net::SocketAddr::new(ip, 443);

    let started = Instant::now();
    let tcp = match dial_tcp(&addr, Duration::from_secs_f64(cfg.timeout)).await {
        Ok(stream) => stream,
        Err(e) => {
            let (status, detail) = e.verdict();
            tracing::debug!("speed: {} ({ip}) connect: {detail:?}", target.host);
            return SpeedAttempt::failed(status, detail);
        }
    };

    let profile = TlsProfile::insecure(MEDIA_FINGERPRINT);
    let connector = RustlsConnector::from(profile);
    let name = match server_name(&target.host) {
        Ok(n) => n,
        Err(e) => return SpeedAttempt::failed(DpiStatus::Err, Detail::Other(format!("bad SNI: {e}"))),
    };
    let tracker = DpiProbeTracker::new();
    let probe_stream = DpiProbeStream::new(tcp, tracker);
    let tls = match timeout(deadline, connector.connect(name, probe_stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let msg = e.to_string();
            tracing::debug!("speed: {} ({ip}) handshake: {msg}", target.host);
            let (status, detail) = classify_connect_error_full(
                &msg,
                e.raw_os_error(),
                Some(e.kind()),
                0,
                ProbeStage::TlsHandshake,
            );
            return SpeedAttempt::failed(status, detail);
        }
        Err(_) => {
            tracing::debug!("speed: {} ({ip}) handshake timed out", target.host);
            return SpeedAttempt::failed(DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout);
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(tls)).await {
        Ok(pair) => pair,
        Err(e) => {
            return SpeedAttempt::failed(DpiStatus::Err, Detail::Other(format!("http1: {e}")));
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let identity = http_identity(MEDIA_FINGERPRINT);
    let range = format!(
        "bytes=0-{}",
        limit.min(source.content_length.unwrap_or(limit).max(1)) - 1
    );
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(source.path_and_query.as_str())
        .header(hyper::header::HOST, source.host.as_str());
    for (name, value) in request_headers(
        &identity,
        TlsFingerprint::user_agent_for(cfg, MEDIA_FINGERPRINT),
        [
            ("connection", "close".into()),
            ("range", range.as_str().into()),
        ],
        true,
    ) {
        builder = builder.header(name, value.as_ref());
    }
    let request = match builder.body(Full::new(Bytes::new())) {
        Ok(request) => request,
        Err(e) => {
            return SpeedAttempt::failed(DpiStatus::Err, Detail::Other(format!("bad request: {e}")));
        }
    };

    let mut response = match timeout(deadline, sender.send_request(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            let (status, detail) = classify_connect_error_full(
                &e.to_string(),
                None,
                None,
                0,
                ProbeStage::ReadingData,
            );
            return SpeedAttempt::failed(status, detail);
        }
        Err(_) => {
            return SpeedAttempt::failed(
                DpiStatus::ReadTimeout,
                Detail::at_kb(Detail::ReadTimeoutWord, 0.0),
            );
        }
    };
    let ttfb_ms = started.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        // A redirect is the node saying "not here", and the host it points at
        // is the answer the row needs: the rest of `Location` is a signed
        // token that has no place in a report.
        let location_host = response
            .headers()
            .get(hyper::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                let base = url::Url::parse(&format!(
                    "https://{}{}",
                    target.host, source.path_and_query
                ))
                .ok()?;
                base.join(value).ok()?.host_str().map(str::to_string)
            });
        tracing::debug!("speed: {} ({ip}) answered {status} -> {location_host:?}", target.host);
        return SpeedAttempt {
            status: DpiStatus::Err,
            detail: Detail::Other(format!("http {status}")),
            bytes: 0,
            ttfb_ms: Some(ttfb_ms),
            ms: started.elapsed().as_millis() as u64,
            location_host,
        };
    }

    let mut bytes = 0u64;
    while let Ok(Some(frame)) = timeout(deadline, response.body_mut().frame()).await {
        let Ok(frame) = frame else { break };
        if let Some(data) = frame.data_ref() {
            bytes += data.len() as u64;
        }
    }
    let ms = started.elapsed().as_millis() as u64;
    if bytes == 0 {
        // The status promised a body and none came: the same silence a cut
        // transfer shows, and the row must say so rather than print 0 MB/s as
        // a measurement.
        tracing::debug!("speed: {} ({ip}) answered {status} with no body", target.host);
        return SpeedAttempt {
            status: DpiStatus::ReadTimeout,
            detail: Detail::at_kb(Detail::ReadTimeoutWord, 0.0),
            bytes: 0,
            ttfb_ms: Some(ttfb_ms),
            ms,
            location_host: None,
        };
    }
    tracing::debug!(
        "speed: {} ({ip}) {bytes} bytes in {ms} ms ({status})",
        target.host
    );
    SpeedAttempt {
        status: DpiStatus::Ok,
        detail: Detail::None,
        bytes,
        ttfb_ms: Some(ttfb_ms),
        ms,
        location_host: None,
    }
}

/// The sibling names of a media host: the steering hands out one
/// `<index>---<cluster>` name, and the cluster's other named nodes answer to
/// `rr1---<cluster>`, `rr2---<cluster>` … — the index is the node, and the
/// cluster part is the same. A host without the `---` separator (a
/// `r1.<cluster>` name, say) has no siblings of this shape.
pub fn name_variants(host: &str, max: u8) -> Vec<String> {
    let Some((_, cluster)) = host.split_once("---") else {
        return Vec::new();
    };
    (1..=max)
        .map(|index| format!("rr{index}---{cluster}"))
        .collect()
}

/// Resolves the cluster's sibling names and returns the addresses that
/// answered, each with the name it came from.
///
/// This is the cheap half of the search: a handful of DNS queries to Google's
/// authoritative servers, and no traffic to any address. A name that does not
/// resolve is not an error — the measured cluster named `rr1`…`rr3` and
/// nothing above, while the rest of its nodes were nameless — so the list is
/// simply shorter. Addresses already known are left to the caller to dedupe.
pub async fn named_targets(source: &MediaSource, family: IpFamily) -> Vec<SpeedTarget> {
    let mut targets: Vec<SpeedTarget> = Vec::new();
    for name in name_variants(&source.host, NAME_VARIANTS_MAX) {
        let Some(ip) = resolve_ip(&name, family).await else {
            continue;
        };
        if targets.iter().any(|target| target.address == Some(ip)) {
            continue;
        }
        targets.push(SpeedTarget {
            host: source.host.clone(),
            address: Some(ip),
            node: SpeedNode::Named,
            name: Some(name),
        });
    }
    targets
}

/// The addresses a walk asks: every host of the block `bits` wide that holds
/// `base`, network and broadcast excluded.
///
/// `None` when the prefix is outside the walk's range: `/20` is the widest
/// block an operator's network justifies, and `/30` the narrowest that has a
/// host at all.
fn block(
    base: std::net::Ipv4Addr,
    bits: u8,
) -> Option<(std::net::Ipv4Addr, Vec<std::net::Ipv4Addr>)> {
    if !(20..=30).contains(&bits) {
        return None;
    }
    let size = 1u32 << (32 - bits);
    let network = std::net::Ipv4Addr::from(u32::from(base) & !(size - 1));
    let first = u32::from(network) + 1;
    let last = u32::from(network) + size - 1;
    Some((network, (first..last).map(std::net::Ipv4Addr::from).collect()))
}

/// Asks one address whether it serves the URL's hostname.
async fn probe(
    cfg: &AppConfig,
    source: &MediaSource,
    address: std::net::Ipv4Addr,
    gate: &Semaphore,
) -> Option<SpeedTarget> {
    let target = SpeedTarget {
        host: source.host.clone(),
        address: Some(std::net::IpAddr::V4(address)),
        node: SpeedNode::Scanned,
        name: None,
    };
    let attempt = fetch(cfg, source, &target, SCAN_BYTES, SCAN_TIMEOUT, gate).await;
    // A node of this cluster serves the URL (`2xx`) or steers it on (`3xx`);
    // a node of another network answers `400`, and a silent one is not a
    // delivery node at all. Only the first two are worth measuring.
    if attempt.status == DpiStatus::Ok || attempt.location_host.is_some() {
        tracing::debug!("scan: {address} serves the cluster ({:?})", attempt.detail);
        Some(target)
    } else {
        None
    }
}

/// Walks the URL node's block, asks every address whether it serves this
/// cluster, and returns the addresses that do.
///
/// The walk is a scan of the operator's network, so it is opt-in
/// (`GGC_SCAN_PREFIX`), runs a fixed window (16 probes in flight) and
/// stops at a three-minute budget. `None` when there is nothing to walk: an
/// IPv6 node address or a prefix outside the range, both reported as
/// warnings.
pub async fn scan_cluster(
    cfg: &AppConfig,
    source: &MediaSource,
    base: std::net::IpAddr,
    bits: u8,
    skip: &[std::net::IpAddr],
    gate: &std::sync::Arc<Semaphore>,
) -> Option<ScanReport> {
    let std::net::IpAddr::V4(base) = base else {
        tracing::warn!("scan: {base} is IPv6, and a walk covers IPv4 blocks only");
        return None;
    };
    let Some((network, candidates)) = block(base, bits) else {
        tracing::warn!("scan: {bits} is outside the walk's range (20..=30)");
        return None;
    };
    let queue: Vec<_> = candidates
        .into_iter()
        .filter(|ip| !skip.contains(&std::net::IpAddr::V4(*ip)))
        .collect();
    let total = queue.len();
    let mut queue = queue.into_iter();
    let deadline = Instant::now() + SCAN_BUDGET;
    let mut set: tokio::task::JoinSet<Option<SpeedTarget>> = tokio::task::JoinSet::new();
    let mut targets = Vec::new();
    let mut scanned = 0usize;
    let mut cut = false;
    loop {
        while !cut && set.len() < SCAN_CONCURRENCY {
            let Some(address) = queue.next() else { break };
            if Instant::now() >= deadline {
                cut = true;
                break;
            }
            scanned += 1;
            let cfg = cfg.clone();
            let source = source.clone();
            let gate = std::sync::Arc::clone(gate);
            set.spawn(async move { probe(&cfg, &source, address, &gate).await });
        }
        let Some(joined) = set.join_next().await else {
            break;
        };
        if let Ok(Some(target)) = joined {
            targets.push(target);
        }
    }
    targets.sort_by_key(|target| target.address);
    tracing::debug!(
        "scan: {network}/{bits} asked {scanned} of {total} addresses, {} answered",
        targets.len()
    );
    Some(ScanReport {
        prefix: format!("{network}/{bits}"),
        scanned,
        complete: !cut,
        targets,
    })
}

/// A GET (or a POST when `body` is set) that returns the body as text, with
/// the same TLS shape and identity the media fetch uses.
///
/// The body is capped: a page or an answer that runs past `cap` is not one
/// this test can read, and reading it whole is what the cap is here to stop.
#[allow(clippy::too_many_arguments)]
async fn fetch_text(
    cfg: &AppConfig,
    url_str: &str,
    fingerprint: TlsFingerprint,
    extra_headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
    cap: usize,
    sem: &Semaphore,
) -> Result<String, String> {
    let _permit = permit(sem).await;
    let url = url::Url::parse(url_str).map_err(|e| format!("bad url: {e}"))?;
    let host = url.host_str().ok_or("no host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addr = match resolve_ip(&host, crate::probe::domains::IpFamily::from_config(&cfg.ip_version)).await {
        Some(ip) => std::net::SocketAddr::new(ip, port),
        None => return Err(format!("{host} did not resolve")),
    };
    let tcp = dial_tcp(&addr, Duration::from_secs_f64(cfg.timeout))
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    // The page and the player are asked over `www.youtube.com`, which offers
    // h2 and would take it: the sender here speaks HTTP/1.1, so the offer is
    // pinned to it. The media fetch below does not pin — its nodes negotiate
    // no ALPN at all, and the offer itself is part of the hello they answer.
    let profile = TlsProfile::insecure(fingerprint).alpn(vec![b"http/1.1".to_vec()]);
    let connector = RustlsConnector::from(profile);
    let name = server_name(&host).map_err(|e| format!("bad SNI: {e}"))?;
    let tracker = DpiProbeTracker::new();
    let tls = timeout(
        SPEED_TIMEOUT,
        connector.connect(name, DpiProbeStream::new(tcp, tracker)),
    )
    .await
    .map_err(|_| "handshake timed out".to_string())?
    .map_err(|e| format!("handshake: {e}"))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| format!("http1: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let identity = http_identity(fingerprint);
    let uri = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let mut builder = Request::builder()
        .method(if body.is_some() { Method::POST } else { Method::GET })
        .uri(uri)
        .header(hyper::header::HOST, host.as_str());
    let extras: Vec<(&str, std::borrow::Cow<'_, str>)> = extra_headers
        .iter()
        .map(|(name, value)| (*name, std::borrow::Cow::Borrowed(*value)))
        .chain(std::iter::once(("connection", std::borrow::Cow::Borrowed("close"))))
        .collect();
    for (name, value) in request_headers(
        &identity,
        TlsFingerprint::user_agent_for(cfg, fingerprint),
        extras,
        true,
    ) {
        builder = builder.header(name, value.as_ref());
    }
    let payload = body.map(Bytes::from).unwrap_or_default();
    let request = builder
        .body(Full::new(payload))
        .map_err(|e| format!("bad request: {e}"))?;
    let response = timeout(SPEED_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| "request timed out".to_string())?
        .map_err(|e| format!("request: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("http {}", status.as_u16()));
    }
    let collected = timeout(SPEED_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "body timed out".to_string())?
        .map_err(|e| format!("body: {e}"))?;
    let bytes = collected.to_bytes();
    if bytes.len() > cap {
        return Err(format!("body {} bytes over the {cap} cap", bytes.len()));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| "body is not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three Innertube values are plain JSON string members of `ytcfg`;
    /// the failure this pins is a page whose shape moved, which has to fail
    /// minting by name rather than by reading a neighbouring value.
    #[test]
    fn test_ytcfg_value_is_read_verbatim_or_not_at_all() {
        let page = r#"<script>ytcfg.set({"INNERTUBE_API_KEY":"AIza-test","VISITOR_DATA":"Cgt-abc"});</script>"#;
        assert_eq!(json_string(page, "INNERTUBE_API_KEY").as_deref(), Some("AIza-test"));
        assert_eq!(json_string(page, "VISITOR_DATA").as_deref(), Some("Cgt-abc"));
        assert_eq!(json_string(page, "INNERTUBE_CLIENT_VERSION"), None);
    }

    /// The row exists to compare nodes, so the unit is the one the reader
    /// already has: the failure this pins is a rate that is a thousand times
    /// off because the milliseconds were divided the wrong way.
    #[test]
    fn test_rate_is_megabytes_per_second() {
        let attempt = SpeedAttempt {
            status: DpiStatus::Ok,
            detail: Detail::None,
            bytes: 1_000_000,
            ttfb_ms: Some(10),
            ms: 500,
            location_host: None,
        };
        assert_eq!(attempt.mb_per_sec(), Some(2.0));
    }

    /// A transfer that carried nothing is a verdict, not a zero: a row that
    /// prints 0 MB/s as a measurement reads as a slow node.
    #[test]
    fn test_no_bytes_has_no_rate() {
        let failed = SpeedAttempt::failed(DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout);
        assert_eq!(failed.mb_per_sec(), None);
    }

    /// The walk asks every host of the block and never the network or the
    /// broadcast address. The failure this pins is an off-by-one that would
    /// either skip the last host or ask an address that is not a host.
    #[test]
    fn test_block_skips_network_and_broadcast() {
        let (network, hosts) = block(std::net::Ipv4Addr::new(192, 0, 2, 78), 24).unwrap();
        assert_eq!(network, std::net::Ipv4Addr::new(192, 0, 2, 0));
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first(), Some(&std::net::Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(hosts.last(), Some(&std::net::Ipv4Addr::new(192, 0, 2, 254)));
    }

    /// A `/20` is the widest block the walk takes, and the one an operator's
    /// network actually justifies: the failure this pins is a mask that keeps
    /// the node's own /24 and quietly walks the wrong block.
    #[test]
    fn test_slash_20_covers_the_operator_block() {
        let (network, hosts) = block(std::net::Ipv4Addr::new(198, 51, 100, 78), 20).unwrap();
        assert_eq!(network, std::net::Ipv4Addr::new(198, 51, 96, 0));
        assert_eq!(hosts.len(), 4094);
        assert_eq!(hosts.first(), Some(&std::net::Ipv4Addr::new(198, 51, 96, 1)));
        assert_eq!(hosts.last(), Some(&std::net::Ipv4Addr::new(198, 51, 111, 254)));
    }

    /// Prefixes outside the walk's range are refused, not clamped: a typo in
    /// the config must not turn into a scan of some neighbouring block.
    #[test]
    fn test_block_refuses_prefixes_outside_the_walk() {
        let base = std::net::Ipv4Addr::new(192, 0, 2, 1);
        assert!(block(base, 19).is_none());
        assert!(block(base, 31).is_none());
        assert!(block(base, 0).is_none());
    }

    /// Rule 5: the walked address is a wire word, not the table's badge.
    #[test]
    fn test_scanned_node_carries_a_wire_token() {
        assert_eq!(SpeedNode::Scanned.token(), "scan");
        assert_eq!(SpeedNode::Named.token(), "named");
    }

    /// The sibling names follow the index and keep the cluster: the failure
    /// this pins is a variant list that rewrites the cluster part and asks
    /// names that belong to no node. A name without the separator has no
    /// siblings of this shape.
    #[test]
    fn test_name_variants_follow_the_node_index() {
        assert_eq!(
            name_variants("rr3---sn-example-0001.googlevideo.com", 3),
            vec![
                "rr1---sn-example-0001.googlevideo.com".to_string(),
                "rr2---sn-example-0001.googlevideo.com".to_string(),
                "rr3---sn-example-0001.googlevideo.com".to_string(),
            ]
        );
        assert!(name_variants("r1.example.googlevideo.com", 4).is_empty());
    }
}


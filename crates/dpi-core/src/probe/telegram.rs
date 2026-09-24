//!
//! Three parallel sub-tests: media download with stall detection,
//! 10 MB high-entropy upload with stall detection, and raw TCP pings
//! of DC1–DC5. Combined verdict: blocked / slow / partial / ok / error.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::classify::Detail;
use crate::config::AppConfig;
use crate::dns::resolve_host;
use crate::net::tcp::set_no_delay;
use crate::net::tls::{create_tls_config, TlsProfile};
use crate::PhaseProgress;

#[derive(Debug, Clone)]
pub struct TelegramDc {
    pub name: &'static str,
    pub ip: &'static str,
    pub port: u16,
    pub region: &'static str,
}

pub const TELEGRAM_DCS: &[TelegramDc] = &[
    TelegramDc { name: "DC1", ip: "149.154.175.53", port: 443, region: "Miami" },
    TelegramDc { name: "DC2", ip: "149.154.167.51", port: 443, region: "Amsterdam" },
    TelegramDc { name: "DC3", ip: "149.154.175.100", port: 443, region: "Miami" },
    TelegramDc { name: "DC4", ip: "149.154.167.91", port: 443, region: "Amsterdam" },
    TelegramDc { name: "DC5", ip: "91.108.56.130", port: 443, region: "Singapore" },
];

#[derive(Debug, Clone)]
pub struct TelegramDcResult {
    pub name: String,
    pub ip: String,
    pub region: String,
    pub available: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<Detail>,
}

#[derive(Debug, Clone, Default)]
pub struct TelegramReport {
    pub dc_results: Vec<TelegramDcResult>,
    pub dcs_available: usize,
    pub dcs_total: usize,
    pub download_speed_kbps: Option<f64>,
    pub download_ok: bool,
}

/// Probes a single Telegram DC endpoint via raw TCP handshake (L4).
pub async fn probe_telegram_dc(dc: &TelegramDc, timeout_dur: Duration) -> TelegramDcResult {
    let addr_str = format!("{}:{}", dc.ip, dc.port);
    let start = Instant::now();

    match addr_str.parse::<SocketAddr>() {
        Ok(sock_addr) => {
            match timeout(timeout_dur, crate::net::bind::tcp_connect(&sock_addr)).await {
                Ok(Ok(stream)) => {
                    set_no_delay(&stream);
                    let latency = start.elapsed().as_millis() as u64;
                    TelegramDcResult {
                        name: dc.name.to_string(),
                        ip: dc.ip.to_string(),
                        region: dc.region.to_string(),
                        available: true,
                        latency_ms: Some(latency),
                        error: None,
                    }
                }
                Ok(Err(e)) => TelegramDcResult {
                    name: dc.name.to_string(),
                    ip: dc.ip.to_string(),
                    region: dc.region.to_string(),
                    available: false,
                    latency_ms: None,
                    error: Some(Detail::Other(e.to_string())),
                },
                Err(_) => TelegramDcResult {
                    name: dc.name.to_string(),
                    ip: dc.ip.to_string(),
                    region: dc.region.to_string(),
                    available: false,
                    latency_ms: None,
                    error: Some(Detail::SynTimeoutShort),
                },
            }
        }
        Err(e) => TelegramDcResult {
            name: dc.name.to_string(),
            ip: dc.ip.to_string(),
            region: dc.region.to_string(),
            available: false,
            latency_ms: None,
            error: Some(Detail::Other(e.to_string())),
        },
    }
}

/// Probes all Telegram Data Centers concurrently.
pub async fn probe_telegram_all_dcs(timeout_dur: Duration) -> Vec<TelegramDcResult> {
    let mut handles = Vec::new();
    for dc in TELEGRAM_DCS {
        let dc_clone = dc.clone();
        handles.push(tokio::spawn(async move {
            probe_telegram_dc(&dc_clone, timeout_dur).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(res) = handle.await {
            results.push(res);
        }
    }
    results.sort_by(|a, b| a.name.cmp(&b.name));
    results
}

/// Legacy simple report (DC ping + naive download), kept for compat.
pub async fn run_telegram_test(timeout_dur: Duration) -> TelegramReport {
    let dc_results = probe_telegram_all_dcs(timeout_dur).await;
    let dcs_available = dc_results.iter().filter(|r| r.available).count();
    let dcs_total = dc_results.len();
    TelegramReport {
        dc_results,
        dcs_available,
        dcs_total,
        download_speed_kbps: None,
        download_ok: false,
    }
}

// ─── Transfer stats and outcome classification ───────────────────────────────

/// Outcome of one transfer leg — the five tokens `--json` carries.
///
/// The state used to be a `String` compared against literals at each site, so a
/// typo or a sixth state read as a silent `false` everywhere: a stalled leg
/// counted as a clean one and the raw string reached the payload unvalidated.
/// The spellings are unchanged — `as_str()` is the frozen `--json`/TUI token and
/// serde writes the same one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Ok,
    Slow,
    Stalled,
    Blocked,
    /// The leg never ran — an unparsable URL or upload address, or a request
    /// that could not be built. Says nothing about the network.
    #[default]
    Error,
}

impl TransferStatus {
    /// The wire token, carried by `--json` and printed by the TUI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Slow => "slow",
            Self::Stalled => "stalled",
            Self::Blocked => "blocked",
            Self::Error => "error",
        }
    }

    /// True only for a transfer that stopped short of its expected size with the
    /// data gone quiet. It is the one state whose average is taken over the time
    /// it actually moved and that records where it died, so a state added later
    /// has to answer this before the crate compiles.
    pub const fn is_stalled(self) -> bool {
        match self {
            Self::Stalled => true,
            Self::Ok | Self::Slow | Self::Blocked | Self::Error => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    pub status: TransferStatus,
    pub avg_bps: f64,
    pub peak_bps: f64,
    pub bytes_total: u64,
    pub duration: f64,
    pub drop_at_sec: Option<u64>,
}
fn classify_transfer(
    total_bytes: u64,
    expected: u64,
    stalled: bool,
    _duration: f64,
    last_active_sec: u64,
) -> (TransferStatus, Option<u64>) {
    let fully = expected > 0 && total_bytes as f64 >= expected as f64 * 0.98;
    if total_bytes == 0 {
        (TransferStatus::Blocked, None)
    } else if fully {
        (TransferStatus::Ok, None)
    } else if stalled {
        (TransferStatus::Stalled, Some(last_active_sec))
    } else {
        (TransferStatus::Slow, None)
    }
}

fn split_url(url: &str) -> Option<(String, String)> {
    let after_scheme = url.split("://").nth(1)?;
    let slash = after_scheme.find('/').unwrap_or(after_scheme.len());
    let host = after_scheme[..slash].to_string();
    let path = if slash < after_scheme.len() {
        after_scheme[slash..].to_string()
    } else {
        "/".to_string()
    };
    Some((host, path))
}

async fn tls_get(host: &str, path: &str, user_agent: &str) -> Option<(impl Body<Data = Bytes, Error = hyper::Error> + Unpin, impl FnOnce() + Send)> {
    let addr = resolve_host(host, 443, Duration::from_secs(10)).await.ok()?.into_iter().next()?;
    // Every network step below carries the same 8 s cap run_upload uses. A silently dropped
    // ClientHello — exactly the DPI signature this probe exists to measure — never completes
    // the handshake, and neither rustls nor tokio_rustls arms a handshake timer, so an
    // unbounded await here would freeze run_download, run_telegram_full and the whole run
    // (runner.rs has no outer cap on this). Timeout maps to None = the existing blocked verdict.
    let tcp = timeout(Duration::from_secs_f64(8.0), crate::net::bind::tcp_connect(&addr)).await.ok()?.ok()?;
    set_no_delay(&tcp);
    let connector = TlsConnector::from(create_tls_config(&TlsProfile::default()));
    let server_name = ServerName::try_from(host.to_string()).ok()?;
    let tls = timeout(Duration::from_secs_f64(8.0), connector.connect(server_name, tcp)).await.ok()?.ok()?;
    let io = TokioIo::new(tls);
    let (mut sender, conn) = timeout(Duration::from_secs_f64(8.0), hyper::client::conn::http1::handshake(io)).await.ok()?.ok()?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(HOST, host)
        .header(USER_AGENT, user_agent)
        .body(http_body_util::Empty::<Bytes>::new())
        .ok()?;
    let resp = timeout(Duration::from_secs_f64(8.0), sender.send_request(req)).await.ok()?.ok()?;
    let body = resp.into_body();
    // Keep the connection task alive via the body itself
    let noop = || {};
    Some((body, noop))
}

/// Media download with stall detection: streams the configured media URL over TLS
/// (1 s ticks for peak/average rate) and stops on the expected size, a
/// `telegram_stall_timeout` gap without data, or `telegram_total_timeout` overall.
pub async fn run_download(cfg: &AppConfig) -> TransferStats {
    let stall_timeout = cfg.telegram_stall_timeout;
    let total_timeout = cfg.telegram_total_timeout;
    let expected = (cfg.telegram_media_size_mb * 1024.0 * 1024.0) as u64;

    let (host, path) = match split_url(&cfg.telegram_media_url) {
        Some(v) => v,
        None => {
            return TransferStats { status: TransferStatus::Error, ..Default::default() };
        }
    };

    let t_start = Instant::now();
    let Some((mut body, _keep)) = tls_get(&host, &path, &cfg.user_agent).await else {
        return TransferStats { status: TransferStatus::Blocked, ..Default::default() };
    };

    let mut total: u64 = 0;
    let mut peak: f64 = 0.0;
    let mut last_data = Instant::now();
    let mut last_active_sec: u64 = 0;
    let mut tick_total: u64 = 0;
    let mut sec: u64 = 0;
    let mut tick_deadline = Instant::now() + Duration::from_secs(1);

    loop {
        if t_start.elapsed().as_secs_f64() >= total_timeout {
            break;
        }
        if last_data.elapsed().as_secs_f64() >= stall_timeout {
            break;
        }
        let frame_fut = body.frame();
        tokio::pin!(frame_fut);
        // Wait for the next frame or the 1s tick, whichever first
        enum Wake {
            Frame(Option<Result<Frame<Bytes>, hyper::Error>>),
            Tick,
        }
        let woke = tokio::select! {
            biased;
            res = &mut frame_fut => Wake::Frame(res),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(tick_deadline)) => Wake::Tick,
        };
        match woke {
            Wake::Frame(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = data.len() as u64;
                    total += n;
                    tick_total += n;
                    last_data = Instant::now();
                    last_active_sec = sec;
                }
            }
            Wake::Frame(Some(Err(_))) if total > 0 && last_data.elapsed().as_secs_f64() >= stall_timeout => {
                break;
            }
            Wake::Frame(Some(Err(_))) => break,
            Wake::Frame(None) if total > 0 && last_data.elapsed().as_secs_f64() >= stall_timeout => {
                break;
            }
            Wake::Frame(None) => break,
            Wake::Tick => {}
        }
        if Instant::now() >= tick_deadline {
            sec += 1;
            let bps = tick_total as f64;
            tick_total = 0;
            if bps > 0.0 {
                last_active_sec = sec;
            }
            peak = peak.max(bps);
            tick_deadline = Instant::now() + Duration::from_secs(1);
        }
        // EOF check: body ended
        if total >= expected {
            break;
        }
    }

    let duration = t_start.elapsed().as_secs_f64().max(0.001);
    let stalled = last_data.elapsed().as_secs_f64() >= stall_timeout && (total as f64) < expected as f64 * 0.98;
    let (status, drop_at) = classify_transfer(total, expected, stalled, duration, last_active_sec);
    let denom = if status.is_stalled() {
        last_active_sec.max(1) as f64
    } else {
        duration
    };
    TransferStats {
        status,
        avg_bps: total as f64 / denom,
        peak_bps: peak,
        bytes_total: total,
        duration,
        drop_at_sec: drop_at,
    }
}

/// Streaming upload body: 16 KB high-entropy frames until `total` or stop.
struct UploadBody {
    remaining: u64,
    chunk: Bytes,
    sent: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Body for UploadBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.stop.load(Ordering::Relaxed) || this.remaining == 0 {
            return Poll::Ready(None);
        }
        let n = this.remaining.min(this.chunk.len() as u64) as usize;
        this.remaining -= n as u64;
        this.sent.fetch_add(n, Ordering::Relaxed);
        Poll::Ready(Some(Ok(Frame::data(this.chunk.slice(..n)))))
    }
}

/// The upload response is never read, only awaited to completion, so `Limited`
/// is here purely to bound what a hostile or broken peer can make the tool
/// buffer while that await runs; the same value as `net::http`'s `BODY_CAP`.
const BODY_CAP: usize = 64 * 1024;

/// Upload with stall detection: POSTs `telegram_upload_size_mb` MB of filler to the
/// configured IP/port over TLS (8 s connect/handshake), sampling the sent counter
/// every 500 ms until the whole size is out, the stall gap hits, or the total cap does.
pub async fn run_upload(cfg: &AppConfig) -> TransferStats {
    let stall_timeout = cfg.telegram_stall_timeout;
    let total_timeout = cfg.telegram_total_timeout;
    let total_size = (cfg.telegram_upload_size_mb * 1024.0 * 1024.0) as u64;

    let sent = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // High-entropy 16 KB upload chunk from a xorshift64* PRNG, reused for every frame
    let mut chunk = vec![0u8; 16384];
    let mut state: u64 = 0x123456789ABCDEF;
    for b in chunk.iter_mut() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        *b = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 33) as u8;
    }

    let t0 = Instant::now();
    let addr = SocketAddr::new(
        match cfg.telegram_upload_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                return TransferStats { status: TransferStatus::Error, ..Default::default() };
            }
        },
        cfg.telegram_upload_port,
    );
    let tcp = match timeout(Duration::from_secs_f64(8.0), crate::net::bind::tcp_connect(&addr)).await {
        Ok(Ok(s)) => {
            set_no_delay(&s);
            s
        }
        _ => {
            return TransferStats { status: TransferStatus::Blocked, duration: t0.elapsed().as_secs_f64(), ..Default::default() };
        }
    };
    // SNI = IP → rustls sends no SNI extension (raw TLS stall probe)
    let connector = TlsConnector::from(create_tls_config(&TlsProfile::default()));
    let server_name = ServerName::IpAddress(rustls::pki_types::IpAddr::from(addr.ip()));
    let tls = match timeout(Duration::from_secs_f64(8.0), connector.connect(server_name, tcp)).await {
        Ok(Ok(s)) => s,
        _ => {
            return TransferStats { status: TransferStatus::Blocked, duration: t0.elapsed().as_secs_f64(), ..Default::default() };
        }
    };
    let io = TokioIo::new(tls);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(v) => v,
        Err(_) => {
            return TransferStats { status: TransferStatus::Blocked, duration: t0.elapsed().as_secs_f64(), ..Default::default() };
        }
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let body = UploadBody {
        remaining: total_size,
        chunk: Bytes::from(chunk),
        sent: Arc::clone(&sent),
        stop: Arc::clone(&stop),
    };
    let req = match Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .header(HOST, cfg.telegram_upload_ip.as_str())
        .header(USER_AGENT, cfg.user_agent.as_str())
        .body(body)
    {
        Ok(r) => r,
        Err(_) => {
            return TransferStats { status: TransferStatus::Error, ..Default::default() };
        }
    };

    let post_fut = sender.send_request(req);
    tokio::pin!(post_fut);

    let mut prev: u64 = 0;
    let mut peak: f64 = 0.0;
    let mut last_data = Instant::now();
    let mut last_nonzero_sec: u64 = 0;
    let mut post_done = false;
    let mut post_err = false;

    loop {
        let elapsed = t0.elapsed().as_secs_f64();
        if elapsed >= total_timeout {
            break;
        }
        if last_data.elapsed().as_secs_f64() >= stall_timeout {
            break;
        }
        tokio::select! {
            biased;
            res = &mut post_fut => {
                match res {
                    Ok(resp) => {
                        // The loop's `total_timeout`/`stall_timeout` are checked
                        // before the `select!`, so neither can fire while this
                        // arm is awaiting: without the deadline here a peer that
                        // returns headers and then stalls the body would hang
                        // `run_upload` (and the run — `runner.rs` has no outer
                        // cap on it). `Limited` bounds the same read from above.
                        let _ = timeout(
                            Duration::from_secs_f64(stall_timeout),
                            Limited::new(resp.into_body(), BODY_CAP).collect(),
                        )
                        .await;
                        post_done = true;
                    }
                    Err(_) => {
                        post_err = true;
                    }
                }
                break;
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        let cur = sent.load(Ordering::Relaxed) as u64;
        let delta = cur.saturating_sub(prev);
        if delta > 0 {
            last_data = Instant::now();
            last_nonzero_sec = t0.elapsed().as_secs();
        }
        let cur_bps = delta as f64 / 0.5;
        peak = peak.max(cur_bps);
        prev = cur;
        if cur >= total_size {
            // Wait briefly for the server response
            if tokio::time::timeout(Duration::from_secs(5), &mut post_fut).await.is_ok() {
                post_done = true;
            }
            break;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let duration = t0.elapsed().as_secs_f64().max(0.001);
    let sent_total = sent.load(Ordering::Relaxed) as u64;
    let fully = total_size > 0 && sent_total as f64 >= total_size as f64 * 0.98;
    let avg = sent_total as f64 / duration;

    let status = if sent_total == 0 {
        TransferStatus::Blocked
    } else if fully && (post_done || !post_err) {
        TransferStatus::Ok
    } else if last_data.elapsed().as_secs_f64() >= stall_timeout || post_err {
        TransferStatus::Stalled
    } else {
        TransferStatus::Slow
    };

    TransferStats {
        status,
        avg_bps: avg,
        peak_bps: peak.max(avg),
        bytes_total: sent_total,
        duration,
        drop_at_sec: if status.is_stalled() { Some(last_nonzero_sec) } else { None },
    }
}

#[derive(Debug, Clone, Default)]
pub struct TelegramFullReport {
    pub download: TransferStats,
    pub upload: TransferStats,
    pub dc_results: Vec<TelegramDcResult>,
    pub dc_reachable: usize,
    pub dc_total: usize,
    /// "blocked" | "slow" | "partial" | "ok" | "error"
    pub verdict: String,
}

/// The combined verdict for the two transfer legs and the reachable-DC count:
/// `"blocked" | "slow" | "partial" | "ok" | "error"`.
///
/// Every pair of leg states is named, so a sixth [`TransferStatus`] cannot
/// compile until this table says what it means. The order is the contract: a
/// blocked leg outranks a stall, and a stall outranks the DC count.
fn transfer_verdict(
    download: TransferStatus,
    upload: TransferStatus,
    dc_reachable: usize,
    dc_total: usize,
) -> &'static str {
    let some_dcs_missing = dc_reachable > 0 && dc_reachable < dc_total;
    match (download, upload) {
        // A leg that moved nothing is the network being closed only when the DC
        // pings agree that nothing answers; with live DCs it is degradation.
        (TransferStatus::Blocked, _) | (_, TransferStatus::Blocked) if dc_reachable == 0 => "blocked",
        // A stall or a short transfer outranks everything below it.
        (TransferStatus::Slow | TransferStatus::Stalled, _)
        | (_, TransferStatus::Slow | TransferStatus::Stalled) => "slow",
        // Both legs ran: with a DC gone the network is only partial, with all of
        // them live the report is clean.
        (TransferStatus::Ok, TransferStatus::Ok) => {
            if some_dcs_missing {
                "partial"
            } else {
                "ok"
            }
        }
        // Neither leg is slow and none is blocked on a dead network: the DC count
        // separates a partly filtered network from a run that failed outright.
        (TransferStatus::Blocked | TransferStatus::Error, _)
        | (_, TransferStatus::Blocked | TransferStatus::Error) => {
            if some_dcs_missing {
                "partial"
            } else {
                "error"
            }
        }
    }
}

/// Full Telegram test: runs download, upload and the DC pings concurrently, then
/// folds the two transfers and the reachable-DC count into one verdict:
/// "blocked" | "slow" | "partial" | "ok" | "error".
pub async fn run_telegram_full(cfg: &AppConfig, phases: Option<PhaseProgress>) -> TelegramFullReport {
    let tick = phases
        .as_ref()
        .map(|p| (p.on_phase)(crate::PhaseId::Telegram, 3));
    let tick_dl = tick.clone();
    let tick_ul = tick.clone();
    let tick_dc = tick.clone();
    let (dl, ul, dc) = tokio::join!(
        async {
            let r = run_download(cfg).await;
            if let Some(t) = tick_dl.as_ref() {
                t();
            }
            r
        },
        async {
            let r = run_upload(cfg).await;
            if let Some(t) = tick_ul.as_ref() {
                t();
            }
            r
        },
        async {
            let r = probe_telegram_all_dcs(Duration::from_secs_f64(cfg.telegram_dc_ping_timeout)).await;
            if let Some(t) = tick_dc.as_ref() {
                t();
            }
            r
        },
    );
    let dc_reachable = dc.iter().filter(|d| d.available).count();
    let dc_total = dc.len();

    let verdict = transfer_verdict(dl.status, ul.status, dc_reachable, dc_total);

    TelegramFullReport {
        download: dl,
        upload: ul,
        dc_results: dc,
        dc_reachable,
        dc_total,
        verdict: verdict.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telegram_dc_list() {
        assert_eq!(TELEGRAM_DCS.len(), 5);
        assert_eq!(TELEGRAM_DCS[0].name, "DC1");
        assert_eq!(TELEGRAM_DCS[4].name, "DC5");
    }

    #[test]
    fn test_classify_transfer() {
        let (s, _) = classify_transfer(0, 1000, false, 1.0, 0);
        assert_eq!(s.as_str(), "blocked");
        let (s, _) = classify_transfer(1000, 1000, false, 1.0, 0);
        assert_eq!(s.as_str(), "ok");
        let (s, d) = classify_transfer(500, 1000, true, 10.0, 4);
        assert_eq!(s.as_str(), "stalled");
        assert_eq!(d, Some(4));
        let (s, _) = classify_transfer(500, 1000, false, 10.0, 4);
        assert_eq!(s.as_str(), "slow");
    }

    /// The wire tokens are frozen: `--json` writes the state through serde and
    /// the TUI prints `as_str()`, so the two spellings have to agree. A renamed
    /// variant that keeps `as_str()` would otherwise change the payload silently.
    #[test]
    fn test_transfer_status_wire_tokens() {
        for (status, token) in [
            (TransferStatus::Ok, "ok"),
            (TransferStatus::Slow, "slow"),
            (TransferStatus::Stalled, "stalled"),
            (TransferStatus::Blocked, "blocked"),
            (TransferStatus::Error, "error"),
        ] {
            assert_eq!(status.as_str(), token);
            assert_eq!(
                serde_json::to_string(&status).expect("a status serializes"),
                format!("\"{token}\"")
            );
        }
    }

    /// The verdict table, `dc_total = 5`. The guard order is the part a rewrite
    /// gets wrong: a blocked leg with live DCs is not a block, a stall outranks
    /// the DC count, and the DC count only downgrades a pair that ran.
    #[test]
    fn test_transfer_verdict_table() {
        for (dl, ul, dc, want) in [
            (TransferStatus::Blocked, TransferStatus::Blocked, 0, "blocked"),
            (TransferStatus::Blocked, TransferStatus::Ok, 0, "blocked"),
            (TransferStatus::Ok, TransferStatus::Blocked, 0, "blocked"),
            (TransferStatus::Blocked, TransferStatus::Stalled, 3, "slow"),
            (TransferStatus::Slow, TransferStatus::Ok, 5, "slow"),
            (TransferStatus::Stalled, TransferStatus::Ok, 5, "slow"),
            (TransferStatus::Ok, TransferStatus::Ok, 5, "ok"),
            (TransferStatus::Ok, TransferStatus::Ok, 3, "partial"),
            (TransferStatus::Ok, TransferStatus::Ok, 0, "ok"),
            (TransferStatus::Blocked, TransferStatus::Ok, 3, "partial"),
            (TransferStatus::Blocked, TransferStatus::Ok, 5, "error"),
            (TransferStatus::Error, TransferStatus::Ok, 3, "partial"),
            (TransferStatus::Error, TransferStatus::Ok, 5, "error"),
            (TransferStatus::Ok, TransferStatus::Error, 0, "error"),
        ] {
            assert_eq!(
                transfer_verdict(dl, ul, dc, 5),
                want,
                "{dl:?}/{ul:?} with {dc} of 5 DCs"
            );
        }
    }
}

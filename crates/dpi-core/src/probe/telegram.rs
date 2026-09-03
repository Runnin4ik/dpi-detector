//! Test 5: Telegram availability (mirrors `core/telegram_scanner.py`).
//!
//! Three parallel sub-tests: media download with stall detection,
//! 10 MB high-entropy upload with stall detection, and raw TCP pings
//! of DC1–DC5. Combined verdict: blocked / slow / partial / ok / error.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::config::AppConfig;
use crate::net::tls::create_insecure_dpi_tls_config;
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
    pub error: Option<String>,
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
            match timeout(timeout_dur, TcpStream::connect(sock_addr)).await {
                Ok(Ok(_stream)) => {
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
                    error: Some(e.to_string()),
                },
                Err(_) => TelegramDcResult {
                    name: dc.name.to_string(),
                    ip: dc.ip.to_string(),
                    region: dc.region.to_string(),
                    available: false,
                    latency_ms: None,
                    error: Some("SYN timeout".to_string()),
                },
            }
        }
        Err(e) => TelegramDcResult {
            name: dc.name.to_string(),
            ip: dc.ip.to_string(),
            region: dc.region.to_string(),
            available: false,
            latency_ms: None,
            error: Some(e.to_string()),
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

// ─── Speed formatting (mirrors _fmt_speed / _fmt_size) ───────────────────────

pub fn fmt_speed(bps: f64) -> String {
    if bps >= 1024.0 * 1024.0 {
        format!("{:>6.2} МБ/с", bps / (1024.0 * 1024.0))
    } else if bps >= 1024.0 {
        format!("{:>6.1} КБ/с", bps / 1024.0)
    } else {
        format!("{:>6.0} Б/с", bps)
    }
}

pub fn fmt_size(b: u64) -> String {
    if b >= 1024 * 1024 {
        format!("{:.2} МБ", b as f64 / (1024.0 * 1024.0))
    } else if b >= 1024 {
        format!("{:.1} КБ", b as f64 / 1024.0)
    } else {
        format!("{} Б", b)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransferStats {
    /// "ok" | "slow" | "stalled" | "blocked" | "error"
    pub status: String,
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
) -> (String, Option<u64>) {
    let fully = expected > 0 && total_bytes as f64 >= expected as f64 * 0.98;
    if total_bytes == 0 {
        ("blocked".to_string(), None)
    } else if fully {
        ("ok".to_string(), None)
    } else if stalled {
        ("stalled".to_string(), Some(last_active_sec))
    } else {
        ("slow".to_string(), None)
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
    let addr = tokio::net::lookup_host(format!("{}:443", host)).await.ok()?.next()?;
    let tcp = TcpStream::connect(addr).await.ok()?;
    let connector = TlsConnector::from(create_insecure_dpi_tls_config());
    let server_name = ServerName::try_from(host.to_string()).ok()?;
    let tls = connector.connect(server_name, tcp).await.ok()?;
    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
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
    let resp = sender.send_request(req).await.ok()?;
    let body = resp.into_body();
    // Keep the connection task alive via the body itself
    let noop = || {};
    Some((body, noop))
}

/// Media download with stall detection (mirrors `_run_download`).
pub async fn run_download(cfg: &AppConfig) -> TransferStats {
    let stall_timeout = cfg.telegram_stall_timeout;
    let total_timeout = cfg.telegram_total_timeout;
    let expected = (cfg.telegram_media_size_mb * 1024.0 * 1024.0) as u64;

    let (host, path) = match split_url(&cfg.telegram_media_url) {
        Some(v) => v,
        None => {
            return TransferStats { status: "error".into(), ..Default::default() };
        }
    };

    let t_start = Instant::now();
    let Some((mut body, _keep)) = tls_get(&host, &path, &cfg.user_agent).await else {
        return TransferStats { status: "blocked".into(), ..Default::default() };
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
    let denom = if status == "stalled" {
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
    sent: Arc<AtomicU64>,
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
        this.sent.fetch_add(n as u64, Ordering::Relaxed);
        Poll::Ready(Some(Ok(Frame::data(this.chunk.slice(..n)))))
    }
}

/// 10 MB upload with stall detection (mirrors `_run_upload`).
pub async fn run_upload(cfg: &AppConfig) -> TransferStats {
    let stall_timeout = cfg.telegram_stall_timeout;
    let total_timeout = cfg.telegram_total_timeout;
    let total_size = (cfg.telegram_upload_size_mb * 1024.0 * 1024.0) as u64;

    let sent = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // High-entropy 16 KB chunk (xorshift, mirrors os.urandom usage)
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
                return TransferStats { status: "error".into(), ..Default::default() };
            }
        },
        cfg.telegram_upload_port,
    );
    let tcp = match timeout(Duration::from_secs_f64(8.0), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            return TransferStats { status: "blocked".into(), duration: t0.elapsed().as_secs_f64(), ..Default::default() };
        }
    };
    // SNI = IP → rustls sends no SNI extension (raw TLS stall probe)
    let connector = TlsConnector::from(create_insecure_dpi_tls_config());
    let server_name = ServerName::IpAddress(rustls::pki_types::IpAddr::from(addr.ip()));
    let tls = match timeout(Duration::from_secs_f64(8.0), connector.connect(server_name, tcp)).await {
        Ok(Ok(s)) => s,
        _ => {
            return TransferStats { status: "blocked".into(), duration: t0.elapsed().as_secs_f64(), ..Default::default() };
        }
    };
    let io = TokioIo::new(tls);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(v) => v,
        Err(_) => {
            return TransferStats { status: "blocked".into(), duration: t0.elapsed().as_secs_f64(), ..Default::default() };
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
            return TransferStats { status: "error".into(), ..Default::default() };
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
                        let _ = resp.into_body().collect().await;
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
        let cur = sent.load(Ordering::Relaxed);
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
    let sent_total = sent.load(Ordering::Relaxed);
    let fully = total_size > 0 && sent_total as f64 >= total_size as f64 * 0.98;
    let avg = sent_total as f64 / duration;

    let status = if sent_total == 0 {
        "blocked"
    } else if fully && (post_done || !post_err) {
        "ok"
    } else if last_data.elapsed().as_secs_f64() >= stall_timeout || post_err {
        "stalled"
    } else {
        "slow"
    };

    TransferStats {
        status: status.to_string(),
        avg_bps: avg,
        peak_bps: peak.max(avg),
        bytes_total: sent_total,
        duration,
        drop_at_sec: if status == "stalled" { Some(last_nonzero_sec) } else { None },
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

/// Full Telegram test: download + upload + DC pings (mirrors run_telegram_test).
pub async fn run_telegram_full(cfg: &AppConfig, phases: Option<PhaseProgress>) -> TelegramFullReport {
    let tick = phases
        .as_ref()
        .map(|p| (p.on_phase)("Проверка доступности Telegram".to_string(), 3, true));
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

    let verdict = if (dl.status == "blocked" || ul.status == "blocked") && dc_reachable == 0 {
        "blocked"
    } else if dl.status == "stalled" || dl.status == "slow" || ul.status == "stalled" || ul.status == "slow" {
        "slow"
    } else if dc_reachable < dc_total && dc_reachable > 0 {
        "partial"
    } else if dl.status == "ok" && ul.status == "ok" {
        "ok"
    } else {
        "error"
    };

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
    fn test_fmt_speed() {
        assert!(fmt_speed(2.0 * 1024.0 * 1024.0).contains("МБ/с"));
        assert!(fmt_speed(1500.0).contains("КБ/с"));
        assert!(fmt_speed(500.0).contains("Б/с"));
    }

    #[test]
    fn test_classify_transfer() {
        let (s, _) = classify_transfer(0, 1000, false, 1.0, 0);
        assert_eq!(s, "blocked");
        let (s, _) = classify_transfer(1000, 1000, false, 1.0, 0);
        assert_eq!(s, "ok");
        let (s, d) = classify_transfer(500, 1000, true, 10.0, 4);
        assert_eq!(s, "stalled");
        assert_eq!(d, Some(4));
        let (s, _) = classify_transfer(500, 1000, false, 10.0, 4);
        assert_eq!(s, "slow");
    }
}

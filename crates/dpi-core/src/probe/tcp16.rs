//! Test 3: FAT-header TCP probe.
//!
//! Opens one keep-alive connection per target and sends `fat_chunks_count`
//! HEAD requests with a growing `X-Pad` header (`fat_chunk_size` bytes per
//! step, 10 × 4 KB = 40 KB total). A break inside the DPI window
//! (`tcp_block_min_kb`..`tcp_block_max_kb`) is reported as DETECTED.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use http_body_util::BodyExt;

use hyper::Method;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::classify::{
    classify_connect_error_full, classify_read_error, Detail, DpiStatus, ProbeMetrics,
};
use crate::config::AppConfig;
use crate::net::fingerprint::http_identity;
use crate::probe::http::{
    hyper_err_info, negotiated_h2, request_headers, HttpRequest, HttpSender,
};
use crate::net::tcp::{dial_tcp, DialError};
use crate::net::tls::{create_tls_config, TlsProfile};

fn random_pool(size: usize) -> Vec<u8> {
    // xorshift64* — deterministic PRNG, no extra deps, ASCII alphanumerics
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let v = state.wrapping_mul(0x2545F4914F6CDD1D);
        for b in v.to_le_bytes() {
            out.push(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[(b % 62) as usize]);
            if out.len() >= size {
                break;
            }
        }
    }
    out
}

async fn connect_fat_target(
    addr: SocketAddr,
    target_ip: IpAddr,
    sni: &str,
    use_tls: bool,
    cfg: &AppConfig,
) -> Result<HttpSender, (DpiStatus, Detail)> {
    let connect_stage = "tcp_connect";
    let tcp = match dial_tcp(&addr, Duration::from_secs_f64(cfg.fat_connect_timeout)).await {
        Ok(s) => s,
        Err(DialError::Io(e)) => {
            let msg = e.to_string();
            let (s, d) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, connect_stage);
            return Err((s, d));
        }
        Err(DialError::Timeout) => {
            return Err((DpiStatus::SynDropped, Detail::TcpSynTimeout));
        }
    };

    if use_tls {
        let server_name = if sni.is_empty() {
            ServerName::IpAddress(rustls::pki_types::IpAddr::from(target_ip))
        } else {
            match ServerName::try_from(sni.to_string()) {
                Ok(n) => n,
                Err(_) => ServerName::IpAddress(rustls::pki_types::IpAddr::from(target_ip)),
            }
        };
        let profile = TlsProfile::insecure(cfg.fingerprint());
        let tls_stream = match timeout(
            Duration::from_secs_f64(cfg.fat_connect_timeout),
            TlsConnector::from(create_tls_config(&profile)).connect(server_name, tcp),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let msg = e.to_string();
                let (s, d) = classify_connect_error_full(&msg, e.raw_os_error(), Some(e.kind()), 0, "tls_handshake");
                return Err((s, d));
            }
            Err(_) => {
                return Err((DpiStatus::TlsDropped, Detail::TlsHandshakeTimeout));
            }
        };
        let alpn_h2 = negotiated_h2(&tls_stream);
        let io = TokioIo::new(tls_stream);
        match HttpSender::handshake(io, alpn_h2, cfg.fingerprint()).await {
            Ok(sender) => Ok(sender),
            Err(e) => {
                let (msg, os_code, os_kind) = hyper_err_info(&e);
                let (s, d) = classify_connect_error_full(&msg, os_code, os_kind, 0, "tls_connected");
                Err((s, d))
            }
        }
    } else {
        let io = TokioIo::new(tcp);
        // No TLS, so no ALPN: HTTP/1.1 is the only protocol on the wire here.
        match HttpSender::handshake(io, false, cfg.fingerprint()).await {
            Ok(sender) => Ok(sender),
            Err(e) => {
                let (msg, os_code, os_kind) = hyper_err_info(&e);
                let (s, d) = classify_connect_error_full(&msg, os_code, os_kind, 0, "tcp_connect");
                Err((s, d))
            }
        }
    }
}

/// KB actually handed to the socket before the failing chunk, rounded up: the
/// detail reports the chunk the drop happened in, and cutting the remainder
/// (`i * chunk_size / 1024`) made a 16 KB mark read as `15KB` on the default
/// 4000-byte chunks.
fn kb_sent(chunks_sent: usize, chunk_size: usize) -> usize {
    (chunks_sent * chunk_size).div_ceil(1024)
}

/// Raw FAT probe. Returns (status, detail, rtt_secs).
pub async fn probe_tcp_16_20(
    ip: &str,
    port: u16,
    sni: &str,
    cfg: &AppConfig,
    hint_rtt: Option<f64>,
) -> (DpiStatus, Detail, Option<f64>) {
    let target_ip: IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => {
            return (DpiStatus::Err, Detail::Other(format!("bad IP: {}", ip)), None);
        }
    };
    let addr = SocketAddr::new(target_ip, port);
    let use_tls = port != 80;

    let chunks = cfg.fat_chunks_count.max(1);
    let chunk_size = cfg.fat_chunk_size.max(1);
    let min_detect_chunk =
        (cfg.tcp_block_min_kb * 1024).div_ceil(chunk_size as u64).max(1) as usize;

    // Dynamic read timeout: 3 × RTT clamped to 1.5 s..fat_read_timeout, seeded by the
    // hint or, when there is none, by the slowest of the first two measured RTTs.
    let mut dynamic_timeout = hint_rtt.map(|r| (r * 3.0).max(1.5).min(cfg.fat_read_timeout));
    let mut measured_rtt = hint_rtt;
    let mut rtt_samples: Vec<f64> = Vec::new();

    let pool = random_pool(cfg.fat_random_pool_size.max(chunk_size + 1));

    let host_val = if !sni.is_empty() {
        sni.to_string()
    } else if port == 80 || port == 443 {
        target_ip.to_string()
    } else {
        format!("{}:{}", target_ip, port)
    };

    let mut sender = match connect_fat_target(addr, target_ip, sni, use_tls, cfg).await {
        Ok(s) => s,
        Err((s, d)) => return (s, d, measured_rtt),
    };


    for i in 0..chunks {
        // If keep-alive connection was closed by peer or previous response, reconnect
        if sender.is_closed() {
            sender = match connect_fat_target(addr, target_ip, sni, use_tls, cfg).await {
                Ok(s) => s,
                Err((_s, d)) => {
                    if i < min_detect_chunk {
                        return (DpiStatus::Timeout, d, measured_rtt);
                    } else {
                        return (
                            DpiStatus::Tcp16Detected,
                            Detail::at_kb(d, kb_sent(i, chunk_size) as f64),
                            measured_rtt,
                        );
                    }
                }
            };
        }

        let pad_str = if i > 0 {
            let max_start = pool.len().saturating_sub(chunk_size);
            let start_idx = ((i * 7919) % max_start.max(1)).min(max_start);
            Some(String::from_utf8_lossy(&pool[start_idx..start_idx + chunk_size]).into_owned())
        } else {
            None
        };

        let make_req = |pad: Option<&str>| -> HttpRequest<'_> {
            let mut extras = vec![("Connection", "keep-alive".to_string())];
            if let Some(p) = pad {
                extras.push(("X-Pad", p.to_string()));
            }
            HttpRequest {
                method: Method::HEAD,
                host: &host_val,
                path: "/",
                headers: request_headers(
                    &http_identity(cfg.fingerprint()),
                    cfg.user_agent_for(cfg.fingerprint()),
                    extras,
                ),
            }
        };

        let req = make_req(pad_str.as_deref());
        let read_timeout = dynamic_timeout.unwrap_or(cfg.fat_read_timeout);
        let t0 = Instant::now();

        let mut res = timeout(Duration::from_secs_f64(read_timeout), sender.send(req)).await;

        // If connection was closed concurrently between requests, reconnect and retry this chunk once
        if let Ok(Err(ref e)) = res {
            let (emsg, _, _) = hyper_err_info(e);
            if e.is_canceled() || emsg.contains("canceled") || sender.is_closed() {
                if let Ok(new_sender) = connect_fat_target(addr, target_ip, sni, use_tls, cfg).await {
                    sender = new_sender;
                    let retry_req = make_req(pad_str.as_deref());
                    res = timeout(Duration::from_secs_f64(read_timeout), sender.send(retry_req)).await;
                }
            }
        }

        match res {
            Ok(Ok(resp)) => {
                let _ = resp.into_body().collect().await;
                let elapsed = t0.elapsed().as_secs_f64();
                if i == 0 && measured_rtt.is_none() {
                    measured_rtt = Some(elapsed);
                }
                if hint_rtt.is_none() && i < 2 {
                    rtt_samples.push(elapsed);
                    if rtt_samples.len() == 2 {
                        let base = rtt_samples.iter().cloned().reduce(f64::max).unwrap_or(elapsed);
                        dynamic_timeout = Some((base * 3.0).max(1.5).min(cfg.fat_read_timeout));
                    }
                }
                if cfg.fat_chunk_delay > 0.0 {
                    tokio::time::sleep(Duration::from_secs_f64(cfg.fat_chunk_delay)).await;
                }
            }
            Ok(Err(e)) => {
                let (msg, os_code, os_kind) = hyper_err_info(&e);
                let lower = msg.to_ascii_lowercase();
                let is_read_timeout = e.is_timeout() || lower.contains("timed out");
                if is_read_timeout {
                    let err_type = if lower.contains("write") { Detail::WriteTimeoutWord } else { Detail::ReadTimeoutWordCaps };
                    if i == 0 {
                        return (DpiStatus::ReadTimeout, err_type, measured_rtt);
                    }
                    if i < min_detect_chunk {
                        return (DpiStatus::Timeout, err_type, measured_rtt);
                    }
                    return (
                        DpiStatus::Tcp16Detected,
                        Detail::at_kb(err_type, kb_sent(i, chunk_size) as f64),
                        measured_rtt,
                    );
                }
                let (s, d) = classify_read_error(&msg, os_code, os_kind, 0);
                if i == 0 {
                    return (s, d, measured_rtt);
                }
                if i < min_detect_chunk {
                    return (DpiStatus::Timeout, d, measured_rtt);
                }
                return (
                    DpiStatus::Tcp16Detected,
                    Detail::at_kb(d, kb_sent(i, chunk_size) as f64),
                    measured_rtt,
                );
            }
            Err(_) => {
                if i == 0 {
                    return (DpiStatus::ReadTimeout, Detail::ReadTimeoutWordCaps, measured_rtt);
                }
                if i < min_detect_chunk {
                    return (DpiStatus::Timeout, Detail::ReadTimeoutWordCaps, measured_rtt);
                }
                return (
                    DpiStatus::Tcp16Detected,
                    Detail::at_kb(Detail::ReadTimeoutWordCaps, kb_sent(i, chunk_size) as f64),
                    measured_rtt,
                );
            }
        }
    }

    (DpiStatus::Ok, Detail::None, measured_rtt)
}

/// Semaphore-gated wrapper: takes one permit per probe, then runs `probe_tcp_16_20`.
pub async fn check_tcp_16_20(
    ip: &str,
    port: u16,
    sni: &str,
    cfg: &AppConfig,
    sem: &Semaphore,
    hint_rtt: Option<f64>,
) -> (DpiStatus, Detail, Option<f64>) {
    let _permit = crate::probe::permit(sem).await;
    probe_tcp_16_20(ip, port, sni, cfg, hint_rtt).await
}

/// Legacy single-shot probe kept for callers that only need ProbeMetrics.
/// Maps keepalive verdicts onto the metrics contract.
pub async fn probe_tcp16(target: SocketAddr, _payload_size: usize, timeout_dur: Duration) -> ProbeMetrics {
    let mut metrics = ProbeMetrics::default();
    let start = Instant::now();
    let cfg = AppConfig {
        fat_connect_timeout: timeout_dur.as_secs_f64(),
        fat_read_timeout: timeout_dur.as_secs_f64(),
        ..AppConfig::default()
    };
    let (status, detail, _rtt) =
        probe_tcp_16_20(&target.ip().to_string(), target.port(), &cfg.fat_default_sni.clone(), &cfg, None).await;
    metrics.duration_ms = start.elapsed().as_millis() as u64;
    metrics.status = match status {
        DpiStatus::Ok => DpiStatus::Ok,
        DpiStatus::Tcp16Detected => DpiStatus::Tcp16Detected,
        DpiStatus::Timeout | DpiStatus::ReadTimeout => DpiStatus::Tcp16Dropped,
        other => other,
    };
    metrics.detail = detail;
    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_pool_ascii() {
        let pool = random_pool(1000);
        assert_eq!(pool.len(), 1000);
        assert!(pool.iter().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_min_detect_chunk_math() {
        // 12 KB / 4 KB = chunk 3
        let chunk_size = 4000usize;
        let min_detect = (12u64 * 1024).div_ceil(chunk_size as u64).max(1) as usize;
        assert_eq!(min_detect, 4); // chunks are 0-based: the detect range starts at i>=4
    }

    /// The offset in the detail is the mark the drop happened at, not the last
    /// whole KB below it: 4 chunks of 4000 B are 16 KB (15.6 rounded down read
    /// as "15KB" and made the 16 KB test look off by one).
    #[test]
    fn test_kb_sent_rounds_up_to_the_mark() {
        assert_eq!(kb_sent(4, 4000), 16);
        assert_eq!(kb_sent(5, 4000), 20);
        assert_eq!(kb_sent(3, 4000), 12);
        assert_eq!(kb_sent(3, 1024), 3);
        assert_eq!(kb_sent(0, 4000), 0);
    }
}

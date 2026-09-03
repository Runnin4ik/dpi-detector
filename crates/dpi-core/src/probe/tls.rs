use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::connector::{DpiTlsConnector, RustlsConnector};
use crate::classify::{
    classify_connect_error, classify_tls_error, ConnectionStage, DpiProbeStream, DpiProbeTracker,
    DpiStatus, ProbeMetrics,
};

const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

/// Checks whether an HTTP redirect location points to a known DPI/ISP blockpage.
pub fn is_suspicious_redirect(location: &str) -> bool {
    let loc = location.to_ascii_lowercase();
    const BLOCKPAGE_SIGNATURES: &[&str] = &[
        "warning.rt.ru",
        "blocked.rt.ru",
        "block.mts.ru",
        "eais.rkn.gov.ru",
        "blackhole",
        "zapret",
        "blocked",
        "blockpage",
        "megafon.ru/blocked",
        "beeline.ru/blocked",
        "domru.ru/blocked",
    ];

    BLOCKPAGE_SIGNATURES.iter().any(|sig| loc.contains(sig))
}

/// Probes a domain over TLS / HTTPS and classifies the DPI state.
pub async fn probe_tls_domain<C: DpiTlsConnector>(
    domain: &str,
    target_ip: IpAddr,
    port: u16,
    timeout_dur: Duration,
    connector: &C,
) -> ProbeMetrics {
    let start = Instant::now();
    let tracker = DpiProbeTracker::new();
    let addr = SocketAddr::new(target_ip, port);
    let conn = connector;

    let probe_future = async {
        tracker.set_stage(ConnectionStage::TcpConnecting);
        let tcp = match TcpStream::connect(&addr).await {
            Ok(stream) => {
                tracker.set_stage(ConnectionStage::TcpConnected);
                stream
            }
            Err(err) => {
                let (status, detail) = classify_connect_error(Some(&err), false);
                tracker.record_error(status, detail);
                return Err(err.to_string());
            }
        };

        let probe_stream = DpiProbeStream::new(tcp, tracker.clone());
        let server_name = match ServerName::try_from(domain.to_string()) {
            Ok(name) => name,
            Err(err) => {
                let msg = format!("invalid domain for TLS SNI: {}", err);
                tracker.record_error(DpiStatus::Unknown, &msg);
                return Err(msg);
            }
        };

        let tls_stream = match conn.connect(server_name, probe_stream).await {
            Ok(stream) => {
                tracker.set_stage(ConnectionStage::TlsHandshakeDone);
                stream
            }
            Err(err) => {
                let err_str = err.to_string();
                let lock = tracker.state.lock();
                let (status, detail) = classify_tls_error(
                    lock.stage,
                    lock.bytes_sent,
                    lock.bytes_recv,
                    &err_str,
                    false,
                );
                drop(lock);
                tracker.record_error(status, detail);
                return Err(err_str);
            }
        };

        // Send minimal HTTP GET /
        tracker.set_stage(ConnectionStage::HttpPayload);
        let io = TokioIo::new(tls_stream);
        let (mut sender, connection) = match hyper::client::conn::http1::handshake(io).await {
            Ok(res) => res,
            Err(err) => {
                tracker.record_error(DpiStatus::Unknown, format!("HTTP handshake failed: {}", err));
                return Err(err.to_string());
            }
        };

        tokio::spawn(async move {
            let _ = connection.await;
        });

        let req = match Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(HOST, domain)
            .header(USER_AGENT, DEFAULT_USER_AGENT)
            .body(Full::new(Bytes::new()))
        {
            Ok(r) => r,
            Err(err) => {
                tracker.record_error(DpiStatus::Unknown, err.to_string());
                return Err(err.to_string());
            }
        };

        let resp = match sender.send_request(req).await {
            Ok(r) => r,
            Err(err) => {
                tracker.record_error(DpiStatus::Unknown, format!("HTTP request failed: {}", err));
                return Err(err.to_string());
            }
        };

        // Check for suspicious redirect location headers
        if let Some(loc) = resp.headers().get("location") {
            if let Ok(loc_str) = loc.to_str() {
                if is_suspicious_redirect(loc_str) {
                    tracker.record_error(
                        DpiStatus::HttpBlocked,
                        format!("ISP blockpage redirect detected: {}", loc_str),
                    );
                    return Ok(());
                }
            }
        }

        let _ = resp.into_body().collect().await;
        Ok(())
    };

    match timeout(timeout_dur, probe_future).await {
        Ok(Ok(())) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let mut metrics = tracker.get_metrics(elapsed);
            if metrics.status == DpiStatus::Unknown {
                metrics.status = DpiStatus::Ok;
            }
            metrics
        }
        Ok(Err(_)) => {
            let elapsed = start.elapsed().as_millis() as u64;
            tracker.get_metrics(elapsed)
        }
        Err(_) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let lock = tracker.state.lock();
            let (status, detail) = classify_tls_error(
                lock.stage,
                lock.bytes_sent,
                lock.bytes_recv,
                "timeout",
                true,
            );
            drop(lock);
            tracker.record_error(status, detail);
            tracker.get_metrics(elapsed)
        }
    }
}

/// Probes a domain with the default insecure DPI TLS connector.
pub async fn probe_tls_domain_default(
    domain: &str,
    target_ip: IpAddr,
    port: u16,
    timeout_dur: Duration,
) -> ProbeMetrics {
    let connector = RustlsConnector::new_insecure();
    probe_tls_domain(domain, target_ip, port, timeout_dur, &connector).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_suspicious_redirect() {
        assert!(is_suspicious_redirect("http://warning.rt.ru/blocked"));
        assert!(is_suspicious_redirect("https://eais.rkn.gov.ru/"));
        assert!(is_suspicious_redirect("http://block.mts.ru/index.html"));
        assert!(!is_suspicious_redirect("https://example.com/login"));
        assert!(!is_suspicious_redirect("/relative/path"));
    }
}

use std::net::IpAddr;
use std::time::{Duration, Instant};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

use super::types::{DnsError, DnsRecord};
use super::wire::{build_dns_query, parse_dns_response, QTYPE_A};
use crate::config::AppConfig;
use crate::net::tls::create_verifying_doh_tls_config;

pub enum DohSender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl DohSender {
    pub async fn send_request(&mut self, req: Request<Full<Bytes>>) -> Result<hyper::Response<hyper::body::Incoming>, DnsError> {
        match self {
            DohSender::H1(s) => s.send_request(req).await.map_err(|e| DnsError::Io(e.to_string())),
            DohSender::H2(s) => s.send_request(req).await.map_err(|e| DnsError::Io(e.to_string())),
        }
    }
}

/// Opens one verifying-TLS HTTPS (HTTP/2 with HTTP/1.1 fallback) connection to a DoH endpoint
/// (mirrors the single-client-per-server DoH Wire design).
pub async fn doh_connect(endpoint_url: &str, timeout_dur: Duration) -> Result<(DohSender, String, String), DnsError> {
    let url = Url::parse(endpoint_url)
        .map_err(|e| DnsError::Io(format!("invalid DoH URL: {}", e)))?;

    let host = url
        .host_str()
        .ok_or_else(|| DnsError::Io("missing DoH host".to_string()))?
        .to_string();
    let port = url.port().unwrap_or(443);

    // Per-stage timeouts (mirrors httpx per-operation timeout + trace stages):
    // a stall surfaces as its stage token (SYN DROP / TLS DROP), not a flat timeout.
    let addrs_iter = timeout(timeout_dur, tokio::net::lookup_host(format!("{}:{}", host, port)))
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: "resolve",
            detail: "lookup timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: "resolve",
            detail: e.to_string(),
        })?;
    let addrs: Vec<std::net::SocketAddr> = addrs_iter.collect();
    // Prefer IPv4 unless user specifically requested IPv6 (mirrors Python get_resolved_ip)
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| DnsError::ConnectFault {
            stage: "resolve",
            detail: "no address".to_string(),
        })?;
    let tcp = timeout(timeout_dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: "tcp_connect",
            detail: "connect timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: "tcp_connect",
            detail: e.to_string(),
        })?;
    let _ = tcp.set_nodelay(true);

    let tls_config = create_verifying_doh_tls_config();
    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| DnsError::Io(format!("invalid TLS server name '{}': {}", host, e)))?;

    let tls_stream = timeout(timeout_dur, connector.connect(server_name, tcp))
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: "tls_handshake",
            detail: "handshake timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: "tls_handshake",
            detail: e.to_string(),
        })?;
    let alpn = tls_stream.get_ref().1.alpn_protocol();
    let is_h2 = alpn == Some(b"h2");
    let io = TokioIo::new(tls_stream);

    let sender = if is_h2 {
        let (sender, conn) = timeout(
            timeout_dur,
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new()).handshake(io),
        )
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: "connected",
            detail: "HTTP/2 handshake timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: "connected",
            detail: e.to_string(),
        })?;
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("DoH HTTP/2 connection error: {:?}", err);
            }
        });
        DohSender::H2(sender)
    } else {
        let (sender, conn) = timeout(timeout_dur, hyper::client::conn::http1::handshake(io))
            .await
            .map_err(|_| DnsError::ConnectFault {
                stage: "connected",
                detail: "HTTP handshake timed out".to_string(),
            })?
            .map_err(|e| DnsError::ConnectFault {
                stage: "connected",
                detail: e.to_string(),
            })?;
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("DoH HTTP/1 connection error: {:?}", err);
            }
        });
        DohSender::H1(sender)
    };

    Ok((sender, host, url.path().to_string()))
}

async fn send_doh(
    sender: &mut DohSender,
    host: &str,
    path: &str,
    query_data: &[u8],
    user_agent: &str,
) -> Result<Bytes, DnsError> {
    // POST first (mirrors _probe_doh_wire)
    let full_uri = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("https://{}{}", host, path)
    };
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(&full_uri)
        .header(CONTENT_TYPE, "application/dns-message")
        .header(ACCEPT, "application/dns-message")
        .header(USER_AGENT, user_agent);
    if matches!(sender, DohSender::H1(_)) {
        builder = builder.header(HOST, host);
    }
    let req = builder
        .body(Full::new(Bytes::copy_from_slice(query_data)))
        .map_err(|e| DnsError::Io(e.to_string()))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| DnsError::Io(e.to_string()))?;

    if resp.status().is_success() {
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| DnsError::Io(e.to_string()))?
            .to_bytes();
        return Ok(body);
    }
    let post_status = resp.status().as_u16();

    // GET ?dns= fallback (mirrors the Python POST→GET retry)
    let b64 = URL_SAFE_NO_PAD.encode(query_data);
    let full_get_uri = if path.starts_with("http://") || path.starts_with("https://") {
        format!("{}?dns={}", path, b64)
    } else {
        format!("https://{}{}?dns={}", host, path, b64)
    };
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(&full_get_uri)
        .header(ACCEPT, "application/dns-message")
        .header(USER_AGENT, user_agent);
    if matches!(sender, DohSender::H1(_)) {
        builder = builder.header(HOST, host);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| DnsError::Io(e.to_string()))?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| DnsError::Io(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(DnsError::DohHttp(post_status));
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| DnsError::Io(e.to_string()))?
        .to_bytes();
    Ok(body)
}
/// A reused DoH connection to one resolver (one TLS connection, sequential
/// queries — mirrors the single-client `_probe_doh_wire` design).
pub struct DohSession {
    sender: DohSender,
    host: String,
    path: String,
    user_agent: String,
}

impl DohSession {
    pub async fn connect(endpoint_url: &str, timeout_dur: Duration) -> Result<Self, DnsError> {
        let cfg = AppConfig::default();
        let (sender, host, path) = doh_connect(endpoint_url, timeout_dur).await?;
        Ok(Self { sender, host, path, user_agent: cfg.user_agent })
    }
    pub async fn query(&mut self, domain: &str, timeout_dur: Duration) -> Result<(Vec<IpAddr>, f64), DnsError> {
        let tx_id = rand::random::<u16>();
        let query_data = build_dns_query(domain, QTYPE_A, Some(tx_id))?;
        let start = Instant::now();
        let body_fut = send_doh(&mut self.sender, &self.host, &self.path, &query_data, &self.user_agent);
        let body = timeout(timeout_dur, body_fut).await.map_err(|_| DnsError::Timeout)??;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let parsed = parse_dns_response(&body, Some(tx_id))?;
        let mut ips = Vec::new();
        for ans in parsed.answers {
            match ans {
                DnsRecord::A(v4) => ips.push(IpAddr::V4(v4)),
                DnsRecord::AAAA(v6) => ips.push(IpAddr::V6(v6)),
                _ => {}
            }
        }
        Ok((ips, latency_ms))
    }
}

/// Executes a raw DoH (RFC 8484) wire query (POST with GET fallback).
pub async fn query_doh_raw(
    endpoint_url: &str,
    query_data: &[u8],
    timeout_dur: Duration,
) -> Result<Bytes, DnsError> {
    let cfg = AppConfig::default();
    let (mut sender, host, path) = doh_connect(endpoint_url, timeout_dur).await?;
    let execute = send_doh(&mut sender, &host, &path, query_data, &cfg.user_agent);
    timeout(timeout_dur, execute)
        .await
        .map_err(|_| DnsError::Timeout)?
}

/// Queries a DNS-over-HTTPS resolver via RFC 8484 (POST wireformat query for A/AAAA).
pub async fn probe_doh_dns(
    endpoint_url: &str,
    domain: &str,
    timeout_dur: Duration,
) -> Result<(Vec<IpAddr>, f64), DnsError> {
    let tx_id = rand::random::<u16>();
    let query_data = build_dns_query(domain, QTYPE_A, Some(tx_id))?;

    let start = Instant::now();
    let body = query_doh_raw(endpoint_url, &query_data, timeout_dur).await?;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let parsed = parse_dns_response(&body, Some(tx_id))?;
    let mut ips = Vec::new();
    for ans in parsed.answers {
        match ans {
            DnsRecord::A(v4) => ips.push(IpAddr::V4(v4)),
            DnsRecord::AAAA(v6) => ips.push(IpAddr::V6(v6)),
            _ => {}
        }
    }
    Ok((ips, latency_ms))
}

/// Queries a DoH resolver for TXT records (e.g. for Team Cymru ASN lookups).
pub async fn query_doh_txt(
    endpoint_url: &str,
    domain: &str,
    timeout_dur: Duration,
) -> Result<Vec<String>, DnsError> {
    use super::wire::QTYPE_TXT;
    let tx_id = rand::random::<u16>();
    let query_data = build_dns_query(domain, QTYPE_TXT, Some(tx_id))?;

    let body = query_doh_raw(endpoint_url, &query_data, timeout_dur).await?;
    let parsed = parse_dns_response(&body, Some(tx_id))?;

    let mut txts = Vec::new();
    for ans in parsed.answers {
        if let DnsRecord::TXT(parts) = ans {
            txts.extend(parts);
        }
    }

    Ok(txts)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_doh_connect_h2() {
        let mut sess = DohSession::connect("https://dns.google/dns-query", Duration::from_secs(5))
            .await
            .expect("Google DoH connect");
        let (ips, lat) = sess.query("google.com", Duration::from_secs(5))
            .await
            .expect("Google DoH query");
        assert!(!ips.is_empty());
        assert!(lat > 0.0);
    }
}

use std::net::IpAddr;
use std::time::{Duration, Instant};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use url::Url;

use super::resolve::resolve_host;
use super::types::{DnsError, DnsRecord};
use super::wire::{build_dns_query, parse_dns_response, QTYPE_A};
use crate::classify::ConnectStage;
use crate::config::AppConfig;
use crate::net::tcp::set_no_delay;
use crate::net::tls::{create_tls_config, TlsProfile};

/// The transport half of one DoH connection: one variant per protocol the
/// handshake negotiated. `pub(crate)`, not `pub`: both variants are `hyper` types,
/// and `hyper` here is a `[patch.crates-io]` fork (root `Cargo.toml`), so in a
/// public signature the fork becomes part of dpi-core's API — swapping it would
/// break callers instead of rebuilding them. Nothing outside this crate names the
/// type; `DohSession` is what the probes hold.
pub(crate) enum DohSender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl DohSender {
    pub(crate) async fn send_request(&mut self, req: Request<Full<Bytes>>) -> Result<hyper::Response<hyper::body::Incoming>, DnsError> {
        match self {
            DohSender::H1(s) => s.send_request(req).await.map_err(|e| DnsError::Io(e.to_string())),
            DohSender::H2(s) => s.send_request(req).await.map_err(|e| DnsError::Io(e.to_string())),
        }
    }
}

/// Opens one verifying-TLS HTTPS (HTTP/2 with HTTP/1.1 fallback) connection to a DoH endpoint.
/// The caller keeps that single connection for every query to the server.
/// `pub(crate)`, like the `DohSender` it returns: its variants are vendored `hyper` types.
pub(crate) async fn doh_connect(endpoint_url: &str, timeout_dur: Duration) -> Result<(DohSender, String, String), DnsError> {
    let url = Url::parse(endpoint_url)
        .map_err(|e| DnsError::Io(format!("invalid DoH URL: {}", e)))?;

    let host = url
        .host_str()
        .ok_or_else(|| DnsError::Io("missing DoH host".to_string()))?
        .to_string();
    let port = url.port().unwrap_or(443);

    // Per-stage timeouts: each connection step gets the full window, so a stall
    // surfaces as its stage token (SYN DROP / TLS DROP), not a flat timeout.
    let addrs: Vec<std::net::SocketAddr> = timeout(timeout_dur, resolve_host(&host, port, timeout_dur))
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: ConnectStage::Resolve,
            detail: "lookup timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: ConnectStage::Resolve,
            detail: e.to_string(),
        })?;
    // Prefer IPv4 unless the user specifically requested IPv6; otherwise
    // take the first resolved address.
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| DnsError::ConnectFault {
            stage: ConnectStage::Resolve,
            detail: "no address".to_string(),
        })?;
    let tcp = timeout(timeout_dur, crate::net::bind::tcp_connect(&addr))
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: ConnectStage::TcpConnect,
            detail: "connect timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: ConnectStage::TcpConnect,
            detail: e.to_string(),
        })?;
    set_no_delay(&tcp);

    // DoH (RFC 8484) over the system roots, offering h2 first, then http/1.1.
    let tls_config = create_tls_config(
        &TlsProfile::verifying().alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    );
    let connector = TlsConnector::from(tls_config);
    let server_name = ServerName::try_from(host.clone())
        .map_err(|e| DnsError::Io(format!("invalid TLS server name '{}': {}", host, e)))?;

    let tls_stream = timeout(timeout_dur, connector.connect(server_name, tcp))
        .await
        .map_err(|_| DnsError::ConnectFault {
            stage: ConnectStage::TlsHandshake,
            detail: "handshake timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: ConnectStage::TlsHandshake,
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
            stage: ConnectStage::Connected,
            detail: "HTTP/2 handshake timed out".to_string(),
        })?
        .map_err(|e| DnsError::ConnectFault {
            stage: ConnectStage::Connected,
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
                stage: ConnectStage::Connected,
                detail: "HTTP handshake timed out".to_string(),
            })?
            .map_err(|e| DnsError::ConnectFault {
                stage: ConnectStage::Connected,
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

/// A DoH response body *is* one DNS message, and a DNS message is at most
/// 65 535 bytes on the wire (the 16-bit length prefix of RFC 1035 §4.2.2), so
/// 64 KiB is the whole of it and anything past that is a broken or hostile
/// resolver. The cap stops such a server from making the tool buffer an
/// arbitrary stream; same shape as `net::http_client`'s `MAX_BODY`.
const MAX_BODY: usize = 1 << 16;

async fn send_doh(
    sender: &mut DohSender,
    host: &str,
    path: &str,
    query_data: &[u8],
    user_agent: &str,
) -> Result<Bytes, DnsError> {
    // POST first; a non-2xx status falls through to the GET form below.
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
        let body = Limited::new(resp.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| DnsError::Io(e.to_string()))?
            .to_bytes();
        return Ok(body);
    }
    let post_status = resp.status().as_u16();

    // GET ?dns= fallback with the unpadded base64url query; if this one also
    // fails, the error carries the status the POST returned.
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
    let body = Limited::new(resp.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|e| DnsError::Io(e.to_string()))?
        .to_bytes();
    Ok(body)
}
/// A reused DoH connection to one resolver (one TLS connection, sequential
/// queries).
pub struct DohSession {
    sender: DohSender,
    host: String,
    path: String,
    user_agent: String,
}

impl DohSession {
    /// Whether the endpoint negotiated HTTP/2. Multiplexed streams are
    /// independent, so a request may be abandoned without harming the ones
    /// after it; on HTTP/1.1 an abandoned request poisons the whole connection,
    /// which is why callers must not cut a request short on h1.
    pub fn is_h2(&self) -> bool {
        matches!(self.sender, DohSender::H2(_))
    }

    /// Whether the connection can no longer carry a request. A dropped HTTP/1.1
    /// response future leaves hyper unable to resynchronise the stream, so the
    /// connection is closed and every further request fails immediately.
    pub fn is_closed(&self) -> bool {
        match &self.sender {
            DohSender::H1(s) => s.is_closed(),
            DohSender::H2(s) => s.is_closed(),
        }
    }

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
        Ok((parsed.collect_ips(), latency_ms))
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
    Ok((parsed.collect_ips(), latency_ms))
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

    #[cfg(feature = "live-network")]
    use super::*;

    /// The only test in this workspace that reaches the real internet, and
    /// `dns.google` is exactly what the networks this tool is built to diagnose
    /// block. Behind `live-network` so the default `cargo test` runs air-gapped:
    /// otherwise a runner whose egress is blocked or rate-limited reddens the tree
    /// with no code change. `cargo test -p dpi-core --features live-network`.
    #[cfg(feature = "live-network")]
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

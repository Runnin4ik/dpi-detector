//! What does `quinn` see on the host list this repository's QUIC column tests?
//!
//! Same hosts, same window (8 s, the value measured for the probe), and the
//! outcome classified the way the column classifies it: a completed handshake,
//! a stateless reset, a close with a code, a timeout. The interesting question
//! is not whether it connects - it will - but what it says about the endpoints
//! this probe gets wrong, and in particular whether an endpoint that answers
//! with a packet the client cannot decrypt is distinguishable from silence.
//!
//! Run:  cargo run --release            (from this directory)
//!       cargo run --release -- host... (a subset)

use std::time::{Duration, Instant};

use quinn::{ConnectionError, Endpoint, TransportConfig};

const IDLE: Duration = Duration::from_secs(8);

fn transport() -> TransportConfig {
    let mut config = TransportConfig::default();
    config.max_idle_timeout(Some(IDLE.try_into().expect("8 s fits")));
    config
}

fn client_config() -> quinn::ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    // The endpoint's certificate is not the subject: a diagnostic client must
    // reach the same verdict a browser does on a host whose chain it cannot
    // verify.
    crypto
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(AcceptAny));
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quinn can use rustls");
    let mut config = quinn::ClientConfig::new(std::sync::Arc::new(quic));
    config.transport_config(std::sync::Arc::new(transport()));
    config
}

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512, ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ED25519,
        ]
    }
}

/// One host, in the vocabulary the column uses.
async fn probe(endpoint: &Endpoint, host: &str, addr: std::net::SocketAddr) -> String {
    let started = Instant::now();
    let connecting = match endpoint.connect_with(client_config(), addr, host) {
        Ok(connecting) => connecting,
        Err(error) => return format!("connect: {error}"),
    };
    match connecting.await {
        Ok(connection) => {
            let stats = connection.stats();
            let elapsed = started.elapsed().as_secs_f32();
            connection.close(0u32.into(), b"done");
            format!(
                "ok {elapsed:.2}s udp_rx={} crypto_rx={} udp_tx={}",
                stats.udp_rx.datagrams, stats.frame_rx.crypto, stats.udp_tx.datagrams
            )
        }
        Err(error) => {
            let elapsed = started.elapsed().as_secs_f32();
            let kind = match &error {
                ConnectionError::Reset => "stateless_reset".to_owned(),
                ConnectionError::TimedOut => "timeout".to_owned(),
                ConnectionError::VersionMismatch => "version_negotiation".to_owned(),
                ConnectionError::ConnectionClosed(close) => format!(
                    "close_{} ({})",
                    close.error_code,
                    String::from_utf8_lossy(&close.reason)
                ),
                ConnectionError::ApplicationClosed(close) => format!(
                    "application_close_{} ({})",
                    close.error_code,
                    String::from_utf8_lossy(&close.reason)
                ),
                ConnectionError::TransportError(transport) => {
                    format!("transport_error_{} ({})", transport.code, transport.reason)
                }
                other => format!("{other}"),
            };
            format!("{kind} {elapsed:.2}s")
        }
    }
}

async fn resolve(host: &str) -> Option<std::net::SocketAddr> {
    tokio::net::lookup_host((host, 443)).await.ok()?.next()
}

#[tokio::main]
async fn main() {
    // `ring` as the process-wide provider: rustls refuses to guess when it
    // cannot see exactly one, and quinn's handshake runs through it.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("no other provider installed");
    let listed: Vec<String> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            let listing = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/quic/hosts.txt");
            std::fs::read_to_string(listing)
                .expect("scripts/quic/hosts.txt")
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_owned)
                .collect()
        } else {
            args
        }
    };

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("bind address")).expect("endpoint");
    endpoint.set_default_client_config(client_config());

    for host in &listed {
        let Some(addr) = resolve(host).await else {
            println!("{host:24} resolve failed");
            continue;
        };
        let outcome = probe(&endpoint, host, addr).await;
        println!("{host:24} {addr:22} {outcome}");
    }
}

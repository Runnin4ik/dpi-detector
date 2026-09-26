//! The QUIC column run through `quinn` instead of the hand-written Initial.
//!
//! An experiment, not a candidate. `quinn` hands the handshake to `rustls` and
//! requires a QUIC-capable crypto provider; this tree's provider
//! (`rustls-rustcrypto`) declares `quic: None` and its QUIC functions are
//! `todo!()`, so the client below is built on quinn's own default provider,
//! `ring` — assembly, no MIPS target, outside Rule 1. The `quinn-probe` feature
//! is what pulls it in, and enabling the feature *is* the measurement.
//!
//! The outcome mapping deliberately mirrors the hand-written probe's vocabulary
//! (`QuicCheck`, `DpiStatus`, `Detail`), so the two implementations can be
//! compared row by row on the same host list.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::{ClientConfig, ConnectionError, Endpoint, TransportConfig};

use super::QuicCheck;
use crate::classify::{Detail, DpiStatus};
use crate::config::AppConfig;

/// The port the column dials, and the ALPN an HTTP/3 client offers.
const QUIC_PORT: u16 = 443;
const ALPN: &[u8] = b"h3";

/// Why the handshake did not complete.
enum Outcome {
    /// The endpoint said something, and this is quinn's classification of it.
    Peer(ConnectionError),
    /// Our side failed before the wire (bind, configuration). Not a verdict
    /// about the endpoint, so it is reported the way the hand-written probe
    /// reports a transport failure of its own.
    Local(String),
}

/// One domain: the same signature as `quic::check_domain_quic`, so the caller can
/// swap one implementation for the other.
pub async fn check(domain: &str, target: IpAddr, cfg: &AppConfig) -> QuicCheck {
    let started = Instant::now();
    let window = Duration::from_secs_f64(cfg.quic_timeout.max(0.1));
    let addr = SocketAddr::new(target, QUIC_PORT);
    let (status, detail) = match handshake(addr, domain, window).await {
        Ok(()) => (DpiStatus::QuicOk, Detail::QuicServerHello),
        Err(Outcome::Peer(error)) => classify(&error),
        Err(Outcome::Local(message)) => (DpiStatus::Err, Detail::Other(message)),
    };
    QuicCheck { status, detail, elapsed: started.elapsed().as_secs_f64() }
}

/// quinn's outcome in the column's vocabulary. The close codes are the same
/// numbers the hand-written probe reads off the wire (`quic_close_296` is a TLS
/// `handshake_failure`), which is what makes the two comparable.
fn classify(error: &ConnectionError) -> (DpiStatus, Detail) {
    match error {
        ConnectionError::Reset => (DpiStatus::QuicClosed, Detail::QuicReset),
        ConnectionError::TimedOut => (DpiStatus::QuicDrop, Detail::QuicTimeout),
        ConnectionError::VersionMismatch => (DpiStatus::QuicClosed, Detail::QuicVersionNegotiation),
        ConnectionError::ConnectionClosed(close) => close_code(u64::from(close.error_code)),
        ConnectionError::ApplicationClosed(close) => close_code(close.error_code.into_inner()),
        ConnectionError::TransportError(error) => close_code(u64::from(error.code)),
        // `LocallyClosed` and `CidsExhausted` are our own doing, not the
        // endpoint's: reported as such rather than as a verdict about the host.
        other => (DpiStatus::Err, Detail::Other(format!("quinn: {other}"))),
    }
}

fn close_code(code: u64) -> (DpiStatus, Detail) {
    (DpiStatus::QuicClosed, Detail::QuicClose { error_code: code })
}

/// One address, one window, one verdict.
async fn handshake(addr: SocketAddr, sni: &str, window: Duration) -> Result<(), Outcome> {
    let mut transport = TransportConfig::default();
    if let Ok(idle) = window.try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto()?)
        .map_err(|error| Outcome::Local(format!("quinn: {error}")))?;
    let mut client = ClientConfig::new(Arc::new(quic));
    client.transport_config(Arc::new(transport));

    let endpoint = Endpoint::client("0.0.0.0:0".parse().expect("bind address"))
        .map_err(|error| Outcome::Local(format!("quinn: {error}")))?;
    let connecting = endpoint
        .connect_with(client, addr, sni)
        .map_err(|error| Outcome::Local(format!("quinn: {error}")))?;
    // Dropping the endpoint closes it; the connection's own result is what the
    // column reports.
    connecting.await.map(|_| ()).map_err(Outcome::Peer)
}

fn client_crypto() -> Result<rustls::ClientConfig, Outcome> {
    // `ring`, explicitly: this tree's provider cannot do QUIC at all, so the
    // experiment cannot use it. Built per call rather than installed process
    // wide — a library has no business setting a global provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| Outcome::Local(format!("quinn: {error}")))?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    // The endpoint's chain is not the subject: the column is about the path, and
    // a browser reaches a verdict on a host whose chain it cannot verify too.
    config.dangerous().set_certificate_verifier(Arc::new(AcceptAnyCertificate));
    Ok(config)
}

/// Accepts every chain, for the reason above.
#[derive(Debug)]
struct AcceptAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
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
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
        ]
    }
}

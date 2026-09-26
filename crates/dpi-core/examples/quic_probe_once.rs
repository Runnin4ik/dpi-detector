//! One QUIC Initial against a chosen address and fingerprint: the stand's client.
//!
//! The detector's own CLI never probes a loopback address (`127.0.0.1` is
//! classified as a local IP), so this is how the probe is pointed at the lab's
//! UDP tap (`tools/fingerprint/utls/lab --quic-tap-port 443 --quic-upstream
//! <host>:443`) or at a local endpoint under test.
//!
//! `cargo run -p dpi-core --example quic_probe_once -- 127.0.0.1 [fingerprint]`

use std::net::IpAddr;

use dpi_core::config::AppConfig;
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::probe::quic::check_domain_quic;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1".to_string());
    let target: IpAddr = arg.parse().expect("an IP address");
    let mut cfg = AppConfig::default();
    if let Some(name) = std::env::args().nth(2) {
        let fingerprint = TlsFingerprint::parse(&name).expect("a known fingerprint");
        cfg.tls_fingerprint = fingerprint.code().to_string();
    }
    println!("fingerprint: {}", cfg.fingerprint().code());
    let check = check_domain_quic("localhost", target, &cfg).await;
    println!("status: {:?}", check.status);
    println!("token:  {}", check.status.as_str());
    println!("detail: {:?}", check.detail);
    println!("elapsed: {:.2}s", check.elapsed);
}

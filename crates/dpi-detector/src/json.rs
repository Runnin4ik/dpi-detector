//! The `--json` payload.
//!
//! One struct per test describes the machine-readable output in a single place:
//! `serde` writes the keys, the statuses and details come from the core's
//! `Serialize` impls (`DpiStatus` is its snake_case token, `Detail` its code), and
//! a field that no test filled is simply absent from `results`.

use std::collections::BTreeMap;

use dpi_core::classify::Detail;
use serde::Serialize;

use crate::render::TcpRow;

/// Wire version of the payload; bump it when a key changes meaning.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub version: &'static str,
    pub profile: &'static str,
    pub tls_fingerprint: String,
    pub results: Results,
}

/// One field per test, filled only when that test ran. The field order is the
/// order the tests appear in the menu.
#[derive(Serialize, Default)]
pub struct Results {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_info: Option<NetworkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_availability: Option<DnsAvailability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_inspection: Option<Vec<DomainRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp16: Option<Vec<TcpRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist_sni: Option<WhitelistSni>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram: Option<Telegram>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_burst: Option<FingerprintBurst>,
}

#[derive(Serialize)]
pub struct Endpoint {
    pub ip: String,
    pub latency_ms: u64,
}

#[derive(Serialize)]
pub struct NetworkInfo {
    pub ipv4: Option<Endpoint>,
    pub ipv6: Option<Endpoint>,
    pub v4_asn: Option<String>,
    pub v4_org: Option<String>,
    pub v4_cc: Option<String>,
    pub upstream: Option<String>,
    pub system_dns: Vec<String>,
    pub gateway: Option<String>,
    pub tun: Vec<String>,
    pub bypass_tools: Vec<String>,
}

#[derive(Serialize)]
pub struct DnsAvailability {
    pub doh_ok: usize,
    pub doh_total: usize,
    pub dot_ok: usize,
    pub dot_total: usize,
    pub udp_ok: usize,
    pub udp_total: usize,
    pub hijacked_brands: Vec<String>,
    pub resolvers_total: usize,
    pub subst_sub: usize,
    pub subst_total: usize,
    /// Of the substituted UDP answers, how many came back inside the fake-ip
    /// range (198.18.0.0/15) — a proxy or VPN answering instead of the resolver.
    /// The table prints them as their own line (`FakeIP responses`) and counts
    /// them out of `subst_sub`, so this is that part of it.
    pub fakeip_sub: usize,
    /// Every endpoint that did not answer all its domains, one entry each: the
    /// summary counts say how many resolvers answered, these say which did not
    /// and why (`no_ca_bundle` reads differently from `tls_dropped`).
    pub failures: Vec<DnsEndpointFailure>,
}

/// One endpoint of test 1 that was not clean.
#[derive(Serialize)]
pub struct DnsEndpointFailure {
    /// Provider as configured (`Google`, `AdGuard (F)`, …).
    pub provider: String,
    /// `ProbeKind::as_str()`: `udp`, `doh_wire` or `dot`.
    pub protocol: &'static str,
    /// The endpoint as configured: the DoH URL, or the host of a DoT/UDP server.
    pub endpoint: String,
    /// Domains this endpoint answered.
    pub ok: usize,
    /// Domains it was asked (`forbidden` for DoH/DoT, `allowed` for UDP).
    pub total: usize,
    /// `DpiStatus::as_str()` of its first failure, absent when some domains
    /// answered and the connection itself never failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    /// `Detail::code()` behind that failure: `no_root_certificates` for a chain
    /// that did not reach a bundled root, `tls_drop_handshake` for a hello that
    /// was dropped, and the raw message where no classification fits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Serialize)]
pub struct DomainRow {
    pub domain: String,
    pub resolved: Option<String>,
    pub http: &'static str,
    pub http_detail: Detail,
    pub tls12: &'static str,
    pub tls12_detail: Detail,
    pub tls13: &'static str,
    pub tls13_detail: Detail,
}

#[derive(Serialize)]
pub struct WhitelistSni {
    pub detected_as: usize,
    pub found_as: usize,
}

#[derive(Serialize)]
pub struct Transfer {
    pub status: String,
    pub avg_bps: f64,
    pub peak_bps: f64,
    pub bytes: u64,
    pub drop_at_sec: Option<u64>,
}

#[derive(Serialize)]
pub struct Telegram {
    pub verdict: String,
    pub download: Transfer,
    pub upload: Transfer,
    pub dc_reachable: usize,
    pub dc_total: usize,
}

#[derive(Serialize)]
pub struct BurstProfile {
    pub answered: usize,
    pub attempts: usize,
    pub statuses: Vec<&'static str>,
    /// The first non-ok attempt's detail, `""` when the shape answered everywhere.
    pub detail: Detail,
}

#[derive(Serialize)]
pub struct BurstDomain {
    pub domain: String,
    pub resolved: Option<String>,
    /// Keyed by the fingerprint code, so the shape is readable on its own.
    pub profiles: BTreeMap<String, BurstProfile>,
}

#[derive(Serialize)]
pub struct FingerprintBurst {
    pub attempts: usize,
    pub tls: String,
    pub alpn: String,
    pub timeout_secs: u64,
    /// Delay between attempt starts, milliseconds — `0` when the run fired the
    /// whole round at one instant.
    pub gap_ms: u64,
    pub profiles: Vec<String>,
    pub domains: Vec<BurstDomain>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dpi_core::classify::{Detail, DpiStatus};

    /// Rule 5: the payload carries the core's own tokens, not the table's badges.
    #[test]
    fn dns_failures_carry_wire_tokens() {
        let payload = DnsAvailability {
            doh_ok: 0,
            doh_total: 1,
            dot_ok: 0,
            dot_total: 1,
            udp_ok: 1,
            udp_total: 1,
            hijacked_brands: Vec::new(),
            resolvers_total: 1,
            subst_sub: 0,
            subst_total: 1,
            fakeip_sub: 0,
            failures: vec![DnsEndpointFailure {
                provider: "Google".to_string(),
                protocol: dpi_core::probe::dns_avail::ProbeKind::Dot.as_str(),
                endpoint: "dns.google".to_string(),
                ok: 0,
                total: 5,
                status: Some(DpiStatus::NoCa.as_str()),
                detail: Some(Detail::NoRootCa.code().into_owned()),
            }],
        };

        let text = serde_json::to_string(&payload).expect("the payload serializes");
        assert!(text.contains(r#""protocol":"dot""#), "{text}");
        assert!(text.contains(r#""status":"no_ca_bundle""#), "{text}");
        assert!(text.contains(r#""detail":"no_root_certificates""#), "{text}");
    }
}

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
    pub profiles: Vec<String>,
    pub domains: Vec<BurstDomain>,
}

//! The `--json` payload.
//!
//! One struct per test describes the machine-readable output in a single place:
//! `serde` writes the keys, the statuses and details come from the core's
//! `Serialize` impls (`DpiStatus` is its snake_case token, `Detail` its code), and
//! a field that no test filled is simply absent from `results`.

use std::collections::BTreeMap;

use dpi_core::classify::Detail;
use dpi_core::net::ggc::{GgcMapping, GgcPlacement};
use dpi_core::probe::telegram::TransferStatus;
use serde::Serialize;

use dpi_core::probe::tcp16::Tcp16Row;

/// Wire version of the payload; bump it when a key changes meaning.
pub(crate) const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub(crate) struct Report {
    pub schema_version: u32,
    pub version: &'static str,
    pub profile: &'static str,
    pub tls_fingerprint: String,
    pub results: Results,
}

/// One field per test, filled only when that test ran. The field order is the
/// order the tests appear in the menu.
#[derive(Serialize, Default)]
pub(crate) struct Results {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_info: Option<NetworkInfo>,
    /// The cache node the GGC mapping endpoint steered this address to — the
    /// answer behind test 2's YouTube verdict — together with what this run
    /// measured about where that node actually is. Absent when the endpoint
    /// answered nothing the parser accepts or timed out, the same `None` the
    /// report prints as its `unknown` line. Additive, so `SCHEMA_VERSION`
    /// stands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ggc: Option<GgcReport>,
    /// The control node probed beside the mapped one for the same row: a node in
    /// Google's own network, which is what "global" looks like from this run.
    /// Absent when the mapping named no node or the control did not answer.
    /// Additive, so `SCHEMA_VERSION` stands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ggc_control: Option<GgcControl>,
    /// `Some(true)` when the mapping was computed for a different address than
    /// the one the run's own public-IP echo returned: the split-routing shape
    /// behind an HTTP 403 on video, because the media token is bound to the
    /// address that fetched the manifest. Absent when either address is unknown,
    /// so the key never claims "the same". Additive, so `SCHEMA_VERSION` stands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ggc_ip_mismatch: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_availability: Option<DnsAvailability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_inspection: Option<Vec<DomainRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp16: Option<Vec<Tcp16Row>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist_sni: Option<WhitelistSni>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telegram: Option<Telegram>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_burst: Option<FingerprintBurst>,
}

/// `results.ggc`: the mapping the redirector answered, plus what this run
/// measured about where the node it named actually is.
///
/// The mapping's own keys are flattened in unchanged (`client_ip`, `cluster_id`,
/// `prefix`, `is_local_ru`), because a reader that knows them must not have to
/// look one level deeper for them; the added keys are the address's answer,
/// which is not the name's. `placement` is always there while the mapping is:
/// when `asn` is absent the address could not be classified and the placement is
/// the name's reading. Additive, so `SCHEMA_VERSION` stands.
#[derive(Serialize)]
pub(crate) struct GgcReport {
    #[serde(flatten)]
    pub mapping: GgcMapping,
    /// Where the node sits: `local` (its AS is this run's own provider's),
    /// `global` (Google's own network, AS15169) or `other`.
    pub placement: GgcPlacement,
    /// The address the node's name resolved to, absent when it did not resolve
    /// inside the budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The AS Team Cymru answered for that address, absent when the lookup did
    /// not answer — which is also what sends `placement` to the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    /// The org name Cymru gave that AS, absent when it gave none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// The control node measured beside the mapped one: a node in Google's own
/// network, whose two rows are the pair the `GGC:` line reads.
#[derive(Serialize)]
pub(crate) struct GgcControl {
    /// The host as probed (`r1.pniada-as.googlevideo.com`).
    pub host: String,
    /// Where the control sits, read by the same rule as the mapped node; the
    /// name is its fallback.
    pub placement: GgcPlacement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct Endpoint {
    pub ip: String,
    pub latency_ms: u64,
}

#[derive(Serialize)]
pub(crate) struct NetworkInfo {
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
pub(crate) struct DnsAvailability {
    pub doh_ok: usize,
    pub doh_total: usize,
    pub dot_ok: usize,
    pub dot_total: usize,
    pub udp_ok: usize,
    pub udp_total: usize,
    /// Endpoints not measured because their certificate chain did not reach a
    /// bundled root: a local trust mismatch (`no_ca_bundle` /
    /// `no_root_certificates` in `failures`), not a dead resolver. They are out
    /// of `doh_total`/`dot_total`, so a ratio never reads the trust store as
    /// the network's verdict, and counted here so they stay visible. Additive,
    /// so `SCHEMA_VERSION` stands.
    pub no_ca_bundle: usize,
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
pub(crate) struct DnsEndpointFailure {
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
pub(crate) struct DomainRow {
    pub domain: String,
    pub resolved: Option<String>,
    pub http: &'static str,
    pub http_detail: Detail,
    pub tls12: &'static str,
    pub tls12_detail: Detail,
    pub tls13: &'static str,
    pub tls13_detail: Detail,
    /// The QUIC column: the `DpiStatus` token of the Initial probe on UDP 443.
    pub quic: &'static str,
    pub quic_detail: Detail,
    /// What the bundled Mozilla roots said about the chain the TLS legs were
    /// shown, judged after the handshake: `fake_cert`, `cert_expired`,
    /// `self_signed`, `hostname_mismatch` or `no_root_certificates` when they
    /// reject it, empty when they accept it, when no handshake completed or when
    /// the row never dialled. A mark beside the columns, never one of their
    /// statuses: `tls12`/`tls13` above read the same with and without it.
    pub cert_detail: Detail,
}

#[derive(Serialize)]
pub(crate) struct WhitelistSni {
    pub detected_as: usize,
    pub found_as: usize,
}

#[derive(Serialize)]
pub(crate) struct Transfer {
    pub status: TransferStatus,
    pub avg_bps: f64,
    pub peak_bps: f64,
    pub bytes: u64,
    pub drop_at_sec: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct Telegram {
    pub verdict: String,
    pub download: Transfer,
    pub upload: Transfer,
    pub dc_reachable: usize,
    pub dc_total: usize,
}

#[derive(Serialize)]
pub(crate) struct BurstProfile {
    pub answered: usize,
    pub attempts: usize,
    pub statuses: Vec<&'static str>,
    /// The first non-ok attempt's detail, `""` when the shape answered everywhere.
    pub detail: Detail,
}

#[derive(Serialize)]
pub(crate) struct BurstDomain {
    pub domain: String,
    pub resolved: Option<String>,
    /// Keyed by the fingerprint code, so the shape is readable on its own.
    pub profiles: BTreeMap<String, BurstProfile>,
}

#[derive(Serialize)]
pub(crate) struct FingerprintBurst {
    pub attempts: usize,
    pub tls: String,
    pub alpn: String,
    pub timeout_secs: u64,
    /// Delay between attempt starts, milliseconds — `0` when the run fired the
    /// whole round at one instant.
    pub gap_ms: u64,
    pub profiles: Vec<String>,
    /// The one edit applied to every profile's hello, in the spelling
    /// `--burst-variant` takes. Absent when the run fired the shapes as they are.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
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
            no_ca_bundle: 1,
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
        // The skipped-endpoint counter is a wire key of its own: the ratio it is
        // kept out of (`doh_total`/`dot_total`) cannot name it.
        assert!(text.contains(r#""no_ca_bundle":1"#), "{text}");
    }

    /// `results.ggc` keeps the mapping's own keys where they were and adds the
    /// address's verdict beside them: the flatten is the point, because a reader
    /// that already keys on `cluster_id` must not have to look one level deeper
    /// after this change. An unfilled fact is absent, not `null`.
    #[test]
    fn ggc_report_flattens_the_mapping_beside_the_placement() {
        let report = GgcReport {
            mapping: GgcMapping {
                client_ip: Some("203.0.113.7".parse().expect("an IPv4 address")),
                cluster_id: "ertelecom-pez1".to_string(),
                prefix: "85.249.20.0/22".to_string(),
                is_local_ru: true,
            },
            placement: GgcPlacement::Local,
            address: Some("109.194.137.76".to_string()),
            asn: Some("41754".to_string()),
            org: None,
        };
        let text = serde_json::to_string(&report).expect("the payload serializes");
        for key in [
            r#""client_ip":"203.0.113.7""#,
            r#""cluster_id":"ertelecom-pez1""#,
            r#""prefix":"85.249.20.0/22""#,
            r#""is_local_ru":true"#,
            r#""placement":"local""#,
            r#""address":"109.194.137.76""#,
            r#""asn":"41754""#,
        ] {
            assert!(text.contains(key), "{key} missing from {text}");
        }
        assert!(!text.contains("org"), "an unfilled org is absent, not null: {text}");

        let control = GgcControl {
            host: "r1.pniada-as.googlevideo.com".to_string(),
            placement: GgcPlacement::Global,
            address: Some("172.217.152.129".to_string()),
            asn: Some("15169".to_string()),
            org: Some("GOOGLE".to_string()),
        };
        let text = serde_json::to_string(&control).expect("the control serializes");
        assert!(text.contains(r#""placement":"global""#), "{text}");
        assert!(text.contains(r#""host":"r1.pniada-as.googlevideo.com""#), "{text}");
    }
}

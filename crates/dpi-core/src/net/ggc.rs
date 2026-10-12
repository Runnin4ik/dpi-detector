//! GGC (Google Global Cache) discovery: where the video traffic is actually
//! served.
//!
//! `www.youtube.com` and `r1.<cluster>.googlevideo.com` are different hosts with
//! different verdicts. The YouTube frontend answering says nothing about the
//! delivery node: the client is steered to a cache inside a local operator's
//! network (a Russian ISP) or to a foreign PoP (`fra16s48`, Frankfurt), and the
//! two explain a throttled or reset stream in opposite ways — one is a domestic
//! cache whose path is broken, the other is transit whose peering was cut.
//!
//! The endpoint [`REPORT_MAPPING_URL`] names the exact node for the calling
//! address: one line, `<client ip> => <cluster id> (<prefix>)`. This module is
//! the parser for that line, the heuristic that reads "Russian network" out of
//! a cluster id, and the fetch that fetches the line — nothing else. Test 2
//! still measures hosts; this is the lookup that explains what it measured.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use serde::Serialize;
use tracing::debug;

use crate::net::http_client::http_get_text;

/// The endpoint that names the cache node the calling address is steered to.
///
/// `di=no` asks it not to run the per-client diagnostic, which keeps the answer
/// to the mapping line alone.
pub const REPORT_MAPPING_URL: &str = "https://redirector.googlevideo.com/report_mapping?di=no";

/// Operator substrings inside a cluster id that put the node in a Russian
/// provider's own network — the shape a cache inside an ISP takes. A cache
/// rented in a foreign datacentre is named after its PoP instead
/// ([`RU_AIRPORTS`], `fra16s48`), so a name carrying one of these is the
/// domestic case regardless of the city in it (`vimpelcom-iar2` is Irkutsk
/// inside Beeline's network, not a window abroad).
const RU_OPERATORS: &[&str] = &[
    "rostelecom",
    "vimpelcom",
    "megafon",
    "mts",
    "ertelecom",
    "comstar",
    "transtelecom",
];

/// IATA codes of the Russian airports GGC names a node after when it is not
/// inside an operator network: the cluster id is the code plus a serial
/// (`fra16s48` is Frankfurt, `led` is Pulkovo). The code leads one of the id's
/// `-`/`_`/`.`-separated tokens — the endpoint's own naming shape ([`leads_a_token`])
/// — and is never looked for inside one: three letters are short enough to be
/// spelled by accident in a foreign id, where the code in the middle of a name
/// would read as domestic without being one. A node steered to Crimea is not
/// named after `sip`, deliberately: the mapping says where the cache is, not
/// whose it is.
const RU_AIRPORTS: &[&str] = &[
    "svo", "dme", "vko", "led", "svx", "ovb", "kzn", "ufa", "kuf", "rov", "aer", "mrv", "goj",
    "krr", "ikt", "vvo", "kja", "kgd", "cek", "tof", "rtw", "voz",
];

/// One cache node as the mapping endpoint describes it.
///
/// `client_ip` is the address the answer was computed for: `None` when the line
/// carried none. The cluster and prefix are the payload — they carry the
/// diagnosis — and the address is context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GgcMapping {
    /// The address the endpoint steered, when the line named one.
    pub client_ip: Option<IpAddr>,
    /// The cache node's cluster id (`vimpelcom-iar2`, `fra16s48`).
    pub cluster_id: String,
    /// The address block that block gets served (`85.249.20.0/22`).
    pub prefix: String,
    /// The cluster sits in a Russian operator's network or a Russian city.
    pub is_local_ru: bool,
}

/// The host test 2 probes for the node the endpoint named: the cache itself,
/// not the redirector that reported it.
pub fn candidate_ggc_host(cluster_id: &str) -> String {
    format!("r1.{cluster_id}.googlevideo.com")
}

/// Parses the mapping endpoint's line: `<ip> => <cluster_id> (<prefix>)`.
///
/// The first non-blank line is the answer, the rest of a captured body is
/// ignored. `None` for anything that is not that shape — a captive-portal
/// landing page or an intercepted redirect has no cluster, and a mapping
/// without one explains nothing. An address that does not parse rejects the
/// line with it; a missing one leaves [`GgcMapping::client_ip`] `None` rather
/// than failing, because the cluster and prefix carry the diagnosis either way.
pub fn parse_report_mapping(body: &str) -> Option<GgcMapping> {
    let line = body.lines().map(str::trim).find(|l| !l.is_empty())?;
    let (address, rest) = line.split_once("=>")?;
    let client_ip = match address.trim() {
        "" => None,
        text => Some(IpAddr::from_str(text).ok()?),
    };
    let (cluster_part, prefix_part) = rest.trim().split_once('(')?;
    let prefix = prefix_part.strip_suffix(')')?.trim();
    let cluster_id = cluster_part.trim();
    if cluster_id.is_empty() || prefix.is_empty() {
        return None;
    }
    Some(GgcMapping {
        client_ip,
        cluster_id: cluster_id.to_string(),
        prefix: prefix.to_string(),
        is_local_ru: is_russian_cluster(cluster_id),
    })
}

/// Whether the cluster id names a Russian network — an operator's own cache, or
/// a node named after a Russian airport.
///
/// The two tables are matched differently on purpose: an operator name is
/// distinctive enough to be looked for anywhere in the id, while a three-letter
/// airport code has to lead a token to mean the city it names at all.
fn is_russian_cluster(cluster_id: &str) -> bool {
    let id = cluster_id.to_ascii_lowercase();
    RU_OPERATORS.iter().any(|operator| id.contains(operator))
        || RU_AIRPORTS.iter().any(|code| leads_a_token(&id, code))
}

/// Whether `name` leads one of `id`'s `-`/`_`/`.`-separated tokens, the id's own
/// shape for both an operator and an airport code (`vimpelcom-iar2`, `led`).
fn leads_a_token(id: &str, name: &str) -> bool {
    id.split(['-', '_', '.']).any(|token| leads_with(token, name))
}

/// Whether `token` begins with `name` as that name: `name` first, then anything
/// but another letter — a serial or a further digit is part of it (`led3s2`),
/// while a letter means a longer word that merely opens with the same letters,
/// which is how a foreign id would borrow a code it does not carry.
fn leads_with(token: &str, name: &str) -> bool {
    let Some(rest) = token.strip_prefix(name) else {
        return false;
    };
    match rest.as_bytes().first() {
        None => true,
        Some(byte) => !byte.is_ascii_alphabetic(),
    }
}

/// Fetches and parses the mapping for the calling address.
///
/// The whole request — dial, TLS, the answer — runs inside `timeout_dur`, the
/// control-plane GET's own deadline. A failure is a diagnostic and never a
/// stage in the run: an intercepted network answers something the parser
/// rejects, an unreachable one nothing at all, and both are the GGC column
/// showing `unknown` rather than an error.
pub async fn fetch_ggc_mapping(timeout_dur: Duration) -> Option<GgcMapping> {
    match http_get_text(REPORT_MAPPING_URL, timeout_dur).await {
        Ok(body) => {
            let mapping = parse_report_mapping(&body);
            if mapping.is_none() {
                debug!("report_mapping answered a body with no mapping line");
            }
            mapping
        }
        Err(error) => {
            debug!("report_mapping fetch failed: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Russian case: the client's own provider carries the cache, so the
    /// delivery path is domestic and a breakage in it is not a transit problem.
    #[test]
    fn test_russian_operator_cluster_is_local() {
        let mapping = parse_report_mapping("85.249.22.12 => vimpelcom-iar2 (85.249.20.0/22)\n")
            .expect("the real line shape parses");
        assert_eq!(mapping.client_ip, Some("85.249.22.12".parse().expect("an IPv4 address")));
        assert_eq!(mapping.cluster_id, "vimpelcom-iar2");
        assert_eq!(mapping.prefix, "85.249.20.0/22");
        assert!(mapping.is_local_ru);
    }

    /// A cache named after a Russian airport rather than rented inside an
    /// operator: still local, still not a foreign PoP.
    #[test]
    fn test_russian_airport_cluster_is_local() {
        let mapping = parse_report_mapping("95.108.240.6 => led (95.108.240.0/20)")
            .expect("a bare code names the cluster");
        assert!(mapping.is_local_ru, "Pulkovo is a Russian node");
    }

    /// The foreign case: the same endpoint steered the client to a PoP abroad,
    /// and the verdict the mapping feeds is the opposite one.
    #[test]
    fn test_foreign_pop_cluster_is_not_local() {
        let mapping = parse_report_mapping("178.62.1.1 => fra16s48 (178.62.0.0/16)")
            .expect("a PoP line parses");
        assert!(!mapping.is_local_ru, "Frankfurt is a PoP, not a Russian node");
    }

    /// The other half of the heuristic's contract, over the PoPs the endpoint
    /// actually names: one of these reading as domestic inverts the verdict the
    /// GGC column exists to give, so each is checked bare and with a serial.
    #[test]
    fn test_foreign_pop_ids_are_never_local() {
        for cluster_id in [
            "fra16s48", "ams09s15", "arn09s18", "hel03s02", "waw", "lhr", "cdg", "iad", "lax",
            "sin", "hkg", "nrt", "mia", "dfw", "sea", "gru", "bom", "del",
        ] {
            let line = format!("178.62.1.1 => {cluster_id} (178.62.0.0/16)");
            let mapping = parse_report_mapping(&line).expect("a PoP line parses");
            assert!(
                !mapping.is_local_ru,
                "{cluster_id} is a foreign PoP, not a Russian node"
            );
        }
    }

    /// The boundary the airport table rests on: a three-letter code spelled
    /// inside a longer name is not the city it names. These ids are built to
    /// carry one mid-word rather than taken from traffic, because a plain
    /// substring search reads every one of them as domestic.
    #[test]
    fn test_foreign_id_spelling_a_code_mid_word_is_not_local() {
        for cluster_id in ["mysvo4", "kaer12", "stoled9", "vozak3", "framrv2"] {
            assert!(
                !is_russian_cluster(cluster_id),
                "{cluster_id} spells a Russian code without being the node it names"
            );
        }
    }

    /// The line's shape is the whole contract: every deviation — no cluster, no
    /// prefix, an address that is not one — is a body this module cannot read.
    #[test]
    fn test_parser_rejects_every_shape_it_cannot_read() {
        for body in [
            "",
            "   \n ",
            "garbage",
            "178.62.1.1",
            "178.62.1.1 =>",
            "178.62.1.1 => fra16s48",
            "178.62.1.1 => fra16s48 (178.62.0.0/16",
            "178.62.1.1 => (178.62.0.0/16)",
            "178.62.1.1 => fra16s48 ()",
            "not-an-ip => fra16s48 (178.62.0.0/16)",
            "HTTP/1.1 200 OK",
        ] {
            assert!(
                parse_report_mapping(body).is_none(),
                "not a mapping line: {body:?}"
            );
        }
    }

    /// The endpoint answers with a trailing newline and IPv6 clients with an
    /// IPv6 line: neither is a reason to lose the mapping.
    #[test]
    fn test_mapping_tolerates_ipv6_and_a_trailing_newline() {
        let mapping = parse_report_mapping("2001:db8::1 => fra16s48 (2001:db8::/32)\n\n")
            .expect("the line survives whitespace around it");
        assert_eq!(mapping.client_ip, Some("2001:db8::1".parse().expect("an IPv6 address")));
        assert_eq!(mapping.prefix, "2001:db8::/32");
    }

    /// The node's own host is what test 2 would probe next: the cluster id
    /// under the delivery domain, not the redirector that reported it.
    #[test]
    fn test_candidate_host_is_the_cache_node() {
        assert_eq!(
            candidate_ggc_host("vimpelcom-iar2"),
            "r1.vimpelcom-iar2.googlevideo.com"
        );
        assert_eq!(candidate_ggc_host("fra16s48"), "r1.fra16s48.googlevideo.com");
    }
}

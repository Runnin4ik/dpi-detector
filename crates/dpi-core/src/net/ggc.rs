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
//! a cluster id, the fetch that fetches the line, and the measurement that
//! places the node it named — nothing else. Test 2 still measures hosts; this
//! is the lookup that explains what it measured.
//!
//! A node is placed by its address, not by its name. The name is a convention
//! (`is_russian_cluster`) while the address this run actually reached is the
//! path the packets take: the run's own AS means a cache next door, the AS of
//! Google's own network means a PoP over transit ([`placement`]). The name
//! decides only where no address could.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use serde::Serialize;
use tokio::time::timeout;
use tracing::debug;

use crate::dns::cymru::fetch_ip_cymru;
use crate::dns::resolve_host;
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

/// The AS of Google's own network. A node inside it is a PoP over transit from
/// this run, however the node is named — `pniada-as` is exactly such a name,
/// which is why the name alone cannot be the answer.
pub const GGC_GOOGLE_ASN: &str = "15169";

/// The control nodes test 2 probes beside the one the mapping named, so the pair
/// stands in two rows and the `GGC:` line can say what the difference between
/// them is.
///
/// Measured on this machine: `r1.pniada-as.googlevideo.com` is 172.217.152.129,
/// `AS15169 / 172.217.128.0/19 / US` — Google's own network — while the node
/// this address is steered to (`r1.ertelecom-pez1.googlevideo.com`,
/// 109.194.137.76) sits in `AS41754 / 109.194.128.0/20 / RU`, the run's own
/// provider. The `r1.<cluster>` namespace is not enumerable: of the names tried,
/// `fra16s48`, `ams16s48`, `lhr16s48`, `mad16s48`, `led`, `goj`, `mts`,
/// `megafon` and `vimpelcom` have no A record at all — only the calling
/// address's own cluster answers. So this one measured name is the control and a
/// second one would be a guess. The Google-owned `manifest` and `redirector`
/// hosts are rows of the shipped list already, so they need no entry here.
pub const GGC_CONTROL_HOSTS: &[&str] = &["r1.pniada-as.googlevideo.com"];

/// Where a delivery node sits relative to this run's own network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GgcPlacement {
    /// Inside the run's own provider's network (the same AS): a cache next door,
    /// so a broken path to it is not a transit problem.
    Local,
    /// Inside Google's own network ([`GGC_GOOGLE_ASN`]): a PoP over transit,
    /// whose peering is what a break there looks like.
    Global,
    /// Neither: the node answered with an AS of its own, so it is somebody
    /// else's network — not the run's own provider, and not Google.
    Other,
}

/// The placement of a node, by address when the ASNs allow it and by name
/// otherwise.
///
/// The address is a fact and the name is a convention, which is why the name is
/// only the fallback: an AS Team Cymru answered for the address this run reached
/// is the path the packets take, while the cluster id is a naming scheme —
/// `pniada-as`, in Google's own network, is in neither table and would read as a
/// foreign PoP by accident, and an operator that names its own cache something
/// the tables do not carry would read as foreign while being next door.
///
/// So when both sides of the comparison are known the address decides outright:
/// the run's own AS is `Local`, [`GGC_GOOGLE_ASN`] is `Global`, and any third AS
/// is `Other` — the name cannot overrule a measured AS, or the misreading this
/// rule exists to remove would come back through the fallback. With a side
/// missing there is nothing to compare: Google's AS still says `Global` on its
/// own, and everything else leaves the name the last word.
/// `is_local_ru` is [`GgcMapping::is_local_ru`] for a node the mapping named and
/// [`node_name_is_local_ru`] for one it did not.
pub fn placement(node_asn: Option<&str>, run_asn: Option<&str>, is_local_ru: bool) -> GgcPlacement {
    if let (Some(node), Some(run)) = (node_asn, run_asn) {
        return if node == run {
            GgcPlacement::Local
        } else if node == GGC_GOOGLE_ASN {
            GgcPlacement::Global
        } else {
            GgcPlacement::Other
        };
    }
    if node_asn == Some(GGC_GOOGLE_ASN) {
        return GgcPlacement::Global;
    }
    if is_local_ru {
        GgcPlacement::Local
    } else {
        GgcPlacement::Other
    }
}

/// Whether a delivery node's *name* reads as a local one — the fallback
/// [`placement`] takes for a host no mapping named (the control).
///
/// `host` is a node as test 2 probes it (`r1.<cluster>.googlevideo.com`): the
/// cluster id between the two is what the two tables read, and a host of any
/// other shape is not a node this module can judge, so it is not local. The
/// verdict is a guess by construction — that is what the address rule above
/// exists to replace.
pub fn node_name_is_local_ru(host: &str) -> bool {
    let Some(cluster_id) = host
        .strip_prefix("r1.")
        .and_then(|rest| rest.strip_suffix(".googlevideo.com"))
    else {
        return false;
    };
    is_russian_cluster(cluster_id)
}

/// One delivery node as measured from this run: the address its name resolves to
/// and what Team Cymru says about that address.
///
/// Every field is an `Option` on purpose. A name that does not resolve, or a
/// Cymru answer that never came, leaves the fields it could not fill absent —
/// which is the same shape the mapping itself has. `host` is what was asked, so
/// a report can name the node it could not place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgcNodeFacts {
    pub host: String,
    pub address: Option<IpAddr>,
    pub asn: Option<String>,
    pub org: Option<String>,
}

impl GgcNodeFacts {
    /// Whether the node answered at all: its name resolved, so the pair it
    /// belongs to has a row to be read against. An address without a Cymru
    /// answer still answered — the placement then falls back to the name.
    pub fn answered(&self) -> bool {
        self.address.is_some()
    }
}

/// Resolves `host` and looks its address up in Team Cymru, all inside
/// `timeout_dur` — the caller's whole budget for the one node.
///
/// The address looked up is the IPv4 one when the name has both: the measured
/// pairs are A records, and a node's AAAA is as likely to be Google's own
/// network while its A sits inside the operator's prefix — the very distinction
/// [`placement`] reads. Nothing here fails: a name that does not resolve, an
/// address Cymru does not know and a deadline that runs out before the answers
/// do all come back as the same facts with the unfilled fields absent, which the
/// `GGC:` line reads as a node it cannot place rather than as an error.
pub async fn gather_node_facts(
    host: &str,
    doh_servers: &[String],
    timeout_dur: Duration,
) -> GgcNodeFacts {
    let mut facts = GgcNodeFacts {
        host: host.to_string(),
        address: None,
        asn: None,
        org: None,
    };
    let gathered = timeout(timeout_dur, async {
        let addrs = resolve_host(host, 443, timeout_dur).await.ok()?;
        let address = addrs
            .iter()
            .map(SocketAddr::ip)
            .find(IpAddr::is_ipv4)
            .or_else(|| addrs.first().map(SocketAddr::ip))?;
        Some((address, fetch_ip_cymru(&address, doh_servers, timeout_dur).await))
    })
    .await;
    // Nothing answered inside the budget: the facts stay empty and the host is
    // named in the log, because the line has no room for a second diagnostic.
    let Ok(Some((address, cymru))) = gathered else {
        debug!("GGC node {host}: no address inside the budget");
        return facts;
    };
    facts.address = Some(address);
    let Some(info) = cymru else {
        debug!("GGC node {host}: address {address} without a Cymru answer");
        return facts;
    };
    if !info.asn.is_empty() {
        facts.asn = Some(info.asn);
    }
    facts.org = info.org.filter(|org| !org.is_empty());
    facts
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

    /// The address decides when it can: the run's own AS is the cache next door
    /// and Google's AS is the transit case, with the name outvoted in both
    /// directions. Pins the failure the name heuristic alone had — it read the
    /// node by convention, so `pniada-as` (Google's own network) and an
    /// operator's unusually named cache would each come out the wrong way.
    #[test]
    fn test_placement_reads_the_address_when_both_asns_are_known() {
        // The measured pair of this machine: the node in the run's own
        // provider's AS, the control in Google's own network.
        assert_eq!(placement(Some("41754"), Some("41754"), false), GgcPlacement::Local);
        assert_eq!(placement(Some(GGC_GOOGLE_ASN), Some("41754"), true), GgcPlacement::Global);
        // An AS of its own is neither: the name reading it disagrees with is
        // exactly what this rule replaced.
        assert_eq!(placement(Some("8359"), Some("41754"), true), GgcPlacement::Other);
        assert_eq!(placement(Some("8359"), Some("41754"), false), GgcPlacement::Other);
        // The rule's order, pinned: the same-AS case is read first, so a run
        // that itself sits in Google's network reads its node as next door and
        // not as transit.
        assert_eq!(placement(Some(GGC_GOOGLE_ASN), Some(GGC_GOOGLE_ASN), false), GgcPlacement::Local);
    }

    /// The fallback's two sides: the node's ASN missing (its name did not
    /// resolve, or Cymru did not answer) and the run's own missing (test 0 not in
    /// the run, or its lookup dead). Both leave the name the last word, which is
    /// the verdict the line printed before this rule existed — an unclassified
    /// node is not a third placement.
    #[test]
    fn test_placement_falls_back_to_the_name_when_an_asn_is_missing() {
        assert_eq!(placement(None, Some("41754"), true), GgcPlacement::Local);
        assert_eq!(placement(None, Some("41754"), false), GgcPlacement::Other);
        assert_eq!(placement(Some("41754"), None, true), GgcPlacement::Local);
        assert_eq!(placement(Some("41754"), None, false), GgcPlacement::Other);
        assert_eq!(placement(None, None, true), GgcPlacement::Local);
        assert_eq!(placement(None, None, false), GgcPlacement::Other);
        // Google's AS is a fact about the node alone, so it needs no second
        // side; and a node whose ASN is unknown is never called global, because
        // an address that did not answer cannot say "Google's network".
        assert_eq!(placement(Some(GGC_GOOGLE_ASN), None, true), GgcPlacement::Global);
        assert_eq!(placement(None, Some(GGC_GOOGLE_ASN), false), GgcPlacement::Other);
    }

    /// Why the control needs its address: its name — the only thing the
    /// heuristic can read — carries no operator and no airport code, so the name
    /// alone leaves it unplaced, and the address is what says Google. The shape
    /// is checked too: a host that is not a delivery node has no cluster id to
    /// read, and a suffix that only ends the same way is not one either.
    #[test]
    fn test_control_name_is_not_a_russian_cluster() {
        assert!(!node_name_is_local_ru("r1.pniada-as.googlevideo.com"));
        assert!(!node_name_is_local_ru("r1.fra16s48.googlevideo.com"));
        assert!(node_name_is_local_ru("r1.ertelecom-pez1.googlevideo.com"));
        assert!(node_name_is_local_ru("r1.vimpelcom-iar2.googlevideo.com"));
        assert!(!node_name_is_local_ru("manifest.googlevideo.com"));
        assert!(!node_name_is_local_ru("r1.led.googlevideo.com.evil.example"));
    }

    /// The control list is the shipped pair's other half: one node, shaped like
    /// the nodes test 2 probes, in no name table — the measured one. A list that
    /// grew a second, unmeasured name would be a control nothing measured.
    #[test]
    fn test_control_list_holds_one_measured_node() {
        assert_eq!(GGC_CONTROL_HOSTS.len(), 1);
        assert_eq!(GGC_CONTROL_HOSTS[0], "r1.pniada-as.googlevideo.com");
        // A node host of the same shape the mapping names (`candidate_ggc_host`):
        // the control is a row like ours, not a redirector or a manifest host.
        assert_eq!(GGC_CONTROL_HOSTS[0], candidate_ggc_host("pniada-as"));
        assert!(!node_name_is_local_ru(GGC_CONTROL_HOSTS[0]));
        // The AS the rule keys on is Google's own network, not a nearby number.
        assert_eq!(GGC_GOOGLE_ASN, "15169");
    }

    /// The wire token of each placement, which `--json` readers key on.
    #[test]
    fn test_placement_tokens_are_the_wire_vocabulary() {
        let token = |p: GgcPlacement| serde_json::to_string(&p).expect("a placement serializes");
        assert_eq!(token(GgcPlacement::Local), "\"local\"");
        assert_eq!(token(GgcPlacement::Global), "\"global\"");
        assert_eq!(token(GgcPlacement::Other), "\"other\"");
    }

    /// The gatherer's contract: it has no failure mode. A name that cannot
    /// resolve comes back as facts with nothing filled in — the `GGC:` line then
    /// has no placement to print and says so, instead of the run ending on a
    /// lookup that did not answer.
    #[tokio::test]
    async fn test_gather_leaves_facts_empty_rather_than_failing() {
        let facts = gather_node_facts(
            "no-such-node.invalid",
            &["https://cloudflare-dns.com/dns-query".to_string()],
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(facts.host, "no-such-node.invalid");
        assert!(!facts.answered());
        assert_eq!((facts.address, facts.asn, facts.org), (None, None, None));
    }
}

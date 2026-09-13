//! Team Cymru reverse-DNS lookups over DoH: ASN, subnet, country code and
//! org name of an IP, used for the AS/Org column of test 0 and for the
//! egress resolvers of test 1.

use std::net::IpAddr;
use std::time::Duration;

use tokio::time::timeout;

use crate::dns::query_doh_txt;

#[derive(Debug, Clone, Default)]
pub struct IpCymruInfo {
    pub asn: String,
    /// None = answer missing (renders red "timeout").
    pub subnet: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
}

/// Resolves IP ASN, subnet, country code, and Org name via Team Cymru reverse-DNS TXT query over DoH.
pub async fn fetch_ip_cymru(
    ip: &IpAddr,
    doh_servers: &[String],
    timeout_dur: Duration,
) -> Option<IpCymruInfo> {
    // The timeout bounds the whole server chain, not each attempt: one DoH
    // attempt spends it per stage (resolve, TCP, TLS, handshake, body), so a
    // chain of dead servers could run for many multiples of what the caller
    // allowed and overrun its deadline (test 0 caps the panel fetch at 10 s).
    timeout(timeout_dur, fetch_ip_cymru_chain(ip, doh_servers, timeout_dur))
        .await
        .ok()
        .flatten()
}

async fn fetch_ip_cymru_chain(
    ip: &IpAddr,
    doh_servers: &[String],
    timeout_dur: Duration,
) -> Option<IpCymruInfo> {
    // Walk the configured Cymru DoH servers until one answers; Cloudflare is the fallback.
    let fallbacks = ["https://cloudflare-dns.com/dns-query".to_string()];
    let servers: Vec<&str> = if doh_servers.is_empty() {
        fallbacks.iter().map(|s| s.as_str()).collect()
    } else {
        doh_servers.iter().map(|s| s.as_str()).collect()
    };
    for doh in servers {
        if let Some(info) = fetch_ip_cymru_one(ip, doh, timeout_dur).await {
            return Some(info);
        }
    }
    None
}
fn split_txt_fields(txt: &str) -> Vec<&str> {
    txt.trim_matches('"').split('|').map(|s| s.trim()).collect()
}

fn parts_empty(txt: &str) -> bool {
    split_txt_fields(txt).is_empty()
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Cymru origin answer ("AS | subnet | CC | ...") -> (asn, subnet, cc).
fn parse_cymru_origin(txt: &str) -> (String, Option<String>, Option<String>) {
    let parts = split_txt_fields(txt);
    let asn = parts.first().unwrap_or(&"").split_whitespace().next().unwrap_or("").to_string();
    let mut subnet: Option<String> = None;
    let mut cc: Option<String> = None;
    for f in parts.iter().skip(1) {
        if f.contains('/') {
            subnet = Some((*f).to_string());
        } else if f.len() == 2 && f.bytes().all(|b| b.is_ascii_uppercase()) {
            cc = Some((*f).to_string());
        }
    }
    (asn, subnet, cc)
}
/// AS-name query TXT -> org name with the allocation-date guard.
fn parse_cymru_as_name(txt: &str) -> String {
    let fields = split_txt_fields(txt);
    let name = if fields.len() >= 3 { fields.last().copied().unwrap_or("") } else { fields.first().copied().unwrap_or("") };
    let org = collapse_ws(name);
    if org.is_empty() || is_cymru_date(&org) {
        String::new()
    } else {
        org
    }
}

/// Allocation-date stub ("2024-01-31") means "no org name".
fn is_cymru_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(|c| c.is_ascii_digit())
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[8..].iter().all(|c| c.is_ascii_digit())
}

async fn fetch_ip_cymru_one(
    ip: &IpAddr,
    doh: &str,
    timeout_dur: Duration,
) -> Option<IpCymruInfo> {

    let origin_query = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles = Vec::new();
            for seg in v6.segments() {
                for i in (0..4).rev() {
                    let nibble = (seg >> (i * 4)) & 0x0f;
                    nibbles.push(format!("{:x}", nibble));
                }
            }
            nibbles.reverse();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    };

    let txt_records = query_doh_txt(doh, &origin_query, timeout_dur).await.ok()?;
    let first_txt = txt_records.first()?;
    let (asn, subnet, country) = parse_cymru_origin(first_txt);
    if parts_empty(first_txt) || asn.is_empty() {
        return None;
    }

    let mut org: Option<String> = None;
    if !asn.is_empty() {
        let as_query = format!("AS{}.asn.cymru.com", asn);
        if let Ok(as_txts) = query_doh_txt(doh, &as_query, timeout_dur).await {
            if let Some(as_first) = as_txts.first() {
                org = Some(parse_cymru_as_name(as_first));
            }
        }
    }

    Some(IpCymruInfo {
        asn,
        subnet,
        country,
        org,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cymru_origin() {
        let (asn, sub, cc) = parse_cymru_origin("\"100 | 10.0.0.0/8 | US | EXAMPLE |\"");
        assert_eq!((asn.as_str(), sub.as_deref(), cc.as_deref()), ("100", Some("10.0.0.0/8"), Some("US")));
        let (asn, sub, cc) = parse_cymru_origin("\"200 |  |  |\"");
        assert_eq!(asn, "200");
        assert_eq!((sub, cc), (None, None));
        // the last field of each kind wins
        let (_, sub, cc) = parse_cymru_origin("\"300 | 1.0.0.0/8 | XY | 2.0.0.0/8 | ZZ |\"");
        assert_eq!((sub.as_deref(), cc.as_deref()), (Some("2.0.0.0/8"), Some("ZZ")));
    }

    #[test]
    fn test_parse_cymru_as_name() {
        assert_eq!(parse_cymru_as_name("\"65001 | US | ARIN | 2000-01-01 | EXAMPLE ORG\""), "EXAMPLE ORG");
        assert_eq!(parse_cymru_as_name("\"100 | AS100 | 2024-01-31\""), "");
        assert_eq!(parse_cymru_as_name("\"LONELY\""), "LONELY");
        assert!(is_cymru_date("2024-01-31"));
        assert!(!is_cymru_date("EXAMPLE"));
    }
}

pub mod availability;
pub mod socks;
pub mod doh;
pub mod dot;
pub mod types;
pub mod udp;
pub mod wire;
pub mod resolve;

pub use doh::{doh_connect, probe_doh_dns, query_doh_raw, query_doh_txt, DohSession};
pub use availability::{check_dns_availability, connect_fail_label, dns_name_sort_key, known_resolver, net24, org_label, subst_counts, brand, DnsAnswer, DnsAvailReport, DnsAvailStats, ProbeKey, ProbeKind};
pub use dot::{probe_dot, split_dot_endpoint, DotSession};
pub use socks::{parse_socks_proxy, SocksProxyConfig};
pub use types::{DnsError, DnsRecord, DnsResponse};
pub use resolve::resolve_host;
pub use udp::probe_udp_dns;
pub use wire::{build_dns_query, parse_dns_response, QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_TXT};

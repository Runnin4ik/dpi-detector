//! Test 2: the domain table and the DNS resolve notes printed under it.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::*;
use dpi_core::i18n::{Language, Messages, detail_text, format_bidi};
use dpi_core::probe::domains::{DetailLine, DomainEntry};

use crate::tui::widgets::{cell_color, status_color, table_preset};

pub fn render_domain_table(entries: &[DomainEntry], msg: &Messages) -> String {
    let mut out = String::new();
    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.domain, msg.lang)),
            Cell::new(msg.http),
            Cell::new(msg.tls12),
            Cell::new(msg.tls13),
            Cell::new(format_bidi(msg.detail, msg.lang)),
        ]);

    for e in entries {
        let (http_s, t12_s, t13_s, raw_details) = dpi_core::probe::domains::build_domain_row(e);
        let details = row_details(&raw_details, msg.lang);
        table.add_row(vec![
            Cell::new(cell_color(&e.domain, Color::Cyan)),
            Cell::new(cell_color(http_s.display_label(), status_color(http_s))),
            Cell::new(cell_color(t12_s.display_label(), status_color(t12_s))),
            Cell::new(cell_color(t13_s.display_label(), status_color(t13_s))),
            Cell::new(details),
        ]);
    }

    out.push_str(&format_bidi(msg.domain_title, msg.lang));
    out.push('\n');
    out.push_str(&format!("{}\n", table));
    out
}

/// Detail cell of the domain table: one `<proto>:<detail>` line per failing
/// protocol, or a single line when the failure is shared. Protocol tags are
/// canonical Latin tokens (Rule 4) and stay untranslated.
fn row_details(lines: &[DetailLine], lang: Language) -> String {
    lines
        .iter()
        .map(|(tag, detail)| match tag {
            Some(tag) => format!("{}:{}", tag, detail_text(detail, lang)),
            None => detail_text(detail, lang),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Post-table DNS resolve notes (stubs, fake-ip, DoH recommendation).
pub fn render_dns_resolve_notes(entries: &[DomainEntry], msg: &Messages) -> String {
    use dpi_core::probe::domains::FakeIpType;
    let mut out = String::new();

    let mut dns_fail: usize = 0;
    let mut no_ipv6: usize = 0;
    let mut isp_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut local_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut fakeip_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for e in entries {
        if e.t13.status == DpiStatus::DnsFail || e.t12.status == DpiStatus::DnsFail || e.http.status == DpiStatus::DnsFail {
            dns_fail += 1;
            if e.t13.detail == Detail::Ipv6Unsupported || e.t13.detail == Detail::Ipv6NotSupportedShort {
                no_ipv6 += 1;
            }
        }
        if let Some(ip) = e.resolved {
            if dpi_core::probe::domains::fake_ip_type(&ip) == FakeIpType::FakeIp {
                *fakeip_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
            // ISP stub = resolved IP present in stub set is decided upstream;
            // here DNS FAKE/LOCAL IP statuses mark them.
            if e.t13.status == DpiStatus::DnsFake {
                *isp_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
            if e.t13.status == DpiStatus::LocalIp {
                *local_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
        }
    }

    let real_dns_fail = dns_fail.saturating_sub(no_ipv6);
    if isp_stubs.is_empty() && local_stubs.is_empty() && fakeip_stubs.is_empty() && real_dns_fail == 0 {
        return out;
    }

    out.push_str(&format!("\n{}\n", msg.dns_info_title));
    if !fakeip_stubs.is_empty() {
        let total: usize = fakeip_stubs.values().sum();
        out.push_str(&format!("{}\n", msg.traffic_fakeip.replace("{}", &total.to_string())));
    }
    if !isp_stubs.is_empty() {
        let total: usize = isp_stubs.values().sum();
        if isp_stubs.len() <= 3 {
            let ips: Vec<String> = isp_stubs.keys().cloned().collect();
            let s = msg.dns_isp_stub.replacen("{}", &ips.join(", "), 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        } else {
            let s = msg.dns_isp_stub.replacen("({})", "", 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        }
    }
    if !local_stubs.is_empty() {
        let total: usize = local_stubs.values().sum();
        if local_stubs.len() <= 3 {
            let ips: Vec<String> = local_stubs.keys().cloned().collect();
            let s = msg.dns_local_ip.replacen("{}", &ips.join(", "), 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        } else {
            let s = msg.dns_local_ip.replacen("({})", "", 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        }
    }
    if real_dns_fail > 0 {
        out.push_str(&format!("{}\n", msg.dns_fail_detected.replace("{}", &real_dns_fail.to_string())));
    }
    if !isp_stubs.is_empty() || real_dns_fail > 0 {
        out.push_str(msg.doh_flush_guide);
    }
    out.push('\n');
    out
}

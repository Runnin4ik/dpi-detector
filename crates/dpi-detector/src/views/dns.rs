//! Test 1: DNS availability - endpoints, per-domain latency, egress and answer
//! substitution.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::config::AppConfig;
use dpi_core::i18n::{Messages, format_bidi};
use dpi_core::probe::dns_avail::{
    DnsAnswer, DnsAvailReport, ProbeKind, known_resolver, net24, org_label, subst_counts,
};
use std::net::IpAddr;

use crate::tui::widgets::{asc, cell_color, join_cell_colored, table_preset, warn_mark};

pub fn render_dns_endpoints(report: &DnsAvailReport, msg: &Messages) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\n{}  DoH: {} | DoT: {} | UDP: {} | {}: {} | {}: {} | {}: {}s\n\n",
        msg.dns_check_title,
        report.doh_servers.len(),
        report.dot_servers.len(),
        report.udp_servers.len(),
        msg.blocked,
        report.forbidden.len(),
        msg.available,
        report.allowed.len(),
        msg.timeout_label,
        report.timeout_secs,
    ));
    out.push_str(&format!(
        "{} {}\n{} {}\n{}",
        msg.blocked_domains_label,
        report.forbidden.join(", "),
        msg.unblocked_domains_label,
        report.allowed.join(", "),
        msg.dns_independent_warn,
    ));
    if report.non_socks_proxy_warn {
        out.push_str(msg.non_socks_proxy_warn);
    }

    // Endpoint tables per kind
    for (title, servers, kind) in [
        (msg.doh_endpoints, &report.doh_servers, ProbeKind::DohWire),
        (msg.dot_endpoints, &report.dot_servers, ProbeKind::Dot),
        (msg.udp_endpoints, &report.udp_servers, ProbeKind::Udp),
    ] {
        if servers.is_empty() {
            continue;
        }
        let mut table = Table::new();
        table
            .load_preset(table_preset())
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new(format_bidi(msg.provider, msg.lang)),
                Cell::new(format_bidi(title, msg.lang)),
            ]);
        // Group by provider name preserving order
        let mut order: Vec<String> = Vec::new();
        let mut by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (addr, name, port) in servers {
            let default_port = match kind {
                ProbeKind::DohWire => 443,
                ProbeKind::Dot => 853,
                ProbeKind::Udp => 53,
            };
            let disp = if *port != default_port {
                format!("{}:{}", addr, port)
            } else {
                addr.clone()
            };
            if !by_name.contains_key(name) {
                order.push(name.clone());
            }
            by_name.entry(name.clone()).or_default().push(disp);
        }
        for name in order {
            let eps = &by_name[&name];
            let cell = if eps.len() > 1 {
                eps.iter().enumerate().map(|(i, e)| format!("{} #{}", e, i + 1)).collect::<Vec<_>>().join("\n")
            } else {
                eps[0].clone()
            };
            table.add_row(vec![Cell::new(cell_color(&name, Color::Cyan)), Cell::new(cell)]);
        }
        out.push_str(&format!("\n{}\n\n", table));
    }
    out
}

fn fail_color(token: &str) -> Color {
    // Label color: DNS FAIL is yellow, every other fail token is red.
    match token {
        "DNS FAIL" => Color::Yellow,
        _ => Color::Red,
    }
}

#[derive(Debug, Clone)]
pub struct PartialDnsEndpoint {
    pub provider: String,
    pub protocol: &'static str,
    pub endpoint: String,
    pub ok: usize,
    pub total: usize,
    pub min_ms: f64,
}

/// One latency line per endpoint: per-domain minimum in green (or yellow on partial
/// packet loss), per-addr fail label. Partial endpoints are recorded for post-table listing.
#[allow(clippy::too_many_arguments)]
fn dns_latency_lines(
    report: &DnsAvailReport,
    kind: ProbeKind,
    name: &str,
    addrs: &[String],
    domains: &[String],
    udp: bool,
    partial: &mut Vec<PartialDnsEndpoint>,
    ms_unit: &str,
) -> Vec<(String, Color)> {
    let mut lines = Vec::new();
    for a in addrs {
        let key = dpi_core::probe::dns_avail::ProbeKey {
            kind,
            addr: a.clone(),
            name: name.to_string(),
        };
        let dm = report.raw.get(&key);
        let vals: Vec<f64> = domains
            .iter()
            .filter_map(|d| dm.and_then(|m| m.get(d)).copied().flatten())
            .collect();
        if vals.is_empty() {
            // A UDP miss reads TIMEOUT; DoH/DoT show the recorded fail label.
            let token = if udp {
                "TIMEOUT".to_string()
            } else {
                report
                    .fail_reasons
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| "TIMEOUT".to_string())
            };
            lines.push((token.clone(), fail_color(&token)));
            continue;
        }
        let min = vals.iter().cloned().reduce(f64::min).unwrap_or(0.0);
        let text = format!("{:.1}{}", min, ms_unit);
        let color = if vals.len() == domains.len() {
            Color::Green
        } else {
            let proto = match kind {
                ProbeKind::DohWire => "DoH",
                ProbeKind::Dot => "DoT",
                ProbeKind::Udp => "UDP",
            };
            partial.push(PartialDnsEndpoint {
                provider: name.to_string(),
                protocol: proto,
                endpoint: a.clone(),
                ok: vals.len(),
                total: domains.len(),
                min_ms: min,
            });
            Color::Yellow
        };
        lines.push((text, color));
    }
    lines
}


pub fn render_dns_availability(report: &DnsAvailReport, cfg: &AppConfig, msg: &Messages) -> String {
    let mut out = String::new();
    let has_dot = !report.dot_servers.is_empty();

    let mut table = Table::new();
    table.load_preset(table_preset()).set_content_arrangement(ContentArrangement::Dynamic);
    let mut header = vec![
        Cell::new(format_bidi(msg.provider, msg.lang)),
        Cell::new(format_bidi(msg.doh_min, msg.lang)),
    ];
    if has_dot {
        header.push(Cell::new(format_bidi(msg.dot_min, msg.lang)));
    }
    header.extend([
        Cell::new(format_bidi(msg.udp_min, msg.lang)),
        Cell::new(format_bidi(msg.real_udp_resolver, msg.lang)),
        Cell::new(format_bidi(msg.spoofing, msg.lang)),
    ]);
    table.set_header(header);
    // by-name endpoint grouping
    let mut udp_by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (a, n, _) in &report.udp_servers {
        udp_by_name.entry(n.clone()).or_default().push(a.clone());
    }
    let mut doh_by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (a, n, _) in &report.doh_servers {
        doh_by_name.entry(n.clone()).or_default().push(a.clone());
    }
    let mut dot_by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (a, n, _) in &report.dot_servers {
        dot_by_name.entry(n.clone()).or_default().push(a.clone());
    }

    let mut partial_endpoints = Vec::new();

    for name in &report.all_names {
        // DoH cell: one line per endpoint.
        let doh_addrs = doh_by_name.get(name).cloned().unwrap_or_default();
        let doh_lines: Vec<(String, Color)> = if doh_addrs.is_empty() {
            vec![("—".to_string(), Color::DarkGrey)]
        } else {
            dns_latency_lines(report, ProbeKind::DohWire, name, &doh_addrs, &report.forbidden, false, &mut partial_endpoints, msg.ms_unit.trim())
        };

        // DoT cell: one line per endpoint.
        let mut dot_lines: Vec<(String, Color)> = Vec::new();
        if has_dot {
            let dot_addrs = dot_by_name.get(name).cloned().unwrap_or_default();
            if dot_addrs.is_empty() {
                dot_lines.push(("—".to_string(), Color::DarkGrey));
            } else {
                dot_lines = dns_latency_lines(report, ProbeKind::Dot, name, &dot_addrs, &report.forbidden, false, &mut partial_endpoints, msg.ms_unit.trim());
            }
        }

        // UDP cell (trusted-domain ping): one line per endpoint.
        let udp_addrs = udp_by_name.get(name).cloned().unwrap_or_default();
        let udp_lines: Vec<(String, Color)> = if udp_addrs.is_empty() {
            vec![("—".to_string(), Color::DarkGrey)]
        } else {
            dns_latency_lines(report, ProbeKind::Udp, name, &udp_addrs, &report.allowed, true, &mut partial_endpoints, msg.ms_unit.trim())
        };
        // Egress cell
        let mut egress_lines: Vec<(String, Option<Color>)> = Vec::new();
        for a in &udp_addrs {
            let key = dpi_core::probe::dns_avail::ProbeKey { kind: ProbeKind::Udp, addr: a.clone(), name: name.clone() };
            let alive = report.raw.get(&key).map(|dm| {
                report.allowed.iter().any(|d| dm.get(d).copied().flatten().is_some())
            }).unwrap_or(false);
            let eip = report.egress.get(&(a.clone(), name.clone())).copied().flatten();
            match (alive, eip) {
                (false, _) => egress_lines.push((format!("{}: {}", a, msg.timeout_label), Some(Color::DarkGrey))),
                (true, None) => egress_lines.push((format!("{}: {}", a, msg.egress_na), Some(Color::DarkGrey))),
                (true, Some(ip)) if ip == IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED) => {
                    egress_lines.push((format!("{}: {}", a, msg.egress_na), Some(Color::DarkGrey)));
                }
                (true, Some(ip)) => {
                    if dpi_core::probe::domains::fake_ip_type(&ip) == dpi_core::probe::domains::FakeIpType::FakeIp {
                        egress_lines.push((format!("{}→FakeIP", a), Some(Color::Magenta)));
                    } else {
                        let org = report.org_names.get(&ip.to_string()).cloned().unwrap_or_else(|| ip.to_string());
                        let label = org_label(&org);
                        if known_resolver(&label, &cfg.dns_known_resolver_names) {
                            egress_lines.push((format!("{}→{}", a, label), Some(Color::Green)));
                        } else {
                            egress_lines.push((format!("{}→{}", a, label), Some(Color::Red)));
                        }
                    }
                }
            }
        }
        let egress_text = egress_lines
            .iter()
            .map(|(t, c)| match c {
                Some(col) => cell_color(t, *col),
                None => t.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Substitution cell
        let mut subst_lines: Vec<(String, Color)> = Vec::new();
        if !udp_addrs.is_empty() && !report.forbidden.is_empty() {
            for a in &udp_addrs {
                let (judged, sub) = subst_counts(report, a, name);
                if judged == 0 {
                    subst_lines.push(("—".to_string(), Color::DarkGrey));
                    continue;
                }
                // FakeIP check
                let mut fake_n = 0;
                for d in &report.forbidden {
                    let key = dpi_core::probe::dns_avail::ProbeKey { kind: ProbeKind::Udp, addr: a.clone(), name: name.clone() };
                    if let Some(DnsAnswer::Ips(ips)) = report.udp_answers.get(&(key, d.clone())) {
                        if !ips.is_empty() && ips.iter().any(|ip| dpi_core::probe::domains::fake_ip_type(ip) == dpi_core::probe::domains::FakeIpType::FakeIp) {
                            fake_n += 1;
                        }
                    }
                }
                let frac = format!("{}/{}", sub, report.forbidden.len());
                if fake_n > 0 {
                    subst_lines.push((frac, Color::Magenta));
                } else if sub == report.forbidden.len() {
                    subst_lines.push((frac, Color::Red));
                } else if sub == 0 {
                    subst_lines.push((frac, Color::Green));
                } else {
                    subst_lines.push((frac, Color::Yellow));
                }
            }
        } else {
            subst_lines.push(("—".to_string(), Color::DarkGrey));
        }
        // Name column spans the tallest cell ("Google", "Google #2", ...).
        let n_rows = doh_lines
            .len()
            .max(dot_lines.len())
            .max(udp_lines.len())
            .max(egress_lines.len())
            .max(subst_lines.len())
            .max(1);
        let doh_text = join_cell_colored(doh_lines);
        let dot_text = join_cell_colored(dot_lines);
        let udp_text = join_cell_colored(udp_lines);
        let subst_text = join_cell_colored(subst_lines);
        let name_text = (0..n_rows)
            .map(|i| if i == 0 { name.clone() } else { format!("{} #{}", name, i + 1) })
            .collect::<Vec<_>>()
            .join("\n");
        let mut row = vec![
            Cell::new(cell_color(&name_text, Color::Cyan)),
            Cell::new(doh_text),
        ];
        if has_dot {
            row.push(Cell::new(dot_text));
        }
        row.push(Cell::new(udp_text));
        row.push(Cell::new(egress_text));
        row.push(Cell::new(subst_text));
        table.add_row(row);
    }

    out.push_str(&format!("{}\n", table));

    // The reference was not measured on this network, so a stale configured IP
    // must never look like a measurement.
    if report.truth_fallback_used {
        out.push('\n');
        out.push_str(&format!(
            "\x1b[1;33m[{}] {}\x1b[0m\n",
            warn_mark(),
            msg.dns_truth_fallback_note
        ));
    }

    if !partial_endpoints.is_empty() {
        out.push('\n');
        let warn = warn_mark();
        out.push_str(&format!(
            "\x1b[1;33m[{}] {}\x1b[0m\n",
            warn, msg.partial_dns_warn
        ));
        for p in &partial_endpoints {
            let bullet = asc("•");
            out.push_str(&format!(
                "  \x1b[33m{}\x1b[0m \x1b[1m{}\x1b[0m [{}] \x1b[2m{}\x1b[0m — \x1b[1;33m{}/{}\x1b[0m {} ({:.1}{})\n",
                bullet, p.provider, p.protocol, p.endpoint, p.ok, p.total, msg.replies_label, p.min_ms, msg.ms_unit
            ));
        }
    }

    // Hijack warning block
    let st = &report.stats;
    if st.subst_sub > 0 {
        out.push('\n');
        match st.top_stub.as_deref() {
            Some(top) if top.parse::<std::net::IpAddr>().map(|ip| dpi_core::probe::domains::fake_ip_type(&ip) == dpi_core::probe::domains::FakeIpType::FakeIp).unwrap_or(false) => {
                out.push_str(msg.dns_fakeip_warn);
                out.push('\n');
            }
            _ => {
                out.push_str(msg.dns_intercept_warn);
                out.push('\n');
                if let Some(top) = st.top_stub.as_deref() {
                    out.push_str(&format!("{}\n", msg.dns_stub_ip_label.replace("{}", top)));
                }
                out.push_str(msg.doh_recommendation);
                out.push('\n');
            }
        }
    }
    // /24 sharing info (brand → net) is computed in stats.hijacked_brands (summary row)
    let _ = net24;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Regression: latency cells aggregated addr counts against domain counts
    /// ("40.0мс 1/5"). Cells must carry one line per endpoint, with
    /// the name column spanning ("Google", "Google #2").
    #[test]
    fn dns_table_cells_are_per_endpoint() {
        use dpi_core::probe::dns_avail::{DnsAnswer, DnsAvailReport, ProbeKey, ProbeKind};
        use std::collections::HashMap;

        let mut report = DnsAvailReport {
            allowed: vec!["vk.ru".to_string(), "gosuslugi.ru".to_string()],
            forbidden: vec!["rutor.info".to_string()],
            udp_servers: vec![
                ("8.8.4.4".to_string(), "Google".to_string(), 53),
                ("8.8.8.8".to_string(), "Google".to_string(), 53),
            ],
            doh_servers: vec![(
                "https://dns.google/dns-query".to_string(),
                "Google".to_string(),
                443,
            )],
            all_names: vec!["Google".to_string()],
            ..Default::default()
        };
        for a in ["8.8.4.4", "8.8.8.8"] {
            let key = ProbeKey { kind: ProbeKind::Udp, addr: a.to_string(), name: "Google".to_string() };
            let mut dm = HashMap::new();
            dm.insert("vk.ru".to_string(), Some(10.0));
            dm.insert("gosuslugi.ru".to_string(), Some(12.0));
            dm.insert("rutor.info".to_string(), Some(11.0));
            report.raw.insert(key.clone(), dm);
            report.egress.insert(
                (a.to_string(), "Google".to_string()),
                Some("8.8.4.4".parse().unwrap()),
            );
            report.udp_answers.insert(
                (key, "rutor.info".to_string()),
                DnsAnswer::Ips(vec!["1.2.3.4".parse().unwrap()]),
            );
        }
        let dkey = ProbeKey {
            kind: ProbeKind::DohWire,
            addr: "https://dns.google/dns-query".to_string(),
            name: "Google".to_string(),
        };
        let mut ddm = HashMap::new();
        ddm.insert("rutor.info".to_string(), Some(30.0));
        report.raw.insert(dkey.clone(), ddm);
        report.doh_answers.insert(
            (dkey, "rutor.info".to_string()),
            DnsAnswer::Ips(vec!["5.6.7.8".parse().unwrap()]),
        );
        report.org_names.insert("8.8.4.4".to_string(), "GOOGLE - Google LLC".to_string());
        let cfg = AppConfig::default();
        let out = render_dns_availability(&report, &cfg, &dpi_core::i18n::get_messages(dpi_core::i18n::Language::Ru));
        // One line per endpoint, full success shows no fraction.
        assert!(out.contains("Google #2"), "name spans tallest cell");
        assert!(!out.contains("1/5"), "no addr/domain count mix-up");
        assert!(!out.contains("1/2"), "no addr/domain count mix-up");
        assert!(out.contains("8.8.4.4"), "per-addr egress lines");
        assert!(out.contains("8.8.8.8"), "per-addr egress lines");
    }
}

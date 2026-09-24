//! Test 0: network and system - public IP, TTLB, ASN/org, system DNS, bypass tools.

use crate::i18n::Messages;
use dpi_core::net::netinfo::{SystemDnsInfo, is_tun_name};
use dpi_core::probe::domains::{FakeIpType, fake_ip_type};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::tui::widgets::{BOX_WIDTH, geo_country_ascii, panel_with, strip_ansi_len};

/// TTLB cell: the probe timed out, or a measured round-trip in milliseconds.
#[derive(Debug, Clone)]
pub(crate) enum NetTtlb {
    Timeout,
    Ms(u64),
}
/// Per-family network fact: address, TTLB, subnet, org, ASN and country code.
#[derive(Debug, Clone)]
pub(crate) struct NetFamilyInfo {
    pub ip: String,
    pub ttlb: NetTtlb,
    pub subnet: String,
    pub org: String,
    pub asn: String,
    pub cc: String,
}

pub(crate) struct NetInfoData {
    pub v4: Option<NetFamilyInfo>,
    pub v6: Option<NetFamilyInfo>,
    /// Legacy empty-dict branch: placeholder rows.
    pub empty: bool,
}

/// Value color: red for the literal "timeout", cyan for anything else.
fn cyan_val(v: &str) -> String {
    if v == "timeout" {
        format!("\x1b[31m{}\x1b[0m", v)
    } else {
        format!("\x1b[36m{}\x1b[0m", v)
    }
}

fn dim_val(v: &str) -> String {
    format!("\x1b[2m{}\x1b[0m", v)
}

fn ttlb_str(t: &NetTtlb, msg: &Messages) -> String {
    match t {
        NetTtlb::Timeout => format!("\x1b[31m{}\x1b[0m", msg.timeout_label),
        NetTtlb::Ms(ms) => format!("\x1b[2m{} {}\x1b[0m", ms, msg.ms_unit),
    }
}

/// DNS block: label, comma-joined addresses in cyan and a tail, wrapped at 70 columns.
/// Widths are char counts; the tail glues to the last chunk when it fits.
fn dns_block_lines(label: &str, ips: &[String], tail: &str) -> Vec<String> {
    const W: usize = 70;
    const IND: usize = 15;
    let n = |s: &str| s.chars().count();
    let joined = ips.join(", ");
    if n(label) + n(&joined) + n(tail) <= W {
        return vec![format!("{}{}{}", label, cyan_val(&joined), tail)];
    }
    let mut limit_end = W.saturating_sub(IND + n(tail));
    let tail_own = limit_end < 8;
    if tail_own {
        limit_end = W - IND;
    }
    let mut end_chunk = String::new();
    let mut rest: Vec<&String> = ips.iter().collect();
    while let Some(ip) = rest.pop() {
        let piece = if end_chunk.is_empty() { (*ip).clone() } else { format!("{}, {}", ip, end_chunk) };
        if n(&piece) <= limit_end {
            end_chunk = piece;
        } else {
            rest.push(ip);
            break;
        }
    }
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ip in rest {
        let piece = if cur.is_empty() { (*ip).clone() } else { format!("{}, {}", cur, ip) };
        if n(&piece) <= W - IND {
            cur = piece;
        } else {
            chunks.push(cur);
            cur = (*ip).clone();
        }
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    if !end_chunk.is_empty() {
        chunks.push(end_chunk);
    }
    if chunks.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let last = chunks.len() - 1;
    for (i, c) in chunks.iter().enumerate() {
        if i == last && !tail_own {
            out.push(format!("{}{}{}", " ".repeat(IND), cyan_val(c), tail));
        } else {
            out.push(format!("{}{}", " ".repeat(IND), cyan_val(c)));
        }
    }
    if let Some(first) = out.first_mut() {
        *first = format!("{}{}", label, cyan_val(&chunks[0]));
    }
    if tail_own {
        out.push(format!("{}{}", " ".repeat(IND), tail));
    }
    out
}

pub(crate) fn render_netinfo_panel(
    data: &NetInfoData,
    dns_info: &SystemDnsInfo,
    bypass_tools: &[String],
    msg: &Messages,
) -> String {
    let mut lines = Vec::new();
    // Cymru-less fields carry the canonical "timeout" marker; it renders red
    // like the DNS cells and follows the interface language.
    let val = |v: &str| {
        if v == "timeout" {
            format!("\x1b[31m{}\x1b[0m", msg.timeout_label)
        } else {
            cyan_val(v)
        }
    };

    if data.empty {
        lines.push(format!(
            "IPv4: {}  {} {}  {} …",
            cyan_val("…"),
            msg.subnet_label,
            cyan_val("…"),
            msg.ttlb_label
        ));
        lines.push(format!("IPv6: {}", cyan_val("…")));
        lines.push(format!("{} {}", msg.org_label, cyan_val("…")));
        lines.push(format!("{} {}", msg.location_label, cyan_val("…")));
    } else {
        match data.v4.as_ref() {
            Some(f) if !f.ip.is_empty() => {
                lines.push(format!(
                    "IPv4: {}  {} {}  {} {}",
                    cyan_val(&f.ip),
                    msg.subnet_label,
                    val(&f.subnet),
                    msg.ttlb_label,
                    ttlb_str(&f.ttlb, msg)
                ));
            }
            _ => lines.push(format!("IPv4: {}", dim_val(msg.unavailable))),
        }
        match data.v6.as_ref() {
            Some(f) if !f.ip.is_empty() => {
                lines.push(format!("IPv6: {}", cyan_val(&f.ip)));
                lines.push(format!(
                    "      {} {}  {} {}",
                    msg.subnet_label,
                    val(&f.subnet),
                    msg.ttlb_label,
                    ttlb_str(&f.ttlb, msg)
                ));
            }
            _ => lines.push(format!("IPv6: {}", dim_val(msg.unavailable))),
        }
        let v4_org = data.v4.as_ref().map(|f| f.org.as_str()).unwrap_or("");
        let v4_asn = data.v4.as_ref().map(|f| f.asn.as_str()).unwrap_or("");
        let v4_cc = data.v4.as_ref().map(|f| f.cc.as_str()).unwrap_or("");
        let v6_org = data.v6.as_ref().map(|f| f.org.as_str()).unwrap_or("");
        let v6_asn = data.v6.as_ref().map(|f| f.asn.as_str()).unwrap_or("");
        let v6_cc = data.v6.as_ref().map(|f| f.cc.as_str()).unwrap_or("");
        let org_s = if !v4_org.is_empty() && !v6_org.is_empty() && v4_org != v6_org {
            let s4 = if !v4_asn.is_empty() {
                format!("{} (AS{})", v4_org, v4_asn)
            } else {
                v4_org.to_string()
            };
            let s6 = if !v6_asn.is_empty() {
                format!("{} (AS{})", v6_org, v6_asn)
            } else {
                v6_org.to_string()
            };
            format!("{} {}, {} {}", s4, dim_val("(v4)"), s6, dim_val("(v6)"))
        } else {
            let main_org = if !v4_org.is_empty() {
                v4_org
            } else if !v6_org.is_empty() {
                v6_org
            } else {
                "…"
            };
            let main_asn = if !v4_asn.is_empty() {
                v4_asn
            } else if !v6_asn.is_empty() {
                v6_asn
            } else {
                ""
            };
            if !main_asn.is_empty() {
                format!("{} (AS{})", main_org, main_asn)
            } else {
                main_org.to_string()
            }
        };
        lines.push(format!("{} {}", msg.org_label, val(&org_s)));
        let loc = if !v4_cc.is_empty() && !v6_cc.is_empty() && v4_cc != v6_cc {
            format!(
                "{} {} {}, {} {} {}",
                geo_country_ascii(v4_cc).trim(),
                v4_cc,
                dim_val("(v4)"),
                geo_country_ascii(v6_cc).trim(),
                v6_cc,
                dim_val("(v6)")
            )
        } else {
            let main_cc = if !v4_cc.is_empty() {
                v4_cc
            } else if !v6_cc.is_empty() {
                v6_cc
            } else {
                "…"
            };
            if main_cc == "…" {
                "…".to_string()
            } else {
                format!("{} {}", geo_country_ascii(main_cc).trim(), main_cc)
            }
        };
        lines.push(format!("{} {}", msg.location_label, val(&loc)));
    }

    if let Some(os) = dns_info.os.as_ref() {
        lines.push(format!("{} {}", msg.os, cyan_val(os)));
    }
    if !dns_info.active.is_empty() {
        let a_name = dns_info.active_name.clone().unwrap_or_default();
        let a_ip = dns_info.active_ip.clone().unwrap_or_default();
        let iface_shown = !a_name.is_empty() && !a_ip.is_empty();
        let mark = |ips: &[String]| {
            ips.iter()
                .map(|ip| {
                    if dns_info.doh.contains_key(ip) {
                        format!("{}(DoH)", ip)
                    } else {
                        ip.clone()
                    }
                })
                .collect::<Vec<_>>()
        };
        let ips_all: Vec<String> = dns_info.active.iter().map(|e| e.0.clone()).collect();
        let srcs: HashSet<&str> = dns_info.active.iter().map(|e| e.1.as_str()).collect();
        let mut src_label = String::new();
        if ips_all.iter().any(|ip| {
            ip.parse::<IpAddr>()
                .map(|a| fake_ip_type(&a) == FakeIpType::FakeIp)
                .unwrap_or(false)
        }) {
            src_label = "fake-ip".to_string();
        } else if is_tun_name(&a_name) {
            src_label = "TUN".to_string();
        } else if srcs.len() == 1 && srcs.contains("wsl") {
            src_label = msg.wsl_proxy.to_string();
        } else if srcs.len() == 1 && srcs.contains("dhcp") {
            src_label = "DHCP".to_string();
        }
        if (src_label == "fake-ip" || src_label == "TUN")
            && bypass_tools.iter().any(|b| b.to_lowercase().contains("xray"))
        {
            src_label += ", xray";
        }
        let tail = if !src_label.is_empty() && !iface_shown && !a_name.is_empty() {
            format!(" ({}, {})", src_label, a_name)
        } else if !src_label.is_empty() {
            format!(" ({})", src_label)
        } else if !iface_shown && !a_name.is_empty() {
            format!(" ({})", a_name)
        } else {
            String::new()
        };
        lines.extend(dns_block_lines(&format!("{} ", msg.system_dns), &mark(&ips_all), &tail));
        if iface_shown {
            lines.push(format!("{} {} ({})", msg.active_interface, cyan_val(&a_ip), a_name));
        }
        if !dns_info.other_static.is_empty() {
            let mut order: Vec<&String> = Vec::new();
            let mut by_name: HashMap<&String, Vec<String>> = HashMap::new();
            for (ip, n) in &dns_info.other_static {
                if !by_name.contains_key(n) {
                    order.push(n);
                    by_name.insert(n, Vec::new());
                }
                if let Some(v) = by_name.get_mut(n) {
                    v.push(ip.clone());
                }
            }
            for (k, n) in order.iter().enumerate() {
                let label = if k == 0 { format!("{} ", msg.inactive_dns) } else { " ".repeat(16) };
                if let Some(v) = by_name.get(*n) {
                    lines.extend(dns_block_lines(&label, &mark(v), &format!(" ({})", n)));
                }
            }
        }
    }
    if let Some(up) = dns_info.upstream.as_ref() {
        let label = dns_info.upstream_label.clone().unwrap_or_else(|| msg.router_resolver.to_string());
        lines.push(format!("{}: {}", label, cyan_val(up)));
    }
    let mut bypass: Vec<String> = bypass_tools.to_vec();
    if !bypass.is_empty() {
        let mut names_l = dns_info.active_name.clone().unwrap_or_default().to_lowercase();
        for (_, n) in &dns_info.other_static {
            names_l.push(' ');
            names_l.push_str(&n.to_lowercase());
        }
        bypass.retain(|t| t != "AmneziaWG" || names_l.contains("warp") || names_l.contains("amnezia"));
    }
    if let Some(w) = dns_info.wsl_net.as_ref() {
        lines.push(format!("{} {}", msg.wsl_network, cyan_val(w)));
    }
    if !bypass.is_empty() {
        lines.push(format!(
            "{} \x1b[33m{}\x1b[0m",
            msg.local_bypass,
            bypass.join(", ")
        ));
    } else {
        lines.push(format!(
            "{} {}",
            msg.local_bypass,
            dim_val(msg.not_detected)
        ));
    }

    // Content lines get two leading spaces here; the panel adds one more
    // padding space, so body rows start with three.
    let lines: Vec<String> = lines.iter().map(|l| format!("  {}", l)).collect();
    let mut width = BOX_WIDTH;
    for l in &lines {
        let w = strip_ansi_len(l) + 6;
        if w > width {
            width = w;
        }
    }
    panel_with(msg.netinfo_title, &lines, width, true, "2")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn netinfo_fixture() -> (NetInfoData, SystemDnsInfo, Vec<String>) {
        use dpi_core::net::netinfo::SystemDnsInfo;
        let data = NetInfoData {
            v4: Some(NetFamilyInfo {
                ip: "203.0.113.7".to_string(),
                ttlb: NetTtlb::Ms(701),
                subnet: "203.0.113.0/24".to_string(),
                org: "EXAMPLE-AS".to_string(),
                asn: "65001".to_string(),
                cc: "US".to_string(),
            }),
            v6: None,
            empty: false,
        };
        let dns = SystemDnsInfo {
            active: vec![("192.0.2.1".to_string(), "dhcp".to_string())],
            active_name: Some("Ethernet".to_string()),
            active_ip: Some("192.0.2.10".to_string()),
            other_static: vec![("198.51.100.2".to_string(), "Wi-Fi".to_string())],
            os: Some("Windows 11 (26200)".to_string()),
            upstream: Some("203.0.113.1 (EXAMPLE UP)".to_string()),
            ..Default::default()
        };
        (data, dns, Vec::new())
    }

    /// The panel is the product surface, so its vocabulary is pinned: every label
    /// in the active language, next to the value it belongs to. What is NOT pinned
    /// is the exact escape bytes or the width of the gap between the columns —
    /// those fail on a harmless layout tweak and are not what a reader sees.
    #[test]
    fn netinfo_panel_matches_expected_rows() {
        use crate::i18n::get_messages;
        use crate::i18n::Language;
        use crate::render::strip_ansi;
        let (data, dns, bypass) = netinfo_fixture();
        let out = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Ru));
        let text = strip_ansi(&out);
        for row in [
            "IPv4: 203.0.113.7",
            "Subnet: 203.0.113.0/24",
            "TTLB: 701 мс",
            "IPv6: недоступен",
            "Org: EXAMPLE-AS (AS65001)",
            "ОС: Windows 11 (26200)",
            "Системный DNS: 192.0.2.1 (DHCP)",
            "Активный интерфейс: 192.0.2.10 (Ethernet)",
            "Неактивные DNS: 198.51.100.2 (Wi-Fi)",
            "Резолвер роутера: 203.0.113.1 (EXAMPLE UP)",
            "Локальный обход DPI на устройстве: не обнаружен",
        ] {
            assert!(text.contains(row), "{row} missing from the panel: {text}");
        }
        // The colour role, separately: a measured value is cyan, a value that is
        // simply not there is dim. Both are language-independent.
        assert!(out.contains("\x1b[36m203.0.113.7\x1b[0m"), "IPv4 value is cyan");
        assert!(out.contains("\x1b[2mнедоступен\x1b[0m"), "an unavailable value is dim");
    }

    /// The same vocabulary contract in the other two languages. Only the words
    /// are pinned, not the styling around them.
    #[test]
    fn netinfo_panel_renders_english_and_chinese() {
        use crate::i18n::get_messages;
        use crate::i18n::Language;
        use crate::render::strip_ansi;
        let (data, dns, bypass) = netinfo_fixture();

        let out_en = strip_ansi(&render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::En)));
        for row in [
            "IPv6: unavailable",
            "OS: Windows 11 (26200)",
            "System DNS: 192.0.2.1 (DHCP)",
            "Active interface: 192.0.2.10 (Ethernet)",
            "Inactive DNS: 198.51.100.2 (Wi-Fi)",
            "Router resolver: 203.0.113.1 (EXAMPLE UP)",
            "Local DPI bypass on device: not detected",
        ] {
            assert!(out_en.contains(row), "{row} missing from the English panel: {out_en}");
        }

        let out_zh = strip_ansi(&render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Zh)));
        for row in [
            "IPv6: 不可用",
            "操作系统: Windows 11 (26200)",
            "系统 DNS: 192.0.2.1 (DHCP)",
            "活动接口: 192.0.2.10 (Ethernet)",
            "非活动 DNS: 198.51.100.2 (Wi-Fi)",
            "路由器解析器: 203.0.113.1 (EXAMPLE UP)",
            "设备本地 DPI 绕过: 未检测到",
        ] {
            assert!(out_zh.contains(row), "{row} missing from the Chinese panel: {out_zh}");
        }
    }

    #[test]
    fn netinfo_timeout_rows_are_red() {
        use crate::i18n::get_messages;
        use crate::i18n::Language;
        let t = || "timeout".to_string();
        let data = NetInfoData {
            v4: Some(NetFamilyInfo {
                ip: "203.0.113.7".to_string(),
                ttlb: NetTtlb::Ms(100),
                subnet: t(),
                org: t(),
                asn: t(),
                cc: t(),
            }),
            v6: None,
            empty: false,
        };
        let dns = Default::default();
        let out = render_netinfo_panel(&data, &dns, &[], &get_messages(Language::Ru));
        assert!(out.contains("\x1b[31mтаймаут\x1b[0m"), "cymru-less fields render red");
    }

    #[test]
    fn netinfo_filters_amnezia_without_warp() {
        use crate::i18n::get_messages;
        use crate::i18n::Language;
        let (data, dns, _) = netinfo_fixture();
        let bypass = vec!["AmneziaWG".to_string(), "xray".to_string()];
        let out = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Ru));
        assert!(!out.contains("AmneziaWG"), "filtered without warp/amnezia adapter");
        assert!(out.contains("xray"), "other tools stay");
    }

    #[test]
    fn dns_block_lines_wrap_at_70_cols() {
        let ips: Vec<String> = (1..=8).map(|i| format!("192.0.2.{}", i)).collect();
        let lines = dns_block_lines("Системный DNS: ", &ips, " (DHCP)");
        assert!(lines.len() > 1, "long server list wraps");
        assert!(lines[0].starts_with("Системный DNS: "), "first line keeps the label");
        assert!(lines[1].starts_with("               "), "continuation indented by 15");
        assert!(lines.last().unwrap().ends_with(" (DHCP)"), "tail glued to last chunk");
    }
}

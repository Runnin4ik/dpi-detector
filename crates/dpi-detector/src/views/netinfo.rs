//! Test 0: network and system - public IP, TTLB, ASN/org, system DNS, bypass tools.

use crate::i18n::Messages;
use dpi_core::net::netinfo::{SystemDnsInfo, is_tun_name};
use dpi_core::net::sysinfo::DnsSource;
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
///
/// The Cymru fields are `Option` because "the lookup never answered" is a fact
/// of its own: it used to travel here as a bare string, which the panel had to
/// recognize back by comparing text — and a *composed* row
/// (`"timeout (AStimeout)"`) no longer matched that text, so it printed as a
/// value. `ip` is `Option` for the same reason: `timeout_family` is a family
/// that was probed and answered nothing, which the panel draws as a timeout row
/// — unlike `None` in `NetInfoData`, a family that is not on the link at all
/// and gets the dim "unavailable" row.
#[derive(Debug, Clone)]
pub(crate) struct NetFamilyInfo {
    pub ip: Option<String>,
    pub ttlb: NetTtlb,
    pub subnet: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub cc: Option<String>,
}

pub(crate) struct NetInfoData {
    pub v4: Option<NetFamilyInfo>,
    pub v6: Option<NetFamilyInfo>,
    /// Legacy empty-dict branch: placeholder rows.
    pub empty: bool,
}

/// A measured value: cyan.
fn cyan_val(v: &str) -> String {
    format!("\x1b[36m{}\x1b[0m", v)
}

/// A Cymru field of the panel: cyan when the lookup answered, the red
/// localized timeout label when it did not. This is the only place the two
/// readings are told apart — the state itself lives in the `Option`.
fn family_val(v: Option<&str>, msg: &Messages) -> String {
    match v {
        Some(v) => cyan_val(v),
        None => format!("\x1b[31m{}\x1b[0m", msg.timeout_label),
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
        // A family that is `Some` was probed: `None` here is "that family is
        // not on this link at all", which is what the dim unavailable row says.
        // Whether the address itself was measured is the field's own `Option`.
        match data.v4.as_ref() {
            Some(f) => {
                lines.push(format!(
                    "IPv4: {}  {} {}  {} {}",
                    family_val(f.ip.as_deref(), msg),
                    msg.subnet_label,
                    family_val(f.subnet.as_deref(), msg),
                    msg.ttlb_label,
                    ttlb_str(&f.ttlb, msg)
                ));
            }
            None => lines.push(format!("IPv4: {}", dim_val(msg.unavailable))),
        }
        match data.v6.as_ref() {
            Some(f) => {
                lines.push(format!("IPv6: {}", family_val(f.ip.as_deref(), msg)));
                lines.push(format!(
                    "      {} {}  {} {}",
                    msg.subnet_label,
                    family_val(f.subnet.as_deref(), msg),
                    msg.ttlb_label,
                    ttlb_str(&f.ttlb, msg)
                ));
            }
            None => lines.push(format!("IPv6: {}", dim_val(msg.unavailable))),
        }
        // Per family: `None` is "Cymru never answered", an empty string is an
        // answer that carried no value (the org query returns the allocation
        // date as an empty name). Only the first is a timeout; the second falls
        // back like any other missing field, as it always did.
        let f4 = data.v4.as_ref();
        let f6 = data.v6.as_ref();
        let org4 = f4.and_then(|f| f.org.as_deref()).filter(|s| !s.is_empty());
        let asn4 = f4.and_then(|f| f.asn.as_deref()).filter(|s| !s.is_empty());
        let cc4 = f4.and_then(|f| f.cc.as_deref()).filter(|s| !s.is_empty());
        let org6 = f6.and_then(|f| f.org.as_deref()).filter(|s| !s.is_empty());
        let asn6 = f6.and_then(|f| f.asn.as_deref()).filter(|s| !s.is_empty());
        let cc6 = f6.and_then(|f| f.cc.as_deref()).filter(|s| !s.is_empty());
        let org_asn = |org: &str, asn: Option<&str>| match asn {
            Some(asn) => format!("{} (AS{})", org, asn),
            None => org.to_string(),
        };
        // Two measured orgs that differ are shown side by side; otherwise the
        // one that was measured. Nothing measured at all is `None` — the red
        // label. That row used to be composed as `"timeout (AStimeout)"` and
        // printed cyan, because only a lone marker word was recognized.
        let org_s = match (org4, org6) {
            (Some(a), Some(b)) if a != b => Some(format!(
                "{} {}, {} {}",
                org_asn(a, asn4),
                dim_val("(v4)"),
                org_asn(b, asn6),
                dim_val("(v6)")
            )),
            _ => match org4.or(org6) {
                Some(org) => Some(org_asn(org, asn4.or(asn6))),
                None => asn4.or(asn6).map(|asn| format!("… (AS{})", asn)),
            },
        };
        lines.push(format!("{} {}", msg.org_label, family_val(org_s.as_deref(), msg)));
        let loc = match (cc4, cc6) {
            (Some(a), Some(b)) if a != b => Some(format!(
                "{} {} {}, {} {} {}",
                geo_country_ascii(a).trim(),
                a,
                dim_val("(v4)"),
                geo_country_ascii(b).trim(),
                b,
                dim_val("(v6)")
            )),
            _ => cc4.or(cc6).map(|cc| format!("{} {}", geo_country_ascii(cc).trim(), cc)),
        };
        lines.push(format!("{} {}", msg.location_label, family_val(loc.as_deref(), msg)));
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
        let srcs: HashSet<DnsSource> = dns_info.active.iter().map(|e| e.1).collect();
        let mut src_label = String::new();
        if ips_all.iter().any(|ip| {
            ip.parse::<IpAddr>()
                .map(|a| fake_ip_type(&a) == FakeIpType::FakeIp)
                .unwrap_or(false)
        }) {
            src_label = "fake-ip".to_string();
        } else if is_tun_name(&a_name) {
            src_label = "TUN".to_string();
        } else if srcs.len() == 1 && srcs.contains(&DnsSource::Wsl) {
            src_label = msg.wsl_proxy.to_string();
        } else if srcs.len() == 1 && srcs.contains(&DnsSource::Dhcp) {
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
                ip: Some("203.0.113.7".to_string()),
                ttlb: NetTtlb::Ms(701),
                subnet: Some("203.0.113.0/24".to_string()),
                org: Some("EXAMPLE-AS".to_string()),
                asn: Some("65001".to_string()),
                cc: Some("US".to_string()),
            }),
            v6: None,
            empty: false,
        };
        let dns = SystemDnsInfo {
            active: vec![("192.0.2.1".to_string(), DnsSource::Dhcp)],
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

    /// A family whose address was measured but whose Cymru lookup was not — the
    /// DoH query timed out, so the producer hands over `None` for every Cymru
    /// field — reads as the red localized timeout label in each of them.
    ///
    /// This is the state that used to print a *value*: "not measured" was a
    /// string, and the org row was composed as `format!("{} (AS{})", org, asn)`
    /// = `"timeout (AStimeout)"`, which no longer equalled the marker the panel
    /// compared against — so a cyan `timeout (AStimeout)` was drawn instead of
    /// the label. The org-row assertion and the sentinel check below are what
    /// fails on that code.
    #[test]
    fn netinfo_timeout_rows_are_red() {
        use crate::i18n::get_messages;
        use crate::i18n::Language;
        let msg = get_messages(Language::Ru);
        // The producer's own path: an address from the public-IP race, no Cymru.
        let v4 = crate::runner::family_info(Some(("203.0.113.7".parse().unwrap(), 100)), None).unwrap();
        let data = NetInfoData { v4: Some(v4), v6: None, empty: false };
        let dns = Default::default();
        let out = render_netinfo_panel(&data, &dns, &[], &msg);
        let red = format!("\x1b[31m{}\x1b[0m", msg.timeout_label);
        assert!(out.contains(&red), "cymru-less fields render red: {out}");
        assert!(
            out.contains(&format!("{} {}", msg.org_label, red)),
            "the org row is the red timeout label: {out}"
        );
        assert!(!out.contains("AStimeout"), "no sentinel leaks in as a value: {out}");
    }

    /// Both public-IP lookups dead (`timeout_family`): every cell of both
    /// families is the red timeout label. It must not become the dim
    /// "unavailable" row — that one means the family is not on this link at all,
    /// and the two states are told apart by the family being present, not by the
    /// address being non-empty (which is what the panel used to do).
    #[test]
    fn netinfo_dead_lookups_are_timeout_rows_not_unavailable() {
        use crate::i18n::get_messages;
        use crate::i18n::Language;
        let msg = get_messages(Language::Ru);
        let data = NetInfoData {
            v4: Some(crate::runner::timeout_family()),
            v6: Some(crate::runner::timeout_family()),
            empty: false,
        };
        let out = render_netinfo_panel(&data, &Default::default(), &[], &msg);
        let red = format!("\x1b[31m{}\x1b[0m", msg.timeout_label);
        assert!(out.contains(&format!("IPv4: {red}")), "IPv4 row is the red label: {out}");
        assert!(out.contains(&format!("IPv6: {red}")), "IPv6 row is the red label: {out}");
        assert!(!out.contains(msg.unavailable), "not the dim unavailable row: {out}");
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

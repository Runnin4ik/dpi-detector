use comfy_table::presets::{ASCII_FULL_CONDENSED, UTF8_FULL_CONDENSED};
use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::DpiStatus;
use dpi_core::config::AppConfig;
use dpi_core::dns::availability::{
    is_domestic, known_resolver, net24, org_label, subst_counts, DnsAvailReport, ProbeKind,
};
use dpi_core::dns::availability::DnsAnswer;
use dpi_core::i18n::Messages;
use dpi_core::net::netinfo::{flag_emoji, is_tun_name, SystemDnsInfo};
use dpi_core::probe::domains::{fake_ip_type, DomainEntry, DomainStats, FakeIpType};
use dpi_core::probe::telegram::TelegramFullReport;
use dpi_core::probe::whitelist::{AsVerdict, WhitelistReport};
use dpi_core::profile::RegionProfile;

use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::OnceLock;
use std::time::Duration;
/// ASCII-only output for legacy consoles (see `--ascii`).
static ASCII_MODE: OnceLock<bool> = OnceLock::new();

/// Enables ASCII-only output (font-safe glyphs, ASCII table borders).
pub fn set_ascii_mode(v: bool) {
    let _ = ASCII_MODE.set(v);
}

/// Whether ASCII-only output is on.
pub fn ascii_mode() -> bool {
    *ASCII_MODE.get().unwrap_or(&false)
}

/// Replaces font-risky glyphs when ASCII mode is on; passthrough otherwise.
/// Apply to content BEFORE width measurement ([OK]/-> widen the text).
pub fn asc_with(s: &str, ascii: bool) -> String {
    if !ascii {
        return s.to_string();
    }
    // Single pass, single allocation (ASCII expansions widen the text).
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '✓' => out.push_str("[OK]"),
            '→' => out.push_str("->"),
            '►' => out.push('>'),
            '•' | '─' | '╌' | '–' | '—' => out.push('-'),
            '●' => out.push('*'),
            '○' => out.push('o'),
            '√' => out.push('x'),
            '↑' => out.push('^'),
            '↓' => out.push('v'),
            '←' => out.push('<'),
            '⚠' => out.push('!'),
            '≈' => out.push('~'),
            '×' => out.push('x'),
            '╭' | '╮' | '╰' | '╯' | '┌' | '┬' | '┐' | '├' | '┼' | '┤' | '└' | '┴' | '┘' | '╞' | '╪' | '╡' => {
                out.push('+');
            }
            '│' => out.push('|'),
            _ => out.push(c),
        }
    }
    out
}

/// Glyph-safe string for the current output mode.
pub fn asc(s: &str) -> String {
    asc_with(s, ascii_mode())
}

/// Table border preset for the current output mode.
fn table_preset() -> &'static str {
    if ascii_mode() {
        ASCII_FULL_CONDENSED
    } else {
        UTF8_FULL_CONDENSED
    }
}

/// Country flag for the current mode (emoji needs a CJK/emoji font).
fn geo_country_ascii(cc: &str) -> String {
    if ascii_mode() {
        format!(" [{}]", cc.trim().to_uppercase())
    } else {
        format!(" {}", flag_emoji(cc))
    }
}

/// Warning mark for the current mode.
fn warn_mark() -> &'static str {
    if ascii_mode() {
        "!"
    } else {
        "⚠"
    }
}
pub const BOX_WIDTH: usize = 71;

/// Maps a probe status to its table cell color (mirrors the Rich markup).
pub fn status_color(s: DpiStatus) -> Color {
    match s {
        DpiStatus::Ok | DpiStatus::Redir => Color::Green,
        DpiStatus::NoTls13 | DpiStatus::NoCa => Color::Yellow,
        DpiStatus::LocalIp | DpiStatus::DnsFail | DpiStatus::NxDomain => Color::Yellow,
        DpiStatus::Err => Color::DarkGrey,
        _ => Color::Red,
    }
}

fn strip_ansi_len(s: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            count += 1;
        }
    }
    count
}

pub fn panel_to_string(title: &str, lines: &[String]) -> String {
    panel_with(title, lines, BOX_WIDTH, false, "1;36")
}

/// Panel with explicit width, title alignment and border SGR code.
/// Mirrors Rich: banner is left-titled cyan, netinfo centered dim.
pub fn panel_with(title: &str, lines: &[String], width: usize, centered: bool, border: &str) -> String {
    // Glyph-safe content first: widths are measured after replacement.
    let title_clean = format!(" {} ", asc(title));
    let lines: Vec<String> = lines.iter().map(|l| asc(l)).collect();
    let mut out = String::new();
    // Titles may carry SGR escapes (e.g. the bold banner title): measure visible
    // width only, and re-arm the border color after the title so an inner reset
    // cannot bleach the border run or shift the right edge.
    let title_len = strip_ansi_len(&title_clean);
    let inner = width.saturating_sub(2);
    let (tl, tr, bl, br, hb, vb) = if ascii_mode() {
        ("+", "+", "+", "+", "-", "|")
    } else {
        ("╭", "╮", "╰", "╯", "─", "│")
    };
    if centered {
        let left = inner.saturating_sub(title_len) / 2;
        let right = inner.saturating_sub(title_len + left);
        out.push_str(&format!(
            "\x1b[{border}m{}{}\x1b[{border}m{}\x1b[{border}m{}{}\x1b[0m\n",
            tl,
            hb.repeat(left),
            title_clean,
            hb.repeat(right),
            tr
        ));
    } else {
        let border_total = width.saturating_sub(title_len + 3);
        out.push_str(&format!(
            "\x1b[{border}m{}{}\x1b[{border}m{}\x1b[{border}m{}\x1b[{border}m{}\x1b[0m\n",
            tl, hb, title_clean, hb.repeat(border_total), tr
        ));
    }
    for line in &lines {
        let plain_len = strip_ansi_len(line);
        let pad = width.saturating_sub(plain_len + 3);
        out.push_str(&format!("\x1b[{border}m{}\x1b[0m {}{}\x1b[{border}m{}\x1b[0m\n", vb, line, " ".repeat(pad), vb));
    }
    out.push_str(&format!("\x1b[{border}m{}{}{}\x1b[0m\n", bl, hb.repeat(width.saturating_sub(2)), br));
    out
}
struct ProgressState {
    desc: String,
    total: usize,
    parens: bool,
}

/// Live one-line progress on stderr (mirrors rich transient `Progress` and the
/// `\r` DNS bar). Draws only when stderr is a TTY; silent otherwise so pipes
/// and the report file stay byte-clean.
pub struct LiveProgress {
    state: Mutex<ProgressState>,
    done: AtomicUsize,
    tty: bool,
}

impl LiveProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ProgressState { desc: String::new(), total: 0, parens: true }),
            done: AtomicUsize::new(0),
            tty: std::io::stderr().is_terminal(),
        })
    }

    /// Starts (or restarts) a phase: resets the counter and draws `(0/total)`.
    pub fn set(&self, desc: String, total: usize, parens: bool) {
        self.done.store(0, Ordering::SeqCst);
        if let Ok(mut st) = self.state.lock() {
            *st = ProgressState { desc, total, parens };
        }
        self.draw();
    }

    pub fn tick(&self) {
        self.done.fetch_add(1, Ordering::SeqCst);
        self.draw();
    }

    /// Clears the line (transient: nothing remains after the phase).
    pub fn finish(&self) {
        if self.tty {
            eprint!("\x1b[2K\r");
            let _ = std::io::stderr().flush();
        }
    }

    fn draw(&self) {
        if !self.tty {
            return;
        }
        if let Ok(st) = self.state.lock() {
            let done = self.done.load(Ordering::SeqCst);
            let text = if st.parens {
                format!("{} ({}/{})...", st.desc, done, st.total)
            } else {
                format!("{} {}/{}", st.desc, done, st.total)
            };
            eprint!("\r  {}   ", text);
            let _ = std::io::stderr().flush();
        }
    }
}

/// Indeterminate spinner for phases without a total (mirrors
/// `console.status(..., spinner="line")`, frames `- \ | /`).
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    tty: bool,
}

impl Spinner {
    pub fn start(desc: &str) -> Self {
        let tty = std::io::stderr().is_terminal();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if tty {
            let stop_c = Arc::clone(&stop);
            let desc = desc.to_string();
            Some(std::thread::spawn(move || {
                let frames = ["-", "\\", "|", "/"];
                let mut i = 0;
                while !stop_c.load(Ordering::SeqCst) {
                    eprint!("\r  {} {}   ", desc, frames[i % 4]);
                    let _ = std::io::stderr().flush();
                    i += 1;
                    std::thread::sleep(Duration::from_millis(120));
                }
            }))
        } else {
            None
        };
        Self { stop, handle, tty }
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.tty {
            eprint!("\x1b[2K\r");
            let _ = std::io::stderr().flush();
        }
    }
}

pub fn render_banner(msg: &Messages, profile: RegionProfile, badge: &str) -> String {
    let badge_colored = if badge == "✓ Актуальная версия" {
        "\x1b[38;2;90;247;142m✓ Актуальная версия\x1b[0m".to_string()
    } else if badge.starts_with("↑") {
        format!("\x1b[33m{}\x1b[0m", badge)
    } else {
        format!("\x1b[2m{}\x1b[0m", badge)
    };
    let version_line = format!("DPI Detector v{}", env!("CARGO_PKG_VERSION"));
    let row1 = "  \x1b[2mАвтор:\x1b[0m \x1b[38;2;214;180;255mRunni\x1b[0m \x1b[36m•\x1b[0m \x1b[2mGitHub:\x1b[0m Runnin4ik/dpi-detector".to_string();
    let row2 = format!(
        "  \x1b[2mЧат:\x1b[0m t.me/DPI_detector \x1b[36m•\x1b[0m {}",
        badge_colored
    );
    let _ = (msg, profile);
    panel_with(&version_line, &[row1, row2], BOX_WIDTH, false, "36")
}

// ─── Test 0: network & system ─────────────────────────────────────────────────

/// TTLB cell (mirrors `_ttlb_str`).
#[derive(Debug, Clone)]
pub enum NetTtlb {
    Timeout,
    Ms(u64),
}
/// Per-family network fact (mirrors the `info["v4"]` / `info["v6"]` dicts).
#[derive(Debug, Clone)]
pub struct NetFamilyInfo {
    pub ip: String,
    pub ttlb: NetTtlb,
    pub subnet: String,
    pub org: String,
    pub asn: String,
    pub cc: String,
}

pub struct NetInfoData {
    pub v4: Option<NetFamilyInfo>,
    pub v6: Option<NetFamilyInfo>,
    /// Legacy empty-dict branch: placeholder rows.
    pub empty: bool,
}

/// Value color (mirrors `_v`): red "timeout", cyan otherwise.
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

fn ttlb_str(t: &NetTtlb) -> String {
    match t {
        NetTtlb::Timeout => "\x1b[31mtimeout\x1b[0m".to_string(),
        NetTtlb::Ms(ms) => format!("\x1b[2m{} ms\x1b[0m", ms),
    }
}

/// DNS block with 70-column wrap (mirrors `_dns_block_lines`).
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

pub fn render_netinfo_panel(
    data: &NetInfoData,
    dns_info: &SystemDnsInfo,
    bypass_tools: &[String],
    msg: &Messages,
) -> String {
    let mut lines = Vec::new();

    if data.empty {
        lines.push(format!("IPv4: {}  Subnet: {}  TTLB: …", cyan_val("…"), cyan_val("…")));
        lines.push(format!("IPv6: {}", cyan_val("…")));
        lines.push(format!("Org: {}", cyan_val("…")));
        lines.push(format!("Location: {}", cyan_val("…")));
    } else {
        match data.v4.as_ref() {
            Some(f) if !f.ip.is_empty() => {
                lines.push(format!(
                    "IPv4: {}  Subnet: {}  TTLB: {}",
                    cyan_val(&f.ip),
                    cyan_val(&f.subnet),
                    ttlb_str(&f.ttlb)
                ));
            }
            _ => lines.push(format!("IPv4: {}", dim_val("недоступен"))),
        }
        match data.v6.as_ref() {
            Some(f) if !f.ip.is_empty() => {
                lines.push(format!("IPv6: {}", cyan_val(&f.ip)));
                lines.push(format!("      Subnet: {}  TTLB: {}", cyan_val(&f.subnet), ttlb_str(&f.ttlb)));
            }
            _ => lines.push(format!("IPv6: {}", dim_val("недоступен"))),
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
        lines.push(format!("Org: {}", cyan_val(&org_s)));
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
        lines.push(format!("Location: {}", cyan_val(&loc)));
    }

    if let Some(os) = dns_info.os.as_ref() {
        lines.push(format!("ОС: {}", cyan_val(os)));
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
            src_label = "прокси WSL".to_string();
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
        lines.extend(dns_block_lines("Системный DNS: ", &mark(&ips_all), &tail));
        if iface_shown {
            lines.push(format!("Активный интерфейс: {} ({})", cyan_val(&a_ip), a_name));
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
                let label = if k == 0 { "Неактивные DNS: ".to_string() } else { " ".repeat(16) };
                if let Some(v) = by_name.get(*n) {
                    lines.extend(dns_block_lines(&label, &mark(v), &format!(" ({})", n)));
                }
            }
        }
    }
    if let Some(up) = dns_info.upstream.as_ref() {
        let label = dns_info.upstream_label.clone().unwrap_or_else(|| "Резолвер роутера".to_string());
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
        lines.push(format!("WSL-сеть: {}", cyan_val(w)));
    }
    if !bypass.is_empty() {
        lines.push(format!(
            "Локальный обход DPI на устройстве: \x1b[33m{}\x1b[0m",
            bypass.join(", ")
        ));
    } else {
        lines.push(format!(
            "Локальный обход DPI на устройстве: {}",
            dim_val("не обнаружен")
        ));
    }

    // Rich prefixes content lines with two spaces ("  " + l); the panel adds
    // one padding space, so body rows start with three.
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

// ─── Test 1: DNS availability ─────────────────────────────────────────────────

pub fn render_dns_endpoints(report: &DnsAvailReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\nПроверка доступности DNS-серверов  DoH: {} | DoT: {} | UDP: {} | Запрещённых: {} | Доверенных: {} | timeout: {}s\n\n",
        report.doh_servers.len(),
        report.dot_servers.len(),
        report.udp_servers.len(),
        report.forbidden.len(),
        report.allowed.len(),
        report.timeout_secs,
    ));
    out.push_str(&format!(
        "Заблокированные домены для проверки: {}\nНезаблокированные домены для проверки: {}\nВНИМАНИЕ: Это независимая проверка и она не использует ваши настроенные DNS!\n",
        report.forbidden.join(", "),
        report.allowed.join(", "),
    ));
    if report.non_socks_proxy_warn {
        out.push_str("Прокси не SOCKS5 — UDP-пробы идут напрямую: через HTTP-прокси UDP-релей невозможен.\n");
    }

    // Endpoint tables per kind
    for (title, servers) in [
        ("DoH эндпоинты", &report.doh_servers),
        ("DoT эндпоинты", &report.dot_servers),
        ("UDP эндпоинты", &report.udp_servers),
    ] {
        if servers.is_empty() {
            continue;
        }
        let mut table = Table::new();
        table
            .load_preset(table_preset())
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["Провайдер", title]);
        // Group by provider name preserving order
        let mut order: Vec<String> = Vec::new();
        let mut by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (addr, name, port) in servers {
            let default_port = if title.starts_with("DoH") { 443 } else if title.starts_with("DoT") { 853 } else { 53 };
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
            table.add_row(vec![Cell::new(&name).fg(Color::Cyan), Cell::new(cell)]);
        }
        out.push_str(&format!("\n{}\n\n", table));
    }
    out
}

fn fail_color(token: &str) -> Color {
    // Mirrors Python label markup: DNS FAIL is yellow, the rest are red.
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
fn dns_latency_lines(
    report: &DnsAvailReport,
    kind: ProbeKind,
    name: &str,
    addrs: &[String],
    domains: &[String],
    udp: bool,
    partial: &mut Vec<PartialDnsEndpoint>,
) -> Vec<(String, Color)> {
    let mut lines = Vec::new();
    for a in addrs {
        let key = dpi_core::dns::availability::ProbeKey {
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
            // UDP shows a flat TIMEOUT (mirrors Python); DoH/DoT use the
            // recorded fail label.
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
        let text = format!("{:.1}мс", min);
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

/// Joins multi-line cell parts, worst color wins (single fg per cell).
fn join_cell(mut lines: Vec<(String, Color)>) -> (String, Color) {
    if lines.is_empty() {
        lines.push(("—".to_string(), Color::DarkGrey));
    }
    let color = lines
        .iter()
        .map(|(_, c)| *c)
        .max_by_key(|c| color_sev(*c))
        .unwrap_or(Color::DarkGrey);
    let text = lines.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>().join("\n");
    (text, color)
}

pub fn render_dns_availability(report: &DnsAvailReport, cfg: &AppConfig) -> String {
    let mut out = String::new();
    let has_dot = !report.dot_servers.is_empty();

    let mut table = Table::new();
    table.load_preset(table_preset()).set_content_arrangement(ContentArrangement::Dynamic);
    let mut header = vec!["Провайдер", "DoH мин"];
    if has_dot {
        header.push("DoT мин");
    }
    header.extend(["UDP мин", "Реальный UDP резолвер", "Подмена"]);
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
        // DoH cell: one line per endpoint (mirrors Python).
        let doh_addrs = doh_by_name.get(name).cloned().unwrap_or_default();
        let doh_lines: Vec<(String, Color)> = if doh_addrs.is_empty() {
            vec![("—".to_string(), Color::DarkGrey)]
        } else {
            dns_latency_lines(report, ProbeKind::DohWire, name, &doh_addrs, &report.forbidden, false, &mut partial_endpoints)
        };

        // DoT cell: one line per endpoint.
        let mut dot_lines: Vec<(String, Color)> = Vec::new();
        if has_dot {
            let dot_addrs = dot_by_name.get(name).cloned().unwrap_or_default();
            if dot_addrs.is_empty() {
                dot_lines.push(("—".to_string(), Color::DarkGrey));
            } else {
                dot_lines = dns_latency_lines(report, ProbeKind::Dot, name, &dot_addrs, &report.forbidden, false, &mut partial_endpoints);
            }
        }

        // UDP cell (trusted-domain ping): one line per endpoint.
        let udp_addrs = udp_by_name.get(name).cloned().unwrap_or_default();
        let udp_lines: Vec<(String, Color)> = if udp_addrs.is_empty() {
            vec![("—".to_string(), Color::DarkGrey)]
        } else {
            dns_latency_lines(report, ProbeKind::Udp, name, &udp_addrs, &report.allowed, true, &mut partial_endpoints)
        };
        // Egress cell
        let mut egress_lines: Vec<(String, Option<Color>)> = Vec::new();
        for a in &udp_addrs {
            let key = dpi_core::dns::availability::ProbeKey { kind: ProbeKind::Udp, addr: a.clone(), name: name.clone() };
            let alive = report.raw.get(&key).map(|dm| {
                report.allowed.iter().any(|d| dm.get(d).copied().flatten().is_some())
            }).unwrap_or(false);
            let eip = report.egress.get(&(a.clone(), name.clone())).copied().flatten();
            match (alive, eip) {
                (false, _) => egress_lines.push((format!("{}: таймаут", a), Some(Color::DarkGrey))),
                (true, None) => egress_lines.push((format!("{}: выход н/д", a), Some(Color::DarkGrey))),
                (true, Some(ip)) if ip == "0.0.0.0".parse::<std::net::IpAddr>().unwrap() => {
                    egress_lines.push((format!("{}: выход н/д", a), Some(Color::DarkGrey)));
                }
                (true, Some(ip)) => {
                    if dpi_core::probe::domains::fake_ip_type(&ip) == dpi_core::probe::domains::FakeIpType::FakeIp {
                        egress_lines.push((format!("{}→FakeIP", a), Some(Color::Magenta)));
                    } else {
                        let org = report.org_names.get(&ip.to_string()).cloned().unwrap_or_else(|| ip.to_string());
                        let label = org_label(&org);
                        if is_domestic(name) {
                            // Domestic brands stay uncolored (mirrors Python).
                            egress_lines.push((format!("{}→{}", a, label), None));
                        } else if known_resolver(&label, &cfg.dns_known_resolver_names) {
                            egress_lines.push((format!("{}→{}", a, label), Some(Color::Green)));
                        } else {
                            egress_lines.push((format!("{}→{}", a, label), Some(Color::Red)));
                        }
                    }
                }
            }
        }
        let egress_text = egress_lines.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>().join("\n");
        let egress_color: Option<Color> =
            egress_lines.iter().filter_map(|(_, c)| *c).max_by_key(|c| color_sev(*c));

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
                    let key = dpi_core::dns::availability::ProbeKey { kind: ProbeKind::Udp, addr: a.clone(), name: name.clone() };
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
        let (doh_text, doh_color) = join_cell(doh_lines);
        let (dot_text, dot_color) = join_cell(dot_lines);
        let (udp_text, udp_color) = join_cell(udp_lines);
        let (subst_text, subst_color) = join_cell(subst_lines);
        let name_text = (0..n_rows)
            .map(|i| if i == 0 { name.clone() } else { format!("{} #{}", name, i + 1) })
            .collect::<Vec<_>>()
            .join("\n");
        let mut row = vec![
            Cell::new(name_text).fg(Color::Cyan),
            Cell::new(doh_text).fg(doh_color),
        ];
        if has_dot {
            row.push(Cell::new(dot_text).fg(dot_color));
        }
        row.push(Cell::new(udp_text).fg(udp_color));
        row.push(match egress_color {
            Some(c) => Cell::new(egress_text).fg(c),
            None => Cell::new(egress_text),
        });
        row.push(Cell::new(subst_text).fg(subst_color));
        table.add_row(row);
    }

    out.push_str(&format!("{}\n", table));

    if !partial_endpoints.is_empty() {
        out.push('\n');
        let warn = warn_mark();
        out.push_str(&format!(
            "\x1b[1;33m[{}] Частично доступные DNS-серверы (потери запросов):\x1b[0m\n",
            warn
        ));
        for p in &partial_endpoints {
            let bullet = asc("•");
            out.push_str(&format!(
                "  \x1b[33m{}\x1b[0m \x1b[1m{}\x1b[0m [{}] \x1b[2m{}\x1b[0m — \x1b[1;33m{}/{}\x1b[0m ответов ({:.1}мс)\n",
                bullet, p.provider, p.protocol, p.endpoint, p.ok, p.total, p.min_ms
            ));
        }
    }

    // Hijack warning block
    let st = &report.stats;
    if st.subst_sub > 0 {
        out.push('\n');
        match st.top_stub.as_deref() {
            Some(top) if top.parse::<std::net::IpAddr>().map(|ip| dpi_core::probe::domains::fake_ip_type(&ip) == dpi_core::probe::domains::FakeIpType::FakeIp).unwrap_or(false) => {
                out.push_str("[!] DNS-ответы содержат FakeIP\nДля честной оценки DNS отключите прокси/FakeIP на время проверки.\n");
            }
            _ => {
                out.push_str("[!] Ваш интернет-провайдер перехватывает DNS-запросы\nПровайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN/EMPTY/TIMEOUT\n");
                if let Some(top) = st.top_stub.as_deref() {
                    out.push_str(&format!("IP адрес заглушки провайдера - {}.\n", top));
                }
                out.push_str("Рекомендация: настройте DoH на устройстве/роутере, если еще не сделали этого.\n");
            }
        }
    }
    // /24 sharing info (brand → net) is computed in stats.hijacked_brands (summary row)
    let _ = net24;
    out
}

fn color_sev(c: Color) -> u8 {
    match c {
        Color::Red => 5,
        Color::Magenta => 4,
        Color::Yellow => 3,
        Color::Green => 2,
        Color::White => 1,
        _ => 0,
    }
}

// ─── Test 2: domains ──────────────────────────────────────────────────────────

pub fn render_domain_table(entries: &[DomainEntry], msg: &Messages) -> String {
    let mut out = String::new();
    let mut table = Table::new();
    table
            .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Домен", "HTTP", "TLS1.2", "TLS1.3", "Детали"]);

    for e in entries {
        let (http_s, t12_s, t13_s, details) = dpi_core::probe::domains::build_domain_row(e);
        table.add_row(vec![
            Cell::new(&e.domain).fg(Color::Cyan),
            Cell::new(http_s.display_label()).fg(status_color(http_s)),
            Cell::new(t12_s.display_label()).fg(status_color(t12_s)),
            Cell::new(t13_s.display_label()).fg(status_color(t13_s)),
            Cell::new(details),
        ]);
    }

    out.push_str(msg.domain_title);
    out.push('\n');
    out.push_str(&format!("{}\n", table));
    out
}

/// Post-table DNS resolve notes (stubs, fake-ip, DoH recommendation).
pub fn render_dns_resolve_notes(entries: &[DomainEntry]) -> String {
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
            if e.t13.detail.contains("IPv6 не поддерживается") {
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

    out.push_str("\n[i] ИНФОРМАЦИЯ О DNS РЕЗОЛВЕ:\n");
    if !fakeip_stubs.is_empty() {
        let total: usize = fakeip_stubs.values().sum();
        out.push_str(&format!("Трафик перехватывается Fake-IP: у {} доменов\n", total));
    }
    if !isp_stubs.is_empty() {
        let total: usize = isp_stubs.values().sum();
        if isp_stubs.len() <= 3 {
            let ips: Vec<String> = isp_stubs.keys().cloned().collect();
            out.push_str(&format!("DNS вернул IP заглушки провайдера ({}): у {} доменов\n", ips.join(", "), total));
        } else {
            out.push_str(&format!("DNS вернул IP заглушки провайдера: у {} доменов\n", total));
        }
    }
    if !local_stubs.is_empty() {
        let total: usize = local_stubs.values().sum();
        if local_stubs.len() <= 3 {
            let ips: Vec<String> = local_stubs.keys().cloned().collect();
            out.push_str(&format!("DNS вернул локальные IP (работает AdGuard/hosts?): ({}): у {} доменов\n", ips.join(", "), total));
        } else {
            out.push_str(&format!("DNS вернул локальные IP (AdGuard/hosts/Pi-hole?): у {} доменов\n", total));
        }
    }
    if real_dns_fail > 0 {
        out.push_str(&format!("У {} сайтов обнаружен DNS FAIL\n", real_dns_fail));
    }
    if !isp_stubs.is_empty() || real_dns_fail > 0 {
        out.push_str("Рекомендация: Настройте DoH на вашем устройстве и роутере\n\nПосле настройки сбросьте кеш DNS:\nWindows: ipconfig /flushdns\nMacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n");
    }
    out.push('\n');
    out
}

// ─── Test 3: TCP ──────────────────────────────────────────────────────────────

pub struct TcpRow {
    pub id: String,
    pub asn: String,
    pub provider: String,
    pub status: DpiStatus,
    pub detail: String,
}

fn provider_group(provider: &str) -> String {
    let clean: String = provider.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '.' || *c == '-').collect();
    clean.split_whitespace().next().unwrap_or(&clean).to_string()
}

pub fn render_tcp_table(rows: &[TcpRow], _msg: &Messages) -> String {
    let mut out = String::new();
    // Sort: provider group frequency desc, group name, id number (mirrors Python)
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in rows {
        *counts.entry(provider_group(&r.provider)).or_insert(0) += 1;
    }
    let mut sorted: Vec<&TcpRow> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        let ga = provider_group(&a.provider);
        let gb = provider_group(&b.provider);
        let ca = counts.get(&ga).copied().unwrap_or(0);
        let cb = counts.get(&gb).copied().unwrap_or(0);
        cb.cmp(&ca)
            .then(ga.cmp(&gb))
            .then(id_num(&a.id).cmp(&id_num(&b.id)))
    });

    let mut table = Table::new();
    table
            .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["ID", "ASN", "Провайдер", "Статус", "Детали"]);

    let mut passed = 0;
    let mut blocked = 0;
    let mut mixed = 0;
    for r in sorted {
        let label = r.status.display_label();
        if label.contains("OK") {
            passed += 1;
        } else if label.contains("DETECTED") {
            blocked += 1;
        } else if label.contains("MIXED") {
            mixed += 1;
        }
        table.add_row(vec![
            Cell::new(&r.id),
            Cell::new(&r.asn).fg(Color::Yellow),
            Cell::new(&r.provider).fg(Color::Cyan),
            Cell::new(label).fg(status_color(r.status)),
            Cell::new(&r.detail),
        ]);
    }
    out.push_str("\nПроверка TCP 16-20KB блокировки\n");
    out.push_str(&format!("{}\n", table));
    if mixed > 0 {
        out.push_str("Смешанные результаты указывают на балансировку DPI у провайдера\n");
    }
    let _ = (passed, blocked);
    out
}

fn id_num(id: &str) -> u64 {
    id.rsplit('-').next().and_then(|s| s.parse().ok()).unwrap_or(99999)
}

// ─── Test 4: whitelist SNI ────────────────────────────────────────────────────

pub fn render_whitelist(report: &WhitelistReport, targets_total: usize) -> String {
    let mut out = String::new();
    if targets_total == 0 {
        out.push_str("Нет целей с портом 443 для теста белых SNI.\n");
        return out;
    }
    if report.detected_as == 0 {
        out.push_str("Ни одна AS не заблокирована — перебор SNI не нужен.\n");
        return out;
    }
    for row in &report.rows {
        match &row.verdict {
            AsVerdict::Found { snis, ban_after } => {
                let parts: Vec<String> = snis
                    .iter()
                    .map(|(label, n)| {
                        if *n > 0 {
                            format!("{} #{}", label, n)
                        } else {
                            label.clone()
                        }
                    })
                    .collect();
                let suffix = if *ban_after { "  ⚠ бан после" } else { "" };
                out.push_str(&asc(&format!("  {} {}  ✓ {}{}\n", row.provider, row.asn_str, parts.join("  "), suffix)));
            }
            AsVerdict::Banned { detail } => {
                let clean = strip_brackets(detail);
                out.push_str(&format!("  {} {}  {} бан/рейт-лимит ({})\n", row.provider, row.asn_str, warn_mark(), clean));
            }
            AsVerdict::NotFound => {
                out.push_str(&format!("  {} {}  × SNI не найден (все заблокированы)\n", row.provider, row.asn_str));
            }
        }
    }
    out.push('\n');
    if report.found_as > 0 {
        out.push_str(&format!(
            "Найдено белых SNI: у {} из {} заблокированных AS\n",
            report.found_as, report.detected_as
        ));
    } else {
        out.push_str(&format!(
            "Белые SNI не найдены ни для одной из {} заблокированных AS\n",
            report.detected_as
        ));
    }
    out
}

fn strip_brackets(s: &str) -> String {
    let mut out = String::new();
    let mut depth: usize = 0;
    for c in s.chars() {
        if c == '[' {
            depth += 1;
        } else if c == ']' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            out.push(c);
        }
    }
    out.trim().to_string()
}

// ─── Test 5: Telegram ─────────────────────────────────────────────────────────

pub fn render_telegram(report: &TelegramFullReport, _msg: &Messages) -> String {
    use dpi_core::probe::telegram::{fmt_size, fmt_speed};
    let mut out = String::new();
    out.push_str("\nПроверка доступности Telegram\n");

    let mut table = Table::new();
    table
            .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["DC", "IP", "Регион", "Статус", "Пинг"]);
    for dc in &report.dc_results {
        let (label, color) = if dc.available {
            ("OK", Color::Green)
        } else {
            ("НЕДОСТУПЕН", Color::Red)
        };
        let ping = match dc.latency_ms {
            Some(l) => format!("{}мс", l),
            None => dc.error.clone().unwrap_or_else(|| "—".to_string()),
        };
        // Region from telegram_dc_list order is not carried; show stored region
        table.add_row(vec![
            Cell::new(&dc.name).fg(Color::Cyan),
            Cell::new(&dc.ip),
            Cell::new(&dc.region),
            Cell::new(label).fg(color),
            Cell::new(ping),
        ]);
    }
    out.push_str(&format!("{}\n", table));

    // Download / upload verdict lines (mirror display.finish rows)
    for (label, t) in [("Скачивание", &report.download), ("Загрузка  ", &report.upload)] {
        let (st_text, color) = match t.status.as_str() {
            "ok" => ("ОК", Color::Green),
            "stalled" => ("ОБРЫВ", Color::Yellow),
            "slow" => ("ЗАМЕДЛЕНИЕ", Color::Yellow),
            "blocked" => ("НЕДОСТУПНО", Color::Red),
            _ => ("ОШИБКА", Color::Red),
        };
        let mut line = format!(
            "  {}: {}  пик {}  ср. {}  ({} за {:.0}с",
            label,
            st_text,
            fmt_speed(t.peak_bps),
            fmt_speed(t.avg_bps),
            fmt_size(t.bytes_total),
            t.duration
        );
        if let Some(sec) = t.drop_at_sec {
            line += &format!(", обрыв после {}с", sec);
        }
        line += ")";
        let _ = color;
        out.push_str(&format!("{}\n", line));
    }
    out.push('\n');
    out
}

// ─── Summary ──────────────────────────────────────────────────────────────────

fn frac_color(ok: usize, total: usize) -> &'static str {
    if total == 0 || ok == total {
        "green"
    } else if ok == 0 {
        "red"
    } else {
        "yellow"
    }
}

pub struct SummaryData<'a> {
    pub run_dns: bool,
    pub dns: Option<&'a dpi_core::dns::availability::DnsAvailStats>,
    pub domains: Option<&'a DomainStats>,
    pub tcp: Option<(usize, usize, usize, usize)>, // ok, blocked, mixed, total
    pub run_telegram: bool,
    pub telegram: Option<&'a TelegramFullReport>,
}

pub fn render_summary(data: &SummaryData) -> String {
    let mut items: Vec<(String, String)> = Vec::new();

    if data.run_dns {
        if let Some(d) = data.dns {
            let doh_c = frac_color(d.doh_ok, d.doh_total);
            let udp_c = frac_color(d.udp_ok, d.udp_total);
            let mut parts = vec![format!("[{}]{}/{} DoH[/]", doh_c, d.doh_ok, d.doh_total)];
            if d.dot_total > 0 {
                let dot_c = frac_color(d.dot_ok, d.dot_total);
                parts.push(format!("[{}]{}/{} DoT[/]", dot_c, d.dot_ok, d.dot_total));
            }
            parts.push(format!("[{}]{}/{} UDP[/]", udp_c, d.udp_ok, d.udp_total));
            items.push(("DNS доступность".to_string(), parts.join("  ")));
            if !d.hijacked_brands.is_empty() {
                if d.resolvers_total > 0 && d.hijacked_brands.len() >= d.resolvers_total {
                    items.push(("Подмена резолвера".to_string(), "[red]Все[/]".to_string()));
                } else {
                    items.push((
                        "Подмена резолвера".to_string(),
                        format!("[red]{}[/]", d.hijacked_brands.join(", ")),
                    ));
                }
            } else {
                items.push(("Подмена резолвера".to_string(), "[dim]—[/]".to_string()));
            }
            if d.subst_total > 0 {
                if d.fakeip_sub > 0 {
                    items.push((
                        "FakeIP ответов".to_string(),
                        format!("[magenta]у {}/{} UDP[/]", d.fakeip_sub, d.subst_total),
                    ));
                }
                let rest = d.subst_sub.saturating_sub(d.fakeip_sub);
                if rest > 0 {
                    let c = if rest == d.subst_total { "red" } else { "yellow" };
                    items.push((
                        "Подмена ответов".to_string(),
                        format!("[{}]у {}/{} UDP[/]", c, rest, d.subst_total),
                    ));
                } else if d.fakeip_sub == 0 {
                    items.push((
                        "Подмена ответов".to_string(),
                        format!("[green]у 0/{} UDP[/]", d.subst_total),
                    ));
                }
            }
        } else {
            items.push(("DNS доступность".to_string(), "[dim]—[/]".to_string()));
        }
    }

    if let Some(d) = data.domains {
        let stat = |label: &str, ok: usize| {
            let c = frac_color(ok, d.total);
            format!("[{}]{}/{} {}[/]", c, ok, d.total, label)
        };
        items.push((
            "Домены".to_string(),
            format!("{}  {}  {}", stat("HTTP", d.http_ok), stat("TLS1.2", d.t12_ok), stat("TLS1.3", d.t13_ok)),
        ));
    }

    if let Some((ok, blocked, mixed, total)) = data.tcp {
        let pct = ok.checked_mul(100).and_then(|v| v.checked_div(total)).unwrap_or(0);
        let mut value = format!("[green]√ {}/{} OK[/]", ok, total);
        if blocked > 0 {
            value += &format!("  [red]× {} блок.[/]", blocked);
        }
        if mixed > 0 {
            value += &format!("  [yellow]≈ {} смеш.[/]", mixed);
        }
        value += &format!("  [dim]({}% ОК)[/]", pct);
        items.push(("TCP 16-20KB".to_string(), value));
    }

    if data.run_telegram {
        if let Some(t) = data.telegram {
            use dpi_core::probe::telegram::{fmt_size, fmt_speed};
            let tg_row = |label: &str, st: &dpi_core::probe::telegram::TransferStats, speed: f64, size: u64| {
                let (raw, color) = match st.status.as_str() {
                    "ok" => ("ОК", "green"),
                    "stalled" => ("ЗАМЕДЛЕНИЕ+ОБРЫВ", "yellow"),
                    "slow" => ("ЗАМЕДЛЕНИЕ", "yellow"),
                    "blocked" => ("НЕДОСТУПНО", "red"),
                    _ => ("ОШИБКА", "red"),
                };
                let mut metrics = format!("ср. {}, {}", fmt_speed(speed), fmt_size(size));
                if let Some(sec) = st.drop_at_sec {
                    metrics += &format!(", обрыв на {}с", sec);
                }
                (label.to_string(), format!("[{}]{:<16}[/] {}", color, raw, metrics))
            };
            let (l1, v1) = tg_row("TG Скачивание", &t.download, t.download.avg_bps, t.download.bytes_total);
            let (l2, v2) = tg_row("TG Загрузка", &t.upload, t.upload.avg_bps, t.upload.bytes_total);
            items.push((l1, v1));
            items.push((l2, v2));
            let dc_c = if t.dc_reachable == t.dc_total {
                "green"
            } else if t.dc_reachable == 0 {
                "red"
            } else {
                "yellow"
            };
            items.push((
                "TG Датацентры".to_string(),
                format!("[{}]ОК {}/{}[/]", dc_c, t.dc_reachable, t.dc_total),
            ));
        }
    }

    if items.is_empty() {
        return String::new();
    }
    let mut lines = Vec::new();
    for (label, val) in items {
        lines.push(format!("  \x1b[1m{}\x1b[0m  {}", label, rich_to_ansi(&val)));
    }
    panel_to_string("Итог", &lines)
}

/// Minimal Rich-markup → ANSI converter for summary values.
fn rich_to_ansi(s: &str) -> String {
    s.replace("[green]", "\x1b[32m")
        .replace("[red]", "\x1b[31m")
        .replace("[yellow]", "\x1b[33m")
        .replace("[magenta]", "\x1b[35m")
        .replace("[cyan]", "\x1b[36m")
        .replace("[dim]", "\x1b[2m")
        .replace("[/]", "\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_top_border_matches_box_width_with_styled_title() {
        // Regression: the bold banner title once leaked its inner reset into
        // the top border (white dashes, right edge 8 cells short).
        let title = "\x1b[1mDPI Detector v4.2.0 (Rust Native Engine)\x1b[0m";
        let out = panel_to_string(title, &["  row".to_string()]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        let widths: Vec<usize> = lines.iter().map(|l| strip_ansi_len(l)).collect();
        assert_eq!(widths[0], BOX_WIDTH, "top border visible width");
        assert_eq!(widths[1], BOX_WIDTH, "body visible width");
        assert_eq!(widths[2], BOX_WIDTH, "bottom border visible width");
        assert!(lines[0].ends_with("\x1b[1;36m╮\x1b[0m"), "right edge stays cyan");
        assert!(lines[0].contains("\x1b[0m \x1b[1;36m"), "cyan re-armed after inner reset");
    }

    #[test]
    fn asc_replacements_are_stable() {
        // Passthrough when ASCII mode is off.
        assert_eq!(asc_with("✓ • ►", false), "✓ • ►");
        // Width-1 swaps stay exact; [OK]/-> widen and must precede padding.
        assert_eq!(asc_with("[√] ● ○", true), "[x] * o");
        assert_eq!(asc_with("↑↓ ←→", true), "^v <->");
        assert_eq!(asc_with("✓ done", true), "[OK] done");
        assert_eq!(asc_with("⚠ ≈ × — –", true), "! ~ x - -");
        assert_eq!(asc_with("╭─╮ │ └┘", true), "+-+ | ++");
        // ANSI escapes pass through untouched.
        assert_eq!(asc_with("\x1b[1;32m✓\x1b[0m", true), "\x1b[1;32m[OK]\x1b[0m");
        // Cyrillic passes through; arrows become ASCII in ascii mode.
        assert_eq!(asc_with("8.8.8.8→GOOGLE мс", true), "8.8.8.8->GOOGLE мс");
    }

    /// Regression: latency cells aggregated addr counts against domain counts
    /// ("40.0мс 1/5"). Cells must be one line per endpoint like Python, with
    /// the name column spanning ("Google", "Google #2").
    #[test]
    fn dns_table_cells_are_per_endpoint() {
        use dpi_core::dns::availability::{DnsAnswer, DnsAvailReport, ProbeKey, ProbeKind};
        use std::collections::HashMap;

        let mut report = DnsAvailReport::default();
        report.allowed = vec!["vk.ru".to_string(), "gosuslugi.ru".to_string()];
        report.forbidden = vec!["rutor.info".to_string()];
        report.udp_servers = vec![
            ("8.8.4.4".to_string(), "Google".to_string(), 53),
            ("8.8.8.8".to_string(), "Google".to_string(), 53),
        ];
        report.doh_servers =
            vec![("https://dns.google/dns-query".to_string(), "Google".to_string(), 443)];
        report.all_names = vec!["Google".to_string()];
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
        let out = render_dns_availability(&report, &cfg);
        // One line per endpoint, full success shows no fraction.
        assert!(out.contains("Google #2"), "name spans tallest cell");
        assert!(!out.contains("1/5"), "no addr/domain count mix-up");
        assert!(!out.contains("1/2"), "no addr/domain count mix-up");
        assert!(out.contains("8.8.4.4"), "per-addr egress lines");
        assert!(out.contains("8.8.8.8"), "per-addr egress lines");
    }
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

    #[test]
    fn netinfo_panel_matches_python_rows() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
        let (data, dns, bypass) = netinfo_fixture();
        let out = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Ru));
        assert!(out.contains("IPv4: \x1b[36m203.0.113.7\x1b[0m  Subnet: \x1b[36m203.0.113.0/24\x1b[0m  TTLB: \x1b[2m701 ms\x1b[0m"));
        assert!(out.contains("IPv6: \x1b[2mнедоступен\x1b[0m"));
        assert!(out.contains("Org: \x1b[36mEXAMPLE-AS (AS65001)\x1b[0m"));
        assert!(out.contains("ОС: \x1b[36mWindows 11 (26200)\x1b[0m"));
        assert!(out.contains("Системный DNS: \x1b[36m192.0.2.1\x1b[0m (DHCP)"));
        assert!(out.contains("Активный интерфейс: \x1b[36m192.0.2.10\x1b[0m (Ethernet)"));
        assert!(out.contains("Неактивные DNS: \x1b[36m198.51.100.2\x1b[0m (Wi-Fi)"));
        assert!(out.contains("Резолвер роутера: \x1b[36m203.0.113.1 (EXAMPLE UP)\x1b[0m"));
        assert!(out.contains("Локальный обход DPI на устройстве: \x1b[2mне обнаружен\x1b[0m"));
    }

    #[test]
    fn netinfo_timeout_rows_are_red() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
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
        assert!(out.contains("\x1b[31mtimeout\x1b[0m"), "cymru-less fields render red");
    }

    #[test]
    fn netinfo_filters_amnezia_without_warp() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
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

    #[test]
    fn centered_panel_title_is_centered() {
        let out = panel_with("AB", &["x".to_string()], 11, true, "36");
        let top = out.lines().next().unwrap();
        let plain: String = top
            .split('\x1b')
            .flat_map(|p| p.split('m').skip(1).flat_map(|s| s.chars()).collect::<Vec<_>>())
            .collect();
        // inner width 9, title " AB " (4): 2 left + 3 right
        assert!(plain.contains("╭── AB ───╮"), "title centered, extra dash goes right");
    }
}

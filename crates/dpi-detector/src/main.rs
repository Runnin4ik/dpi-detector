use std::collections::{HashMap, HashSet};
use std::io::{stdout, IsTerminal, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dpi_core::config::{
    base_dir, clean_domain, default_tcp16_targets, embedded_domains, embedded_tcp16_targets,
    embedded_whitelist_sni, load_config, load_domains_from_file, load_tcp16_targets_from_file,
    load_whitelist_sni, resource_path, AppConfig,
};
use dpi_core::dns::availability::check_dns_availability;
use dpi_core::dns::parse_socks_proxy;
use dpi_core::i18n::{get_messages, print_legend, Language, Messages};
use dpi_core::dns::udp::probe_udp_dns;
use dpi_core::net::netinfo::{
    detect_bypass_tools, fetch_ip_cymru, fetch_public_ips, get_system_dns, is_tun_name, IpCymruInfo,
};
use dpi_core::{PhaseProgress, ProgressTick};
use dpi_core::net::version::{fetch_latest_version, version_badge};
use dpi_core::probe::domains::{
    check_http_all, check_tls_all, collect_stub_ips, domain_stats, resolve_all, IpFamily,
};
use dpi_core::probe::telegram::run_telegram_full;
use dpi_core::probe::whitelist::run_whitelist_sni;
use dpi_core::probe::{check_tcp_16_20, domains};
use dpi_core::profile::RegionProfile;
use serde_json::json;
use tokio::sync::Semaphore;

mod args;
mod menu;
mod render;

use args::CliArgs;
use menu::{run_interactive_menu, MenuResult, VersionSlot};
use render::{
    asc, panel_to_string, render_banner, render_dns_availability, render_dns_endpoints,
    render_dns_resolve_notes, render_domain_table, render_netinfo_panel, render_summary,
    render_tcp_table, render_telegram, render_whitelist, set_ascii_mode, LiveProgress, NetFamilyInfo,
    NetInfoData, NetTtlb, Spinner, SummaryData, TcpRow,
};

/// Splits a test selection string into per-test flags (mirrors `_selection_flags`).
/// Tests: 0 netinfo, 1 DNS, 2 domains, 3 TCP, 4 white-SNI, 5 Telegram, 6 legend.
fn selection_flags(selection: &str) -> (bool, bool, bool, bool, bool, bool, bool, bool) {
    let has = |c: char| selection.contains(c);
    let net = has('0');
    let dns = has('1');
    let dom = has('2');
    let tcp = has('3');
    let sni = has('4');
    let tg = has('5');
    let legend = has('6');
    let only_legend = legend && !(net || dns || dom || tcp || sni || tg);
    (net, dns, dom, tcp, sni, tg, legend, only_legend)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct Emitter {
    report: String,
    json_mode: bool,
}

impl Emitter {
    fn emit(&mut self, s: &str) {
        if !self.json_mode {
            print!("{}", s);
        }
        self.report.push_str(&strip_ansi(s));
    }
}

#[derive(Debug, Clone)]
enum PostTestAction {
    Repeat,
    Menu,
    Export,
    Quit,
}

fn read_post_test_action() -> PostTestAction {
    let _ = enable_raw_mode();
    loop {
        if let Ok(Event::Key(KeyEvent { code, modifiers, kind, .. })) = event::read() {
            if kind != KeyEventKind::Press {
                continue;
            }
            if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
                let _ = disable_raw_mode();
                return PostTestAction::Quit;
            }

            match code {
                KeyCode::Enter => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Repeat;
                }
                KeyCode::Char('m') | KeyCode::Char('M') | KeyCode::Char('ь') | KeyCode::Char('Ь') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Menu;
                }
                KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Char('ы') | KeyCode::Char('Ы') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Export;
                }
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Char('й') | KeyCode::Char('Й') | KeyCode::Esc => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Quit;
                }
                _ => {}
            }
        }
    }
}

fn export_report(path: &str, content: &str) {
    match std::fs::write(path, content) {
        Ok(()) => println!("{}", asc(&format!("\x1b[1;32m✓ Отчёт сохранён в {}\x1b[0m\n", path))),
        Err(e) => println!("\x1b[1;33mНе удалось сохранить файл: {}\x1b[0m\n", e),
    }
}


/// Legend-only interactive loop (mirrors `handle_legend_menu`).
fn legend_loop(lang: Language, msg: &Messages) -> MenuAction {
    loop {
        print_legend(lang, msg);
        if !std::io::stdin().is_terminal() {
            return MenuAction::Quit;
        }
        println!(
            "{}",
            panel_to_string(
                "Меню",
                &["  \x1b[1;42;37m Enter \x1b[0m Повторить   \x1b[1;44;37m M \x1b[0m Меню   \x1b[1;41;37m Q \x1b[0m Выход".to_string()],
            )
        );
        let _ = stdout().flush();
        match read_post_test_action() {
            PostTestAction::Repeat => continue,
            PostTestAction::Menu => return MenuAction::Menu,
            PostTestAction::Export => continue,
            PostTestAction::Quit => return MenuAction::Quit,
        }
    }
}

enum MenuAction {
    Menu,
    Quit,
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    // Glyph-safe output for legacy consoles; must precede any printing.
    set_ascii_mode(args.ascii);

    // Validators (mirror argparse errors)
    if let Some(ref t) = args.tests {
        if !t.chars().all(|c| ('0'..='6').contains(&c)) {
            eprintln!("Недопустимое значение --tests: '{}'. Допустимы только цифры 0-6.", t);
            std::process::exit(2);
        }
    }
    if let Some(c) = args.concurrency {
        if c < 1 {
            eprintln!("Параметр --concurrency должен быть целым числом >= 1.");
            std::process::exit(2);
        }
    }

    let mut cfg = load_config();
    if let Some(ref p) = args.proxy {
        cfg.proxy = Some(p.clone());
    }
    if let Some(c) = args.concurrency {
        cfg.max_concurrent = c;
    }

    let lang = if args.lang == "auto" {
        Language::autodetect()
    } else {
        Language::from_code(&args.lang).unwrap_or_default()
    };
    let msg = get_messages(lang);
    let profile = RegionProfile::from_code(&args.profile).unwrap_or_default();

    let level = if args.verbose {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::WARN
    };
    let _ = tracing_subscriber::fmt().with_max_level(level).try_init();

    // Domains / TCP targets / whitelist (mirror dpi_detector.py loading)
    let domains: Vec<String> = if !args.domain.is_empty() {
        args.domain.iter().filter_map(|d| clean_domain(d)).collect()
    } else if let Some(ref path) = args.domains {
        load_domains_from_file(path).unwrap_or_default()
    } else {
        let p = resource_path(&cfg.domains_file);
        let from_file = load_domains_from_file(&p).unwrap_or_default();
        if !from_file.is_empty() {
            from_file
        } else {
            // No external file: use the domains shipped inside the binary.
            let embedded = embedded_domains();
            if !embedded.is_empty() {
                embedded
            } else {
                profile.default_domains().iter().map(|s| s.to_string()).collect()
            }
        }
    };
    let tcp_items = if let Some(ref path) = args.tcp16 {
        let from_file = load_tcp16_targets_from_file(path).unwrap_or_default();
        if !from_file.is_empty() {
            from_file
        } else {
            embedded_tcp16_targets()
        }
    } else {
        let p = resource_path(&cfg.tcp16_file);
        let from_file = load_tcp16_targets_from_file(&p).unwrap_or_default();
        if !from_file.is_empty() {
            from_file
        } else {
            let embedded = embedded_tcp16_targets();
            if !embedded.is_empty() {
                embedded
            } else {
                default_tcp16_targets()
            }
        }
    };
    let whitelist_sni = {
        let p = resource_path(&cfg.whitelist_sni_file);
        let from_file = load_whitelist_sni(&p);
        if !from_file.is_empty() {
            from_file
        } else {
            embedded_whitelist_sni()
        }
    };
    // Mirrors Python: test 4 is unavailable without any SNI list.
    if whitelist_sni.is_empty() && !args.json {
        println!(
            "\x1b[33mФайл {} не найден, тест 4 недоступен.\x1b[0m",
            cfg.whitelist_sni_file
        );
    }


    if let Some(ref e) = cfg.config_load_error {
        println!("\x1b[1;33mВнимание при загрузке config.yml:\x1b[0m {}", e);
    }
    for w in &cfg.config_warnings {
        println!("\x1b[33mПредупреждение config.yml:\x1b[0m {}", w);
    }

    if args.legend {
        print_legend(lang, &msg);
        return;
    }

    // Background version check (4 s budget, mirrors init_header_state)
    let started = Instant::now();
    let version_slot: VersionSlot = Arc::new(Mutex::new(None));
    {
        let slot = Arc::clone(&version_slot);
        tokio::spawn(async move {
            let latest = fetch_latest_version().await;
            if let Ok(mut g) = slot.lock() {
                *g = Some(latest);
            }
        });
    }

    let is_interactive =
        args.tests.is_none() && !args.batch && !args.json && std::io::stdin().is_terminal();

    let mut tests_str = args.tests.clone().unwrap_or_else(|| "123".to_string());
    let mut concurrency = cfg.max_concurrent;
    let mut ip_version = cfg.ip_version.clone();

    // Initial badge: wait up to 4 s only in non-interactive mode
    let mut badge = "Проверка обновлений...".to_string();
    if !is_interactive {
        let remaining = Duration::from_secs(4).saturating_sub(started.elapsed());
        let slot = Arc::clone(&version_slot);
        let deadline = tokio::time::sleep(remaining);
        tokio::pin!(deadline);
        loop {
            if slot.lock().map(|g| g.is_some()).unwrap_or(true) {
                break;
            }
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        if let Ok(g) = version_slot.lock() {
            if let Some(ref latest) = *g {
                badge = version_badge(latest.as_ref());
            }
        }
    }

    if is_interactive {
        // Poll the version slot for the menu badge without blocking
        if let Ok(g) = version_slot.lock() {
            if let Some(ref latest) = *g {
                badge = version_badge(latest.as_ref());
            }
        }
        match run_interactive_menu(&msg, profile, &cfg, &badge, &version_slot) {
            MenuResult::Run(sel) => {
                tests_str = sel.selected_tests;
                concurrency = sel.concurrency;
                ip_version = sel.ip_version;
            }
            MenuResult::Quit => return,
        }
        // Refresh badge after menu dwell time
        if let Ok(g) = version_slot.lock() {
            if let Some(ref latest) = *g {
                badge = version_badge(latest.as_ref());
            }
        }
    }
    let mut banner_done = is_interactive;

    // Banner first in non-interactive runs, then the config line (mirrors header order).
    if !args.json && !banner_done {
        print!("{}", render_banner(&msg, profile, &badge));
        banner_done = true;
    }

    // Selection info line (mirrors dpi_detector.py)
    if !args.json {
        println!(
            "\x1b[2mСемейство IP: \x1b[36m{}\x1b[0m\x1b[2m | Параллельных запросов: \x1b[36m{}\x1b[0m",
            ip_version, concurrency
        );
        if let Some(p) = cfg.effective_proxy() {
            println!("\x1b[2mИспользуется прокси: \x1b[33m{}\x1b[0m", mask_proxy(p));
        }
    }
    let (_, _, _, _, _, _, _, only_legend) = selection_flags(&tests_str);
    if only_legend {
        match legend_loop(lang, &msg) {
            MenuAction::Quit => return,
            MenuAction::Menu => {
                // Re-enter interactive menu once, then run
                if is_interactive {
                    match run_interactive_menu(&msg, profile, &cfg, &badge, &version_slot) {
                        MenuResult::Run(sel) => {
                            tests_str = sel.selected_tests;
                            concurrency = sel.concurrency;
                            ip_version = sel.ip_version;
                        }
                        MenuResult::Quit => return,
                    }
                }
            }
        }
        let (_, _, _, _, _, _, _, only_legend) = selection_flags(&tests_str);
        if only_legend {
            return;
        }
    }

    if ip_version == "ipv6" && !dpi_core::net::netinfo::ipv6_supported() {
        println!("\x1b[31mОшибка: выбран режим IPv6, но IPv6 не настроен в системе.\x1b[0m");
        println!("{}", asc("\x1b[2mПереключите семейство на IPv4: IP_VERSION: ipv4 в config.yml или стрелки ← → в меню.\x1b[0m"));
        return;
    }
    cfg.ip_version = ip_version.clone();

    let mut result_path = args.output.clone();
    let mut selection = tests_str.clone();

    loop {
        let mut emitter = Emitter { report: String::new(), json_mode: args.json };
        let stats = run_test_suite(
            &selection,
            concurrency,
            &args,
            &cfg,
            &domains,
            &tcp_items,
            &whitelist_sni,
            &msg,
            profile,
            lang,
            &badge,
            banner_done,
            &mut emitter,
        )
        .await;
        let _ = stats;
        banner_done = true;

        if !args.json {
            if let Some(ref out_path) = result_path {
                export_report(out_path, &emitter.report);
            }
        }

        if !is_interactive {
            break;
        }

        // Post-test actions (mirrors the HORIZONTALS panel: dim rules, no title
        // or side borders, full console width, white-on-color keycaps).
        println!();
        let cols = crossterm::terminal::size().map(|(c, _)| c as usize).unwrap_or(80);
        let rule = asc(&"─".repeat(cols.max(8)));
        println!("\x1b[2m{}\x1b[0m", rule);
        println!(
            " \x1b[1;42;37m  Enter  \x1b[0m Повторить   \x1b[1;44;37m  M  \x1b[0m Меню   \x1b[1;43;37m  S  \x1b[0m Экспорт   \x1b[1;41;37m  Q  \x1b[0m Выход"
        );
        println!("\x1b[2m{}\x1b[0m", rule);
        println!();
        let _ = stdout().flush();

        let mut should_repeat = false;
        while !should_repeat {
            match read_post_test_action() {
                PostTestAction::Repeat => should_repeat = true,
                PostTestAction::Menu => {
                    println!();
                    // Refresh badge
                    if let Ok(g) = version_slot.lock() {
                        if let Some(ref latest) = *g {
                            badge = version_badge(latest.as_ref());
                        }
                    }
                    match run_interactive_menu(&msg, profile, &cfg, &badge, &version_slot) {
                        MenuResult::Run(sel) => {
                            selection = sel.selected_tests;
                            concurrency = sel.concurrency;
                            cfg.ip_version = sel.ip_version.clone();
                        }
                        MenuResult::Quit => return,
                    }
                    let (_, _, _, _, _, _, _, only) = selection_flags(&selection);
                    if only {
                        match legend_loop(lang, &msg) {
                            MenuAction::Quit => return,
                            MenuAction::Menu => continue,
                        }
                    }
                    should_repeat = true;
                }
                PostTestAction::Export => {
                    if result_path.is_none() {
                        result_path = Some(base_dir().join("dpi_detector_results.txt").to_string_lossy().to_string());
                    }
                    if let Some(ref p) = result_path {
                        export_report(p, &emitter.report);
                    }
                }
                PostTestAction::Quit => return,
            }
        }
        println!();
    }
}

fn mask_proxy(url: &str) -> String {
    // socks5://user:pass@host → socks5://user:***@host
    match url.find('@') {
        Some(at) => {
            let (left, right) = url.split_at(at);
            match left.rfind(':') {
                Some(colon) if left[..colon].contains("://") => {
                    format!("{}:***{}", &left[..colon], right)
                }
                _ => url.to_string(),
            }
        }
        None => url.to_string(),
    }
}

/// Builds one per-family fact; missing Cymru fields become red "timeout"
/// (mirrors the `update`/`setdefault` block in `fetch_network_panel`).
fn family_info(ip: Option<(IpAddr, u64)>, extra: Option<IpCymruInfo>) -> Option<NetFamilyInfo> {
    let (addr, ms) = ip?;
    let missing = || "timeout".to_string();
    match extra {
        Some(e) => Some(NetFamilyInfo {
            ip: addr.to_string(),
            ttlb: NetTtlb::Ms(ms),
            subnet: e.subnet.unwrap_or_else(missing),
            org: e.org.unwrap_or_else(missing),
            asn: e.asn,
            cc: e.country.unwrap_or_else(missing),
        }),
        None => Some(NetFamilyInfo {
            ip: addr.to_string(),
            ttlb: NetTtlb::Ms(ms),
            subnet: missing(),
            org: missing(),
            asn: missing(),
            cc: missing(),
        }),
    }
}

/// Both lookups dead: red "timeout" rows.
fn timeout_family() -> NetFamilyInfo {
    NetFamilyInfo {
        ip: "timeout".to_string(),
        ttlb: NetTtlb::Timeout,
        subnet: "timeout".to_string(),
        org: "timeout".to_string(),
        asn: "timeout".to_string(),
        cc: "timeout".to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_test_suite(
    tests_str: &str,
    concurrency: usize,
    args: &CliArgs,
    cfg: &AppConfig,
    domains: &[String],
    tcp_items: &[dpi_core::config::Tcp16Target],
    whitelist_sni: &[(String, usize)],
    msg: &Messages,
    profile: RegionProfile,
    lang: Language,
    badge: &str,
    banner_done: bool,
    emitter: &mut Emitter,
) -> HashMap<String, serde_json::Value> {
    let (run_net, run_dns, run_dom, run_tcp, run_sni, run_tg, run_legend, _) =
        selection_flags(tests_str);

    let mut json_results: HashMap<String, serde_json::Value> = HashMap::new();

    if !args.json && !banner_done {
        emitter.emit(&render_banner(msg, profile, badge));
    }

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    // Live progress lines on a TTY only (mirrors rich transient Progress);
    // pipes and --json stay byte-clean.
    let live = LiveProgress::new();
    let phases: Option<PhaseProgress> = if !args.json && std::io::stderr().is_terminal() {
        let live_c = Arc::clone(&live);
        Some(PhaseProgress {
            on_phase: Arc::new(move |desc: String, total: usize, parens: bool| {
                live_c.set(desc, total, parens);
                let tick_c = Arc::clone(&live_c);
                let tick: ProgressTick = Arc::new(move || tick_c.tick());
                tick
            }),
        })
    } else {
        None
    };
    let family = IpFamily::from_config(&cfg.ip_version);
    let socks_proxy = match cfg.effective_proxy() {
        Some(url) => match parse_socks_proxy(url) {
            Ok(c) => Some(c),
            Err(e) => {
                emitter.emit(&format!("Некорректный прокси {}: {}\n", url, e));
                None
            }
        },
        None => None,
    };

    let mut dns_stats = None;
    let mut dom_stats = None;
    let mut tcp_summary = None;
    let mut tg_full = None;

    // ── Test 0: network & system ──
    if run_net {
        let spinner = (!args.json).then(|| Spinner::start("Получение сетевых данных..."));
        let net_data = tokio::time::timeout(Duration::from_secs(10), async {
            let ips = fetch_public_ips(
                &cfg.ip4_lookup_urls,
                &cfg.ip6_lookup_urls,
                Duration::from_millis(3500),
            )
            .await;
            let (v4_extra, v6_extra) = tokio::join!(
                async {
                    match ips.v4 {
                        Some((ip, _)) => {
                            fetch_ip_cymru(&IpAddr::V4(ip), &cfg.cymru_doh_servers, Duration::from_secs(5)).await
                        }
                        None => None,
                    }
                },
                async {
                    match ips.v6 {
                        Some((ip, _)) => {
                            fetch_ip_cymru(&IpAddr::V6(ip), &cfg.cymru_doh_servers, Duration::from_secs(5)).await
                        }
                        None => None,
                    }
                }
            );
            (ips, v4_extra, v6_extra)
        })
        .await;
        if let Some(s) = spinner {
            s.finish();
        }

        let mut dns_info = get_system_dns();
        let bypass = detect_bypass_tools(&cfg.bypass_tools());

        if let Ok((ips, v4_extra, v6_extra)) = net_data {
            // Upstream router / VPN relay: whoami.akamai.net via local candidates
            // (mirrors fetch_network_panel).
            let mut candidates: Vec<IpAddr> = Vec::new();
            for (ip_str, _) in &dns_info.active {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if domains::is_local_or_relay_ip(&ip) && !candidates.contains(&ip) {
                        candidates.push(ip);
                    }
                }
            }
            if let Some(gw) = dns_info.gateway {
                if domains::is_local_or_relay_ip(&gw) && !candidates.contains(&gw) {
                    candidates.push(gw);
                }
            }
            let mut upstream: Option<String> = None;
            for cand in &candidates {
                let server = SocketAddr::new(*cand, 53);
                if let Ok((addrs, _)) =
                    probe_udp_dns(server, "whoami.akamai.net", Duration::from_secs(2), None).await
                {
                    if let Some(up) = addrs.first() {
                        let mut text = up.to_string();
                        if let Some(extra) =
                            fetch_ip_cymru(up, &cfg.cymru_doh_servers, Duration::from_secs(5)).await
                        {
                            if let Some(org) = extra.org.as_ref() {
                                if !org.is_empty() {
                                    text += &format!(" ({})", org);
                                }
                            }
                        }
                        upstream = Some(text);
                        break;
                    }
                }
            }
            if let Some(up) = upstream {
                let a_name = dns_info.active_name.clone().unwrap_or_default();
                let label = if is_tun_name(&a_name) { "Upstream VPN" } else { "Резолвер роутера" };
                dns_info.upstream = Some(up);
                dns_info.upstream_label = Some(label.to_string());
            }

            let v4 = family_info(ips.v4.map(|(ip, ms)| (IpAddr::V4(ip), ms)), v4_extra.clone());
            let v6 = ips.v6.map(|(ip, ms)| (IpAddr::V6(ip), ms));
            let v6 = family_info(v6, v6_extra);
            // Both lookups dead: red "timeout" rows (mirrors fetch_network_panel).
            let (v4, v6) = match (&v4, &v6) {
                (None, None) => (Some(timeout_family()), Some(timeout_family())),
                _ => (v4, v6),
            };
            let data = NetInfoData { v4, v6, empty: false };
            if !args.json {
                emitter.emit(&render_netinfo_panel(&data, &dns_info, &bypass, msg));
            } else {
                let mut tun: Vec<String> = Vec::new();
                if let Some(ref n) = dns_info.active_name {
                    if is_tun_name(n) && !tun.contains(n) {
                        tun.push(n.clone());
                    }
                }
                for (_, n) in &dns_info.other_static {
                    if is_tun_name(n) && !tun.contains(n) {
                        tun.push(n.clone());
                    }
                }
                json_results.insert(
                    "network_info".to_string(),
                    json!({
                        "ipv4": ips.v4.map(|(ip, lat)| json!({"ip": ip.to_string(), "latency_ms": lat})),
                        "ipv6": ips.v6.map(|(ip, lat)| json!({"ip": ip.to_string(), "latency_ms": lat})),
                        "v4_asn": v4_extra.as_ref().map(|c| &c.asn),
                        "v4_org": v4_extra.as_ref().and_then(|c| c.org.as_ref()),
                        "v4_cc": v4_extra.as_ref().and_then(|c| c.country.as_ref()),
                        "upstream": dns_info.upstream,
                        "system_dns": dns_info.nameservers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                        "gateway": dns_info.gateway.map(|g| g.to_string()),
                        "tun": tun,
                        "bypass_tools": bypass,
                    }),
                );
            }
        } else if !args.json {
            emitter.emit("Информация о сети недоступна.\n");
        }

        if !args.json && (run_dns || run_dom || run_tcp || run_sni || run_tg) && !args.batch {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    // ── Test 1: DNS availability ──
    if run_dns {
        if cfg.availability_servers().is_empty() {
            if !args.json {
                emitter.emit("DNS_AVAILABILITY_SERVERS не задан в config.yml — тест пропущен.\n");
            }
        } else {
            let report = check_dns_availability(cfg, phases.clone()).await;
            live.finish();
            if !args.json {
                emitter.emit(&render_dns_endpoints(&report));
                emitter.emit(&render_dns_availability(&report, cfg));
            } else {
                let s = &report.stats;
                json_results.insert(
                    "dns_availability".to_string(),
                    json!({
                        "doh_ok": s.doh_ok, "doh_total": s.doh_total,
                        "dot_ok": s.dot_ok, "dot_total": s.dot_total,
                        "udp_ok": s.udp_ok, "udp_total": s.udp_total,
                        "hijacked_brands": s.hijacked_brands,
                        "resolvers_total": s.resolvers_total,
                        "subst_sub": s.subst_sub, "subst_total": s.subst_total,
                    }),
                );
            }
            dns_stats = Some(report.stats.clone());
        }
    }

    // ── Test 2: domains (resolve → TLS1.3 → TLS1.2 → HTTP) ──
    if run_dom {
        if !args.json {
            emitter.emit(&format!(
                "\nПроверка доступности доменов  Целей: {} | IP: {} | timeout: {}s\n\n",
                domains.len(),
                if cfg.ip_version == "ipv6" { "IPv6" } else { "IPv4" },
                cfg.connect_timeout
            ));
        }
        // Silent stub collection with timeout (mirrors STUB_IPS_TIMEOUT)
        let stub_ips: HashSet<IpAddr> = tokio::time::timeout(
            Duration::from_secs_f64(cfg.stub_ips_timeout),
            collect_stub_ips(cfg),
        )
        .await
        .unwrap_or_default();

        if !args.json {
            emitter.emit("Фаза 0/3: DNS-резолв...\n");
        }
        let mut entries = resolve_all(domains, family, &stub_ips, &sem, phases.clone()).await;
        live.finish();
        if !args.json {
            emitter.emit("Фаза 1/3: TLS 1.3...\n");
        }
        check_tls_all(&mut entries, false, cfg, &sem, phases.clone()).await;
        live.finish();
        if !args.json {
            emitter.emit("Фаза 2/3: TLS 1.2...\n");
        }
        check_tls_all(&mut entries, true, cfg, &sem, phases.clone()).await;
        live.finish();
        if !args.json {
            emitter.emit("Фаза 3/3: HTTP...\n");
        }
        check_http_all(&mut entries, cfg, &stub_ips, &sem, phases.clone()).await;
        live.finish();

        let stats = domain_stats(&entries);
        if !args.json {
            emitter.emit(&render_domain_table(&entries, msg));
            emitter.emit(&render_dns_resolve_notes(&entries));
        } else {
            let list: Vec<_> = entries
                .iter()
                .map(|e| {
                    json!({
                        "domain": e.domain,
                        "resolved": e.resolved.map(|ip| ip.to_string()),
                        "http": e.http.status.as_str(),
                        "http_detail": e.http.detail,
                        "tls12": e.t12.status.as_str(),
                        "tls12_detail": e.t12.detail,
                        "tls13": e.t13.status.as_str(),
                        "tls13_detail": e.t13.detail,
                    })
                })
                .collect();
            json_results.insert("domain_inspection".to_string(), json!(list));
        }
        dom_stats = Some(stats);
    }

    // ── Test 3: TCP 16–20 KB ──
    if run_tcp {
        if !args.json {
            emitter.emit(&format!(
                "\nПроверка TCP 16-20KB блокировки  Целей: {} | timeout: {}s\n",
                tcp_items.len(),
                cfg.fat_connect_timeout
            ));
            emitter.emit("Проверка...\n");
        }
        let mut rows: Vec<TcpRow> = Vec::new();
        let tcp_tick = phases
            .as_ref()
            .map(|p| (p.on_phase)("Проверка...".to_string(), tcp_items.len(), true));
        let mut handles = Vec::new();
        for item in tcp_items {
            let item = item.clone();
            let cfg_c = cfg.clone();
            let sem_c = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let port = item.port;
                let sni = if port == 80 {
                    String::new()
                } else {
                    item.sni.clone().unwrap_or_else(|| cfg_c.fat_default_sni.clone())
                };
                let t0 = Instant::now();
                let (_alive, status, detail, _rtt) =
                    check_tcp_16_20(&item.ip, port, &sni, &cfg_c, &sem_c, None).await;
                let elapsed = t0.elapsed().as_secs_f64();
                let detail = if detail.is_empty() {
                    format!("{:.1}s", elapsed)
                } else {
                    format!("{} | {:.1}s", detail, elapsed)
                };
                let asn_raw = item.asn.trim().to_string();
                let asn_str = if asn_raw.is_empty() {
                    "-".to_string()
                } else if asn_raw.to_uppercase().starts_with("AS") {
                    asn_raw.to_uppercase()
                } else {
                    format!("AS{}", asn_raw)
                };
                (item.id, asn_str, item.provider, status, detail)
            }));
        }
        let mut ok = 0;
        let mut blocked = 0;
        let mut mixed = 0;
        for h in handles {
            if let Some(t) = tcp_tick.as_ref() {
                t();
            }
            if let Ok((id, asn, provider, status, detail)) = h.await {
                let label = status.display_label();
                if label.contains("OK") {
                    ok += 1;
                } else if label.contains("DETECTED") {
                    blocked += 1;
                } else if label.contains("MIXED") {
                    mixed += 1;
                }
                rows.push(TcpRow { id, asn, provider, status, detail });
            }
        }
        tcp_summary = Some((ok, blocked, mixed, rows.len()));
        live.finish();
        if !args.json {
            emitter.emit(&render_tcp_table(&rows, msg));
        } else {
            let list: Vec<_> = rows
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id, "asn": r.asn, "provider": r.provider,
                        "status": r.status.as_str(), "detail": r.detail,
                    })
                })
                .collect();
            json_results.insert("tcp16".to_string(), json!(list));
        }
        let _ = socks_proxy;
    }

    // ── Test 4: white SNI ──
    if run_sni {
        if whitelist_sni.is_empty() {
            if !args.json {
                emitter.emit("Файл whitelist_sni.txt пуст или не найден — тест 4 пропущен.\n");
            }
        } else {
            let port443: Vec<_> = tcp_items.iter().filter(|t| t.port == 443).collect();
            if !args.json {
                let mut asns = std::collections::HashSet::new();
                for t in &port443 {
                    let k = t.asn.trim().to_uppercase();
                    asns.insert(if k.is_empty() { t.ip.clone() } else { k });
                }
                emitter.emit(&format!(
                    "\nПоиск белых SNI для ASN  AS: {} | IP: {} | SNI: {} | батч: {}\n",
                    asns.len(),
                    port443.len(),
                    whitelist_sni.len(),
                    cfg.sni_batch_size
                ));
                emitter.emit("Фаза 1/2: Базовая проверка...\n");
            }
            let report = run_whitelist_sni(tcp_items, whitelist_sni, cfg, &sem, phases.clone()).await;
            live.finish();
            if !args.json {
                if report.detected_as > 0 {
                    emitter.emit(&format!(
                        "Фаза 2/2: Параллельный перебор SNI для {} AS (батч {}, топ-{})...\n\n",
                        report.detected_as, cfg.sni_batch_size, cfg.sni_top_n
                    ));
                }
                emitter.emit(&render_whitelist(&report, port443.len()));
            } else {
                json_results.insert(
                    "whitelist_sni".to_string(),
                    json!({
                        "detected_as": report.detected_as,
                        "found_as": report.found_as,
                    }),
                );
            }
        }
    }

    // ── Test 5: Telegram ──
    if run_tg {
        let rep = run_telegram_full(cfg, phases.clone()).await;
        live.finish();
        if !args.json {
            emitter.emit(&render_telegram(&rep, msg));
        } else {
            json_results.insert(
                "telegram".to_string(),
                json!({
                    "verdict": rep.verdict,
                    "download": {"status": rep.download.status, "avg_bps": rep.download.avg_bps, "peak_bps": rep.download.peak_bps, "bytes": rep.download.bytes_total, "drop_at_sec": rep.download.drop_at_sec},
                    "upload": {"status": rep.upload.status, "avg_bps": rep.upload.avg_bps, "peak_bps": rep.upload.peak_bps, "bytes": rep.upload.bytes_total, "drop_at_sec": rep.upload.drop_at_sec},
                    "dc_reachable": rep.dc_reachable, "dc_total": rep.dc_total,
                }),
            );
        }
        tg_full = Some(rep);
    }

    // ── Test 6: legend ──
    if run_legend && !args.json {
        print_legend(lang, msg);
    }

    // ── Summary ──
    if !args.json {
        emitter.emit("\n");
        let summary = render_summary(&SummaryData {
            run_dns,
            dns: dns_stats.as_ref(),
            domains: dom_stats.as_ref(),
            tcp: tcp_summary,
            run_telegram: run_tg,
            telegram: tg_full.as_ref(),
        });
        if !summary.is_empty() {
            emitter.emit(&summary);
        }
    }

    if args.json {
        let payload = json!({
            "schema_version": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "profile": profile.code(),
            "results": json_results,
        });
        let text = serde_json::to_string_pretty(&payload).unwrap_or_default();
        println!("{}", text);
        if let Some(ref out_path) = args.output {
            let _ = std::fs::write(out_path, &text);
        }
    }

    json_results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors Python `tests/test_helpers.py::test_selection_flags`.
    #[test]
    fn test_selection_flags() {
        let (run_net, run_dns, run_dom, run_tcp, run_wl, run_tg, run_leg, only_leg) =
            selection_flags("123");
        assert!(!run_net);
        assert!(run_dns);
        assert!(run_dom);
        assert!(run_tcp);
        assert!(!run_wl);
        assert!(!run_tg);
        assert!(!run_leg);
        assert!(!only_leg);

        let (_, _, _, _, _, _, run_leg, only_leg) = selection_flags("6");
        assert!(run_leg);
        assert!(only_leg);

        let (run_net, _, _, _, _, _, run_leg, only_leg) = selection_flags("06");
        assert!(run_net);
        assert!(run_leg);
        assert!(!only_leg);
    }
}

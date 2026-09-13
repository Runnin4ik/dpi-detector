use std::collections::{HashMap, HashSet};
use std::io::{stdout, IsTerminal, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dpi_core::config::{
    base_dir, clean_domain, default_tcp16_targets, embedded_domains, embedded_tcp16_targets,
    embedded_whitelist_sni, load_config, load_domains_from_file, load_tcp16_targets_from_file,
    load_whitelist_sni, resource_path, AppConfig,
};
use dpi_core::dns::availability::check_dns_availability;
use dpi_core::dns::parse_socks_proxy;
use dpi_core::i18n::{get_messages, legend_text, Language, Messages};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::dns::udp::probe_udp_dns;
use dpi_core::net::netinfo::{
    detect_bypass_tools, fetch_ip_cymru, fetch_public_ips, get_system_dns, is_tun_name, IpCymruInfo,
};
use dpi_core::{PhaseProgress, ProgressTick};
use dpi_core::net::version::{fetch_latest_version, version_badge_lang};
use dpi_core::probe::domains::{
    check_http_all, check_tls_all, collect_stub_ips, domain_stats, resolve_all, IpFamily,
};
use dpi_core::probe::telegram::run_telegram_full;
use dpi_core::probe::burst::{
    burst_targets, BurstSettings, BurstTarget, BURST_DEFAULT_ATTEMPTS, BURST_DEFAULT_TIMEOUT_SECS,
};
use dpi_core::probe::whitelist::run_whitelist_sni;
use dpi_core::probe::{check_tcp_16_20, domains};
use dpi_core::profile::RegionProfile;
use serde_json::json;
use tokio::sync::Semaphore;

mod args;
mod menu;
mod render;

use args::CliArgs;
use menu::{burst_settings_menu, run_interactive_menu, tui_available, MenuResult, VersionSlot};
use render::{
    asc, clean_output, output_str, panel_to_string, plain_mode, render_banner, render_burst_table,
    render_dns_availability,
    render_dns_endpoints, render_dns_resolve_notes, render_domain_table, render_fingerprint_header,
    render_netinfo_panel, render_summary, render_tcp_table, render_telegram, render_whitelist, set_ascii_mode,
    set_has_vt, set_plain_mode, strip_ansi, LiveProgress, NetFamilyInfo, NetInfoData, NetTtlb, Spinner,
    SummaryData, TcpRow,
};
/// Splits a test selection string into per-test flags (mirrors `_selection_flags`).
/// Tests: 0 netinfo, 1 DNS, 2 domains, 3 TCP, 4 white-SNI, 5 Telegram, 6 legend,
/// 7 fingerprint stress (burst).
fn selection_flags(selection: &str) -> (bool, bool, bool, bool, bool, bool, bool, bool, bool) {
    let has = |c: char| selection.contains(c);
    let net = has('0');
    let dns = has('1');
    let dom = has('2');
    let tcp = has('3');
    let sni = has('4');
    let tg = has('5');
    let burst = has('7');
    let legend = has('6');
    let only_legend = legend && !(net || dns || dom || tcp || sni || tg || burst);
    (net, dns, dom, tcp, sni, tg, burst, legend, only_legend)
}

/// Cell of the CDN (16 KB) table's detail column. An empty probe detail is a
/// clean 20 KB pass, so the row carries only its duration; every other detail is
/// a drop/RST/timeout diagnosis and stands alone — a duration glued to an error
/// reads as if the timing were part of the verdict.
fn tcp16_detail(detail: String, elapsed: f64) -> String {
    if detail.is_empty() {
        format!("{:.1}s", elapsed)
    } else {
        detail
    }
}
fn print_out(s: &str) {
    output_str(&clean_output(s));
}

fn println_out(s: &str) {
    let mut text = clean_output(s);
    text.push_str("\r\n");
    output_str(&text);
}
struct Emitter {
    report: String,
    json_mode: bool,
}
impl Emitter {
    fn emit(&mut self, s: &str) {
        if !self.json_mode {
            output_str(&clean_output(s));
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
pub fn normalize_key_char(c: char) -> char {
    // Fullwidth ASCII (Chinese, Japanese, Korean IME 全角: ｑ -> q, １ -> 1, etc.)
    if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        return char::from_u32(c as u32 - 0xFEE0).unwrap_or(c);
    }
    if c == '\u{3000}' {
        return ' ';
    }
    c
}

fn read_post_test_action() -> PostTestAction {
    let _ = enable_raw_mode();
    loop {
        if let Ok(Event::Key(KeyEvent { code, modifiers, kind, .. })) = event::read() {
            if kind != KeyEventKind::Press {
                continue;
            }
            let code = match code {
                KeyCode::Char(c) => KeyCode::Char(normalize_key_char(c)),
                other => other,
            };
            if modifiers.contains(KeyModifiers::CONTROL) && (code == KeyCode::Char('c') || code == KeyCode::Char('C')) {
                let _ = disable_raw_mode();
                return PostTestAction::Quit;
            }

            match code {
                // Repeat: Enter or 'r' / 'R' / 'к' / 'К' (RU) / 'ر' (AR/FA) / 'ㄐ' (Bopomofo)
                KeyCode::Enter
                | KeyCode::Char('r')
                | KeyCode::Char('R')
                | KeyCode::Char('к')
                | KeyCode::Char('К')
                | KeyCode::Char('ر')
                | KeyCode::Char('ㄐ') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Repeat;
                }

                // Menu: 'm' / 'M' / 'ь' / 'Ь' (RU) / 'پ' / 'م' / 'ة' (AR/FA) / 'ㄩ' (Bopomofo) / 'צ' (Hebrew)
                KeyCode::Char('m')
                | KeyCode::Char('M')
                | KeyCode::Char('ь')
                | KeyCode::Char('Ь')
                | KeyCode::Char('پ')
                | KeyCode::Char('م')
                | KeyCode::Char('ة')
                | KeyCode::Char('ㄩ')
                | KeyCode::Char('צ') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Menu;
                }

                // Export: 's' / 'S' / 'ы' / 'Ы' (RU) / 'і' / 'І' (UA) / 'س' (AR/FA) / 'ㄋ' (Bopomofo) / 'ד' (Hebrew)
                KeyCode::Char('s')
                | KeyCode::Char('S')
                | KeyCode::Char('ы')
                | KeyCode::Char('Ы')
                | KeyCode::Char('і')
                | KeyCode::Char('І')
                | KeyCode::Char('س')
                | KeyCode::Char('ㄋ')
                | KeyCode::Char('ד') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Export;
                }

                // Quit: 'q' / 'Q' / 'й' / 'Й' (RU) / 'ض' (AR/FA) / 'ㄆ' (Bopomofo) or Esc
                KeyCode::Char('q')
                | KeyCode::Char('Q')
                | KeyCode::Char('й')
                | KeyCode::Char('Й')
                | KeyCode::Char('ض')
                | KeyCode::Char('ㄆ')
                | KeyCode::Esc => {
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

fn export_report(path: &str, content: &str, msg: &Messages) {
    match std::fs::write(path, content) {
        Ok(()) => println_out(&format!("\x1b[1;32m{}\x1b[0m", msg.report_saved.replace("{}", path))),
        Err(e) => println_out(&format!("\x1b[1;33m{}\x1b[0m", msg.report_save_fail.replace("{}", &e.to_string()))),
    }
}


/// Legend-only interactive loop (mirrors `handle_legend_menu`).
fn legend_loop(lang: Language, msg: &Messages) -> MenuAction {
    loop {
        print_out(&legend_text(lang, msg));
        if !std::io::stdin().is_terminal() {
            return MenuAction::Quit;
        }
        println_out(&panel_to_string(
            msg.menu_control_menu,
            &[format!(
                "  \x1b[1;42;37m Enter \x1b[0m {}   \x1b[1;44;37m M \x1b[0m {}   \x1b[1;41;37m Q \x1b[0m {}",
                msg.menu_control_repeat, msg.menu_control_menu, msg.menu_control_exit
            )],
        ));
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

/// Language of the run, for the panic hook (which has no access to state).
static PANIC_LANG: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn lang_code(lang: Language) -> u8 {
    match lang {
        Language::En => 0,
        Language::Ru => 1,
        Language::Zh => 2,
        Language::Fa => 3,
    }
}

fn lang_from_code(code: u8) -> Language {
    match code {
        1 => Language::Ru,
        2 => Language::Zh,
        3 => Language::Fa,
        _ => Language::En,
    }
}

/// Resolves the interface language from the raw arguments, before `clap` runs,
/// so `--help` and parse errors speak the language the user asked for.
fn prescan_language() -> Language {
    let argv: Vec<String> = std::env::args().collect();
    let mut raw: Option<String> = None;
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        if let Some(v) = arg.strip_prefix("--lang=") {
            raw = Some(v.to_string());
        } else if arg == "--lang" || arg == "-l" {
            if let Some(v) = argv.get(i + 1) {
                raw = Some(v.clone());
                i += 1;
            }
        } else if let Some(v) = arg.strip_prefix("-l") {
            if !v.is_empty() {
                raw = Some(v.to_string());
            }
        }
        i += 1;
    }
    match raw.as_deref() {
        None | Some("auto") => Language::autodetect(),
        Some(code) => Language::from_code(code).unwrap_or(Language::En),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Panic hook: write crash details to file and pause so console does not instantly vanish.
    std::panic::set_hook(Box::new(|info| {
        let msg = get_messages(lang_from_code(PANIC_LANG.load(std::sync::atomic::Ordering::Relaxed)));
        let err_msg = format!("{}\n", msg.crash_title.replace("{}", &info.to_string()));
        let _ = std::fs::write("dpi_detector_crash.log", &err_msg);
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(err_msg.as_bytes());
        let _ = stderr.write_all(msg.crash_press_enter.as_bytes());
        let _ = stderr.write_all(b"\r\n");
        let _ = stderr.flush();
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }));

    let args = args::parse_cli(prescan_language());
    #[cfg(windows)]
    let has_vt = {
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> isize;
            fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
            fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
            fn SetConsoleCP(wCodePageID: u32) -> i32;
        }
        const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
        // Probe Virtual Terminal Processing (VT100) on stdout.
        // On Windows 7 / 8 this returns 0 (fails), indicating legacy conhost.
        let out_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let mut out_mode: u32 = 0;
        let vt_ok = if unsafe { GetConsoleMode(out_handle, &mut out_mode) } != 0 {
            unsafe { SetConsoleMode(out_handle, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 }
        } else {
            false
        };

        // Only switch to UTF-8 code page if VT is supported; on Win7 raster fonts require OEM codepage
        if vt_ok {
            unsafe {
                SetConsoleOutputCP(65001);
                SetConsoleCP(65001);
            }
        }
        vt_ok
    };
    #[cfg(not(windows))]
    let has_vt = {
        let term = std::env::var("TERM").unwrap_or_default();
        term != "dumb" && term != "linux"
    };
    set_has_vt(has_vt);
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let legacy_console = !has_vt || args.ascii;
    set_ascii_mode(legacy_console);
    #[cfg(windows)]
    let plain = no_color || !std::io::stdout().is_terminal();
    #[cfg(not(windows))]
    let plain = legacy_console || no_color;
    set_plain_mode(plain);
    let profile = RegionProfile::from_code(&args.profile).unwrap_or_default();
    let mut lang = if args.lang == "auto" {
        Language::autodetect()
    } else {
        match Language::from_code(&args.lang) {
            Some(lang) => lang,
            None => {
                if !args.json {
                    let en = get_messages(Language::En);
                    eprintln!("{}", en.warn_unknown_lang.replace("{}", &args.lang));
                }
                Language::En
            }
        }
    };
    let mut msg = get_messages(lang);
    PANIC_LANG.store(lang_code(lang), std::sync::atomic::Ordering::Relaxed);

    // Validators (mirror argparse errors)
    if let Some(ref t) = args.tests {
        let valid = !t.is_empty()
            && t.chars().all(|c| ('0'..='7').contains(&c) || c == ',' || c == ' ')
            && t.chars().any(|c| ('0'..='7').contains(&c));
        if !valid {
            eprintln!("{}", msg.invalid_tests_flag.replace("{}", t));
            std::process::exit(2);
        }
    }
    if let Some(c) = args.concurrency {
        if c < 1 {
            eprintln!("{}", msg.invalid_concurrency_flag);
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
        print_out(&format!("\x1b[33m{}\x1b[0m", msg.whitelist_skipped));
    }

    if let Some(ref e) = cfg.config_load_error {
        println_out(&format!("\x1b[1;33m{}\x1b[0m {}", msg.config_load_error_label, e));
    }
    for w in &cfg.config_warnings {
        println_out(&format!(
            "\x1b[33m{}\x1b[0m {}",
            msg.config_warning_label,
            msg.config_warning(w)
        ));
    }

    if args.legend {
        print_out(&legend_text(lang, &msg));
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

    let has_explicit_cmd = args.tests.is_some()
        || !args.domain.is_empty()
        || args.domains.is_some()
        || args.tcp16.is_some()
        || args.legend
        || args.json;
    let wants_menu = !has_explicit_cmd && std::io::stdin().is_terminal() && tui_available();
    let is_interactive = wants_menu;

    // If user ran the binary with NO arguments and TUI is unavailable:
    if !has_explicit_cmd && !wants_menu {
        let banner = render_banner(&msg, profile, msg.checking_updates);
        print_out(&clean_output(&banner));
        let raw_err = if let Err(e) = crossterm::terminal::enable_raw_mode() {
            Some(format!("{e}"))
        } else {
            let _ = crossterm::terminal::disable_raw_mode();
            None
        };
        let reason = if !std::io::stdin().is_terminal() {
            msg.tui_reason_stdin.to_string()
        } else if let Some(ref e) = raw_err {
            e.clone()
        } else {
            msg.tui_reason_raw_mode.to_string()
        };
        let notice = msg.tui_unavailable.replace("{}", &reason);
        print_out(&clean_output(&notice));
        return;
    }
    let mut tests_str = if let Some(ref t) = args.tests {
        t.chars().filter(|c| ('0'..='7').contains(c)).collect::<String>()
    } else if !args.domain.is_empty() || args.domains.is_some() {
        "2".to_string()
    } else if args.tcp16.is_some() {
        "3".to_string()
    } else {
        "123".to_string()
    };
    let mut concurrency = cfg.max_concurrent;
    let mut ip_version = cfg.ip_version.clone();
    let mut tls_fingerprint = cfg.fingerprint();

    // Initial badge: wait up to 4 s only in non-interactive mode
    let mut badge = msg.checking_updates.to_string();
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
                badge = version_badge_lang(latest.as_ref(), lang);
            }
        }
    }

    if is_interactive {
        // Poll the version slot for the menu badge without blocking
        if let Ok(g) = version_slot.lock() {
            if let Some(ref latest) = *g {
                badge = version_badge_lang(latest.as_ref(), lang);
            }
        }
        match run_interactive_menu(lang, profile, &cfg, &badge, &version_slot).await {
            MenuResult::Run(sel) => {
                tests_str = sel.selected_tests;
                concurrency = sel.concurrency;
                ip_version = sel.ip_version;
                tls_fingerprint = sel.tls_fingerprint;
                lang = sel.language;
                msg = get_messages(lang);
            }
            MenuResult::Quit => return,
        }
        // Refresh badge after menu dwell time
        if let Ok(g) = version_slot.lock() {
            if let Some(ref latest) = *g {
                badge = version_badge_lang(latest.as_ref(), lang);
            }
        }
    }
    let mut banner_done = is_interactive;

    // Banner first in non-interactive runs, then the config line (mirrors header order).
    if !args.json && !banner_done {
        print_out(&render_banner(&msg, profile, &badge));
        banner_done = true;
    }

    // Selection info line (mirrors dpi_detector.py)
    if !args.json {
        println_out(&format!(
            "\x1b[2m{}: \x1b[36m{}\x1b[0m\x1b[2m | {}: \x1b[36m{}\x1b[0m",
            msg.menu_ip_version, ip_version, msg.menu_concurrency, concurrency
        ));
        if let Some(p) = cfg.effective_proxy() {
            let proxy_label = msg.proxy_in_use;
            println_out(&format!("\x1b[2m{}: \x1b[33m{}\x1b[0m", proxy_label, mask_proxy(p)));
        }
    }
    let (_, _, _, _, _, _, _, _, only_legend) = selection_flags(&tests_str);
    if only_legend {
        match legend_loop(lang, &msg) {
            MenuAction::Quit => return,
            MenuAction::Menu => {
                // Re-enter interactive menu once, then run
                if is_interactive {
                    match run_interactive_menu(lang, profile, &cfg, &badge, &version_slot).await {
                        MenuResult::Run(sel) => {
                            tests_str = sel.selected_tests;
                            concurrency = sel.concurrency;
                            ip_version = sel.ip_version;
                            tls_fingerprint = sel.tls_fingerprint;
                            lang = sel.language;
                            msg = get_messages(lang);
                        }
                        MenuResult::Quit => return,
                    }
                }
            }
        }
        let (_, _, _, _, _, _, _, _, only_legend) = selection_flags(&tests_str);
        if only_legend {
            return;
        }
    }

    if ip_version == "ipv6" && !dpi_core::net::netinfo::ipv6_supported() {
        println_out(&format!("\x1b[31m{}\x1b[0m", msg.ipv6_not_configured));
        println_out(&format!("\x1b[2m{}\x1b[0m", msg.ipv6_switch_hint));
        return;
    }
    cfg.ip_version = ip_version.clone();
    // Precedence: CLI flag > menu selection > config.yml value.
    cfg.tls_fingerprint = tls_fingerprint.code().to_string();
    if let Some(f) = &args.fingerprint {
        match TlsFingerprint::parse(f) {
            Some(fp) => cfg.tls_fingerprint = fp.code().to_string(),
            None => {
                if !args.json {
                    eprintln!(
                        "{}",
                        msg.warn_unknown_fingerprint
                            .replacen("{}", f, 1)
                            .replacen("{}", &cfg.tls_fingerprint, 1)
                    );
                }
            }
        }
    }
    if !args.json {
        println_out(&render_fingerprint_header(cfg.fingerprint(), &msg));
    }

    let mut burst_plan = burst_plan_from_cli(&args, &domains, &msg);
    let mut result_path = args.output.clone();
    let mut selection = tests_str.clone();

    loop {
        // Test 7 is destructive for its targets, so it asks for its own settings
        // screen before it runs instead of starting with guesses: cancelling the
        // screen drops test 7 from the selection and runs the rest. The screen
        // belongs to the test itself, so an explicit `-t 7` gets it too — but
        // only on a terminal at both ends: with stdin or stdout redirected there
        // is nobody to answer the screen, and the CLI flags stand in for it.
        let settings_screen = !args.json
            && selection.contains('7')
            && std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && tui_available();
        if settings_screen {
            // The screen always opens with an empty field: prefilling the last
            // target made a fresh run append to it, so an edited domain looked
            // ignored. Empty means "the CLI/config list", and the count of that
            // list is printed under the field.
            match burst_settings_menu(lang, &burst_plan.settings, burst_plan.targets.len()).await {
                Some(choice) => {
                    burst_plan.settings = choice.settings;
                    if let Some(domain) = choice.domain {
                        burst_plan.targets = vec![domain];
                    }
                }
                None => {
                    selection = selection.replace('7', "");
                    if selection.is_empty() {
                        // Test 7 was the only selection and its settings were
                        // cancelled: leave instead of printing an empty report.
                        println_out("");
                        return;
                    }
                }
            }
        }
        let mut emitter = Emitter { report: String::new(), json_mode: args.json };
        let stats = run_test_suite(
            &selection,
            concurrency,
            &args,
            &cfg,
            &domains,
            &tcp_items,
            &whitelist_sni,
            &burst_plan,
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
                export_report(out_path, &emitter.report, &msg);
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
        let rule_str = format!("\x1b[2m{}\x1b[0m", rule);
        println_out(&rule_str);
        if plain_mode() {
            println_out(&format!(
                "  [Enter] {}   [M] {}   [S] {}   [Q] {}",
                msg.menu_control_repeat, msg.menu_control_menu, msg.menu_control_export, msg.menu_control_exit
            ));
        } else {
            println_out(&format!(
                " \x1b[1;42;37m  Enter  \x1b[0m {}   \x1b[1;44;37m  M  \x1b[0m {}   \x1b[1;43;37m  S  \x1b[0m {}   \x1b[1;41;37m  Q  \x1b[0m {}",
                msg.menu_control_repeat, msg.menu_control_menu, msg.menu_control_export, msg.menu_control_exit
            ));
        }
        println_out(&rule_str);
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
                            badge = version_badge_lang(latest.as_ref(), lang);
                        }
                    }
                    match run_interactive_menu(lang, profile, &cfg, &badge, &version_slot).await {
                        MenuResult::Run(sel) => {
                            selection = sel.selected_tests;
                            concurrency = sel.concurrency;
                            cfg.ip_version = sel.ip_version.clone();
                            cfg.tls_fingerprint = sel.tls_fingerprint.code().to_string();
                            lang = sel.language;
                            msg = get_messages(lang);
                        }
                        MenuResult::Quit => return,
                    }
                    let (_, _, _, _, _, _, _, _, only) = selection_flags(&selection);
                    if only {
                        match legend_loop(lang, &msg) {
                            MenuAction::Quit => return,
                            MenuAction::Menu => {}
                        }
                    }
                    should_repeat = true;
                }
                PostTestAction::Export => {
                    if result_path.is_none() {
                        result_path = Some(base_dir().join("dpi_detector_results.txt").to_string_lossy().to_string());
                    }
                    if let Some(ref p) = result_path {
                        export_report(p, &emitter.report, &msg);
                    }
                }
                PostTestAction::Quit => return,
            }
        }
        println_out("");
    }

    if plain_mode() && is_interactive && std::io::stdin().is_terminal() {
        println_out(msg.press_enter_to_exit);
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
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

/// Everything test 7 needs: the burst shape and the hosts to fire it at.
struct BurstPlan {
    settings: BurstSettings,
    targets: Vec<String>,
}

/// Builds test 7's plan from the CLI. An unknown profile name is reported (the
/// test then runs the profiles it did understand) rather than silently swapped
/// for a different set.
fn burst_plan_from_cli(args: &CliArgs, domains: &[String], msg: &Messages) -> BurstPlan {
    let (profiles, unknown) = match &args.burst_profiles {
        Some(value) => TlsFingerprint::parse_list(value),
        None => (TlsFingerprint::ALL.to_vec(), Vec::new()),
    };
    if !args.json {
        for token in unknown {
            let fallback = profiles.iter().map(|f| f.token()).collect::<Vec<_>>().join(", ");
            eprintln!(
                "{}",
                msg.warn_unknown_fingerprint.replacen("{}", &token, 1).replacen("{}", &fallback, 1)
            );
        }
    }
    let settings = BurstSettings::clamped(
        args.burst.unwrap_or(BURST_DEFAULT_ATTEMPTS),
        args.burst_timeout.unwrap_or(BURST_DEFAULT_TIMEOUT_SECS),
        profiles,
    );
    // `-d` picks the targets, exactly as it does for test 2; without it the
    // configured list is used.
    let targets = if args.domain.is_empty() {
        domains.to_vec()
    } else {
        args.domain.clone()
    };
    BurstPlan { settings, targets }
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
    burst: &BurstPlan,
    msg: &Messages,
    profile: RegionProfile,
    lang: Language,
    badge: &str,
    banner_done: bool,
    emitter: &mut Emitter,
) -> HashMap<String, serde_json::Value> {
    let (run_net, run_dns, run_dom, run_tcp, run_sni, run_tg, run_burst, run_legend, _) =
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
        let live_b = Arc::clone(&live);
        let msg_copy = *msg;
        Some(PhaseProgress {
            on_phase: Arc::new(move |phase: dpi_core::PhaseId, total: usize| {
                // Stages of test 2 share one line, so a new stage advances its
                // own counter instead of starting a line of its own.
                if let Some(block) = phase.stage_block() {
                    live_c.set_total(block, total);
                    let tick_c = Arc::clone(&live_c);
                    let tick: ProgressTick = Arc::new(move || tick_c.bump(block));
                    return tick;
                }
                let desc = msg_copy.phase_text(phase);
                live_c.set(desc, total);
                let tick_c = Arc::clone(&live_c);
                let tick: ProgressTick = Arc::new(move || tick_c.tick());
                tick
            }),
            on_blocks: Arc::new(move |phase: dpi_core::PhaseId, blocks: &[(dpi_core::ProgressBlock, usize)]| {
                let desc = msg_copy.phase_text(phase);
                live_b.set_blocks(desc, blocks);
                let tick_c = Arc::clone(&live_b);
                let tick: dpi_core::BlockTick = Arc::new(move |block| tick_c.bump(block));
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
                emitter.emit(&msg.invalid_proxy_err.replacen("{}", url, 1).replacen("{}", &e.to_string(), 1));
                None
            }
        },
        None => None,
    };

    let mut dns_stats = None;
    let mut dom_stats = None;
    let mut tcp_summary = None;
    let mut tg_full = None;
    let mut burst_summary = None;

    // ── Test 0: network & system ──
    if run_net {
        let spinner = (!args.json).then(|| Spinner::start(msg.fetching_net_info));
        // The cap must clear the inner budgets (3.5 s public-IP race then 5 s
        // Cymru, both bounding their whole fetch): with a smaller one a slow
        // but working network would print "network information unavailable"
        // instead of the panel with its red timeout rows.
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
                let label = if is_tun_name(&a_name) { msg.upstream_vpn } else { msg.router_resolver };
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
            emitter.emit(msg.net_info_unavailable);
        }

    }
    // ── Test 1: DNS availability ──
    if run_dns {
        if cfg.availability_servers().is_empty() {
            if !args.json {
                emitter.emit(msg.dns_servers_empty_skip);
            }
        } else {
            let report = check_dns_availability(cfg, phases.clone(), concurrency).await;
            live.finish();
            if !args.json {
                emitter.emit(&render_dns_endpoints(&report, msg));
                emitter.emit(&render_dns_availability(&report, cfg, msg));
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
                "\n{}  {}: {} | {}: {} | {}: {}s\n\n",
                msg.domains_check_header,
                msg.targets_label,
                domains.len(),
                msg.ip_col,
                if cfg.ip_version == "ipv6" { "IPv6" } else { "IPv4" },
                msg.timeout_label,
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

        // All four stages are on the road from the first second (test 1
        // style), so the run reads as one progressing line rather than four
        // headers that scroll away.
        if !args.json {
            live.begin_stages(
                msg.stages_label.to_string(),
                &[
                    (dpi_core::ProgressBlock::DomainDns, domains.len()),
                    (dpi_core::ProgressBlock::DomainTls13, domains.len()),
                    (dpi_core::ProgressBlock::DomainTls12, domains.len()),
                    (dpi_core::ProgressBlock::DomainHttp, domains.len()),
                ],
            );
        }
        let mut entries = resolve_all(domains, family, &stub_ips, &sem, phases.clone()).await;
        check_tls_all(&mut entries, false, cfg, &sem, phases.clone()).await;
        check_tls_all(&mut entries, true, cfg, &sem, phases.clone()).await;
        check_http_all(&mut entries, cfg, &stub_ips, &sem, phases.clone()).await;
        live.finish();

        let stats = domain_stats(&entries);
        if !args.json {
            emitter.emit(&render_domain_table(&entries, msg));
            emitter.emit(&render_dns_resolve_notes(&entries, msg));
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
                "\n{}  {}: {} | {}: {}s\n",
                msg.tcp16_check_title,
                msg.targets_label,
                tcp_items.len(),
                msg.timeout_label,
                cfg.fat_connect_timeout
            ));
            emitter.emit(&format!("{}\n", msg.checking_status));
        }
        let mut rows: Vec<TcpRow> = Vec::new();
        let tcp_tick = phases
            .as_ref()
            .map(|p| (p.on_phase)(dpi_core::PhaseId::Tcp16, tcp_items.len()));
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
                let (status, detail, _rtt) =
                    check_tcp_16_20(&item.ip, port, &sni, &cfg_c, &sem_c, None).await;
                let elapsed = t0.elapsed().as_secs_f64();
                let detail = tcp16_detail(detail, elapsed);
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
            let done = h.await;
            if let Some(t) = tcp_tick.as_ref() {
                t();
            }
            if let Ok((id, asn, provider, status, detail)) = done {
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
                emitter.emit(msg.whitelist_skipped);
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
                    "\n{}  AS: {} | {}: {} | SNI: {} | {}: {}\n",
                    msg.menu_test_sni,
                    asns.len(),
                    msg.ip_col,
                    port443.len(),
                    whitelist_sni.len(),
                    msg.batch_label,
                    cfg.sni_batch_size
                ));
                emitter.emit(&format!("{}\n", msg.phase_sni_base));
            }
            let report = run_whitelist_sni(tcp_items, whitelist_sni, cfg, &sem, phases.clone()).await;
            live.finish();
            if !args.json {
                if report.detected_as > 0 {
                    let pmsg = msg.phase_sni_parallel
                        .replacen("{}", &report.detected_as.to_string(), 1)
                        .replacen("{}", &cfg.sni_batch_size.to_string(), 1)
                        .replacen("{}", &cfg.sni_top_n.to_string(), 1);
                    emitter.emit(&format!("{}\n\n", pmsg));
                }
                emitter.emit(&render_whitelist(&report, port443.len(), msg));
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

    // ── Test 7: fingerprint stress (simultaneous handshakes) ──
    if run_burst {
        let settings = &burst.settings;
        if !args.json {
            let profile_label = if settings.profiles.len() == TlsFingerprint::ALL.len() {
                msg.burst_profiles_all.to_string()
            } else {
                settings.profiles.iter().map(|f| f.token()).collect::<Vec<_>>().join(", ")
            };
            emitter.emit(&format!(
                "\n{}  {}: {} | {}: {} | {}: {}s | {}: {}\n\n",
                msg.burst_title,
                msg.targets_label,
                burst.targets.len(),
                msg.burst_attempts_label,
                settings.attempts,
                msg.timeout_label,
                settings.timeout.as_secs(),
                msg.burst_field_profiles.trim_end_matches(':'),
                profile_label,
            ));
        }
        let spinner = (!args.json).then(|| Spinner::start(msg.burst_title));
        // Profile-major: `burst_targets` probes every target with the first
        // shape to the end before the next shape starts, so a block one shape
        // triggers can never be read as the other's result. The simultaneity the
        // test measures is *within* a host (its N handshakes all leave together);
        // hosts inside one shape overlap like any other phase of the suite.
        let targets: Vec<BurstTarget> = burst.targets.iter().map(BurstTarget::new).collect();
        let reports = burst_targets(cfg, &targets, settings, concurrency).await;
        if let Some(spinner) = spinner {
            spinner.finish();
        }

        let answered: usize = reports.iter().map(|r| r.answered()).sum();
        let total: usize = reports.iter().map(|r| r.total()).sum();
        let lossy = reports.iter().filter(|r| r.has_losses()).count();
        burst_summary = Some((answered, total, lossy));

        if !args.json {
            emitter.emit(&render_burst_table(&reports, settings, msg));
        } else {
            let domains_json: Vec<serde_json::Value> = reports
                .iter()
                .map(|report| {
                    let profiles: serde_json::Map<String, serde_json::Value> = report
                        .profiles
                        .iter()
                        .map(|profile| {
                            let failed = profile.attempts.iter().find(|a| !a.status.is_ok_status());
                            (
                                profile.fingerprint.code().to_string(),
                                json!({
                                    "answered": profile.answered(),
                                    "attempts": profile.attempts.len(),
                                    "statuses": profile.attempts.iter().map(|a| a.status.as_str()).collect::<Vec<_>>(),
                                    "detail": failed.map(|a| a.detail.clone()).unwrap_or_default(),
                                }),
                            )
                        })
                        .collect();
                    json!({
                        "domain": report.domain,
                        "resolved": report.resolved.map(|ip| ip.to_string()),
                        "profiles": profiles,
                    })
                })
                .collect();
            json_results.insert(
                "fingerprint_burst".to_string(),
                json!({
                    "attempts": settings.attempts,
                    "timeout_secs": settings.timeout.as_secs(),
                    "profiles": settings.profiles.iter().map(|f| f.code()).collect::<Vec<_>>(),
                    "domains": domains_json,
                }),
            );
        }
    }

    // ── Test 6: legend ──
    if run_legend && !args.json {
        print_out(&legend_text(lang, msg));
    }

    // ── Summary ──
    if !args.json {
        let summary = render_summary(
            &SummaryData {
                run_dns,
                dns: dns_stats.as_ref(),
                domains: dom_stats.as_ref(),
                tcp: tcp_summary,
                burst: burst_summary,
                run_telegram: run_tg,
                telegram: tg_full.as_ref(),
            },
            msg,
        );
        if !summary.is_empty() {
            emitter.emit(&summary);
        }
    }

    if args.json {
        let payload = json!({
            "schema_version": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "profile": profile.code(),
            "tls_fingerprint": cfg.fingerprint().code(),
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

    #[test]
    fn test_cdn_detail_keeps_the_time_only_when_there_is_no_error() {
        use dpi_core::classify::{
            DET_AT_KB_MARKER, DET_KB_SUFFIX, DET_TCP_ABORTED, DET_TCP_SYN_TIMEOUT, DET_TLS_HANDSHAKE_TIMEOUT,
        };
        // Clean pass: the row is the duration.
        assert_eq!(tcp16_detail(String::new(), 3.25), "3.2s");
        // Drop/RST/timeout: the classifier detail stands alone, the KB offset it
        // carries included, and no `| 12.5s` is glued to it.
        let killed = format!("{DET_TCP_ABORTED}{DET_AT_KB_MARKER}16{DET_KB_SUFFIX}");
        assert_eq!(tcp16_detail(killed.clone(), 12.5), killed);
        assert_eq!(tcp16_detail(DET_TCP_SYN_TIMEOUT.to_string(), 5.0), DET_TCP_SYN_TIMEOUT);
        assert_eq!(
            tcp16_detail(DET_TLS_HANDSHAKE_TIMEOUT.to_string(), 8.4),
            DET_TLS_HANDSHAKE_TIMEOUT
        );
    }

    /// Mirrors Python `tests/test_helpers.py::test_selection_flags`.
    #[test]
    fn test_selection_flags() {
        let (run_net, run_dns, run_dom, run_tcp, run_wl, run_tg, run_burst, run_leg, only_leg) =
            selection_flags("123");
        assert!(!run_net);
        assert!(run_dns);
        assert!(run_dom);
        assert!(run_tcp);
        assert!(!run_wl);
        assert!(!run_tg);
        assert!(!run_burst);
        assert!(!run_leg);
        assert!(!only_leg);

        let (_, _, _, _, _, _, run_burst, run_leg, only_leg) = selection_flags("67");
        assert!(run_burst);
        assert!(run_leg);
        assert!(!only_leg);

        let (_, _, _, _, _, _, _, run_leg, only_leg) = selection_flags("6");
        assert!(run_leg);
        assert!(only_leg);

        let (run_net, _, _, _, _, _, _, run_leg, only_leg) = selection_flags("06");
        assert!(run_net);
        assert!(run_leg);
        assert!(!only_leg);
    }

    #[test]
    fn test_selection_flags_with_commas_and_spaces() {
        let raw = "1, 2, 3";
        let normalized: String = raw.chars().filter(|c| ('0'..='7').contains(c)).collect();
        let (run_net, run_dns, run_dom, run_tcp, _, _, _, _, _) = selection_flags(&normalized);
        assert!(!run_net);
        assert!(run_dns);
        assert!(run_dom);
        assert!(run_tcp);
    }

    #[test]
    fn test_normalize_key_char() {
        // Fullwidth letters to ASCII (Chinese / Japanese / Korean IME)
        assert_eq!(normalize_key_char('ｑ'), 'q');
        assert_eq!(normalize_key_char('Ｑ'), 'Q');
        assert_eq!(normalize_key_char('ｗ'), 'w');
        assert_eq!(normalize_key_char('ｓ'), 's');
        assert_eq!(normalize_key_char('ａ'), 'a');
        assert_eq!(normalize_key_char('ｄ'), 'd');
        assert_eq!(normalize_key_char('ｒ'), 'r');
        assert_eq!(normalize_key_char('ｍ'), 'm');

        // Fullwidth digits to ASCII
        assert_eq!(normalize_key_char('０'), '0');
        assert_eq!(normalize_key_char('１'), '1');
        assert_eq!(normalize_key_char('２'), '2');
        assert_eq!(normalize_key_char('６'), '6');

        // Fullwidth space
        assert_eq!(normalize_key_char('\u{3000}'), ' ');

        // Standard characters preserved
        assert_eq!(normalize_key_char('q'), 'q');
        assert_eq!(normalize_key_char('й'), 'й');
        assert_eq!(normalize_key_char('ض'), 'ض');
    }
}

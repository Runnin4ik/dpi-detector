use std::io::{stdout, IsTerminal, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use dpi_core::config::{
    base_dir, clean_domain, default_tcp16_targets, embedded_domains, embedded_tcp16_targets,
    embedded_whitelist_sni, load_config, load_domains_from_file, load_tcp16_targets_from_file,
    load_whitelist_sni, resource_path,
};
use dpi_core::i18n::{get_messages, legend_text, Language};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::version::{fetch_latest_version, version_badge_lang};
use dpi_core::profile::RegionProfile;

mod args;
mod menu;
mod render;
mod runner;
mod terminal;

use menu::{
    burst_settings_menu, export_report, legend_loop, menu_until_something_to_run,
    read_post_test_action, run_interactive_menu, tui_available, MenuAction, MenuResult,
    PostTestAction, VersionSlot,
};
use runner::{burst_plan_from_cli, burst_targets_after_screen, mask_proxy, run_test_suite};
use render::{
    asc, clean_output, output_str, plain_mode, render_banner, render_fingerprint_header, set_ascii_mode,
    set_has_vt, set_plain_mode, strip_ansi,
};
/// Splits a test selection string into per-test flags (mirrors `_selection_flags`).
/// Tests: 0 netinfo, 1 DNS, 2 domains, 3 TCP, 4 white-SNI, 5 Telegram,
/// 6 fingerprint/burst, 7 legend.
pub(crate) fn selection_flags(selection: &str) -> (bool, bool, bool, bool, bool, bool, bool, bool, bool) {
    let has = |c: char| selection.contains(c);
    let net = has('0');
    let dns = has('1');
    let dom = has('2');
    let tcp = has('3');
    let sni = has('4');
    let tg = has('5');
    let burst = has('6');
    let legend = has('7');
    let only_legend = legend && !(net || dns || dom || tcp || sni || tg || burst);
    (net, dns, dom, tcp, sni, tg, burst, legend, only_legend)
}

/// Cell of the CDN (16 KB) table's detail column. An empty probe detail is a
/// clean 20 KB pass, so the row carries only its duration; every other detail is
/// a drop/RST/timeout diagnosis and stands alone — a duration glued to an error
/// reads as if the timing were part of the verdict.
pub(crate) fn tcp16_detail(detail: String, elapsed: f64) -> String {
    if detail.is_empty() {
        format!("{:.1}s", elapsed)
    } else {
        detail
    }
}
pub(crate) fn print_out(s: &str) {
    output_str(&clean_output(s));
}

pub(crate) fn println_out(s: &str) {
    let mut text = clean_output(s);
    text.push_str("\r\n");
    output_str(&text);
}
pub(crate) struct Emitter {
    pub(crate) report: String,
    pub(crate) json_mode: bool,
}
impl Emitter {
    pub(crate) fn emit(&mut self, s: &str) {
        if !self.json_mode {
            output_str(&clean_output(s));
        }
        self.report.push_str(&strip_ansi(s));
    }
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

/// Single-threaded runtime on purpose — see `docs/OPTIMIZATIONS.md` §2.5: one
/// thread serves the whole probe fan-out, which is what the 1–2 core routers this
/// targets can afford, it saves ~50–120 KB against `rt-multi-thread`, and the
/// crypto that runs inline (X25519, ML-KEM-768, certificate verification) is
/// bounded — `auto_gate` already downscales the concurrency to the local CPU
/// count, which is where a wide fan-out on a weak core actually hurt.
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
    let has_vt = terminal::detect_vt();
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
        // Only `-t 7`, or the menu picking the legend and nothing else, gets
        // here. The screen's menu key leads back into the menu; without a
        // terminal to answer it, the legend is the whole program.
        match legend_loop(lang, &msg) {
            MenuAction::Menu if is_interactive => {
                match menu_until_something_to_run(lang, profile, &cfg, &badge, &version_slot).await {
                    Some(chosen) => {
                        tests_str = chosen.selected_tests;
                        concurrency = chosen.concurrency;
                        ip_version = chosen.ip_version;
                        tls_fingerprint = chosen.tls_fingerprint;
                        lang = chosen.language;
                        msg = get_messages(lang);
                    }
                    None => return,
                }
            }
            _ => return,
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
    // The configured list, kept apart from what a run actually probes: the
    // settings screen shows its size as the meaning of an empty box, and an
    // empty box has to go back to it instead of reusing the host typed into a
    // previous screen session.
    let burst_defaults = burst_plan.targets.clone();
    let mut burst_domain: Option<String> = None;
    let mut result_path = args.output.clone();
    let mut selection = tests_str.clone();

    loop {
        // Test 6 is destructive for its targets, so it asks for its own settings
        // screen before it runs instead of starting with guesses: cancelling the
        // screen drops test 6 from the selection and runs the rest. The screen
        // belongs to the test itself, so an explicit `-t 6` gets it too — but
        // only on a terminal at both ends: with stdin or stdout redirected there
        // is nobody to answer the screen, and the CLI flags stand in for it.
        let settings_screen = !args.json
            && selection.contains('6')
            && std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
            && tui_available();
        if settings_screen {
            // The screen always opens with an empty field: prefilling the last
            // target made a fresh run append to it, so an edited domain looked
            // ignored. Empty means "the CLI/config list", and the count of that
            // list is printed under the field.
            match burst_settings_menu(
                lang,
                &burst_plan.settings,
                burst_defaults.len(),
                burst_domain.as_deref(),
            )
            .await
            {
                Some(choice) => {
                    burst_plan.settings = choice.settings;
                    burst_domain = choice.domain;
                    burst_plan.targets =
                        burst_targets_after_screen(&burst_defaults, burst_domain.as_deref());
                }
                None => {
                    selection = selection.replace('6', "");
                    if selection.is_empty() {
                        // Test 6 was the only selection and its settings were
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
                    match menu_until_something_to_run(lang, profile, &cfg, &badge, &version_slot).await {
                        Some(chosen) => {
                            selection = chosen.selected_tests;
                            concurrency = chosen.concurrency;
                            cfg.ip_version = chosen.ip_version.clone();
                            cfg.tls_fingerprint = chosen.tls_fingerprint.code().to_string();
                            lang = chosen.language;
                            msg = get_messages(lang);
                        }
                        None => return,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::CliArgs;

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

    /// `-d` reaches test 6 through the same cleaner as everything else: a pasted
    /// URL probes its host, and an input that cleans to nothing keeps the
    /// configured list instead of firing at no target.
    #[test]
    fn cli_targets_are_cleaned_like_every_other_domain() {
        let msg = get_messages(Language::En);
        let configured = vec!["www.google.com".to_string()];
        let plan = |domain: Vec<&str>| {
            let args = CliArgs {
                domain: domain.into_iter().map(str::to_string).collect(),
                ..CliArgs::default()
            };
            burst_plan_from_cli(&args, &configured, &msg).targets
        };
        assert_eq!(plan(vec!["https://info.paymaster.ru/x?y=1"]), vec!["info.paymaster.ru"]);
        assert_eq!(plan(vec!["ELY.BY"]), vec!["ely.by"]);
        assert_eq!(plan(vec!["  "]), configured);
        assert_eq!(plan(vec![]), configured);
    }

    /// An empty domain box means the configured list. It used to keep the host a
    /// previous screen session stored, so a run probed `ely.by` while the box it
    /// was answered from looked empty.
    #[test]
    fn empty_domain_box_goes_back_to_the_configured_list() {
        let defaults = vec!["www.google.com".to_string(), "ely.by".to_string()];
        assert_eq!(
            burst_targets_after_screen(&defaults, Some("ely.by")),
            vec!["ely.by".to_string()]
        );
        assert_eq!(burst_targets_after_screen(&defaults, None), defaults);
        assert_eq!(
            burst_targets_after_screen(&defaults, Some("example.com")),
            vec!["example.com".to_string()]
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

        // The legend is test 7 now, and the fingerprint burst test 6.
        let (_, _, _, _, _, _, run_burst, run_leg, only_leg) = selection_flags("6");
        assert!(run_burst);
        assert!(!run_leg);
        assert!(!only_leg);

        let (_, _, _, _, _, _, _, run_leg, only_leg) = selection_flags("7");
        assert!(run_leg);
        assert!(only_leg);

        let (run_net, _, _, _, _, _, _, run_leg, only_leg) = selection_flags("07");
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

}
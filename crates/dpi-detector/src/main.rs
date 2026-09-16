use std::io::{stdout, IsTerminal, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use dpi_core::config::{
    base_dir, load_config,
};
use crate::i18n::{get_messages, legend_text, Language};
use dpi_core::net::fingerprint::TlsFingerprint;
use crate::update::{fetch_latest_version, version_badge_lang};
use dpi_core::profile::RegionProfile;

mod args;
mod i18n;
mod json;
mod menu;
mod render;
mod runner;
mod terminal;
mod tui;
mod update;
mod views;

use dpi_core::classify::Detail;
use menu::{
    burst_settings_menu, export_report, legend_loop, menu_until_something_to_run,
    read_post_test_action, run_interactive_menu, tui_available, MenuAction,
    MenuResult, PostTestAction, VersionSlot,
};
use runner::{
    burst_plan_from_cli, burst_targets_after_screen, load_burst_domains, load_domains,
    load_tcp16_targets, load_whitelist_sni_list, mask_proxy, run_test_suite,
};
use render::{
    asc, clean_output, output_str, plain_mode, render_banner, render_fingerprint_header,
    set_ascii_mode, set_has_vt, set_plain_mode, strip_ansi,
};
use dpi_core::dns::resolve_host;
use dpi_core::net::netinfo::{nfqws2, Family, Intercept};

/// Which tests a run turns on, parsed from the selection string (digits 0–7).
///
/// Named fields on purpose: the tuple this replaced had nine `bool`s, and swapping
/// two of them at a call site compiled silently. Test digits: 0 netinfo, 1 DNS,
/// 2 domains, 3 TCP, 4 white-SNI, 5 Telegram, 6 fingerprint/burst, 7 legend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TestSelection {
    pub net: bool,
    pub dns: bool,
    pub domains: bool,
    pub tcp: bool,
    pub sni: bool,
    pub telegram: bool,
    pub burst: bool,
    pub legend: bool,
    /// Only the legend was asked for: the run prints the legend and nothing else.
    pub only_legend: bool,
}

impl TestSelection {
    pub(crate) fn parse(selection: &str) -> Self {
        let has = |c: char| selection.contains(c);
        let mut sel = Self {
            net: has('0'),
            dns: has('1'),
            domains: has('2'),
            tcp: has('3'),
            sni: has('4'),
            telegram: has('5'),
            burst: has('6'),
            legend: has('7'),
            only_legend: false,
        };
        sel.only_legend = sel.legend
            && !(sel.net || sel.dns || sel.domains || sel.tcp || sel.sni || sel.telegram || sel.burst);
        sel
    }
}

pub(crate) fn tcp16_detail(detail: Detail, elapsed: f64) -> Detail {
    if detail.is_none() {
        Detail::Elapsed(elapsed)
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

/// A bypass probe per address family: the package covers IPv4 and IPv6 with
/// separate rules, so the answer can differ between them.
#[derive(Debug, Clone, Default)]
struct Intercepts {
    v4: Option<Intercept>,
    v6: Option<Intercept>,
}

/// Shared slot for the background interception probe: None = pending.
type InterceptSlot = Arc<Mutex<Option<Intercepts>>>;

/// Runs the probe for one family. A missing target is not fatal: the verdict
/// then rests on the package's configuration alone, which is the half that says
/// whether that family is covered at all — an IPv6 run of a domain with no AAAA
/// record is exactly that case.
async fn probe_family(family: Family, target: Option<SocketAddr>) -> Option<Intercept> {
    nfqws2(family, target).await
}

/// The probe result for the family this run will use (`ip_version`).
fn intercept_for(slot: &InterceptSlot, ip_version: &str) -> Option<Intercept> {
    let guard = slot.lock().ok()?;
    let found = guard.as_ref()?;
    if ip_version == "ipv6" {
        found.v6.clone()
    } else {
        found.v4.clone()
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

    // Validators: an invalid flag prints its message and exits with status 2.
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

    // Domains / TCP targets / whitelist, loaded from the CLI args and the config.
    let domains = load_domains(&args, &cfg, profile);
    let tcp_items = load_tcp16_targets(&args, &cfg);
    let whitelist_sni = load_whitelist_sni_list(&cfg);
    // Test 4 is unavailable without an SNI list, so warn when the list is empty.
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

    // Background version check (4 s budget), spawned so the header does not wait on it.
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

    // Background interception probe, on the version check's own budget: it
    // answers whether the bypass on this device takes *our* traffic, and the
    // header must not wait on it either. Both families are probed — the menu
    // picks the run's family after this, and the package covers v4 and v6
    // separately.
    let intercept_slot: InterceptSlot = Arc::new(Mutex::new(None));
    {
        let slot = Arc::clone(&intercept_slot);
        let domain = args
            .domain
            .first()
            .cloned()
            .or_else(|| dpi_core::config::embedded_burst_domains().into_iter().next());
        tokio::spawn(async move {
            // The probe needs an address, not a name: resolution is the binary's
            // business, since `net/` never reaches into `dns/`.
            let addrs = match domain {
                Some(domain) => resolve_host(&domain, 443, Duration::from_secs(3)).await.ok(),
                None => None,
            };
            let target = |v6: bool| {
                addrs
                    .iter()
                    .flatten()
                    .copied()
                    .find(|addr| addr.is_ipv6() == v6)
            };
            let (v4, v6) = tokio::join!(
                probe_family(Family::V4, target(false)),
                probe_family(Family::V6, target(true))
            );
            if let Ok(mut guard) = slot.lock() {
                *guard = Some(Intercepts { v4, v6 });
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
            let versions_ready = slot.lock().map(|g| g.is_some()).unwrap_or(true);
            let intercept_ready = intercept_slot.lock().map(|g| g.is_some()).unwrap_or(true);
            if versions_ready && intercept_ready {
                break;
            }
            tokio::select! {
                biased;
                _ = &mut deadline => break,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        if let Ok(g) = version_slot.lock() {
            if let Some(latest) = &*g {
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

    // Non-interactive runs print the banner first, then the config line.
    if !args.json && !banner_done {
        print_out(&render_banner(&msg, profile, &badge));
        banner_done = true;
    }

    // Selection info line: IP version and concurrency, dim label with cyan value.
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
    let only_legend = TestSelection::parse(&tests_str).only_legend;
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

    // Test 6 fires at its own shipped hosts: the two tests ask opposite questions
    // of a domain, and a site that is already blocked cannot tell whether the
    // connecting is what broke it.
    let burst_plan_domains = load_burst_domains(&args, profile);
    let mut burst_plan = burst_plan_from_cli(&args, &burst_plan_domains, &msg);
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
        run_test_suite(
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
            intercept_for(&intercept_slot, &ip_version).as_ref(),
            banner_done,
            &mut emitter,
        )
        .await;
        banner_done = true;

        if !args.json {
            if let Some(ref out_path) = result_path {
                export_report(out_path, &emitter.report, &msg);
            }
        }

        if !is_interactive {
            break;
        }

        // Post-test actions: dim rules at full console width, no panel title or
        // side borders, white-on-color keycaps.
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
    use dpi_core::config::AppConfig;

    #[test]
    fn test_cdn_detail_keeps_the_time_only_when_there_is_no_error() {
        use dpi_core::classify::Detail;
        // Clean pass: the row is the duration.
        assert_eq!(tcp16_detail(Detail::None, 3.25), Detail::Elapsed(3.25));
        // Drop/RST/timeout: the classifier detail stands alone, the KB offset it
        // carries included, and no `| 12.5s` is glued to it.
        let killed = Detail::at_kb(Detail::TcpAborted, 16.0);
        assert_eq!(tcp16_detail(killed.clone(), 12.5), killed);
        assert_eq!(tcp16_detail(Detail::TcpSynTimeout, 5.0), Detail::TcpSynTimeout);
        assert_eq!(
            tcp16_detail(Detail::TlsHandshakeTimeout, 8.4),
            Detail::TlsHandshakeTimeout
        );
    }

    /// Test 6 must not inherit test 2's list. A `domains.txt` next to the binary
    /// is the censored-sites list, and that is the one thing test 6 cannot be
    /// fired at: a blocked host fails every attempt for a reason the test does
    /// not measure, so a run at those hosts would blame the connecting for a
    /// block that was always there.
    #[test]
    fn burst_targets_come_from_their_own_list() {
        let args = CliArgs::default();
        let burst = load_burst_domains(&args, RegionProfile::Ru);
        assert!(burst.contains(&"reg.ru".to_string()), "{burst:?}");
        assert!(burst.contains(&"info.paymaster.ru".to_string()), "{burst:?}");
        let shared = load_domains(&args, &AppConfig::default(), RegionProfile::Ru);
        assert!(!burst.is_empty() && !shared.is_empty());
        assert!(!burst.iter().any(|d| shared.contains(d)), "the two lists ask different questions");
        // `-d` still picks the hosts for a run, and picks them for this test too.
        let picked = CliArgs {
            domain: vec!["https://info.paymaster.ru/x?y=1".to_string()],
            ..CliArgs::default()
        };
        assert_eq!(load_burst_domains(&picked, RegionProfile::Ru), vec!["info.paymaster.ru"]);
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

    /// Test digits map to per-test flags: "123" runs DNS, domains and TCP, while
    /// "7" alone is a legend-only run.
    #[test]
    fn test_selection_flags() {
        let sel = TestSelection::parse("123");
        assert_eq!(
            sel,
            TestSelection { dns: true, domains: true, tcp: true, ..Default::default() }
        );

        let sel = TestSelection::parse("67");
        assert!(sel.burst && sel.legend && !sel.only_legend);

        // The legend is test 7 now, and the fingerprint burst test 6.
        let sel = TestSelection::parse("6");
        assert!(sel.burst && !sel.legend && !sel.only_legend);

        let sel = TestSelection::parse("7");
        assert!(sel.legend && sel.only_legend);

        let sel = TestSelection::parse("07");
        assert!(sel.net && sel.legend && !sel.only_legend);
    }

    #[test]
    fn test_selection_flags_with_commas_and_spaces() {
        let raw = "1, 2, 3";
        let normalized: String = raw.chars().filter(|c| ('0'..='7').contains(c)).collect();
        let sel = TestSelection::parse(&normalized);
        assert_eq!(
            sel,
            TestSelection { dns: true, domains: true, tcp: true, ..Default::default() }
        );
    }

}
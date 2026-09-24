use std::io::{self, stdout, IsTerminal, Write};
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
mod tui;
mod update;
mod views;

use dpi_core::classify::Detail;
use menu::{
    apply_interface, burst_settings_menu, export_report, legend_loop, menu_until_something_to_run,
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

/// Operator-facing text under `--json`: stdout carries the machine-readable
/// document, and nothing else may reach it (`.omp/rules/stdout-is-machine-channel.md`),
/// so a config diagnostic or the legend goes to stderr instead. Escape codes are
/// stripped on the way — stderr has no Win32 console translation behind it, and
/// what reads it is a log.
fn diagnostic_to_stderr(text: &str) {
    eprintln!("{}", strip_ansi(&clean_output(text)));
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

/// A target list the run was pointed at, or a stop.
///
/// A list the user named is the run's input, not a preference: `--domains
/// /typo.txt` used to reach the tables as an empty set, so a run that measured
/// nothing printed a report of nothing and exited zero, and `--tcp16 /typo.json`
/// used to fire at the shipped hosts instead. Same shape as the `--iface`
/// validator — message, then exit code 2.
fn targets_or_exit<T>(loaded: io::Result<Vec<T>>, notice: &str) -> Vec<T> {
    match loaded {
        Ok(targets) => targets,
        Err(err) => {
            eprintln!("{}", notice.replacen("{}", &err.to_string(), 1));
            std::process::exit(2);
        }
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

/// How many worker threads the runtime gets, or `None` for tokio's own default.
///
/// Two on the router targets, which is where it was measured
/// (`docs/OPTIMIZATIONS.md` §2.5): there the CPU work (X25519, ML-KEM-768,
/// certificate verification) is serialized behind one executor, two threads take
/// the whole gain on the burst test and most of it elsewhere, and four take
/// nothing further while costing a peak of ~3.9 cores out of 4 — the half of a
/// router that has to keep routing. Which targets those are is decided by the
/// build, through `--cfg dpi_router` on the four router rows of the release
/// matrix, not inferred from the target: `target_env = "musl"` would also catch
/// `x86_64-unknown-linux-musl`, the desktop artifact, and a router is a role, not
/// a libc.
///
/// A desktop is not that machine. The same code there is network-bound — measured
/// on a 12-thread box, tests run at 1–9% of a single core — so it gets tokio's
/// default, one worker per core, which is what "use as many as it needs" means
/// for a workload whose bottleneck is the network.
///
/// `DPI_WORKERS` overrides both, for measuring and for anyone who knows better.
/// A value that cannot be a worker count is ignored rather than fatal: this runs
/// before `run()` installs the panic hook, so a bad one would otherwise end the
/// process with nothing on screen but tokio's own message.
fn worker_threads() -> Option<usize> {
    if let Some(n) = std::env::var("DPI_WORKERS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        return Some(n.min(threads_ceiling()));
    }
    // tokio reads `TOKIO_WORKER_THREADS` itself when the builder says nothing.
    // Setting a count here would overrule it in silence, and only on the router
    // targets, where this branch is the one that runs.
    if std::env::var_os("TOKIO_WORKER_THREADS").is_none() && cfg!(dpi_router) {
        return Some(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .min(2),
        );
    }
    None
}

/// The most workers `DPI_WORKERS` may ask for: four per core, well above the
/// measured optimum and well below the count the OS refuses to spawn — a value
/// past that fails inside tokio's `build()`, where nothing of ours is watching.
fn threads_ceiling() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .saturating_mul(4)
}

fn main() {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(workers) = worker_threads() {
        builder.worker_threads(workers);
    }
    let runtime = builder
        .build()
        .expect("the runtime is built from a fixed configuration and a checked thread count");
    runtime.block_on(run());
}

async fn run() {
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
    let has_vt = tui::backend::detect_vt();
    set_has_vt(has_vt);
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let legacy_console = !has_vt || args.ascii;
    set_ascii_mode(legacy_console);
    #[cfg(windows)]
    let plain = no_color || !std::io::stdout().is_terminal();
    #[cfg(not(windows))]
    let plain = legacy_console || no_color;
    set_plain_mode(plain);
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
    // A `--profile` that matches nothing used to pick the default region in
    // silence, and the region is not cosmetic: it names the target lists a run
    // falls back to and it is the `profile` field of the `--json` document, so a
    // typo measured the wrong hosts and reported the wrong region. Reported the
    // way an unknown `--lang`/`--fingerprint` is — the same kind of recoverable
    // value: the default stands and the operator is told. stderr in every mode,
    // `--json` included: stdout is the document, and a consumer cannot tell a
    // rejected flag from a correct one. `warn_unknown_flag_value` is the tree's
    // generic "unknown flag value" wording (three `{}`: flag, value, what is used
    // instead), already shared by the test 6 axis flags.
    let profile = match RegionProfile::from_code(&args.profile) {
        Some(profile) => profile,
        None => {
            eprintln!(
                "{}",
                msg.warn_unknown_flag_value
                    .replacen("{}", "--profile", 1)
                    .replacen("{}", &args.profile, 1)
                    .replacen("{}", RegionProfile::default().code(), 1)
            );
            RegionProfile::default()
        }
    };

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
    // Which interface the probes leave through. A name that matches nothing is
    // fatal: carrying on would test the routing table while the user believes the
    // tunnel is being tested, and that is a wrong answer rather than a warning.
    if let Some(sel) = &args.iface {
        match dpi_core::net::bind::resolve(sel) {
            Some(target) => dpi_core::net::bind::set_target(Some(target)),
            None => {
                eprintln!("{}", msg.iface_unknown.replacen("{}", sel, 1));
                std::process::exit(2);
            }
        }
    }


    let level = if args.verbose {
        tracing_subscriber::filter::LevelFilter::DEBUG
    } else {
        tracing_subscriber::filter::LevelFilter::WARN
    };
    // Logs go to stderr, never to stdout: stdout carries the machine-readable
    // `--json` document, which a consumer pipes straight into a parser. The
    // human output below is already gated on `json_mode` (`print_out`,
    // `Emitter::emit`); the subscriber was the one path around that gate, and
    // `-v` turns on DEBUG for the whole dependency graph, so its lines are
    // both numerous and not ours.
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .try_init();

    // Domains / TCP targets / whitelist, loaded from the CLI args and the config.
    let domains = targets_or_exit(load_domains(&args, &cfg, profile, &msg), msg.domains_load_failed);
    let tcp_items = targets_or_exit(load_tcp16_targets(&args, &cfg), msg.tcp16_load_failed);
    let whitelist_sni = load_whitelist_sni_list(&cfg, &msg);
    // Test 4 is unavailable without an SNI list, so warn when the list is empty.
    if whitelist_sni.is_empty() && !args.json {
        print_out(&format!("\x1b[33m{}\x1b[0m", msg.whitelist_skipped));
    }

    // A config error or warning is operator text, like the legend below: under
    // `--json` it goes to stderr, so a consumer's parser sees the document alone.
    if let Some(e) = &cfg.config_load_error {
        let line = format!("\x1b[1;33m{}\x1b[0m {}", msg.config_load_error_label, e);
        if args.json {
            diagnostic_to_stderr(&line);
        } else {
            println_out(&line);
        }
    }
    for w in &cfg.config_warnings {
        let line = format!(
            "\x1b[33m{}\x1b[0m {}",
            msg.config_warning_label,
            msg.config_warning(w)
        );
        if args.json {
            diagnostic_to_stderr(&line);
        } else {
            println_out(&line);
        }
    }

    if args.legend {
        let legend = legend_text(lang, &msg);
        if args.json {
            diagnostic_to_stderr(&legend);
        } else {
            print_out(&legend);
        }
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
                // The row is what the user just chose, so it has the last word
                // over `--iface`; `None` means the routing table and clears any
                // target the flag had set. Before the fields move out of `sel`.
                apply_interface(&sel);
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
        // terminal to answer it, the legend is the whole program. That loop
        // writes the legend to stdout, which `--json` has spoken for: there the
        // legend goes to the diagnostic channel and the run stops where the loop
        // would have started.
        if args.json {
            diagnostic_to_stderr(&legend_text(lang, &msg));
            return;
        }
        match legend_loop(lang, &msg) {
            MenuAction::Menu if is_interactive => {
                match menu_until_something_to_run(lang, profile, &cfg, &badge, &version_slot).await {
                    Some(chosen) => {
                        apply_interface(&chosen);
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
        // The refusal and its hint are operator text too: under `--json` they go
        // to stderr rather than into the document's stream.
        let error = format!("\x1b[31m{}\x1b[0m", msg.ipv6_not_configured);
        let hint = format!("\x1b[2m{}\x1b[0m", msg.ipv6_switch_hint);
        if args.json {
            diagnostic_to_stderr(&error);
            diagnostic_to_stderr(&hint);
        } else {
            println_out(&error);
            println_out(&hint);
        }
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
    let burst_plan_domains = targets_or_exit(load_burst_domains(&args, profile, &msg), msg.domains_load_failed);
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
                            // Everything the first menu applies, in the same shape:
                            // the run reads the local `ip_version` while the core
                            // reads `cfg`, so a site that updates one and not the
                            // other leaves that setting on whatever the first trip
                            // chose. The interface (process-wide) and the IP version
                            // were the two that did.
                            apply_interface(&chosen);
                            selection = chosen.selected_tests;
                            concurrency = chosen.concurrency;
                            ip_version = chosen.ip_version.clone();
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
        let msg = get_messages(Language::En);
        let burst = load_burst_domains(&args, RegionProfile::Ru, &msg).unwrap();
        assert!(burst.contains(&"ezgame.su".to_string()), "{burst:?}");
        assert!(burst.contains(&"www.smartape.ru".to_string()), "{burst:?}");
        let shared = load_domains(&args, &AppConfig::default(), RegionProfile::Ru, &msg).unwrap();
        assert!(!burst.is_empty() && !shared.is_empty());
        assert!(!burst.iter().any(|d| shared.contains(d)), "the two lists ask different questions");
        // `-d` still picks the hosts for a run, and picks them for this test too.
        let picked = CliArgs {
            domain: vec!["https://info.paymaster.ru/x?y=1".to_string()],
            ..CliArgs::default()
        };
        assert_eq!(
            load_burst_domains(&picked, RegionProfile::Ru, &msg).unwrap(),
            vec!["info.paymaster.ru"]
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

    /// `--burst-gap` reaches the plan, which is what the firing loop reads: the
    /// flag is a value like any other knob, so zero survives (the whole round at
    /// one instant) and an out-of-range one clamps instead of spreading the
    /// round over minutes.
    #[test]
    fn the_cli_gap_flag_reaches_the_plan() {
        use dpi_core::probe::burst::{BURST_DEFAULT_LAUNCH_GAP_MS, BURST_MAX_LAUNCH_GAP_MS};

        let msg = get_messages(Language::En);
        let configured = vec!["www.google.com".to_string()];
        let gap = |asked: Option<u64>| {
            let args = CliArgs { burst_gap: asked, ..CliArgs::default() };
            burst_plan_from_cli(&args, &configured, &msg).settings.launch_gap
        };
        assert_eq!(gap(Some(0)), Duration::ZERO, "zero is a value, not the default");
        assert_eq!(gap(Some(250)), Duration::from_millis(250));
        assert_eq!(gap(None), Duration::from_millis(BURST_DEFAULT_LAUNCH_GAP_MS));
        assert_eq!(gap(Some(9999)), Duration::from_millis(BURST_MAX_LAUNCH_GAP_MS));
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
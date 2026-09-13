use std::collections::HashSet;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dpi_core::config::AppConfig;
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::probe::burst::{
    BurstAlpn, BurstSettings, BurstTlsVersion, BURST_MAX_ATTEMPTS, BURST_MAX_TIMEOUT_SECS,
    BURST_MIN_ATTEMPTS, BURST_MIN_TIMEOUT_SECS,
};
use dpi_core::i18n::{fingerprint_label, format_bidi, get_messages, Language, Messages};
use dpi_core::net::netinfo::ipv6_supported;
use dpi_core::net::version::{version_badge_lang, ReleaseInfo};
use dpi_core::profile::RegionProfile;

use crate::render::{
    asc, ascii_mode, clean_output, frame_home, frame_repaint, output_str, plain_mode, render_banner,
    strip_ansi_len, BOX_WIDTH,
};

#[derive(Debug, Clone)]
pub struct MenuSelection {
    pub selected_tests: String,
    #[allow(dead_code)]
    pub ip_version: String, // "ipv4" or "ipv6"
    pub concurrency: usize,
    pub language: Language,
    pub tls_fingerprint: TlsFingerprint,
}

pub enum MenuResult {
    Run(MenuSelection),
    Quit,
}

/// Shared slot for the background version check: None = pending.
pub type VersionSlot = Arc<Mutex<Option<Option<ReleaseInfo>>>>;

/// Probes whether this terminal supports raw mode (TUI) without visible side effects.
pub fn tui_available() -> bool {
    if enable_raw_mode().is_err() {
        return false;
    }
    let _ = disable_raw_mode();
    true
}

pub async fn run_interactive_menu(
    initial_lang: Language,
    profile: RegionProfile,
    cfg: &AppConfig,
    badge: &str,
    latest_slot: &VersionSlot,
) -> MenuResult {
    if enable_raw_mode().is_err() {
        return MenuResult::Quit;
    }
    let mut out = std::io::stdout();
    // Nothing is cleared: the frame is painted at the cursor and repainted in
    // place (`frame_home`), so everything a run printed above it stays on
    // screen and in the scrollback.
    let _ = execute!(out, crossterm::cursor::Hide);

    let result = run_menu_loop(initial_lang, profile, cfg, badge, latest_slot).await;

    let _ = execute!(out, crossterm::cursor::Show);
    let _ = disable_raw_mode();
    result
}


/// Resolves the banner badge against the background version-check slot:
/// a pending fetch keeps the initial "checking..." text, a finished fetch
/// renders the real badge (version or failure notice) instead of going stale.
fn current_badge(_initial: &str, latest_slot: &VersionSlot, lang: Language) -> String {
    let msg = get_messages(lang);
    match latest_slot.lock() {
        Ok(guard) => match &*guard {
            None => msg.checking_updates.to_string(),
            Some(maybe) => version_badge_lang(maybe.as_ref(), lang),
        },
        Err(_) => msg.checking_updates.to_string(),
    }
}

async fn run_menu_loop(
    initial_lang: Language,
    profile: RegionProfile,
    cfg: &AppConfig,
    badge: &str,
    latest_slot: &VersionSlot,
) -> MenuResult {
    let mut cursor = 0usize;
    let mut current_lang = initial_lang;
    let mut msg = get_messages(current_lang);
    let mut ip_version = cfg.ip_version.clone();
    if ip_version != "ipv4" && ip_version != "ipv6" {
        ip_version = "ipv4".to_string();
    }
    let presets = if cfg.concurrency_presets.is_empty() {
        vec![1, 5, 20, 50, 100]
    } else {
        cfg.concurrency_presets.clone()
    };
    let mut conc_idx = presets
        .iter()
        .position(|&p| p == cfg.max_concurrent)
        .unwrap_or_else(|| {
            presets.iter().position(|&p| p == 50).unwrap_or(0)
        });
    if conc_idx >= presets.len() {
        conc_idx = 0;
    }
    let mut fp_idx = TlsFingerprint::ALL
        .iter()
        .position(|&f| f == cfg.fingerprint())
        .unwrap_or(0);
    let v6_supported = ipv6_supported();

    let mut selected_tests: HashSet<char> = HashSet::new(); // empty by default, like Python

    // Paint state: a full clear+redraw several times a second flickers, so
    // repaint only on the first paint, a keypress, or a badge/row change.
    let mut last_badge = String::new();
    // Widest row of the previous frame: the next repaint pads every row to at
    // least this, so a line that shrank cannot leave glyphs behind.
    let mut prev_max = 0usize;
    // Rows the frame on screen occupies: the next repaint steps back over them
    // so the frame is redrawn where it is, not at the top of the buffer.
    let mut drawn = 0u16;
    let mut dirty = true;
    // Empty-selection warning (mirrors Python "Выберите хотя бы один тест"):
    // shown until the next keypress.
    let mut notice: Option<String> = None;
    let mut reader = EventStream::new();
    loop {
        let offset = 4;
        let test_options = get_test_options(&msg);
        let total_rows = offset + test_options.len();

        // Re-resolve every iteration, repaint only on change.
        let live_badge = current_badge(badge, latest_slot, current_lang);
        if dirty || live_badge != last_badge {
            draw_menu(
                cursor,
                current_lang,
                &ip_version,
                presets[conc_idx],
                &presets,
                TlsFingerprint::ALL[fp_idx],
                v6_supported,
                &test_options,
                &selected_tests,
                &msg,
                profile,
                &live_badge,
                notice.as_deref(),
                &mut prev_max,
                &mut drawn,
            );
            last_badge = live_badge;
            dirty = false;
        }
        let event = tokio::select! {
            maybe_event = reader.next() => {
                match maybe_event {
                    Some(Ok(ev)) => Some(ev),
                    _ => return MenuResult::Quit,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {
                None
            }
        };

        let Some(Event::Key(KeyEvent { code, modifiers, kind, .. })) = event else {
            continue;
        };
        if kind != KeyEventKind::Press {
            continue;
        }
            dirty = true;
            notice = None;
            let code = match code {
                KeyCode::Char(c) => KeyCode::Char(crate::normalize_key_char(c)),
                other => other,
            };
            if modifiers.contains(KeyModifiers::CONTROL) && (code == KeyCode::Char('c') || code == KeyCode::Char('C')) {
                return MenuResult::Quit;
            }
            match code {
                // Navigation: UP (Arrows, WASD, Vim, BackTab)
                KeyCode::Up
                | KeyCode::BackTab
                | KeyCode::Char('w')
                | KeyCode::Char('W')
                | KeyCode::Char('z')
                | KeyCode::Char('Z')
                | KeyCode::Char('ц')
                | KeyCode::Char('Ц')
                | KeyCode::Char('ص')
                | KeyCode::Char('ㄊ')
                | KeyCode::Char('k')
                | KeyCode::Char('K')
                | KeyCode::Char('л')
                | KeyCode::Char('Л') => {
                    cursor = (cursor + total_rows - 1) % total_rows;
                }

                // Navigation: DOWN (Arrows, WASD, Vim, Tab)
                KeyCode::Down
                | KeyCode::Tab
                | KeyCode::Char('s')
                | KeyCode::Char('S')
                | KeyCode::Char('ы')
                | KeyCode::Char('Ы')
                | KeyCode::Char('і')
                | KeyCode::Char('І')
                | KeyCode::Char('س')
                | KeyCode::Char('ㄋ')
                | KeyCode::Char('ד')
                | KeyCode::Char('j')
                | KeyCode::Char('J')
                | KeyCode::Char('о')
                | KeyCode::Char('О') => {
                    cursor = (cursor + 1) % total_rows;
                }

                // Navigation: LEFT / PREVIOUS (Arrows, WASD, Vim, '-')
                KeyCode::Left
                | KeyCode::Char('a')
                | KeyCode::Char('A')
                | KeyCode::Char('ф')
                | KeyCode::Char('Ф')
                | KeyCode::Char('ش')
                | KeyCode::Char('ㄇ')
                | KeyCode::Char('ש')
                | KeyCode::Char('h')
                | KeyCode::Char('H')
                | KeyCode::Char('р')
                | KeyCode::Char('Р')
                | KeyCode::Char('-')
                | KeyCode::Char('<') => {
                    if cursor == 0 {
                        let all = Language::ALL;
                        let cur_idx = all.iter().position(|&l| l == current_lang).unwrap_or(0);
                        let next_idx = (cur_idx + all.len() - 1) % all.len();
                        current_lang = all[next_idx];
                        msg = get_messages(current_lang);
                    } else if cursor == 1 {
                        if v6_supported {
                            ip_version = if ip_version == "ipv4" { "ipv6".to_string() } else { "ipv4".to_string() };
                        }
                    } else if cursor == 2 {
                        conc_idx = (conc_idx + presets.len() - 1) % presets.len();
                    } else if cursor == 3 {
                        fp_idx = (fp_idx + TlsFingerprint::ALL.len() - 1) % TlsFingerprint::ALL.len();
                    } else if cursor >= offset {
                        let t_idx = cursor - offset;
                        if t_idx < test_options.len() {
                            toggle_test(&mut selected_tests, test_options[t_idx].0);
                        }
                    }
                }

                // Navigation: RIGHT / NEXT (Arrows, WASD, Vim, '+')
                KeyCode::Right
                | KeyCode::Char('d')
                | KeyCode::Char('D')
                | KeyCode::Char('в')
                | KeyCode::Char('В')
                | KeyCode::Char('ی')
                | KeyCode::Char('ي')
                | KeyCode::Char('ㄎ')
                | KeyCode::Char('ג')
                | KeyCode::Char('l')
                | KeyCode::Char('L')
                | KeyCode::Char('д')
                | KeyCode::Char('Д')
                | KeyCode::Char('+')
                | KeyCode::Char('>') => {
                    if cursor == 0 {
                        let all = Language::ALL;
                        let cur_idx = all.iter().position(|&l| l == current_lang).unwrap_or(0);
                        let next_idx = (cur_idx + 1) % all.len();
                        current_lang = all[next_idx];
                        msg = get_messages(current_lang);
                    } else if cursor == 1 {
                        if v6_supported {
                            ip_version = if ip_version == "ipv4" { "ipv6".to_string() } else { "ipv4".to_string() };
                        }
                    } else if cursor == 2 {
                        conc_idx = (conc_idx + 1) % presets.len();
                    } else if cursor == 3 {
                        fp_idx = (fp_idx + 1) % TlsFingerprint::ALL.len();
                    } else if cursor >= offset {
                        let t_idx = cursor - offset;
                        if t_idx < test_options.len() {
                            toggle_test(&mut selected_tests, test_options[t_idx].0);
                        }
                    }
                }

                // Toggle at cursor: Space or 'x' / 'X' / 'ч' / 'Ч'
                KeyCode::Char(' ')
                | KeyCode::Char('x')
                | KeyCode::Char('X')
                | KeyCode::Char('ч')
                | KeyCode::Char('Ч') => {
                    if cursor == 0 {
                        let all = Language::ALL;
                        let cur_idx = all.iter().position(|&l| l == current_lang).unwrap_or(0);
                        let next_idx = (cur_idx + 1) % all.len();
                        current_lang = all[next_idx];
                        msg = get_messages(current_lang);
                    } else if cursor == 1 {
                        if v6_supported {
                            ip_version = if ip_version == "ipv4" { "ipv6".to_string() } else { "ipv4".to_string() };
                        }
                    } else if cursor == 2 {
                        conc_idx = (conc_idx + 1) % presets.len();
                    } else if cursor == 3 {
                        fp_idx = (fp_idx + 1) % TlsFingerprint::ALL.len();
                    } else if cursor >= offset {
                        let t_idx = cursor - offset;
                        if t_idx < test_options.len() {
                            toggle_test(&mut selected_tests, test_options[t_idx].0);
                        }
                    }
                }

                // Direct toggle by digit
                KeyCode::Char(c @ '0'..='7') => {
                    toggle_test(&mut selected_tests, c);
                }

                // Start tests: Enter or 'r' / 'R' / 'к' / 'К' (Run) or 'g' / 'G' / 'п' / 'П' (Go)
                KeyCode::Enter
                | KeyCode::Char('r')
                | KeyCode::Char('R')
                | KeyCode::Char('к')
                | KeyCode::Char('К')
                | KeyCode::Char('ر')
                | KeyCode::Char('ㄐ')
                | KeyCode::Char('g')
                | KeyCode::Char('G')
                | KeyCode::Char('п')
                | KeyCode::Char('П') => {
                    if selected_tests.is_empty() {
                        // Mirrors Python: refuse to run with no tests checked.
                        notice = Some(msg.menu_need_one.to_string());
                        continue;
                    }
                    return MenuResult::Run(MenuSelection {
                        selected_tests: sorted_selection(&selected_tests),
                        ip_version: ip_version.clone(),
                        concurrency: presets[conc_idx],
                        language: current_lang,
                        tls_fingerprint: TlsFingerprint::ALL[fp_idx],
                    });
                }

                // Quit: 'q' / 'Q' / 'й' / 'Й' / 'ض' / 'ㄆ' or Esc
                KeyCode::Char('q')
                | KeyCode::Char('Q')
                | KeyCode::Char('й')
                | KeyCode::Char('Й')
                | KeyCode::Char('ض')
                | KeyCode::Char('ㄆ')
                | KeyCode::Esc => {
                    return MenuResult::Quit;
                }
                _ => {}
            }
    }
}

fn radio_btn(selected: bool) -> &'static str {
    if ascii_mode() {
        if selected {
            "\x1b[1;32m(x)\x1b[0m"
        } else {
            "\x1b[2m( )\x1b[0m"
        }
    } else {
        if selected {
            "\x1b[1;32m●\x1b[0m"
        } else {
            "\x1b[2m○\x1b[0m"
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_menu(
    cursor: usize,
    current_lang: Language,
    ip_version: &str,
    concurrency: usize,
    presets: &[usize],
    fingerprint: TlsFingerprint,
    v6_supported: bool,
    test_options: &[(char, &str)],
    selected_tests: &HashSet<char>,
    msg: &Messages,
    profile: RegionProfile,
    badge: &str,
    notice: Option<&str>,
    prev_max: &mut usize,
    drawn: &mut u16,
) {
    let mut rows: Vec<String> = Vec::with_capacity(24);
    for row in render_banner(msg, profile, badge).split('\n') {
        rows.push(clean_output(row));
    }
    let mut lines = Vec::new();
    let offset = 4;

    // Language row
    let lang_opts = Language::ALL
        .iter()
        .map(|&l| {
            let lbl = if ascii_mode() {
                l.label_ascii().to_string()
            } else {
                format_bidi(l.label(), l)
            };
            format!("{} {}", radio_btn(l == current_lang), lbl)
        })
        .collect::<Vec<_>>()
        .join(" ");
    let lang_cursor = if cursor == 0 { "►" } else { " " };
    let lang_lbl = format!("{}:", msg.menu_language.trim_end_matches(':'));
    lines.push(format!("  {} {} {}", lang_cursor, pad_width(&lang_lbl, 16), lang_opts));

    // IP version row
    let ip_opts = if v6_supported {
        if ip_version == "ipv4" {
            format!("{} IPv4   {} IPv6", radio_btn(true), radio_btn(false))
        } else {
            format!("{} IPv4   {} IPv6", radio_btn(false), radio_btn(true))
        }
    } else {
        let word = if ascii_mode() { msg.unavailable_ascii } else { msg.unavailable };
        let unavail = format!("({})", word);
        let off_str = if ascii_mode() { "( )" } else { "○" };
        format!("{} IPv4   \x1b[2m{} IPv6 {}\x1b[0m", radio_btn(true), off_str, unavail)
    };
    let ip_cursor = if cursor == 1 { "►" } else { " " };
    let ip_lbl = format!("{}:", msg.menu_ip_version.trim_end_matches(':'));
    lines.push(format!("  {} {} {}", ip_cursor, pad_width(&ip_lbl, 16), ip_opts));

    // Concurrency row
    let conc_opts = presets
        .iter()
        .map(|&p| {
            format!("{} {}", radio_btn(p == concurrency), p)
        })
        .collect::<Vec<_>>()
        .join("   ");
    let conc_cursor = if cursor == 2 { "►" } else { " " };
    let conc_lbl = format!("{}:", msg.menu_concurrency.trim_end_matches(':'));
    lines.push(format!("  {} {} {}", conc_cursor, pad_width(&conc_lbl, 16), conc_opts));
    // Fingerprint row: only the active profile is drawn. All four names side by
    // side are wider than the box, and cycling through them is what the change
    // keys already do; the index above says more profiles exist.
    let fp_index = TlsFingerprint::ALL
        .iter()
        .position(|&f| f == fingerprint)
        .unwrap_or(0);
    let fp_opt = format!(
        "{} \x1b[2m[{}/{}]\x1b[0m",
        fingerprint_label(fingerprint, current_lang),
        fp_index + 1,
        TlsFingerprint::ALL.len()
    );
    let fp_cursor = if cursor == 3 { "►" } else { " " };
    let fp_lbl = format!("{}:", msg.fingerprint_label.trim_end_matches(':'));
    lines.push(format!("  {} {} {}", fp_cursor, pad_width(&fp_lbl, 16), fp_opt));
    lines.push(format!("  {}", "─".repeat(BOX_WIDTH - 8)));
    for (i, (digit, label)) in test_options.iter().enumerate() {
        let is_selected = selected_tests.contains(digit);
        let check_box = if is_selected {
            "\x1b[1;32m[√]\x1b[0m"
        } else {
            "\x1b[2m[ ]\x1b[0m"
        };
        let row_cursor = if cursor == i + offset { "►" } else { " " };
        let prefix = format!("  {} {} {}. ", row_cursor, check_box, digit);
        let content = format_bidi(label, current_lang);
        lines.push(format!("{}{}", prefix, content));
    }
    // Glyph-safe content first: widths are measured after replacement.
    let lines: Vec<String> = lines.into_iter().map(|l| asc(&l)).collect();

    let title_clean = format!(" {} ", asc(&format_bidi(msg.menu_title, current_lang)));
    let title_len = strip_ansi_len(&title_clean);
    let border_total = BOX_WIDTH.saturating_sub(title_len + 3);
    let (tl, tr, bl, br, hb, vb) = if ascii_mode() {
        ("┌", "┐", "└", "┘", "─", "│")
    } else {
        ("╭", "╮", "╰", "╯", "─", "│")
    };

    let top_border = format!(
        "\x1b[1;36m{}{}\x1b[1;36m{}\x1b[1;36m{}\x1b[1;36m{}\x1b[0m",
        tl, hb, title_clean, hb.repeat(border_total), tr
    );
    rows.push(clean_output(&top_border));

    for line in &lines {
        let plain_len = strip_ansi_len(line);
        let pad = BOX_WIDTH.saturating_sub(plain_len + 3);
        let row = format!("\x1b[1;36m{}\x1b[0m {}{}\x1b[1;36m{}\x1b[0m", vb, line, " ".repeat(pad), vb);
        rows.push(clean_output(&row));
    }

    let bot_border = format!("\x1b[1;36m{}{}{}\x1b[0m", bl, hb.repeat(BOX_WIDTH - 2), br);
    rows.push(clean_output(&bot_border));

    rows.push(clean_output(&asc(&hotkey_row(msg, current_lang, plain_mode()))));

    let notice_str = if let Some(n) = notice {
        clean_output(&format!("\x1b[1;33m{}\x1b[0m", format_bidi(n, current_lang)))
    } else {
        String::new()
    };
    rows.push(notice_str);

    frame_home(*drawn);
    output_str(&frame_repaint(&rows, prev_max));
    *drawn = rows.len() as u16;
}

/// Hotkey footer of the menu: each key chip followed by its label, groups
/// separated by spaces. No `│` between the groups: the glyph is East Asian
/// Ambiguous (a console with a CJK font draws it two columns wide, which the
/// width math does not know), and dropping it also keeps the longest footer -
/// the Farsi one - inside a standard 80-column console.
///
/// `plain` is passed in rather than read from the global so both branches can
/// be measured in tests.
fn hotkey_row(msg: &Messages, lang: Language, plain: bool) -> String {
    let label = |text: &str| format_bidi(text, lang);
    let (row, change, tests, start, quit) = (
        label(msg.menu_hw_row),
        label(msg.menu_hw_change),
        label(msg.menu_hw_tests),
        label(msg.menu_hw_start),
        label(msg.menu_hw_quit),
    );
    if plain {
        // Brackets delimit the key where the colored branch uses a chip; no bar
        // separators, so every glyph in the footer is ASCII outside ascii mode.
        format!("[↑↓/WS] {row} [←→/AD] {change} [0-7] {tests} [Enter] {start} [Q] {quit}")
    } else {
        // The chips carry a padding space of their own, so a single plain space
        // keeps the same visual gap while staying inside 80 columns.
        format!(
            "\x1b[1;46;37m ↑↓/WS \x1b[0m {row} \x1b[1;46;37m ←→/AD \x1b[0m {change} \x1b[1;46;37m 0-7 \x1b[0m {tests} \x1b[1;42;37m Enter \x1b[0m {start} \x1b[1;41;37m Q \x1b[0m {quit}"
        )
    }
}

fn pad_width(s: &str, target_width: usize) -> String {
    let w = strip_ansi_len(s);
    if w >= target_width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(target_width - w))
    }
}



/// Toggles a test checkbox (mirrors Python `_toggle_test`).
pub fn toggle_test(selected: &mut HashSet<char>, digit: char) {
    if !selected.remove(&digit) {
        selected.insert(digit);
    }
}

/// Sorted selection string, e.g. {'3','1'} → "13".
pub fn sorted_selection(selected: &HashSet<char>) -> String {
    let mut v: Vec<char> = selected.iter().copied().collect();
    v.sort_unstable();
    v.into_iter().collect()
}


fn get_test_options(msg: &Messages) -> [(char, &'static str); 8] {
    [
        ('0', msg.menu_test_netinfo),
        ('1', msg.menu_test_dns),
        ('2', msg.menu_test_domains),
        ('3', msg.menu_test_tcp),
        ('4', msg.menu_test_sni),
        ('5', msg.menu_test_telegram),
        ('6', msg.menu_test_burst),
        ('7', msg.menu_test_legend),
    ]
}

/// What the settings screen hands back to the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurstChoice {
    pub settings: BurstSettings,
    /// `None` = the configured domain list (the same set test 2 uses).
    pub domain: Option<String>,
}

/// Rows of the settings screen, in cursor order.
const BURST_ROW_ATTEMPTS: usize = 0;
const BURST_ROW_TIMEOUT: usize = 1;
const BURST_ROW_TLS: usize = 2;
const BURST_ROW_HTTP: usize = 3;
const BURST_ROW_DOMAIN: usize = 4;
const BURST_ROW_PROFILES: usize = 5;
/// Label column of the settings screen: wide enough for the longest label at
/// the widest language, so the values line up in one column.
const BURST_LABEL_WIDTH: usize = 24;
/// Inner cells of the domain input box (`[ ` … ` ]` is drawn around them).
const BURST_INPUT_WIDTH: usize = 34;
/// Background of the domain input box while its row is selected but not being
/// typed into, and while it is: grey reads as "a field you can open", the blue
/// as "the keyboard goes here". The text colors keep the two states apart on a
/// light console theme too. All five are the 16-colour set on purpose: the
/// legacy console translator maps exactly those to `SetConsoleTextAttribute`,
/// while a 256-colour code would leave a Windows 7/8 console with no background
/// at all.
const IDLE_BG: &str = "\x1b[100m";
const IDLE_FG: &str = "\x1b[37m";
const TYPED_FG: &str = "\x1b[97m";
const EDITING_BG: &str = "\x1b[44m";
const EDITING_FG: &str = "\x1b[97m";

/// The last `width` characters of the text: the caret sits at the end, so a long
/// host keeps its end in view rather than its beginning.
fn tail_of(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count > width {
        text.chars().skip(count - width).collect()
    } else {
        text.to_string()
    }
}

/// Test 6's own screen: how many handshakes at once, how long each may take,
/// which host, and which ClientHello profiles.
///
/// Returns `None` when the user cancels (Q/Esc/Ctrl-C): the caller then skips
/// test 6 instead of running it with guesses. The screen is only shown for an
/// interactive run; a piped `-t 6` takes the values from the CLI.
pub async fn burst_settings_menu(
    lang: Language,
    initial: &BurstSettings,
    domain_count: usize,
) -> Option<BurstChoice> {
    if enable_raw_mode().is_err() {
        return None;
    }
    let msg = get_messages(lang);
    let mut out = std::io::stdout();
    let _ = execute!(out, crossterm::cursor::Hide);
    let result = burst_settings_loop(&msg, lang, initial, domain_count).await;
    let _ = execute!(out, crossterm::cursor::Show);
    let _ = disable_raw_mode();
    result
}

async fn burst_settings_loop(
    msg: &Messages,
    lang: Language,
    initial: &BurstSettings,
    domain_count: usize,
) -> Option<BurstChoice> {
    let mut cursor = BURST_ROW_ATTEMPTS;
    let mut attempts = initial.attempts;
    let mut timeout_secs = initial.timeout.as_secs();
    let mut tls = initial.tls;
    let mut alpn = initial.alpn;
    let mut text = String::new();
    let mut editing = false;
    let mut profiles = initial.profiles.clone();
    let mut profile_index = profile_index_of(&profiles);
    let mut prev_max = 0usize;
    let mut drawn = 0u16;
    let mut reader = EventStream::new();

    loop {
        draw_burst_settings(
            msg, lang, cursor, attempts, timeout_secs, tls, alpn, &text, editing, &profiles,
            profile_index, domain_count, &mut prev_max, &mut drawn,
        );

        let Some(Ok(Event::Key(KeyEvent { code, modifiers, kind, .. }))) = reader.next().await else {
            continue;
        };
        if kind != KeyEventKind::Press {
            continue;
        }
        let code = match code {
            KeyCode::Char(c) => KeyCode::Char(crate::normalize_key_char(c)),
            other => other,
        };
        if modifiers.contains(KeyModifiers::CONTROL) && matches!(code, KeyCode::Char('c') | KeyCode::Char('C')) {
            return None;
        }
        // The domain field has two states: inactive (a grey input box) and
        // editing, entered with Right and left with Left. Only while editing are
        // the letters text — `w`/`a`/`s`/`d`/`q` are host characters there, so a
        // domain that contains one of them stays typable.
        match code {
            KeyCode::Esc => return None,
            KeyCode::Up | KeyCode::BackTab => {
                cursor = cursor.saturating_sub(1);
                editing = false;
            }
            KeyCode::Down | KeyCode::Tab => {
                cursor = (cursor + 1).min(BURST_ROW_PROFILES);
                editing = false;
            }
            KeyCode::Char('q') | KeyCode::Char('Q') if !editing => return None,
            KeyCode::Char('w') | KeyCode::Char('W') if !editing => {
                cursor = cursor.saturating_sub(1);
                editing = false;
            }
            KeyCode::Char('s') | KeyCode::Char('S') if !editing => {
                cursor = (cursor + 1).min(BURST_ROW_PROFILES);
                editing = false;
            }
            KeyCode::Enter => {
                let domain = {
                    let trimmed = text.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                };
                return Some(BurstChoice {
                    settings: BurstSettings::clamped(attempts, timeout_secs, tls, alpn, profiles),
                    domain,
                });
            }
            // Left leaves the field, and outside it steps a value down.
            KeyCode::Left if editing => editing = false,
            KeyCode::Left | KeyCode::Char('a') | KeyCode::Char('A') if !editing => match cursor {
                BURST_ROW_ATTEMPTS => attempts = attempts.saturating_sub(1).max(BURST_MIN_ATTEMPTS),
                BURST_ROW_TIMEOUT => timeout_secs = timeout_secs.saturating_sub(1).max(BURST_MIN_TIMEOUT_SECS),
                // Two-valued axes: either direction flips them.
                BURST_ROW_TLS => tls = flip_tls(tls),
                BURST_ROW_HTTP => alpn = flip_alpn(alpn),
                BURST_ROW_PROFILES => {
                    let next = profile_index.map(|i| (i + PROFILE_CHOICES - 1) % PROFILE_CHOICES).unwrap_or(0);
                    profile_index = Some(next);
                    profiles = profiles_for_index(next);
                }
                _ => {}
            },
            // Right enters the field, and outside it steps a value up.
            KeyCode::Right | KeyCode::Char('d') | KeyCode::Char('D') if !editing => match cursor {
                BURST_ROW_DOMAIN => editing = true,
                BURST_ROW_ATTEMPTS => attempts = (attempts + 1).min(BURST_MAX_ATTEMPTS),
                BURST_ROW_TIMEOUT => timeout_secs = (timeout_secs + 1).min(BURST_MAX_TIMEOUT_SECS),
                BURST_ROW_TLS => tls = flip_tls(tls),
                BURST_ROW_HTTP => alpn = flip_alpn(alpn),
                BURST_ROW_PROFILES => {
                    let next = profile_index.map(|i| (i + 1) % PROFILE_CHOICES).unwrap_or(0);
                    profile_index = Some(next);
                    profiles = profiles_for_index(next);
                }
                _ => {}
            },
            KeyCode::Backspace if editing => {
                text.pop();
            }
            KeyCode::Delete if editing => {
                text.clear();
            }
            KeyCode::Char(c) if editing => {
                // Host characters only: a pasted URL or a stray space would
                // become part of the SNI and fail the handshake for the wrong
                // reason.
                let host_char = c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']');
                if host_char && text.chars().count() < 120 {
                    text.push(c);
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_burst_settings(
    msg: &Messages,
    lang: Language,
    cursor: usize,
    attempts: usize,
    timeout_secs: u64,
    tls: BurstTlsVersion,
    alpn: BurstAlpn,
    text: &str,
    editing: bool,
    profiles: &[TlsFingerprint],
    profile_index: Option<usize>,
    domain_count: usize,
    prev_max: &mut usize,
    drawn: &mut u16,
) {
    let rows = burst_settings_rows(
        msg, lang, cursor, attempts, timeout_secs, tls, alpn, text, editing, profiles, profile_index,
        domain_count,
    );
    frame_home(*drawn);
    output_str(&frame_repaint(&rows, prev_max));
    *drawn = rows.len() as u16;
}

/// Builds the settings screen's rows, borders and footer included. Pure, so the
/// layout (a row never wider than the box, the prompt under the input box) is
/// testable without a terminal.
#[allow(clippy::too_many_arguments)]
fn burst_settings_rows(
    msg: &Messages,
    lang: Language,
    cursor: usize,
    attempts: usize,
    timeout_secs: u64,
    tls: BurstTlsVersion,
    alpn: BurstAlpn,
    text: &str,
    editing: bool,
    profiles: &[TlsFingerprint],
    profile_index: Option<usize>,
    domain_count: usize,
) -> Vec<String> {
    let label = |s: &str| format_bidi(s, lang);
    let mark = |row: usize| if cursor == row { "►" } else { " " };
    let field = |row: usize, name: &str, value: String| {
        let name = if name.is_empty() {
            String::new()
        } else {
            format!("{}:", name.trim_end_matches(':'))
        };
        format!("  {} {} {}", mark(row), pad_width(&label(&name), BURST_LABEL_WIDTH), value)
    };
    let steer = |row: usize, value: String| {
        if cursor == row {
            format!("\x1b[1;33m<\x1b[0m {} \x1b[1;33m>\x1b[0m", value)
        } else {
            format!("< {} >", value)
        }
    };

    let mut lines: Vec<String> = Vec::with_capacity(6);
    lines.push(field(BURST_ROW_ATTEMPTS, msg.burst_field_attempts, steer(BURST_ROW_ATTEMPTS, attempts.to_string())));
    lines.push(field(BURST_ROW_TIMEOUT, msg.burst_field_timeout, steer(BURST_ROW_TIMEOUT, timeout_secs.to_string())));
    // Canonical protocol tokens, never translated (rule 4).
    lines.push(field(BURST_ROW_TLS, msg.burst_field_tls, steer(BURST_ROW_TLS, tls.token().to_string())));
    lines.push(field(BURST_ROW_HTTP, msg.burst_field_http, steer(BURST_ROW_HTTP, alpn.token().to_string())));

    // Domain: an input box whose own background carries the state — dark grey
    // while the row is only selected (letters are still hotkeys), blue while it
    // is being typed into (letters become text). The brackets and the pad are
    // painted with the same background, so the box reads as one field instead of
    // a color behind some text.
    let domain_value = {
        let (background, foreground, inner, visible) = if editing {
            let shown = tail_of(text, BURST_INPUT_WIDTH - 1);
            let visible = shown.chars().count() + 1;
            (EDITING_BG, EDITING_FG, format!("{}\x1b[1;33m▏", shown), visible)
        } else if text.is_empty() {
            let placeholder = label(msg.burst_domain_placeholder);
            let visible = placeholder.chars().count();
            (IDLE_BG, IDLE_FG, placeholder, visible)
        } else {
            let shown = tail_of(text, BURST_INPUT_WIDTH);
            let visible = shown.chars().count();
            (IDLE_BG, TYPED_FG, shown, visible)
        };
        format!(
            "{}{}[ {}{} ]\x1b[0m",
            background,
            foreground,
            inner,
            " ".repeat(BURST_INPUT_WIDTH.saturating_sub(visible))
        )
    };
    lines.push(field(BURST_ROW_DOMAIN, msg.burst_field_domain, domain_value));
    // The value column of the row above, so the prompt sits under the field.
    lines.push(format!(
        "{}{}\x1b[2m{} ({})\x1b[0m",
        " ".repeat(4 + BURST_LABEL_WIDTH),
        " ",
        label(msg.burst_domain_default_hint),
        domain_count
    ));

    // Profiles cycle like the main menu's fingerprint row: one value with its
    // position, moved by the same keys.
    let profile_value = match profile_index {
        Some(index) => {
            let name = if index == 0 {
                label(msg.burst_profiles_all)
            } else {
                // Latin with the pinned version, like the table headers: the
                // cycler names the exact shape the run will use (rule 4, never
                // translated).
                TlsFingerprint::ALL[index - 1].display_label().to_string()
            };
            format!("{} \x1b[2m[{}/{}]\x1b[0m", name, index + 1, PROFILE_CHOICES)
        }
        None => profiles.iter().map(|f| f.display_label()).collect::<Vec<_>>().join(", "),
    };
    lines.push(field(BURST_ROW_PROFILES, msg.burst_field_profiles, profile_value));
    let lines: Vec<String> = lines.into_iter().map(|l| asc(&l)).collect();

    let mut rows: Vec<String> = Vec::with_capacity(12);
    let title_clean = format!(" {} ", asc(&format_bidi(msg.burst_settings_title, lang)));
    let title_len = strip_ansi_len(&title_clean);
    let border_total = BOX_WIDTH.saturating_sub(title_len + 3);
    let (tl, tr, bl, br, hb, vb) = if ascii_mode() {
        ("┌", "┐", "└", "┘", "─", "│")
    } else {
        ("╭", "╮", "╰", "╯", "─", "│")
    };
    rows.push(clean_output(&format!(
        "\x1b[1;36m{}{}\x1b[1;36m{}\x1b[1;36m{}\x1b[1;36m{}\x1b[0m",
        tl, hb, title_clean, hb.repeat(border_total), tr
    )));
    for line in &lines {
        let plain_len = strip_ansi_len(line);
        let pad = BOX_WIDTH.saturating_sub(plain_len + 3);
        rows.push(clean_output(&format!(
            "\x1b[1;36m{}\x1b[0m {}{}\x1b[1;36m{}\x1b[0m",
            vb, line, " ".repeat(pad), vb
        )));
    }
    rows.push(clean_output(&format!("\x1b[1;36m{}{}{}\x1b[0m", bl, hb.repeat(BOX_WIDTH - 2), br)));
    rows.push(clean_output(&asc(&burst_hotkey_row(msg, lang, plain_mode()))));
    rows
}

/// Either direction flips a two-valued axis.
fn flip_tls(tls: BurstTlsVersion) -> BurstTlsVersion {
    match tls {
        BurstTlsVersion::Tls13 => BurstTlsVersion::Tls12,
        BurstTlsVersion::Tls12 => BurstTlsVersion::Tls13,
    }
}

fn flip_alpn(alpn: BurstAlpn) -> BurstAlpn {
    match alpn {
        BurstAlpn::Http2 => BurstAlpn::Http11,
        BurstAlpn::Http11 => BurstAlpn::Http2,
    }
}

/// Choices of the profile cycler: `all`, then one per profile — the same shape
/// as the main menu's fingerprint row.
const PROFILE_CHOICES: usize = TlsFingerprint::ALL.len() + 1;

/// The cycler position a selection corresponds to: `Some(0)` = all, `Some(1+n)`
/// = the n-th profile alone, `None` = a combination the cycler cannot show (only
/// `--burst-profiles` can ask for one).
fn profile_index_of(profiles: &[TlsFingerprint]) -> Option<usize> {
    if profiles.len() == TlsFingerprint::ALL.len() {
        Some(0)
    } else if profiles.len() == 1 {
        TlsFingerprint::ALL.iter().position(|f| *f == profiles[0]).map(|i| i + 1)
    } else {
        None
    }
}

/// The selection a cycler position means.
fn profiles_for_index(index: usize) -> Vec<TlsFingerprint> {
    if index == 0 {
        TlsFingerprint::ALL.to_vec()
    } else {
        vec![TlsFingerprint::ALL[index - 1]]
    }
}

/// Footer of the settings screen: the same keycap style as the main menu. The
/// key legend lives here only — the screen itself carries no second copy of it.
fn burst_hotkey_row(msg: &Messages, lang: Language, plain: bool) -> String {
    let label = |text: &str| format_bidi(text, lang);
    let (row, change, start, quit) = (
        label(msg.menu_hw_row),
        label(msg.menu_hw_change),
        label(msg.menu_hw_start),
        label(msg.menu_hw_quit),
    );
    if plain {
        format!("[↑↓/WS] {row} [←→/AD] {change} [Enter] {start} [Q] {quit}")
    } else {
        format!(
            "\x1b[1;46;37m ↑↓/WS \x1b[0m {row} \x1b[1;46;37m ←→/AD \x1b[0m {change} \x1b[1;42;37m Enter \x1b[0m {start} \x1b[1;41;37m Q \x1b[0m {quit}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::{asc_with, strip_ansi};

    /// The settings screen is a fixed-width box: every row must be exactly the
    /// box width, an inactive empty field prompts how to start typing, and the
    /// default it falls back to is printed on the line under it, in the value
    /// column of the row above.
    #[test]
    fn burst_settings_rows_align_and_prompt() {
        let msg = get_messages(Language::Ru);
        let all = TlsFingerprint::ALL.to_vec();

        let empty = burst_settings_rows(&msg, Language::Ru, 4, 4, 8, BurstTlsVersion::Tls13, BurstAlpn::Http2, "", false, &all, Some(0), 35);
        // The last row is the footer, which lives outside the box.
        for row in empty.iter().take(empty.len() - 1) {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        // Text is asserted without its styling: the escapes sit between words.
        let joined = strip_ansi(&empty.join("\n"));
        assert!(joined.contains("Переключитесь для ввода"), "{joined}");
        assert!(joined.contains("По умолчанию — все домены (35)"), "{joined}");
        assert!(joined.contains("все [1/5]"), "{joined}");

        // Measured without styling: an escape contains '[' and would be mistaken
        // for the input box.
        let field_row = strip_ansi(empty.iter().find(|r| r.contains("Переключитесь")).expect("field row"));
        let hint_row = strip_ansi(empty.iter().find(|r| r.contains("По умолчанию")).expect("hint row"));
        // Column, not byte offset: the box border and the labels are multi-byte.
        let field_col = strip_ansi_len(&field_row[..field_row.find('[').expect("input box")]);
        let hint_col = strip_ansi_len(&hint_row[..hint_row.find("По").expect("prompt")]);
        assert_eq!(field_col, hint_col, "prompt must sit under the field");

        // Typing replaces the prompt; the caret marks the active field, and the
        // row still fits the box.
        let typed = burst_settings_rows(&msg, Language::Ru, 4, 4, 8, BurstTlsVersion::Tls13, BurstAlpn::Http11, "www.google.com", true, &all, Some(0), 35);
        for row in typed.iter().take(typed.len() - 1) {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        let joined = strip_ansi(&typed.join("\n"));
        assert!(joined.contains("www.google.com"), "{joined}");
        assert!(!joined.contains("Переключитесь для ввода"), "{joined}");

        // A single-profile selection is what the cycler shows after a press: the
        // position counts the `all` entry, so CHROME is the fourth of five — and
        // it is named with the version it reproduces, not with the bare family.
        let chrome = [TlsFingerprint::Chrome];
        let single = burst_settings_rows(
            &msg, Language::Ru, 3, 4, 8, BurstTlsVersion::Tls12, BurstAlpn::Http2, "", false, &chrome, profile_index_of(&chrome), 35,
        );
        assert!(strip_ansi(&single.join("\n")).contains("CHROME 107 [4/5]"));
    }

    /// The domain box announces its state with its own background — grey while
    /// the row is only selected, blue while it is being typed into — and the
    /// brackets and pad carry it too, so the box reads as one field. A pair of
    /// screenshots is not something a test can hold, so the escapes are.
    #[test]
    fn burst_domain_box_paints_its_state() {
        let msg = get_messages(Language::Ru);
        let all = vec![TlsFingerprint::Chrome];
        let box_row = |editing: bool, text: &str| {
            burst_settings_rows(
                &msg,
                Language::Ru,
                BURST_ROW_DOMAIN,
                4,
                8,
                BurstTlsVersion::Tls13,
                BurstAlpn::Http2,
                text,
                editing,
                &all,
                Some(0),
                35,
            )
            .into_iter()
            .find(|row| row.contains("[ ") && row.contains(" ]"))
            .expect("domain input box")
        };

        let idle = box_row(false, "");
        assert!(idle.contains(IDLE_BG) && idle.contains(IDLE_FG), "{idle:?}");
        assert!(!idle.contains(EDITING_BG), "a selected row is not an open field: {idle:?}");

        let typed = box_row(false, "www.google.com");
        assert!(typed.contains(IDLE_BG) && typed.contains(TYPED_FG), "{typed:?}");
        assert!(typed.contains("www.google.com"), "{typed:?}");

        let editing = box_row(true, "www.google.com");
        assert!(editing.contains(EDITING_BG) && editing.contains(EDITING_FG), "{editing:?}");
        assert!(!editing.contains(IDLE_BG), "an open field must not look selected: {editing:?}");
        assert!(editing.contains('▏'), "the caret marks the active field: {editing:?}");
    }

    /// The keycaps of both screens must not exceed an 80-column console.
    #[test]
    fn burst_footer_fits_an_eighty_column_console() {
        for lang in Language::ALL {
            let msg = get_messages(lang);
            for plain in [false, true] {
                let footer = burst_hotkey_row(&msg, lang, plain);
                assert!(strip_ansi_len(&footer) <= 80, "{:?}: {footer}", lang);
            }
        }
    }

    /// The footer is the widest row of the menu, and on a Win7 console it must
    /// not wrap: 80 columns is the legacy default. Measured with the ASCII
    /// glyphs too, where `^v`/`<->` are wider than `↑↓`/`←→`.
    #[test]
    fn hotkey_row_fits_an_eighty_column_console() {
        for lang in Language::ALL {
            let msg = get_messages(lang);
            for plain in [false, true] {
                for ascii in [false, true] {
                    let row = asc_with(&hotkey_row(&msg, lang, plain), ascii);
                    let w = strip_ansi_len(&row);
                    assert!(
                        w <= 79,
                        "footer for {lang:?} plain={plain} ascii={ascii} is {w} columns: {row}"
                    );
                    // The chip carries its own single pad space; anything
                    // wider is an indent. No bar between the key groups (it is
                    // East Asian Ambiguous and doubles on CJK consoles).
                    let visible = strip_ansi(&row);
                    let lead = visible.chars().take_while(|c| *c == ' ').count();
                    assert!(lead <= 1, "footer is indented by {lead}: {visible}");
                    if !plain && !ascii {
                        assert_eq!(lead, 1, "the chip keeps its pad space: {visible}");
                        // The pad space lives inside the chip escape, so the
                        // row starts with the color, not a plain space.
                        assert!(
                            row.starts_with("\x1b[1;46;37m "),
                            "the leading pad space must be colored: {row:?}"
                        );
                    }
                    assert!(!visible.contains('│') && !visible.contains('|'), "footer has a bar: {visible}");
                }
            }
        }
    }

    #[test]
    fn test_toggle_and_sort() {
        let mut s = HashSet::new();
        toggle_test(&mut s, '3');
        toggle_test(&mut s, '1');
        assert_eq!(sorted_selection(&s), "13");
        toggle_test(&mut s, '1');
        assert_eq!(sorted_selection(&s), "3");
    }
    #[test]
    fn test_menu_selection_with_language() {
        let sel = MenuSelection {
            selected_tests: "123".to_string(),
            ip_version: "ipv4".to_string(),
            concurrency: 50,
            language: Language::Ru,
            tls_fingerprint: TlsFingerprint::Rustls,
        };
        assert_eq!(sel.language, Language::Ru);
        assert_eq!(sel.selected_tests, "123");
    }
    #[test]
    fn test_menu_rows_fit_in_box_for_all_languages() {
        for lang in Language::ALL {
            let msg = get_messages(lang);
            let test_options = get_test_options(&msg);

            // Title
            let title_clean = format!(" {} ", asc(&format_bidi(msg.menu_title, lang)));
            let title_len = strip_ansi_len(&title_clean);
            assert!(title_len + 3 <= BOX_WIDTH, "title for {:?} overflows box: {}", lang, title_len);

            let lang_opts = Language::ALL
                .iter()
                .map(|&l| {
                    let lbl = l.label();
                    if l == lang {
                        format!("\x1b[1;32m(x)\x1b[0m {}", lbl)
                    } else {
                        format!("\x1b[2m( )\x1b[0m {}", lbl)
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            let lang_lbl = format_bidi(msg.menu_language, lang);
            let lang_line = format!("  ► {} {}", pad_width(&lang_lbl, 8), lang_opts);
            let w = strip_ansi_len(&lang_line);
            assert!(w + 3 <= BOX_WIDTH, "language row for {:?} overflows box: w={}", lang, w);

            let ip_lbl = format_bidi(msg.menu_ip_version, lang);
            let ip_line = format!("    {} (x) IPv4   ( ) IPv6", pad_width(&ip_lbl, 15));
            let w = strip_ansi_len(&ip_line);
            assert!(w + 3 <= BOX_WIDTH, "ip row for {:?} overflows box: w={}", lang, w);

            let conc_lbl = format_bidi(msg.menu_concurrency, lang);
            let conc_line = format!("    {} (x) 50   ( ) 100", pad_width(&conc_lbl, 15));
            let w = strip_ansi_len(&conc_line);
            assert!(w + 3 <= BOX_WIDTH, "conc row for {:?} overflows box: w={}", lang, w);

            // Every profile, since the row shows one label at a time and a longer
            // label must not push the box border out.
            for (i, fp) in TlsFingerprint::ALL.iter().enumerate() {
                let fp_line = format!(
                    "  ► {} {} [{}/{}]",
                    pad_width(msg.fingerprint_label.trim_end_matches(':'), 16),
                    fingerprint_label(*fp, lang),
                    i + 1,
                    TlsFingerprint::ALL.len()
                );
                let w = strip_ansi_len(&fp_line);
                assert!(
                    w + 3 <= BOX_WIDTH,
                    "fingerprint row {} for {:?} overflows box: w={}",
                    fp.code(),
                    lang,
                    w
                );
            }
            for (digit, label) in test_options {
                let test_line = format!("  ► [ ] {}. {}", digit, format_bidi(label, lang));
                let w = strip_ansi_len(&test_line);
                assert!(w + 3 <= BOX_WIDTH, "test row {} for {:?} overflows box: w={}", digit, lang, w);
            }
        }
    }


}

//! The main menu: language, IP version, concurrency, fingerprint and the test
//! checkboxes, and the loop that runs it until a selection is made.

use crossterm::execute;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dpi_core::config::AppConfig;
use crate::i18n::{Language, Messages, fingerprint_label, format_bidi, get_messages};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::netinfo::ipv6_supported;
use dpi_core::profile::RegionProfile;
use futures_util::StreamExt;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::TestSelection;
use crate::render::{
    BOX_WIDTH, asc, ascii_mode, clean_output, frame_home, frame_repaint, output_str,
    panel_to_string, plain_mode, render_banner, strip_ansi_len,
};
use crate::tui::input::nav_key;
use crate::tui::screens::legend::{MenuAction, legend_loop};
use crate::update::{ReleaseInfo, version_badge_lang};

#[derive(Debug, Clone)]
pub struct MenuSelection {
    pub selected_tests: String,
    #[allow(dead_code)]
    pub ip_version: String, // "ipv4" or "ipv6"
    pub concurrency: usize,
    pub language: Language,
    pub tls_fingerprint: TlsFingerprint,
    /// The interface the probes leave through, when the user picked one: `None`
    /// is the routing table.
    pub interface: Option<String>,
}

/// Applies the interface a menu selection carries to the process-wide bind.
///
/// The bind is a global rather than a field of the run, so *every* place that
/// takes a `MenuSelection` has to call this: a run that returned to the menu with
/// `M` and picked another interface kept the first one, because the second
/// selection only updated the locals beside it.
pub fn apply_interface(selection: &MenuSelection) {
    match &selection.interface {
        Some(name) => dpi_core::net::bind::set_target(dpi_core::net::bind::resolve(name)),
        None => dpi_core::net::bind::set_target(None),
    }
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
    // Interfaces a probe can actually leave through, and index 0 for the routing
    // table — the answer every run gave before this row existed. The list is read
    // once: it cannot change while the menu is open in any way that matters, and
    // re-reading it on every keypress would make the cursor jump under the user.
    let ifaces: Vec<dpi_core::net::bind::BindTarget> = dpi_core::net::bind::interfaces()
        .iter()
        .filter_map(|i| dpi_core::net::bind::resolve(&i.name))
        .collect();
    let mut iface_idx = dpi_core::net::bind::target()
        .and_then(|t| {
            ifaces
                .iter()
                .position(|i| i.name == t.name)
                .map(|pos| pos + 1)
        })
        .unwrap_or(0);
    let v6_supported = ipv6_supported();

    let mut selected_tests: HashSet<char> = HashSet::new(); // empty by default

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
    // Empty-selection warning ("Выберите хотя бы один тест"): shown until the
    // next keypress.
    let mut notice: Option<String> = None;
    let mut reader = EventStream::new();
    loop {
        let offset = 5;
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
                iface_idx
                    .checked_sub(1)
                    .and_then(|pos| ifaces.get(pos))
                    .map_or_else(|| msg.menu_interface_auto.to_string(), |target| target.label.clone()),
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
                KeyCode::Char(c) => KeyCode::Char(nav_key(c)),
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
                | KeyCode::Char('k')
                | KeyCode::Char('K') => {
                    cursor = (cursor + total_rows - 1) % total_rows;
                }

                // Navigation: DOWN (Arrows, WASD, Vim, Tab)
                KeyCode::Down
                | KeyCode::Tab
                | KeyCode::Char('s')
                | KeyCode::Char('S')
                | KeyCode::Char('j')
                | KeyCode::Char('J') => {
                    cursor = (cursor + 1) % total_rows;
                }

                // Navigation: LEFT / PREVIOUS (Arrows, WASD, Vim, '-')
                KeyCode::Left
                | KeyCode::Char('a')
                | KeyCode::Char('A')
                | KeyCode::Char('h')
                | KeyCode::Char('H')
                | KeyCode::Char('-')
                | KeyCode::Char('<') => {
                    if cursor == 0 {
                        let all = Language::ALL;
                        let cur_idx = all.iter().position(|&l| l == current_lang).unwrap_or(0);
                        let next_idx = (cur_idx + all.len() - 1) % all.len();
                        current_lang = all[next_idx];
                        msg = get_messages(current_lang);
                    } else if cursor == 1 {
                        let slots = ifaces.len() + 1;
                        iface_idx = (iface_idx + slots - 1) % slots;
                    } else if cursor == 2 {
                        if v6_supported {
                            ip_version = if ip_version == "ipv4" { "ipv6".to_string() } else { "ipv4".to_string() };
                        }
                    } else if cursor == 3 {
                        conc_idx = (conc_idx + presets.len() - 1) % presets.len();
                    } else if cursor == 4 {
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
                | KeyCode::Char('l')
                | KeyCode::Char('L')
                | KeyCode::Char('+')
                | KeyCode::Char('>') => {
                    if cursor == 0 {
                        let all = Language::ALL;
                        let cur_idx = all.iter().position(|&l| l == current_lang).unwrap_or(0);
                        let next_idx = (cur_idx + 1) % all.len();
                        current_lang = all[next_idx];
                        msg = get_messages(current_lang);
                    } else if cursor == 1 {
                        iface_idx = (iface_idx + 1) % (ifaces.len() + 1);
                    } else if cursor == 2 {
                        if v6_supported {
                            ip_version = if ip_version == "ipv4" { "ipv6".to_string() } else { "ipv4".to_string() };
                        }
                    } else if cursor == 3 {
                        conc_idx = (conc_idx + 1) % presets.len();
                    } else if cursor == 4 {
                        fp_idx = (fp_idx + 1) % TlsFingerprint::ALL.len();
                    } else if cursor >= offset {
                        let t_idx = cursor - offset;
                        if t_idx < test_options.len() {
                            toggle_test(&mut selected_tests, test_options[t_idx].0);
                        }
                    }
                }

                // Toggle at cursor: Space or 'x'
                KeyCode::Char(' ')
                | KeyCode::Char('x')
                | KeyCode::Char('X') => {
                    if cursor == 0 {
                        let all = Language::ALL;
                        let cur_idx = all.iter().position(|&l| l == current_lang).unwrap_or(0);
                        let next_idx = (cur_idx + 1) % all.len();
                        current_lang = all[next_idx];
                        msg = get_messages(current_lang);
                    } else if cursor == 1 {
                        iface_idx = (iface_idx + 1) % (ifaces.len() + 1);
                    } else if cursor == 2 {
                        if v6_supported {
                            ip_version = if ip_version == "ipv4" { "ipv6".to_string() } else { "ipv4".to_string() };
                        }
                    } else if cursor == 3 {
                        conc_idx = (conc_idx + 1) % presets.len();
                    } else if cursor == 4 {
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

                // Start tests: Enter or 'r' (Run) / 'g' (Go)
                KeyCode::Enter
                | KeyCode::Char('r')
                | KeyCode::Char('R')
                | KeyCode::Char('g')
                | KeyCode::Char('G') => {
                    if selected_tests.is_empty() {
                        // Refuse to run when no test is checked.
                        notice = Some(msg.menu_need_one.to_string());
                        continue;
                    }
                    return MenuResult::Run(MenuSelection {
                        selected_tests: sorted_selection(&selected_tests),
                        ip_version: ip_version.clone(),
                        concurrency: presets[conc_idx],
                        language: current_lang,
                        tls_fingerprint: TlsFingerprint::ALL[fp_idx],
                        interface: iface_idx
                            .checked_sub(1)
                            .and_then(|pos| ifaces.get(pos))
                            .map(|target| target.name.clone()),
                    });
                }

                // Quit: 'q' or Esc
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
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
    iface_value: String,
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
    let offset = 5;

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

    // Interface row: a cycler rather than a radio list, because a router reports
    // dozens of interfaces and the panel has one line for them.
    let iface_cursor = if cursor == 1 { "►" } else { " " };
    let iface_lbl = format!("{}:", msg.menu_interface.trim_end_matches(':'));
    lines.push(format!("  {} {} < {} >", iface_cursor, pad_width(&iface_lbl, 16), iface_value));

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
    let ip_cursor = if cursor == 2 { "►" } else { " " };
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
    let conc_cursor = if cursor == 3 { "►" } else { " " };
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
    let fp_cursor = if cursor == 4 { "►" } else { " " };
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
    // The box comes from the shared panel helper: border glyphs, title padding
    // and the per-row pad to the right edge live in one place, the same one the
    // legend and netinfo panels are drawn with.
    rows.extend(
        panel_to_string(&format_bidi(msg.menu_title, current_lang), &lines)
            .lines()
            .map(clean_output),
    );

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

pub(crate) fn pad_width(s: &str, target_width: usize) -> String {
    let w = strip_ansi_len(s);
    if w >= target_width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(target_width - w))
    }
}



/// Toggles a test checkbox: the digit is added if absent, removed if present.
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


/// The menu's test rows in digit order. The labels come from [`Messages`], which
/// is where the digit-to-test mapping lives; the table here is only its order.
fn get_test_options(msg: &Messages) -> [(char, &'static str); 8] {
    std::array::from_fn(|i| {
        let digit = char::from(b'0' + i as u8);
        (digit, msg.menu_test_label(digit))
    })
}

/// The interactive menu, and then the legend screen for as long as the selection
/// is only the legend.
///
/// A legend-only selection has nothing to run, so the legend text stands in for
/// the run. It used to be printed once and its own menu key was answered by
/// running the (empty) selection again: the screen came back with the post-run
/// panel and only the *second* press opened the menu. The key now does what it
/// says, and the screen ends when the selection can actually run.
pub(crate) async fn menu_until_something_to_run(
    lang: Language,
    profile: RegionProfile,
    cfg: &AppConfig,
    badge: &str,
    version_slot: &VersionSlot,
) -> Option<MenuSelection> {
    loop {
        let chosen = match run_interactive_menu(lang, profile, cfg, badge, version_slot).await {
            MenuResult::Run(chosen) => chosen,
            MenuResult::Quit => return None,
        };
        if !TestSelection::parse(&chosen.selected_tests).only_legend {
            return Some(chosen);
        }
        match legend_loop(chosen.language, &get_messages(chosen.language)) {
            MenuAction::Menu => continue,
            MenuAction::Quit => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::strip_ansi;
    use crate::tui::widgets::asc_with;
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
            interface: None,
        };
        assert_eq!(sel.language, Language::Ru);
        assert_eq!(sel.selected_tests, "123");
        assert!(sel.interface.is_none(), "the routing table is the default");
    }

    /// A selection's interface always reaches the process-wide bind: the call
    /// was missing from the post-run path, so a second trip through the menu with
    /// `M` kept testing whatever the first trip picked.
    #[test]
    fn a_selection_applies_its_interface() {
        use dpi_core::net::bind;

        let mut sel = MenuSelection {
            selected_tests: "1".to_string(),
            ip_version: "ipv4".to_string(),
            concurrency: 50,
            language: Language::Ru,
            tls_fingerprint: TlsFingerprint::Rustls,
            interface: None,
        };
        bind::set_target(Some(bind::BindTarget {
            name: "example0".to_string(),
            v4: Some("192.0.2.9".parse().expect("documentation address")),
            v6: None,
            label: "example0 (192.0.2.9)".to_string(),
        }));
        apply_interface(&sel);
        assert!(bind::target().is_none(), "an empty row clears the bind");

        // Whatever this machine has: the name the menu shows is the name that
        // ends up bound, and a name that resolves to nothing clears it rather
        // than leaving the previous choice in place.
        if let Some(iface) = bind::interfaces().iter().find_map(|i| bind::resolve(&i.name)) {
            sel.interface = Some(iface.name.clone());
            apply_interface(&sel);
            assert_eq!(bind::target().map(|t| t.name), Some(iface.name));
        }
        sel.interface = Some("no-such-interface-2791".to_string());
        apply_interface(&sel);
        assert!(bind::target().is_none(), "a name that resolves to nothing binds nothing");
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

use std::collections::HashSet;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use crossterm::cursor::MoveTo;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use dpi_core::config::AppConfig;
use dpi_core::i18n::{format_bidi, get_messages, Language, Messages};
use dpi_core::net::netinfo::ipv6_supported;
use dpi_core::net::version::{version_badge_lang, ReleaseInfo};
use dpi_core::profile::RegionProfile;

use crate::render::{asc, ascii_mode, clean_output, output_str, plain_mode, render_banner, strip_ansi_len, BOX_WIDTH};

#[derive(Debug, Clone)]
pub struct MenuSelection {
    pub selected_tests: String,
    #[allow(dead_code)]
    pub ip_version: String, // "ipv4" or "ipv6"
    pub concurrency: usize,
    pub language: Language,
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

pub fn run_interactive_menu(
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
    let _ = execute!(out, crossterm::cursor::Hide, Clear(ClearType::All));

    let result = run_menu_loop(initial_lang, profile, cfg, badge, latest_slot);

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

fn run_menu_loop(
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
    let v6_supported = ipv6_supported();

    let mut selected_tests: HashSet<char> = HashSet::new(); // empty by default, like Python

    // Paint state: a full clear+redraw several times a second flickers, so
    // repaint only on the first paint, a keypress, or a badge/row change.
    let mut last_badge = String::new();
    let mut dirty = true;
    // Empty-selection warning (mirrors Python "Выберите хотя бы один тест"):
    // shown until the next keypress.
    let mut notice: Option<String> = None;
    loop {
        let offset = 3;
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
                v6_supported,
                &test_options,
                &selected_tests,
                &msg,
                profile,
                &live_badge,
                notice.as_deref(),
            );
            last_badge = live_badge;
            dirty = false;
        }

        // Poll instead of blocking so the badge above still goes live
        // while no key is pressed.
        if !event::poll(Duration::from_millis(300)).unwrap_or(false) {
            continue;
        }
        if let Ok(Event::Key(KeyEvent { code, modifiers, kind, .. })) = event::read() {
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
                    } else if cursor >= offset {
                        let t_idx = cursor - offset;
                        if t_idx < test_options.len() {
                            toggle_test(&mut selected_tests, test_options[t_idx].0);
                        }
                    }
                }

                // Direct toggle by digit
                KeyCode::Char(c @ '0'..='6') => {
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
    v6_supported: bool,
    test_options: &[(char, &str)],
    selected_tests: &HashSet<char>,
    msg: &Messages,
    profile: RegionProfile,
    badge: &str,
    notice: Option<&str>,
) {
    let mut screen = String::with_capacity(4096);
    let banner = render_banner(msg, profile, badge).replace("\r\n", "\n").replace('\n', "\r\n");
    screen.push_str(&clean_output(&banner));
    let mut lines = Vec::new();
    let offset = 3;

    // Language row
    let lang_opts = Language::ALL
        .iter()
        .map(|&l| {
            let lbl = format_bidi(l.label(), l);
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
        let unavail = match current_lang {
            Language::Ru => "(недоступен)".to_string(),
            Language::Zh => "(不可用)".to_string(),
            Language::Es => "(no disponible)".to_string(),
            Language::En => "(unavailable)".to_string(),
        };
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
        "\x1b[1;36m{}{}\x1b[1;36m{}\x1b[1;36m{}\x1b[1;36m{}\x1b[0m\r\n",
        tl, hb, title_clean, hb.repeat(border_total), tr
    );
    screen.push_str(&clean_output(&top_border));

    for line in &lines {
        let plain_len = strip_ansi_len(line);
        let pad = BOX_WIDTH.saturating_sub(plain_len + 3);
        let row = format!("\x1b[1;36m{}\x1b[0m {}{}\x1b[1;36m{}\x1b[0m\r\n", vb, line, " ".repeat(pad), vb);
        screen.push_str(&clean_output(&row));
    }

    let bot_border = format!("\x1b[1;36m{}{}{}\x1b[0m\r\n", bl, hb.repeat(BOX_WIDTH - 2), br);
    screen.push_str(&clean_output(&bot_border));

    let hotkey_row = if plain_mode() {
        format!(
            "  [↑↓/WS] {} | [←→/AD] {} | [0-6] {} | [Enter] {} | [Q] {}",
            format_bidi(msg.menu_hw_row, current_lang),
            format_bidi(msg.menu_hw_change, current_lang),
            format_bidi(msg.menu_hw_tests, current_lang),
            format_bidi(msg.menu_hw_start, current_lang),
            format_bidi(msg.menu_hw_quit, current_lang)
        )
    } else {
        format!(
            "  \x1b[1;46;37m ↑↓/WS \x1b[0m {} │ \x1b[1;46;37m ←→/AD \x1b[0m {} │ \x1b[1;46;37m 0-6 \x1b[0m {} │ \x1b[1;42;37m Enter \x1b[0m {} │ \x1b[1;41;37m Q \x1b[0m {}",
            format_bidi(msg.menu_hw_row, current_lang),
            format_bidi(msg.menu_hw_change, current_lang),
            format_bidi(msg.menu_hw_tests, current_lang),
            format_bidi(msg.menu_hw_start, current_lang),
            format_bidi(msg.menu_hw_quit, current_lang)
        )
    };
    let clean_hotkeys = clean_output(&asc(&hotkey_row));
    let hk_w = strip_ansi_len(&clean_hotkeys);
    let hk_pad = (BOX_WIDTH + 8).saturating_sub(hk_w);
    screen.push_str(&clean_hotkeys);
    screen.push_str(&" ".repeat(hk_pad));
    screen.push_str("\r\n");

    let notice_str = if let Some(n) = notice {
        clean_output(&format!("  \x1b[1;33m{}\x1b[0m", format_bidi(n, current_lang)))
    } else {
        String::new()
    };
    let n_w = strip_ansi_len(&notice_str);
    let n_pad = (BOX_WIDTH + 8).saturating_sub(n_w);
    screen.push_str(&notice_str);
    screen.push_str(&" ".repeat(n_pad));
    screen.push_str("\r\n");

    let mut out = std::io::stdout();
    let _ = execute!(out, MoveTo(0, 0));
    output_str(&screen);
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


#[cfg(test)]
mod tests {
    use super::*;

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
            for (digit, label) in test_options {
                let test_line = format!("  ► [ ] {}. {}", digit, format_bidi(label, lang));
                let w = strip_ansi_len(&test_line);
                assert!(w + 3 <= BOX_WIDTH, "test row {} for {:?} overflows box: w={}", digit, lang, w);
            }
        }
    }


    #[test]
    fn test_print_menu_visual() {
        let msg = get_messages(Language::Ru);

        // Check top border
        let title_clean = format!(" {} ", asc(&format_bidi(msg.menu_title, Language::Ru)));
        let title_len = strip_ansi_len(&title_clean);
        let border_total = BOX_WIDTH.saturating_sub(title_len + 3);
        let top_border = format!("╭─{} {}─╮", title_clean.trim(), "─".repeat(border_total));
        println!("\n[VISUAL TEST MENU]");
        println!("{}", top_border);

        let banner = render_banner(&msg, RegionProfile::Ru, msg.latest_version);
        println!("{}", banner);

        // Language row
        let lang_lbl = format!("{}:", msg.menu_language.trim_end_matches(':'));
        let lang_opts = Language::ALL
            .iter()
            .map(|&l| {
                let lbl = format_bidi(l.label(), l);
                format!("{} {}", radio_btn(l == Language::Ru), lbl)
            })
            .collect::<Vec<_>>()
            .join(" ");
        let l1 = format!("  ► {} {}", pad_width(&lang_lbl, 16), lang_opts);
        let pad1 = BOX_WIDTH.saturating_sub(strip_ansi_len(&l1) + 3);
        println!("│ {}{} │", l1, " ".repeat(pad1));

        // IP row
        let ip_lbl = format!("{}:", msg.menu_ip_version.trim_end_matches(':'));
        let ip_unavail = format!("({})", format_bidi("недоступен", Language::Ru));
        let off_str = if ascii_mode() { "( )" } else { "○" };
        let ip_opts = format!("{} IPv4   \x1b[2m{} IPv6 {}\x1b[0m", radio_btn(true), off_str, ip_unavail);
        let l2 = format!("    {} {}", pad_width(&ip_lbl, 16), ip_opts);
        let pad2 = BOX_WIDTH.saturating_sub(strip_ansi_len(&l2) + 3);
        println!("│ {}{} │", l2, " ".repeat(pad2));

        // Concurrency row
        let conc_lbl = format!("{}:", msg.menu_concurrency.trim_end_matches(':'));
        let conc_opts = [1, 5, 20, 50, 100]
            .iter()
            .map(|&p| {
                format!("{} {}", radio_btn(p == 20), p)
            })
            .collect::<Vec<_>>()
            .join("   ");
        let l3 = format!("    {} {}", pad_width(&conc_lbl, 12), conc_opts);
        let pad3 = BOX_WIDTH.saturating_sub(strip_ansi_len(&l3) + 3);
        println!("│ {}{} │", l3, " ".repeat(pad3));
        println!("│   {}  │", "─".repeat(BOX_WIDTH - 8));
        for (digit, label) in get_test_options(&msg) {
            let line = format!("  [ ] {}. {}", digit, format_bidi(label, Language::Ru));
            let pad = BOX_WIDTH.saturating_sub(strip_ansi_len(&line) + 3);
            println!("│ {}{} │", line, " ".repeat(pad));
        }
        let bot_border = format!("╰{}╯", "─".repeat(BOX_WIDTH - 2));
        println!("{}", bot_border);

        let hotkey_row = format!(
            "  [↑↓/WS]  {} │ [←→/AD]  {} │ [0-6]  {} │ [Enter]  {} │ [Q]  {}",
            format_bidi(msg.menu_hw_row, Language::Ru),
            format_bidi(msg.menu_hw_change, Language::Ru),
            format_bidi(msg.menu_hw_tests, Language::Ru),
            format_bidi(msg.menu_hw_start, Language::Ru),
            format_bidi(msg.menu_hw_quit, Language::Ru)
        );
        println!("{}", hotkey_row);
    }
}

fn get_test_options(msg: &Messages) -> [(char, &'static str); 7] {
    [
        ('0', msg.menu_test_netinfo),
        ('1', msg.menu_test_dns),
        ('2', msg.menu_test_domains),
        ('3', msg.menu_test_tcp),
        ('4', msg.menu_test_sni),
        ('5', msg.menu_test_telegram),
        ('6', msg.menu_test_legend),
    ]
}

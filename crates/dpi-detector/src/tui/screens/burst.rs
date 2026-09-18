//! Test 6's settings screen: handshake count, timeout, host and the ClientHello
//! profiles a burst run reproduces.

use crossterm::execute;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use dpi_core::config::clean_domain;
use crate::i18n::{Language, Messages, format_bidi, get_messages};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::probe::burst::{
    BURST_MAX_ATTEMPTS, BURST_MAX_TIMEOUT_SECS, BURST_MIN_ATTEMPTS, BURST_MIN_TIMEOUT_SECS,
    BurstAlpn, BurstSettings, BurstTlsVersion,
};
use futures_util::StreamExt;

use crate::render::{
    asc, clean_output, frame_home, frame_repaint, output_str, panel_to_string, plain_mode,
    strip_ansi_len, BOX_WIDTH,
};
use crate::tui::input::{nav_key, normalize_key_char};
use crate::tui::screens::main::pad_width;

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
/// Longest domain box content: a pasted list would otherwise become the SNI.
const DOMAIN_MAX_CHARS: usize = 120;
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

/// Columns left for a row's value: the box, its two borders and the space inside
/// each, the mark, the gap and the label column.
const BURST_VALUE_WIDTH: usize = BOX_WIDTH - 3 - (2 + 1 + BURST_LABEL_WIDTH + 1);

/// The shapes as one value, cut to `width` columns with an ellipsis. A selection
/// the cycler has no position for is a list whose names would otherwise run past
/// the box's right edge — the row is one line, so what does not fit is dropped
/// rather than pushed off the screen.
fn names_value(names: &[&str], width: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for (index, name) in names.iter().enumerate() {
        let separator = if index > 0 { 2 } else { 0 };
        if used + separator + strip_ansi_len(name) + 1 > width {
            out.push('…');
            return out;
        }
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(name);
        used += separator + strip_ansi_len(name);
    }
    out
}

/// Test 6's own screen: how many handshakes at once, how long each may take,
/// which host, and which ClientHello profiles.
///
/// Returns `None` when the user cancels (Q/Esc/Ctrl-C): the caller then skips
/// test 6 instead of running it with guesses. The screen is only shown for an
/// interactive run; a piped `-t 6` takes the values from the CLI.
///
/// `domain_count` is the size of the *configured* list — what an empty box means
/// — not the size of the current selection, and `current_domain` is the host the
/// caller probed last, drawn in the box.
pub async fn burst_settings_menu(
    lang: Language,
    initial: &BurstSettings,
    domain_count: usize,
    current_domain: Option<&str>,
) -> Option<BurstChoice> {
    if enable_raw_mode().is_err() {
        return None;
    }
    let msg = get_messages(lang);
    let mut out = std::io::stdout();
    let _ = execute!(out, crossterm::cursor::Hide);
    let result = burst_settings_loop(&msg, lang, initial, domain_count, current_domain).await;
    let _ = execute!(out, crossterm::cursor::Show);
    let _ = disable_raw_mode();
    result
}

async fn burst_settings_loop(
    msg: &Messages,
    lang: Language,
    initial: &BurstSettings,
    domain_count: usize,
    current_domain: Option<&str>,
) -> Option<BurstChoice> {
    let mut cursor = BURST_ROW_ATTEMPTS;
    let mut attempts = initial.attempts;
    let mut timeout_secs = initial.timeout.as_secs();
    let mut tls = initial.tls;
    let mut alpn = initial.alpn;
    // The box opens holding the host the caller probed last, so a repeated run
    // shows what it is about to probe, and the first typed character replaces it
    // — with the caret at the end, typing into a prefilled box read as an append
    // to a domain the user meant to replace. Emptying the box means the
    // configured list again.
    let mut text = current_domain.unwrap_or_default().to_string();
    let mut edited = current_domain.is_none();
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
            KeyCode::Char(c) => KeyCode::Char(normalize_key_char(c)),
            other => other,
        };
        if modifiers.contains(KeyModifiers::CONTROL) && matches!(code, KeyCode::Char('c') | KeyCode::Char('C')) {
            return None;
        }
        // Outside the text field a key is a command, so it resolves through the
        // layout mapping like every other screen; inside it, letters are text
        // and must arrive exactly as typed.
        let code = if editing {
            code
        } else {
            match code {
                KeyCode::Char(c) => KeyCode::Char(nav_key(c)),
                other => other,
            }
        };
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
            KeyCode::Char('w')
            | KeyCode::Char('W')
            | KeyCode::Char('z')
            | KeyCode::Char('Z')
            | KeyCode::Char('k')
            | KeyCode::Char('K')
            if !editing => {
                cursor = cursor.saturating_sub(1);
                editing = false;
            }
            KeyCode::Char('s')
            | KeyCode::Char('S')
            | KeyCode::Char('j')
            | KeyCode::Char('J')
            if !editing => {
                cursor = (cursor + 1).min(BURST_ROW_PROFILES);
                editing = false;
            }
            KeyCode::Enter => {
                // The same cleaner the configured list goes through, so a pasted
                // URL probes its host and an empty box means that list.
                let domain = clean_domain(&text);
                return Some(BurstChoice {
                    settings: BurstSettings::clamped(attempts, timeout_secs, tls, alpn, profiles),
                    domain,
                });
            }
            // Left leaves the field, and outside it steps a value down.
            KeyCode::Left if editing => editing = false,
            KeyCode::Left
            | KeyCode::Char('a')
            | KeyCode::Char('A')
            | KeyCode::Char('h')
            | KeyCode::Char('H')
            | KeyCode::Char('-')
            | KeyCode::Char('<')
            if !editing => match cursor {
                BURST_ROW_ATTEMPTS => attempts = attempts.saturating_sub(1).max(BURST_MIN_ATTEMPTS),
                BURST_ROW_TIMEOUT => timeout_secs = timeout_secs.saturating_sub(1).max(BURST_MIN_TIMEOUT_SECS),
                // The TLS axis has three values, so each direction steps it.
                BURST_ROW_TLS => tls = flip_tls(tls, false),
                BURST_ROW_HTTP => alpn = flip_alpn(alpn),
                BURST_ROW_PROFILES => {
                    let next = profile_index.map(|i| (i + PROFILE_CHOICES - 1) % PROFILE_CHOICES).unwrap_or(0);
                    profile_index = Some(next);
                    profiles = profiles_for_index(next);
                }
                _ => {}
            },
            // Right enters the field, and outside it steps a value up.
            KeyCode::Right
            | KeyCode::Char('d')
            | KeyCode::Char('D')
            | KeyCode::Char('l')
            | KeyCode::Char('L')
            | KeyCode::Char('+')
            | KeyCode::Char('>')
            if !editing => match cursor {
                BURST_ROW_DOMAIN => editing = true,
                BURST_ROW_ATTEMPTS => attempts = (attempts + 1).min(BURST_MAX_ATTEMPTS),
                BURST_ROW_TIMEOUT => timeout_secs = (timeout_secs + 1).min(BURST_MAX_TIMEOUT_SECS),
                BURST_ROW_TLS => tls = flip_tls(tls, true),
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
                edited = true;
            }
            KeyCode::Delete if editing => {
                text.clear();
                edited = true;
            }
            KeyCode::Char(c) if editing => {
                domain_push(&mut text, c, &mut edited);
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
    // position, moved by the same keys. The first value is every shape at once —
    // the run then puts one shape per row of the table.
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
        // A selection the cycler has no position for (`--burst-profiles`): its
        // names are shown while they fit the column, so the box keeps its edge.
        None => names_value(
            &profiles.iter().map(|f| f.display_label()).collect::<Vec<_>>(),
            BURST_VALUE_WIDTH,
        ),
    };
    lines.push(field(BURST_ROW_PROFILES, msg.burst_field_profiles, profile_value));

    // Same shared box as the menu: the settings screen used to carry its own
    // copy of the border, the title pad and the per-row pad.
    let mut rows: Vec<String> = panel_to_string(&format_bidi(msg.burst_settings_title, lang), &lines)
        .lines()
        .map(clean_output)
        .collect();
    rows.push(clean_output(&asc(&burst_hotkey_row(msg, lang, plain_mode()))));
    rows
}

/// Applies one typed character to the domain box.
///
/// Everything printable is accepted, because pasting a URL is normal and the
/// host is what [`clean_domain`] extracts when the screen is submitted — keeping
/// only host characters here turned `https://info.paymaster.ru` into
/// `https:info.paymaster.ru`, a name that resolves to nothing. The first
/// character after the box opened replaces the host the caller showed, so typing
/// over a prefilled box is an edit rather than an append.
fn domain_push(text: &mut String, c: char, edited: &mut bool) {
    if !*edited {
        text.clear();
        *edited = true;
    }
    if c.is_ascii_graphic() && text.chars().count() < DOMAIN_MAX_CHARS {
        text.push(c);
    }
}

/// Cycles the three-valued TLS axis: the browser's offer, then each pinned
/// version. Ordered so the first two entries read as "what a browser sends" and
/// "the same shape with one version" — the pair a 1.3-only middlebox separates.
const TLS_CHOICES: [BurstTlsVersion; 3] = [
    BurstTlsVersion::Tls13And12,
    BurstTlsVersion::Tls13Only,
    BurstTlsVersion::Tls12Only,
];

/// Either direction steps through [`TLS_CHOICES`].
fn flip_tls(tls: BurstTlsVersion, forward: bool) -> BurstTlsVersion {
    let at = TLS_CHOICES.iter().position(|choice| *choice == tls).unwrap_or(0);
    let next = if forward {
        (at + 1) % TLS_CHOICES.len()
    } else {
        (at + TLS_CHOICES.len() - 1) % TLS_CHOICES.len()
    };
    TLS_CHOICES[next]
}

fn flip_alpn(alpn: BurstAlpn) -> BurstAlpn {
    match alpn {
        BurstAlpn::Http2 => BurstAlpn::Http11,
        BurstAlpn::Http11 => BurstAlpn::Http2,
    }
}

/// Choices of the profile cycler: every shape there is, all of them at once, or
/// one — the first entry is the whole list, because a run that presents one shape
/// after another is how the table gets a row per shape.
const PROFILE_CHOICES: usize = TlsFingerprint::ALL.len() + 1;

/// The cycler position a selection corresponds to: `Some(0)` = every shape,
/// `Some(1+n)` = the n-th shape alone, `None` = a combination the cycler cannot
/// show, which only `--burst-profiles` can ask for, so the row names the shapes
/// until a press picks one.
fn profile_index_of(profiles: &[TlsFingerprint]) -> Option<usize> {
    if profiles.len() == TlsFingerprint::ALL.len() {
        Some(0)
    } else if profiles.len() == 1 {
        TlsFingerprint::ALL.iter().position(|f| *f == profiles[0]).map(|i| i + 1)
    } else {
        None
    }
}

/// The selection a cycler position means: every shape, or that one alone.
fn profiles_for_index(index: usize) -> Vec<TlsFingerprint> {
    if index == 0 {
        TlsFingerprint::ALL.to_vec()
    } else {
        vec![TlsFingerprint::ALL[index.min(PROFILE_CHOICES - 1) - 1]]
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
    use crate::render::{BOX_WIDTH, strip_ansi, strip_ansi_len};
    /// The settings screen is a fixed-width box: every row must be exactly the
    /// box width, an inactive empty field prompts how to start typing, and the
    /// default it falls back to is printed on the line under it, in the value
    /// column of the row above.
    #[test]
    fn burst_settings_rows_align_and_prompt() {
        let msg = get_messages(Language::Ru);
        let all = TlsFingerprint::ALL.to_vec();

        let empty = burst_settings_rows(&msg, Language::Ru, 4, 4, 8, BurstTlsVersion::Tls13And12, BurstAlpn::Http2, "", false, &all, Some(0), 35);
        // The last row is the footer, which lives outside the box.
        for row in empty.iter().take(empty.len() - 1) {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        // Text is asserted without its styling: the escapes sit between words.
        let joined = strip_ansi(&empty.join("\n"));
        assert!(joined.contains("Переключитесь для ввода"), "{joined}");
        assert!(joined.contains("По умолчанию — все домены (35)"), "{joined}");
        // The cycler's position and size come from the profile table, so this
        // is the count the tool actually offers rather than a number here.
        assert!(joined.contains(&format!("все [1/{PROFILE_CHOICES}]")), "{joined}");

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
        let typed = burst_settings_rows(&msg, Language::Ru, 4, 4, 8, BurstTlsVersion::Tls13And12, BurstAlpn::Http11, "www.google.com", true, &all, Some(0), 35);
        for row in typed.iter().take(typed.len() - 1) {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        let joined = strip_ansi(&typed.join("\n"));
        assert!(joined.contains("www.google.com"), "{joined}");
        assert!(!joined.contains("Переключитесь для ввода"), "{joined}");

        // A single-profile selection is what the cycler shows after a press: the
        // position counts the `all` entry, so CHROME is its place in the full
        // list plus one — and it is named with the version it reproduces, not
        // with the bare family.
        let chrome = [TlsFingerprint::Chrome107];
        let single = burst_settings_rows(
            &msg, Language::Ru, 3, 4, 8, BurstTlsVersion::Tls12Only, BurstAlpn::Http2, "", false, &chrome, profile_index_of(&chrome), 35,
        );
        let chrome_position = TlsFingerprint::ALL
            .iter()
            .position(|f| *f == TlsFingerprint::Chrome107)
            .expect("the cycler lists chrome")
            + 2;
        assert!(
            strip_ansi(&single.join("\n"))
                .contains(&format!("CHROME 107 [{chrome_position}/{PROFILE_CHOICES}]")),
            "{}",
            strip_ansi(&single.join("\n"))
        );
    }

    /// A selection the cycler has no position for is the CLI's default set: the
    /// row names the shapes while they fit the column and drops the rest, so the
    /// box keeps its right edge — the names of seven shapes used to run past it.
    #[test]
    fn a_selection_without_a_position_is_cut_to_the_column() {
        let msg = get_messages(Language::Ru);
        let chosen = TlsFingerprint::DEFAULT_SET.to_vec();
        let rows = burst_settings_rows(
            &msg, Language::Ru, BURST_ROW_PROFILES, 4, 8, BurstTlsVersion::Tls13And12,
            BurstAlpn::Http2, "", false, &chosen, profile_index_of(&chosen), 35,
        );
        for row in rows.iter().take(rows.len() - 1) {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        let joined = strip_ansi(&rows.join("\n"));
        assert!(joined.contains('…'), "what does not fit is cut: {joined}");
        assert!(joined.contains(TlsFingerprint::DEFAULT_SET[0].display_label()), "{joined}");
    }

    /// The row offers every shape the detector can present, one press away, and
    /// the first value is the whole list — the run that fills the table with a
    /// row per shape. A selection the cycler did not produce (a
    /// `--burst-profiles` list) has no position, so the row names the shapes
    /// until a press picks one.
    #[test]
    fn the_profile_cycler_reaches_every_shape_and_the_whole_list() {
        assert_eq!(PROFILE_CHOICES, TlsFingerprint::ALL.len() + 1, "every shape, plus all");
        assert_eq!(profiles_for_index(0), TlsFingerprint::ALL.to_vec(), "the first value is all");
        assert_eq!(profile_index_of(&TlsFingerprint::ALL), Some(0), "and it round-trips");
        for index in 1..PROFILE_CHOICES {
            let chosen = profiles_for_index(index);
            assert_eq!(chosen.len(), 1, "{index}: one shape at a time");
            assert_eq!(chosen[0], TlsFingerprint::ALL[index - 1]);
            assert_eq!(profile_index_of(&chosen), Some(index), "the position round-trips");
        }
        assert_eq!(profile_index_of(&TlsFingerprint::DEFAULT_SET), None, "a set has no position");
    }

    /// A pasted URL must survive in the box and come out as its host, not as the
    /// scheme plus a colon: dropping the slashes as they arrived produced
    /// `https:info.paymaster.ru`, which is not a name any resolver knows.
    #[test]
    fn domain_box_accepts_a_pasted_url_and_hands_back_its_host() {
        let mut text = String::new();
        let mut edited = true;
        for c in "https://info.paymaster.ru/path?q=1".chars() {
            domain_push(&mut text, c, &mut edited);
        }
        assert_eq!(text, "https://info.paymaster.ru/path?q=1");
        assert_eq!(clean_domain(&text), Some("info.paymaster.ru".to_string()));

        // The first character replaces a prefilled host instead of appending to
        // it; typing over the box is how a domain gets corrected.
        let mut text = "ely.by".to_string();
        let mut edited = false;
        domain_push(&mut text, 'e', &mut edited);
        assert_eq!(text, "e");

        // A stray space or a control character never reaches the box, and a
        // pasted blob cannot grow past the cap.
        let mut text = String::new();
        let mut edited = true;
        domain_push(&mut text, ' ', &mut edited);
        domain_push(&mut text, '\u{1b}', &mut edited);
        assert!(text.is_empty(), "{text:?}");
        for _ in 0..(DOMAIN_MAX_CHARS + 10) {
            domain_push(&mut text, 'a', &mut edited);
        }
        assert_eq!(text.chars().count(), DOMAIN_MAX_CHARS);
    }

    /// The domain box announces its state with its own background — grey while
    /// the row is only selected, blue while it is being typed into — and the
    /// brackets and pad carry it too, so the box reads as one field. A pair of
    /// screenshots is not something a test can hold, so the escapes are.
    #[test]
    fn burst_domain_box_paints_its_state() {
        let msg = get_messages(Language::Ru);
        let all = vec![TlsFingerprint::Chrome107];
        let box_row = |editing: bool, text: &str| {
            burst_settings_rows(
                &msg,
                Language::Ru,
                BURST_ROW_DOMAIN,
                4,
                8,
                BurstTlsVersion::Tls13And12,
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
}

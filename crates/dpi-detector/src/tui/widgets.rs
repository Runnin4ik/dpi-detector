//! Panels, boxes and the width math behind them. Every row a screen draws goes
//! through [`frame_repaint`], so a row is never padded to a fixed width by hand.

use comfy_table::Color;
use dpi_core::classify::*;
use dpi_core::net::netinfo::flag_emoji;

use crate::tui::backend::{ascii_mode, plain_mode};

/// The box-drawing glyphs for the current mode, as
/// `(top-left, top-right, bottom-left, bottom-right, horizontal, vertical)`.
///
/// Every box in the TUI takes its border from here, so `--ascii` can never be
/// honoured by half the screens.
pub fn box_chars() -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if ascii_mode() {
        ("┌", "┐", "└", "┘", "─", "│")
    } else {
        ("╭", "╮", "╰", "╯", "─", "│")
    }
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
            '•' | '╌' | '–' | '—' => out.push('-'),
            '◉' | '●' => out.push_str("(x)"),
            '○' => out.push_str("( )"),
            '√' => out.push('√'),
            '↑' => out.push('^'),
            '↓' => out.push('v'),
            '←' => out.push('<'),
            '⚠' => out.push('!'),
            '≈' => out.push('~'),
            '×' => out.push('x'),
            // Map modern curved corners to standard CP866 single corners (0xDA, 0xBF, 0xC0, 0xD9)
            '╭' => out.push('┌'),
            '╮' => out.push('┐'),
            '╰' => out.push('└'),
            '╯' => out.push('┘'),
            // Preserve hardware CP866 single-line box drawing:
            // ─ (0xC4), │ (0xB3), ┌ (0xDA), ┐ (0xBF), └ (0xC0), ┘ (0xD9),
            // ├ (0xC3), ┤ (0xB4), ┬ (0xC2), ┴ (0xC1), ┼ (0xC5)
            // Preserve hardware CP866 single and double-line box drawing:
            // ─ (0xC4), │ (0xB3), ┌ (0xDA), ┐ (0xBF), └ (0xC0), ┘ (0xD9),
            // ├ (0xC3), ┤ (0xB4), ┬ (0xC2), ┴ (0xC1), ┼ (0xC5),
            // ╞ (0xC6), ═ (0xCD), ╪ (0xD8), ╡ (0xB5)
            '─' | '│' | '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼'
            | '╞' | '═' | '╪' | '╡' => out.push(c),
            _ => out.push(c),
        }
    }
    out
}

/// Glyph-safe string for the current output mode.
pub fn asc(s: &str) -> String {
    asc_with(s, ascii_mode())
}

/// Single-line box drawing table preset fully compatible with hardware CP866:
/// uses `│` (0xB3) instead of `┆` (U+2506) for column borders, eliminating
/// `?` character corruption on Windows legacy consoles and raster fonts.
pub const CP866_TABLE_PRESET: &str = "││──╞═╪╡│    ┬┴┌┐└┘";

pub(crate) fn table_preset() -> &'static str {
    CP866_TABLE_PRESET
}

/// Formats text with inline ANSI SGR color codes.
/// Using inline ANSI escapes inside comfy-table cells instead of `Cell.fg(...)`
/// avoids a crossterm bug on Windows without VT (Windows 7), where crossterm's
/// `StyledContent` drops all text on non-VT consoles during string formatting.
pub fn cell_color(text: &str, color: Color) -> String {
    let sgr = match color {
        Color::Reset => "\x1b[0m",
        Color::Black => "\x1b[30m",
        Color::DarkGrey => "\x1b[90m",
        Color::Red | Color::DarkRed => "\x1b[31m",
        Color::Green | Color::DarkGreen => "\x1b[32m",
        Color::Yellow | Color::DarkYellow => "\x1b[33m",
        Color::Blue | Color::DarkBlue => "\x1b[34m",
        Color::Magenta | Color::DarkMagenta => "\x1b[35m",
        Color::Cyan | Color::DarkCyan => "\x1b[36m",
        Color::White | Color::Grey => "\x1b[37m",
        _ => "\x1b[0m",
    };
    text.lines()
        .map(|l| format!("{}{}\x1b[0m", sgr, l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Joins multi-line cell parts, each line carrying its own inline ANSI color.
pub(crate) fn join_cell_colored(mut lines: Vec<(String, Color)>) -> String {
    if lines.is_empty() {
        lines.push(("—".to_string(), Color::DarkGrey));
    }
    lines
        .into_iter()
        .map(|(t, c)| cell_color(&t, c))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Country flag for the current mode (emoji needs a CJK/emoji font).
pub(crate) fn geo_country_ascii(cc: &str) -> String {
    if ascii_mode() {
        format!(" [{}]", cc.trim().to_uppercase())
    } else {
        format!(" {}", flag_emoji(cc))
    }
}

/// Warning mark for the current mode.
pub(crate) fn warn_mark() -> &'static str {
    if ascii_mode() {
        "!"
    } else {
        "⚠"
    }
}
pub const BOX_WIDTH: usize = 71;

/// Maps a probe status to its table cell color: green for OK, yellow for the
/// "no TLS 1.3 / no CA / local IP / DNS fail / NXDOMAIN" outcomes, dark grey
/// for Err, and red for the rest.
pub fn status_color(s: DpiStatus) -> Color {
    match s {
        DpiStatus::Ok => Color::Green,
        DpiStatus::NoTls13 | DpiStatus::NoCa => Color::Yellow,
        DpiStatus::LocalIp | DpiStatus::DnsFail | DpiStatus::NxDomain => Color::Yellow,
        DpiStatus::Err => Color::DarkGrey,
        _ => Color::Red,
    }
}

pub fn strip_ansi_len(s: &str) -> usize {
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
            count += unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        }
    }
    count
}

/// One element of a styled string: an SGR escape run, or a visible character
/// with its terminal cell width.
enum AnsiTok {
    Esc(String),
    Ch(char, usize),
}

fn ansi_tokens(s: &str) -> Vec<AnsiTok> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            let mut esc = String::from(c);
            for c2 in chars.by_ref() {
                esc.push(c2);
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            out.push(AnsiTok::Esc(esc));
        } else {
            out.push(AnsiTok::Ch(c, unicode_width::UnicodeWidthChar::width(c).unwrap_or(0)));
        }
    }
    out
}

/// SGR sequences still in effect at the end of `s` (empty when the text is
/// back to the default style).
fn active_sgr(s: &str) -> String {
    let mut active = String::new();
    for tok in ansi_tokens(s) {
        if let AnsiTok::Esc(e) = tok {
            if e == "\x1b[0m" {
                active.clear();
            } else if e.ends_with('m') {
                active.push_str(&e);
            }
        }
    }
    active
}

/// Terminates the line's open SGR: without it the panel's padding, which is
/// written after the content in the same escape run, would inherit the colour.
fn close_sgr(line: &mut String) {
    if !active_sgr(line).is_empty() {
        line.push_str("\x1b[0m");
    }
}

/// Splits a styled string at the last possible space so it fits `width` cells;
/// a single token wider than the column is broken by character. Every line is
/// self-contained: a style open at the break is re-armed on the next line, so
/// the colour of a wrapped value survives the break.
pub(crate) fn wrap_ansi(s: &str, width: usize) -> Vec<String> {
    let width = width.max(8);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    // Byte offset of the space the line may be broken at.
    let mut brk: Option<usize> = None;
    for tok in ansi_tokens(s) {
        match tok {
            AnsiTok::Esc(e) => cur.push_str(&e),
            AnsiTok::Ch(c, cw) => {
                if cur_w + cw > width {
                    // Close the line and carry the open SGR over to the next one.
                    // The break is at the last space; a single token wider than
                    // the column is broken where it stands (by character).
                    let tail = brk.take().map(|idx| cur.split_off(idx));
                    let state = active_sgr(&cur);
                    close_sgr(&mut cur);
                    lines.push(std::mem::take(&mut cur));
                    cur.push_str(&state);
                    if let Some(tail) = tail {
                        cur.push_str(tail.trim_start_matches(' '));
                    }
                    cur_w = strip_ansi_len(&cur);
                }
                if c == ' ' {
                    // Remember the newest space: the line is filled greedily.
                    brk = Some(cur.len());
                }
                cur.push(c);
                cur_w += cw;
            }
        }
    }
    if !cur.is_empty() || lines.is_empty() {
        close_sgr(&mut cur);
        lines.push(cur);
    }
    lines
}

/// Erase to the end of the current row (`EL`), empty in plain (ANSI-free) mode.
fn erase_line() -> &'static str {
    if plain_mode() {
        ""
    } else {
        "\x1b[K"
    }
}

/// Erase everything below the cursor (`ED`), empty in plain (ANSI-free) mode.
fn erase_below() -> &'static str {
    if plain_mode() {
        ""
    } else {
        "\x1b[J"
    }
}

/// One repaint of a multi-line frame (menu) drawn from the top-left corner.
///
/// Every row is padded to the widest row of this frame *and* to the widest row
/// of the previous one, so a line that shrank between repaints - another
/// language, a shorter counter - cannot leave glyphs of the longer line behind.
/// The erase sequences cover what padding cannot: `EL` after each row because a
/// terminal with a CJK font advances ambiguous glyphs (`│`, `↑`, `←`, `•`) by two
/// columns, so our width math lands a few cells short of the real row end, and
/// `ED` once at the end to drop rows a previous, wrapped frame left below this
/// one. Non-VT consoles get the padding only: their cells are one column wide,
/// which is exactly what the padding is measured in, and they ignore both
/// escapes.
///
/// `prev_max` is the widest row of the previous frame, updated in place.
pub fn frame_repaint(rows: &[String], prev_max: &mut usize) -> String {
    let widths: Vec<usize> = rows.iter().map(|r| strip_ansi_len(r)).collect();
    let widest = widths.iter().copied().max().unwrap_or(0);
    let target = widest.max(*prev_max);
    let mut out = String::with_capacity(rows.len() * (target + 16));
    for (row, width) in rows.iter().zip(widths.iter()) {
        out.push_str(row);
        out.push_str(&" ".repeat(target - width));
        out.push_str(erase_line());
        out.push_str("\r\n");
    }
    out.push_str(erase_below());
    *prev_max = widest;
    out
}

pub fn panel_to_string(title: &str, lines: &[String]) -> String {
    panel_with(title, lines, BOX_WIDTH, false, "1;36")
}

/// Panel with explicit width, title alignment and border SGR code.
/// Banner titles are left-aligned cyan; the netinfo panel's is centered and dim.
pub fn panel_with(title: &str, lines: &[String], width: usize, centered: bool, border: &str) -> String {
    // Glyph-safe content first: widths are measured after replacement.
    let title_bidi = crate::i18n::format_bidi_str(title);
    let title_clean = format!(" {} ", asc(&title_bidi));
    let lines: Vec<String> = lines.iter().map(|l| asc(l)).collect();
    let mut out = String::new();
    // Titles may carry SGR escapes (e.g. the bold banner title): measure visible
    // width only, and re-arm the border color after the title so an inner reset
    // cannot bleach the border run or shift the right edge.
    let title_len = strip_ansi_len(&title_clean);
    let inner = width.saturating_sub(2);
    let (tl, tr, bl, br, hb, vb) = box_chars();
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

#[cfg(test)]
mod tests {
    use super::*;
    /// Minimal column/row model of a VT terminal: enough to prove that a repaint
    /// leaves nothing of the previous frame behind. SGR sequences are skipped,
    /// `EL` clears to the row end, `ED` clears from the cursor down, a write past
    /// the last column wraps, and - as in a console with a CJK font - the
    /// ambiguous glyphs the menu draws (`│`, `↑`, `←`, `●`) take two columns.
    struct Screen {
        width: usize,
        rows: Vec<Vec<char>>,
        row: usize,
        col: usize,
    }

    impl Screen {
        fn new(width: usize) -> Self {
            Self { width, rows: vec![vec![' '; width]], row: 0, col: 0 }
        }

        fn put(&mut self, c: char, width: usize) {
            if self.col >= self.width {
                self.row += 1;
                self.col = 0;
                if self.rows.len() <= self.row {
                    self.rows.push(vec![' '; self.width]);
                }
            }
            self.rows[self.row][self.col] = c;
            for k in 1..width {
                if self.col + k < self.width {
                    self.rows[self.row][self.col + k] = '\u{0}';
                }
            }
            self.col += width;
        }

        /// Start of the frame: `frame_repaint` tests paint every frame from the
        /// same row so only the row content is under test.
        fn home(&mut self) {
            self.row = 0;
            self.col = 0;
        }

        fn erase_row_tail(&mut self) {
            for c in self.col..self.width {
                self.rows[self.row][c] = ' ';
            }
        }

        fn write(&mut self, s: &str) {
            let chars: Vec<char> = s.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let c = chars[i];
                if c == '\x1b' {
                    if chars.get(i + 1) == Some(&'[') {
                        let mut j = i + 2;
                        while j < chars.len() && !chars[j].is_ascii_alphabetic() {
                            j += 1;
                        }
                        match chars.get(j) {
                            Some('K') => self.erase_row_tail(),
                            Some('J') => {
                                self.erase_row_tail();
                                for r in self.row + 1..self.rows.len() {
                                    self.rows[r] = vec![' '; self.width];
                                }
                            }
                            _ => {}
                        }
                        i = j + 1;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                match c {
                    '\r' => self.col = 0,
                    '\n' => {
                        self.row += 1;
                        if self.rows.len() <= self.row {
                            self.rows.push(vec![' '; self.width]);
                        }
                    }
                    _ => {
                        let wide = matches!(c, '│' | '↑' | '↓' | '←' | '→' | '●' | '○' | '►');
                        self.put(c, if wide { 2 } else { 1 });
                    }
                }
                i += 1;
            }
        }

        /// Visible text: cells written and not overwritten since.
        fn text(&self) -> String {
            self.rows
                .iter()
                .map(|r| r.iter().filter(|c| **c != '\u{0}').collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
        }
    }

    /// Regression: switching the menu from Farsi to English left `rooj` (the tail
    /// of `Khorooj`) on the footer row, because the repaint only padded to a
    /// fixed width and a CJK font renders `│`/`↑` two columns wide, so the row was
    /// wider than the pad. The frames below are the real footer shapes.
    #[test]
    fn repaint_leaves_no_tail_of_a_longer_frame() {
        let fa = vec![
            "  ╭─ Параметры и выбор тестов ─╮".to_string(),
            "  ↑↓/WS  Peymayesh │ ←→/AD  Taghir │ 0-7  Test ha │ Enter  Shoroo │ Q  Khorooj".to_string(),
        ];
        let en = vec![
            "  ╭─ Parameters & test selection ─╮".to_string(),
            "  ↑↓/WS  row │ ←→/AD  change │ 0-7  tests │ Enter  start │ Q  quit".to_string(),
        ];

        let mut screen = Screen::new(80);
        let mut prev_max = 0usize;
        screen.home();
        screen.write(&frame_repaint(&fa, &mut prev_max));
        screen.home();
        screen.write(&frame_repaint(&en, &mut prev_max));
        let text = screen.text();
        assert!(text.contains("Q  quit"), "the English footer is intact:\n{text}");
        assert!(!text.contains("rooj"), "no Farsi tail survives:\n{text}");
        assert!(!text.contains("Khorooj"), "no Farsi footer survives:\n{text}");
    }

    /// A frame whose rows wrap (the long Farsi footer on an 80-column console)
    /// occupies one row more than the frame that replaces it; the row below the
    /// new frame must be blanked as well.
    #[test]
    fn repaint_clears_the_row_a_wrapped_frame_left_below() {
        let long = vec!["  Q  Khorooj az in barname".to_string()];
        let short = vec!["  Q  quit".to_string()];

        let mut screen = Screen::new(40);
        let mut prev_max = 0usize;
        screen.home();
        screen.write(&frame_repaint(&long, &mut prev_max));
        assert!(screen.text().contains("Khorooj"), "long frame is on screen");
        screen.home();
        screen.write(&frame_repaint(&short, &mut prev_max));
        let text = screen.text();
        assert!(text.contains("Q  quit"), "short frame replaced it:\n{text}");
        assert!(!text.contains("rooj"), "wrapped tail is gone:\n{text}");
    }

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
        assert_eq!(asc_with("[√] ● ○", true), "[√] (x) ( )");
        assert_eq!(asc_with("↑↓ ←→", true), "^v <->");
        assert_eq!(asc_with("✓ done", true), "[OK] done");
        assert_eq!(asc_with("⚠ ≈ × — –", true), "! ~ x - -");
        assert_eq!(asc_with("╭─╮ │ └┘", true), "┌─┐ │ └┘");
        // ANSI escapes pass through untouched.
        assert_eq!(asc_with("\x1b[1;32m✓\x1b[0m", true), "\x1b[1;32m[OK]\x1b[0m");
        // Cyrillic passes through; arrows become ASCII in ascii mode.
        assert_eq!(asc_with("8.8.8.8→GOOGLE мс", true), "8.8.8.8->GOOGLE мс");
    }

    /// The domain table colors a foreign redirect red `REDIR` and a legitimate
    /// response green `OK` (`status_color`; a red `REDIR` is not an ok status).
    /// The badge itself stays canonical Latin in every language (Rule 4), and the
    /// cell colour survives `asc()` in ASCII mode.
    #[test]
    fn foreign_redirect_cell_is_red() {
        use crate::i18n::Language;
        use crate::i18n::get_messages;
        for lang in Language::ALL {
            let msg = get_messages(lang);
            let cell = |s: DpiStatus| cell_color(s.display_label(), status_color(s));
            assert_eq!(cell(DpiStatus::RedirSuspect), "\x1b[31mREDIR\x1b[0m", "{:?}", msg.lang);
            assert_eq!(cell(DpiStatus::Ok), "\x1b[32mOK\x1b[0m", "{:?}", msg.lang);
            assert!(!DpiStatus::RedirSuspect.is_ok_status());
            assert!(asc_with(&cell(DpiStatus::RedirSuspect), true).contains("\x1b[31mREDIR\x1b[0m"));
        }
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

    #[test]
    fn test_cp866_table_preset_and_cell_color() {
        use comfy_table::*;
        let mut table = Table::new();
        table.load_preset(table_preset()).set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec![
            Cell::new("ID"),
            Cell::new("ASN"),
            Cell::new("Status"),
            Cell::new("Detail"),
        ]);
        table.add_row(vec![
            Cell::new("AK-01"),
            Cell::new(cell_color("AS12345", Color::Yellow)),
            Cell::new(cell_color("OK", Color::Green)),
            Cell::new("8.8s"),
        ]);
        let ts = table.to_string();
        assert!(ts.contains('│'), "CP866 single vertical line present");
        assert!(!ts.contains('┆'), "no U+2506 non-CP866 separators");
        assert!(ts.contains("AS12345"), "cell content preserved");
        assert!(ts.contains("OK"), "cell content preserved");
        assert!(ts.contains("\x1b[33mAS12345\x1b[0m"), "inline ANSI color preserved");
    }
}

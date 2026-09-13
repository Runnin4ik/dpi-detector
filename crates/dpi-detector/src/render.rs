use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::*;
use dpi_core::config::AppConfig;
use dpi_core::dns::availability::{
    known_resolver, net24, org_label, subst_counts, DnsAvailReport, ProbeKind,
};
use dpi_core::dns::availability::DnsAnswer;
use dpi_core::i18n::{
    detail_lines, detail_text, fingerprint_label, fmt_size, fmt_speed, format_bidi, Messages,
};
use dpi_core::net::netinfo::{flag_emoji, is_tun_name, SystemDnsInfo};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::probe::domains::{fake_ip_type, DomainEntry, DomainStats, FakeIpType};
use dpi_core::probe::burst::{BurstReport, BurstSettings};
use dpi_core::probe::telegram::TelegramFullReport;
use dpi_core::probe::whitelist::{AsVerdict, WhitelistReport, NO_SNI_TAG};
use dpi_core::profile::RegionProfile;

use std::collections::{HashMap, HashSet};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dpi_core::ProgressBlock;
/// ASCII-only output for legacy consoles (see `--ascii`).
static ASCII_MODE: OnceLock<bool> = OnceLock::new();
static PLAIN_MODE: OnceLock<bool> = OnceLock::new();
static HAS_VT: OnceLock<bool> = OnceLock::new();

/// Enables ASCII-only output (font-safe glyphs, ASCII table borders).
pub fn set_ascii_mode(v: bool) {
    let _ = ASCII_MODE.set(v);
}

/// Whether ASCII-only output is on.
pub fn ascii_mode() -> bool {
    *ASCII_MODE.get().unwrap_or(&false)
}

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

/// Enables plain (ANSI-free) output for terminals without color support.
pub fn set_plain_mode(v: bool) {
    let _ = PLAIN_MODE.set(v);
}

/// Whether plain (ANSI-free) output is enabled.
pub fn plain_mode() -> bool {
    *PLAIN_MODE.get().unwrap_or(&false)
}

/// Sets whether the terminal supports native virtual terminal processing (VT100/ANSI).
pub fn set_has_vt(v: bool) {
    let _ = HAS_VT.set(v);
}

/// Whether native virtual terminal processing is supported.
pub fn has_vt() -> bool {
    *HAS_VT.get().unwrap_or(&true)
}
/// Strips all ANSI SGR escape sequences (`\x1b[...m` and `\x1b[...K`) from a string.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Formats a string for terminal display, respecting plain and ASCII modes.
pub fn clean_output(s: &str) -> String {
    if plain_mode() {
        strip_ansi(&asc(s))
    } else if ascii_mode() {
        asc(s)
    } else {
        s.to_string()
    }
}
/// Writes a string to stdout, transparently translating ANSI color codes to
/// Win32 Console API calls (SetConsoleTextAttribute) on legacy consoles (Windows 7 / 8).
pub fn output_str(s: &str) {
    #[cfg(windows)]
    {
        use std::io::IsTerminal;
        if !has_vt() && !plain_mode() && std::io::stdout().is_terminal() {
            write_win32_ansi(s);
            return;
        }
    }
    let mut out = std::io::stdout();
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
}

#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct COORD { x: i16, y: i16 }
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SMALL_RECT { left: i16, top: i16, right: i16, bottom: i16 }
#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CONSOLE_SCREEN_BUFFER_INFO {
    size: COORD,
    cursor_pos: COORD,
    attributes: u16,
    window: SMALL_RECT,
    max_size: COORD,
}
#[cfg(windows)]
const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;

#[cfg(windows)]
fn write_win32_ansi(s: &str) {
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn SetConsoleTextAttribute(hConsoleOutput: isize, wAttributes: u16) -> i32;
        fn WriteConsoleW(
            hConsoleOutput: isize,
            lpBuffer: *const u16,
            nNumberOfCharsToWrite: u32,
            lpNumberOfCharsWritten: *mut u32,
            lpReserved: *mut std::ffi::c_void,
        ) -> i32;
        fn GetConsoleScreenBufferInfo(
            hConsoleOutput: isize,
            lpConsoleScreenBufferInfo: *mut CONSOLE_SCREEN_BUFFER_INFO,
        ) -> i32;
    }

    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle == 0 || handle == -1 {
        let _ = std::io::stdout().write_all(s.as_bytes());
        return;
    }

    static DEFAULT_ATTR: OnceLock<u16> = OnceLock::new();
    let default_attr = *DEFAULT_ATTR.get_or_init(|| {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } != 0 {
            info.attributes
        } else {
            0x0007
        }
    });

    let mut cur_attr = default_attr;
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == 0x1b && i + 1 < len && bytes[i + 1] == b'[' {
            let start = i;
            i += 2;
            while i < len && !bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            if i < len && bytes[i] == b'm' {
                let code_str = std::str::from_utf8(&bytes[start + 2..i]).unwrap_or("");
                cur_attr = apply_ansi_code(code_str, cur_attr, default_attr);
                unsafe { SetConsoleTextAttribute(handle, cur_attr) };
                i += 1;
                continue;
            } else if i < len {
                i += 1;
                continue;
            }
        }

        let start = i;
        while i < len && !(bytes[i] == 0x1b && i + 1 < len && bytes[i + 1] == b'[') {
            i += 1;
        }
        let chunk = &s[start..i];
        let utf16: Vec<u16> = chunk.encode_utf16().collect();
        let mut written = 0;
        unsafe {
            WriteConsoleW(
                handle,
                utf16.as_ptr(),
                utf16.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );
        }
    }
}

/// Returns the cursor to column 0 of the row `drawn` lines above it: the first
/// row of the frame the previous paint left on screen. Nothing is erased and no
/// absolute home is used, so the output written above the frame stays where it
/// is and stays scrollable.
///
/// Written straight to stdout rather than through `output_str`: the legacy
/// translator below drops every escape that is not SGR, and on those consoles
/// (Windows 7/8) the move is done through the console API instead.
pub fn frame_home(drawn: u16) {
    if drawn == 0 {
        return;
    }
    #[cfg(windows)]
    {
        if !has_vt() {
            win32_frame_home(drawn);
            return;
        }
    }
    let mut out = std::io::stdout();
    let _ = out.write_all(format!("\x1b[{}A\r", drawn).as_bytes());
    let _ = out.flush();
}

#[cfg(windows)]
fn win32_frame_home(drawn: u16) {
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn GetConsoleScreenBufferInfo(
            hConsoleOutput: isize,
            lpConsoleScreenBufferInfo: *mut CONSOLE_SCREEN_BUFFER_INFO,
        ) -> i32;
        fn SetConsoleCursorPosition(hConsoleOutput: isize, dwCursorPosition: COORD) -> i32;
    }
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle == 0 || handle == -1 {
        return;
    }
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } != 0 {
        // Buffer coordinates, clamped: an escape would wrap past the top row of
        // the screen buffer and come back up from the bottom.
        let row = (info.cursor_pos.y as i32 - drawn as i32).max(0) as i16;
        unsafe { SetConsoleCursorPosition(handle, COORD { x: 0, y: row }) };
    }
}

#[cfg(windows)]
fn apply_ansi_code(code: &str, mut cur: u16, default_attr: u16) -> u16 {
    const FOREGROUND_BLUE: u16 = 0x0001;
    const FOREGROUND_GREEN: u16 = 0x0002;
    const FOREGROUND_RED: u16 = 0x0004;
    const FOREGROUND_INTENSITY: u16 = 0x0008;
    const BACKGROUND_BLUE: u16 = 0x0010;
    const BACKGROUND_GREEN: u16 = 0x0020;
    const BACKGROUND_RED: u16 = 0x0040;
    const BACKGROUND_INTENSITY: u16 = 0x0080;
    // RGB bits only: intensity is a separate SGR attribute (`1` bright / `2`
    // dim) and has to survive a color code, or `\x1b[1;32m` lands on a legacy
    // console as plain dark green.
    const FG_MASK: u16 = 0x0007;
    const FG_ATTR_MASK: u16 = FG_MASK | FOREGROUND_INTENSITY;
    const BG_MASK: u16 = 0x00F0;

    if code == "0" || code.is_empty() {
        return default_attr;
    }

    let parts: Vec<&str> = code.split(';').collect();
    let mut idx = 0;
    while idx < parts.len() {
        let part = parts[idx];
        match part {
            "0" => cur = default_attr,
            "1" => cur |= FOREGROUND_INTENSITY,
            "2" => cur &= !FOREGROUND_INTENSITY,
            "30" => cur &= !FG_MASK,
            "31" => cur = (cur & !FG_MASK) | FOREGROUND_RED,
            "32" => cur = (cur & !FG_MASK) | FOREGROUND_GREEN,
            "33" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_GREEN,
            "34" => cur = (cur & !FG_MASK) | FOREGROUND_BLUE,
            "35" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_BLUE,
            "36" => cur = (cur & !FG_MASK) | FOREGROUND_GREEN | FOREGROUND_BLUE,
            "37" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
            "38" if idx + 4 < parts.len() && parts[idx + 1] == "2" => {
                let r: u8 = parts[idx + 2].parse().unwrap_or(0);
                let g: u8 = parts[idx + 3].parse().unwrap_or(0);
                let b: u8 = parts[idx + 4].parse().unwrap_or(0);
                let mut fg = 0;
                if r > 64 { fg |= FOREGROUND_RED; }
                if g > 64 { fg |= FOREGROUND_GREEN; }
                if b > 64 { fg |= FOREGROUND_BLUE; }
                if r > 160 || g > 160 || b > 160 { fg |= FOREGROUND_INTENSITY; }
                cur = (cur & !FG_ATTR_MASK) | fg;
                idx += 4;
            }
            "38" if idx + 2 < parts.len() && parts[idx + 1] == "5" => {
                let col: u8 = parts[idx + 2].parse().unwrap_or(0);
                let fg = match col {
                    0 => 0,
                    1 => FOREGROUND_RED,
                    2 => FOREGROUND_GREEN,
                    3 => FOREGROUND_RED | FOREGROUND_GREEN,
                    4 => FOREGROUND_BLUE,
                    5 => FOREGROUND_RED | FOREGROUND_BLUE,
                    6 => FOREGROUND_GREEN | FOREGROUND_BLUE,
                    7 => FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
                    8 => FOREGROUND_INTENSITY,
                    9 => FOREGROUND_RED | FOREGROUND_INTENSITY,
                    10 => FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    11 => FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
                    12 => FOREGROUND_BLUE | FOREGROUND_INTENSITY,
                    13 => FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
                    14 => FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
                    15 => FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
                    _ => FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
                };
                cur = (cur & !FG_ATTR_MASK) | fg;
                idx += 2;
            }
            "90" => cur = (cur & !FG_MASK) | FOREGROUND_INTENSITY,
            "91" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_INTENSITY,
            "92" => cur = (cur & !FG_MASK) | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
            "93" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
            "94" => cur = (cur & !FG_MASK) | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
            "95" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
            "96" => cur = (cur & !FG_MASK) | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
            "97" => cur = (cur & !FG_MASK) | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
            "40" => cur &= !BG_MASK,
            "41" => cur = (cur & !BG_MASK) | BACKGROUND_RED,
            "42" => cur = (cur & !BG_MASK) | BACKGROUND_GREEN,
            "43" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_GREEN,
            "44" => cur = (cur & !BG_MASK) | BACKGROUND_BLUE,
            "45" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_BLUE,
            "46" => cur = (cur & !BG_MASK) | BACKGROUND_GREEN | BACKGROUND_BLUE,
            "47" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE,
            "100" => cur = (cur & !BG_MASK) | BACKGROUND_INTENSITY,
            "101" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_INTENSITY,
            "102" => cur = (cur & !BG_MASK) | BACKGROUND_GREEN | BACKGROUND_INTENSITY,
            "103" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_INTENSITY,
            "104" => cur = (cur & !BG_MASK) | BACKGROUND_BLUE | BACKGROUND_INTENSITY,
            "105" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_BLUE | BACKGROUND_INTENSITY,
            "106" => cur = (cur & !BG_MASK) | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY,
            "107" => cur = (cur & !BG_MASK) | BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE | BACKGROUND_INTENSITY,
            _ => {}
        }
        idx += 1;
    }
    cur
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

fn table_preset() -> &'static str {
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
fn join_cell_colored(mut lines: Vec<(String, Color)>) -> String {
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
fn geo_country_ascii(cc: &str) -> String {
    if ascii_mode() {
        format!(" [{}]", cc.trim().to_uppercase())
    } else {
        format!(" {}", flag_emoji(cc))
    }
}

/// Warning mark for the current mode.
fn warn_mark() -> &'static str {
    if ascii_mode() {
        "!"
    } else {
        "⚠"
    }
}
pub const BOX_WIDTH: usize = 71;

/// Maps a probe status to its table cell color (mirrors the Rich markup).
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
/// the colour of a wrapped value survives the break (mirrors what Rich does
/// when it wraps a table cell).
fn wrap_ansi(s: &str, width: usize) -> Vec<String> {
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
/// Mirrors Rich: banner is left-titled cyan, netinfo centered dim.
pub fn panel_with(title: &str, lines: &[String], width: usize, centered: bool, border: &str) -> String {
    // Glyph-safe content first: widths are measured after replacement.
    let title_bidi = dpi_core::i18n::format_bidi_str(title);
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
struct BlockState {
    /// Canonical protocol token (rule 4), empty for a single-counter phase.
    token: &'static str,
    done: usize,
    total: usize,
}

struct ProgressState {
    desc: String,
    blocks: Vec<BlockState>,
    started: Instant,
    /// Width of the last drawn line, so a shrinking counter cannot leave
    /// digits behind on the terminal.
    drawn: usize,
}

/// How often the line is redrawn while nothing finishes, so the elapsed clock
/// keeps moving and a slow unit does not make the phase look hung.
const REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// `mm:ss`, or `h:mm:ss` past the hour.
fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

/// One progress line: `desc  12/50 · 00:07`. A multi-block phase (test 1) shows
/// every counter that is running at the same time instead —
/// `DNS  UDP 12/50 · DoH 2/37 · DoT 0/34 · EGRESS 5/50 · 00:31` — because the
/// blocks overlap and no single sequential counter describes them. Only the
/// elapsed clock is drawn, never an estimate: per-unit cost differs by an order
/// of magnitude across blocks, so a projected rate would lie. The trailing
/// ellipsis of the phase descriptions is dropped, the live numbers already say
/// "running".
fn progress_line(desc: &str, blocks: &[BlockState], elapsed: Duration) -> String {
    let mut line = desc.trim_end_matches(['.', ' ']).to_string();
    if blocks.len() == 1 && blocks[0].token.is_empty() {
        line.push_str(&format!("  {}/{}", blocks[0].done, blocks[0].total));
    } else if !blocks.is_empty() {
        let counters: Vec<String> = blocks
            .iter()
            .map(|b| format!("{} {}/{}", b.token, b.done, b.total))
            .collect();
        line.push_str("  ");
        line.push_str(&counters.join(" · "));
    }
    line.push_str(&format!(" · {}", fmt_dur(elapsed)));
    line
}

/// A timer that redraws the line while a phase runs.
struct Refresher {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Refresher {
    fn idle() -> Self {
        Self { stop: Arc::new(AtomicBool::new(false)), handle: None }
    }
}

/// Live one-line progress on stderr (mirrors rich transient `Progress`).
/// Draws only when stderr is a TTY; silent otherwise so pipes and the report
/// file stay byte-clean.
pub struct LiveProgress {
    state: Mutex<ProgressState>,
    /// Weak self-reference for the refresher thread (never a cycle).
    me: Mutex<Weak<LiveProgress>>,
    refresher: Mutex<Refresher>,
    tty: bool,
}

impl LiveProgress {
    pub fn new() -> Arc<Self> {
        let live = Arc::new(Self {
            state: Mutex::new(ProgressState {
                desc: String::new(),
                blocks: Vec::new(),
                started: Instant::now(),
                drawn: 0,
            }),
            me: Mutex::new(Weak::new()),
            refresher: Mutex::new(Refresher::idle()),
            tty: std::io::stderr().is_terminal(),
        });
        if let Ok(mut me) = live.me.lock() {
            *me = Arc::downgrade(&live);
        }
        live
    }

    /// Starts a single-counter phase: resets the counter and its clock.
    pub fn set(&self, desc: String, total: usize) {
        self.start(desc, vec![BlockState { token: "", done: 0, total }]);
    }

    /// Starts a sequential run of stages that share one line (test 2: DNS →
    /// TLS 1.3 → TLS 1.2 → HTTP): every stage keeps its own counter, the
    /// counters already finished stay on screen and the clock spans the whole
    /// run instead of restarting at each stage.
    pub fn begin_stages(&self, desc: String, stages: &[(ProgressBlock, usize)]) {
        self.start(
            desc,
            stages
                .iter()
                .map(|(block, total)| BlockState { token: block.token(), done: 0, total: *total })
                .collect(),
        );
    }

    /// Corrects the total of a stage that is already on the line, for when its
    /// phase reports the count it actually iterates.
    pub fn set_total(&self, block: ProgressBlock, total: usize) {
        let changed = match self.state.lock() {
            Ok(mut st) => match st.blocks.iter_mut().find(|b| b.token == block.token()) {
                Some(b) if b.total != total => {
                    b.total = total;
                    true
                }
                _ => false,
            },
            Err(_) => false,
        };
        if changed {
            self.draw();
        }
    }

    /// Starts a phase whose blocks run concurrently and are all reported.
    pub fn set_blocks(&self, desc: String, blocks: &[(ProgressBlock, usize)]) {
        self.start(
            desc,
            blocks
                .iter()
                .map(|(block, total)| BlockState { token: block.token(), done: 0, total: *total })
                .collect(),
        );
    }

    fn start(&self, desc: String, blocks: Vec<BlockState>) {
        if let Ok(mut st) = self.state.lock() {
            st.desc = desc;
            st.blocks = blocks;
            st.started = Instant::now();
        }
        self.start_refresher();
        self.draw();
    }

    /// Advances the single counter of the current phase.
    pub fn tick(&self) {
        if self.bump_first() {
            self.draw();
        }
    }

    /// Advances the counter of `block` in a multi-block phase.
    pub fn bump(&self, block: ProgressBlock) {
        let advanced = match self.state.lock() {
            Ok(mut st) => match st.blocks.iter_mut().find(|b| b.token == block.token()) {
                Some(b) => {
                    b.done += 1;
                    true
                }
                None => false,
            },
            Err(_) => false,
        };
        if advanced {
            self.draw();
        }
    }

    fn bump_first(&self) -> bool {
        match self.state.lock() {
            Ok(mut st) => match st.blocks.first_mut() {
                Some(b) => {
                    b.done += 1;
                    true
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// Clears the line and stops redrawing (transient: nothing remains).
    pub fn finish(&self) {
        self.stop_refresher();
        if !self.tty {
            return;
        }
        let drawn = self.state.lock().map(|st| st.drawn).unwrap_or(0);
        if has_vt() {
            eprint!("\x1b[2K\r");
        } else {
            eprint!("\r{}\r", " ".repeat(drawn.max(79)));
        }
        let _ = std::io::stderr().flush();
    }

    fn start_refresher(&self) {
        if !self.tty {
            return;
        }
        self.stop_refresher();
        let weak = match self.me.lock() {
            Ok(me) => me.clone(),
            Err(_) => return,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                std::thread::sleep(REFRESH_INTERVAL);
                if stop_c.load(Ordering::SeqCst) {
                    break;
                }
                match weak.upgrade() {
                    Some(live) => live.draw(),
                    None => break,
                }
            }
        });
        if let Ok(mut r) = self.refresher.lock() {
            *r = Refresher { stop, handle: Some(handle) };
        }
    }

    fn stop_refresher(&self) {
        let old = match self.refresher.lock() {
            Ok(mut r) => std::mem::replace(&mut *r, Refresher::idle()),
            Err(_) => return,
        };
        old.stop.store(true, Ordering::SeqCst);
        if let Some(h) = old.handle {
            let _ = h.join();
        }
    }

    fn draw(&self) {
        if !self.tty {
            return;
        }
        if let Ok(mut st) = self.state.lock() {
            let elapsed = st.started.elapsed();
            let text = progress_line(&st.desc, &st.blocks, elapsed);
            // Pad over the tail of a longer previous line before parking the
            // cursor: `\r` alone only moves it, it does not erase.
            let width = text.chars().count();
            let pad = st.drawn.saturating_sub(width);
            eprint!("\r  {}{}", text, " ".repeat(pad));
            let _ = std::io::stderr().flush();
            st.drawn = width;
        }
    }
}

/// Indeterminate spinner for phases without a total (mirrors
/// `console.status(..., spinner="line")`, frames `- \ | /`).
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    tty: bool,
}

impl Spinner {
    pub fn start(desc: &str) -> Self {
        let tty = std::io::stderr().is_terminal();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if tty {
            let stop_c = Arc::clone(&stop);
            let desc = desc.to_string();
            Some(std::thread::spawn(move || {
                let frames = ["-", "\\", "|", "/"];
                let mut i = 0;
                while !stop_c.load(Ordering::SeqCst) {
                    eprint!("\r  {} {}   ", desc, frames[i % 4]);
                    let _ = std::io::stderr().flush();
                    i += 1;
                    std::thread::sleep(Duration::from_millis(120));
                }
            }))
        } else {
            None
        };
        Self { stop, handle, tty }
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.tty {
            if has_vt() {
                eprint!("\x1b[2K\r");
            } else {
                eprint!("\r                                                                               \r");
            }
            let _ = std::io::stderr().flush();
        }
    }
}

pub fn render_banner(msg: &Messages, _profile: RegionProfile, badge: &str) -> String {
    let badge_colored = if badge.starts_with("✓") {
        format!("\x1b[38;2;90;247;142m{}\x1b[0m", badge)
    } else if badge.starts_with("↑") {
        format!("\x1b[33m{}\x1b[0m", badge)
    } else {
        format!("\x1b[2m{}\x1b[0m", badge)
    };
    let version_line = format!("DPI Detector v{}", env!("CARGO_PKG_VERSION"));
    let row1 = format!(
        "  \x1b[2m{}\x1b[0m \x1b[38;2;214;180;255mRunni\x1b[0m \x1b[36m•\x1b[0m \x1b[2mGitHub:\x1b[0m Runnin4ik/dpi-detector",
        msg.author
    );
    let row2 = format!(
        "  \x1b[2m{}\x1b[0m t.me/DPI_detector \x1b[36m•\x1b[0m {}",
        msg.chat, badge_colored
    );
    panel_with(&version_line, &[row1, row2], BOX_WIDTH, false, "36")
}
/// Active TLS fingerprint line(s) for the human report header (text mode only).
/// Always one line with the profile (`Fingerprint: FIREFOX (firefox 148)`) using the
/// canonical token and label; the translated caveat follows on a second line for every
/// non-default profile (with RUSTLS it is irrelevant noise). The `[!]` prefix
/// and colors are added here, never stored in i18n (rule 4 keeps
/// JA3/JA4/ClientHello/TLS/RUSTLS/FIREFOX/CHROME/SAFARI untranslated there too).
pub fn render_fingerprint_header(fp: TlsFingerprint, msg: &Messages) -> String {
    let label = fingerprint_label(fp, msg.lang);
    // The default profile's label repeats its code ("rustls (default)" against
    // the RUSTLS token), which read as "RUSTLS (rustls (default))": a label
    // that starts with the code keeps only the qualifier.
    let head = match label.strip_prefix(fp.code()) {
        Some(qualifier) => format!("{}: {}{}", msg.fingerprint_label, fp.token(), qualifier),
        None => format!("{}: {} ({})", msg.fingerprint_label, fp.token(), label),
    };
    if fp != TlsFingerprint::Rustls {
        let note = format!("\x1b[33m[!]\x1b[0m \x1b[2m{}\x1b[0m", msg.fingerprint_note);
        format!("{}\n{}", head, note)
    } else {
        head
    }
}

// ─── Test 0: network & system ─────────────────────────────────────────────────

/// TTLB cell (mirrors `_ttlb_str`).
#[derive(Debug, Clone)]
pub enum NetTtlb {
    Timeout,
    Ms(u64),
}
/// Per-family network fact (mirrors the `info["v4"]` / `info["v6"]` dicts).
#[derive(Debug, Clone)]
pub struct NetFamilyInfo {
    pub ip: String,
    pub ttlb: NetTtlb,
    pub subnet: String,
    pub org: String,
    pub asn: String,
    pub cc: String,
}

pub struct NetInfoData {
    pub v4: Option<NetFamilyInfo>,
    pub v6: Option<NetFamilyInfo>,
    /// Legacy empty-dict branch: placeholder rows.
    pub empty: bool,
}

/// Value color (mirrors `_v`): red "timeout", cyan otherwise.
fn cyan_val(v: &str) -> String {
    if v == "timeout" {
        format!("\x1b[31m{}\x1b[0m", v)
    } else {
        format!("\x1b[36m{}\x1b[0m", v)
    }
}

fn dim_val(v: &str) -> String {
    format!("\x1b[2m{}\x1b[0m", v)
}

fn ttlb_str(t: &NetTtlb, msg: &Messages) -> String {
    match t {
        NetTtlb::Timeout => format!("\x1b[31m{}\x1b[0m", msg.timeout_label),
        NetTtlb::Ms(ms) => format!("\x1b[2m{} {}\x1b[0m", ms, msg.ms_unit),
    }
}

/// DNS block with 70-column wrap (mirrors `_dns_block_lines`).
/// Widths are char counts; the tail glues to the last chunk when it fits.
fn dns_block_lines(label: &str, ips: &[String], tail: &str) -> Vec<String> {
    const W: usize = 70;
    const IND: usize = 15;
    let n = |s: &str| s.chars().count();
    let joined = ips.join(", ");
    if n(label) + n(&joined) + n(tail) <= W {
        return vec![format!("{}{}{}", label, cyan_val(&joined), tail)];
    }
    let mut limit_end = W.saturating_sub(IND + n(tail));
    let tail_own = limit_end < 8;
    if tail_own {
        limit_end = W - IND;
    }
    let mut end_chunk = String::new();
    let mut rest: Vec<&String> = ips.iter().collect();
    while let Some(ip) = rest.pop() {
        let piece = if end_chunk.is_empty() { (*ip).clone() } else { format!("{}, {}", ip, end_chunk) };
        if n(&piece) <= limit_end {
            end_chunk = piece;
        } else {
            rest.push(ip);
            break;
        }
    }
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ip in rest {
        let piece = if cur.is_empty() { (*ip).clone() } else { format!("{}, {}", cur, ip) };
        if n(&piece) <= W - IND {
            cur = piece;
        } else {
            chunks.push(cur);
            cur = (*ip).clone();
        }
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    if !end_chunk.is_empty() {
        chunks.push(end_chunk);
    }
    if chunks.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let last = chunks.len() - 1;
    for (i, c) in chunks.iter().enumerate() {
        if i == last && !tail_own {
            out.push(format!("{}{}{}", " ".repeat(IND), cyan_val(c), tail));
        } else {
            out.push(format!("{}{}", " ".repeat(IND), cyan_val(c)));
        }
    }
    if let Some(first) = out.first_mut() {
        *first = format!("{}{}", label, cyan_val(&chunks[0]));
    }
    if tail_own {
        out.push(format!("{}{}", " ".repeat(IND), tail));
    }
    out
}

pub fn render_netinfo_panel(
    data: &NetInfoData,
    dns_info: &SystemDnsInfo,
    bypass_tools: &[String],
    msg: &Messages,
) -> String {
    let mut lines = Vec::new();
    // Cymru-less fields carry the canonical "timeout" marker; it renders red
    // like the DNS cells and follows the interface language.
    let val = |v: &str| {
        if v == "timeout" {
            format!("\x1b[31m{}\x1b[0m", msg.timeout_label)
        } else {
            cyan_val(v)
        }
    };

    if data.empty {
        lines.push(format!(
            "IPv4: {}  {} {}  {} …",
            cyan_val("…"),
            msg.subnet_label,
            cyan_val("…"),
            msg.ttlb_label
        ));
        lines.push(format!("IPv6: {}", cyan_val("…")));
        lines.push(format!("{} {}", msg.org_label, cyan_val("…")));
        lines.push(format!("{} {}", msg.location_label, cyan_val("…")));
    } else {
        match data.v4.as_ref() {
            Some(f) if !f.ip.is_empty() => {
                lines.push(format!(
                    "IPv4: {}  {} {}  {} {}",
                    cyan_val(&f.ip),
                    msg.subnet_label,
                    val(&f.subnet),
                    msg.ttlb_label,
                    ttlb_str(&f.ttlb, msg)
                ));
            }
            _ => lines.push(format!("IPv4: {}", dim_val(msg.unavailable))),
        }
        match data.v6.as_ref() {
            Some(f) if !f.ip.is_empty() => {
                lines.push(format!("IPv6: {}", cyan_val(&f.ip)));
                lines.push(format!(
                    "      {} {}  {} {}",
                    msg.subnet_label,
                    val(&f.subnet),
                    msg.ttlb_label,
                    ttlb_str(&f.ttlb, msg)
                ));
            }
            _ => lines.push(format!("IPv6: {}", dim_val(msg.unavailable))),
        }
        let v4_org = data.v4.as_ref().map(|f| f.org.as_str()).unwrap_or("");
        let v4_asn = data.v4.as_ref().map(|f| f.asn.as_str()).unwrap_or("");
        let v4_cc = data.v4.as_ref().map(|f| f.cc.as_str()).unwrap_or("");
        let v6_org = data.v6.as_ref().map(|f| f.org.as_str()).unwrap_or("");
        let v6_asn = data.v6.as_ref().map(|f| f.asn.as_str()).unwrap_or("");
        let v6_cc = data.v6.as_ref().map(|f| f.cc.as_str()).unwrap_or("");
        let org_s = if !v4_org.is_empty() && !v6_org.is_empty() && v4_org != v6_org {
            let s4 = if !v4_asn.is_empty() {
                format!("{} (AS{})", v4_org, v4_asn)
            } else {
                v4_org.to_string()
            };
            let s6 = if !v6_asn.is_empty() {
                format!("{} (AS{})", v6_org, v6_asn)
            } else {
                v6_org.to_string()
            };
            format!("{} {}, {} {}", s4, dim_val("(v4)"), s6, dim_val("(v6)"))
        } else {
            let main_org = if !v4_org.is_empty() {
                v4_org
            } else if !v6_org.is_empty() {
                v6_org
            } else {
                "…"
            };
            let main_asn = if !v4_asn.is_empty() {
                v4_asn
            } else if !v6_asn.is_empty() {
                v6_asn
            } else {
                ""
            };
            if !main_asn.is_empty() {
                format!("{} (AS{})", main_org, main_asn)
            } else {
                main_org.to_string()
            }
        };
        lines.push(format!("{} {}", msg.org_label, val(&org_s)));
        let loc = if !v4_cc.is_empty() && !v6_cc.is_empty() && v4_cc != v6_cc {
            format!(
                "{} {} {}, {} {} {}",
                geo_country_ascii(v4_cc).trim(),
                v4_cc,
                dim_val("(v4)"),
                geo_country_ascii(v6_cc).trim(),
                v6_cc,
                dim_val("(v6)")
            )
        } else {
            let main_cc = if !v4_cc.is_empty() {
                v4_cc
            } else if !v6_cc.is_empty() {
                v6_cc
            } else {
                "…"
            };
            if main_cc == "…" {
                "…".to_string()
            } else {
                format!("{} {}", geo_country_ascii(main_cc).trim(), main_cc)
            }
        };
        lines.push(format!("{} {}", msg.location_label, val(&loc)));
    }

    if let Some(os) = dns_info.os.as_ref() {
        lines.push(format!("{} {}", msg.os, cyan_val(os)));
    }
    if !dns_info.active.is_empty() {
        let a_name = dns_info.active_name.clone().unwrap_or_default();
        let a_ip = dns_info.active_ip.clone().unwrap_or_default();
        let iface_shown = !a_name.is_empty() && !a_ip.is_empty();
        let mark = |ips: &[String]| {
            ips.iter()
                .map(|ip| {
                    if dns_info.doh.contains_key(ip) {
                        format!("{}(DoH)", ip)
                    } else {
                        ip.clone()
                    }
                })
                .collect::<Vec<_>>()
        };
        let ips_all: Vec<String> = dns_info.active.iter().map(|e| e.0.clone()).collect();
        let srcs: HashSet<&str> = dns_info.active.iter().map(|e| e.1.as_str()).collect();
        let mut src_label = String::new();
        if ips_all.iter().any(|ip| {
            ip.parse::<IpAddr>()
                .map(|a| fake_ip_type(&a) == FakeIpType::FakeIp)
                .unwrap_or(false)
        }) {
            src_label = "fake-ip".to_string();
        } else if is_tun_name(&a_name) {
            src_label = "TUN".to_string();
        } else if srcs.len() == 1 && srcs.contains("wsl") {
            src_label = msg.wsl_proxy.to_string();
        } else if srcs.len() == 1 && srcs.contains("dhcp") {
            src_label = "DHCP".to_string();
        }
        if (src_label == "fake-ip" || src_label == "TUN")
            && bypass_tools.iter().any(|b| b.to_lowercase().contains("xray"))
        {
            src_label += ", xray";
        }
        let tail = if !src_label.is_empty() && !iface_shown && !a_name.is_empty() {
            format!(" ({}, {})", src_label, a_name)
        } else if !src_label.is_empty() {
            format!(" ({})", src_label)
        } else if !iface_shown && !a_name.is_empty() {
            format!(" ({})", a_name)
        } else {
            String::new()
        };
        lines.extend(dns_block_lines(&format!("{} ", msg.system_dns), &mark(&ips_all), &tail));
        if iface_shown {
            lines.push(format!("{} {} ({})", msg.active_interface, cyan_val(&a_ip), a_name));
        }
        if !dns_info.other_static.is_empty() {
            let mut order: Vec<&String> = Vec::new();
            let mut by_name: HashMap<&String, Vec<String>> = HashMap::new();
            for (ip, n) in &dns_info.other_static {
                if !by_name.contains_key(n) {
                    order.push(n);
                    by_name.insert(n, Vec::new());
                }
                if let Some(v) = by_name.get_mut(n) {
                    v.push(ip.clone());
                }
            }
            for (k, n) in order.iter().enumerate() {
                let label = if k == 0 { format!("{} ", msg.inactive_dns) } else { " ".repeat(16) };
                if let Some(v) = by_name.get(*n) {
                    lines.extend(dns_block_lines(&label, &mark(v), &format!(" ({})", n)));
                }
            }
        }
    }
    if let Some(up) = dns_info.upstream.as_ref() {
        let label = dns_info.upstream_label.clone().unwrap_or_else(|| msg.router_resolver.to_string());
        lines.push(format!("{}: {}", label, cyan_val(up)));
    }
    let mut bypass: Vec<String> = bypass_tools.to_vec();
    if !bypass.is_empty() {
        let mut names_l = dns_info.active_name.clone().unwrap_or_default().to_lowercase();
        for (_, n) in &dns_info.other_static {
            names_l.push(' ');
            names_l.push_str(&n.to_lowercase());
        }
        bypass.retain(|t| t != "AmneziaWG" || names_l.contains("warp") || names_l.contains("amnezia"));
    }
    if let Some(w) = dns_info.wsl_net.as_ref() {
        lines.push(format!("{} {}", msg.wsl_network, cyan_val(w)));
    }
    if !bypass.is_empty() {
        lines.push(format!(
            "{} \x1b[33m{}\x1b[0m",
            msg.local_bypass,
            bypass.join(", ")
        ));
    } else {
        lines.push(format!(
            "{} {}",
            msg.local_bypass,
            dim_val(msg.not_detected)
        ));
    }

    // Rich prefixes content lines with two spaces ("  " + l); the panel adds
    // one padding space, so body rows start with three.
    let lines: Vec<String> = lines.iter().map(|l| format!("  {}", l)).collect();
    let mut width = BOX_WIDTH;
    for l in &lines {
        let w = strip_ansi_len(l) + 6;
        if w > width {
            width = w;
        }
    }
    panel_with(msg.netinfo_title, &lines, width, true, "2")
}

// ─── Test 1: DNS availability ─────────────────────────────────────────────────

pub fn render_dns_endpoints(report: &DnsAvailReport, msg: &Messages) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\n{}  DoH: {} | DoT: {} | UDP: {} | {}: {} | {}: {} | {}: {}s\n\n",
        msg.dns_check_title,
        report.doh_servers.len(),
        report.dot_servers.len(),
        report.udp_servers.len(),
        msg.blocked,
        report.forbidden.len(),
        msg.available,
        report.allowed.len(),
        msg.timeout_label,
        report.timeout_secs,
    ));
    out.push_str(&format!(
        "{} {}\n{} {}\n{}",
        msg.blocked_domains_label,
        report.forbidden.join(", "),
        msg.unblocked_domains_label,
        report.allowed.join(", "),
        msg.dns_independent_warn,
    ));
    if report.non_socks_proxy_warn {
        out.push_str(msg.non_socks_proxy_warn);
    }

    // Endpoint tables per kind
    for (title, servers, kind) in [
        (msg.doh_endpoints, &report.doh_servers, ProbeKind::DohWire),
        (msg.dot_endpoints, &report.dot_servers, ProbeKind::Dot),
        (msg.udp_endpoints, &report.udp_servers, ProbeKind::Udp),
    ] {
        if servers.is_empty() {
            continue;
        }
        let mut table = Table::new();
        table
            .load_preset(table_preset())
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new(format_bidi(msg.provider, msg.lang)),
                Cell::new(format_bidi(title, msg.lang)),
            ]);
        // Group by provider name preserving order
        let mut order: Vec<String> = Vec::new();
        let mut by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (addr, name, port) in servers {
            let default_port = match kind {
                ProbeKind::DohWire => 443,
                ProbeKind::Dot => 853,
                ProbeKind::Udp => 53,
            };
            let disp = if *port != default_port {
                format!("{}:{}", addr, port)
            } else {
                addr.clone()
            };
            if !by_name.contains_key(name) {
                order.push(name.clone());
            }
            by_name.entry(name.clone()).or_default().push(disp);
        }
        for name in order {
            let eps = &by_name[&name];
            let cell = if eps.len() > 1 {
                eps.iter().enumerate().map(|(i, e)| format!("{} #{}", e, i + 1)).collect::<Vec<_>>().join("\n")
            } else {
                eps[0].clone()
            };
            table.add_row(vec![Cell::new(cell_color(&name, Color::Cyan)), Cell::new(cell)]);
        }
        out.push_str(&format!("\n{}\n\n", table));
    }
    out
}

fn fail_color(token: &str) -> Color {
    // Mirrors Python label markup: DNS FAIL is yellow, the rest are red.
    match token {
        "DNS FAIL" => Color::Yellow,
        _ => Color::Red,
    }
}

#[derive(Debug, Clone)]
pub struct PartialDnsEndpoint {
    pub provider: String,
    pub protocol: &'static str,
    pub endpoint: String,
    pub ok: usize,
    pub total: usize,
    pub min_ms: f64,
}

/// One latency line per endpoint: per-domain minimum in green (or yellow on partial
/// packet loss), per-addr fail label. Partial endpoints are recorded for post-table listing.
#[allow(clippy::too_many_arguments)]
fn dns_latency_lines(
    report: &DnsAvailReport,
    kind: ProbeKind,
    name: &str,
    addrs: &[String],
    domains: &[String],
    udp: bool,
    partial: &mut Vec<PartialDnsEndpoint>,
    ms_unit: &str,
) -> Vec<(String, Color)> {
    let mut lines = Vec::new();
    for a in addrs {
        let key = dpi_core::dns::availability::ProbeKey {
            kind,
            addr: a.clone(),
            name: name.to_string(),
        };
        let dm = report.raw.get(&key);
        let vals: Vec<f64> = domains
            .iter()
            .filter_map(|d| dm.and_then(|m| m.get(d)).copied().flatten())
            .collect();
        if vals.is_empty() {
            // UDP shows a flat TIMEOUT (mirrors Python); DoH/DoT use the
            // recorded fail label.
            let token = if udp {
                "TIMEOUT".to_string()
            } else {
                report
                    .fail_reasons
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| "TIMEOUT".to_string())
            };
            lines.push((token.clone(), fail_color(&token)));
            continue;
        }
        let min = vals.iter().cloned().reduce(f64::min).unwrap_or(0.0);
        let text = format!("{:.1}{}", min, ms_unit);
        let color = if vals.len() == domains.len() {
            Color::Green
        } else {
            let proto = match kind {
                ProbeKind::DohWire => "DoH",
                ProbeKind::Dot => "DoT",
                ProbeKind::Udp => "UDP",
            };
            partial.push(PartialDnsEndpoint {
                provider: name.to_string(),
                protocol: proto,
                endpoint: a.clone(),
                ok: vals.len(),
                total: domains.len(),
                min_ms: min,
            });
            Color::Yellow
        };
        lines.push((text, color));
    }
    lines
}


pub fn render_dns_availability(report: &DnsAvailReport, cfg: &AppConfig, msg: &Messages) -> String {
    let mut out = String::new();
    let has_dot = !report.dot_servers.is_empty();

    let mut table = Table::new();
    table.load_preset(table_preset()).set_content_arrangement(ContentArrangement::Dynamic);
    let mut header = vec![
        Cell::new(format_bidi(msg.provider, msg.lang)),
        Cell::new(format_bidi(msg.doh_min, msg.lang)),
    ];
    if has_dot {
        header.push(Cell::new(format_bidi(msg.dot_min, msg.lang)));
    }
    header.extend([
        Cell::new(format_bidi(msg.udp_min, msg.lang)),
        Cell::new(format_bidi(msg.real_udp_resolver, msg.lang)),
        Cell::new(format_bidi(msg.spoofing, msg.lang)),
    ]);
    table.set_header(header);
    // by-name endpoint grouping
    let mut udp_by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (a, n, _) in &report.udp_servers {
        udp_by_name.entry(n.clone()).or_default().push(a.clone());
    }
    let mut doh_by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (a, n, _) in &report.doh_servers {
        doh_by_name.entry(n.clone()).or_default().push(a.clone());
    }
    let mut dot_by_name: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (a, n, _) in &report.dot_servers {
        dot_by_name.entry(n.clone()).or_default().push(a.clone());
    }

    let mut partial_endpoints = Vec::new();

    for name in &report.all_names {
        // DoH cell: one line per endpoint (mirrors Python).
        let doh_addrs = doh_by_name.get(name).cloned().unwrap_or_default();
        let doh_lines: Vec<(String, Color)> = if doh_addrs.is_empty() {
            vec![("—".to_string(), Color::DarkGrey)]
        } else {
            dns_latency_lines(report, ProbeKind::DohWire, name, &doh_addrs, &report.forbidden, false, &mut partial_endpoints, msg.ms_unit.trim())
        };

        // DoT cell: one line per endpoint.
        let mut dot_lines: Vec<(String, Color)> = Vec::new();
        if has_dot {
            let dot_addrs = dot_by_name.get(name).cloned().unwrap_or_default();
            if dot_addrs.is_empty() {
                dot_lines.push(("—".to_string(), Color::DarkGrey));
            } else {
                dot_lines = dns_latency_lines(report, ProbeKind::Dot, name, &dot_addrs, &report.forbidden, false, &mut partial_endpoints, msg.ms_unit.trim());
            }
        }

        // UDP cell (trusted-domain ping): one line per endpoint.
        let udp_addrs = udp_by_name.get(name).cloned().unwrap_or_default();
        let udp_lines: Vec<(String, Color)> = if udp_addrs.is_empty() {
            vec![("—".to_string(), Color::DarkGrey)]
        } else {
            dns_latency_lines(report, ProbeKind::Udp, name, &udp_addrs, &report.allowed, true, &mut partial_endpoints, msg.ms_unit.trim())
        };
        // Egress cell
        let mut egress_lines: Vec<(String, Option<Color>)> = Vec::new();
        for a in &udp_addrs {
            let key = dpi_core::dns::availability::ProbeKey { kind: ProbeKind::Udp, addr: a.clone(), name: name.clone() };
            let alive = report.raw.get(&key).map(|dm| {
                report.allowed.iter().any(|d| dm.get(d).copied().flatten().is_some())
            }).unwrap_or(false);
            let eip = report.egress.get(&(a.clone(), name.clone())).copied().flatten();
            match (alive, eip) {
                (false, _) => egress_lines.push((format!("{}: {}", a, msg.timeout_label), Some(Color::DarkGrey))),
                (true, None) => egress_lines.push((format!("{}: {}", a, msg.egress_na), Some(Color::DarkGrey))),
                (true, Some(ip)) if ip == "0.0.0.0".parse::<std::net::IpAddr>().unwrap() => {
                    egress_lines.push((format!("{}: {}", a, msg.egress_na), Some(Color::DarkGrey)));
                }
                (true, Some(ip)) => {
                    if dpi_core::probe::domains::fake_ip_type(&ip) == dpi_core::probe::domains::FakeIpType::FakeIp {
                        egress_lines.push((format!("{}→FakeIP", a), Some(Color::Magenta)));
                    } else {
                        let org = report.org_names.get(&ip.to_string()).cloned().unwrap_or_else(|| ip.to_string());
                        let label = org_label(&org);
                        if known_resolver(&label, &cfg.dns_known_resolver_names) {
                            egress_lines.push((format!("{}→{}", a, label), Some(Color::Green)));
                        } else {
                            egress_lines.push((format!("{}→{}", a, label), Some(Color::Red)));
                        }
                    }
                }
            }
        }
        let egress_text = egress_lines
            .iter()
            .map(|(t, c)| match c {
                Some(col) => cell_color(t, *col),
                None => t.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Substitution cell
        let mut subst_lines: Vec<(String, Color)> = Vec::new();
        if !udp_addrs.is_empty() && !report.forbidden.is_empty() {
            for a in &udp_addrs {
                let (judged, sub) = subst_counts(report, a, name);
                if judged == 0 {
                    subst_lines.push(("—".to_string(), Color::DarkGrey));
                    continue;
                }
                // FakeIP check
                let mut fake_n = 0;
                for d in &report.forbidden {
                    let key = dpi_core::dns::availability::ProbeKey { kind: ProbeKind::Udp, addr: a.clone(), name: name.clone() };
                    if let Some(DnsAnswer::Ips(ips)) = report.udp_answers.get(&(key, d.clone())) {
                        if !ips.is_empty() && ips.iter().any(|ip| dpi_core::probe::domains::fake_ip_type(ip) == dpi_core::probe::domains::FakeIpType::FakeIp) {
                            fake_n += 1;
                        }
                    }
                }
                let frac = format!("{}/{}", sub, report.forbidden.len());
                if fake_n > 0 {
                    subst_lines.push((frac, Color::Magenta));
                } else if sub == report.forbidden.len() {
                    subst_lines.push((frac, Color::Red));
                } else if sub == 0 {
                    subst_lines.push((frac, Color::Green));
                } else {
                    subst_lines.push((frac, Color::Yellow));
                }
            }
        } else {
            subst_lines.push(("—".to_string(), Color::DarkGrey));
        }
        // Name column spans the tallest cell ("Google", "Google #2", ...).
        let n_rows = doh_lines
            .len()
            .max(dot_lines.len())
            .max(udp_lines.len())
            .max(egress_lines.len())
            .max(subst_lines.len())
            .max(1);
        let doh_text = join_cell_colored(doh_lines);
        let dot_text = join_cell_colored(dot_lines);
        let udp_text = join_cell_colored(udp_lines);
        let subst_text = join_cell_colored(subst_lines);
        let name_text = (0..n_rows)
            .map(|i| if i == 0 { name.clone() } else { format!("{} #{}", name, i + 1) })
            .collect::<Vec<_>>()
            .join("\n");
        let mut row = vec![
            Cell::new(cell_color(&name_text, Color::Cyan)),
            Cell::new(doh_text),
        ];
        if has_dot {
            row.push(Cell::new(dot_text));
        }
        row.push(Cell::new(udp_text));
        row.push(Cell::new(egress_text));
        row.push(Cell::new(subst_text));
        table.add_row(row);
    }

    out.push_str(&format!("{}\n", table));

    // The reference was not measured on this network, so a stale configured IP
    // must never look like a measurement.
    if report.truth_fallback_used {
        out.push('\n');
        out.push_str(&format!(
            "\x1b[1;33m[{}] {}\x1b[0m\n",
            warn_mark(),
            msg.dns_truth_fallback_note
        ));
    }

    if !partial_endpoints.is_empty() {
        out.push('\n');
        let warn = warn_mark();
        out.push_str(&format!(
            "\x1b[1;33m[{}] {}\x1b[0m\n",
            warn, msg.partial_dns_warn
        ));
        for p in &partial_endpoints {
            let bullet = asc("•");
            out.push_str(&format!(
                "  \x1b[33m{}\x1b[0m \x1b[1m{}\x1b[0m [{}] \x1b[2m{}\x1b[0m — \x1b[1;33m{}/{}\x1b[0m {} ({:.1}{})\n",
                bullet, p.provider, p.protocol, p.endpoint, p.ok, p.total, msg.replies_label, p.min_ms, msg.ms_unit
            ));
        }
    }

    // Hijack warning block
    let st = &report.stats;
    if st.subst_sub > 0 {
        out.push('\n');
        match st.top_stub.as_deref() {
            Some(top) if top.parse::<std::net::IpAddr>().map(|ip| dpi_core::probe::domains::fake_ip_type(&ip) == dpi_core::probe::domains::FakeIpType::FakeIp).unwrap_or(false) => {
                out.push_str(msg.dns_fakeip_warn);
                out.push('\n');
            }
            _ => {
                out.push_str(msg.dns_intercept_warn);
                out.push('\n');
                if let Some(top) = st.top_stub.as_deref() {
                    out.push_str(&format!("{}\n", msg.dns_stub_ip_label.replace("{}", top)));
                }
                out.push_str(msg.doh_recommendation);
                out.push('\n');
            }
        }
    }
    // /24 sharing info (brand → net) is computed in stats.hijacked_brands (summary row)
    let _ = net24;
    out
}


// ─── Test 2: domains ──────────────────────────────────────────────────────────

/// Test 6's table: one row per host, one column per profile, the cell being how
/// many of the simultaneous handshakes came back. The header names each profile
/// with the pinned version it reproduces (rule 4: Latin, never translated), and
/// the detail column names the failure that happened most often across the
/// profile columns.
pub fn render_burst_table(reports: &[BurstReport], settings: &BurstSettings, msg: &Messages) -> String {
    let profiles: &[TlsFingerprint] = &settings.profiles;
    let mut table = Table::new();
    let mut header = vec![Cell::new(format_bidi(msg.domain, msg.lang))];
    for fingerprint in profiles {
        // The version, not just the family: two runs of "CHROME" can differ in
        // the shape they sent, and the header is where that is read off.
        header.push(Cell::new(fingerprint.display_label()));
    }
    header.push(Cell::new(format_bidi(msg.detail, msg.lang)));
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(header);

    // A cell is green when everything was answered, red when nothing was, and
    // yellow in between: a burst that lost part of its handshakes is a weaker
    // signal than one that lost all of them.
    let cell_color_for = |answered: usize, total: usize| {
        if total == 0 {
            Color::DarkGrey
        } else if answered == total {
            Color::Green
        } else if answered == 0 {
            Color::Red
        } else {
            Color::Yellow
        }
    };

    for report in reports {
        let mut row = vec![Cell::new(cell_color(&report.domain, Color::Cyan))];
        for fingerprint in profiles {
            let cell = match report.profiles.iter().find(|p| p.fingerprint == *fingerprint) {
                Some(profile) => cell_color(
                    &format!("{}/{}", profile.answered(), profile.attempts.len()),
                    cell_color_for(profile.answered(), profile.attempts.len()),
                ),
                None => cell_color("—", Color::DarkGrey),
            };
            row.push(Cell::new(cell));
        }
        let (detail, detail_color) = match report.resolved {
            None => (
                DpiStatus::DnsFail.display_label().to_string(),
                status_color(DpiStatus::DnsFail),
            ),
            Some(_) => match report.dominant_failure() {
                Some((status, _, count)) => (
                    format!("{} ×{}", status.display_label(), count),
                    status_color(status),
                ),
                None => (DET_ALL_ANSWERED.to_string(), Color::DarkGrey),
            },
        };
        row.push(Cell::new(cell_color(&detail, detail_color)));
        table.add_row(row);
    }

    let mut out = String::new();
    out.push_str(&format!("{}\n", table));
    out
}

/// Detail cell of a host whose every handshake was answered: an em dash, like
/// the other tables' empty-detail cells.
const DET_ALL_ANSWERED: &str = "—";

pub fn render_domain_table(entries: &[DomainEntry], msg: &Messages) -> String {
    let mut out = String::new();
    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.domain, msg.lang)),
            Cell::new(msg.http),
            Cell::new(msg.tls12),
            Cell::new(msg.tls13),
            Cell::new(format_bidi(msg.detail, msg.lang)),
        ]);

    for e in entries {
        let (http_s, t12_s, t13_s, raw_details) = dpi_core::probe::domains::build_domain_row(e);
        let details = detail_lines(&raw_details, msg.lang);
        table.add_row(vec![
            Cell::new(cell_color(&e.domain, Color::Cyan)),
            Cell::new(cell_color(http_s.display_label(), status_color(http_s))),
            Cell::new(cell_color(t12_s.display_label(), status_color(t12_s))),
            Cell::new(cell_color(t13_s.display_label(), status_color(t13_s))),
            Cell::new(details),
        ]);
    }

    out.push_str(&format_bidi(msg.domain_title, msg.lang));
    out.push('\n');
    out.push_str(&format!("{}\n", table));
    out
}

/// Post-table DNS resolve notes (stubs, fake-ip, DoH recommendation).
pub fn render_dns_resolve_notes(entries: &[DomainEntry], msg: &Messages) -> String {
    use dpi_core::probe::domains::FakeIpType;
    let mut out = String::new();

    let mut dns_fail: usize = 0;
    let mut no_ipv6: usize = 0;
    let mut isp_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut local_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut fakeip_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for e in entries {
        if e.t13.status == DpiStatus::DnsFail || e.t12.status == DpiStatus::DnsFail || e.http.status == DpiStatus::DnsFail {
            dns_fail += 1;
            if e.t13.detail == DET_IPV6_UNSUPPORTED || e.t13.detail == DET_IPV6_NOT_SUPPORTED_SHORT {
                no_ipv6 += 1;
            }
        }
        if let Some(ip) = e.resolved {
            if dpi_core::probe::domains::fake_ip_type(&ip) == FakeIpType::FakeIp {
                *fakeip_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
            // ISP stub = resolved IP present in stub set is decided upstream;
            // here DNS FAKE/LOCAL IP statuses mark them.
            if e.t13.status == DpiStatus::DnsFake {
                *isp_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
            if e.t13.status == DpiStatus::LocalIp {
                *local_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
        }
    }

    let real_dns_fail = dns_fail.saturating_sub(no_ipv6);
    if isp_stubs.is_empty() && local_stubs.is_empty() && fakeip_stubs.is_empty() && real_dns_fail == 0 {
        return out;
    }

    out.push_str(&format!("\n{}\n", msg.dns_info_title));
    if !fakeip_stubs.is_empty() {
        let total: usize = fakeip_stubs.values().sum();
        out.push_str(&format!("{}\n", msg.traffic_fakeip.replace("{}", &total.to_string())));
    }
    if !isp_stubs.is_empty() {
        let total: usize = isp_stubs.values().sum();
        if isp_stubs.len() <= 3 {
            let ips: Vec<String> = isp_stubs.keys().cloned().collect();
            let s = msg.dns_isp_stub.replacen("{}", &ips.join(", "), 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        } else {
            let s = msg.dns_isp_stub.replacen("({})", "", 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        }
    }
    if !local_stubs.is_empty() {
        let total: usize = local_stubs.values().sum();
        if local_stubs.len() <= 3 {
            let ips: Vec<String> = local_stubs.keys().cloned().collect();
            let s = msg.dns_local_ip.replacen("{}", &ips.join(", "), 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        } else {
            let s = msg.dns_local_ip.replacen("({})", "", 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        }
    }
    if real_dns_fail > 0 {
        out.push_str(&format!("{}\n", msg.dns_fail_detected.replace("{}", &real_dns_fail.to_string())));
    }
    if !isp_stubs.is_empty() || real_dns_fail > 0 {
        out.push_str(msg.doh_flush_guide);
    }
    out.push('\n');
    out
}

// ─── Test 3: TCP ──────────────────────────────────────────────────────────────

pub struct TcpRow {
    pub id: String,
    pub asn: String,
    pub provider: String,
    pub status: DpiStatus,
    pub detail: String,
}

fn provider_group(provider: &str) -> String {
    let clean: String = provider.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '.' || *c == '-').collect();
    clean.split_whitespace().next().unwrap_or(&clean).to_string()
}

pub fn render_tcp_table(rows: &[TcpRow], msg: &Messages) -> String {
    let mut out = String::new();
    // Sort: provider group frequency desc, group name, id number (mirrors Python)
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in rows {
        *counts.entry(provider_group(&r.provider)).or_insert(0) += 1;
    }
    let mut sorted: Vec<&TcpRow> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        let ga = provider_group(&a.provider);
        let gb = provider_group(&b.provider);
        let ca = counts.get(&ga).copied().unwrap_or(0);
        let cb = counts.get(&gb).copied().unwrap_or(0);
        cb.cmp(&ca)
            .then(ga.cmp(&gb))
            .then(id_num(&a.id).cmp(&id_num(&b.id)))
    });

    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.col_id, msg.lang)),
            Cell::new(format_bidi(msg.col_asn, msg.lang)),
            Cell::new(format_bidi(msg.provider, msg.lang)),
            Cell::new(format_bidi(msg.status, msg.lang)),
            Cell::new(format_bidi(msg.detail, msg.lang)),
        ]);
    let mut passed = 0;
    let mut blocked = 0;
    let mut mixed = 0;
    for r in sorted {
        let label = r.status.display_label();
        if label.contains("OK") {
            passed += 1;
        } else if label.contains("DETECTED") {
            blocked += 1;
        } else if label.contains("MIXED") {
            mixed += 1;
        }
        table.add_row(vec![
            Cell::new(&r.id),
            Cell::new(cell_color(&r.asn, Color::Yellow)),
            Cell::new(cell_color(&r.provider, Color::Cyan)),
            Cell::new(cell_color(label, status_color(r.status))),
            Cell::new(detail_text(&r.detail, msg.lang)),
        ]);
    }
    out.push_str(&format!("\n{}\n", msg.tcp16_check_title));
    out.push_str(&format!("{}\n", table));
    if mixed > 0 {
        out.push_str(&format!("{}\n", msg.tcp_mixed_warn));
    }
    let _ = (passed, blocked);
    out
}

fn id_num(id: &str) -> u64 {
    id.rsplit('-').next().and_then(|s| s.parse().ok()).unwrap_or(99999)
}

// ─── Test 4: whitelist SNI ────────────────────────────────────────────────────

pub fn render_whitelist(report: &WhitelistReport, targets_total: usize, msg: &Messages) -> String {
    let mut out = String::new();
    if targets_total == 0 {
        out.push_str(msg.no_port_443_targets);
        return out;
    }
    if report.detected_as == 0 {
        out.push_str(msg.no_as_blocked);
        return out;
    }
    for row in &report.rows {
        match &row.verdict {
            AsVerdict::Found { snis, ban_after } => {
                let parts: Vec<String> = snis
                    .iter()
                    .map(|(label, n)| {
                        let disp = if label == NO_SNI_TAG {
                            msg.no_sni_label
                        } else {
                            label.as_str()
                        };
                        if *n > 0 {
                            format!("\x1b[1;32m{}\x1b[0m \x1b[2m#{}\x1b[0m", disp, n)
                        } else {
                            format!("\x1b[1;32m{}\x1b[0m", disp)
                        }
                    })
                    .collect();
                let suffix = if *ban_after {
                    format!("\x1b[2;33m{}\x1b[0m", msg.ban_after_label)
                } else {
                    String::new()
                };
                out.push_str(&asc(&format!(
                    "  \x1b[36m{}\x1b[0m \x1b[2m{}\x1b[0m  \x1b[32m✓\x1b[0m {}{}\n",
                    row.provider,
                    row.asn_str,
                    parts.join("  "),
                    suffix
                )));
            }
            AsVerdict::Banned { detail } => {
                let clean = strip_brackets(detail);
                out.push_str(&asc(&format!(
                    "  \x1b[36m{}\x1b[0m \x1b[2m{}\x1b[0m  \x1b[33m{} {}\x1b[0m \x1b[2m({})\x1b[0m\n",
                    row.provider,
                    row.asn_str,
                    warn_mark(),
                    msg.ban_rate_limit,
                    clean
                )));
            }
            AsVerdict::NotFound => {
                out.push_str(&asc(&format!(
                    "  \x1b[36m{}\x1b[0m \x1b[2m{}\x1b[0m  \x1b[31m{}\x1b[0m\n",
                    row.provider, row.asn_str, msg.sni_not_found
                )));
            }
        }
    }
    out.push('\n');
    if report.found_as > 0 {
        let s = msg.whitelist_found_summary.replacen("{}", &report.found_as.to_string(), 1).replacen("{}", &report.detected_as.to_string(), 1);
        out.push_str(&format!("\x1b[32m{}\x1b[0m\n", s));
    } else {
        let s = msg.whitelist_none_summary.replace("{}", &report.detected_as.to_string());
        out.push_str(&format!("\x1b[33m{}\x1b[0m\n", s));
    }
    out
}

fn strip_brackets(s: &str) -> String {
    let mut out = String::new();
    let mut depth: usize = 0;
    for c in s.chars() {
        if c == '[' {
            depth += 1;
        } else if c == ']' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            out.push(c);
        }
    }
    out.trim().to_string()
}

// ─── Test 5: Telegram ─────────────────────────────────────────────────────────

pub fn render_telegram(report: &TelegramFullReport, msg: &Messages) -> String {
    
    let mut out = String::new();
    out.push_str(&format!("\n{}\n", msg.telegram_check_title));

    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.dc_col, msg.lang)),
            Cell::new(format_bidi(msg.ip_col, msg.lang)),
            Cell::new(format_bidi(msg.region, msg.lang)),
            Cell::new(format_bidi(msg.status, msg.lang)),
            Cell::new(format_bidi(msg.ping_col, msg.lang)),
        ]);
    for dc in &report.dc_results {
        let (label, color) = if dc.available {
            ("OK", Color::Green)
        } else {
            (msg.unavailable, Color::Red)
        };
        let ping = match dc.latency_ms {
            Some(l) => format!("{}{}", l, msg.ms_unit),
            None => detail_text(dc.error.as_deref().unwrap_or("—"), msg.lang),
        };
        // Region from telegram_dc_list order is not carried; show stored region
        table.add_row(vec![
            Cell::new(cell_color(&dc.name, Color::Cyan)),
            Cell::new(&dc.ip),
            Cell::new(&dc.region),
            Cell::new(cell_color(label, color)),
            Cell::new(ping),
        ]);
    }
    out.push_str(&format!("{}\n", table));

    // Download / upload verdict lines (mirror display.finish rows)
    for (label, t) in [(msg.download_label, &report.download), (msg.upload_label, &report.upload)] {
        let (st_text, color) = match t.status.as_str() {
            "ok" => ("OK", Color::Green),
            "stalled" => ("STALL", Color::Yellow),
            "slow" => ("SLOW", Color::Yellow),
            "blocked" => ("BLOCKED", Color::Red),
            _ => ("ERROR", Color::Red),
        };
        let mut line = format!(
            "  {}: {}  {} {}  {} {}  ({} / {:.0}s",
            label,
            st_text,
            msg.peak_label,
            fmt_speed(t.peak_bps, msg.lang),
            msg.avg_label,
            fmt_speed(t.avg_bps, msg.lang),
            fmt_size(t.bytes_total, msg.lang),
            t.duration
        );
        if let Some(sec) = t.drop_at_sec {
            line += &msg.stall_after.replace("{}", &sec.to_string());
        }
        line += ")";
        let _ = color;
        out.push_str(&format!("{}\n", line));
    }
    out.push('\n');
    out
}

// ─── Summary ──────────────────────────────────────────────────────────────────

fn frac_color(ok: usize, total: usize) -> &'static str {
    if total == 0 || ok == total {
        "green"
    } else if ok == 0 {
        "red"
    } else {
        "yellow"
    }
}

pub struct SummaryData<'a> {
    pub run_dns: bool,
    pub dns: Option<&'a dpi_core::dns::availability::DnsAvailStats>,
    pub domains: Option<&'a DomainStats>,
    pub tcp: Option<(usize, usize, usize, usize)>, // ok, blocked, mixed, total
    pub run_telegram: bool,
    pub telegram: Option<&'a TelegramFullReport>,
}

pub fn render_summary(data: &SummaryData, msg: &Messages) -> String {
    let mut items: Vec<(String, String)> = Vec::new();

    if data.run_dns {
        if let Some(d) = data.dns {
            let doh_c = frac_color(d.doh_ok, d.doh_total);
            let udp_c = frac_color(d.udp_ok, d.udp_total);
            let mut parts = vec![format!("[{}]{}/{} DoH[/]", doh_c, d.doh_ok, d.doh_total)];
            if d.dot_total > 0 {
                let dot_c = frac_color(d.dot_ok, d.dot_total);
                parts.push(format!("[{}]{}/{} DoT[/]", dot_c, d.dot_ok, d.dot_total));
            }
            parts.push(format!("[{}]{}/{} UDP[/]", udp_c, d.udp_ok, d.udp_total));
            items.push((msg.summary_dns_avail.to_string(), parts.join("  ")));
            if !d.hijacked_brands.is_empty() {
                if d.resolvers_total > 0 && d.hijacked_brands.len() >= d.resolvers_total {
                    items.push((msg.summary_resolver_hijack.to_string(), format!("[red]{}[/]", msg.summary_all)));
                } else {
                    items.push((
                        msg.summary_resolver_hijack.to_string(),
                        format!("[red]{}[/]", d.hijacked_brands.join(", ")),
                    ));
                }
            } else {
                items.push((msg.summary_resolver_hijack.to_string(), "[dim]—[/]".to_string()));
            }
            if d.subst_total > 0 {
                if d.fakeip_sub > 0 {
                    items.push((
                        msg.summary_fakeip_resp.to_string(),
                        format!("[magenta]{}/{} UDP[/]", d.fakeip_sub, d.subst_total),
                    ));
                }
                let rest = d.subst_sub.saturating_sub(d.fakeip_sub);
                if rest > 0 {
                    let c = if rest == d.subst_total { "red" } else { "yellow" };
                    items.push((
                        msg.summary_ans_hijack.to_string(),
                        format!("[{}]{}/{} UDP[/]", c, rest, d.subst_total),
                    ));
                } else if d.fakeip_sub == 0 {
                    items.push((
                        msg.summary_ans_hijack.to_string(),
                        format!("[green]0/{} UDP[/]", d.subst_total),
                    ));
                }
            }
        } else {
            items.push((msg.summary_dns_avail.to_string(), "[dim]—[/]".to_string()));
        }
    }

    if let Some(d) = data.domains {
        let stat = |label: &str, ok: usize| {
            let c = frac_color(ok, d.total);
            format!("[{}]{}/{} {}[/]", c, ok, d.total, label)
        };
        items.push((
            msg.summary_domains.to_string(),
            format!("{}  {}  {}", stat("HTTP", d.http_ok), stat("TLS1.2", d.t12_ok), stat("TLS1.3", d.t13_ok)),
        ));
    }

    if let Some((ok, blocked, mixed, total)) = data.tcp {
        let pct = ok.checked_mul(100).and_then(|v| v.checked_div(total)).unwrap_or(0);
        let mut value = format!("[green]√ {}/{} OK[/]", ok, total);
        if blocked > 0 {
            value += &format!("  [red]× {} {}[/]", blocked, msg.blocked_short);
        }
        if mixed > 0 {
            value += &format!("  [yellow]≈ {} {}[/]", mixed, msg.mixed_short);
        }
        value += &format!("  [dim]({}% OK)[/]", pct);
        items.push(("TCP 16-20KB".to_string(), value));
    }

    if data.run_telegram {
        if let Some(t) = data.telegram {
            
            let tg_row = |label: &str, st: &dpi_core::probe::telegram::TransferStats, speed: f64, size: u64| {
                let (raw, color) = match st.status.as_str() {
                    "ok" => ("OK", "green"),
                    "stalled" => ("STALL", "yellow"),
                    "slow" => ("SLOW", "yellow"),
                    "blocked" => ("BLOCKED", "red"),
                    _ => ("ERROR", "red"),
                };
                let mut metrics = format!("{} {}, {}", msg.avg_label, fmt_speed(speed, msg.lang), fmt_size(size, msg.lang));
                if let Some(sec) = st.drop_at_sec {
                    metrics += &msg.stall_after.replace("{}", &sec.to_string());
                }
                (label.to_string(), format!("[{}]{:<16}[/] {}", color, raw, metrics))
            };
            let (l1, v1) = tg_row(msg.summary_tg_download, &t.download, t.download.avg_bps, t.download.bytes_total);
            let (l2, v2) = tg_row(msg.summary_tg_upload, &t.upload, t.upload.avg_bps, t.upload.bytes_total);
            items.push((l1, v1));
            items.push((l2, v2));
            let dc_c = if t.dc_reachable == t.dc_total {
                "green"
            } else if t.dc_reachable == 0 {
                "red"
            } else {
                "yellow"
            };
            items.push((
                msg.summary_tg_datacenters.to_string(),
                format!("[{}]OK {}/{}[/]", dc_c, t.dc_reachable, t.dc_total),
            ));
        }
    }

    if items.is_empty() {
        return String::new();
    }
    // Two columns, as in the Python prototype (`cli/summary.py` uses a Rich table
    // with `no_wrap` on the label column): pad the label column to its widest
    // entry so every value starts at the same offset. Widths are measured after
    // ANSI stripping, and per character, because CJK labels are two cells wide.
    let label_w = items.iter().map(|(label, _)| strip_ansi_len(label)).max().unwrap_or(0);
    // The value column: indent + label column + gap, and what is left of a row
    // once the borders and the single space around the content are taken out.
    let value_col = 2 + label_w + 2;
    let value_w = BOX_WIDTH.saturating_sub(3 + value_col);
    let mut lines = Vec::new();
    for (label, val) in items {
        let pad = label_w.saturating_sub(strip_ansi_len(&label));
        // `asc` widens glyphs in ASCII mode (`✓` becomes `[OK]`), so it has to run
        // before the width is measured; `panel_with` repeats it on the finished
        // line, which is idempotent.
        let value = asc(&rich_to_ansi(&val));
        for (i, chunk) in wrap_ansi(&value, value_w).into_iter().enumerate() {
            if i == 0 {
                lines.push(format!("  \x1b[1m{}{}\x1b[0m  {}", label, " ".repeat(pad), chunk));
            } else {
                lines.push(format!("{}{}", " ".repeat(value_col), chunk));
            }
        }
    }
    panel_to_string(msg.summary_title, &lines)
}

/// Minimal Rich-markup → ANSI converter for summary values.
fn rich_to_ansi(s: &str) -> String {
    s.replace("[green]", "\x1b[32m")
        .replace("[red]", "\x1b[31m")
        .replace("[yellow]", "\x1b[33m")
        .replace("[magenta]", "\x1b[35m")
        .replace("[cyan]", "\x1b[36m")
        .replace("[dim]", "\x1b[2m")
        .replace("[/]", "\x1b[0m")
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

    /// Regression: latency cells aggregated addr counts against domain counts
    /// ("40.0мс 1/5"). Cells must be one line per endpoint like Python, with
    /// the name column spanning ("Google", "Google #2").
    #[test]
    fn dns_table_cells_are_per_endpoint() {
        use dpi_core::dns::availability::{DnsAnswer, DnsAvailReport, ProbeKey, ProbeKind};
        use std::collections::HashMap;

        let mut report = DnsAvailReport {
            allowed: vec!["vk.ru".to_string(), "gosuslugi.ru".to_string()],
            forbidden: vec!["rutor.info".to_string()],
            udp_servers: vec![
                ("8.8.4.4".to_string(), "Google".to_string(), 53),
                ("8.8.8.8".to_string(), "Google".to_string(), 53),
            ],
            doh_servers: vec![(
                "https://dns.google/dns-query".to_string(),
                "Google".to_string(),
                443,
            )],
            all_names: vec!["Google".to_string()],
            ..Default::default()
        };
        for a in ["8.8.4.4", "8.8.8.8"] {
            let key = ProbeKey { kind: ProbeKind::Udp, addr: a.to_string(), name: "Google".to_string() };
            let mut dm = HashMap::new();
            dm.insert("vk.ru".to_string(), Some(10.0));
            dm.insert("gosuslugi.ru".to_string(), Some(12.0));
            dm.insert("rutor.info".to_string(), Some(11.0));
            report.raw.insert(key.clone(), dm);
            report.egress.insert(
                (a.to_string(), "Google".to_string()),
                Some("8.8.4.4".parse().unwrap()),
            );
            report.udp_answers.insert(
                (key, "rutor.info".to_string()),
                DnsAnswer::Ips(vec!["1.2.3.4".parse().unwrap()]),
            );
        }
        let dkey = ProbeKey {
            kind: ProbeKind::DohWire,
            addr: "https://dns.google/dns-query".to_string(),
            name: "Google".to_string(),
        };
        let mut ddm = HashMap::new();
        ddm.insert("rutor.info".to_string(), Some(30.0));
        report.raw.insert(dkey.clone(), ddm);
        report.doh_answers.insert(
            (dkey, "rutor.info".to_string()),
            DnsAnswer::Ips(vec!["5.6.7.8".parse().unwrap()]),
        );
        report.org_names.insert("8.8.4.4".to_string(), "GOOGLE - Google LLC".to_string());
        let cfg = AppConfig::default();
        let out = render_dns_availability(&report, &cfg, &dpi_core::i18n::get_messages(dpi_core::i18n::Language::Ru));
        // One line per endpoint, full success shows no fraction.
        assert!(out.contains("Google #2"), "name spans tallest cell");
        assert!(!out.contains("1/5"), "no addr/domain count mix-up");
        assert!(!out.contains("1/2"), "no addr/domain count mix-up");
        assert!(out.contains("8.8.4.4"), "per-addr egress lines");
        assert!(out.contains("8.8.8.8"), "per-addr egress lines");
    }
    fn netinfo_fixture() -> (NetInfoData, SystemDnsInfo, Vec<String>) {
        use dpi_core::net::netinfo::SystemDnsInfo;
        let data = NetInfoData {
            v4: Some(NetFamilyInfo {
                ip: "203.0.113.7".to_string(),
                ttlb: NetTtlb::Ms(701),
                subnet: "203.0.113.0/24".to_string(),
                org: "EXAMPLE-AS".to_string(),
                asn: "65001".to_string(),
                cc: "US".to_string(),
            }),
            v6: None,
            empty: false,
        };
        let dns = SystemDnsInfo {
            active: vec![("192.0.2.1".to_string(), "dhcp".to_string())],
            active_name: Some("Ethernet".to_string()),
            active_ip: Some("192.0.2.10".to_string()),
            other_static: vec![("198.51.100.2".to_string(), "Wi-Fi".to_string())],
            os: Some("Windows 11 (26200)".to_string()),
            upstream: Some("203.0.113.1 (EXAMPLE UP)".to_string()),
            ..Default::default()
        };
        (data, dns, Vec::new())
    }

    #[test]
    fn netinfo_panel_matches_python_rows() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
        let (data, dns, bypass) = netinfo_fixture();
        let out = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Ru));
        assert!(out.contains("IPv4: \x1b[36m203.0.113.7\x1b[0m  Subnet: \x1b[36m203.0.113.0/24\x1b[0m  TTLB: \x1b[2m701 мс\x1b[0m"));
        assert!(out.contains("IPv6: \x1b[2mнедоступен\x1b[0m"));
        assert!(out.contains("Org: \x1b[36mEXAMPLE-AS (AS65001)\x1b[0m"));
        assert!(out.contains("ОС: \x1b[36mWindows 11 (26200)\x1b[0m"));
        assert!(out.contains("Системный DNS: \x1b[36m192.0.2.1\x1b[0m (DHCP)"));
        assert!(out.contains("Активный интерфейс: \x1b[36m192.0.2.10\x1b[0m (Ethernet)"));
        assert!(out.contains("Неактивные DNS: \x1b[36m198.51.100.2\x1b[0m (Wi-Fi)"));
        assert!(out.contains("Резолвер роутера: \x1b[36m203.0.113.1 (EXAMPLE UP)\x1b[0m"));
        assert!(out.contains("Локальный обход DPI на устройстве: \x1b[2mне обнаружен\x1b[0m"));
    }
    #[test]
    fn netinfo_panel_renders_english_and_chinese() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
        let (data, dns, bypass) = netinfo_fixture();

        let out_en = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::En));
        assert!(out_en.contains("IPv6: \x1b[2munavailable\x1b[0m"));
        assert!(out_en.contains("OS: \x1b[36mWindows 11 (26200)\x1b[0m"));
        assert!(out_en.contains("System DNS: \x1b[36m192.0.2.1\x1b[0m (DHCP)"));
        assert!(out_en.contains("Active interface: \x1b[36m192.0.2.10\x1b[0m (Ethernet)"));
        assert!(out_en.contains("Inactive DNS: \x1b[36m198.51.100.2\x1b[0m (Wi-Fi)"));
        assert!(out_en.contains("Router resolver: \x1b[36m203.0.113.1 (EXAMPLE UP)\x1b[0m"));
        assert!(out_en.contains("Local DPI bypass on device: \x1b[2mnot detected\x1b[0m"));

        let out_zh = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Zh));
        assert!(out_zh.contains("IPv6: \x1b[2m不可用\x1b[0m"));
        assert!(out_zh.contains("操作系统: \x1b[36mWindows 11 (26200)\x1b[0m"));
        assert!(out_zh.contains("系统 DNS: \x1b[36m192.0.2.1\x1b[0m (DHCP)"));
        assert!(out_zh.contains("活动接口: \x1b[36m192.0.2.10\x1b[0m (Ethernet)"));
        assert!(out_zh.contains("非活动 DNS: \x1b[36m198.51.100.2\x1b[0m (Wi-Fi)"));
        assert!(out_zh.contains("路由器解析器: \x1b[36m203.0.113.1 (EXAMPLE UP)\x1b[0m"));
        assert!(out_zh.contains("设备本地 DPI 绕过: \x1b[2m未检测到\x1b[0m"));
    }

    #[test]
    fn netinfo_timeout_rows_are_red() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
        let t = || "timeout".to_string();
        let data = NetInfoData {
            v4: Some(NetFamilyInfo {
                ip: "203.0.113.7".to_string(),
                ttlb: NetTtlb::Ms(100),
                subnet: t(),
                org: t(),
                asn: t(),
                cc: t(),
            }),
            v6: None,
            empty: false,
        };
        let dns = Default::default();
        let out = render_netinfo_panel(&data, &dns, &[], &get_messages(Language::Ru));
        assert!(out.contains("\x1b[31mтаймаут\x1b[0m"), "cymru-less fields render red");
    }

    /// The domain table colors a foreign redirect red `REDIR` and a legitimate
    /// response green `OK` (`status_color`; Python's `ProbeStatus.is_ok` counts a
    /// red REDIR as not ok). The badge itself stays canonical Latin in every
    /// language (Rule 4), and the cell colour survives `asc()` in ASCII mode.
    #[test]
    fn foreign_redirect_cell_is_red() {
        use dpi_core::i18n::Language;
        use dpi_core::i18n::get_messages;
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
    fn netinfo_filters_amnezia_without_warp() {
        use dpi_core::i18n::get_messages;
        use dpi_core::i18n::Language;
        let (data, dns, _) = netinfo_fixture();
        let bypass = vec!["AmneziaWG".to_string(), "xray".to_string()];
        let out = render_netinfo_panel(&data, &dns, &bypass, &get_messages(Language::Ru));
        assert!(!out.contains("AmneziaWG"), "filtered without warp/amnezia adapter");
        assert!(out.contains("xray"), "other tools stay");
    }

    #[test]
    fn dns_block_lines_wrap_at_70_cols() {
        let ips: Vec<String> = (1..=8).map(|i| format!("192.0.2.{}", i)).collect();
        let lines = dns_block_lines("Системный DNS: ", &ips, " (DHCP)");
        assert!(lines.len() > 1, "long server list wraps");
        assert!(lines[0].starts_with("Системный DNS: "), "first line keeps the label");
        assert!(lines[1].starts_with("               "), "continuation indented by 15");
        assert!(lines.last().unwrap().ends_with(" (DHCP)"), "tail glued to last chunk");
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

    /// The live line is what the user watches during a run: a single-counter
    /// phase names the unit and estimates the remainder while there is one, and
    /// a multi-block phase shows every counter that is running at once.
    #[test]
    fn progress_line_single_and_blocks() {
        let one = [BlockState { token: "", done: 12, total: 50 }];
        assert_eq!(
            progress_line("Проверка... ", &one, Duration::from_secs(7)),
            "Проверка  12/50 · 00:07"
        );
        // The counter and clock are drawn in every state, 0/total included.
        let start = [BlockState { token: "", done: 0, total: 50 }];
        assert_eq!(progress_line("X", &start, Duration::from_secs(3)), "X  0/50 · 00:03");
        let done = [BlockState { token: "", done: 50, total: 50 }];
        assert_eq!(progress_line("X", &done, Duration::from_secs(60)), "X  50/50 · 01:00");

        // Test 1: four blocks, one line, elapsed only (per-unit cost differs by
        // an order of magnitude between blocks, so no aggregate estimate).
        let blocks = [
            BlockState { token: "UDP", done: 12, total: 50 },
            BlockState { token: "DoH", done: 2, total: 37 },
            BlockState { token: "DoT", done: 0, total: 34 },
            BlockState { token: "EGRESS", done: 5, total: 50 },
        ];
        assert_eq!(
            progress_line("DNS", &blocks, Duration::from_secs(31)),
            "DNS  UDP 12/50 · DoH 2/37 · DoT 0/34 · EGRESS 5/50 · 00:31"
        );

        assert_eq!(fmt_dur(Duration::from_secs(3661)), "1:01:01");
        assert_eq!(fmt_dur(Duration::from_secs(59)), "00:59");
    }

    #[test]
    fn fingerprint_header_never_repeats_the_profile_code() {
        use dpi_core::i18n::{get_messages, Language};
        let en = get_messages(Language::En);
        // The default label ("rustls (default)") carried the token as well, so
        // the header read "RUSTLS (rustls (default))".
        assert_eq!(render_fingerprint_header(TlsFingerprint::Rustls, &en), "Fingerprint: RUSTLS (default)");
        let fa = get_messages(Language::Fa);
        assert_eq!(render_fingerprint_header(TlsFingerprint::Rustls, &fa), "Fingerprint: RUSTLS (pishfarz)");
        // A label that does not repeat the code keeps the full parenthetical.
        let custom = render_fingerprint_header(TlsFingerprint::Custom, &en);
        assert!(custom.starts_with("Fingerprint: FIREFOX (firefox 133)"), "{custom}");
        assert!(custom.contains("FIREFOX = firefox133"), "the caveat still follows");
    }

    /// The summary is a two-column table (label, value), as in the Python
    /// prototype's Rich table: the label column is padded to its widest entry,
    /// so a short label cannot pull its value out of the column.
    #[test]
    fn summary_rows_align_their_values_into_two_columns() {
        use dpi_core::i18n::{get_messages, Language};
        let msg = get_messages(Language::Ru);
        let out = render_summary(
            &SummaryData {
                run_dns: true,
                dns: None,
                domains: None,
                tcp: Some((104, 0, 0, 110)),
                run_telegram: false,
                telegram: None,
            },
            &msg,
        );
        let rows: Vec<Vec<char>> = out
            .lines()
            .map(strip_ansi)
            .filter(|l| l.starts_with('│'))
            .map(|l| l.chars().collect())
            .collect();
        assert_eq!(rows.len(), 2, "one row per item, no wrapping");
        // Border, one space, the two-space indent, the label column, the gap.
        let longest = msg.summary_dns_avail.chars().count();
        let short = "TCP 16-20KB".len();
        assert!(longest > short, "the two labels must differ in width: {longest} vs {short}");
        let value_col = 1 + 1 + 2 + longest + 2;
        for row in &rows {
            let line: String = row.iter().collect();
            assert_ne!(row[value_col], ' ', "the value starts in the column: {line:?}");
            let gap: String = row[value_col - 2..value_col].iter().collect();
            assert_eq!(gap, "  ", "the column gap is intact: {line:?}");
        }
        // The short label is padded up to the column, not left ragged.
        let short_end = 1 + 1 + 2 + short;
        let pad: String = rows[1][short_end..value_col].iter().collect();
        assert_eq!(pad, " ".repeat(value_col - short_end), "pad the short label to the column");
    }

    /// The panel is a fixed-width box: `panel_with` pads a row, it cannot reflow
    /// one, so a value wider than its column has to be wrapped by the summary
    /// itself - otherwise it pushes the right border off the line.
    #[test]
    fn summary_wraps_a_long_value_inside_the_box() {
        use dpi_core::dns::availability::DnsAvailStats;
        use dpi_core::i18n::{get_messages, Language};
        let msg = get_messages(Language::Ru);
        let brands: Vec<String> = [
            "Cloudflare IP 2", "Google", "Level 3", "Level 3 2", "MSK-IX", "OpenDNS", "XboxDNS",
            "НСДИ",
        ]
        .iter()
        .map(|b| b.to_string())
        .collect();
        let stats = DnsAvailStats {
            doh_ok: 33,
            doh_total: 37,
            dot_ok: 33,
            dot_total: 34,
            udp_ok: 44,
            udp_total: 50,
            hijacked_brands: brands.clone(),
            resolvers_total: 120,
            subst_sub: 43,
            subst_total: 44,
            fakeip_sub: 0,
            fakeip_total: 0,
            top_stub: None,
        };
        let out = render_summary(
            &SummaryData {
                run_dns: true,
                dns: Some(&stats),
                domains: None,
                tcp: None,
                run_telegram: false,
                telegram: None,
            },
            &msg,
        );
        let rows: Vec<String> =
            out.lines().map(strip_ansi).filter(|l| l.starts_with('│')).collect();
        // Every row is exactly the box width: nothing spills past the border.
        for row in &rows {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        // One row for DNS availability, two for the hijack list, one for the
        // answer substitution - the list is the only value too wide to fit.
        assert_eq!(rows.len(), 4, "{rows:#?}");
        let label_w = msg.summary_resolver_hijack.chars().count();
        let value_col = 1 + 1 + 2 + label_w + 2;
        let list: Vec<String> = rows[1..rows.len() - 1]
            .iter()
            .map(|row| {
                assert_eq!(row.chars().nth(value_col - 1), Some(' '), "gap before the value: {row:?}");
                assert_ne!(row.chars().nth(value_col), Some(' '), "a value starts in the column: {row:?}");
                let text: String = row.chars().skip(value_col).collect();
                text.trim_end_matches('│').trim_end().to_string()
            })
            .collect();
        assert!(rows[1].contains(msg.summary_resolver_hijack), "the label sits on the first line");
        assert!(!rows[2].contains(msg.summary_resolver_hijack), "the continuation repeats no label");
        assert_eq!(list.join(" "), brands.join(", "), "wrapping loses no entry");
    }

    /// The SNI discovery rows mirror the Rich markup of the Python original:
    /// found is green, a ban is yellow, a miss is red, and every one of those
    /// codes is what the legacy (non-VT) console translator maps onto a Win32
    /// attribute — a row that loses its SGR goes monochrome on Windows 7.
    #[test]
    fn whitelist_rows_carry_their_status_colors() {
        use dpi_core::i18n::{get_messages, Language};
        use dpi_core::probe::whitelist::AsRow;
        let msg = get_messages(Language::Ru);
        let report = WhitelistReport {
            rows: vec![
                AsRow {
                    provider: "EXAMPLE".to_string(),
                    asn_str: "AS64500".to_string(),
                    verdict: AsVerdict::Found {
                        snis: vec![("www.example.org".to_string(), 3)],
                        ban_after: true,
                    },
                },
                AsRow {
                    provider: "EXAMPLE".to_string(),
                    asn_str: "AS64501".to_string(),
                    verdict: AsVerdict::Banned { detail: "read timed out [connect]".to_string() },
                },
                AsRow {
                    provider: "EXAMPLE".to_string(),
                    asn_str: "AS64502".to_string(),
                    verdict: AsVerdict::NotFound,
                },
            ],
            detected_as: 3,
            found_as: 1,
        };
        let out = render_whitelist(&report, 3, &msg);
        assert!(
            out.contains("\x1b[36mEXAMPLE\x1b[0m \x1b[2mAS64500\x1b[0m  \x1b[32m✓\x1b[0m "),
            "found row: {out}"
        );
        assert!(out.contains("\x1b[1;32mwww.example.org\x1b[0m \x1b[2m#3\x1b[0m"), "found label: {out}");
        assert!(out.contains("\x1b[2;33m"), "ban-after suffix is dim yellow: {out}");
        assert!(out.contains("\x1b[33m"), "ban row is yellow: {out}");
        assert!(out.contains("\x1b[31m"), "miss row is red: {out}");
        assert!(out.contains("\x1b[32m"), "found summary is green: {out}");
        // ASCII mode swaps the glyphs but must keep the colors.
        let ascii = asc_with(&out, true);
        assert!(ascii.contains("\x1b[32m[OK]\x1b[0m"), "ascii mark: {ascii}");
        assert!(ascii.contains("\x1b[31mx SNI"), "ascii miss: {ascii}");
        assert!(ascii.contains("\x1b[2;33m  ! "), "ascii ban-after: {ascii}");
        assert!(!ascii.contains('✓') && !ascii.contains('×'), "glyphs left: {ascii}");
    }

    /// Windows 7/8 consoles have no VT processing: the SNI rows keep their
    /// colors only if every SGR code they emit lands on a Win32 attribute. The
    /// codes are the ones `render_whitelist` writes (cyan provider, dim ASN,
    /// bold-green label, dim-yellow ban-after, yellow ban, red miss, green
    /// summary); a code the translator drops would silently go monochrome.
    #[cfg(windows)]
    #[test]
    fn legacy_console_maps_the_whitelist_colors() {
        const DEFAULT: u16 = 0x0007;
        const RED: u16 = 0x0004;
        const GREEN: u16 = 0x0002;
        const BLUE: u16 = 0x0001;
        const BRIGHT: u16 = 0x0008;
        assert_eq!(apply_ansi_code("36", DEFAULT, DEFAULT), GREEN | BLUE, "provider cyan");
        assert_eq!(apply_ansi_code("31", DEFAULT, DEFAULT), RED, "miss red");
        assert_eq!(apply_ansi_code("33", DEFAULT, DEFAULT), RED | GREEN, "ban yellow");
        assert_eq!(apply_ansi_code("1;32", DEFAULT, DEFAULT), GREEN | BRIGHT, "label bold green");
        assert_eq!(apply_ansi_code("2;33", DEFAULT, DEFAULT), RED | GREEN, "ban-after dim yellow");
        assert_eq!(apply_ansi_code("32", DEFAULT, DEFAULT), GREEN, "summary green");
        assert_eq!(apply_ansi_code("2", DEFAULT, DEFAULT), DEFAULT, "dim keeps the default fg");
        assert_eq!(apply_ansi_code("0", RED, DEFAULT), DEFAULT, "reset restores");
    }
}

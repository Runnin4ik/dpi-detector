//! Terminal modes and the raw escape plumbing: the stdout path, the Win32 console
//! translation for consoles without VT, the cursor moves a repaint needs, and the
//! capability probe that decides which of those a console gets. This is the
//! crate's only `unsafe` site — the Win32 console surface lives in one file.

use std::io::Write;
use std::sync::OnceLock;

use crate::tui::widgets::asc;

/// ASCII-only output for legacy consoles (see `--ascii`).
static ASCII_MODE: OnceLock<bool> = OnceLock::new();
static PLAIN_MODE: OnceLock<bool> = OnceLock::new();
static HAS_VT: OnceLock<bool> = OnceLock::new();

/// Enables ASCII-only output (font-safe glyphs, ASCII table borders).
pub(crate) fn set_ascii_mode(v: bool) {
    let _ = ASCII_MODE.set(v);
}

/// Whether ASCII-only output is on.
pub(crate) fn ascii_mode() -> bool {
    *ASCII_MODE.get().unwrap_or(&false)
}


/// Enables plain (ANSI-free) output for terminals without color support.
pub(crate) fn set_plain_mode(v: bool) {
    let _ = PLAIN_MODE.set(v);
}

/// Whether plain (ANSI-free) output is enabled.
pub(crate) fn plain_mode() -> bool {
    *PLAIN_MODE.get().unwrap_or(&false)
}

/// Sets whether the terminal supports native virtual terminal processing (VT100/ANSI).
pub(crate) fn set_has_vt(v: bool) {
    let _ = HAS_VT.set(v);
}

/// Whether native virtual terminal processing is supported.
pub(crate) fn has_vt() -> bool {
    *HAS_VT.get().unwrap_or(&true)
}
/// Strips all ANSI SGR escape sequences (`\x1b[...m` and `\x1b[...K`) from a string.
pub(crate) fn strip_ansi(s: &str) -> String {
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
pub(crate) fn clean_output(s: &str) -> String {
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
pub(crate) fn output_str(s: &str) {
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
#[allow(clippy::upper_case_acronyms, reason = "the name is the Win32 COORD this struct is laid out against, not a Rust acronym")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct COORD { x: i16, y: i16 }
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SMALL_RECT { left: i16, top: i16, right: i16, bottom: i16 }
#[cfg(windows)]
#[allow(clippy::upper_case_acronyms, reason = "the name is the Win32 CONSOLE_SCREEN_BUFFER_INFO this struct is laid out against")]
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
#[allow(
    unsafe_code,
    reason = "Win32 console FFI — the ANSI-to-console translation for legacy consoles (Windows 7/8). Each block carries its own SAFETY note."
)]
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

    // SAFETY: `STD_OUTPUT_HANDLE` is a constant pseudo-handle, not a pointer,
    // and the call takes no out-parameter. A 0 or -1 return is checked below
    // before the handle is used.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle == 0 || handle == -1 {
        let _ = std::io::stdout().write_all(s.as_bytes());
        return;
    }

    static DEFAULT_ATTR: OnceLock<u16> = OnceLock::new();
    let default_attr = *DEFAULT_ATTR.get_or_init(|| {
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        // SAFETY: `info` is a live local the call fills, and the handle was
        // checked against 0 and -1 before this point. A failure leaves `info` at
        // its `Default` (all zeroes), which the `!= 0` test discards.
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
                // SAFETY: the attribute word is the live local `cur_attr`,
                // produced by `apply_ansi_code` from a parsed SGR code, and the
                // handle was checked before use.
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
        // SAFETY: `utf16` is a live local `Vec<u16>` that outlives the call and
        // `written` a live `u32`; the reserved pointer is null as the API
        // requires. The call writes to this process's own stdout and reads
        // nothing back.
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
pub(crate) fn frame_home(drawn: u16) {
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
#[allow(
    unsafe_code,
    reason = "Win32 console FFI — the cursor move a repaint needs on legacy consoles. Each block carries its own SAFETY note."
)]
fn win32_frame_home(drawn: u16) {
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> isize;
        fn GetConsoleScreenBufferInfo(
            hConsoleOutput: isize,
            lpConsoleScreenBufferInfo: *mut CONSOLE_SCREEN_BUFFER_INFO,
        ) -> i32;
        fn SetConsoleCursorPosition(hConsoleOutput: isize, dwCursorPosition: COORD) -> i32;
    }
    // SAFETY: the same constant pseudo-handle as in `write_win32_ansi`, checked
    // against 0 and -1 before use.
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if handle == 0 || handle == -1 {
        return;
    }
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    // SAFETY: `info` is a live local the call fills; a failure leaves it at its
    // `Default`, which the `!= 0` test discards, so the move is skipped.
    if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } != 0 {
        // Buffer coordinates, clamped: an escape would wrap past the top row of
        // the screen buffer and come back up from the bottom.
        let row = (info.cursor_pos.y as i32 - drawn as i32).max(0) as i16;
        // SAFETY: `COORD` is a plain `#[repr(C)]` pair of `i16` built on the
        // stack, and `row` was clamped to the buffer above.
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

/// Whether the terminal renders VT100/ANSI escape sequences — switching the
/// Windows console to UTF-8 when it does.
///
/// The answer is taken once, before anything is printed, because it also decides
/// the glyph set; `terminal`'s `OnceLock`s hold it afterwards. It lives here
/// rather than beside that state because it is the crate's other Win32 call
/// site, and one file for the console surface is one place to audit.
#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 console FFI — the console-mode and code-page calls that decide whether this terminal can render ANSI. Each block carries its own SAFETY note."
)]
pub(crate) fn detect_vt() -> bool {
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
    // SAFETY: `STD_OUTPUT_HANDLE` is a constant pseudo-handle, not a
    // pointer, and the call takes no out-parameter.
    let out_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut out_mode: u32 = 0;
    // SAFETY: `out_mode` is a live local `u32` that outlives the call, and
    // the handle is the one just returned. A failed call leaves the local
    // at its zero initialiser, which the test then reads as "no VT".
    let vt_ok = if unsafe { GetConsoleMode(out_handle, &mut out_mode) } != 0 {
        // SAFETY: the mode word is the local the previous call filled,
        // ORed with a constant bit; the handle is the same one.
        unsafe { SetConsoleMode(out_handle, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 }
    } else {
        false
    };

    // Only switch to UTF-8 code page if VT is supported; on Win7 raster fonts require OEM codepage
    if vt_ok {
        // SAFETY: both calls take a constant code page and no pointer;
        // their return value says whether the console accepted it, which
        // this code does not depend on.
        unsafe {
            SetConsoleOutputCP(65001);
            SetConsoleCP(65001);
        }
    }
    vt_ok
}

/// Whether this terminal looks ANSI-capable.
#[cfg(not(windows))]
pub(crate) fn detect_vt() -> bool {
    let term = std::env::var("TERM").unwrap_or_default();
    term != "dumb" && term != "linux"
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
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

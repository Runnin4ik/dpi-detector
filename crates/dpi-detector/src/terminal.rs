//! Console capability probe. The crate's only `unsafe` lives here: the Win32
//! console-mode and code-page calls that decide whether the terminal can render
//! the ANSI the renderer emits. The answer is taken once, before anything is
//! printed, because it also decides the glyph set.

/// Whether the terminal renders VT100/ANSI escape sequences — switching the
/// Windows console to UTF-8 when it does.
#[cfg(windows)]
pub fn detect_vt() -> bool {
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
    let out_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let mut out_mode: u32 = 0;
    let vt_ok = if unsafe { GetConsoleMode(out_handle, &mut out_mode) } != 0 {
        unsafe { SetConsoleMode(out_handle, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 }
    } else {
        false
    };

    // Only switch to UTF-8 code page if VT is supported; on Win7 raster fonts require OEM codepage
    if vt_ok {
        unsafe {
            SetConsoleOutputCP(65001);
            SetConsoleCP(65001);
        }
    }
    vt_ok
}

/// Whether this terminal looks ANSI-capable.
#[cfg(not(windows))]
pub fn detect_vt() -> bool {
    let term = std::env::var("TERM").unwrap_or_default();
    term != "dumb" && term != "linux"
}

//! Console capability probe. This file and `tui::backend` are the crate's only
//! `unsafe` sites — the two halves of the Win32 console surface: here the
//! console-mode and code-page calls that decide whether the terminal can render
//! the ANSI the renderer emits. The answer is taken once, before anything is
//! printed, because it also decides the glyph set.
#![allow(
    unsafe_code,
    reason = "Win32 console FFI — the console-mode and code-page calls that decide whether this terminal can render ANSI. Each block carries its own SAFETY note."
)]

cfg_select! {
    windows => {
        /// Whether the terminal renders VT100/ANSI escape sequences — switching the
        /// Windows console to UTF-8 when it does.
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
    }
    _ => {
        /// Whether this terminal looks ANSI-capable.
        pub(crate) fn detect_vt() -> bool {
            let term = std::env::var("TERM").unwrap_or_default();
            term != "dumb" && term != "linux"
        }
    }
}

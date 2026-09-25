//! After a run: the key read for the post-run menu and the report export.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use chrono::{Datelike, Timelike};
use crate::i18n::Messages;
use std::io::{Write, stdout};

use crate::println_out;
use crate::tui::input::nav_key;

#[derive(Debug, Clone)]
pub(crate) enum PostTestAction {
    Repeat,
    Menu,
    Export,
    Quit,
}

pub(crate) fn read_post_test_action() -> PostTestAction {
    let _ = enable_raw_mode();
    loop {
        if let Ok(Event::Key(KeyEvent { code, modifiers, kind, .. })) = event::read() {
            if kind != KeyEventKind::Press {
                continue;
            }
            let code = match code {
                KeyCode::Char(c) => KeyCode::Char(nav_key(c)),
                other => other,
            };
            if modifiers.contains(KeyModifiers::CONTROL) && (code == KeyCode::Char('c') || code == KeyCode::Char('C')) {
                let _ = disable_raw_mode();
                return PostTestAction::Quit;
            }

            match code {
                // Repeat: Enter or 'r' (any layout)
                KeyCode::Enter | KeyCode::Char('r') | KeyCode::Char('R') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Repeat;
                }

                // Menu: 'm' (any layout)
                KeyCode::Char('m') | KeyCode::Char('M') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Menu;
                }

                // Export: 's' (any layout)
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Export;
                }

                // Quit: 'q' (any layout) or Esc
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                    let _ = disable_raw_mode();
                    print!("\r\n");
                    let _ = stdout().flush();
                    return PostTestAction::Quit;
                }
                _ => {}
            }
        }
    }
}

pub(crate) fn export_report(path: &str, content: &str, msg: &Messages) {
    match std::fs::write(path, content) {
        Ok(()) => println_out(&format!("\x1b[1;32m{}\x1b[0m", msg.report_saved.replace("{}", path))),
        Err(e) => println_out(&format!("\x1b[1;33m{}\x1b[0m", msg.report_save_fail.replace("{}", &e.to_string()))),
    }
}

/// The name the tool gives its own report when the caller named no `-o` path:
/// `dpi_detector_results-20260925-010507.txt`.
///
/// The date and time are the run's local ones, in the order the Windows
/// diagnostic script names its report with (`yyyyMMdd-HHmmss`, `Get-Date`), so a
/// folder holding both reads and sorts the same way. Without them every export of
/// a session wrote the same file: the report an operator was about to send went
/// away with the next press of `S`, and the folder could not say which run a file
/// belonged to.
///
/// The offset comes from the OS (`chrono::Local`) rather than from arithmetic on
/// the epoch: a fixed offset would be wrong across a DST change, a hand-rolled one
/// would be wrong on every platform but the one it was written for, and this is
/// the only clock in the program that has to agree with the one on the desk.
pub(crate) fn default_report_name() -> String {
    format!("dpi_detector_results-{}.txt", stamp(&chrono::Local::now()))
}

/// `20260925-010507` — the stamp itself, over anything carrying the six fields,
/// so the format can be pinned without a clock and read by anyone who has to
/// reproduce one of these names.
fn stamp(dt: &(impl Datelike + Timelike)) -> String {
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report file is found and sorted by its name, so the stamp's order and
    /// its padding are the two things a reader depends on: `20260925-010507` is
    /// the shape `tools/diag/dns-ca-report.ps1` names its report with, and a
    /// regression that swapped day and month or dropped a zero would sort and
    /// read wrong in the folder.
    #[test]
    fn the_report_stamp_is_zero_padded_and_year_first() {
        let at = chrono::NaiveDate::from_ymd_opt(2026, 9, 25).unwrap().and_hms_opt(1, 5, 7).unwrap();
        assert_eq!(stamp(&at), "20260925-010507");
        let single = chrono::NaiveDate::from_ymd_opt(2001, 1, 9).unwrap().and_hms_opt(0, 0, 0).unwrap();
        assert_eq!(stamp(&single), "20010109-000000", "one-digit fields pad");
    }

    /// The name handed to `export_report` has to carry that stamp: the failure
    /// this guards is the fixed `dpi_detector_results.txt` coming back, which
    /// overwrites the report of the previous run, and a stamp that is in the
    /// string but not in the pattern (`2026-09-25`, seconds left out).
    #[test]
    fn the_generated_report_name_carries_the_stamp() {
        let name = default_report_name();
        let stamp = name
            .strip_prefix("dpi_detector_results-")
            .and_then(|rest| rest.strip_suffix(".txt"))
            .unwrap_or_else(|| panic!("the name is not the report name plus a stamp: {name}"));
        assert_eq!(stamp.len(), 15, "yyyymmdd-hhmmss: {name}");
        assert!(
            stamp.char_indices().all(|(i, c)| if i == 8 { c == '-' } else { c.is_ascii_digit() }),
            "{name} does not carry yyyymmdd-hhmmss"
        );
    }
}

//! After a run: the key read for the post-run menu and the report export.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
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

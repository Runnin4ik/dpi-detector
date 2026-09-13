//! The legend screen: prints the legend and answers its own key menu.

use crate::i18n::{Language, Messages, legend_text};
use std::io::{IsTerminal, Write, stdout};

use crate::{print_out, println_out};
use crate::render::panel_to_string;
use crate::tui::screens::post_run::{PostTestAction, read_post_test_action};

/// Legend-only interactive loop: shows the legend and its key menu until the user
/// repeats it, goes back to the menu, or quits.
pub(crate) fn legend_loop(lang: Language, msg: &Messages) -> MenuAction {
    loop {
        print_out(&legend_text(lang, msg));
        if !std::io::stdin().is_terminal() {
            return MenuAction::Quit;
        }
        println_out(&panel_to_string(
            msg.menu_control_menu,
            &[format!(
                "  \x1b[1;42;37m Enter \x1b[0m {}   \x1b[1;44;37m M \x1b[0m {}   \x1b[1;41;37m Q \x1b[0m {}",
                msg.menu_control_repeat, msg.menu_control_menu, msg.menu_control_exit
            )],
        ));
        let _ = stdout().flush();
        match read_post_test_action() {
            PostTestAction::Repeat => continue,
            PostTestAction::Menu => return MenuAction::Menu,
            PostTestAction::Export => continue,
            PostTestAction::Quit => return MenuAction::Quit,
        }
    }
}

pub(crate) enum MenuAction {
    Menu,
    Quit,
}

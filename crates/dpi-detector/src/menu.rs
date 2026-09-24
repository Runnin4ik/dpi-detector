//! Interactive terminal UI. The screens live in [`crate::tui::screens`] and the
//! key mapping in [`crate::tui::input`]; what the CLI shell drives is re-exported
//! here.

pub(crate) use crate::tui::screens::burst::burst_settings_menu;
pub(crate) use crate::tui::screens::main::{run_interactive_menu, tui_available, MenuResult, VersionSlot};

pub(crate) use crate::tui::screens::legend::{legend_loop, MenuAction};
pub(crate) use crate::tui::screens::main::{apply_interface, menu_until_something_to_run};
pub(crate) use crate::tui::screens::post_run::{
    export_report, read_post_test_action, PostTestAction,
};

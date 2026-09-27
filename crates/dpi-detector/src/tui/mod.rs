//! Terminal layer: escape and console plumbing, the widgets and width math the
//! screens draw with, and the live progress line.
//!
//! The interactive screens themselves live beside `views/` in
//! [`crate::screens`]: they render reports and therefore depend on `views`,
//! while `views` depends on the widgets here — one direction, `screens → views
//! → tui`.

pub(crate) mod backend;
pub(crate) mod input;
pub(crate) mod progress;
pub(crate) mod widgets;

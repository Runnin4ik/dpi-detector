//! dpi-core: high-performance, memory-efficient DPI detection engine

pub mod classify;
pub mod config;
pub mod dns;
pub mod net;
pub mod probe;
pub mod i18n;
pub mod profile;

/// Completion tick for live progress lines (mirrors rich `Progress.update`).
/// The renderer lives in the binary; core only signals "one unit done".
pub type ProgressTick = std::sync::Arc<dyn Fn() + Send + Sync>;

/// Phase switch: called with (description, total, parens) at each phase start,
/// returns the tick sink for the new phase. `parens` selects the
/// `desc (done/total)...` shape (rich phases) vs `desc done/total` (DNS bar).
#[derive(Clone)]
pub struct PhaseProgress {
    pub on_phase: std::sync::Arc<dyn Fn(String, usize, bool) -> ProgressTick + Send + Sync>,
}

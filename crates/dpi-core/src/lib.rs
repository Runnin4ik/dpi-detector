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

/// Diagnostic phase identifier for live progress reporting.
/// Language-independent: the renderer maps each variant to localized text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseId {
    /// DNS availability testing across configured resolvers
    DnsAvailability,
    /// Phase 0: DNS resolve of target domains
    DomainDns,
    /// Phase 1: TLS 1.3 handshake probes
    DomainTls13,
    /// Phase 2: TLS 1.2 handshake probes
    DomainTls12,
    /// Phase 3: Plain HTTP request probes
    DomainHttp,
    /// TCP 16–20 KB window throttling test
    Tcp16,
    /// Phase 1/2 of whitelist discovery: base check
    SniBase,
    /// Phase 2/2 of whitelist discovery: parallel SNI search
    SniParallel {
        detected_as: usize,
        batch: usize,
        top_n: usize,
    },
    /// Telegram data centers availability and speed test
    Telegram,
}

/// Phase switch: called with (phase_id, total, parens) at each phase start,
/// returns the tick sink for the new phase. `parens` selects the
/// `desc (done/total)...` shape (rich phases) vs `desc done/total` (DNS bar).
#[derive(Clone)]
pub struct PhaseProgress {
    pub on_phase: std::sync::Arc<dyn Fn(PhaseId, usize, bool) -> ProgressTick + Send + Sync>,
}

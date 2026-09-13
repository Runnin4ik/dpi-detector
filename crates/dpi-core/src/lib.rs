#![warn(unreachable_pub)]
//! dpi-core: high-performance, memory-efficient DPI detection engine

pub mod classify;
pub mod config;
pub mod dns;
pub mod net;
pub mod probe;
pub mod i18n;
pub mod profile;

/// Completion tick for live progress lines: called once per finished unit.
/// The renderer lives in the binary; core only signals "one unit done".
pub type ProgressTick = std::sync::Arc<dyn Fn() + Send + Sync>;

/// Diagnostic phase identifier for live progress reporting.
/// Language-independent: the renderer maps each variant to localized text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseId {
    /// Test 1: DNS resolver availability (reported as a block line, see
    /// [`ProgressBlock`])
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

/// One counter of a multi-block live progress line. Test 1 runs its blocks
/// concurrently, so they are all reported at once instead of one after
/// another. Tokens are canonical protocol names (rule 4): never translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressBlock {
    /// UDP resolver probes
    Udp,
    /// DoH endpoint probes (truth source)
    Doh,
    /// DoT endpoint probes (truth source)
    Dot,
    /// Egress fingerprint probes (`whoami.akamai.net`)
    Egress,
    /// Test 2 stage 0: DNS resolve of the target domains
    DomainDns,
    /// Test 2 stage 1: TLS 1.3 handshakes
    DomainTls13,
    /// Test 2 stage 2: TLS 1.2 handshakes
    DomainTls12,
    /// Test 2 stage 3: plain HTTP requests
    DomainHttp,
}

impl ProgressBlock {
    pub fn token(self) -> &'static str {
        match self {
            ProgressBlock::Udp => "UDP",
            ProgressBlock::Doh => "DoH",
            ProgressBlock::Dot => "DoT",
            ProgressBlock::Egress => "EGRESS",
            ProgressBlock::DomainDns => "DNS",
            ProgressBlock::DomainTls13 => "TLS 1.3",
            ProgressBlock::DomainTls12 => "TLS 1.2",
            ProgressBlock::DomainHttp => "HTTP",
        }
    }
}

impl PhaseId {
    /// The counter this phase owns on a line shared with other stages, for the
    /// phases that run one after another inside one test (test 2: DNS →
    /// TLS 1.3 → TLS 1.2 → HTTP). Phases that own a whole line return `None`.
    pub fn stage_block(self) -> Option<ProgressBlock> {
        match self {
            PhaseId::DomainDns => Some(ProgressBlock::DomainDns),
            PhaseId::DomainTls13 => Some(ProgressBlock::DomainTls13),
            PhaseId::DomainTls12 => Some(ProgressBlock::DomainTls12),
            PhaseId::DomainHttp => Some(ProgressBlock::DomainHttp),
            _ => None,
        }
    }
}

/// Ticks one block of the multi-block line; called as that block's own units
/// finish, never by a collector loop (a slow unit must not freeze the rest).
pub type BlockTick = std::sync::Arc<dyn Fn(ProgressBlock) + Send + Sync>;

/// Declares a single-counter phase and hands back its tick sink.
pub type PhaseSwitch = std::sync::Arc<dyn Fn(PhaseId, usize) -> ProgressTick + Send + Sync>;

/// Declares a multi-block phase: every counter that runs at the same time, and
/// the sink each of them ticks as its own units finish.
pub type BlocksSwitch =
    std::sync::Arc<dyn Fn(PhaseId, &[(ProgressBlock, usize)]) -> BlockTick + Send + Sync>;

/// Phase switch: called with (phase_id, total) at each phase start, returns
/// the tick sink for the new phase (called once per finished unit).
#[derive(Clone)]
pub struct PhaseProgress {
    pub on_phase: PhaseSwitch,
    /// Test 1 declares every block that runs at the same time and gets back a
    /// sink each block ticks as its units finish.
    pub on_blocks: BlocksSwitch,
}

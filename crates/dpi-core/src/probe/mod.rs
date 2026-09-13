use tokio::sync::{Semaphore, SemaphorePermit};

/// Takes one permit from a concurrency gate. `acquire` only fails when the
/// semaphore has been closed, and nothing in this crate ever closes one — the
/// gates live for the whole run and are dropped when it ends.
pub(crate) async fn permit(sem: &Semaphore) -> SemaphorePermit<'_> {
    sem.acquire().await.expect("concurrency gate is never closed")
}

pub mod connector;
pub mod cymru;
pub mod dns_avail;
pub mod tcp16;
pub mod domains;
pub mod burst;
pub mod telegram;
pub mod whitelist;
pub mod http;
pub use burst::{burst_targets, BurstAttempt, BurstProfileReport, BurstReport, BurstSettings, BurstTarget};
pub use tcp16::{check_tcp_16_20, probe_tcp16};
pub use telegram::{probe_telegram_all_dcs, probe_telegram_dc, run_download, run_telegram_full, run_telegram_test, run_upload, TelegramDcResult, TelegramFullReport, TelegramReport, TransferStats};
pub use whitelist::{run_whitelist_sni, AsRow, AsVerdict, WhitelistReport};

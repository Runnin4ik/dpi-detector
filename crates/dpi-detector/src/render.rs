//! Report rendering. The terminal layer lives in [`crate::tui`] (escapes, widgets
//! and width math, live progress) and one module per screen in [`crate::views`];
//! what the callers drive is re-exported here, so they keep naming the
//! presentation surface through `crate::render`.

pub use crate::tui::backend::{
    ascii_mode, clean_output, frame_home, output_str, plain_mode, set_ascii_mode, set_has_vt,
    set_plain_mode, strip_ansi,
};
pub use crate::tui::progress::{LiveProgress, Spinner};
pub use crate::tui::widgets::{asc, frame_repaint, panel_to_string, strip_ansi_len, BOX_WIDTH};
pub use crate::views::banner::{render_banner, render_fingerprint_header};
pub use crate::views::burst::render_burst_table;
pub use crate::views::dns::{render_dns_availability, render_dns_endpoints};
pub use crate::views::domains::{render_dns_resolve_notes, render_domain_table};
pub use crate::views::netinfo::{render_netinfo_panel, NetFamilyInfo, NetInfoData, NetTtlb};
pub use crate::views::summary::{render_summary, SummaryData};
pub use crate::views::tcp::{render_tcp_table, TcpRow};
pub use crate::views::telegram::render_telegram;
pub use crate::views::whitelist::render_whitelist;

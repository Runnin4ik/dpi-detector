//! Test 3: the TCP 16-20 KB table.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::*;
use crate::i18n::{Messages, detail_text, format_bidi};

use crate::tui::widgets::{cell_color, status_color, table_preset};

#[derive(Clone, serde::Serialize)]
pub(crate) struct TcpRow {
    pub id: String,
    pub asn: String,
    pub provider: String,
    pub status: DpiStatus,
    pub detail: Detail,
}

fn provider_group(provider: &str) -> String {
    let clean: String = provider.chars().filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '.' || *c == '-').collect();
    clean.split_whitespace().next().unwrap_or(&clean).to_string()
}

pub(crate) fn render_tcp_table(rows: &[TcpRow], msg: &Messages) -> String {
    let mut out = String::new();
    // Sort: provider group frequency desc, then group name, then id number.
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in rows {
        *counts.entry(provider_group(&r.provider)).or_insert(0) += 1;
    }
    let mut sorted: Vec<&TcpRow> = rows.iter().collect();
    sorted.sort_by(|a, b| {
        let ga = provider_group(&a.provider);
        let gb = provider_group(&b.provider);
        let ca = counts.get(&ga).copied().unwrap_or(0);
        let cb = counts.get(&gb).copied().unwrap_or(0);
        cb.cmp(&ca)
            .then(ga.cmp(&gb))
            .then(id_num(&a.id).cmp(&id_num(&b.id)))
    });

    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.col_id, msg.lang)),
            Cell::new(format_bidi(msg.col_asn, msg.lang)),
            Cell::new(format_bidi(msg.provider, msg.lang)),
            Cell::new(format_bidi(msg.status, msg.lang)),
            Cell::new(format_bidi(msg.detail, msg.lang)),
        ]);
    let mut passed = 0;
    let mut blocked = 0;
    let mut mixed = 0;
    for r in sorted {
        let label = r.status.display_label();
        if label.contains("OK") {
            passed += 1;
        } else if label.contains("DETECTED") {
            blocked += 1;
        } else if label.contains("MIXED") {
            mixed += 1;
        }
        table.add_row(vec![
            Cell::new(&r.id),
            Cell::new(cell_color(&r.asn, Color::Yellow)),
            Cell::new(cell_color(&r.provider, Color::Cyan)),
            Cell::new(cell_color(label, status_color(r.status))),
            Cell::new(detail_text(&r.detail, msg.lang)),
        ]);
    }
    out.push_str(&format!("\n{}\n", msg.tcp16_check_title));
    out.push_str(&format!("{}\n", table));
    if mixed > 0 {
        out.push_str(&format!("{}\n", msg.tcp_mixed_warn));
    }
    let _ = (passed, blocked);
    out
}

fn id_num(id: &str) -> u64 {
    id.rsplit('-').next().and_then(|s| s.parse().ok()).unwrap_or(99999)
}

//! Test 5: the Telegram full report.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::i18n::{Messages, detail_text, fmt_size, fmt_speed, format_bidi};
use dpi_core::probe::telegram::TelegramFullReport;

use crate::tui::widgets::{cell_color, table_preset};

pub fn render_telegram(report: &TelegramFullReport, msg: &Messages) -> String {
    
    let mut out = String::new();
    out.push_str(&format!("\n{}\n", msg.telegram_check_title));

    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.dc_col, msg.lang)),
            Cell::new(format_bidi(msg.ip_col, msg.lang)),
            Cell::new(format_bidi(msg.region, msg.lang)),
            Cell::new(format_bidi(msg.status, msg.lang)),
            Cell::new(format_bidi(msg.ping_col, msg.lang)),
        ]);
    for dc in &report.dc_results {
        let (label, color) = if dc.available {
            ("OK", Color::Green)
        } else {
            (msg.unavailable, Color::Red)
        };
        let ping = match dc.latency_ms {
            Some(l) => format!("{}{}", l, msg.ms_unit),
            None => match &dc.error {
                Some(err) => detail_text(err, msg.lang),
                None => "—".to_string(),
            },
        };
        // Region from telegram_dc_list order is not carried; show stored region
        table.add_row(vec![
            Cell::new(cell_color(&dc.name, Color::Cyan)),
            Cell::new(&dc.ip),
            Cell::new(&dc.region),
            Cell::new(cell_color(label, color)),
            Cell::new(ping),
        ]);
    }
    out.push_str(&format!("{}\n", table));

    // Download / upload verdict lines: label, status, peak, average, size, duration.
    for (label, t) in [(msg.download_label, &report.download), (msg.upload_label, &report.upload)] {
        let (st_text, color) = match t.status.as_str() {
            "ok" => ("OK", Color::Green),
            "stalled" => ("STALL", Color::Yellow),
            "slow" => ("SLOW", Color::Yellow),
            "blocked" => ("BLOCKED", Color::Red),
            _ => ("ERROR", Color::Red),
        };
        let mut line = format!(
            "  {}: {}  {} {}  {} {}  ({} / {:.0}s",
            label,
            st_text,
            msg.peak_label,
            fmt_speed(t.peak_bps, msg.lang),
            msg.avg_label,
            fmt_speed(t.avg_bps, msg.lang),
            fmt_size(t.bytes_total, msg.lang),
            t.duration
        );
        if let Some(sec) = t.drop_at_sec {
            line += &msg.stall_after.replace("{}", &sec.to_string());
        }
        line += ")";
        let _ = color;
        out.push_str(&format!("{}\n", line));
    }
    out.push('\n');
    out
}

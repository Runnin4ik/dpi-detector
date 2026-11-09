//! Test 8: the delivery node's throughput table.
//!
//! One row per measured address: which address, where it came from (the URL's
//! own node or the cluster the redirector named), what it answered, the rate
//! over the bytes that arrived and the detail of a failure. The rate is absent
//! when nothing arrived — a zero would read as a slow node rather than as no
//! measurement — and the status badge is the core's own Latin label, so a log
//! line greps alike for every user (rule 4).

use comfy_table::{Cell, ContentArrangement, Table};
use dpi_core::probe::ggc_speed::{MediaSource, ScanReport, SpeedAttempt, SpeedNode, SpeedTarget};

use crate::i18n::{detail_text, fmt_speed, format_bidi, Messages};
use crate::tui::widgets::{cell_color, status_color, table_preset};

/// Test 8's table, with the signed URL's node named above it: the host is the
/// half of the answer that says *which* cluster was measured, and a rate
/// without it is a number about nothing.
pub(crate) fn render_ggc_speed(
    source: &MediaSource,
    rows: &[(SpeedTarget, SpeedAttempt)],
    scan: Option<&ScanReport>,
    msg: &Messages,
) -> String {
    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.ggc_field_address, msg.lang)),
            Cell::new(format_bidi(msg.ggc_field_node, msg.lang)),
            Cell::new(format_bidi(msg.ggc_field_status, msg.lang)),
            Cell::new(format_bidi(msg.ggc_field_rate, msg.lang)),
            Cell::new(format_bidi(msg.detail, msg.lang)),
        ]);

    // An em dash, like the other tables' empty cells.
    let dash = "—";

    for (target, attempt) in rows {
        let node = match target.node {
            SpeedNode::UrlNode => msg.ggc_node_url,
            SpeedNode::MappedCluster => msg.ggc_node_mapped,
            SpeedNode::Scanned => msg.ggc_node_scan,
            SpeedNode::Named => msg.ggc_node_named,
        };
        // The rate the test measures is bytes per second; the tool's formatter
        // speaks bits, and one conversion here keeps every speed in the report
        // on one scale.
        let rate = match attempt.mb_per_sec() {
            Some(mb) => fmt_speed(mb * 8.0 * 1_000_000.0, msg.lang),
            None => dash.to_string(),
        };
        let detail = {
            let mut text = detail_text(&attempt.detail, msg.lang);
            if let Some(host) = &attempt.location_host {
                text.push_str(" → ");
                text.push_str(host);
            }
            // The name an address was found under is the row's other half: the
            // walk and the mapping find addresses, and a sibling name is the
            // only thing that says which of them has one.
            if let Some(name) = &target.name {
                if !text.is_empty() {
                    text.push_str(", ");
                }
                text.push_str(name);
            }
            text
        };
        table.add_row(vec![
            Cell::new(target.address.map(|a| a.to_string()).unwrap_or_else(|| dash.to_string())),
            Cell::new(format_bidi(node, msg.lang)),
            Cell::new(cell_color(attempt.status.display_label(), status_color(attempt.status))),
            Cell::new(rate),
            Cell::new(format_bidi(&detail, msg.lang)),
        ]);
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        msg.ggc_speed_title.replacen("{}", &source.host, 1)
    ));
    out.push_str(&format!("itag {}\n", source.itag));
    // The walk's own facts come before the table: the range and how much of it
    // was asked is what the rows under it are a sample of. A walk cut short by
    // its budget says so, so a short count is not read as "the block has no
    // more nodes".
    if let Some(report) = scan {
        let mut line = msg
            .ggc_scan_summary
            .replacen("{}", &report.prefix, 1)
            .replacen("{}", &report.scanned.to_string(), 1)
            .replacen("{}", &report.targets.len().to_string(), 1);
        if !report.complete {
            line.push_str(&format!(" ({})", msg.ggc_scan_partial));
        }
        out.push_str(&format!("{}\n", format_bidi(&line, msg.lang)));
    }
    out.push('\n');
    out.push_str(&format!("{table}\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{get_messages, Language};
    use dpi_core::classify::{Detail, DpiStatus};

    /// The walk's facts sit above the table, because they are what the rows are
    /// a sample of. The failure this pins is a summary printed under the table,
    /// where it reads as a caption for the last row rather than the range that
    /// was asked.
    #[test]
    fn test_walk_facts_precede_the_table() {
        let msg = get_messages(Language::En);
        let source = MediaSource {
            host: "r1.example.googlevideo.com".to_string(),
            path_and_query: "/videoplayback?id=1".to_string(),
            itag: 313,
            content_length: Some(1_000_000),
        };
        let rows = vec![(
            SpeedTarget {
                host: source.host.clone(),
                address: Some("192.0.2.78".parse().expect("an IPv4 address")),
                node: SpeedNode::UrlNode,
                name: None,
            },
            SpeedAttempt {
                status: DpiStatus::Ok,
                detail: Detail::None,
                bytes: 1_000_000,
                ttfb_ms: Some(10),
                ms: 500,
                location_host: None,
            },
        )];
        let scan = ScanReport {
            prefix: "192.0.2.0/24".to_string(),
            scanned: 254,
            complete: true,
            targets: Vec::new(),
        };
        let out = render_ggc_speed(&source, &rows, Some(&scan), &msg);
        let summary = out.find("192.0.2.0/24").expect("the range is printed");
        let table = out.find('┌').expect("the table is drawn");
        assert!(summary < table, "the walk's range must precede the table:\n{out}");
    }
}

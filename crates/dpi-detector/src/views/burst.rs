//! Test 6: the fingerprint burst table, one column per ClientHello profile.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::*;
use crate::i18n::{Messages, format_bidi};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::probe::burst::{BurstReport, BurstSettings};

use crate::tui::widgets::{cell_color, status_color, table_preset};

/// Test 6's table: one row per host, one column per profile, the cell being how
/// many of the simultaneous handshakes came back. The header names each profile
/// with the pinned version it reproduces (rule 4: Latin, never translated), and
/// the detail column names the failure that happened most often across the
/// profile columns.
pub fn render_burst_table(reports: &[BurstReport], settings: &BurstSettings, msg: &Messages) -> String {
    let profiles: &[TlsFingerprint] = &settings.profiles;
    let mut table = Table::new();
    let mut header = vec![Cell::new(format_bidi(msg.domain, msg.lang))];
    for fingerprint in profiles {
        // The version, not just the family: two runs of "CHROME" can differ in
        // the shape they sent, and the header is where that is read off.
        header.push(Cell::new(fingerprint.display_label()));
    }
    header.push(Cell::new(format_bidi(msg.detail, msg.lang)));
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(header);

    // A cell is green when everything was answered, red when nothing was, and
    // yellow in between: a burst that lost part of its handshakes is a weaker
    // signal than one that lost all of them.
    let cell_color_for = |answered: usize, total: usize| {
        if total == 0 {
            Color::DarkGrey
        } else if answered == total {
            Color::Green
        } else if answered == 0 {
            Color::Red
        } else {
            Color::Yellow
        }
    };

    for report in reports {
        let mut row = vec![Cell::new(cell_color(&report.domain, Color::Cyan))];
        for fingerprint in profiles {
            let cell = match report.profiles.iter().find(|p| p.fingerprint == *fingerprint) {
                Some(profile) => cell_color(
                    &format!("{}/{}", profile.answered(), profile.attempts.len()),
                    cell_color_for(profile.answered(), profile.attempts.len()),
                ),
                None => cell_color("—", Color::DarkGrey),
            };
            row.push(Cell::new(cell));
        }
        let (detail, detail_color) = match report.resolved {
            None => (
                DpiStatus::DnsFail.display_label().to_string(),
                status_color(DpiStatus::DnsFail),
            ),
            Some(_) => match report.dominant_failure() {
                Some((status, _, count)) => (
                    format!("{} ×{}", status.display_label(), count),
                    status_color(status),
                ),
                None => (DET_ALL_ANSWERED.to_string(), Color::DarkGrey),
            },
        };
        row.push(Cell::new(cell_color(&detail, detail_color)));
        table.add_row(row);
    }

    let mut out = String::new();
    out.push_str(&format!("{}\n", table));
    out
}

/// Detail cell of a host whose every handshake was answered: an em dash, like
/// the other tables' empty-detail cells.
const DET_ALL_ANSWERED: &str = "—";

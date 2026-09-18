//! Test 6: the fingerprint burst table, one column per ClientHello profile.

use std::fmt::Write;

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::*;
use crate::i18n::{Messages, format_bidi};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::probe::burst::{group_failures, BurstReport, BurstSettings};

use crate::tui::widgets::{cell_color, status_color, table_preset};

/// Test 6's table: one row per profile, one column per host, the cell being how
/// many of the overlapping handshakes came back. Rows are the shapes and columns
/// are the hosts because one run can hold every shape at once — twenty host
/// columns would be wider than any terminal, while twenty shapes read down the
/// list. The header names each host, a host whose name did not resolve carries
/// the DNS FAIL badge beside it (the column is dashes otherwise, with nothing to
/// say why), the row label names the shape with the pinned version it reproduces
/// (rule 4: Latin, never translated), and the detail cell groups the failures
/// that shape saw across every host by status, commonest first — the loudest one
/// leads and gives the cell its colour.
pub fn render_burst_table(reports: &[BurstReport], settings: &BurstSettings, msg: &Messages) -> String {
    let profiles: &[TlsFingerprint] = &settings.profiles;
    let mut table = Table::new();
    let mut header = vec![Cell::new(format_bidi(msg.burst_field_profiles, msg.lang))];
    for report in reports {
        let name = match report.resolved {
            Some(_) => report.domain.clone(),
            None => format!("{} ({})", report.domain, DpiStatus::DnsFail.display_label()),
        };
        header.push(Cell::new(cell_color(&name, Color::Cyan)));
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

    for fingerprint in profiles {
        let mut row = vec![Cell::new(fingerprint.display_label())];
        for report in reports {
            let cell = match report.profiles.iter().find(|p| p.fingerprint == *fingerprint) {
                Some(profile) => cell_color(
                    &format!("{}/{}", profile.answered(), profile.attempts.len()),
                    cell_color_for(profile.answered(), profile.attempts.len()),
                ),
                // A host that never resolved has no attempts to show, and one
                // the runner did not fire this shape at has none either.
                None => cell_color("—", Color::DarkGrey),
            };
            row.push(Cell::new(cell));
        }
        // Every failure this shape met, across every host: a shape that only
        // fails on one site reads as that site's status, not as a silent dash.
        let failures = group_failures(
            reports
                .iter()
                .flat_map(|report| report.profiles.iter())
                .filter(|profile| profile.fingerprint == *fingerprint)
                .flat_map(|profile| profile.attempts.iter())
                .map(|attempt| attempt.status),
        );
        let (detail, detail_color) = match failures.first() {
            None => (DET_ALL_ANSWERED.to_string(), Color::DarkGrey),
            Some((dominant, _)) => {
                // Every failure, not just the loudest one: a host whose 12 lost
                // handshakes came back as two different errors reads as two
                // groups, so nothing the run saw is dropped from the row. The
                // commonest one leads and colors it.
                let mut text = String::new();
                for (index, (status, count)) in failures.iter().enumerate() {
                    if index > 0 {
                        text.push_str(DETAIL_SEPARATOR);
                    }
                    let _ = write!(text, "{} ×{}", status.display_label(), count);
                }
                (text, status_color(*dominant))
            }
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

/// Between two failure groups in a detail cell (`TLS RST ×3 · SYN DROP ×1`).
const DETAIL_SEPARATOR: &str = " · ";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::get_messages;
    use crate::render::strip_ansi;

    fn attempt(status: DpiStatus) -> dpi_core::probe::burst::BurstAttempt {
        dpi_core::probe::burst::BurstAttempt { status, detail: Detail::RstHello, ms: 10 }
    }

    fn report(
        domain: &str,
        resolved: Option<&str>,
        profiles: &[(TlsFingerprint, &[DpiStatus])],
    ) -> BurstReport {
        BurstReport {
            domain: domain.to_string(),
            resolved: resolved.map(|ip| ip.parse().unwrap()),
            profiles: profiles
                .iter()
                .map(|(fingerprint, statuses)| dpi_core::probe::burst::BurstProfileReport {
                    fingerprint: *fingerprint,
                    attempts: statuses.iter().copied().map(attempt).collect(),
                })
                .collect(),
        }
    }

    /// The matrix is read the way a run is made: one row per shape down the side,
    /// one column per host across the top. Both host names share the header line
    /// (they are columns, not rows), a shape's cell is what that shape got on
    /// that host, and its detail cell carries what the shape met on *every* host
    /// — a shape that fails on one site still says so. A host whose name never
    /// resolved has no attempts to show, so its column says why it is dashes.
    #[test]
    fn the_burst_table_puts_shapes_in_rows_and_hosts_in_columns() {
        let msg = get_messages(crate::i18n::Language::En);
        let settings = BurstSettings {
            profiles: vec![TlsFingerprint::Rustls, TlsFingerprint::Chrome146],
            ..Default::default()
        };
        let reports = vec![
            report(
                "host-one.example",
                Some("192.0.2.1"),
                &[
                    (TlsFingerprint::Rustls, &[DpiStatus::Ok, DpiStatus::TlsRst]),
                    (TlsFingerprint::Chrome146, &[DpiStatus::Ok, DpiStatus::Ok]),
                ],
            ),
            report("host-two.example", None, &[]),
        ];
        let out = strip_ansi(&render_burst_table(&reports, &settings, &msg));

        let header = out.lines().find(|line| line.contains("host-one.example")).expect("a header");
        assert!(header.contains("host-two.example"), "hosts share one line: {header}");
        assert!(header.contains("DNS FAIL"), "an unresolved host says why: {header}");

        let rustls = out.lines().find(|line| line.contains("RUSTLS")).expect("a shape row");
        assert!(rustls.contains("1/2"), "the shape's own cell: {rustls}");
        assert!(rustls.contains("TLS RST ×1"), "failures from every host: {rustls}");
        assert_eq!(out.lines().filter(|line| line.contains("RUSTLS")).count(), 1, "one row per shape");

        let chrome = out.lines().find(|line| line.contains("CHROME")).expect("a shape row");
        assert!(chrome.contains("2/2") && chrome.contains("—"), "cells stay per host: {chrome}");
        assert!(chrome.contains(DET_ALL_ANSWERED), "nothing failed: {chrome}");
    }
}

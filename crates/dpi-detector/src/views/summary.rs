//! Summary panel: one row per tested area with its counters.

use crate::i18n::{Messages, fmt_size, fmt_speed};
use dpi_core::probe::domains::DomainStats;
use dpi_core::probe::telegram::TelegramFullReport;

use crate::tui::widgets::{BOX_WIDTH, asc, panel_to_string, strip_ansi_len, wrap_ansi};

fn frac_sgr(ok: usize, total: usize) -> &'static str {
    if total == 0 || ok == total {
        "32"
    } else if ok == 0 {
        "31"
    } else {
        "33"
    }
}

pub struct SummaryData<'a> {
    pub run_dns: bool,
    pub dns: Option<&'a dpi_core::probe::dns_avail::DnsAvailStats>,
    pub domains: Option<&'a DomainStats>,
    pub tcp: Option<(usize, usize, usize, usize)>, // ok, blocked, mixed, total
    pub run_telegram: bool,
    pub telegram: Option<&'a TelegramFullReport>,
}

pub fn render_summary(data: &SummaryData, msg: &Messages) -> String {
    let mut items: Vec<(String, String)> = Vec::new();

    if data.run_dns {
        if let Some(d) = data.dns {
            let doh_c = frac_sgr(d.doh_ok, d.doh_total);
            let udp_c = frac_sgr(d.udp_ok, d.udp_total);
            let mut parts = vec![format!("\x1b[{}m{}/{} DoH\x1b[0m", doh_c, d.doh_ok, d.doh_total)];
            if d.dot_total > 0 {
                let dot_c = frac_sgr(d.dot_ok, d.dot_total);
                parts.push(format!("\x1b[{}m{}/{} DoT\x1b[0m", dot_c, d.dot_ok, d.dot_total));
            }
            parts.push(format!("\x1b[{}m{}/{} UDP\x1b[0m", udp_c, d.udp_ok, d.udp_total));
            items.push((msg.summary_dns_avail.to_string(), parts.join("  ")));
            if !d.hijacked_brands.is_empty() {
                if d.resolvers_total > 0 && d.hijacked_brands.len() >= d.resolvers_total {
                    items.push((msg.summary_resolver_hijack.to_string(), format!("\x1b[31m{}\x1b[0m", msg.summary_all)));
                } else {
                    items.push((
                        msg.summary_resolver_hijack.to_string(),
                        format!("\x1b[31m{}\x1b[0m", d.hijacked_brands.join(", ")),
                    ));
                }
            } else {
                items.push((msg.summary_resolver_hijack.to_string(), "\x1b[2m—\x1b[0m".to_string()));
            }
            if d.subst_total > 0 {
                if d.fakeip_sub > 0 {
                    items.push((
                        msg.summary_fakeip_resp.to_string(),
                        format!("\x1b[35m{}/{} UDP\x1b[0m", d.fakeip_sub, d.subst_total),
                    ));
                }
                let rest = d.subst_sub.saturating_sub(d.fakeip_sub);
                if rest > 0 {
                    let c = if rest == d.subst_total { "31" } else { "33" };
                    items.push((
                        msg.summary_ans_hijack.to_string(),
                        format!("\x1b[{}m{}/{} UDP\x1b[0m", c, rest, d.subst_total),
                    ));
                } else if d.fakeip_sub == 0 {
                    items.push((
                        msg.summary_ans_hijack.to_string(),
                        format!("\x1b[32m0/{} UDP\x1b[0m", d.subst_total),
                    ));
                }
            }
        } else {
            items.push((msg.summary_dns_avail.to_string(), "\x1b[2m—\x1b[0m".to_string()));
        }
    }

    if let Some(d) = data.domains {
        let stat = |label: &str, ok: usize| {
            let c = frac_sgr(ok, d.total);
            format!("\x1b[{}m{}/{} {}\x1b[0m", c, ok, d.total, label)
        };
        items.push((
            msg.summary_domains.to_string(),
            format!("{}  {}  {}", stat("HTTP", d.http_ok), stat("TLS1.2", d.t12_ok), stat("TLS1.3", d.t13_ok)),
        ));
    }

    if let Some((ok, blocked, mixed, total)) = data.tcp {
        let pct = ok.checked_mul(100).and_then(|v| v.checked_div(total)).unwrap_or(0);
        let mut value = format!("\x1b[32m√ {}/{} OK\x1b[0m", ok, total);
        if blocked > 0 {
            value += &format!("  \x1b[31m× {} {}\x1b[0m", blocked, msg.blocked_short);
        }
        if mixed > 0 {
            value += &format!("  \x1b[33m≈ {} {}\x1b[0m", mixed, msg.mixed_short);
        }
        value += &format!("  \x1b[2m({}% OK)\x1b[0m", pct);
        items.push(("TCP 16-20KB".to_string(), value));
    }

    if data.run_telegram {
        if let Some(t) = data.telegram {
            
            let tg_row = |label: &str, st: &dpi_core::probe::telegram::TransferStats, speed: f64, size: u64| {
                let (raw, sgr) = match st.status.as_str() {
                    "ok" => ("OK", "32"),
                    "stalled" => ("STALL", "33"),
                    "slow" => ("SLOW", "33"),
                    "blocked" => ("BLOCKED", "31"),
                    _ => ("ERROR", "31"),
                };
                let mut metrics = format!("{} {}, {}", msg.avg_label, fmt_speed(speed, msg.lang), fmt_size(size, msg.lang));
                if let Some(sec) = st.drop_at_sec {
                    metrics += &msg.stall_after.replace("{}", &sec.to_string());
                }
                (label.to_string(), format!("\x1b[{}m{:<16}\x1b[0m {}", sgr, raw, metrics))
            };
            let (l1, v1) = tg_row(msg.summary_tg_download, &t.download, t.download.avg_bps, t.download.bytes_total);
            let (l2, v2) = tg_row(msg.summary_tg_upload, &t.upload, t.upload.avg_bps, t.upload.bytes_total);
            items.push((l1, v1));
            items.push((l2, v2));
            let dc_c = if t.dc_reachable == t.dc_total {
                "32"
            } else if t.dc_reachable == 0 {
                "31"
            } else {
                "33"
            };
            items.push((
                msg.summary_tg_datacenters.to_string(),
                format!("\x1b[{}mOK {}/{}\x1b[0m", dc_c, t.dc_reachable, t.dc_total),
            ));
        }
    }

    if items.is_empty() {
        return String::new();
    }
    // Two columns: the label column never wraps, so pad it to its widest entry
    // and every value starts at the same offset. Widths are measured after ANSI
    // stripping, and per character, because CJK labels are two cells wide.
    let label_w = items.iter().map(|(label, _)| strip_ansi_len(label)).max().unwrap_or(0);
    // The value column: indent + label column + gap, and what is left of a row
    // once the borders and the single space around the content are taken out.
    let value_col = 2 + label_w + 2;
    let value_w = BOX_WIDTH.saturating_sub(3 + value_col);
    let mut lines = Vec::new();
    for (label, val) in items {
        let pad = label_w.saturating_sub(strip_ansi_len(&label));
        // `asc` widens glyphs in ASCII mode (`✓` becomes `[OK]`), so it has to run
        // before the width is measured; `panel_with` repeats it on the finished
        // line, which is idempotent.
        let value = asc(&val);
        for (i, chunk) in wrap_ansi(&value, value_w).into_iter().enumerate() {
            if i == 0 {
                lines.push(format!("  \x1b[1m{}{}\x1b[0m  {}", label, " ".repeat(pad), chunk));
            } else {
                lines.push(format!("{}{}", " ".repeat(value_col), chunk));
            }
        }
    }
    panel_to_string(msg.summary_title, &lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::backend::strip_ansi;
    /// The summary is a two-column table (label, value): the label column is
    /// padded to its widest entry, so a short label cannot pull its value out of
    /// the column.
    #[test]
    fn summary_rows_align_their_values_into_two_columns() {
        use crate::i18n::{get_messages, Language};
        let msg = get_messages(Language::Ru);
        let out = render_summary(
            &SummaryData {
                run_dns: true,
                dns: None,
                domains: None,
                tcp: Some((104, 0, 0, 110)),
                run_telegram: false,
                telegram: None,
            },
            &msg,
        );
        let rows: Vec<Vec<char>> = out
            .lines()
            .map(strip_ansi)
            .filter(|l| l.starts_with('│'))
            .map(|l| l.chars().collect())
            .collect();
        assert_eq!(rows.len(), 2, "one row per item, no wrapping");
        // Border, one space, the two-space indent, the label column, the gap.
        let longest = msg.summary_dns_avail.chars().count();
        let short = "TCP 16-20KB".len();
        assert!(longest > short, "the two labels must differ in width: {longest} vs {short}");
        let value_col = 1 + 1 + 2 + longest + 2;
        for row in &rows {
            let line: String = row.iter().collect();
            assert_ne!(row[value_col], ' ', "the value starts in the column: {line:?}");
            let gap: String = row[value_col - 2..value_col].iter().collect();
            assert_eq!(gap, "  ", "the column gap is intact: {line:?}");
        }
        // The short label is padded up to the column, not left ragged.
        let short_end = 1 + 1 + 2 + short;
        let pad: String = rows[1][short_end..value_col].iter().collect();
        assert_eq!(pad, " ".repeat(value_col - short_end), "pad the short label to the column");
    }

    /// The panel is a fixed-width box: `panel_with` pads a row, it cannot reflow
    /// one, so a value wider than its column has to be wrapped by the summary
    /// itself - otherwise it pushes the right border off the line.
    #[test]
    fn summary_wraps_a_long_value_inside_the_box() {
        use dpi_core::probe::dns_avail::DnsAvailStats;
        use crate::i18n::{get_messages, Language};
        let msg = get_messages(Language::Ru);
        let brands: Vec<String> = [
            "Cloudflare IP 2", "Google", "Level 3", "Level 3 2", "MSK-IX", "OpenDNS", "XboxDNS",
            "НСДИ",
        ]
        .iter()
        .map(|b| b.to_string())
        .collect();
        let stats = DnsAvailStats {
            doh_ok: 33,
            doh_total: 37,
            dot_ok: 33,
            dot_total: 34,
            udp_ok: 44,
            udp_total: 50,
            hijacked_brands: brands.clone(),
            resolvers_total: 120,
            subst_sub: 43,
            subst_total: 44,
            fakeip_sub: 0,
            top_stub: None,
        };
        let out = render_summary(
            &SummaryData {
                run_dns: true,
                dns: Some(&stats),
                domains: None,
                tcp: None,
                run_telegram: false,
                telegram: None,
            },
            &msg,
        );
        let rows: Vec<String> =
            out.lines().map(strip_ansi).filter(|l| l.starts_with('│')).collect();
        // Every row is exactly the box width: nothing spills past the border.
        for row in &rows {
            assert_eq!(strip_ansi_len(row), BOX_WIDTH, "{row:?}");
        }
        // One row for DNS availability, two for the hijack list, one for the
        // answer substitution - the list is the only value too wide to fit.
        assert_eq!(rows.len(), 4, "{rows:#?}");
        let label_w = msg.summary_resolver_hijack.chars().count();
        let value_col = 1 + 1 + 2 + label_w + 2;
        let list: Vec<String> = rows[1..rows.len() - 1]
            .iter()
            .map(|row| {
                assert_eq!(row.chars().nth(value_col - 1), Some(' '), "gap before the value: {row:?}");
                assert_ne!(row.chars().nth(value_col), Some(' '), "a value starts in the column: {row:?}");
                let text: String = row.chars().skip(value_col).collect();
                text.trim_end_matches('│').trim_end().to_string()
            })
            .collect();
        assert!(rows[1].contains(msg.summary_resolver_hijack), "the label sits on the first line");
        assert!(!rows[2].contains(msg.summary_resolver_hijack), "the continuation repeats no label");
        assert_eq!(list.join(" "), brands.join(", "), "wrapping loses no entry");
    }
}

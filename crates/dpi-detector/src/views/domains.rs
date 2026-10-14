//! Test 2: the domain table and the DNS resolve notes printed under it.

use comfy_table::{Cell, Color, ContentArrangement, Table};
use dpi_core::classify::*;
use crate::i18n::{Language, Messages, detail_text, format_bidi};
use dpi_core::probe::domains::{DetailLine, DomainEntry};

use crate::tui::widgets::{cell_color, status_color, table_preset};

pub(crate) fn render_domain_table(entries: &[DomainEntry], msg: &Messages) -> String {
    let mut out = String::new();
    let mut table = Table::new();
    table
        .load_preset(table_preset())
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new(format_bidi(msg.domain, msg.lang)),
            Cell::new(msg.http),
            Cell::new(msg.tls12),
            Cell::new(msg.tls13),
            Cell::new(msg.quic_col),
            Cell::new(format_bidi(msg.detail, msg.lang)),
        ]);

    for e in entries {
        let (http, tls12, tls13, quic, raw_details) = dpi_core::probe::domains::build_domain_row(e);
        let details = row_details(&raw_details, msg.lang);
        table.add_row(vec![
            Cell::new(cell_color(&e.domain, Color::Cyan)),
            Cell::new(proto_cell(http, &e.http.detail)),
            Cell::new(proto_cell(tls12, &e.t12.detail)),
            Cell::new(proto_cell(tls13, &e.t13.detail)),
            Cell::new(proto_cell(quic, &e.quic.detail)),
            Cell::new(details),
        ]);
    }

    out.push_str(&format_bidi(msg.domain_title, msg.lang));
    out.push('\n');
    out.push_str(&format!("{}\n", table));
    out
}

/// One protocol cell of the domain table.
///
/// A cell that was never measured prints the dash, not a verdict. `Unknown` is
/// that state — `DomainEntry::pending` starts every column as `Unknown` with no
/// detail, and a scan that is aborted mid-row can reach the table with the row
/// still in it — and `build_domain_row` reads it the same way when it decides
/// which details a row carries. `Unknown` *with* a detail is a real
/// unclassifiable failure and keeps the red `UNKNOWN` it always had.
///
/// The dash is the glyph the QUIC column already prints for a host that serves
/// no HTTP/3: one cell that is not a verdict, one glyph, spelled in one place.
fn proto_cell(status: DpiStatus, detail: &Detail) -> String {
    if status == DpiStatus::Unknown && detail.is_none() {
        cell_color(DpiStatus::QuicUnsupported.display_label(), Color::DarkGrey)
    } else {
        cell_color(status.display_label(), status_color(status))
    }
}

/// Detail cell of the domain table: one line per reason a row failed for, and a
/// `TLS:`-style prefix only when the row carries more than one reason — the lines
/// then name the protocols they belong to, joined in the table's own column order
/// (`HTTP,TLS13:→ m.megafonpro.ru`). One protocol name, or none, comes from the
/// core (`build_domain_row`); the names are canonical Latin tokens (Rule 4) and
/// stay untranslated.
///
/// A row where every protocol passed carries the four stage timings instead —
/// `0.2s,0.2s,0.2s,0.2s`, one per column in the table's order (HTTP, TLS 1.2,
/// TLS 1.3, QUIC).
fn row_details(lines: &[DetailLine], lang: Language) -> String {
    lines
        .iter()
        .map(|line| match line {
            DetailLine::Tagged(protos, detail) => {
                let text = detail_text(detail, lang);
                if protos.is_empty() {
                    text
                } else {
                    format!("{}:{}", protos.join(","), text)
                }
            }
            DetailLine::Timings([http, tls12, tls13, quic]) => {
                format!("{:.1}s,{:.1}s,{:.1}s,{:.1}s", http, tls12, tls13, quic)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Post-table DNS resolve notes (stubs, fake-ip, DoH recommendation).
pub(crate) fn render_dns_resolve_notes(entries: &[DomainEntry], msg: &Messages) -> String {
    use dpi_core::probe::domains::FakeIpType;
    let mut out = String::new();

    let mut dns_fail: usize = 0;
    let mut isp_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut local_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut fakeip_stubs: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for e in entries {
        if e.t13.status == DpiStatus::DnsFail || e.t12.status == DpiStatus::DnsFail || e.http.status == DpiStatus::DnsFail {
            dns_fail += 1;
        }
        if let Some(ip) = e.resolved {
            if dpi_core::probe::domains::fake_ip_type(&ip) == FakeIpType::FakeIp {
                *fakeip_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
            // ISP stub = resolved IP present in stub set is decided upstream;
            // here DNS FAKE/LOCAL IP statuses mark them.
            if e.t13.status == DpiStatus::DnsFake {
                *isp_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
            if e.t13.status == DpiStatus::LocalIp {
                *local_stubs.entry(ip.to_string()).or_insert(0) += 1;
            }
        }
    }

    if isp_stubs.is_empty() && local_stubs.is_empty() && fakeip_stubs.is_empty() && dns_fail == 0 {
        return out;
    }

    out.push_str(&format!("\n{}\n", msg.dns_info_title));
    if !fakeip_stubs.is_empty() {
        let total: usize = fakeip_stubs.values().sum();
        out.push_str(&format!("{}\n", msg.traffic_fakeip.replace("{}", &total.to_string())));
    }
    if !isp_stubs.is_empty() {
        let total: usize = isp_stubs.values().sum();
        if isp_stubs.len() <= 3 {
            let ips: Vec<String> = isp_stubs.keys().cloned().collect();
            let s = msg.dns_isp_stub.replacen("{}", &ips.join(", "), 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        } else {
            let s = msg.dns_isp_stub.replacen("({})", "", 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        }
    }
    if !local_stubs.is_empty() {
        let total: usize = local_stubs.values().sum();
        if local_stubs.len() <= 3 {
            let ips: Vec<String> = local_stubs.keys().cloned().collect();
            let s = msg.dns_local_ip.replacen("{}", &ips.join(", "), 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        } else {
            let s = msg.dns_local_ip.replacen("({})", "", 1).replacen("{}", &total.to_string(), 1);
            out.push_str(&format!("{}\n", s));
        }
    }
    if dns_fail > 0 {
        out.push_str(&format!("{}\n", msg.dns_fail_detected.replace("{}", &dns_fail.to_string())));
    }
    if !isp_stubs.is_empty() || dns_fail > 0 {
        out.push_str(msg.doh_flush_guide);
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure this pins: `DomainEntry::pending` starts every column as
    /// `Unknown` with no detail, and a row that reached the table in that state
    /// printed the red `UNKNOWN` a real unclassifiable error gets — a cell that
    /// was never measured read as a block. The dash is what the QUIC column
    /// prints for a host that serves no HTTP/3, and it is grey, never red.
    #[test]
    fn an_unmeasured_cell_is_the_dash_and_a_real_unknown_error_is_not() {
        let dash = proto_cell(DpiStatus::Unknown, &Detail::None);
        assert!(dash.contains(DpiStatus::QuicUnsupported.display_label()), "{dash:?}");
        assert!(!dash.contains("UNKNOWN"), "{dash:?}");

        // An `Unknown` that carries a detail is a failure, not an absent
        // measurement, and must keep saying so.
        let error = proto_cell(DpiStatus::Unknown, &Detail::Other("boom".to_string()));
        assert!(error.contains("UNKNOWN"), "{error:?}");

        // Measured verdicts are untouched, the QUIC "not applicable" included.
        assert!(proto_cell(DpiStatus::Ok, &Detail::None).contains("OK"));
        let unsupported = proto_cell(DpiStatus::QuicUnsupported, &Detail::None);
        assert!(unsupported.contains(DpiStatus::QuicUnsupported.display_label()), "{unsupported:?}");
        assert!(proto_cell(DpiStatus::TlsRst, &Detail::RstHello).contains("TLS RST"));
    }

    /// The details cell has a rendering rule of its own: the names the core put
    /// on a line are joined by a comma in the order the table prints the columns,
    /// a colon separates them from the detail, and a line the core left unnamed
    /// gets no colon at all. Regression: the first version of the shared line
    /// would have rendered `:→ host` for a row with a single reason.
    #[test]
    fn the_details_cell_joins_the_names_that_share_a_reason() {
        let lang = Language::Ru;
        let redirect = Detail::Redirect { host: "m.megafonpro.ru".to_string() };

        assert_eq!(
            row_details(&[DetailLine::Tagged(vec!["HTTP", "TLS13"], redirect.clone())], lang),
            "HTTP,TLS13:→ m.megafonpro.ru"
        );
        assert_eq!(
            row_details(&[DetailLine::Tagged(vec![], redirect.clone())], lang),
            "→ m.megafonpro.ru"
        );
        assert_eq!(
            row_details(&[DetailLine::Tagged(vec!["TLS12"], redirect.clone())], lang),
            "TLS12:→ m.megafonpro.ru"
        );
    }

    /// One row whose four columns all carry `status`/`detail`.
    fn row(domain: &str, status: DpiStatus, detail: Detail) -> DomainEntry {
        use dpi_core::probe::domains::{HttpCheck, TlsCheck};
        use dpi_core::probe::quic::QuicCheck;
        let tls = TlsCheck { status, detail: detail.clone(), cert: Detail::None, elapsed: 0.0 };
        DomainEntry {
            domain: domain.to_string(),
            resolved: Some("203.0.113.7".parse().unwrap()),
            dns_fake: Some(false),
            t13: tls.clone(),
            t12: tls,
            http: HttpCheck { status, detail: detail.clone(), elapsed: 0.0 },
            quic: QuicCheck { status, detail, elapsed: 0.0 },
        }
    }

    /// The table is the surface a consumer reads, so the two "not measured"
    /// shapes are pinned there and not only in the cell helper: a row that never
    /// ran shows the dash rather than a verdict, and a row whose address family
    /// this run could not reach is named `NO IPV6` instead of `DNS FAIL`.
    #[test]
    fn the_table_names_a_missing_family_and_shows_no_verdict_for_an_unmeasured_row() {
        use crate::i18n::get_messages;
        let msg = get_messages(Language::En);

        let pending =
            render_domain_table(&[row("never.example", DpiStatus::Unknown, Detail::None)], &msg);
        assert!(!pending.contains("UNKNOWN"), "{pending}");
        assert!(pending.contains(DpiStatus::QuicUnsupported.display_label()), "{pending}");

        let v6 = render_domain_table(
            &[row("v6.example", DpiStatus::NoIpv6, Detail::Ipv6Unsupported)],
            &msg,
        );
        assert!(v6.contains("NO IPV6"), "{v6}");
        assert!(!v6.contains("DNS FAIL"), "{v6}");
    }
}

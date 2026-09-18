//! The banner and the fingerprint header: what a report opens with.

use crate::i18n::{Messages, fingerprint_label};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::sysinfo::intercept::{Intercept, ListFix, Missing, Problem, Unchecked};
use dpi_core::profile::RegionProfile;

use crate::tui::widgets::{asc, panel_with, BOX_WIDTH};

/// What to print about interception before a run, if anything.
///
/// Silence in the two states that do not need a reader's attention: the traffic
/// *is* intercepted, or the package is not running at all. Everything else is
/// one header and a list, where each entry carries its own fix on the lines
/// under it — so a reader who has two problems fixes both in one pass, and a
/// reader whose check did not complete is not left reading an empty list as a
/// clean bill.
///
/// The bullet, the indent and the restart command are added here rather than
/// stored per language: they are layout and one path, and they must read the
/// same in all four.
pub fn render_intercept_notice(msg: &Messages, found: Option<&Intercept>) -> Option<String> {
    let found = found?;
    if found.problems.is_empty() && found.unchecked.is_empty() {
        return None;
    }
    let mut body = String::from(msg.intercept_header);
    for problem in &found.problems {
        body.push('\n');
        body.push_str(&entry(&problem_text(msg, found, problem)));
        if let Problem::ListRecipe { fixes } = problem {
            for fix in fixes {
                match fix {
                    // Config lines, not prose: printed flush left, so they can
                    // be copied into the config exactly as they read here.
                    ListFix::Assign { variable, value } => {
                        body.push_str(&format!("\n{variable}=\"{value}\""));
                    }
                    // A whole strategy is not pasted back: the options to drop
                    // are prose, and they go under the entry like the rest.
                    ListFix::Drop { variable, options } => {
                        let options = options.join(" ");
                        body.push('\n');
                        body.push_str(&format!(
                            "    {}",
                            msg.intercept_list_drop.replacen("{}", variable, 1).replacen("{}", &options, 1)
                        ));
                    }
                }
            }
        }
    }
    for unchecked in &found.unchecked {
        body.push('\n');
        body.push_str(&entry(&unchecked_text(msg, *unchecked)));
    }
    // A family the device has no route for is worth saying out loud, but there
    // is nothing in the package to change about it, so nothing follows it.
    let changed =
        !found.problems.is_empty() || found.unchecked.iter().any(|u| *u != Unchecked::Route);
    let tail = if changed { format!("\n\n{}", msg.intercept_after) } else { String::new() };
    Some(format!("\n\x1b[33m{body}{tail}\x1b[0m\n"))
}

/// One entry: the problem behind a bullet, what to do about it indented under.
fn entry(text: &str) -> String {
    let bullet = asc("•");
    let mut out = String::new();
    for (n, line) in text.lines().enumerate() {
        if n == 0 {
            out.push_str(&format!("  {} {}", bullet, line));
        } else {
            out.push_str(&format!("\n    {}", line));
        }
    }
    out
}

/// One problem as it reads, with the values only the core knows filled in.
fn problem_text(msg: &Messages, found: &Intercept, problem: &Problem) -> String {
    match problem {
        Problem::Excluded => match found.policy.as_deref() {
            Some(policy) => msg.intercept_excluded.replacen("{}", policy, 1),
            None => msg.intercept_excluded_unnamed.to_string(),
        },
        Problem::Interface => {
            let rules = if found.rules_interfaces.is_empty() {
                "?".to_string()
            } else {
                found.rules_interfaces.join(", ")
            };
            let ours = found.our_interface.clone().unwrap_or_else(|| "?".to_string());
            msg.intercept_interface.replacen("{}", &rules, 1).replacen("{}", &ours, 1)
        }
        Problem::Tunnel => msg.intercept_tunnel.to_string(),
        Problem::Port { port, missing } => {
            let side = match missing {
                Missing::Queue => msg.intercept_ports_queue,
                Missing::Filters => msg.intercept_ports_filters,
                Missing::Both => msg.intercept_ports_both,
            };
            msg.intercept_ports
                .replacen("{}", &port.to_string(), 1)
                .replacen("{}", side, 1)
        }
        Problem::Ipv6 => msg.intercept_ipv6.to_string(),
        Problem::ListRecipe { .. } => msg.intercept_list_recipe.to_string(),
        Problem::ListNamed { profile, option } => msg
            .intercept_list_named
            .replacen("{}", profile, 1)
            .replacen("{}", option, 1),
    }
}

/// One reason the check did not complete.
fn unchecked_text(msg: &Messages, unchecked: Unchecked) -> String {
    match unchecked {
        Unchecked::Config => msg.intercept_unchecked_config.to_string(),
        Unchecked::Queue => msg.intercept_unchecked_queue.to_string(),
        Unchecked::Route => msg.intercept_unchecked_route.to_string(),
    }
}

pub fn render_banner(msg: &Messages, _profile: RegionProfile, badge: &str) -> String {
    let badge_colored = if badge.starts_with("✓") {
        format!("\x1b[38;2;90;247;142m{}\x1b[0m", badge)
    } else if badge.starts_with("↑") {
        format!("\x1b[33m{}\x1b[0m", badge)
    } else {
        format!("\x1b[2m{}\x1b[0m", badge)
    };
    let version_line = format!("DPI Detector v{}", env!("CARGO_PKG_VERSION"));
    let row1 = format!(
        "  \x1b[2m{}\x1b[0m \x1b[38;2;214;180;255mRunni\x1b[0m \x1b[36m•\x1b[0m \x1b[2mGitHub:\x1b[0m Runnin4ik/dpi-detector",
        msg.author
    );
    let row2 = format!(
        "  \x1b[2m{}\x1b[0m t.me/DPI_detector \x1b[36m•\x1b[0m {}",
        msg.chat, badge_colored
    );
    panel_with(&version_line, &[row1, row2], BOX_WIDTH, false, "36")
}

/// Active TLS fingerprint line(s) for the human report header (text mode only).
/// One line with the profile — its canonical token and the version the shape
/// reproduces (`Fingerprint: CHROME 133`, `Fingerprint: RUSTLS (default)`) —
/// and, for every non-default profile, the translated caveat on a second line.
/// The `[!]` prefix and colors are added here, never stored in i18n; the
/// profile list itself is generated into `--legend` from the profile table.
pub fn render_fingerprint_header(fp: TlsFingerprint, msg: &Messages) -> String {
    let head = format!("{}: {}", msg.fingerprint_label, fingerprint_label(fp, msg.lang));
    if fp != TlsFingerprint::Rustls {
        let note = format!("\x1b[33m[!]\x1b[0m \x1b[2m{}\x1b[0m", msg.fingerprint_note);
        format!("{}\n{}", head, note)
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{get_messages, Language};
    use dpi_core::net::sysinfo::intercept::ListFix;

    fn found(problems: Vec<Problem>) -> Intercept {
        Intercept {
            problems,
            unchecked: Vec::new(),
            policy: Some("nfqws".to_string()),
            rules_interfaces: vec!["wan0".to_string()],
            our_interface: Some("wwan1".to_string()),
        }
    }

    /// The same, with the check itself incomplete.
    fn unchecked(reasons: Vec<Unchecked>) -> Intercept {
        Intercept { unchecked: reasons, ..found(Vec::new()) }
    }

    /// The two states that need no reader attention print nothing at all.
    #[test]
    fn a_working_bypass_and_a_missing_package_stay_silent() {
        let msg = get_messages(Language::En);
        assert_eq!(render_intercept_notice(&msg, None), None, "package not running");
        assert_eq!(
            render_intercept_notice(&msg, Some(&found(Vec::new()))),
            None,
            "traffic is intercepted"
        );
    }

    /// A notice is a block: a blank line above, the entries, a blank line, and
    /// the fixed closing line.
    #[test]
    fn a_notice_ends_with_the_fixed_line() {
        let msg = get_messages(Language::En);
        let notice = render_intercept_notice(&msg, Some(&found(vec![Problem::Excluded]))).unwrap();
        assert!(notice.starts_with('\n'), "{notice:?}");
        assert!(notice.trim_end().contains(msg.intercept_after), "{notice}");
        assert!(notice.contains("nfqws"), "the policy the package looks for: {notice}");
        assert_eq!(notice.lines().filter(|l| l.is_empty()).count(), 2, "{notice}");
    }

    /// The interface case names both interfaces, so the reader knows what to
    /// move where.
    #[test]
    fn the_interface_case_shows_both_interfaces() {
        let msg = get_messages(Language::En);
        let notice =
            render_intercept_notice(&msg, Some(&found(vec![Problem::Interface]))).unwrap();
        assert!(notice.contains("wan0"), "{notice}");
        assert!(notice.contains("wwan1"), "{notice}");
        assert!(notice.contains("ISP_INTERFACE"), "with the key to change: {notice}");
    }

    /// The port entry names the port and the side it is missing from: the
    /// package's queue list and the strategy's filters are edited in different
    /// places, so "TCP_PORTS or --filter-tcp" tells a reader nothing.
    #[test]
    fn the_port_entry_names_the_port_and_the_side() {
        let msg = get_messages(Language::En);
        let side = |port: u16, missing: Missing| {
            let state = found(vec![Problem::Port { port, missing }]);
            render_intercept_notice(&msg, Some(&state)).unwrap()
        };
        let queue = side(80, Missing::Queue);
        assert!(queue.contains("port 80"), "{queue}");
        assert!(queue.contains("from TCP_PORTS"), "{queue}");
        assert!(!queue.contains("--filter-tcp"), "one side only: {queue}");
        let filters = side(443, Missing::Filters);
        assert!(filters.contains("port 443"), "{filters}");
        assert!(filters.contains("from --filter-tcp"), "{filters}");
        assert!(!filters.contains("from TCP_PORTS"), "one side only: {filters}");
        let both = side(80, Missing::Both);
        assert!(both.contains("from both TCP_PORTS and --filter-tcp"), "{both}");
    }

    /// Two problems hold at once and the block says both, under one header: a
    /// reader who fixes one should not have to run the detector again to meet
    /// the next.
    #[test]
    fn several_problems_share_one_header() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::En);
        let state = found(vec![
            Problem::Ipv6,
            Problem::Port { port: 443, missing: Missing::Filters },
        ]);
        let body = strip_ansi(&render_intercept_notice(&msg, Some(&state)).unwrap());
        assert_eq!(body.matches(msg.intercept_header).count(), 1, "printed once: {body}");
        assert!(body.contains("IPV6_ENABLED=0"), "{body}");
        assert!(body.contains("--filter-tcp"), "{body}");
        // Both entries are bullets of the same list, and what to do sits under
        // them rather than in a paragraph of its own.
        assert_eq!(body.matches("  • ").count(), 2, "{body}");
        assert!(body.contains("\n    Set IPV6_ENABLED=1"), "{body}");
        assert_eq!(body.matches(msg.intercept_after).count(), 1, "once, at the end: {body}");
    }

    /// The recipe prints two shapes: a one-line value as the config line to
    /// paste, and a whole strategy as the options to drop from it. The first is
    /// code and goes flush left; the second is prose and stays indented.
    #[test]
    fn the_list_recipe_prints_both_shapes() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::En);
        let state = found(vec![Problem::ListRecipe {
            fixes: vec![
                ListFix::Assign {
                    variable: "NFQWS_EXTRA_ARGS".to_string(),
                    value: "$MODE_ALL".to_string(),
                },
                ListFix::Assign {
                    variable: "NFQWS_ARGS_IPSET".to_string(),
                    value: "--ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list".to_string(),
                },
                ListFix::Drop {
                    variable: "NFQWS_ARGS_CUSTOM".to_string(),
                    options: vec!["--hostlist=/opt/etc/nfqws2/lists/google.list".to_string()],
                },
            ],
        }]);
        let body = strip_ansi(&render_intercept_notice(&msg, Some(&state)).unwrap());
        assert!(body.contains("hostlist/ipset"), "{body}");
        assert!(body.contains("\nNFQWS_EXTRA_ARGS=\"$MODE_ALL\"\n"), "no indent: {body}");
        assert!(
            body.contains(
                "\nNFQWS_ARGS_IPSET=\"--ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list\"\n"
            ),
            "{body}"
        );
        // The strategy is named, not pasted: the option to drop is what a reader
        // can act on.
        assert!(body.contains("Drop from NFQWS_ARGS_CUSTOM"), "{body}");
        assert!(body.contains("--hostlist=/opt/etc/nfqws2/lists/google.list"), "{body}");
        assert!(!body.contains("{}"), "every placeholder is filled: {body}");
    }

    /// When the filter lives in no variable the detector can name, the entry
    /// points at the profile and the option instead of inventing a recipe.
    #[test]
    fn an_unnameable_filter_is_pointed_at() {
        let msg = get_messages(Language::En);
        let state = found(vec![Problem::ListNamed {
            profile: "tcp=443 l7=tls".to_string(),
            option: "--ipset=/opt/etc/nfqws2/lists/ipset.list".to_string(),
        }]);
        let notice = render_intercept_notice(&msg, Some(&state)).unwrap();
        assert!(notice.contains("tcp=443 l7=tls"), "{notice}");
        assert!(notice.contains("--ipset=/opt/etc/nfqws2/lists/ipset.list"), "{notice}");
        assert!(!notice.contains("{}"), "every placeholder is filled: {notice}");
    }

    /// A check that did not complete is not a problem on the list, and an empty
    /// list must not read as "clean".
    #[test]
    fn an_incomplete_check_is_stated_beside_the_problems() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::En);
        let mut state = found(vec![Problem::Ipv6]);
        state.unchecked = vec![Unchecked::Queue];
        let body = strip_ansi(&render_intercept_notice(&msg, Some(&state)).unwrap());
        assert!(body.contains("IPV6_ENABLED=0"), "{body}");
        assert!(body.contains("nothing is bound to its queue"), "{body}");
    }

    /// A family the device has no route for is the one state with nothing to
    /// change in the package, so the closing line stays out.
    #[test]
    fn an_unknown_route_alone_has_nothing_to_close_with() {
        let msg = get_messages(Language::En);
        let notice =
            render_intercept_notice(&msg, Some(&unchecked(vec![Unchecked::Route]))).unwrap();
        assert!(!notice.contains(msg.intercept_after), "{notice}");
        assert!(notice.contains("could not be determined"), "{notice}");
    }

    /// A package whose config never named a policy must not print empty quotes.
    #[test]
    fn an_unnamed_policy_has_its_own_wording() {
        let msg = get_messages(Language::En);
        let mut state = found(vec![Problem::Excluded]);
        state.policy = None;
        let notice = render_intercept_notice(&msg, Some(&state)).unwrap();
        assert!(!notice.contains("\"\""), "no empty quotes: {notice}");
        assert!(notice.contains("access policy"), "{notice}");
    }

    /// The Russian blocks are the ones a Keenetic owner reads: the wording, the
    /// bullets, the config lines and the blank lines are what the report shows,
    /// so all of them are pinned.
    #[test]
    fn russian_notice_reads_as_written() {
        use crate::render::strip_ansi;
        let msg = get_messages(Language::Ru);
        let state = found(vec![
            Problem::Excluded,
            Problem::Ipv6,
            Problem::Port { port: 80, missing: Missing::Both },
            Problem::ListRecipe {
                fixes: vec![ListFix::Assign {
                    variable: "NFQWS_EXTRA_ARGS".to_string(),
                    value: "$MODE_ALL".to_string(),
                }],
            },
        ]);
        let notice = render_intercept_notice(&msg, Some(&state)).unwrap();
        let body: Vec<String> = strip_ansi(&notice).lines().map(str::to_string).collect();
        assert_eq!(
            body,
            vec![
                "",
                "Обнаружен включённый nfqws2, но есть проблемы:",
                "  • Трафик детектора исключён политикой доступа «nfqws».",
                "    На время тестов поставьте POLICY_EXCLUDE=1 или укажите свой POLICY_NAME,",
                "    которого нет среди политик роутера",
                "  • Детектор запущен в режиме IPv6, но в конфиге стоит IPV6_ENABLED=0.",
                "    Поставьте IPV6_ENABLED=1 в /opt/etc/nfqws2/nfqws2.conf.",
                "  • Трафик идёт мимо nfqws2: порта 80 нет ни в TCP_PORTS, ни в --filter-tcp.",
                "  • Каждый профиль, который берёт порты, тестируемые детектором, сужен списком hostlist/ipset,",
                "    поэтому тестируемые цели могут не подхватываться.",
                "    Для правильной проверки стратегий на время тестирования установите в конфиге:",
                "NFQWS_EXTRA_ARGS=\"$MODE_ALL\"",
                "",
                "После применения изменений перезапустите nfqws2 и dpi-detector.",
            ],
            "{notice}"
        );
    }

    #[test]
    fn fingerprint_header_names_the_shape_and_keeps_the_caveat() {
        use crate::i18n::{get_messages, Language};
        let en = get_messages(Language::En);
        assert_eq!(
            render_fingerprint_header(TlsFingerprint::Rustls, &en),
            "Fingerprint: RUSTLS (default)"
        );
        let fa = get_messages(Language::Fa);
        assert_eq!(
            render_fingerprint_header(TlsFingerprint::Rustls, &fa),
            "Fingerprint: RUSTLS (pishfarz)"
        );
        // A browser profile is named by its token and the version it
        // reproduces (rule 4: Latin, never translated), and the caveat follows
        // verbatim from i18n rather than being pinned here a second time.
        let firefox = render_fingerprint_header(TlsFingerprint::Firefox133, &en);
        assert!(firefox.starts_with("Fingerprint: FIREFOX 133"), "{firefox}");
        assert!(firefox.contains(en.fingerprint_note), "{firefox}");
        // The baseline has no caveat: nobody is impersonated, nothing to warn
        // about.
        assert!(!render_fingerprint_header(TlsFingerprint::Rustls, &en).contains(en.fingerprint_note));
    }
}

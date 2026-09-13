//! Test orchestration: one `run_test_suite` call drives every selected test,
//! collects the rows it produced and emits both the human report and the JSON
//! document. Split out of `main` so the CLI/TUI shell and the run logic do not
//! share one 1700-line file.

use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dpi_core::config::{
    clean_domain, AppConfig,
};
use dpi_core::dns::availability::check_dns_availability;
use dpi_core::dns::parse_socks_proxy;
use dpi_core::dns::udp::probe_udp_dns;
use dpi_core::i18n::{legend_text, Language, Messages};
use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::netinfo::{
    detect_bypass_tools, fetch_ip_cymru, fetch_public_ips, get_system_dns, is_tun_name, IpCymruInfo,
};
use dpi_core::probe::burst::{
    burst_targets, BurstAlpn, BurstObserver, BurstSettings, BurstTarget, BurstTlsVersion,
    BURST_DEFAULT_ATTEMPTS, BURST_DEFAULT_TIMEOUT_SECS,
};
use dpi_core::probe::domains::{
    check_http_all, check_tls_all, collect_stub_ips, domain_stats, resolve_all, IpFamily,
};
use dpi_core::probe::telegram::run_telegram_full;
use dpi_core::probe::whitelist::run_whitelist_sni;
use dpi_core::probe::{check_tcp_16_20, domains};
use dpi_core::profile::RegionProfile;
use dpi_core::{PhaseProgress, ProgressTick};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::args::CliArgs;
use crate::render::{
    render_banner, render_burst_table,
    render_dns_availability, render_dns_endpoints, render_dns_resolve_notes, render_domain_table, render_netinfo_panel, render_summary, render_tcp_table, render_telegram,
    render_whitelist, LiveProgress,
    NetFamilyInfo, NetInfoData, NetTtlb, Spinner, SummaryData, TcpRow,
};
use crate::{print_out, selection_flags, tcp16_detail, Emitter};

pub(crate) fn mask_proxy(url: &str) -> String {
    // socks5://user:pass@host → socks5://user:***@host
    match url.find('@') {
        Some(at) => {
            let (left, right) = url.split_at(at);
            match left.rfind(':') {
                Some(colon) if left[..colon].contains("://") => {
                    format!("{}:***{}", &left[..colon], right)
                }
                _ => url.to_string(),
            }
        }
        None => url.to_string(),
    }
}

/// Builds one per-family fact; missing Cymru fields become red "timeout"
/// (mirrors the `update`/`setdefault` block in `fetch_network_panel`).
pub(crate) fn family_info(ip: Option<(IpAddr, u64)>, extra: Option<IpCymruInfo>) -> Option<NetFamilyInfo> {
    let (addr, ms) = ip?;
    let missing = || "timeout".to_string();
    match extra {
        Some(e) => Some(NetFamilyInfo {
            ip: addr.to_string(),
            ttlb: NetTtlb::Ms(ms),
            subnet: e.subnet.unwrap_or_else(missing),
            org: e.org.unwrap_or_else(missing),
            asn: e.asn,
            cc: e.country.unwrap_or_else(missing),
        }),
        None => Some(NetFamilyInfo {
            ip: addr.to_string(),
            ttlb: NetTtlb::Ms(ms),
            subnet: missing(),
            org: missing(),
            asn: missing(),
            cc: missing(),
        }),
    }
}

/// Both lookups dead: red "timeout" rows.
pub(crate) fn timeout_family() -> NetFamilyInfo {
    NetFamilyInfo {
        ip: "timeout".to_string(),
        ttlb: NetTtlb::Timeout,
        subnet: "timeout".to_string(),
        org: "timeout".to_string(),
        asn: "timeout".to_string(),
        cc: "timeout".to_string(),
    }
}

/// The hosts a run probes once the settings screen has answered: the typed host
/// replaces the configured list for that run, and an empty box goes back to it.
///
/// The screen opens with the last answer already in its box, so an empty box is
/// the user having cleared it. Treating empty as "reuse the previous answer"
/// ran the host typed twenty minutes earlier while the box looked empty.
pub(crate) fn burst_targets_after_screen(defaults: &[String], choice: Option<&str>) -> Vec<String> {
    match choice {
        Some(domain) => vec![domain.to_string()],
        None => defaults.to_vec(),
    }
}

/// Everything test 6 needs: the burst shape and the hosts to fire it at.
pub(crate) struct BurstPlan {
    pub(crate) settings: BurstSettings,
    pub(crate) targets: Vec<String>,
}

/// Reports an unknown test 6 axis value (TLS version, ALPN) and keeps the
/// default, the way an unknown profile name is reported rather than swapped
/// silently.
pub(crate) fn warn_unknown_axis(msg: &Messages, args: &CliArgs, flag: &str, value: &str, fallback: &str) {
    if args.json {
        return;
    }
    eprintln!(
        "{}",
        msg.warn_unknown_burst_axis
            .replacen("{}", flag, 1)
            .replacen("{}", value, 1)
            .replacen("{}", fallback, 1)
    );
}

/// Builds test 6's plan from the CLI. An unknown profile name is reported (the
/// test then runs the profiles it did understand) rather than silently swapped
/// for a different set.
pub(crate) fn burst_plan_from_cli(args: &CliArgs, domains: &[String], msg: &Messages) -> BurstPlan {
    let (profiles, unknown) = match &args.burst_profiles {
        Some(value) => TlsFingerprint::parse_list(value),
        None => (TlsFingerprint::ALL.to_vec(), Vec::new()),
    };
    if !args.json {
        for token in unknown {
            let fallback =
                profiles.iter().map(|f| f.display_label()).collect::<Vec<_>>().join(", ");
            eprintln!(
                "{}",
                msg.warn_unknown_fingerprint.replacen("{}", &token, 1).replacen("{}", &fallback, 1)
            );
        }
    }
    let tls = match &args.burst_tls {
        Some(value) => BurstTlsVersion::parse(value).unwrap_or_else(|| {
            warn_unknown_axis(msg, args, "--burst-tls", value, BurstTlsVersion::default().code());
            BurstTlsVersion::default()
        }),
        None => BurstTlsVersion::default(),
    };
    let alpn = match &args.burst_alpn {
        Some(value) => BurstAlpn::parse(value).unwrap_or_else(|| {
            warn_unknown_axis(msg, args, "--burst-alpn", value, BurstAlpn::default().token());
            BurstAlpn::default()
        }),
        None => BurstAlpn::default(),
    };
    let settings = BurstSettings::clamped(
        args.burst.unwrap_or(BURST_DEFAULT_ATTEMPTS),
        args.burst_timeout.unwrap_or(BURST_DEFAULT_TIMEOUT_SECS),
        tls,
        alpn,
        profiles,
    );
    // `-d` picks the targets, exactly as it does for test 2 — and goes through
    // the same cleaner, so `-d https://host/path` probes `host` instead of a name
    // no resolver knows. An input that cleans to nothing falls back to the
    // configured list rather than firing at no target at all.
    let targets = if args.domain.is_empty() {
        domains.to_vec()
    } else {
        let cleaned: Vec<String> = args.domain.iter().filter_map(|d| clean_domain(d)).collect();
        if cleaned.is_empty() {
            domains.to_vec()
        } else {
            cleaned
        }
    };
    BurstPlan { settings, targets }
}

/// Draws the burst's live line: the shape on the wire right now, which round
/// that is of how many, how many hosts of the round are done, and the clock.
pub(crate) struct BurstLine {
    live: Arc<LiveProgress>,
    msg: Messages,
}

impl BurstObserver for BurstLine {
    fn round_started(&self, fingerprint: TlsFingerprint, index: usize, total: usize, hosts: usize) {
        // `LiveProgress` resets its clock on every `set`, so the timer reads as
        // the round's elapsed time rather than the whole run's.
        self.live.set(
            format!(
                "{}: {} {}/{}",
                self.msg.burst_testing,
                fingerprint.display_label(),
                index + 1,
                total
            ),
            hosts,
        );
    }

    fn host_finished(&self) {
        self.live.tick();
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_test_suite(
    tests_str: &str,
    concurrency: usize,
    args: &CliArgs,
    cfg: &AppConfig,
    domains: &[String],
    tcp_items: &[dpi_core::config::Tcp16Target],
    whitelist_sni: &[(String, usize)],
    burst: &BurstPlan,
    msg: &Messages,
    profile: RegionProfile,
    lang: Language,
    badge: &str,
    banner_done: bool,
    emitter: &mut Emitter,
) -> HashMap<String, serde_json::Value> {
    let (run_net, run_dns, run_dom, run_tcp, run_sni, run_tg, run_burst, run_legend, _) =
        selection_flags(tests_str);

    let mut json_results: HashMap<String, serde_json::Value> = HashMap::new();

    if !args.json && !banner_done {
        emitter.emit(&render_banner(msg, profile, badge));
    }

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    // Live progress lines on a TTY only (mirrors rich transient Progress);
    // pipes and --json stay byte-clean.
    let live = LiveProgress::new();
    let phases: Option<PhaseProgress> = if !args.json && std::io::stderr().is_terminal() {
        let live_c = Arc::clone(&live);
        let live_b = Arc::clone(&live);
        let msg_copy = *msg;
        Some(PhaseProgress {
            on_phase: Arc::new(move |phase: dpi_core::PhaseId, total: usize| {
                // Stages of test 2 share one line, so a new stage advances its
                // own counter instead of starting a line of its own.
                if let Some(block) = phase.stage_block() {
                    live_c.set_total(block, total);
                    let tick_c = Arc::clone(&live_c);
                    let tick: ProgressTick = Arc::new(move || tick_c.bump(block));
                    return tick;
                }
                let desc = msg_copy.phase_text(phase);
                live_c.set(desc, total);
                let tick_c = Arc::clone(&live_c);
                let tick: ProgressTick = Arc::new(move || tick_c.tick());
                tick
            }),
            on_blocks: Arc::new(move |phase: dpi_core::PhaseId, blocks: &[(dpi_core::ProgressBlock, usize)]| {
                let desc = msg_copy.phase_text(phase);
                live_b.set_blocks(desc, blocks);
                let tick_c = Arc::clone(&live_b);
                let tick: dpi_core::BlockTick = Arc::new(move |block| tick_c.bump(block));
                tick
            }),
        })
    } else {
        None
    };
    let family = IpFamily::from_config(&cfg.ip_version);
    let socks_proxy = match cfg.effective_proxy() {
        Some(url) => match parse_socks_proxy(url) {
            Ok(c) => Some(c),
            Err(e) => {
                emitter.emit(&msg.invalid_proxy_err.replacen("{}", url, 1).replacen("{}", &e.to_string(), 1));
                None
            }
        },
        None => None,
    };

    let mut dns_stats = None;
    let mut dom_stats = None;
    let mut tcp_summary = None;
    let mut tg_full = None;

    // ── Test 0: network & system ──
    if run_net {
        let spinner = (!args.json).then(|| Spinner::start(msg.fetching_net_info));
        // The cap must clear the inner budgets (3.5 s public-IP race then 5 s
        // Cymru, both bounding their whole fetch): with a smaller one a slow
        // but working network would print "network information unavailable"
        // instead of the panel with its red timeout rows.
        let net_data = tokio::time::timeout(Duration::from_secs(10), async {
            let ips = fetch_public_ips(
                &cfg.ip4_lookup_urls,
                &cfg.ip6_lookup_urls,
                Duration::from_millis(3500),
            )
            .await;
            let (v4_extra, v6_extra) = tokio::join!(
                async {
                    match ips.v4 {
                        Some((ip, _)) => {
                            fetch_ip_cymru(&IpAddr::V4(ip), &cfg.cymru_doh_servers, Duration::from_secs(5)).await
                        }
                        None => None,
                    }
                },
                async {
                    match ips.v6 {
                        Some((ip, _)) => {
                            fetch_ip_cymru(&IpAddr::V6(ip), &cfg.cymru_doh_servers, Duration::from_secs(5)).await
                        }
                        None => None,
                    }
                }
            );
            (ips, v4_extra, v6_extra)
        })
        .await;
        if let Some(s) = spinner {
            s.finish();
        }

        let mut dns_info = get_system_dns();
        let bypass = detect_bypass_tools(&cfg.bypass_tools());

        if let Ok((ips, v4_extra, v6_extra)) = net_data {
            // Upstream router / VPN relay: whoami.akamai.net via local candidates
            // (mirrors fetch_network_panel).
            let mut candidates: Vec<IpAddr> = Vec::new();
            for (ip_str, _) in &dns_info.active {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if domains::is_local_or_relay_ip(&ip) && !candidates.contains(&ip) {
                        candidates.push(ip);
                    }
                }
            }
            if let Some(gw) = dns_info.gateway {
                if domains::is_local_or_relay_ip(&gw) && !candidates.contains(&gw) {
                    candidates.push(gw);
                }
            }
            let mut upstream: Option<String> = None;
            for cand in &candidates {
                let server = SocketAddr::new(*cand, 53);
                if let Ok((addrs, _)) =
                    probe_udp_dns(server, "whoami.akamai.net", Duration::from_secs(2), None).await
                {
                    if let Some(up) = addrs.first() {
                        let mut text = up.to_string();
                        if let Some(extra) =
                            fetch_ip_cymru(up, &cfg.cymru_doh_servers, Duration::from_secs(5)).await
                        {
                            if let Some(org) = extra.org.as_ref() {
                                if !org.is_empty() {
                                    text += &format!(" ({})", org);
                                }
                            }
                        }
                        upstream = Some(text);
                        break;
                    }
                }
            }
            if let Some(up) = upstream {
                let a_name = dns_info.active_name.clone().unwrap_or_default();
                let label = if is_tun_name(&a_name) { msg.upstream_vpn } else { msg.router_resolver };
                dns_info.upstream = Some(up);
                dns_info.upstream_label = Some(label.to_string());
            }

            let v4 = family_info(ips.v4.map(|(ip, ms)| (IpAddr::V4(ip), ms)), v4_extra.clone());
            let v6 = ips.v6.map(|(ip, ms)| (IpAddr::V6(ip), ms));
            let v6 = family_info(v6, v6_extra);
            // Both lookups dead: red "timeout" rows (mirrors fetch_network_panel).
            let (v4, v6) = match (&v4, &v6) {
                (None, None) => (Some(timeout_family()), Some(timeout_family())),
                _ => (v4, v6),
            };
            let data = NetInfoData { v4, v6, empty: false };
            if !args.json {
                emitter.emit(&render_netinfo_panel(&data, &dns_info, &bypass, msg));
            } else {
                let mut tun: Vec<String> = Vec::new();
                if let Some(ref n) = dns_info.active_name {
                    if is_tun_name(n) && !tun.contains(n) {
                        tun.push(n.clone());
                    }
                }
                for (_, n) in &dns_info.other_static {
                    if is_tun_name(n) && !tun.contains(n) {
                        tun.push(n.clone());
                    }
                }
                json_results.insert(
                    "network_info".to_string(),
                    json!({
                        "ipv4": ips.v4.map(|(ip, lat)| json!({"ip": ip.to_string(), "latency_ms": lat})),
                        "ipv6": ips.v6.map(|(ip, lat)| json!({"ip": ip.to_string(), "latency_ms": lat})),
                        "v4_asn": v4_extra.as_ref().map(|c| &c.asn),
                        "v4_org": v4_extra.as_ref().and_then(|c| c.org.as_ref()),
                        "v4_cc": v4_extra.as_ref().and_then(|c| c.country.as_ref()),
                        "upstream": dns_info.upstream,
                        "system_dns": dns_info.nameservers.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                        "gateway": dns_info.gateway.map(|g| g.to_string()),
                        "tun": tun,
                        "bypass_tools": bypass,
                    }),
                );
            }
        } else if !args.json {
            emitter.emit(msg.net_info_unavailable);
        }

    }
    // ── Test 1: DNS availability ──
    if run_dns {
        if cfg.availability_servers().is_empty() {
            if !args.json {
                emitter.emit(msg.dns_servers_empty_skip);
            }
        } else {
            let report = check_dns_availability(cfg, phases.clone(), concurrency).await;
            live.finish();
            if !args.json {
                emitter.emit(&render_dns_endpoints(&report, msg));
                emitter.emit(&render_dns_availability(&report, cfg, msg));
            } else {
                let s = &report.stats;
                json_results.insert(
                    "dns_availability".to_string(),
                    json!({
                        "doh_ok": s.doh_ok, "doh_total": s.doh_total,
                        "dot_ok": s.dot_ok, "dot_total": s.dot_total,
                        "udp_ok": s.udp_ok, "udp_total": s.udp_total,
                        "hijacked_brands": s.hijacked_brands,
                        "resolvers_total": s.resolvers_total,
                        "subst_sub": s.subst_sub, "subst_total": s.subst_total,
                    }),
                );
            }
            dns_stats = Some(report.stats.clone());
        }
    }

    // ── Test 2: domains (resolve → TLS1.3 → TLS1.2 → HTTP) ──
    if run_dom {
        if !args.json {
            emitter.emit(&format!(
                "\n{}  {}: {} | {}: {} | {}: {}s\n\n",
                msg.domains_check_header,
                msg.targets_label,
                domains.len(),
                msg.ip_col,
                if cfg.ip_version == "ipv6" { "IPv6" } else { "IPv4" },
                msg.timeout_label,
                cfg.connect_timeout
            ));
        }
        // Silent stub collection with timeout (mirrors STUB_IPS_TIMEOUT)
        let stub_ips: HashSet<IpAddr> = tokio::time::timeout(
            Duration::from_secs_f64(cfg.stub_ips_timeout),
            collect_stub_ips(cfg),
        )
        .await
        .unwrap_or_default();

        // All four stages are on the road from the first second (test 1
        // style), so the run reads as one progressing line rather than four
        // headers that scroll away.
        if !args.json {
            live.begin_stages(
                msg.stages_label.to_string(),
                &[
                    (dpi_core::ProgressBlock::DomainDns, domains.len()),
                    (dpi_core::ProgressBlock::DomainTls13, domains.len()),
                    (dpi_core::ProgressBlock::DomainTls12, domains.len()),
                    (dpi_core::ProgressBlock::DomainHttp, domains.len()),
                ],
            );
        }
        let mut entries = resolve_all(domains, family, &stub_ips, &sem, phases.clone()).await;
        check_tls_all(&mut entries, false, cfg, &sem, phases.clone()).await;
        check_tls_all(&mut entries, true, cfg, &sem, phases.clone()).await;
        check_http_all(&mut entries, cfg, &stub_ips, &sem, phases.clone()).await;
        live.finish();

        let stats = domain_stats(&entries);
        if !args.json {
            emitter.emit(&render_domain_table(&entries, msg));
            emitter.emit(&render_dns_resolve_notes(&entries, msg));
        } else {
            let list: Vec<_> = entries
                .iter()
                .map(|e| {
                    json!({
                        "domain": e.domain,
                        "resolved": e.resolved.map(|ip| ip.to_string()),
                        "http": e.http.status.as_str(),
                        "http_detail": e.http.detail,
                        "tls12": e.t12.status.as_str(),
                        "tls12_detail": e.t12.detail,
                        "tls13": e.t13.status.as_str(),
                        "tls13_detail": e.t13.detail,
                    })
                })
                .collect();
            json_results.insert("domain_inspection".to_string(), json!(list));
        }
        dom_stats = Some(stats);
    }

    // ── Test 3: TCP 16–20 KB ──
    if run_tcp {
        if !args.json {
            emitter.emit(&format!(
                "\n{}  {}: {} | {}: {}s\n",
                msg.tcp16_check_title,
                msg.targets_label,
                tcp_items.len(),
                msg.timeout_label,
                cfg.fat_connect_timeout
            ));
            emitter.emit(&format!("{}\n", msg.checking_status));
        }
        let mut rows: Vec<TcpRow> = Vec::new();
        let tcp_tick = phases
            .as_ref()
            .map(|p| (p.on_phase)(dpi_core::PhaseId::Tcp16, tcp_items.len()));
        let mut handles = Vec::new();
        for item in tcp_items {
            let item = item.clone();
            let cfg_c = cfg.clone();
            let sem_c = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let port = item.port;
                let sni = if port == 80 {
                    String::new()
                } else {
                    item.sni.clone().unwrap_or_else(|| cfg_c.fat_default_sni.clone())
                };
                let t0 = Instant::now();
                let (status, detail, _rtt) =
                    check_tcp_16_20(&item.ip, port, &sni, &cfg_c, &sem_c, None).await;
                let elapsed = t0.elapsed().as_secs_f64();
                let detail = tcp16_detail(detail, elapsed);
                let asn_str = item.display_asn();
                (item.id, asn_str, item.provider, status, detail)
            }));
        }
        let mut ok = 0;
        let mut blocked = 0;
        let mut mixed = 0;
        for h in handles {
            let done = h.await;
            if let Some(t) = tcp_tick.as_ref() {
                t();
            }
            if let Ok((id, asn, provider, status, detail)) = done {
                let label = status.display_label();
                if label.contains("OK") {
                    ok += 1;
                } else if label.contains("DETECTED") {
                    blocked += 1;
                } else if label.contains("MIXED") {
                    mixed += 1;
                }
                rows.push(TcpRow { id, asn, provider, status, detail });
            }
        }
        tcp_summary = Some((ok, blocked, mixed, rows.len()));
        live.finish();
        if !args.json {
            emitter.emit(&render_tcp_table(&rows, msg));
        } else {
            let list: Vec<_> = rows
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id, "asn": r.asn, "provider": r.provider,
                        "status": r.status.as_str(), "detail": r.detail,
                    })
                })
                .collect();
            json_results.insert("tcp16".to_string(), json!(list));
        }
        let _ = socks_proxy;
    }

    // ── Test 4: white SNI ──
    if run_sni {
        if whitelist_sni.is_empty() {
            if !args.json {
                emitter.emit(msg.whitelist_skipped);
            }
        } else {
            let port443: Vec<_> = tcp_items.iter().filter(|t| t.port == 443).collect();
            if !args.json {
                let mut asns = std::collections::HashSet::new();
                for t in &port443 {
                    let k = t.asn.trim().to_uppercase();
                    asns.insert(if k.is_empty() { t.ip.clone() } else { k });
                }
                emitter.emit(&format!(
                    "\n{}  AS: {} | {}: {} | SNI: {} | {}: {}\n",
                    msg.menu_test_sni,
                    asns.len(),
                    msg.ip_col,
                    port443.len(),
                    whitelist_sni.len(),
                    msg.batch_label,
                    cfg.sni_batch_size
                ));
                emitter.emit(&format!("{}\n", msg.phase_sni_base));
            }
            let report = run_whitelist_sni(tcp_items, whitelist_sni, cfg, &sem, phases.clone()).await;
            live.finish();
            if !args.json {
                if report.detected_as > 0 {
                    let pmsg = msg.phase_sni_parallel
                        .replacen("{}", &report.detected_as.to_string(), 1)
                        .replacen("{}", &cfg.sni_batch_size.to_string(), 1)
                        .replacen("{}", &cfg.sni_top_n.to_string(), 1);
                    emitter.emit(&format!("{}\n\n", pmsg));
                }
                emitter.emit(&render_whitelist(&report, port443.len(), msg));
            } else {
                json_results.insert(
                    "whitelist_sni".to_string(),
                    json!({
                        "detected_as": report.detected_as,
                        "found_as": report.found_as,
                    }),
                );
            }
        }
    }

    // ── Test 5: Telegram ──
    if run_tg {
        let rep = run_telegram_full(cfg, phases.clone()).await;
        live.finish();
        if !args.json {
            emitter.emit(&render_telegram(&rep, msg));
        } else {
            json_results.insert(
                "telegram".to_string(),
                json!({
                    "verdict": rep.verdict,
                    "download": {"status": rep.download.status, "avg_bps": rep.download.avg_bps, "peak_bps": rep.download.peak_bps, "bytes": rep.download.bytes_total, "drop_at_sec": rep.download.drop_at_sec},
                    "upload": {"status": rep.upload.status, "avg_bps": rep.upload.avg_bps, "peak_bps": rep.upload.peak_bps, "bytes": rep.upload.bytes_total, "drop_at_sec": rep.upload.drop_at_sec},
                    "dc_reachable": rep.dc_reachable, "dc_total": rep.dc_total,
                }),
            );
        }
        tg_full = Some(rep);
    }

    // ── Test 6: fingerprint / Siberian blocking (simultaneous handshakes) ──
    if run_burst {
        let settings = &burst.settings;
        // Profile-major: `burst_targets` probes every target with the first
        // shape to the end before the next shape starts, so a block one shape
        // triggers can never be read as the other's result. The simultaneity the
        // test measures is *within* a host (its N handshakes all leave together);
        // hosts inside one shape overlap like any other phase of the suite.
        let targets: Vec<BurstTarget> = burst.targets.iter().map(BurstTarget::new).collect();
        // No banner and no header block: the test says what it is doing on one
        // live line that names the shape currently on the wire and how far the
        // run has got, and nothing else is printed until the table.
        let line = BurstLine { live: Arc::clone(&live), msg: *msg };
        let observer: &dyn BurstObserver = if args.json || !std::io::stderr().is_terminal() {
            &()
        } else {
            &line
        };
        let reports = burst_targets(cfg, &targets, settings, concurrency, observer).await;
        if !args.json && std::io::stderr().is_terminal() {
            live.finish();
        }

        if !args.json {
            emitter.emit(&render_burst_table(&reports, settings, msg));
        } else {
            let domains_json: Vec<serde_json::Value> = reports
                .iter()
                .map(|report| {
                    let profiles: serde_json::Map<String, serde_json::Value> = report
                        .profiles
                        .iter()
                        .map(|profile| {
                            let failed = profile.attempts.iter().find(|a| !a.status.is_ok_status());
                            (
                                profile.fingerprint.code().to_string(),
                                json!({
                                    "answered": profile.answered(),
                                    "attempts": profile.attempts.len(),
                                    "statuses": profile.attempts.iter().map(|a| a.status.as_str()).collect::<Vec<_>>(),
                                    "detail": failed.map(|a| a.detail.clone()).unwrap_or_default(),
                                }),
                            )
                        })
                        .collect();
                    json!({
                        "domain": report.domain,
                        "resolved": report.resolved.map(|ip| ip.to_string()),
                        "profiles": profiles,
                    })
                })
                .collect();
            json_results.insert(
                "fingerprint_burst".to_string(),
                json!({
                    "attempts": settings.attempts,
                    "tls": settings.tls.code(),
                    "alpn": settings.alpn.token(),
                    "timeout_secs": settings.timeout.as_secs(),
                    "profiles": settings.profiles.iter().map(|f| f.code()).collect::<Vec<_>>(),
                    "domains": domains_json,
                }),
            );
        }
    }

    // ── Test 7: legend ──
    if run_legend && !args.json {
        print_out(&legend_text(lang, msg));
    }

    // ── Summary ──
    if !args.json {
        let summary = render_summary(
            &SummaryData {
                run_dns,
                dns: dns_stats.as_ref(),
                domains: dom_stats.as_ref(),
                tcp: tcp_summary,
                run_telegram: run_tg,
                telegram: tg_full.as_ref(),
            },
            msg,
        );
        if !summary.is_empty() {
            emitter.emit(&summary);
        }
    }

    if args.json {
        let payload = json!({
            "schema_version": 1,
            "version": env!("CARGO_PKG_VERSION"),
            "profile": profile.code(),
            "tls_fingerprint": cfg.fingerprint().code(),
            "results": json_results,
        });
        let text = serde_json::to_string_pretty(&payload).unwrap_or_default();
        println!("{}", text);
        if let Some(ref out_path) = args.output {
            let _ = std::fs::write(out_path, &text);
        }
    }

    json_results
}


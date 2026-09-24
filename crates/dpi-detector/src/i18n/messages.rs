//! The interface text table. Every language fills one `Messages` value; the
//! lookups below read the same in all four.

use super::Language;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Messages {
    pub netinfo_title: &'static str,
    pub domain_title: &'static str,
    pub summary_title: &'static str,
    pub status: &'static str,
    pub available: &'static str,
    pub blocked: &'static str,
    pub domain: &'static str,
    pub detail: &'static str,
    pub provider: &'static str,
    pub region: &'static str,




    pub menu_title: &'static str,
    pub menu_language: &'static str,
    /// Menu row: which interface the probes leave through, and the value that
    /// means the routing table decides.
    pub menu_interface: &'static str,
    pub menu_interface_auto: &'static str,
    pub menu_ip_version: &'static str,
    pub menu_concurrency: &'static str,
    pub menu_hw_row: &'static str,
    pub menu_hw_change: &'static str,
    pub menu_hw_tests: &'static str,
    pub menu_hw_start: &'static str,
    pub menu_hw_quit: &'static str,
    pub menu_need_one: &'static str,
    pub menu_test_netinfo: &'static str,
    pub menu_test_dns: &'static str,
    pub menu_test_domains: &'static str,
    pub menu_test_tcp: &'static str,
    pub menu_test_sni: &'static str,
    pub menu_test_telegram: &'static str,
    pub menu_test_legend: &'static str,
    pub menu_test_burst: &'static str,
    pub burst_settings_title: &'static str,
    pub burst_field_attempts: &'static str,
    pub burst_field_timeout: &'static str,
    pub burst_field_gap: &'static str,
    /// Value of the launch-gap row: one `{}` for the milliseconds with the unit
    /// right after it (`20ms`). The unit is translated, so it lives here rather
    /// than in a format literal at the call site.
    pub burst_gap_value: &'static str,
    pub burst_field_domain: &'static str,
    pub burst_domain_placeholder: &'static str,
    pub burst_domain_default_hint: &'static str,
    pub burst_field_tls: &'static str,
    pub burst_field_http: &'static str,
    pub burst_field_profiles: &'static str,
    pub burst_profiles_all: &'static str,
    /// Line above a test 6 table whose run carried a variant; `{}` is the delta
    /// (`-ext:17513`, `groups:29,4588,23`), never translated — it is a command
    /// line token, like the profile codes.
    pub burst_variant_note: &'static str,
    /// Word in front of the profile the burst is firing right now
    /// (`Тестируем: CHROME 107 2/4`).
    pub burst_testing: &'static str,
    pub fingerprint_label: &'static str,
    /// Prose under a non-default profile's header line. Names no profile: the
    /// list is generated from the profile table into `--legend`
    /// (`legend_profiles_heading`).
    pub fingerprint_note: &'static str,
    /// Heading of the generated profile table in `--legend`. The rows
    /// themselves are data: names, versions and sources stay Latin (rule 4).
    pub legend_profiles_heading: &'static str,
    /// Marks a profile that a run presents when no set was asked for, inside
    /// the `--legend` profile rows.
    pub legend_profiles_default: &'static str,
    /// Explains the JA4 line printed under every `--legend` profile row: what
    /// the key is, why one shape can have two of them, and why JA3 is not
    /// printed at all.
    pub legend_profiles_ja4: &'static str,
    pub lang: Language,
    pub replies_label: &'static str,
    pub blocked_short: &'static str,
    pub mixed_short: &'static str,
    pub legend_title: &'static str,

    // Banner & Version
    pub author: &'static str,
    pub chat: &'static str,
    pub update_failed: &'static str,
    pub update_available: &'static str,
    pub update_current: &'static str,
    pub checking_updates: &'static str,

    // NetInfo panel
    pub os: &'static str,
    pub system_dns: &'static str,
    pub active_interface: &'static str,
    pub inactive_dns: &'static str,
    pub router_resolver: &'static str,
    pub upstream_vpn: &'static str,
    pub wsl_proxy: &'static str,
    pub wsl_network: &'static str,
    pub local_bypass: &'static str,
    pub not_detected: &'static str,
    pub unavailable: &'static str,

    // Interception of this process's own traffic by nfqws2 on Keenetic. One
    // header, then a list: every entry is the problem on its first line and what
    // to do about it on the lines under it. `{}` slots are the policy name, the
    // two interface names, the missing ports and the list filter. The bullet,
    // the indent and the config lines of the list recipe are added by the
    // caller, so the recipe stays one shape in every language.
    pub intercept_header: &'static str,
    pub intercept_excluded: &'static str,
    pub intercept_excluded_unnamed: &'static str,
    pub intercept_interface: &'static str,
    /// The ports the tests speak that nothing queues or takes: `{}` is the port
    /// and `{}` one of the three phrases below, which name the side.
    pub intercept_ports: &'static str,
    pub intercept_ports_queue: &'static str,
    pub intercept_ports_filters: &'static str,
    pub intercept_ports_both: &'static str,
    pub intercept_ipv6: &'static str,
    pub intercept_tunnel: &'static str,
    /// The strategy filters by lists and the config lines that drop them are
    /// known; the caller prints those lines under this.
    pub intercept_list_recipe: &'static str,
    /// One variable of that recipe holds a whole strategy: `{}` is the variable
    /// and `{}` the options to drop from it.
    pub intercept_list_drop: &'static str,
    /// The same when the filter lives in no variable the detector can name:
    /// `{}` is the profile and `{}` the option.
    pub intercept_list_named: &'static str,
    /// The check did not complete. One entry per cause, and each stands alone:
    /// these are not config problems, so they carry no fix of the same kind.
    pub intercept_unchecked_config: &'static str,
    pub intercept_unchecked_queue: &'static str,
    pub intercept_unchecked_route: &'static str,
    /// Closes the block, once, after everything that needs a change.
    pub intercept_after: &'static str,

    // DNS Endpoints & Availability
    pub subnet_label: &'static str,
    pub ttlb_label: &'static str,
    pub org_label: &'static str,
    pub location_label: &'static str,
    pub dns_check_title: &'static str,
    pub doh_endpoints: &'static str,
    pub dot_endpoints: &'static str,
    pub udp_endpoints: &'static str,
    pub doh_min: &'static str,
    pub dot_min: &'static str,
    pub udp_min: &'static str,
    pub real_udp_resolver: &'static str,
    pub spoofing: &'static str,
    pub timeout_label: &'static str,
    pub egress_na: &'static str,
    pub partial_dns_warn: &'static str,
    /// Shown when the substitution reference came from DNS_TRUTH_FALLBACK
    /// instead of a live encrypted-DNS answer.
    pub dns_truth_fallback_note: &'static str,
    pub dns_fakeip_warn: &'static str,
    pub dns_intercept_warn: &'static str,
    pub dns_stub_ip_label: &'static str,
    pub doh_recommendation: &'static str,
    pub non_socks_proxy_warn: &'static str,
    pub blocked_domains_label: &'static str,
    pub unblocked_domains_label: &'static str,
    pub dns_independent_warn: &'static str,

    // Domain Table & DNS Notes
    pub http: &'static str,
    pub tls12: &'static str,
    pub tls13: &'static str,
    pub dns_info_title: &'static str,
    pub traffic_fakeip: &'static str,
    pub dns_isp_stub: &'static str,
    pub dns_local_ip: &'static str,
    pub dns_fail_detected: &'static str,
    pub doh_flush_guide: &'static str,

    // TCP 16KB & Whitelist
    pub tcp16_check_title: &'static str,
    pub tcp_mixed_warn: &'static str,
    pub no_port_443_targets: &'static str,
    pub no_as_blocked: &'static str,
    pub ban_after_label: &'static str,
    pub ban_rate_limit: &'static str,
    pub sni_not_found: &'static str,
    pub whitelist_found_summary: &'static str,
    pub whitelist_none_summary: &'static str,
    pub whitelist_skipped: &'static str,

    // Telegram
    pub telegram_check_title: &'static str,
    pub col_id: &'static str,
    pub col_asn: &'static str,
    pub batch_label: &'static str,
    pub dc_col: &'static str,
    pub ip_col: &'static str,
    pub ping_col: &'static str,
    pub download_label: &'static str,
    pub upload_label: &'static str,
    pub peak_label: &'static str,
    pub avg_label: &'static str,
    pub stall_after: &'static str,
    pub unit_mb_s: &'static str,
    pub unit_kb_s: &'static str,
    pub unit_b_s: &'static str,
    pub unit_mb: &'static str,
    pub unit_kb: &'static str,
    pub unit_b: &'static str,
    pub ms_unit: &'static str,

    // Summary
    pub summary_dns_avail: &'static str,
    pub summary_resolver_hijack: &'static str,
    pub summary_all: &'static str,
    pub summary_fakeip_resp: &'static str,
    pub summary_ans_hijack: &'static str,
    pub summary_domains: &'static str,
    pub summary_tg_download: &'static str,
    pub summary_tg_upload: &'static str,
    pub summary_tg_datacenters: &'static str,

    // Controls & Pipeline
    pub menu_control_repeat: &'static str,
    pub menu_control_menu: &'static str,
    pub menu_control_export: &'static str,
    pub menu_control_exit: &'static str,
    pub report_saved: &'static str,
    pub report_save_fail: &'static str,
    pub invalid_tests_flag: &'static str,
    pub invalid_concurrency_flag: &'static str,
    pub tui_unavailable: &'static str,
    pub unavailable_ascii: &'static str,
    pub proxy_in_use: &'static str,
    pub tui_reason_stdin: &'static str,
    pub tui_reason_raw_mode: &'static str,
    pub crash_title: &'static str,
    pub crash_press_enter: &'static str,
    pub ipv6_not_configured: &'static str,
    pub ipv6_switch_hint: &'static str,
    pub fetching_net_info: &'static str,
    pub net_info_unavailable: &'static str,
    pub domains_check_header: &'static str,
    pub targets_label: &'static str,
    pub stages_label: &'static str,
    pub checking_status: &'static str,
    pub phase_sni_base: &'static str,
    pub phase_sni_parallel: &'static str,
    pub phase_telegram: &'static str,
    pub config_load_error_label: &'static str,
    pub config_warning_label: &'static str,
    pub cfg_warn_unknown_key: &'static str,
    pub cfg_warn_invalid_value: &'static str,
    /// A row-list key that kept its valid rows and dropped the rest. One `{}`:
    /// the key. Distinct from `cfg_warn_invalid_value`, whose "using default"
    /// tail is false when 119 of 120 rows survived.
    pub cfg_warn_skipped_rows: &'static str,
    pub cfg_warn_max_concurrent: &'static str,
    pub cfg_warn_ip_version: &'static str,
    pub cfg_warn_fingerprint: &'static str,
    pub cfg_warn_stub_threshold: &'static str,
    pub cfg_warn_upload_port: &'static str,
    pub cfg_warn_dc_port: &'static str,
    pub warn_unknown_lang: &'static str,
    /// Shown before test 6 when the requested profile set is larger than
    /// `DEFAULT_SET` — `all`, or any long explicit list. Two `{}`: the profiles
    /// about to run and the size of the default set.
    pub warn_burst_budget: &'static str,
    pub warn_unknown_fingerprint: &'static str,
    pub warn_unknown_flag_value: &'static str,
    pub press_enter_to_exit: &'static str,
    pub invalid_proxy_err: &'static str,
    pub dns_servers_empty_skip: &'static str,
    pub no_sni_label: &'static str,
    pub detail_at: &'static str,

    pub detail_isp_stub: &'static str,
    pub detail_local_ip: &'static str,
    pub cli_about: &'static str,
    pub cli_help: &'static str,
    pub cli_version: &'static str,
    pub cli_usage_heading: &'static str,
    pub cli_usage: &'static str,
    pub cli_options_heading: &'static str,
    pub cli_tests: &'static str,
    pub cli_json: &'static str,
    pub cli_verbose: &'static str,
    pub cli_lang: &'static str,
    pub cli_profile: &'static str,
    pub cli_legend: &'static str,
    pub cli_proxy: &'static str,
    /// `--iface`: which interface probes leave through.
    pub cli_iface: &'static str,
    /// Fatal: a name that matched no interface, one `{}`.
    pub iface_unknown: &'static str,
    pub cli_concurrency: &'static str,
    pub cli_domain: &'static str,
    pub cli_output: &'static str,
    pub cli_burst: &'static str,
    pub cli_burst_timeout: &'static str,
    pub cli_burst_gap: &'static str,
    pub cli_burst_profiles: &'static str,
    pub cli_burst_tls: &'static str,
    pub cli_burst_alpn: &'static str,
    /// Test 6's variant help: names every delta `HelloVariant::parse` accepts.
    pub cli_burst_variant: &'static str,
    /// Fatal: test 6's variant is not one of the edits. `{}` is the value given,
    /// `{}` the parse error; the run stops rather than firing plain shapes.
    pub burst_variant_bad: &'static str,
    pub cli_trace: &'static str,
    /// Shown when the `--trace` path cannot be opened; `{}` is `<path>: <error>`.
    pub trace_open_failed: &'static str,
    /// Fatal: a target list the operator named cannot be built. `{}` is the
    /// reason — `<path>: <error>` for a file, or `domains_list_empty`'s
    /// parenthetical for a list that parsed to nothing — and it names the
    /// source (`<path>` or `-d`) itself, so this sentence names no flag: it
    /// serves both. The run stops, because a run with no targets would report
    /// an empty table as if it were a result.
    pub domains_load_failed: &'static str,
    /// The reason `domains_load_failed` prints when the list the operator named
    /// holds nothing to probe: `{}` is the source (`<path>` or `-d`), and the
    /// text is a parenthetical on it, because it lands in the middle of that
    /// notice's sentence — Farsi puts the slot before the verb.
    pub domains_list_empty: &'static str,
    /// Shown when the configured whitelist file is there but cannot be read.
    /// `{}` is `<path>: <error>`; the embedded list is used instead, and this is
    /// what tells an unreadable file from an absent one.
    pub whitelist_load_failed: &'static str,
    /// Fatal: the list `--tcp16` named cannot be read. `{}` is
    /// `<path>: <error>`; the run stops, because the shipped targets would
    /// measure hosts the operator never asked for.
    pub tcp16_load_failed: &'static str,
    pub cli_domains: &'static str,
    pub cli_tcp16: &'static str,
    pub cli_ascii: &'static str,
    pub cli_fingerprint: &'static str,

}

impl Messages {
    pub(crate) fn phase_text(&self, phase: dpi_core::PhaseId) -> String {
        match phase {
            // Test 1 labels itself with the block tokens UDP/DoH/DoT/EGRESS,
            // which say more than any translation of "checking" would.
            dpi_core::PhaseId::DnsAvailability => "DNS".to_string(),
            // Test 2 stages label themselves with their canonical token: they
            // share one line, where a sentence per stage would not fit.
            dpi_core::PhaseId::DomainDns => dpi_core::ProgressBlock::DomainDns.token().to_string(),
            dpi_core::PhaseId::DomainTls13 => dpi_core::ProgressBlock::DomainTls13.token().to_string(),
            dpi_core::PhaseId::DomainTls12 => dpi_core::ProgressBlock::DomainTls12.token().to_string(),
            dpi_core::PhaseId::DomainHttp => dpi_core::ProgressBlock::DomainHttp.token().to_string(),
            dpi_core::PhaseId::Tcp16 => self.tcp16_check_title.to_string(),
            dpi_core::PhaseId::SniBase => self.phase_sni_base.to_string(),
            dpi_core::PhaseId::SniParallel { detected_as, batch, top_n } => {
                self.phase_sni_parallel
                    .replacen("{}", &detected_as.to_string(), 1)
                    .replacen("{}", &batch.to_string(), 1)
                    .replacen("{}", &top_n.to_string(), 1)
            }
            dpi_core::PhaseId::Telegram => self.phase_telegram.to_string(),
        }
    }
}
impl Messages {
    /// Checkbox label for test digit '0'..='6' in the interactive menu.
    pub(crate) fn menu_test_label(&self, digit: char) -> &'static str {
        match digit {
            '0' => self.menu_test_netinfo,
            '1' => self.menu_test_dns,
            '2' => self.menu_test_domains,
            '3' => self.menu_test_tcp,
            '4' => self.menu_test_sni,
            '5' => self.menu_test_telegram,
            '6' => self.menu_test_burst,
            '7' => self.menu_test_legend,
            _ => "",
        }
    }
}

impl Messages {
    /// Text for a recoverable configuration problem (see [`dpi_core::config::ConfigWarning`]).
    pub(crate) fn config_warning(&self, warning: &dpi_core::config::ConfigWarning) -> String {
        use dpi_core::config::ConfigWarning as W;
        match warning {
            W::UnknownKey { key } => self.cfg_warn_unknown_key.replace("{}", key),
            W::InvalidValue { key } => self.cfg_warn_invalid_value.replace("{}", key),
            W::SkippedRows { key } => self.cfg_warn_skipped_rows.replace("{}", key),
            W::UnknownFingerprint { value } => self.cfg_warn_fingerprint.replace("{}", value),
            W::MaxConcurrentReset => self.cfg_warn_max_concurrent.to_string(),
            W::IpVersionReset => self.cfg_warn_ip_version.to_string(),
            W::StubThresholdReset => self.cfg_warn_stub_threshold.to_string(),
            W::UploadPortReset => self.cfg_warn_upload_port.to_string(),
            W::DcPortReset => self.cfg_warn_dc_port.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{get_messages, Language};
    use dpi_core::config::ConfigWarning;

    /// The skipped-rows notice must name the key in every language, and must not
    /// be the scalar wording: "using default" is false when 119 of 120 rows
    /// survived, and an operator reading it stops looking for the row that never
    /// ran. A language whose text lost its `{}` prints the key nowhere.
    #[test]
    fn skipped_rows_notice_names_the_key_in_every_language() {
        let key = "DNS_UDP_SERVERS";
        for lang in Language::ALL {
            let msg = get_messages(lang);
            let text = msg.config_warning(&ConfigWarning::SkippedRows { key: key.to_string() });
            assert!(text.contains(key), "{} does not name the key: {text}", lang.label());
            assert_ne!(
                text,
                msg.config_warning(&ConfigWarning::InvalidValue { key: key.to_string() }),
                "{} reuses the scalar wording",
                lang.label()
            );
        }
    }
}

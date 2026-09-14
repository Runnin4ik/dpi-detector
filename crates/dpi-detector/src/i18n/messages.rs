//! The interface text table. Every language fills one `Messages` value; the
//! lookups below read the same in all four.

use super::Language;

#[derive(Debug, Clone, Copy)]
pub struct Messages {
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
    pub burst_field_domain: &'static str,
    pub burst_domain_placeholder: &'static str,
    pub burst_domain_default_hint: &'static str,
    pub burst_field_tls: &'static str,
    pub burst_field_http: &'static str,
    pub burst_field_profiles: &'static str,
    pub burst_profiles_all: &'static str,
    /// Word in front of the profile the burst is firing right now
    /// (`Тестируем: CHROME 107 2/4`).
    pub burst_testing: &'static str,
    pub fingerprint_label: &'static str,
    pub fingerprint_note: &'static str,
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
    pub cfg_warn_max_concurrent: &'static str,
    pub cfg_warn_ip_version: &'static str,
    pub cfg_warn_fingerprint: &'static str,
    pub cfg_warn_stub_threshold: &'static str,
    pub cfg_warn_upload_port: &'static str,
    pub cfg_warn_dc_port: &'static str,
    pub warn_unknown_lang: &'static str,
    pub warn_unknown_fingerprint: &'static str,
    pub warn_unknown_burst_axis: &'static str,
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
    pub cli_concurrency: &'static str,
    pub cli_domain: &'static str,
    pub cli_output: &'static str,
    pub cli_burst: &'static str,
    pub cli_burst_timeout: &'static str,
    pub cli_burst_profiles: &'static str,
    pub cli_burst_tls: &'static str,
    pub cli_burst_alpn: &'static str,
    pub cli_trace: &'static str,
    /// Shown when the `--trace` path cannot be opened; `{}` is `<path>: <error>`.
    pub trace_open_failed: &'static str,
    pub cli_domains: &'static str,
    pub cli_tcp16: &'static str,
    pub cli_ascii: &'static str,
    pub cli_fingerprint: &'static str,

}

impl Messages {
    pub fn phase_text(&self, phase: dpi_core::PhaseId) -> String {
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
    pub fn menu_test_label(&self, digit: char) -> &'static str {
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
    pub fn config_warning(&self, warning: &dpi_core::config::ConfigWarning) -> String {
        use dpi_core::config::ConfigWarning as W;
        match warning {
            W::UnknownKey { key } => self.cfg_warn_unknown_key.replace("{}", key),
            W::InvalidValue { key } => self.cfg_warn_invalid_value.replace("{}", key),
            W::UnknownFingerprint { value } => self.cfg_warn_fingerprint.replace("{}", value),
            W::MaxConcurrentReset => self.cfg_warn_max_concurrent.to_string(),
            W::IpVersionReset => self.cfg_warn_ip_version.to_string(),
            W::StubThresholdReset => self.cfg_warn_stub_threshold.to_string(),
            W::UploadPortReset => self.cfg_warn_upload_port.to_string(),
            W::DcPortReset => self.cfg_warn_dc_port.to_string(),
        }
    }
}

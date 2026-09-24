use clap::{Arg, ArgAction, Command};
use crate::i18n::{get_messages, Language, Messages};

/// Parsed command line.
///
/// The `clap` command is built at runtime (see [`command`]) because every help
/// string lives in the i18n layer and must follow the language the user asked
/// for on the very same command line.
#[derive(Debug, Default)]
pub(crate) struct CliArgs {
    pub tests: Option<String>,
    pub json: bool,
    pub verbose: bool,
    pub lang: String,
    pub profile: String,
    pub legend: bool,
    pub proxy: Option<String>,
    /// Interface probes leave through: a device name (`wg0`, `opkgtun10`) or one
    /// of its addresses. Unset means the routing table decides.
    pub iface: Option<String>,
    pub concurrency: Option<usize>,
    pub domain: Vec<String>,
    pub output: Option<String>,
    pub domains: Option<String>,
    pub tcp16: Option<String>,
    pub ascii: bool,
    pub fingerprint: Option<String>,
    /// Test 6: connections fired at each host, overlapping.
    pub burst: Option<usize>,
    /// Test 6: per-handshake timeout in seconds.
    pub burst_timeout: Option<u64>,
    /// Test 6: delay between attempt starts, milliseconds. Zero fires the whole
    /// round at one instant.
    pub burst_gap: Option<u64>,
    /// Test 6: `all` or a comma list of profile codes/names.
    pub burst_profiles: Option<String>,
    /// Test 6: pinned TLS version, `1.2` or `1.3`.
    pub burst_tls: Option<String>,
    /// Test 6: ALPN to offer, `h2` or `http/1.1`.
    pub burst_alpn: Option<String>,
    /// Test 6: one edit applied to every profile's ClientHello.
    pub burst_variant: Option<String>,
    /// Test 6: per-attempt trace. `Some("")` is stderr, `Some(path)` that file,
    /// `None` means no trace.
    pub trace: Option<String>,
}

/// Builds the CLI definition with `msg`'s language: `about`, per-argument help
/// and value names all come from [`Messages`].
pub(crate) fn command(msg: &Messages) -> Command {
    Command::new("dpi-detector")
        .about(msg.cli_about)
        .version(env!("CARGO_PKG_VERSION"))
        .disable_help_flag(true)
        .disable_version_flag(true)
        .override_usage(msg.cli_usage)
        .help_template(format!(
            "{{about-with-newline}}\n{} {{usage}}\n\n{{all-args}}\n",
            msg.cli_usage_heading
        ))
        .arg(
            Arg::new("tests")
                .short('t')
                .long("tests")
                .value_name("TESTS")
                .help_heading(msg.cli_options_heading)
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_tests),
        )
        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).help_heading(msg.cli_options_heading)
                .help(msg.cli_json))
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_verbose),
        )
        .arg(
            Arg::new("lang")
                .short('l')
                .long("lang")
                .value_name("LANG")
                .default_value("auto")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_lang),
        )
        .arg(
            Arg::new("profile")
                .long("profile")
                .value_name("PROFILE")
                .default_value("ru")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_profile),
        )
        .arg(Arg::new("legend").long("legend").action(ArgAction::SetTrue).help_heading(msg.cli_options_heading)
                .help(msg.cli_legend))
        .arg(
            Arg::new("proxy")
                .short('p')
                .long("proxy")
                .value_name("URL")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_proxy),
        )
        .arg(
            Arg::new("iface")
                .short('i')
                .long("iface")
                .value_name("NAME")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_iface),
        )
        .arg(
            Arg::new("concurrency")
                .short('c')
                .long("concurrency")
                .value_name("N")
                .value_parser(clap::value_parser!(usize))
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_concurrency),
        )
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .value_name("DOMAIN")
                .action(ArgAction::Append)
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_domain),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("PATH")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_output),
        )
        .arg(
            Arg::new("domains")
                .long("domains")
                .value_name("PATH")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_domains),
        )
        .arg(
            Arg::new("tcp16")
                .long("tcp16")
                .value_name("PATH")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_tcp16),
        )
        .arg(Arg::new("ascii").long("ascii").action(ArgAction::SetTrue).help_heading(msg.cli_options_heading)
                .help(msg.cli_ascii))
        .arg(
            Arg::new("fingerprint")
                .long("fingerprint")
                .value_name("PROFILE")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_fingerprint),
        )
        .arg(
            Arg::new("burst")
                .long("burst")
                .value_name("N")
                .value_parser(clap::value_parser!(usize))
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst),
        )
        .arg(
            Arg::new("burst-timeout")
                .long("burst-timeout")
                .value_name("SECONDS")
                .value_parser(clap::value_parser!(u64))
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst_timeout),
        )
        .arg(
            Arg::new("burst-gap")
                .long("burst-gap")
                .value_name("MS")
                .value_parser(clap::value_parser!(u64))
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst_gap),
        )
        .arg(
            Arg::new("burst-profiles")
                .long("burst-profiles")
                .value_name("LIST")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst_profiles),
        )
        .arg(
            Arg::new("burst-tls")
                .long("burst-tls")
                .value_name("VERSION")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst_tls),
        )
        .arg(
            Arg::new("burst-alpn")
                .long("burst-alpn")
                .value_name("PROTOCOL")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst_alpn),
        )
        .arg(
            Arg::new("burst-variant")
                .long("burst-variant")
                .value_name("DELTA")
                // Most deltas start with a hyphen (`-ext:17513`), which clap would
                // otherwise read as the next option.
                .allow_hyphen_values(true)
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_burst_variant),
        )
        .arg(
            // An optional value: no path means stderr, a path means that file.
            // The empty string is what clap stores for "flag given, no value".
            Arg::new("trace")
                .long("trace")
                .value_name("PATH")
                .num_args(0..=1)
                .default_missing_value("")
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_trace),
        )
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_help),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help_heading(msg.cli_options_heading)
                .help(msg.cli_version),
        )
}

/// Parses the process arguments, printing help/errors in `lang`.
pub(crate) fn parse_cli(lang: Language) -> CliArgs {
    let msg = get_messages(lang);
    let m = command(&msg).get_matches();
    CliArgs {
        tests: m.get_one::<String>("tests").cloned(),
        json: m.get_flag("json"),
        verbose: m.get_flag("verbose"),
        lang: m.get_one::<String>("lang").cloned().unwrap_or_else(|| "auto".to_string()),
        profile: m.get_one::<String>("profile").cloned().unwrap_or_else(|| "ru".to_string()),
        legend: m.get_flag("legend"),
        proxy: m.get_one::<String>("proxy").cloned(),
        iface: m.get_one::<String>("iface").cloned(),
        concurrency: m.get_one::<usize>("concurrency").copied(),
        domain: m.get_many::<String>("domain").map(|v| v.cloned().collect()).unwrap_or_default(),
        output: m.get_one::<String>("output").cloned(),
        domains: m.get_one::<String>("domains").cloned(),
        tcp16: m.get_one::<String>("tcp16").cloned(),
        ascii: m.get_flag("ascii"),
        fingerprint: m.get_one::<String>("fingerprint").cloned(),
        burst: m.get_one::<usize>("burst").copied(),
        burst_timeout: m.get_one::<u64>("burst-timeout").copied(),
        burst_gap: m.get_one::<u64>("burst-gap").copied(),
        burst_profiles: m.get_one::<String>("burst-profiles").cloned(),
        burst_tls: m.get_one::<String>("burst-tls").cloned(),
        burst_alpn: m.get_one::<String>("burst-alpn").cloned(),
        burst_variant: m.get_one::<String>("burst-variant").cloned(),
        trace: m.get_one::<String>("trace").cloned(),
    }
}

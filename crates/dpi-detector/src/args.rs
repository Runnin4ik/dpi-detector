use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "dpi-detector",
    about = "High-performance DPI & censorship detection tool",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct CliArgs {
    /// Test suite selection string (e.g. '012', '1', '2')
    #[arg(short = 't', long = "tests")]
    pub tests: Option<String>,

    /// Emit machine-readable JSON output
    #[arg(long = "json")]
    pub json: bool,

    /// Non-interactive batch mode (no user prompts)
    #[arg(long = "batch")]
    pub batch: bool,

    /// Enable verbose / debug logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Interface language (ru, en, auto, fa, zh, es, ar). Default ru: Python has no i18n.
    #[arg(short = 'l', long = "lang", default_value = "ru")]
    pub lang: String,

    /// Regional censorship profile (ru, ir, cn, global)
    #[arg(long = "profile", default_value = "ru")]
    pub profile: String,
    /// Display diagnostic status legend and exit
    #[arg(long = "legend")]
    pub legend: bool,



    /// SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)
    #[arg(short = 'p', long = "proxy")]
    pub proxy: Option<String>,

    /// Concurrency limit for parallel requests
    #[arg(short = 'c', long = "concurrency")]
    pub concurrency: Option<usize>,

    /// Specific domain(s) to test (can be specified multiple times: -d vk.com -d ya.ru)
    #[arg(short = 'd', long = "domain")]
    pub domain: Vec<String>,

    /// Output file path to save report
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,

    /// Path to custom domain list file
    #[arg(long = "domains")]
    pub domains: Option<String>,

    /// Path to custom TCP16 target file
    #[arg(long = "tcp16")]
    pub tcp16: Option<String>,

    /// ASCII-only output for legacy consoles (no Unicode glyphs or borders)
    #[arg(long = "ascii")]
    pub ascii: bool,
}


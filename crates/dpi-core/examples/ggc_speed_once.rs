//! One signed media URL, measured against the node it names and any extra
//! addresses given on the command line.
//!
//! The addresses are cluster members: a URL names its cluster's node, and a
//! node of another network answers 400, so an extra address only makes sense
//! from the same operator. Pass the second address of the cluster the URL
//! names to compare nodes of one network.
//!
//! ```text
//! cargo run -p dpi-core --example ggc_speed_once -- 192.0.2.76
//! ```

use std::net::IpAddr;

use dpi_core::config::AppConfig;
use dpi_core::probe::domains::{resolve_ip, IpFamily};
use dpi_core::probe::ggc_speed::{measure, mint, SpeedNode, SpeedTarget};
use tokio::sync::Semaphore;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let extra: Vec<IpAddr> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let cfg = AppConfig::default();
    let sem = Semaphore::new(4);

    let source = match mint(&cfg, &sem).await {
        Ok(source) => source,
        Err(error) => {
            eprintln!("mint failed: {error}");
            std::process::exit(1);
        }
    };
    println!(
        "signed URL: host={} itag={} content_length={:?}",
        source.host, source.itag, source.content_length
    );

    let mut targets = Vec::with_capacity(1 + extra.len());
    match resolve_ip(&source.host, IpFamily::from_config(&cfg.ip_version)).await {
        Some(address) => targets.push(SpeedTarget {
            host: source.host.clone(),
            address: Some(address),
            node: SpeedNode::UrlNode,
            name: None,
        }),
        None => eprintln!("{} did not resolve", source.host),
    }
    for address in extra {
        targets.push(SpeedTarget {
            host: source.host.clone(),
            address: Some(address),
            node: SpeedNode::MappedCluster,
            name: None,
        });
    }

    println!("{:<17}{:<9}{:>10}{:>9}{:>9}  rate", "address", "node", "bytes", "ttfb", "total");
    for target in &targets {
        let attempt = measure(&cfg, &source, target, &sem).await;
        let rate = attempt
            .mb_per_sec()
            .map(|v| format!("{v:.2} MB/s"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<17}{:<9}{:>10}{:>9}{:>9}  {rate}  {:?} {:?} {:?}",
            target.address.map(|a| a.to_string()).unwrap_or_default(),
            format!("{:?}", target.node),
            attempt.bytes,
            attempt.ttfb_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            attempt.ms,
            attempt.status,
            attempt.detail,
            attempt.location_host,
        );
    }
}

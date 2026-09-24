//! Test 4: white-SNI search per ASN.
//!
//! Algorithm:
//! 1. Take all port-443 TCP targets.
//! 2. Baseline probe collects blocked IPs per AS — transfer-window blocks
//!    (DETECTED 16–20 KB) and TLS-stage kills of the ClientHello (TLS RST /
//!    TLS DROP) alike (min RTT wins on ties).
//! 3. For each blocked AS, probe SNI candidates in batches: step 0 with
//!    empty SNI, then file-ordered batches; first OKs (up to top_n) win.
//!    A whole batch of connect-level failures means ban/rate-limit.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::classify::{Detail, DpiStatus};
use crate::config::{AppConfig, Tcp16Target};
use crate::PhaseProgress;
use super::tcp16::check_tcp_16_20;
pub const NO_SNI_TAG: &str = "(no SNI)";

fn asn_key_of(item: &Tcp16Target) -> String {
    let raw = item.asn.trim();
    if raw.is_empty() {
        return item.ip.clone();
    }
    raw.to_uppercase()
        .strip_prefix("AS")
        .unwrap_or(&raw.to_uppercase())
        .to_string()
}

#[derive(Debug, Clone)]
pub struct AsCandidate {
    pub ip: String,
    pub provider: String,
    pub asn_str: String,
    pub asn_key: String,
    pub rtt: Option<f64>,
}

#[derive(Debug, Clone)]
pub enum AsVerdict {
    /// (label, file_number) pairs that passed
    Found { snis: Vec<(String, usize)>, ban_after: bool },
    Banned { detail: String },
    NotFound,
}

#[derive(Debug, Clone)]
pub struct AsRow {
    pub provider: String,
    pub asn_str: String,
    pub verdict: AsVerdict,
}

#[derive(Debug, Clone, Default)]
pub struct WhitelistReport {
    pub rows: Vec<AsRow>,
    pub detected_as: usize,
    pub found_as: usize,
}

fn is_ok(status: DpiStatus) -> bool {
    status == DpiStatus::Ok
}

/// True when a baseline verdict proves the target is DPI-filtered and is
/// therefore worth an SNI search: a transfer-window block
/// (`Tcp16Detected`/`Tcp16Range`) or a TLS-stage kill of the ClientHello —
/// `TlsRst` (RST after ClientHello), `TlsDropped` (silent drop / handshake
/// timeout) and `TlsAbort` (WSAECONNABORTED 10053, how a reset often surfaces
/// on Windows). Plain connectivity failures (SYN timeout, refused,
/// unreachable) stay out: those are the ban/rate-limit signal the batch loop
/// aborts on.
fn is_detected(status: DpiStatus, detail: &Detail) -> bool {
    matches!(
        status,
        DpiStatus::Tcp16Detected
            | DpiStatus::Tcp16Range
            | DpiStatus::TlsRst
            | DpiStatus::TlsDropped
            | DpiStatus::TlsAbort
    ) || ((status == DpiStatus::Timeout || status == DpiStatus::ReadTimeout)
        && matches!(detail, Detail::AtKb { .. }))
}

pub async fn run_whitelist_sni(
    tcp_items: &[Tcp16Target],
    clean_sni: &[(String, usize)],
    cfg: &AppConfig,
    sem: &Arc<Semaphore>,
    phases: Option<PhaseProgress>,
) -> WhitelistReport {
    let port443: Vec<&Tcp16Target> = tcp_items.iter().filter(|t| t.port == 443).collect();
    if port443.is_empty() {
        return WhitelistReport::default();
    }
    // One config for every probe task instead of one per target and per SNI
    // candidate: each clone carries the whole DNS server list, and the clones
    // pile up while the tasks wait on the semaphore.
    let cfg_arc = Arc::new(cfg.clone());
    let tick_base = phases
        .as_ref()
        .map(|p| (p.on_phase)(crate::PhaseId::SniBase, port443.len()));

    let sni_index: HashMap<&str, usize> =
        clean_sni.iter().map(|(s, n)| (s.as_str(), *n)).collect();

    // Phase 1: baseline probe of every IP
    let mut handles = Vec::new();
    for item in &port443 {
        let item = (*item).clone();
        let cfg = Arc::clone(&cfg_arc);
        let sem = Arc::clone(sem);
        handles.push(tokio::spawn(async move {
            let default_sni = if cfg.fat_default_sni.is_empty() {
                "example.com".to_string()
            } else {
                cfg.fat_default_sni.clone()
            };
            let sni = item.sni.clone().unwrap_or(default_sni);
            let (status, detail, rtt) =
                check_tcp_16_20(&item.ip, 443, &sni, &cfg, &sem, None).await;
            (item, status, detail, rtt)
        }));
    }
    let mut base_rows = Vec::new();
    for h in handles {
        let done = h.await;
        if let Some(t) = tick_base.as_ref() {
            t();
        }
        if let Ok(r) = done {
            base_rows.push(r);
        }
    }

    // Per AS keep the DETECTED IP with min RTT
    let mut candidates: HashMap<String, AsCandidate> = HashMap::new();
    for (item, status, detail, rtt) in base_rows {
        if !is_detected(status, &detail) {
            continue;
        }
        let key = asn_key_of(&item);
        let cand = AsCandidate {
            ip: item.ip.clone(),
            provider: item.provider.clone(),
            asn_str: item.display_asn(),
            asn_key: key.clone(),
            rtt,
        };
        match candidates.get(&key) {
            Some(prev) => {
                let prev_rtt = prev.rtt.unwrap_or(9999.0);
                let cur_rtt = rtt.unwrap_or(9999.0);
                if cur_rtt < prev_rtt {
                    candidates.insert(key, cand);
                }
            }
            None => {
                candidates.insert(key, cand);
            }
        }
    }

    let mut detected: Vec<AsCandidate> = candidates.into_values().collect();
    detected.sort_by_key(|a| a.provider.to_lowercase());

    // Every field spelled out: a field added to the report must be a compile
    // error here, not a silently defaulted claim the TUI renders as measured.
    let mut report = WhitelistReport {
        rows: Vec::new(),
        detected_as: detected.len(),
        found_as: 0,
    };
    if detected.is_empty() {
        return report;
    }

    let batch_size = cfg.sni_batch_size.max(1);
    let top_n = cfg.sni_top_n.max(1);
    let tick_as = phases.as_ref().map(|p| {
        (p.on_phase)(
            crate::PhaseId::SniParallel {
                detected_as: detected.len(),
                batch: batch_size,
                top_n,
            },
            detected.len(),
        )
    });

    for cand in &detected {
        let verdict = probe_as(cand, clean_sni, &sni_index, &cfg_arc, sem, batch_size, top_n).await;
        if let Some(t) = tick_as.as_ref() {
            t();
        }
        if matches!(verdict, AsVerdict::Found { .. }) {
            report.found_as += 1;
        }
        report.rows.push(AsRow {
            provider: cand.provider.clone(),
            asn_str: cand.asn_str.clone(),
            verdict,
        });
    }

    report
}

async fn probe_as(
    cand: &AsCandidate,
    clean_sni: &[(String, usize)],
    sni_index: &HashMap<&str, usize>,
    cfg: &Arc<AppConfig>,
    sem: &Arc<Semaphore>,
    batch_size: usize,
    top_n: usize,
) -> AsVerdict {
    let mut found: Vec<(String, usize)> = Vec::new();
    let mut ban_detected = false;
    let mut ban_detail = String::new();

    // Step 0: probe without SNI
    {
        let (st0, d0, _rtt) =
            check_tcp_16_20(&cand.ip, 443, "", cfg, sem, cand.rtt).await;
        if is_ok(st0) {
            found.push((NO_SNI_TAG.to_string(), 0));
        } else if !is_detected(st0, &d0) && !matches!(d0, Detail::AtKb { .. }) {
            ban_detected = true;
            ban_detail = st0.display_label().to_string();
        }
    }

    if found.len() < top_n && !ban_detected {
        let batches: Vec<&[(String, usize)]> = clean_sni.chunks(batch_size).collect();
        'outer: for batch in batches {
            if found.len() >= top_n {
                break;
            }
            let mut handles = Vec::new();
            for (sni, _num) in batch {
                let sni = sni.clone();
                let cfg = Arc::clone(cfg);
                let sem = Arc::clone(sem);
                let ip = cand.ip.clone();
                let rtt = cand.rtt;
                handles.push(tokio::spawn(async move {
                    let (s, d, _r) = check_tcp_16_20(&ip, 443, &sni, &cfg, &sem, rtt).await;
                    (sni, s, d)
                }));
            }
            let mut results: Vec<(String, DpiStatus, Detail)> = Vec::new();
            for h in handles {
                match h.await {
                    Ok(r) => results.push(r),
                    Err(_) => results.push((String::new(), DpiStatus::Err, Detail::None)),
                }
            }

            // Whole batch connect-level → ban/rate-limit
            let connect_fails = results
                .iter()
                .filter(|(_, s, d)| !is_ok(*s) && !is_detected(*s, d) && !matches!(d, Detail::AtKb { .. }))
                .count();
            if connect_fails == results.len() && !results.is_empty() {
                ban_detected = true;
                if let Some((_, s, _)) = results.first() {
                    ban_detail = s.display_label().to_string();
                }
                break 'outer;
            }

            // Collect OKs in file order
            for (sni, _num) in batch {
                if found.len() >= top_n {
                    break;
                }
                for (rsni, rs, _) in &results {
                    if rsni == sni && is_ok(*rs) {
                        found.push((sni.clone(), sni_index.get(sni.as_str()).copied().unwrap_or(0)));
                        break;
                    }
                }
            }
        }
    }

    if !found.is_empty() {
        AsVerdict::Found { snis: found, ban_after: ban_detected }
    } else if ban_detected {
        AsVerdict::Banned { detail: ban_detail }
    } else {
        AsVerdict::NotFound
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::Detail;

    /// Which baseline verdicts make an AS worth an SNI search: the transfer
    /// window blocks and the TLS-stage kills; connectivity failures stay out.
    #[test]
    fn test_detected_predicate_covers_tls_kills() {
        assert!(is_detected(
            DpiStatus::Tcp16Detected,
            &Detail::at_kb(Detail::ReadTimeoutWordCaps, 16.0)
        ));
        assert!(is_detected(
            DpiStatus::Tcp16Range,
            &Detail::Kb { head: Box::new(Detail::TimeoutWord), kb: 20.0 }
        ));
        assert!(is_detected(DpiStatus::TlsRst, &Detail::RstHello));
        assert!(is_detected(DpiStatus::TlsDropped, &Detail::TlsHandshakeTimeout));
        assert!(is_detected(DpiStatus::TlsAbort, &Detail::Aborted));

        assert!(!is_detected(DpiStatus::SynDropped, &Detail::TcpSynTimeout));
        assert!(!is_detected(DpiStatus::Refused, &Detail::ConnRefused));
        assert!(!is_detected(DpiStatus::NetUnreach, &Detail::NetUnreach));
        assert!(!is_detected(DpiStatus::Ok, &Detail::None));
    }

    #[test]
    fn test_asn_key() {
        let t = Tcp16Target {
            id: "x".into(),
            asn: "as24940".into(),
            provider: "p".into(),
            ip: "1.1.1.1".into(),
            port: 443,
            sni: None,
        };
        assert_eq!(asn_key_of(&t), "24940");
        assert_eq!(t.display_asn(), "AS24940");
    }
}

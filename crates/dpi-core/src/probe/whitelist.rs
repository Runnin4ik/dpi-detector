//! Test 4: white-SNI search per ASN (mirrors
//! `cli/runners.py::run_whitelist_sni_test`).
//!
//! Algorithm:
//! 1. Take all port-443 TCP targets.
//! 2. Baseline probe finds DETECTED IPs per AS (min RTT wins on ties).
//! 3. For each DETECTED AS, probe SNI candidates in batches: step 0 with
//!    empty SNI, then file-ordered batches; first OKs (up to top_n) win.
//!    A whole batch of connect-level failures means ban/rate-limit.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::classify::DpiStatus;
use crate::config::{AppConfig, Tcp16Target};
use crate::PhaseProgress;
use crate::probe::tcp16::check_tcp_16_20;

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

fn asn_display_of(item: &Tcp16Target) -> String {
    let raw = item.asn.trim();
    if raw.is_empty() {
        return "-".to_string();
    }
    if raw.to_uppercase().starts_with("AS") {
        raw.to_uppercase()
    } else {
        format!("AS{}", raw)
    }
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

fn is_detected(status: DpiStatus, detail: &str) -> bool {
    status == DpiStatus::Tcp16Detected || status == DpiStatus::Tcp16Range
        || (status == DpiStatus::Timeout && detail.contains("at "))
        || (status == DpiStatus::ReadTimeout && detail.contains("at "))
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
    let tick_base = phases
        .as_ref()
        .map(|p| (p.on_phase)("Фаза 1/2: Базовая проверка...".to_string(), port443.len(), true));

    let sni_index: HashMap<&str, usize> =
        clean_sni.iter().map(|(s, n)| (s.as_str(), *n)).collect();

    // Phase 1: baseline probe of every IP
    let mut handles = Vec::new();
    for item in &port443 {
        let item = (*item).clone();
        let cfg = cfg.clone();
        let sem = Arc::clone(sem);
        handles.push(tokio::spawn(async move {
            let default_sni = if cfg.fat_default_sni.is_empty() {
                "example.com".to_string()
            } else {
                cfg.fat_default_sni.clone()
            };
            let sni = item.sni.clone().unwrap_or(default_sni);
            let (alive, status, detail, rtt) =
                check_tcp_16_20(&item.ip, 443, &sni, &cfg, &sem, None).await;
            let _ = alive;
            (item, status, detail, rtt)
        }));
    }
    let mut base_rows = Vec::new();
    for h in handles {
        if let Some(t) = tick_base.as_ref() {
            t();
        }
        if let Ok(r) = h.await {
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
            asn_str: asn_display_of(&item),
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

    let mut report = WhitelistReport {
        detected_as: detected.len(),
        ..Default::default()
    };
    if detected.is_empty() {
        return report;
    }

    let batch_size = cfg.sni_batch_size.max(1);
    let top_n = cfg.sni_top_n.max(1);
    let tick_as = phases.as_ref().map(|p| {
        (p.on_phase)(
            format!(
                "Фаза 2/2: Параллельный перебор SNI для {} AS (батч {}, топ-{})...",
                detected.len(),
                batch_size,
                top_n
            ),
            detected.len(),
            true,
        )
    });

    for cand in &detected {
        let verdict = probe_as(cand, clean_sni, &sni_index, cfg, sem, batch_size, top_n).await;
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
    cfg: &AppConfig,
    sem: &Arc<Semaphore>,
    batch_size: usize,
    top_n: usize,
) -> AsVerdict {
    let mut found: Vec<(String, usize)> = Vec::new();
    let mut ban_detected = false;
    let mut ban_detail = String::new();

    // Step 0: probe without SNI
    {
        let (_alive, st0, d0, _rtt) =
            check_tcp_16_20(&cand.ip, 443, "", cfg, sem, cand.rtt).await;
        if is_ok(st0) {
            found.push(("(без SNI)".to_string(), 0));
        } else if !is_detected(st0, &d0) && !d0.contains("at ") {
            ban_detected = true;
            ban_detail = format!("{:?}", st0);
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
                let cfg = cfg.clone();
                let sem = Arc::clone(sem);
                let ip = cand.ip.clone();
                let rtt = cand.rtt;
                handles.push(tokio::spawn(async move {
                    let (_a, s, d, _r) = check_tcp_16_20(&ip, 443, &sni, &cfg, &sem, rtt).await;
                    (sni, s, d)
                }));
            }
            let mut results: Vec<(String, DpiStatus, String)> = Vec::new();
            for h in handles {
                match h.await {
                    Ok(r) => results.push(r),
                    Err(_) => results.push((String::new(), DpiStatus::Err, String::new())),
                }
            }

            // Whole batch connect-level → ban/rate-limit
            let connect_fails = results
                .iter()
                .filter(|(_, s, d)| !is_ok(*s) && !is_detected(*s, d) && !d.contains("at "))
                .count();
            if connect_fails == results.len() && !results.is_empty() {
                ban_detected = true;
                if let Some((_, s, _)) = results.first() {
                    ban_detail = format!("{:?}", s);
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
        assert_eq!(asn_display_of(&t), "AS24940");
    }
}

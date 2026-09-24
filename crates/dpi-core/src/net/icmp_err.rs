//! ICMP verdicts seen on the wire.
//!
//! `EHOSTUNREACH` is one errno for a whole family of ICMP verdicts: "host
//! unreachable" (type 3 code 1), "host administratively prohibited" (type 3
//! code 13, what a provider's filter answers with) and the rest of the
//! destination-unreachable codes all arrive as the same number, so the errno
//! alone cannot say whether the route or a filter refused the flow.
//!
//! The kernel does not hand that message over for a failed TCP connect: the
//! socket's error queue stays empty even with `IP_RECVERR` set and the errno
//! set to `EHOSTUNREACH`, while the same option on a UDP socket does deliver the
//! ICMP. So the message is read off the wire instead — a raw ICMP socket sees
//! every destination-unreachable the host receives, and the packet quoted inside
//! it names the destination the verdict is about. The dial then asks which
//! verdict was seen for the address it failed on.
//!
//! A raw socket needs privileges the detector may not have. When it cannot be
//! opened the watcher is simply absent and the verdict stays the errno's own.
//!
//! The reader is Linux-only; the parser is plain byte arithmetic and is compiled
//! everywhere so its tests run on every host, which is why dead-code analysis is
//! told about the platform that does not read it.
#![cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the parser is compiled on every host so its tests run there, but only Linux opens the raw socket that feeds it"
    )
)]
// The raw ICMP socket and its receive loop are OS calls; `unsafe` is the FFI
// boundary, and the blocks that use it carry SAFETY notes.
#![allow(
    unsafe_code,
    reason = "OS FFI: socket(2)/recvfrom(2) on a raw ICMP socket, guarded by a SAFETY note"
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::classify::IcmpCode;

/// ICMP type "destination unreachable" — the only type that quotes a packet.
const DEST_UNREACH: u8 = 3;

/// Offset of the destination address inside a quoted IPv4 header, and the
/// smallest header that can hold it.
const QUOTED_ADDR: usize = 16;
const IPV4_HEADER: usize = 20;

/// How long a verdict stays useful. The dial asks about it right after the
/// failure, so an older one would blame the wrong connection.
const VERDICT_TTL: Duration = Duration::from_secs(5);

/// How many destinations are remembered at once. A run speaks to a few dozen
/// hosts, so this is only a ceiling against a flood of ICMP.
const VERDICT_LIMIT: usize = 256;

/// How long the dial waits for the watcher to catch up, and how often it looks.
/// The message reaches the raw socket and the failing socket from the same
/// softirq, but the watcher runs on its own thread and can be a moment behind.
const WAIT_STEP: Duration = Duration::from_millis(2);
const WAIT_STEPS: u32 = 10;

/// The ICMP messages seen recently, by the destination they were about.
pub(crate) struct Watch {
    seen: Mutex<HashMap<Ipv4Addr, Seen>>,
}

struct Seen {
    code: IcmpCode,
    at: Instant,
}

impl Watch {
    /// The verdict recorded for `dst`, if one was seen recently.
    fn verdict(&self, dst: Ipv4Addr) -> Option<IcmpCode> {
        let mut seen = self.seen.lock();
        seen.retain(|_, entry| entry.at.elapsed() < VERDICT_TTL);
        seen.get(&dst).map(|entry| entry.code)
    }

    fn record(&self, dst: Ipv4Addr, code: IcmpCode) {
        let mut seen = self.seen.lock();
        if seen.len() >= VERDICT_LIMIT {
            seen.clear();
        }
        seen.insert(dst, Seen { code, at: Instant::now() });
    }
}

/// The watcher of this process, started on first use.
static WATCH: OnceLock<Option<Arc<Watch>>> = OnceLock::new();

/// Starts the watcher if it is not running yet. Called before a connect rather
/// than after it fails: the verdict for a connection arrives with its failure,
/// so a watcher opened at that moment would miss the very message it is for.
pub(crate) fn ensure_started() {
    let _ = WATCH.get_or_init(start);
}

/// Waits for the verdict seen for `dst`, giving up after a few milliseconds.
pub(crate) async fn verdict_wait(dst: IpAddr) -> Option<IcmpCode> {
    if WATCH.get_or_init(start).is_none() {
        return None;
    }
    let IpAddr::V4(dst) = dst else { return None };
    for _ in 0..WAIT_STEPS {
        if let Some(code) = WATCH.get().and_then(|watch| watch.as_ref())?.verdict(dst) {
            return Some(code);
        }
        tokio::time::sleep(WAIT_STEP).await;
    }
    None
}

cfg_select! {
    target_os = "linux" => {
        /// Opens the raw socket and reads it on a thread of its own. `None` when the
        /// privileges are not there — the detector keeps working without a watcher.
        fn start() -> Option<Arc<Watch>> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
            if fd < 0 {
                return None;
            }
            let watch = Arc::new(Watch { seen: Mutex::new(HashMap::new()) });
            let sink = Arc::clone(&watch);
            std::thread::Builder::new()
                .name("icmp-watch".to_string())
                .spawn(move || {
                    let mut packet = [0u8; 1024];
                    loop {
                        let read = unsafe { libc::recv(fd, packet.as_mut_ptr().cast(), packet.len(), 0) };
                        if read <= 0 {
                            break;
                        }
                        if let Some((dst, code)) = parse_icmp(&packet[..read as usize]) {
                            sink.record(dst, code);
                        }
                    }
                    unsafe { libc::close(fd) };
                })
                .ok()?;
            Some(watch)
        }
    }
    _ => {
        fn start() -> Option<Arc<Watch>> {
            None
        }
    }
}

/// Reads the ICMP type, the code, and the destination of the packet it quotes.
///
/// A raw socket is handed the packet from its IPv4 header, so the ICMP message
/// starts at the header's length, not at the first byte. Only a
/// destination-unreachable quotes a packet, and only the quoted header's
/// destination address is needed to name what the verdict is about.
fn parse_icmp(packet: &[u8]) -> Option<(Ipv4Addr, IcmpCode)> {
    const ICMP_HEADER: usize = 8;

    let ip_len = (packet.first()? & 0x0f) as usize * 4;
    if ip_len < IPV4_HEADER || packet.len() < ip_len + ICMP_HEADER + IPV4_HEADER {
        return None;
    }
    let icmp = &packet[ip_len..];
    if icmp[0] != DEST_UNREACH {
        return None;
    }
    let quoted = &icmp[ICMP_HEADER..];
    let quoted_len = (quoted[0] & 0x0f) as usize * 4;
    if quoted_len < IPV4_HEADER || quoted.len() < QUOTED_ADDR + 4 {
        return None;
    }
    let dst = Ipv4Addr::new(
        quoted[QUOTED_ADDR],
        quoted[QUOTED_ADDR + 1],
        quoted[QUOTED_ADDR + 2],
        quoted[QUOTED_ADDR + 3],
    );
    Some((dst, IcmpCode { icmp_type: icmp[0], icmp_code: icmp[1] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message as a raw socket delivers it: the IPv4 header, then a
    /// destination-unreachable quoting a TCP segment sent to `dst`.
    fn unreachable(icmp_type: u8, code: u8, dst: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; IPV4_HEADER];
        packet[0] = 0x45;
        packet[9] = 1; // ICMP

        let mut icmp = vec![0u8; 8];
        icmp[0] = icmp_type;
        icmp[1] = code;
        let mut quoted = vec![0u8; 24];
        quoted[0] = 0x45;
        quoted[9] = 6; // TCP
        quoted[QUOTED_ADDR..QUOTED_ADDR + 4].copy_from_slice(&dst);
        icmp.extend_from_slice(&quoted);

        packet.extend_from_slice(&icmp);
        packet
    }

    #[test]
    fn a_quoted_packet_names_the_destination() {
        let (dst, code) = parse_icmp(&unreachable(DEST_UNREACH, 13, [1, 1, 1, 1])).unwrap();
        assert_eq!(dst, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(code, IcmpCode::ADMIN_PROHIBITED);
    }

    /// A real one, captured on the router: the provider's filter answering a
    /// connection to 194.41.112.143, with that SYN quoted inside. The leading
    /// fourteen bytes of the capture are the Ethernet header, which a raw socket
    /// never sees.
    #[test]
    fn a_captured_provider_verdict_names_the_destination() {
        let captured: &[u8] = &[
            0x45, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0xce, 0x27, 0x5e, 0xb5,
            0x80, 0x2c, 0x64, 0x5a, 0xab, 0x61, // IPv4: 94.181.128.44 -> 100.90.171.97
            0x03, 0x0d, 0x83, 0xd3, 0x00, 0x00, 0x00, 0x00, // ICMP: type 3, code 13
            0x45, 0x70, 0x00, 0x3c, 0xb0, 0xe2, 0x40, 0x00, 0x7e, 0x06, 0x08, 0xf5, 0x64, 0x5a,
            0xab, 0x61, 0xc2, 0x29, 0x70, 0x8f, // quoted IPv4: -> 194.41.112.143
            0xf6, 0x95, 0x20, 0xfb, 0x1d, 0xc8, 0x43, 0xc6, // quoted TCP
        ];
        let (dst, code) = parse_icmp(captured).unwrap();
        assert_eq!(dst, Ipv4Addr::new(194, 41, 112, 143));
        assert_eq!(code, IcmpCode::ADMIN_PROHIBITED);
    }

    /// The verdict belongs to the packet the message quotes, and only a
    /// destination-unreachable quotes one — an echo request is not a verdict
    /// about anything.
    #[test]
    fn only_a_destination_unreachable_is_read() {
        assert_eq!(parse_icmp(&unreachable(8, 0, [1, 1, 1, 1])), None);
    }

    #[test]
    fn a_truncated_message_is_not_misread() {
        assert_eq!(parse_icmp(&[]), None);
        assert_eq!(parse_icmp(&[0x45]), None);
        let mut short = unreachable(DEST_UNREACH, 13, [1, 1, 1, 1]);
        short.truncate(IPV4_HEADER + 8 + 8);
        assert_eq!(parse_icmp(&short), None);
    }

    /// A header whose length is not IPv4 at all (an Ethernet frame's first byte,
    /// or a corrupt one) must not be read as if the ICMP started there.
    #[test]
    fn a_header_shorter_than_ipv4_is_refused() {
        let mut packet = unreachable(DEST_UNREACH, 13, [1, 1, 1, 1]);
        packet[0] = 0x44;
        assert_eq!(parse_icmp(&packet), None);
    }
}

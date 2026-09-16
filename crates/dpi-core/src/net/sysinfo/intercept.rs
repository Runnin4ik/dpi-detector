//! Whether a local DPI-bypass tool takes *this* process's traffic.
//!
//! The Keenetic package (`nfqws2-keenetic`) hooks `mangle POSTROUTING` and
//! `PREROUTING` on the provider interface, and it decides a packet's fate by
//! three things that have nothing to do with the destination: the interface it
//! leaves by, the mark the access policy left on its connection, and the
//! address family it belongs to. Two probes of the same host can therefore end
//! up in different worlds — one queued to the desync, one going straight out —
//! and a report that does not say which world it measured is unreadable.
//!
//! Everything here is read from the tool's own state, never guessed:
//!
//! * `/opt/etc/nfqws2/nfqws2.conf.run` — what the init script resolved on
//!   start: the queue number, the interfaces it hooked, the ports it queues;
//! * `/opt/var/run/nfqws2.pid` — liveness;
//! * `/proc/net/netfilter/nfnetlink_queue` — that the queue is actually bound;
//! * `/proc/net/route` — the interface our own traffic leaves by;
//! * `/proc/net/nf_conntrack` — the `ctmark` of our own flow, where the
//!   policy's `CONNMARK --set-xmark` shows up.
//!
//! The queue's packet counter is deliberately *not* used as evidence: measured
//! on a Keenetic, its idle rate is around 97 packets/s of other people's
//! traffic, so five probes of our own are indistinguishable from the noise and
//! the verdict flickered between runs. The mark is per-flow and exact; the
//! port and interface coverage is static configuration. Together they answer
//! the question without a coin flip.
//!
//! Nothing is written anywhere, and the only packets sent are the SYNs of one
//! or two TCP connections to the caller's target — the same first packet the
//! tests send.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// The mark the package stamps on connections its access policy leaves alone
/// (`MARK_EXCLUDE` in `etc/init.d/common`): the first packet of such a
/// connection is marked and returned *above* the queue, so the desync never
/// sees it.
pub const MARK_EXCLUDE: u32 = 0x2000_0000;

const CONF_RUN: &str = "/opt/etc/nfqws2/nfqws2.conf.run";
const PIDFILE: &str = "/opt/var/run/nfqws2.pid";
const ROUTE_PROC: &str = "/proc/net/route";
const QUEUE_PROC: &str = "/proc/net/netfilter/nfnetlink_queue";
const CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

/// How long a probe connect is allowed to sit before the next attempt. Below
/// the kernel's initial retransmit timeout, so a probe is one SYN and no retry.
const PROBE_WAIT: Duration = Duration::from_millis(150);
/// Attempts to get a readable mark: the first entry can be missed while the
/// connection is still being created.
const PROBE_ATTEMPTS: usize = 2;

/// What became of our own traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The tool's rules cover the port and interface our traffic uses, and the
    /// policy did not mark the connection: the desync sees these packets.
    Processed,
    /// The access policy excluded our connection before the queue.
    Excluded,
    /// The tool is running, but its rules do not cover us — the port is not in
    /// its list, or our traffic leaves by an interface it did not hook.
    NotQueued,
    /// The tool is running and its queue is not bound, or nothing could be read
    /// back about our flow.
    Unknown,
}

/// The state of the `nfqws2` package on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intercept {
    /// Queue number the tool listens on, as resolved by its init script.
    pub queue: Option<u32>,
    /// `ctmark` of our own connection, when `nf_conntrack` had it.
    pub mark: Option<u32>,
    pub verdict: Verdict,
}

/// Measures how the `nfqws2` package treats a connection to `target`.
///
/// `None` when the package is not running on this device — the caller falls
/// back to whatever else it knows about local bypass tools. `target` must be
/// resolved by the caller: `net/` does not reach into `dns/`.
pub async fn nfqws2(target: SocketAddr) -> Option<Intercept> {
    if !pidfile_alive() {
        return None;
    }
    let Some(conf) = conf_run() else {
        // The package is up but its resolved config is unreadable: say so
        // rather than claim a verdict the numbers do not support.
        return Some(Intercept { queue: None, mark: None, verdict: Verdict::Unknown });
    };

    let mark = probe_mark(target).await;
    let verdict = if mark == Some(MARK_EXCLUDE) {
        Verdict::Excluded
    } else if !conf.queue.is_some_and(queue_bound) {
        // Running, but nothing is listening on its queue: the packets queue and
        // are accepted straight back out, which is not something to report as
        // "processed".
        Verdict::Unknown
    } else if !conf.covers(target.port()) {
        Verdict::NotQueued
    } else {
        Verdict::Processed
    };
    Some(Intercept { queue: conf.queue, mark, verdict })
}

/// The mark on our own connection, opened from an unprivileged source port.
///
/// A failed or blocked connection is fine: the mark is set on the first packet,
/// so the answer does not depend on the handshake completing.
async fn probe_mark(target: SocketAddr) -> Option<u32> {
    for _ in 0..PROBE_ATTEMPTS {
        let Ok(socket) = tokio::net::TcpSocket::new_v4() else {
            return None;
        };
        if socket.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).is_err() {
            return None;
        }
        let Ok(local) = socket.local_addr() else {
            return None;
        };
        let _ = tokio::time::timeout(PROBE_WAIT, socket.connect(target)).await;
        if let Some(mark) = conntrack_mark(local.port(), target) {
            return Some(mark);
        }
    }
    None
}

/// True when the package's pidfile names a live process.
fn pidfile_alive() -> bool {
    let Ok(text) = std::fs::read_to_string(PIDFILE) else {
        return false;
    };
    let pid: String = text.trim().chars().filter(char::is_ascii_digit).collect();
    !pid.is_empty() && std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// The resolved config the init script writes: `KEY=value` or `KEY="value"`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConfRun {
    queue: Option<u32>,
    /// Interfaces the rules were attached to (`ISP_INTERFACE`, space separated).
    interfaces: Vec<String>,
    /// Destination ports the rules queue (`TCP_PORTS`, `80,443` or `590:600`).
    ports: Vec<u16>,
}

impl ConfRun {
    /// Whether the rules would take a connection to `port` out of *our*
    /// interface. Both halves matter: the rules match on `-o <iface>` and on
    /// the destination port, and either one missing means no interception.
    fn covers(&self, port: u16) -> bool {
        self.ports.contains(&port) && self.interfaces.iter().any(|iface| default_route_has(iface))
    }
}

fn conf_run() -> Option<ConfRun> {
    let text = std::fs::read_to_string(CONF_RUN).ok()?;
    Some(parse_conf_run(&text))
}

/// Reads the three values this module needs out of the shell-sourced config.
fn parse_conf_run(text: &str) -> ConfRun {
    let mut conf = ConfRun::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "NFQUEUE_NUM" => conf.queue = value.parse::<u32>().ok(),
            "ISP_INTERFACE" => {
                conf.interfaces = value.split_whitespace().map(str::to_string).collect();
            }
            "TCP_PORTS" => conf.ports = parse_ports(value),
            _ => {}
        }
    }
    conf
}

/// `80,443,2053` and `590:600` both appear in the package's config.
fn parse_ports(value: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if let Some((from, to)) = part.split_once([':', '-']) {
            if let (Ok(from), Ok(to)) = (from.trim().parse::<u16>(), to.trim().parse::<u16>()) {
                ports.extend(from..=to);
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }
    ports
}

/// Whether the package bound its queue: one line per bound queue, and the queue
/// number is the first field.
fn queue_bound(queue: u32) -> bool {
    let Ok(text) = std::fs::read_to_string(QUEUE_PROC) else {
        return false;
    };
    queue_lines_contain(&text, queue)
}

/// The parsing half of [`queue_bound`], on a table in memory.
fn queue_lines_contain(table: &str, queue: u32) -> bool {
    table.lines().any(|line| {
        line.split_whitespace().next().and_then(|q| q.parse::<u32>().ok()) == Some(queue)
    })
}

/// Whether the kernel's IPv4 default route goes out `iface`.
///
/// The probe opens an IPv4 socket to a routable host, so it leaves by the
/// default route; the file lists `Iface Destination ...`, with an all-zero
/// destination for the default.
fn default_route_has(iface: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(ROUTE_PROC) else {
        return false;
    };
    route_lines_have(&text, iface)
}

/// The parsing half of [`default_route_has`], on a table in memory.
fn route_lines_have(table: &str, iface: &str) -> bool {
    table.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(name), Some(destination)) => name == iface && destination == "00000000",
            _ => false,
        }
    })
}

/// `ctmark` of the connection from `local_port` to `target`, if conntrack has it.
fn conntrack_mark(local_port: u16, target: SocketAddr) -> Option<u32> {
    let file = std::fs::File::open(CONNTRACK_PROC).ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if let Some(mark) = parse_conntrack_mark(&line, local_port, target) {
            return Some(mark);
        }
    }
    None
}

/// The mark on the conntrack line describing our connection.
///
/// `None` for any line that is not ours: the entry carries both directions, so
/// the source port alone would also match the reply tuple, whose port is the
/// target's. Only an `ipv4 … tcp` line with our port, our address and the
/// target's port and address is the connection the probe opened.
fn parse_conntrack_mark(line: &str, local_port: u16, target: SocketAddr) -> Option<u32> {
    if !line.starts_with("ipv4") || !line.contains(" tcp ") {
        return None;
    }
    let field = |name: &str, value: &str| {
        let wanted = format!("{name}={value}");
        line.split_whitespace().any(|f| f == wanted)
    };
    if !field("sport", &local_port.to_string())
        || !field("dst", &target.ip().to_string())
        || !field("dport", &target.port().to_string())
    {
        return None;
    }
    line.split_whitespace()
        .find_map(|f| f.strip_prefix("mark=").and_then(|v| v.parse::<u32>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The init script writes these lines verbatim; the queue number, the
    /// interfaces and the port list are the three values this module needs.
    #[test]
    fn conf_run_yields_queue_interfaces_and_ports() {
        let text = "ISP_INTERFACE=\"wan0\"\nIPV6_ENABLED=0\nPOLICY_NAME=\"nfqws\"\n\
                    TCP_PORTS=80,443,1984\nNFQUEUE_NUM=300\n";
        let conf = parse_conf_run(text);
        assert_eq!(conf.queue, Some(300));
        assert_eq!(conf.interfaces, ["wan0"]);
        assert_eq!(conf.ports, [80, 443, 1984]);
    }

    #[test]
    fn conf_run_handles_quote_less_values_and_multiple_interfaces() {
        let conf = parse_conf_run("ISP_INTERFACE=\"wwan0 nwg1\"\nNFQUEUE_NUM=\"512\"\n");
        assert_eq!(conf.queue, Some(512));
        assert_eq!(conf.interfaces, ["wwan0", "nwg1"]);
        assert!(conf.ports.is_empty(), "no TCP_PORTS line");
    }

    /// Both notations appear in the package's own config: `TCP_PORTS` is a plain
    /// list, `UDP_PORTS` uses ranges.
    #[test]
    fn port_lists_expand_ranges() {
        assert_eq!(parse_ports("80,443"), [80, 443]);
        assert_eq!(parse_ports("590:600"), (590..=600).collect::<Vec<u16>>());
        assert_eq!(parse_ports("590-592,1400"), [590, 591, 592, 1400]);
        assert_eq!(parse_ports(""), Vec::<u16>::new());
        assert_eq!(parse_ports("abc,443"), [443], "garbage is skipped, not fatal");
    }

    /// Coverage needs both halves: the port the rules queue, and the interface
    /// they were attached to. Our own traffic leaves by the default route.
    #[test]
    fn coverage_requires_the_port_and_the_default_interface() {
        let mut conf = ConfRun { queue: Some(300), interfaces: vec!["wan0".into()], ports: vec![443] };
        assert!(!conf.covers(8443), "a port the rules do not queue");
        conf.interfaces = vec!["definitely-not-an-interface".into()];
        assert!(!conf.covers(443), "an interface the rules did not hook");
    }

    /// A default route line is the one with an all-zero destination; the header
    /// line must not be mistaken for it.
    #[test]
    fn default_route_is_matched_by_name_and_zero_destination() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     wan0\t00000000\t0101A8C0\t0003\t0\t0\t1000\t00000000\n\
                     wwan1\t00000000\t00000000\t0003\t0\t0\t1000\t00000000\n\
                     wan0\t0100000A\t00000000\t0001\t0\t0\t0\tFFFFFFFF\n";
        assert!(route_lines_have(table, "wan0"), "a default route out of wan0");
        assert!(route_lines_have(table, "wwan1"));
        assert!(!route_lines_have(table, "Iface"), "the header is skipped");
        assert!(!route_lines_have(table, "nwg0"));
    }

    /// The queue file lists bound queues; a queue number that is not there means
    /// nothing is reading it.
    #[test]
    fn queue_bound_only_for_a_listed_queue() {
        let table = "64511    272     0 1     0     0     0    12388  1\n\
                       300    757     0 2 65531     0     0  1247390  1\n";
        assert!(queue_lines_contain(table, 300));
        assert!(queue_lines_contain(table, 64511));
        assert!(!queue_lines_contain(table, 301));
    }

    /// The package's own `MARK_EXCLUDE` is what identifies an excluded flow.
    #[test]
    fn excluded_mark_is_the_one_the_package_sets() {
        assert_eq!(MARK_EXCLUDE, 0x2000_0000);
    }

    /// A real entry from a router: the mark sits beside the tuples, and the same
    /// line carries the reply direction, so a port alone is not enough to
    /// identify the connection the probe opened.
    #[test]
    fn conntrack_mark_requires_the_whole_tuple() {
        let line = "ipv4 2 tcp 6 115 SYN_SENT src=100.90.171.97 dst=31.13.72.174 \
                    sport=56678 dport=443 packets=4 bytes=240 [UNREPLIED] \
                    src=31.13.72.174 dst=100.90.171.97 sport=443 dport=56678 \
                    packets=0 bytes=0 [FASTNAT] mark=0 nmark=256 use=2";
        let target: SocketAddr = "31.13.72.174:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(line, 56678, target), Some(0));
        assert_eq!(parse_conntrack_mark(line, 4711, target), None, "another flow");
        let other_target: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(line, 56678, other_target), None, "another host");
        let udp = line.replace("tcp 6", "udp 17");
        assert_eq!(parse_conntrack_mark(&udp, 56678, target), None, "not TCP");
        let v6 = line.replace("ipv4", "ipv6");
        assert_eq!(parse_conntrack_mark(&v6, 56678, target), None, "not the family we probe");
    }

    /// An excluded connection is what the package stamps before the queue, so
    /// the mark has to survive parsing unchanged.
    #[test]
    fn excluded_connection_reports_the_exclude_mark() {
        let line = "ipv4 2 tcp 6 431 ESTABLISHED src=10.1.30.5 dst=142.250.74.14 \
                    sport=39122 dport=443 src=142.250.74.14 dst=10.1.30.5 sport=443 \
                    dport=39122 mark=536870912 use=1";
        let target: SocketAddr = "142.250.74.14:443".parse().unwrap();
        assert_eq!(parse_conntrack_mark(line, 39122, target), Some(MARK_EXCLUDE));
    }
}

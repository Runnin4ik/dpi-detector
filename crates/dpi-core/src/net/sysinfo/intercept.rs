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
//!   start: the queue number, the policy it looks for, the interfaces it hooked,
//!   the ports it queues, and whether the IPv6 half is on at all;
//! * `/opt/var/run/nfqws2.pid` — liveness;
//! * `/proc/net/netfilter/nfnetlink_queue` — that the queue is actually bound;
//! * `/proc/net/route` and `/proc/net/ipv6_route` — the interface our own
//!   traffic leaves by, one file per address family;
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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// The mark the package stamps on connections its access policy leaves alone
/// (`MARK_EXCLUDE` in `etc/init.d/common`): the first packet of such a
/// connection is marked and returned *above* the queue, so the desync never
/// sees it.
pub const MARK_EXCLUDE: u32 = 0x2000_0000;

const CONF_RUN: &str = "/opt/etc/nfqws2/nfqws2.conf.run";
const PIDFILE: &str = "/opt/var/run/nfqws2.pid";
const ROUTE_PROC: &str = "/proc/net/route";
const ROUTE6_PROC: &str = "/proc/net/ipv6_route";
const QUEUE_PROC: &str = "/proc/net/netfilter/nfnetlink_queue";
const CONNTRACK_PROC: &str = "/proc/net/nf_conntrack";

/// How long a probe connect is allowed to sit before the next attempt. Below
/// the kernel's initial retransmit timeout, so a probe is one SYN and no retry.
const PROBE_WAIT: Duration = Duration::from_millis(150);
/// Attempts to get a readable mark: the first entry can be missed while the
/// connection is still being created.
const PROBE_ATTEMPTS: usize = 2;

/// Why the rules do not take our traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCovered {
    /// Our traffic leaves by an interface the rules were not attached to — a
    /// tunnel, a second uplink. The common case on a router that routes its own
    /// traffic somewhere else.
    Interface,
    /// The port our probe uses is not in the package's `TCP_PORTS`.
    Port,
    /// Our traffic is IPv6 and the package installs no IPv6 rules at all
    /// (`IPV6_ENABLED=0`). The v4 rules can be perfect and this still holds.
    Ipv6,
}

/// What became of our own traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The tool's rules cover the port and interface our traffic uses, and the
    /// policy did not mark the connection: the desync sees these packets.
    Processed,
    /// The access policy excluded our connection before the queue.
    Excluded,
    /// The tool is running, but its rules do not cover us.
    NotQueued(NotCovered),
    /// The tool is running and its queue is not bound, or nothing could be read
    /// back about our flow.
    Unknown,
}

/// Address family a run uses. The package covers the two with separate rules,
/// so the verdict has to be asked for one of them by name: an IPv6 run must not
/// be judged by what the v4 rules do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// The state of the `nfqws2` package on this device, as far as it concerns the
/// detector's own traffic. Everything the notice can name is here; the queue
/// number and the connection mark stay inside — they decide the verdict, they
/// are not something to show a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intercept {
    pub verdict: Verdict,
    /// The policy the package looks for (`POLICY_NAME`), when its config names
    /// one. `None` means the policy part of the verdict is unknown.
    pub policy: Option<String>,
    /// Interfaces the rules were attached to (`ISP_INTERFACE`, space separated).
    pub rules_interfaces: Vec<String>,
    /// The interface our own traffic leaves by — the kernel's default route for
    /// the family, which is where a probe to a routable host goes.
    pub our_interface: Option<String>,
}

/// Measures how the `nfqws2` package treats a connection of `family` to
/// `target`.
///
/// `None` when the package is not running on this device — there is nothing to
/// say about interception, and the caller says nothing.
///
/// `target` is optional and only feeds the mark probe: a run whose family has
/// no address for the chosen domain still gets a verdict from the package's own
/// configuration, which is the half that says whether that family is covered at
/// all. The caller resolves addresses — `net/` does not reach into `dns/`.
pub async fn nfqws2(family: Family, target: Option<SocketAddr>) -> Option<Intercept> {
    if !pidfile_alive() {
        return None;
    }
    let v6 = family == Family::V6;
    let our_interface = if v6 { default_route_interface6() } else { default_route_interface() };
    let Some(conf) = conf_run() else {
        // The package is up but its resolved config is unreadable: say so
        // rather than claim a verdict the numbers do not support.
        return Some(Intercept {
            verdict: Verdict::Unknown,
            policy: None,
            rules_interfaces: Vec::new(),
            our_interface,
        });
    };

    let mark = match target {
        Some(target) => probe_mark(target).await,
        None => None,
    };
    let verdict = if mark == Some(MARK_EXCLUDE) {
        Verdict::Excluded
    } else if !conf.queue.is_some_and(queue_bound) {
        // Running, but nothing is listening on its queue: our packets would be
        // accepted straight back out, which is not "processed".
        Verdict::Unknown
    } else if v6 && !conf.ipv6_enabled {
        // The v4 rules can be perfect and this still holds: with IPV6_ENABLED=0
        // the init script installs no ip6tables rules at all.
        Verdict::NotQueued(NotCovered::Ipv6)
    } else if our_interface.is_none() {
        // Without knowing where our traffic leaves by, coverage cannot be
        // judged at all.
        Verdict::Unknown
    } else if !conf.interfaces.contains(our_interface.as_ref()?) {
        Verdict::NotQueued(NotCovered::Interface)
    } else if !target.is_none_or(|addr| conf.ports.contains(&addr.port())) {
        Verdict::NotQueued(NotCovered::Port)
    } else {
        Verdict::Processed
    };
    Some(Intercept { verdict, policy: conf.policy, rules_interfaces: conf.interfaces, our_interface })
}

/// The mark on our own connection, opened from an unprivileged source port.
///
/// A failed or blocked connection is fine: the mark is set on the first packet,
/// so the answer does not depend on the handshake completing. The socket's
/// family is the target's: an IPv6 run must be judged by the IPv6 path, which
/// the package covers or does not cover separately.
async fn probe_mark(target: SocketAddr) -> Option<u32> {
    for _ in 0..PROBE_ATTEMPTS {
        let v6 = target.is_ipv6();
        let Ok(socket) = (if v6 {
            tokio::net::TcpSocket::new_v6()
        } else {
            tokio::net::TcpSocket::new_v4()
        }) else {
            return None;
        };
        let bind = if v6 {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        if socket.bind(bind).is_err() {
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
    /// The access policy the package looks for (`POLICY_NAME`).
    policy: Option<String>,
    /// Interfaces the rules were attached to (`ISP_INTERFACE`, space separated).
    interfaces: Vec<String>,
    /// Destination ports the rules queue (`TCP_PORTS`, `80,443` or `590:600`).
    ports: Vec<u16>,
    /// `IPV6_ENABLED`: with it off, the init script installs no ip6tables rules
    /// and IPv6 traffic goes out untouched no matter what the v4 side does.
    ipv6_enabled: bool,
}

fn conf_run() -> Option<ConfRun> {
    let text = std::fs::read_to_string(CONF_RUN).ok()?;
    Some(parse_conf_run(&text))
}

/// Reads the values this module needs out of the shell-sourced config.
fn parse_conf_run(text: &str) -> ConfRun {
    let mut conf = ConfRun::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "NFQUEUE_NUM" => conf.queue = value.parse::<u32>().ok(),
            "IPV6_ENABLED" => conf.ipv6_enabled = value.trim() != "0" && !value.trim().is_empty(),
            "POLICY_NAME" => conf.policy = (!value.is_empty()).then(|| value.to_string()),
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

/// The interface the kernel's IPv4 default route goes out.
///
/// The probe opens an IPv4 socket to a routable host, so it leaves this way;
/// the file lists `Iface Destination ...`, with an all-zero destination for the
/// default.
fn default_route_interface() -> Option<String> {
    let text = std::fs::read_to_string(ROUTE_PROC).ok()?;
    route_default_interface(&text)
}

/// The parsing half of [`default_route_interface`], on a table in memory.
fn route_default_interface(table: &str) -> Option<String> {
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(name), Some("00000000")) => Some(name.to_string()),
            _ => None,
        }
    })
}

/// The interface the kernel's IPv6 default route goes out.
///
/// A different file and a different shape from the v4 table: one line per
/// route, `destination/prefix source/prefix nexthop metric ... flags iface`,
/// with the destination written as 32 hex digits and the prefix as two.
fn default_route_interface6() -> Option<String> {
    let text = std::fs::read_to_string(ROUTE6_PROC).ok()?;
    route6_default_interface(&text)
}

/// The parsing half of [`default_route_interface6`], on a table in memory.
fn route6_default_interface(table: &str) -> Option<String> {
    table.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let is_default = fields.first() == Some(&"00000000000000000000000000000000")
            && fields.get(1) == Some(&"00");
        match (is_default, fields.get(9)) {
            (true, Some(iface)) if *iface != "lo" => Some((*iface).to_string()),
            _ => None,
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
/// target's. Only a line of our own address family, for TCP, with our port and
/// the target's port and address, is the connection the probe opened.
fn parse_conntrack_mark(line: &str, local_port: u16, target: SocketAddr) -> Option<u32> {
    let family = if target.is_ipv6() { "ipv6" } else { "ipv4" };
    if !line.starts_with(family) || !line.contains(" tcp ") {
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
    /// policy name, the interfaces and the port list are what this module needs.
    #[test]
    fn conf_run_yields_queue_policy_interfaces_and_ports() {
        let text = "ISP_INTERFACE=\"wan0\"\nIPV6_ENABLED=0\nPOLICY_NAME=\"nfqws\"\n\
                    TCP_PORTS=80,443,1984\nNFQUEUE_NUM=300\n";
        let conf = parse_conf_run(text);
        assert_eq!(conf.queue, Some(300));
        assert_eq!(conf.policy.as_deref(), Some("nfqws"));
        assert_eq!(conf.interfaces, ["wan0"]);
        assert_eq!(conf.ports, [80, 443, 1984]);
    }

    #[test]
    fn conf_run_handles_quote_less_values_and_multiple_interfaces() {
        let conf = parse_conf_run("ISP_INTERFACE=\"wwan0 nwg1\"\nNFQUEUE_NUM=\"512\"\n");
        assert_eq!(conf.queue, Some(512));
        assert_eq!(conf.interfaces, ["wwan0", "nwg1"]);
        assert!(conf.ports.is_empty(), "no TCP_PORTS line");
        assert_eq!(conf.policy, None, "no POLICY_NAME line");
        assert_eq!(parse_conf_run("POLICY_NAME=\"\"\n").policy, None, "an empty name is no name");
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

    /// `IPV6_ENABLED` decides whether the package touches IPv6 at all, and the
    /// init script treats anything but `0` as on.
    #[test]
    fn ipv6_flag_follows_the_config() {
        assert!(parse_conf_run("IPV6_ENABLED=1\n").ipv6_enabled);
        assert!(!parse_conf_run("IPV6_ENABLED=0\n").ipv6_enabled);
        assert!(!parse_conf_run("ISP_INTERFACE=\"wan0\"\n").ipv6_enabled, "absent means off");
    }

    /// The v6 table is hex, one line per route; the default is the all-zero
    /// destination with a zero prefix, and `lo` is not where our traffic leaves.
    #[test]
    fn ipv6_default_route_comes_from_its_own_table() {
        let table = "\
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
            00000000000000000000000000000000 00000400 00000001 00000000 00000003 lo\n\
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
            00000000000000000000000000000000 00000400 00000001 00000000 00000003 wwan1\n\
            2a020000000000000000000000000000 08 00000000000000000000000000000000 00 \
            00000000000000000000000000000000 00000400 00000001 00000000 00000003 wwan1\n";
        assert_eq!(route6_default_interface(table).as_deref(), Some("wwan1"));
        assert_eq!(route6_default_interface(""), None, "no routes at all");
    }

    /// A default route line is the one with an all-zero destination; the header
    /// line must not be mistaken for it, and the name is what the notice shows.
    #[test]
    fn default_route_interface_is_the_zero_destination_entry() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     wwan1\t0101A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
                     wan0\t00000000\t0101A8C0\t0003\t0\t0\t1000\t00000000\n";
        assert_eq!(route_default_interface(table).as_deref(), Some("wan0"));
        assert_eq!(route_default_interface("Iface\tDestination\n"), None, "header only");
        assert_eq!(route_default_interface("wan0\t0101A8C0\n"), None, "no default route");
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

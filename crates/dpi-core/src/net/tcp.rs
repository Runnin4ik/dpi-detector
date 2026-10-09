//! One TCP dial for every probe: connect under a deadline, Nagle off.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::classify::{
    DpiStatus, Detail, IcmpCode, ProbeStage, classify_connect_error_icmp,
};
use crate::net::icmp_err;

/// Why a dial failed: the deadline, or the OS.
///
/// The two are kept apart because callers word them differently — a deadline is
/// a SYN drop ("connect timed out"), while an OS error carries the code the
/// classifier reads to tell a refusal from an unreachable network.
#[derive(Debug)]
pub enum DialError {
    Timeout,
    /// The OS refused the connect. `icmp` is the ICMP message that was seen for
    /// the address at that moment: one errno covers a whole family of ICMP
    /// verdicts, and only the message itself separates a routing failure from a
    /// filter on the path.
    Io { error: io::Error, icmp: Option<IcmpCode> },
}

impl DialError {
    /// The verdict for a connect that did not come up.
    ///
    /// Every probe that dials reports this the same way, and four of them used
    /// to spell it out: the same `classify_connect_error_icmp(&error, icmp, 0,
    /// ProbeStage::TcpConnect)` for an OS error and the same
    /// `(SynDropped, TcpSynTimeout)` for the deadline. Only the wrapper around
    /// the pair differed — a tuple here, `HttpCheck::at` there, a
    /// `BurstAttempt` in the third — so the one place that decides what a
    /// refused connect *means* was four places, and a change to any of them
    /// would have had to find the other three.
    pub fn verdict(self) -> (DpiStatus, Detail) {
        match self {
            DialError::Io { error, icmp } => {
                classify_connect_error_icmp(&error, icmp, 0, ProbeStage::TcpConnect)
            }
            DialError::Timeout => (DpiStatus::SynDropped, Detail::TcpSynTimeout),
        }
    }
}

/// Dials `addr`, giving up after `timeout_dur`, with Nagle disabled.
///
/// `TCP_NODELAY` is not an optimisation here but a requirement: every probe
/// writes one small message and then waits for the answer (a DoH POST, the first
/// fat chunk, a DoT question), and Nagle would hold that write back waiting for
/// an ACK that only the answer produces.
pub async fn dial_tcp(addr: &SocketAddr, timeout_dur: Duration) -> Result<TcpStream, DialError> {
    icmp_err::ensure_started();
    let stream = match timeout(timeout_dur, connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(DialError::Timeout),
    };
    set_no_delay(&stream);
    Ok(stream)
}

/// Connects, and on failure asks what ICMP verdict was seen for the address.
///
/// A failed TCP connect leaves no ICMP message on the socket — the error queue
/// stays empty — so the verdict comes from the watcher that reads the wire.
async fn connect(addr: &SocketAddr) -> Result<TcpStream, DialError> {
    match crate::net::bind::tcp_connect(addr).await {
        Ok(stream) => Ok(stream),
        Err(error) => {
            let icmp = icmp_err::verdict_wait(addr.ip()).await;
            Err(DialError::Io { error, icmp })
        }
    }
}

/// Turns Nagle off on a dialed stream. See [`dial_tcp`] for why every probe wants
/// this — it is a requirement of the exchange, not a tuning knob.
pub(crate) fn set_no_delay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

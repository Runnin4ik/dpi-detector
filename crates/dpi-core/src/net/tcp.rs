//! One TCP dial for every probe: connect under a deadline, Nagle off.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Why a dial failed: the deadline, or the OS.
///
/// The two are kept apart because callers word them differently — a deadline is
/// a SYN drop ("connect timed out"), while an OS error carries the code the
/// classifier reads to tell a refusal from an unreachable network.
#[derive(Debug)]
pub enum DialError {
    Timeout,
    Io(io::Error),
}

/// Dials `addr`, giving up after `timeout_dur`, with Nagle disabled.
///
/// `TCP_NODELAY` is not an optimisation here but a requirement: every probe
/// writes one small message and then waits for the answer (a DoH POST, the first
/// fat chunk, a DoT question), and Nagle would hold that write back waiting for
/// an ACK that only the answer produces.
pub async fn dial_tcp(addr: &SocketAddr, timeout_dur: Duration) -> Result<TcpStream, DialError> {
    let stream = match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return Err(DialError::Io(e)),
        Err(_) => return Err(DialError::Timeout),
    };
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

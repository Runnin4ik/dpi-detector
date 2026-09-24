use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::detail::Detail;
use super::types::{ConnectionStage, DpiStatus, ProbeMetrics};

#[derive(Debug, Clone, Default)]
pub struct ProbeState {
    pub stage: ConnectionStage,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub last_status: Option<DpiStatus>,
    pub last_error_msg: Option<Detail>,
}

/// A handle to observe the progress and classify the outcome of a probe connection.
#[derive(Debug, Clone, Default)]
pub struct DpiProbeTracker {
    pub state: Arc<Mutex<ProbeState>>,
}

impl DpiProbeTracker {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ProbeState::default())),
        }
    }

    pub fn set_stage(&self, stage: ConnectionStage) {
        self.state.lock().stage = stage;
    }

    pub fn get_metrics(&self, duration_ms: u64) -> ProbeMetrics {
        let lock = self.state.lock();
        let status = lock.last_status.unwrap_or_else(|| {
            if lock.stage >= ConnectionStage::TlsHandshakeDone && lock.bytes_recv > 0 {
                DpiStatus::Ok
            } else {
                DpiStatus::Unknown
            }
        });

        ProbeMetrics {
            status,
            stage: lock.stage,
            bytes_sent: lock.bytes_sent,
            bytes_recv: lock.bytes_recv,
            duration_ms,
            detail: lock.last_error_msg.clone().unwrap_or_default(),
        }
    }

    pub fn record_error(&self, status: DpiStatus, detail: Detail) {
        let mut lock = self.state.lock();
        lock.last_status = Some(status);
        lock.last_error_msg = Some(detail);
    }
}

/// Socket wrapper that tracks connection lifecycle stages and byte traffic.
pub struct DpiProbeStream<S> {
    inner: S,
    pub tracker: DpiProbeTracker,
}

impl<S> DpiProbeStream<S> {
    pub fn new(inner: S, tracker: DpiProbeTracker) -> Self {
        Self { inner, tracker }
    }

}

impl<S: AsyncRead + Unpin> AsyncRead for DpiProbeStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before_len = buf.filled().len();
        let poll_res = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(res) = &poll_res {
            let mut state = self.tracker.state.lock();
            match res {
                Ok(()) => {
                    let n = buf.filled().len() - before_len;
                    state.bytes_recv += n;

                    if n == 0 && state.bytes_sent > 0 && state.bytes_recv == 0 {
                        // Premature EOF after sending ClientHello
                        if state.stage == ConnectionStage::TlsClientHelloSent {
                            state.last_status = Some(DpiStatus::TlsRst);
                            state.last_error_msg = Some(Detail::StreamEofHello);
                        }
                    } else if n > 0 && state.stage == ConnectionStage::TlsClientHelloSent {
                        // Received ServerHello
                        state.stage = ConnectionStage::TlsHandshakeDone;
                    }
                }
                Err(err) => {
                    let kind = err.kind();
                    if kind == io::ErrorKind::ConnectionReset || kind == io::ErrorKind::ConnectionAborted {
                        if state.stage == ConnectionStage::TlsClientHelloSent && state.bytes_recv == 0 {
                            state.last_status = Some(DpiStatus::TlsRst);
                            state.last_error_msg = Some(Detail::RstHello);
                        } else if state.stage <= ConnectionStage::TcpConnected {
                            state.last_status = Some(DpiStatus::TcpRst);
                            state.last_error_msg = Some(Detail::StreamRstConnect);
                        }
                    }
                }
            }
        }

        poll_res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DpiProbeStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll_res = Pin::new(&mut self.inner).poll_write(cx, buf);

        if let Poll::Ready(Ok(n)) = poll_res {
            let mut state = self.tracker.state.lock();
            state.bytes_sent += n;

            // Detect TLS ClientHello payload (starts with 0x16 0x03)
            if (state.stage == ConnectionStage::TcpConnected || state.stage == ConnectionStage::Init)
                && buf.len() >= 3
                && buf[0] == 0x16
                && buf[1] == 0x03
            {
                state.stage = ConnectionStage::TlsClientHelloSent;
            }
        }

        poll_res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    /// The socket the wrapper sits on: it answers the next `poll_read` with what
    /// the test queued — bytes, a clean EOF, or an error of the test's kind — and
    /// accepts every write. Nothing else is simulated, so what the assertions read
    /// is the wrapper's own bookkeeping.
    struct MockStream {
        read: Option<Result<usize, io::ErrorKind>>,
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.read.take() {
                Some(Ok(n)) => {
                    buf.put_slice(&vec![0u8; n]);
                    Poll::Ready(Ok(()))
                }
                Some(Err(kind)) => Poll::Ready(Err(io::Error::from(kind))),
                // Nothing queued is a clean EOF: the read returns with no byte
                // filled, which is the event the wrapper classifies.
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A stream already at `stage` with `bytes_sent` on the wire, whose next read
    /// answers with `read`. The tracker's mutex is taken before the stream exists,
    /// so the state the test sets is the state the poll starts from.
    fn stream_at(
        stage: ConnectionStage,
        bytes_sent: usize,
        read: Option<Result<usize, io::ErrorKind>>,
    ) -> DpiProbeStream<MockStream> {
        let tracker = DpiProbeTracker::new();
        {
            let mut state = tracker.state.lock();
            state.stage = stage;
            state.bytes_sent = bytes_sent;
        }
        DpiProbeStream::new(MockStream { read }, tracker)
    }

    fn cx() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    /// The stage every TLS verdict hangs on: a write that carries a ClientHello
    /// moves the probe to `TlsClientHelloSent`, and nothing else does.
    ///
    /// Fails on: the record-header test dropped (a plain-HTTP probe would be read
    /// as a TLS hello, and every reset after it as `TlsRst`), the stage guard
    /// dropped (a hello written after the handshake would drag the stage back), and
    /// the length check dropped — `buf[1]` on a two-byte write is an index out of
    /// bounds, and under `panic = "abort"` that is the process, not the probe.
    #[test]
    fn only_a_client_hello_moves_the_stage() {
        let mut cx = cx();

        let mut hello = stream_at(ConnectionStage::TcpConnected, 0, None);
        assert!(matches!(
            Pin::new(&mut hello).poll_write(&mut cx, &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01]),
            Poll::Ready(Ok(6))
        ));
        assert_eq!(hello.tracker.state.lock().stage, ConnectionStage::TlsClientHelloSent);
        assert_eq!(hello.tracker.state.lock().bytes_sent, 6, "the write is counted");

        let mut http = stream_at(ConnectionStage::TcpConnected, 0, None);
        assert!(matches!(
            Pin::new(&mut http).poll_write(&mut cx, b"GET / HTTP/1.1\r\n"),
            Poll::Ready(Ok(16))
        ));
        assert_eq!(http.tracker.state.lock().stage, ConnectionStage::TcpConnected);

        let mut short = stream_at(ConnectionStage::TcpConnected, 0, None);
        assert!(matches!(Pin::new(&mut short).poll_write(&mut cx, &[0x16, 0x03]), Poll::Ready(Ok(2))));
        assert_eq!(short.tracker.state.lock().stage, ConnectionStage::TcpConnected);
    }

    /// AGENTS.md Rule 3, as a test: a reset or an EOF with the ClientHello on the
    /// wire and **no byte received** is `TlsRst` — the censor dropping the hello —
    /// while the same reset earlier is an ordinary `TcpRst`, and neither label
    /// applies once an answer has arrived.
    ///
    /// Fails on: the `bytes_recv == 0` guard dropped (a server that answered and
    /// then closed would be reported as a TLS reset), the stage guard dropped (a
    /// reset during connect would become a TLS verdict), and the two details
    /// swapped between their branches.
    #[test]
    fn a_reset_after_the_client_hello_is_a_tls_reset() {
        let mut cx = cx();
        let mut buf = [0u8; 64];

        // EOF right after the hello with nothing received: the DROP.
        let mut dropped = stream_at(ConnectionStage::TlsClientHelloSent, 517, None);
        let mut read = ReadBuf::new(&mut buf);
        assert!(matches!(Pin::new(&mut dropped).poll_read(&mut cx, &mut read), Poll::Ready(Ok(()))));
        {
            let state = dropped.tracker.state.lock();
            assert_eq!(state.last_status, Some(DpiStatus::TlsRst));
            assert_eq!(state.last_error_msg, Some(Detail::StreamEofHello));
        }

        // The same reset before the hello: an ordinary TCP reset.
        let mut early =
            stream_at(ConnectionStage::TcpConnected, 0, Some(Err(io::ErrorKind::ConnectionReset)));
        let mut read = ReadBuf::new(&mut buf);
        assert!(matches!(Pin::new(&mut early).poll_read(&mut cx, &mut read), Poll::Ready(Err(_))));
        {
            let state = early.tracker.state.lock();
            assert_eq!(state.last_status, Some(DpiStatus::TcpRst));
            assert_eq!(state.last_error_msg, Some(Detail::StreamRstConnect));
        }

        // A reset after the hello *and* after an answer: the connection got past
        // the hello, so "the hello was dropped" is not the finding.
        let mut answered = stream_at(
            ConnectionStage::TlsClientHelloSent,
            517,
            Some(Err(io::ErrorKind::ConnectionReset)),
        );
        answered.tracker.state.lock().bytes_recv = 1200;
        let mut read = ReadBuf::new(&mut buf);
        assert!(matches!(Pin::new(&mut answered).poll_read(&mut cx, &mut read), Poll::Ready(Err(_))));
        assert_eq!(answered.tracker.state.lock().last_status, None);
    }

    /// A ServerHello on the wire is the handshake done, and that is what makes a
    /// finished probe read `Ok` instead of `Unknown`.
    ///
    /// Fails on: the "bytes received while the hello was out" branch dropped (the
    /// stage would stay at `TlsClientHelloSent`, and `get_metrics` would report
    /// `Unknown` for a probe that answered), and the byte counter not advanced.
    #[test]
    fn a_server_hello_completes_the_handshake_stage() {
        let mut stream = stream_at(ConnectionStage::TlsClientHelloSent, 517, Some(Ok(64)));
        let mut cx = cx();
        let mut buf = [0u8; 64];
        let mut read = ReadBuf::new(&mut buf);
        assert!(matches!(Pin::new(&mut stream).poll_read(&mut cx, &mut read), Poll::Ready(Ok(()))));
        {
            let state = stream.tracker.state.lock();
            assert_eq!(state.stage, ConnectionStage::TlsHandshakeDone);
            assert_eq!(state.bytes_recv, 64);
            assert_eq!(state.last_status, None, "nothing failed");
        }

        let metrics = stream.tracker.get_metrics(12);
        assert_eq!(metrics.status, DpiStatus::Ok);
        assert_eq!(metrics.stage, ConnectionStage::TlsHandshakeDone);
        assert_eq!(metrics.bytes_recv, 64);
    }
}

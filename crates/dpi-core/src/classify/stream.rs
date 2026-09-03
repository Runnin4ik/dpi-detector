use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::types::{ConnectionStage, DpiStatus, ProbeMetrics};

#[derive(Debug, Clone, Default)]
pub struct ProbeState {
    pub stage: ConnectionStage,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub last_status: Option<DpiStatus>,
    pub last_error_msg: Option<String>,
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

    pub fn record_error(&self, status: DpiStatus, detail: impl Into<String>) {
        let mut lock = self.state.lock();
        lock.last_status = Some(status);
        lock.last_error_msg = Some(detail.into());
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

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
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
                            state.last_error_msg =
                                Some("DPI closed connection immediately after TLS ClientHello".into());
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
                            state.last_error_msg =
                                Some("TCP RST received from DPI after TLS ClientHello".into());
                        } else if state.stage <= ConnectionStage::TcpConnected {
                            state.last_status = Some(DpiStatus::TcpRst);
                            state.last_error_msg = Some("TCP RST received from DPI on connect".into());
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

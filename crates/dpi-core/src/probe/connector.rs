use std::future::Future;
use std::io;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::classify::DpiProbeStream;
use crate::net::tls::{create_tls_config, TlsProfile};

/// Pluggable TLS connector trait.
/// Probes interact only with this interface, allowing drop-in browser TLS impersonation (rama)
/// or custom ClientHello engines without rewriting probe logic.
pub(crate) trait DpiTlsConnector: Send + Sync {
    fn connect(
        &self,
        server_name: ServerName<'static>,
        stream: DpiProbeStream<TcpStream>,
    ) -> impl Future<Output = io::Result<TlsStream<DpiProbeStream<TcpStream>>>> + Send;
}

#[derive(Clone)]
pub(crate) struct RustlsConnector {
    connector: TlsConnector,
}

impl From<TlsProfile> for RustlsConnector {
    /// The rustls connector presenting `profile`.
    fn from(profile: TlsProfile) -> Self {
        Self {
            connector: TlsConnector::from(create_tls_config(&profile)),
        }
    }
}

impl DpiTlsConnector for RustlsConnector {
    async fn connect(
        &self,
        server_name: ServerName<'static>,
        stream: DpiProbeStream<TcpStream>,
    ) -> io::Result<TlsStream<DpiProbeStream<TcpStream>>> {
        self.connector.connect(server_name, stream).await
    }
}

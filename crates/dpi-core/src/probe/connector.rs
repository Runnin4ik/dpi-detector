use std::future::Future;
use std::io;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::classify::DpiProbeStream;
use crate::net::tls::{create_insecure_dpi_tls_config, create_verifying_tls_config};

/// Pluggable TLS connector trait.
/// Probes interact only with this interface, allowing drop-in browser TLS impersonation (rama)
/// or custom ClientHello engines without rewriting probe logic.
pub trait DpiTlsConnector: Send + Sync {
    fn connect(
        &self,
        server_name: ServerName<'static>,
        stream: DpiProbeStream<TcpStream>,
    ) -> impl Future<Output = io::Result<TlsStream<DpiProbeStream<TcpStream>>>> + Send;
}

#[derive(Clone)]
pub struct RustlsConnector {
    connector: TlsConnector,
}

impl RustlsConnector {
    pub fn new_insecure() -> Self {
        let config = create_insecure_dpi_tls_config();
        Self {
            connector: TlsConnector::from(config),
        }
    }
    pub fn new_insecure_tls13() -> Self {
        use crate::net::tls::create_insecure_dpi_tls_config_tls13;
        Self {
            connector: TlsConnector::from(create_insecure_dpi_tls_config_tls13()),
        }
    }

    pub fn new_insecure_tls12() -> Self {
        use crate::net::tls::create_insecure_dpi_tls_config_tls12;
        Self {
            connector: TlsConnector::from(create_insecure_dpi_tls_config_tls12()),
        }
    }
    pub fn new_verifying() -> Self {
        let config = create_verifying_tls_config();
        Self {
            connector: TlsConnector::from(config),
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

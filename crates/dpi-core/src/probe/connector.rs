use std::future::Future;
use std::io;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::classify::DpiProbeStream;
use crate::net::fingerprint::HelloVariant;
use crate::net::tls::{create_tls_config, create_tls_config_variant, TlsProfile};

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

impl RustlsConnector {
    /// The rustls connector presenting `profile` with `variant` applied to its
    /// ClientHello — one field of the shape moved, everything else as the profile
    /// has it. `None` is [`Self::from`].
    pub(crate) fn with_variant(profile: TlsProfile, variant: Option<&HelloVariant>) -> Self {
        Self {
            connector: TlsConnector::from(create_tls_config_variant(&profile, variant)),
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

use std::sync::Arc;

use rustls::server::ClientHello;

use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;

#[derive(Debug)]
pub struct FakeServerCertResolver;

impl ResolvesServerCert for FakeServerCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

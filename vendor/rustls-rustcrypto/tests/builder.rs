use std::sync::Arc;

use rustls::ClientConfig as RusTlsClientConfig;
use rustls::ServerConfig as RusTlsServerConfig;

use rustls_rustcrypto::provider as rustcrypto_provider;

mod fake_time;
use fake_time::FakeTime;

mod fake_cert_server_verifier;
use fake_cert_server_verifier::FakeServerCertVerifier;

mod fake_cert_client_verifier;
use fake_cert_client_verifier::FakeClientCertVerifier;

mod fake_cert_server_resolver;
use fake_cert_server_resolver::FakeServerCertResolver;

// Test integration between rustls and rustls in Client builder context
#[test]
fn integrate_client_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let fake_server_cert_verifier = FakeServerCertVerifier {};

    let builder_init =
        RusTlsClientConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let builder_default_versions = builder_init
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?");

    let dangerous_verifier = builder_default_versions
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(fake_server_cert_verifier));

    // Out of scope
    let rustls_client_config = dangerous_verifier.with_no_client_auth();

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

use rustls::DistinguishedName;

// Test integration between rustls and rustls in Server builder context
#[test]
fn integrate_server_builder_with_details_fake() {
    let provider = rustcrypto_provider();
    let time_provider = FakeTime {};

    let builder_init =
        RusTlsServerConfig::builder_with_details(Arc::new(provider), Arc::new(time_provider));

    let builder_default_versions = builder_init
        .with_safe_default_protocol_versions()
        .expect("Default protocol versions error?");

    // A DistinguishedName is a Vec<u8> wrapped in internal types.
    // DER or BER encoded Subject field from RFC 5280 for a single certificate.
    // The Subject field is encoded as an RFC 5280 Name
    //let b_wrap_in: &[u8] = b""; // TODO: should have constant somewhere

    let dummy_entry: &[u8] = b"";

    let client_dn = [DistinguishedName::in_sequence(dummy_entry)];

    let client_cert_verifier = FakeClientCertVerifier { dn: client_dn };

    let dangerous_verifier =
        builder_default_versions.with_client_cert_verifier(Arc::new(client_cert_verifier));

    let server_cert_resolver = FakeServerCertResolver {};

    // Out of scope
    let rustls_client_config =
        dangerous_verifier.with_cert_resolver(Arc::new(server_cert_resolver));

    // RustCrypto is not fips
    assert!(!rustls_client_config.fips());
}

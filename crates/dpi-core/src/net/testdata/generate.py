"""Throwaway generator for crates/dpi-core/src/net/testdata (see the test module
comment for how these are produced). Run once; not part of the build."""

import datetime
import ipaddress
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = pathlib.Path("crates/dpi-core/src/net/testdata")
out.mkdir(parents=True, exist_ok=True)
now = datetime.datetime.now(datetime.timezone.utc)

ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dpi-detector test CA")])
ca = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=7300))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=None,
            decipher_only=None,
        ),
        critical=True,
    )
    .sign(ca_key, hashes.SHA256())
)
(out / "ca.der").write_bytes(ca.public_bytes(serialization.Encoding.DER))

keys = {
    "ecdsa": ec.generate_private_key(ec.SECP256R1()),
    "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "ed25519": ed25519.Ed25519PrivateKey.generate(),
}

for name, key in keys.items():
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=7300))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    (out / f"{name}.der").write_bytes(leaf.public_bytes(serialization.Encoding.DER))
    (out / f"{name}.key.der").write_bytes(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

for path in sorted(out.iterdir()):
    print(path.name, path.stat().st_size)

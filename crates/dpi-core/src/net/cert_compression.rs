//! RFC 8879 certificate decompression — the decoder half only.
//!
//! rustls's `brotli`/`zlib` features implement *both* halves of the extension and
//! publish each as a `&'static dyn` constant, so `default_cert_compressors()`
//! used to keep brotli's encoder linked in every binary that can read a
//! compressed certificate: 241 KiB of encoder code plus 384 KiB of encoder
//! tables (`logs_16`, `kStaticDictionaryBuckets`, `kStaticDictionaryHash`) in the
//! release build, none of which a client can reach — it only ever decompresses
//! what the server sent. Advertising the extension needs the decompressor side
//! alone, so these two live here, over the decoder-only crates.
//!
//! Which algorithms the hello *offers* is the profile's business
//! ([`super::fingerprint::chrome_profile`] and friends pin the RFC 8879 code
//! points). This list only tells rustls which decompressor to pick for the
//! algorithm the server chose in its `CompressedCertificate`, so it holds both
//! algorithms for every profile.
//!
//! Both decoders write into the caller's buffer, sized by rustls to the length
//! the server declared, and neither allocates: a certificate that decompresses to
//! more or fewer bytes than declared is rejected instead of truncated.

use std::io::Cursor;

use rustls::compress::{CertDecompressor, DecompressionFailed};
use rustls::CertificateCompressionAlgorithm;

/// Decompressors for every algorithm a browser profile can advertise.
pub fn decompressors() -> Vec<&'static dyn CertDecompressor> {
    vec![BROTLI, ZLIB]
}

/// True when `algorithm` is one of [`decompressors`], i.e. readable at all.
///
/// A profile must not advertise an algorithm this returns `false` for: the server
/// may then compress its certificate with something the handshake cannot read.
pub fn covers(algorithm: CertificateCompressionAlgorithm) -> bool {
    decompressors().iter().any(|d| d.algorithm() == algorithm)
}

/// `brotli` (RFC 7932), the algorithm Chrome advertises.
pub const BROTLI: &dyn CertDecompressor = &Brotli;

/// `zlib` (RFC 1950), the algorithm Safari and Firefox advertise.
pub const ZLIB: &dyn CertDecompressor = &Zlib;

#[derive(Debug)]
struct Brotli;

#[derive(Debug)]
struct Zlib;

impl CertDecompressor for Brotli {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let mut input = Cursor::new(input);
        let mut output = Cursor::new(output);
        brotli_decompressor::BrotliDecompress(&mut input, &mut output)
            .map_err(|_| DecompressionFailed)?;
        if output.position() as usize != output.into_inner().len() {
            return Err(DecompressionFailed);
        }
        Ok(())
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Brotli
    }
}

impl CertDecompressor for Zlib {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        let declared = output.len();
        match zlib_rs::decompress_slice(output, input, zlib_rs::InflateConfig::default()) {
            (filled, zlib_rs::ReturnCode::Ok) if filled.len() == declared => Ok(()),
            _ => Err(DecompressionFailed),
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zlib
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A body the size of a certificate chain, built from dictionary words and
    /// markup, so the encoder emits back-references the decoder must expand.
    fn payload() -> Vec<u8> {
        let unit = b"<html><head><title>timedownlifeleftbackcodedata</title></head>\
<body>the certificate of a compressed handshake, served by the same host</body></html>";
        unit.iter().copied().cycle().take(64 * 1024).collect()
    }

    fn brotli_compress(plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
        encoder.write_all(plain).expect("encode");
        encoder.flush().expect("encode");
        drop(encoder);
        out
    }

    fn zlib_compress(plain: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; zlib_rs::compress_bound(plain.len())];
        let (filled, rc) =
            zlib_rs::compress_slice(&mut out, plain, zlib_rs::DeflateConfig::default());
        assert_eq!(rc, zlib_rs::ReturnCode::Ok);
        let len = filled.len();
        out.truncate(len);
        out
    }

    #[test]
    fn both_algorithms_read_back_what_an_encoder_wrote() {
        let plain = payload();
        for (algorithm, compressed, decompressor) in [
            ("brotli", brotli_compress(&plain), BROTLI),
            ("zlib", zlib_compress(&plain), ZLIB),
        ] {
            let mut out = vec![0u8; plain.len()];
            decompressor
                .decompress(&compressed, &mut out)
                .unwrap_or_else(|_| panic!("{algorithm} refused a valid stream"));
            assert_eq!(out, plain, "{algorithm} produced the wrong bytes");
        }
    }

    #[test]
    fn a_short_buffer_or_a_truncated_stream_is_refused() {
        let plain = payload();
        let brotli = brotli_compress(&plain);
        let zlib = zlib_compress(&plain);
        for (algorithm, compressed, decompressor) in
            [("brotli", &brotli, BROTLI), ("zlib", &zlib, ZLIB)]
        {
            // rustls sizes the output from the declared length: a stream that
            // does not fill it exactly must fail, not return a prefix.
            let mut short = vec![0u8; plain.len() - 1];
            assert!(
                decompressor.decompress(compressed, &mut short).is_err(),
                "{algorithm} accepted a wrong declared length"
            );
            let mut full = vec![0u8; plain.len()];
            assert!(
                decompressor
                    .decompress(&compressed[..compressed.len() / 2], &mut full)
                    .is_err(),
                "{algorithm} accepted a truncated stream"
            );
        }
    }
}

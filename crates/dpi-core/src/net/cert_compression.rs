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
//! (`net::fingerprint::shapes` pins the RFC 8879 code points per shape). This
//! list only tells rustls which decompressor to pick for the algorithm the
//! server chose in its `CompressedCertificate`, so it holds both algorithms for
//! every profile.
//!
//! All three decoders write into the caller's buffer, sized by rustls to the
//! length the server declared, and a certificate that decompresses to more or
//! fewer bytes than declared is rejected instead of truncated. That buffer is not
//! the only memory a certificate asks for, though: zstd and brotli each name their
//! own window in the bytes the server sent, so both headers are read here first
//! and a window above what this build will allocate for is refused before any
//! decoder state exists (`MAX_ZSTD_WINDOW`, `MAX_BROTLI_WINDOW_BITS`).

use std::io::{Cursor, Read};

use rustls::compress::{CertDecompressor, DecompressionFailed};
use rustls::CertificateCompressionAlgorithm;

/// Decompressors for every algorithm a browser profile can advertise.
pub(crate) fn decompressors() -> Vec<&'static dyn CertDecompressor> {
    vec![BROTLI, ZLIB, ZSTD]
}

/// True when `algorithm` is one of [`decompressors`], i.e. readable at all.
///
/// A profile must not advertise an algorithm this returns `false` for: the server
/// may then compress its certificate with something the handshake cannot read.
/// Test-only: the ClientHello profiles are checked against it, nothing calls it
/// on a live connection.
#[cfg(test)]
pub(crate) fn covers(algorithm: CertificateCompressionAlgorithm) -> bool {
    decompressors().iter().any(|d| d.algorithm() == algorithm)
}

/// `brotli` (RFC 7932), the algorithm Chrome advertises.
pub(crate) const BROTLI: &dyn CertDecompressor = &Brotli;

/// `zlib` (RFC 1950), the algorithm Safari and Firefox advertise.
pub(crate) const ZLIB: &dyn CertDecompressor = &Zlib;

/// `zstd` (RFC 8878), the third algorithm the Firefox family advertises.
///
/// `curl_firefox133` and `curl_firefox147` name
/// `--cert-compression zlib,brotli,zstd` and the bundle's own hello carries
/// `06000100020003` — zlib, brotli, zstd in that order. Advertising it without a
/// decoder is not an option: a server that picks zstd would end the handshake.
pub(crate) const ZSTD: &dyn CertDecompressor = &Zstd;

/// The largest zstd window this build will allocate for.
///
/// rustls caps a compressed certificate at 64 KiB of plaintext
/// (`CERTIFICATE_MAX_SIZE_LIMIT`), so a real encoder's window is a fraction of
/// that. ruzstd's own ceiling is 100 MiB, which is the whole memory budget of
/// the routers this build targets and then some, so the frame header is read
/// here first and anything above this is refused before the decoder allocates.
const MAX_ZSTD_WINDOW: u64 = 1024 * 1024;

/// The largest brotli window this build will allocate for, as the exponent the
/// stream's own header carries.
///
/// brotli, unlike zstd, does not size its window from the input: the header names
/// the `lgwin` the encoder was configured with, and the encoders this build meets
/// leave it at the library default of 22 — rustls's own certificate compressor
/// declares exactly that (`vendor/rustls/src/compress.rs`, `LGWIN = 22`, "the
/// default lgwin parameter"), as does this module's test. RFC 7932's window is
/// 10..=24, so 24 is the top of the range a conforming stream can declare and the
/// only ceiling that cannot refuse a certificate a browser reads.
///
/// The decoder in the tree would honour more: `brotli_decompressor::BrotliDecompress`
/// turns the Large-Window-Brotli extension on (`BrotliState::new` sets
/// `large_window = true`), and its window reaches 30 — a `11 1e` header followed
/// by a one-byte, not-last metablock has that decoder ask its allocator for
/// `1 << 30` bytes, a gibibyte chosen by whoever sent the certificate. Reading the
/// window first is what keeps that out of the allocator: `1 << 24` plus the
/// decoder's 66 bytes of ring-buffer slack is the most any stream can make this
/// build reserve.
const MAX_BROTLI_WINDOW_BITS: u32 = 24;

#[derive(Debug)]
struct Brotli;

#[derive(Debug)]
struct Zstd;

#[derive(Debug)]
struct Zlib;

impl CertDecompressor for Zstd {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        if !matches!(frame_window_size(input), Some(window) if window <= MAX_ZSTD_WINDOW) {
            return Err(DecompressionFailed);
        }

        let mut decoder = ruzstd::decoding::StreamingDecoder::new(Cursor::new(input))
            .map_err(|_| DecompressionFailed)?;
        // rustls sizes the buffer from the length the server declared, and both
        // directions of a mismatch are failures: a stream that does not fill it
        // exactly, and one with bytes left over after it does.
        decoder
            .read_exact(output)
            .map_err(|_| DecompressionFailed)?;
        match decoder.read(&mut [0u8; 1]) {
            Ok(0) => Ok(()),
            _ => Err(DecompressionFailed),
        }
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::Zstd
    }
}

/// The window size a zstd frame declares, from its header alone (RFC 8878 §3.1.1).
///
/// A frame that is not a frame — wrong magic, reserved bit set, or too short to
/// hold its own header — has no window and is refused by the caller.
fn frame_window_size(frame: &[u8]) -> Option<u64> {
    const MAGIC: u32 = 0xfd2f_b528;
    const RESERVED: u8 = 0b0000_1000;
    const SINGLE_SEGMENT: u8 = 0b0010_0000;

    if u32::from_le_bytes(frame.get(..4)?.try_into().ok()?) != MAGIC {
        return None;
    }
    let descriptor = *frame.get(4)?;
    if descriptor & RESERVED != 0 {
        return None;
    }

    // Frame_Header_Descriptor: dictionary id size, then the content size when
    // the frame is a single segment — which is also its window.
    let dictionary_size = match descriptor & 0b11 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let single_segment = descriptor & SINGLE_SEGMENT != 0;
    let content_size = match (descriptor >> 6, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let at = 5 + dictionary_size;

    if single_segment {
        let bytes = frame.get(at..at + content_size)?;
        let mut value = 0u64;
        for (shift, byte) in bytes.iter().enumerate() {
            value |= (*byte as u64) << (8 * shift);
        }
        // The 2-byte form carries an offset of 256.
        if content_size == 2 {
            value += 256;
        }
        return Some(value);
    }

    // RFC 8878 §3.1.1.1.2: with `single_segment` clear the Window_Descriptor
    // is the byte right after the frame header descriptor — it comes *before*
    // the dictionary id, not after it. Reading it at `at` (which is past the
    // dictionary id) read a dictionary or content-size byte instead, so a frame
    // that declares one got a window computed from the wrong byte: the cap the
    // caller applies was then measured against a number that was not the window.
    let window = *frame.get(5)?;
    let window_log = 10 + (window >> 3) as u32;
    let base = 1u64 << window_log;
    let add = (base / 8) * u64::from(window & 7);
    Some(base + add)
}

/// The window size a brotli stream declares, from its header alone (RFC 7932 §9.2).
///
/// The window is the stream's first one to seven bits — fourteen when it uses the
/// Large-Window-Brotli extension — read least-significant bit first, the order
/// `brotli_decompressor`'s own `DecodeWindowBits` reads them in. A stream too
/// short to hold its own header has no window and is refused by the caller.
fn stream_window_bits(stream: &[u8]) -> Option<u32> {
    // `count` bits of `stream` from bit `at` on, least-significant bit first.
    fn take_bits(stream: &[u8], at: usize, count: u32) -> Option<u32> {
        let mut value = 0;
        for offset in 0..count as usize {
            let byte = *stream.get((at + offset) / 8)?;
            value |= u32::from((byte >> ((at + offset) % 8)) & 1) << offset;
        }
        Some(value)
    }

    if take_bits(stream, 0, 1)? == 0 {
        return Some(16);
    }
    let value = take_bits(stream, 1, 3)?;
    if value != 0 {
        return Some(17 + value);
    }
    let value = take_bits(stream, 4, 3)?;
    if value == 1 {
        // The Large-Window-Brotli marker: one bit, then six bits of window.
        return match take_bits(stream, 7, 1)? {
            0 => take_bits(stream, 8, 6),
            _ => None,
        };
    }
    if value != 0 {
        return Some(8 + value);
    }
    Some(17)
}

impl CertDecompressor for Brotli {
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecompressionFailed> {
        if !matches!(stream_window_bits(input), Some(bits) if bits <= MAX_BROTLI_WINDOW_BITS) {
            return Err(DecompressionFailed);
        }

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

    /// `plain` as brotli wrote it with the Large-Window-Brotli extension on.
    ///
    /// `CompressorWriter::new` never sets `large_window`, and its `lgwin` is
    /// clamped to 24 without it, so a stream declaring a window above the ceiling
    /// can only be had through the parameter struct. The encoder's own ring buffer
    /// is `1 << (1 + lgwin)` bytes, so the one call that asks for `lgwin = 25`
    /// costs 64 MiB for as long as it runs.
    fn brotli_compress_large_window(plain: &[u8], lgwin: i32) -> Vec<u8> {
        let params = brotli::enc::BrotliEncoderParams {
            lgwin,
            large_window: true,
            quality: 9,
            ..Default::default()
        };
        let mut out = Vec::new();
        let mut encoder = brotli::CompressorWriter::with_params(&mut out, 4096, &params);
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

    /// `payload()` as zstd wrote it, at level 3.
    ///
    /// Checked in rather than encoded here: `ruzstd` is a decoder, and the only
    /// Rust encoders are the C library this build may not link. The frame is a
    /// single segment of 64 KiB with a 2-byte content size (`0x60`), so it also
    /// covers the header form whose window is the content size. Regenerate with
    /// `python -c "from compression import zstd; …"` if `payload()` ever moves.
    const ZSTD_FRAME: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x60, 0x00, 0xff, 0x95, 0x03, 0x00, 0xe2, 0x07, 0x17, 0x16, 0xa0,
        0xa5, 0x6d, 0xe0, 0xbf, 0x64, 0xfd, 0x8b, 0x35, 0xcb, 0xcd, 0x9d, 0x42, 0x56, 0x35, 0xd4,
        0x13, 0x4c, 0x88, 0xea, 0x30, 0x01, 0xe3, 0xc6, 0x7d, 0xad, 0x9a, 0x15, 0x2e, 0xb3, 0xde,
        0x8a, 0x62, 0x69, 0x01, 0xe1, 0x65, 0x00, 0x0b, 0xa8, 0x2b, 0x07, 0x54, 0x4b, 0xaf, 0x65,
        0x22, 0xa0, 0xd6, 0x18, 0xda, 0x59, 0xf3, 0xd1, 0xa0, 0x83, 0x4e, 0xd8, 0x98, 0xf5, 0xa4,
        0xc8, 0x2d, 0xe3, 0xc6, 0xe1, 0x31, 0x9d, 0x6b, 0x04, 0x83, 0xe5, 0xc7, 0xc9, 0x07, 0xa5,
        0x61, 0xb0, 0x69, 0x85, 0x4e, 0x9c, 0x8e, 0x7e, 0x24, 0xd1, 0x7a, 0x24, 0xa9, 0xeb, 0x05,
        0x05, 0x00, 0x67, 0xff, 0x8b, 0x69, 0x10, 0x31, 0x87, 0x09, 0x13, 0xc4, 0xa9, 0x6a, 0xb4,
        0x38, 0x83, 0xda, 0x03,
    ];

    #[test]
    fn every_algorithm_reads_back_what_an_encoder_wrote() {
        let plain = payload();
        for (algorithm, compressed, decompressor) in [
            ("brotli", brotli_compress(&plain), BROTLI),
            ("zlib", zlib_compress(&plain), ZLIB),
            ("zstd", ZSTD_FRAME.to_vec(), ZSTD),
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
        for (algorithm, compressed, decompressor) in [
            ("brotli", brotli.as_slice(), BROTLI),
            ("zlib", zlib.as_slice(), ZLIB),
            ("zstd", ZSTD_FRAME, ZSTD),
        ] {
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
            // The declared length is the whole plaintext, never a prefix of a
            // longer stream: one byte more must be refused too.
            let mut long = vec![0u8; plain.len() + 1];
            assert!(
                decompressor.decompress(compressed, &mut long).is_err(),
                "{algorithm} accepted a wrong declared length"
            );
        }
    }

    /// A frame that declares a window bigger than this build will allocate for
    /// is refused from its header, before any decoder state exists.
    ///
    /// `ruzstd`'s own limit is 100 MiB — more than the whole memory budget of a
    /// router — so the check is ours: `28 b5 2f fd` is the magic, `00` a frame
    /// header with no dictionary and no content size, and `a0` a window
    /// descriptor of `windowLog = 30`, one gibibyte.
    #[test]
    fn a_frame_that_declares_a_huge_window_is_refused() {
        let frame = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0xa0];
        assert!(frame_window_size(&frame).expect("a readable header") > MAX_ZSTD_WINDOW);
        assert_eq!(frame_window_size(&frame), Some(1 << 30));

        let mut out = vec![0u8; 64];
        assert!(ZSTD.decompress(&frame, &mut out).is_err());

        // The same declared window behind a 4-byte dictionary id (0x03): the
        // descriptor byte is still at 5, so the cap still sees 1 GiB.
        let with_id = [0x28, 0xb5, 0x2f, 0xfd, 0x03, 0xa0, 0x01, 0x02, 0x03, 0x04];
        assert!(frame_window_size(&with_id).expect("a readable header") > MAX_ZSTD_WINDOW);
        assert_eq!(frame_window_size(&with_id), Some(1 << 30));
    }

    /// The window a frame declares is read from its header alone, in both forms
    /// RFC 8878 allows: a window descriptor, or the content size of a
    /// single-segment frame.
    #[test]
    fn the_declared_window_is_read_from_the_frame_header() {
        // Frame_Header_Descriptor 0x00: no content size, so a window descriptor
        // follows. `windowLog = 10 + exponent`, plus `windowBase / 8 * mantissa`.
        assert_eq!(frame_window_size(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00]), Some(1024));
        assert_eq!(frame_window_size(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x08]), Some(2048));
        assert_eq!(frame_window_size(&[0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x09]), Some(2304));
        // Frame_Header_Descriptor 0x03: no content size, not a single segment, a
        // 4-byte dictionary id. The window descriptor is still the byte at 5 and
        // the id runs 6..10 — reading the window past the id (the mistake this
        // pins) would take 0x04 here and report 1024.
        assert_eq!(
            frame_window_size(&[0x28, 0xb5, 0x2f, 0xfd, 0x03, 0x40, 0x01, 0x02, 0x03, 0x04]),
            Some(1 << 18)
        );
        // 0x60: a single segment with a 2-byte content size, which is the window.
        assert_eq!(frame_window_size(ZSTD_FRAME), Some(64 * 1024));
        // Not a frame at all: wrong magic, a reserved bit, or a header that does
        // not fit in what arrived.
        assert_eq!(frame_window_size(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), None);
        assert_eq!(frame_window_size(&[0x28, 0xb5, 0x2f, 0xfd, 0x08, 0x00]), None);
        assert_eq!(frame_window_size(&[0x28, 0xb5]), None);
    }

    /// A stream that declares a window bigger than this build will allocate for
    /// is refused from its header, before any decoder state exists.
    ///
    /// The stream is real: the encoder wrote it with the Large-Window-Brotli
    /// extension at `lgwin = 25`, the smallest window above the ceiling, and the
    /// decoder in the tree reads it back byte for byte — its window is the only
    /// reason this module says no. `BrotliState::new` sets `large_window = true`,
    /// so nothing else stands between such a header and `1 << 25` bytes of ring
    /// buffer, or `1 << 30` for the thirty the extension allows.
    #[test]
    fn a_stream_that_declares_a_window_above_the_ceiling_is_refused() {
        let plain = payload();
        let stream = brotli_compress_large_window(&plain, 25);
        assert_eq!(stream_window_bits(&stream), Some(25));
        assert!(stream_window_bits(&stream).expect("a readable header") > MAX_BROTLI_WINDOW_BITS);

        let mut decoded = vec![0u8; plain.len()];
        brotli_decompressor::BrotliDecompress(
            &mut Cursor::new(&stream),
            &mut Cursor::new(&mut decoded[..]),
        )
        .expect("the decoder reads a large-window stream");
        assert_eq!(decoded, plain, "the stream is the payload, compressed");

        let mut out = vec![0u8; plain.len()];
        assert!(BROTLI.decompress(&stream, &mut out).is_err());
    }

    /// The window a stream declares is read from its header alone, in both forms
    /// the decoder in the tree accepts: RFC 7932's, and the six-bit window of the
    /// Large-Window-Brotli extension.
    #[test]
    fn the_declared_window_is_read_from_the_stream_header() {
        // WBITS 16 is one zero bit, 17 seven bits, 18..=24 four bits, and 10..=15
        // seven bits — the codes brotli's own `EncodeWindowBits` writes.
        assert_eq!(stream_window_bits(&[0x00]), Some(16));
        assert_eq!(stream_window_bits(&[0x01]), Some(17));
        for lgwin in 18..=24 {
            let header = ((lgwin - 17) << 1) | 1;
            assert_eq!(stream_window_bits(&[header as u8]), Some(lgwin));
        }
        for lgwin in 10..=15 {
            let header = ((lgwin - 8) << 4) | 1;
            assert_eq!(stream_window_bits(&[header as u8]), Some(lgwin));
        }
        // `11` is the extension's marker, and the six bits after it the window.
        assert_eq!(stream_window_bits(&[0x11, 0x0a]), Some(10));
        assert_eq!(stream_window_bits(&[0x11, 0x18]), Some(24));
        assert_eq!(stream_window_bits(&[0x11, 0x1e]), Some(30));
        // Not a header at all: nothing there, or a window that has not arrived.
        assert_eq!(stream_window_bits(&[]), None);
        assert_eq!(stream_window_bits(&[0x11]), None);
    }
}

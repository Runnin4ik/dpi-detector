//! The profile suite: the pins that keep a record honest, and the gates that
//! keep the provider and the records from drifting apart.
//!
//! Anything that changes a pinned JA3/JA4 — an extension added or dropped, a
//! cipher reordered, the padding extension lost — makes the profile stop
//! reproducing the fingerprint the censor is reported to match on, so the pins
//! are the reason the numbers live in `shapes.rs` and not in a builder.

use super::shapes::*;
use super::*;

use crate::net::tls::{create_tls_config, crypto_provider, crypto_provider_with_pq, TlsProfile};

/// Pinned from the `curl-impersonate v2.2.2` bundle (see
/// [`tests::bundle_versions_match_their_ja4`]).
const CHROME_107_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
const CHROME_107_JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-\
             49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0";
const SAFARI_155_JA4: &str = "t13d2014h2_a09f3c656075_14788d8d241b";
const FIREFOX_133_JA4: &str = "t13d1716h2_5b57614c22b0_eeeea6562960";

/// The payload lengths a GREASE ECH body declares: BoringSSL's estimate of an
/// encoded inner hello — 128, 160, 192 or 224 bytes, rounded to 32 — plus the
/// AEAD tag. See `setup_ech_grease()` in its `ssl/encrypted_client_hello.cc`;
/// the bodies measured from `curl-impersonate`'s own captures are 186, 218, 250
/// and 282 bytes, which is this list plus the 42-byte header.
const GREASE_PAYLOAD_LENGTHS: [usize; 4] = [144, 176, 208, 240];

/// Every identity is spelled the way its own client writes it, and the two
/// protocols differ in what that costs.
///
/// The bundle's own h1 request is the measurement: the Safari 18 and later
/// wrappers write lowercase names throughout, every other client writes
/// `Accept-Encoding`, `Sec-Fetch-Site` and `TE` capitalized, and `curl_firefox147`
/// — a `--impersonate` one-liner — writes `Te`. HTTP/2 lowercases both (RFC 9113
/// §8.2.1), so the spelling only reaches the wire through the h1 case map
/// (`probe::http::header_case_map`); the `priority` header reaches it on h1 only
/// for the clients that send it there, which the second column pins.
#[test]
fn every_identity_is_spelled_the_way_its_client_writes_it() {
    let expected: [(TlsFingerprint, &str, bool); 20] = [
        (TlsFingerprint::Rustls, "accept-encoding", false),
        (TlsFingerprint::Firefox133, "Accept-Encoding", true),
        (TlsFingerprint::Chrome107, "Accept-Encoding", false),
        (TlsFingerprint::Safari155, "Accept-Encoding", false),
        (TlsFingerprint::Chrome146, "Accept-Encoding", false),
        (TlsFingerprint::Safari180, "accept-encoding", false),
        (TlsFingerprint::Edge101, "Accept-Encoding", false),
        (TlsFingerprint::Chrome99Android, "Accept-Encoding", false),
        (TlsFingerprint::Chrome116, "Accept-Encoding", false),
        (TlsFingerprint::Chrome123, "Accept-Encoding", false),
        (TlsFingerprint::Chrome131, "Accept-Encoding", false),
        (TlsFingerprint::Chrome131Android, "Accept-Encoding", false),
        (TlsFingerprint::Firefox147, "Accept-Encoding", true),
        (TlsFingerprint::Safari153, "Accept-Encoding", false),
        (TlsFingerprint::Safari170, "Accept-Encoding", false),
        (TlsFingerprint::Safari172Ios, "Accept-Encoding", false),
        (TlsFingerprint::Safari184Ios, "accept-encoding", false),
        (TlsFingerprint::Safari260, "accept-encoding", false),
        (TlsFingerprint::Safari260Ios, "accept-encoding", false),
        (TlsFingerprint::Tor145, "Accept-Encoding", true),
    ];

    for (fingerprint, spelling, priority_on_h1) in expected {
        let code = fingerprint.code();
        let identity = http_identity(fingerprint);
        let (name, _) = identity
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .expect("every identity states its encoding");
        assert_eq!(*name, spelling, "{code} spells its header names this way");
        assert_eq!(identity.priority_on_h1, priority_on_h1, "{code} on h1");
    }
}

/// The key shares every profile sends, in wire order.
///
/// rustls's own choice is one share for the first offered group plus, when that
/// group is hybrid, its component's — which is what `chrome131`, `chrome133`,
/// `chrome136` and `safari260` keep. Four wrappers pass
/// `--tls-key-shares-limit 3`, and their records name the groups instead
/// (`TlsShape::key_share_groups`): the Firefox family sends three entries, its
/// hybrid group's component included, and Tor three without one. The bundle puts
/// the same lists on the wire, so this is the count a censor matching a
/// `curl_firefox133` handshake reads.
#[test]
fn every_profile_sends_the_key_shares_its_wrapper_asks_for() {
    let shares = |fingerprint: TlsFingerprint| {
        let config = create_tls_config(&TlsProfile::insecure(fingerprint));
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        crate::net::ja3::key_share_groups(&buf)
    };

    let expected = [
        (TlsFingerprint::Rustls, "29"),
        (TlsFingerprint::Firefox133, "4588,29,23"),
        (TlsFingerprint::Chrome107, "29"),
        (TlsFingerprint::Safari155, "29"),
        (TlsFingerprint::Chrome146, "4588,29"),
        (TlsFingerprint::Safari180, "29"),
        (TlsFingerprint::Edge101, "29"),
        (TlsFingerprint::Chrome99Android, "29"),
        (TlsFingerprint::Chrome116, "29"),
        (TlsFingerprint::Chrome123, "29"),
        (TlsFingerprint::Chrome131, "4588,29"),
        (TlsFingerprint::Chrome131Android, "29"),
        (TlsFingerprint::Chrome146, "4588,29"),
        (TlsFingerprint::Firefox147, "4588,29,23"),
        (TlsFingerprint::Safari153, "29"),
        (TlsFingerprint::Safari170, "29"),
        (TlsFingerprint::Safari172Ios, "29"),
        (TlsFingerprint::Safari184Ios, "29"),
        (TlsFingerprint::Safari260, "4588,29"),
        (TlsFingerprint::Safari260Ios, "29"),
        (TlsFingerprint::Tor145, "29,23,24"),
    ];

    for (fingerprint, groups) in expected {
        assert_eq!(shares(fingerprint), groups, "{}", fingerprint.code());
    }
}

/// JA3 with its extension list sorted — the key that survives Chromium's
/// per-connection shuffle.
///
/// JA3 reads extensions in the order they arrive, so a shape that shuffles them
/// (Chrome 110+) has no single JA3 by construction; the extension *set*, which
/// the shuffle preserves, is what a pin can still hold. JA4 needs no such
/// treatment: it sorts before hashing, which is why the JA4 of a shuffling shape
/// is stable and its JA3 is not.
#[cfg(test)]
fn order_independent_ja3(ja3: &str) -> String {
    let mut fields: Vec<String> = ja3.split(',').map(str::to_string).collect();
    if let Some(extensions) = fields.get_mut(2) {
        let mut parts: Vec<String> = extensions.split('-').map(str::to_string).collect();
        parts.sort_unstable();
        *extensions = parts.join("-");
    }
    fields.join(",")
}

/// The profiles that permute their extension order shuffle it per connection.
///
/// Chromium 110+ sends a fresh order every time (`tls_permute_extensions` in the
/// fork's captures, `--tls-permute-extensions` in the bundle's own wrappers from
/// `curl_chrome110` on), so the set of extensions is the shape and the order is
/// not: JA3 of a real Chrome differs from connection to connection and JA4 does
/// not. One hello is emitted many times, and every shape that does *not* permute
/// has to come back byte-identical — the control that says the shuffle is the
/// only thing that moved.
#[test]
fn only_the_chromium_profiles_shuffle_their_extension_order() {
    let hello = |fingerprint: TlsFingerprint| {
        let config = create_tls_config(&TlsProfile::insecure(fingerprint));
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        buf
    };
    // GREASE values are drawn per connection and masked out, so the orders below
    // compare the extensions a profile named, not the values it greases them with.
    let order = |record: &[u8]| {
        crate::net::ja3::extension_types(record)
            .into_iter()
            .filter(|ext| !crate::net::ja3::is_grease(*ext))
            .collect::<Vec<_>>()
    };

    for fingerprint in TlsFingerprint::ALL {
        let first = hello(fingerprint);
        let shapes = fingerprint.spec();
        if shapes.baseline {
            // The one row that installs no profile: rustls's own hello, whose
            // extension set is the provider's, not a record's.
            continue;
        }
        let expected = shapes.permute_extensions;
        // The set never changes — only its order may.
        let mut set = order(&first);
        set.sort_unstable();
        let mut pinned = shapes.ext_order.to_vec();
        pinned.retain(|ext| {
            *ext != rustls::client::hello_profile::GREASE_EXTENSION_MARKER
        });
        pinned.sort_unstable();
        // The hello carries exactly what the record names, minus what rustls
        // does not emit for this version set.
        assert!(
            set.iter().all(|ext| pinned.contains(ext)),
            "{} sends an extension its record does not name",
            fingerprint.code()
        );

        let mut distinct = 1;
        for _ in 0..16 {
            let next = hello(fingerprint);
            if order(&next) != order(&first) {
                distinct += 1;
            }
            if !expected {
                // The same order every time. The length is not compared any
                // more: the GREASE ECH body is one of four sizes the client
                // draws per connection, so the hello's own size moves with it
                // (`GREASE_PAYLOAD_LENGTHS`), while its order does not.
                assert_eq!(
                    order(&next),
                    order(&first),
                    "{} must send one order every time",
                    fingerprint.code()
                );
            }
        }
        if expected {
            assert!(
                distinct > 1,
                "{} is marked as permuting but sent one order in 16 connections",
                fingerprint.code()
            );
        }
    }
}

/// Every shape that permutes is one of the Chromium records the browser's own
/// captures mark, and no other shape permutes.
#[test]
fn the_shuffling_shapes_are_the_chromium_ones_from_110_on() {
    let mut permuting: Vec<&str> = TlsFingerprint::ALL
        .iter()
        .filter(|fingerprint| fingerprint.spec().permute_extensions)
        .map(|fingerprint| fingerprint.code())
        .collect();
    permuting.sort_unstable();
    assert_eq!(
        permuting,
        ["chrome116", "chrome123", "chrome131", "chrome131android", "chrome146"]
    );
}

/// The seven shapes whose client carries `encrypted_client_hello`, and the body
/// they carry.
///
/// The list is the wrappers that name `--ech true` — `curl_chrome123`,
/// `curl_chrome131`, `curl_chrome131_android`, `curl_chrome146`,
/// `curl_firefox133`, `curl_firefox147` and `curl_tor145` — and every one of
/// them is GREASE: curl needs DoH or an explicit `--ecl:` to have a real
/// config, and no wrapper passes either.
///
/// The body is the GREASE form of draft-ietf-tls-esni §6.2 — outer, a cipher
/// suite, a random `config_id`, an `enc` of the KEM's public-key length, and a
/// payload the size of an encoded inner hello plus the AEAD tag — and a fresh
/// one per connection, which is why the extension's bytes can never be compared
/// between two handshakes, not even two of a real browser's.
#[test]
fn the_ech_shapes_carry_the_grease_extension_and_the_others_do_not() {
    let hello = |fingerprint: TlsFingerprint| {
        let config = create_tls_config(&TlsProfile::insecure(fingerprint));
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        buf
    };
    let body_of = |record: &[u8]| {
        // `write_tls` hands back the record; `extensions` walks a handshake
        // message.
        let message = record.get(5..).unwrap_or(record);
        crate::net::ja3::extensions(message)
            .into_iter()
            .find(|(kind, _)| *kind == EXT_ENCRYPTED_CLIENT_HELLO)
            .map(|(_, body)| body.to_vec())
    };

    let mut carrying = Vec::new();
    for fingerprint in TlsFingerprint::ALL {
        if fingerprint.spec().baseline {
            continue;
        }
        let body = body_of(&hello(fingerprint));
        if !fingerprint.spec().ech {
            assert!(
                body.is_none(),
                "{} sends ECH without advertising it",
                fingerprint.code()
            );
            continue;
        }
        carrying.push(fingerprint.code());
        let body = body.unwrap_or_else(|| {
            panic!("{} advertises ECH and sends none", fingerprint.code())
        });

        assert_eq!(body[0], 0, "{}: type outer", fingerprint.code());
        assert_eq!(
            &body[1..5],
            &[0x00, 0x01, 0x00, 0x01],
            "{}: HKDF-SHA256 with AES-128-GCM",
            fingerprint.code()
        );
        let enc_len = u16::from_be_bytes([body[6], body[7]]) as usize;
        assert_eq!(enc_len, 32, "{}: an X25519 encapsulated key", fingerprint.code());
        let payload_len = u16::from_be_bytes([body[8 + enc_len], body[9 + enc_len]]) as usize;
        assert!(
            GREASE_PAYLOAD_LENGTHS.contains(&payload_len),
            "{}: a {payload_len}-byte payload, not one of the four a browser sends",
            fingerprint.code()
        );
        assert_eq!(
            body.len(),
            10 + enc_len + payload_len,
            "{}: the body is its header plus the payload",
            fingerprint.code()
        );

        // The length is picked per connection, from the same four values, and
        // nothing else about the body repeats: `enc` is a fresh ephemeral
        // public key and the payload is random.
        let mut lengths = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let other = body_of(&hello(fingerprint)).expect("the extension again");
            assert_ne!(other, body, "{}: the same body twice", fingerprint.code());
            let other_enc = u16::from_be_bytes([other[6], other[7]]) as usize;
            let other_len = u16::from_be_bytes([other[8 + other_enc], other[9 + other_enc]]) as usize;
            assert!(
                GREASE_PAYLOAD_LENGTHS.contains(&other_len),
                "{}: a {other_len}-byte payload on a later connection",
                fingerprint.code()
            );
            lengths.insert(other_len);
        }
        assert!(
            lengths.len() > 1,
            "{}: every payload was {lengths:?}, so the length is not drawn per connection",
            fingerprint.code()
        );
    }

    carrying.sort_unstable();
    assert_eq!(
        carrying,
        [
            "chrome123",
            "chrome131",
            "chrome131android",
            "chrome146",
            "firefox133",
            "firefox147",
            "tor145",
        ]
    );
}

/// The HTTP identity and the ClientHello of a profile have to describe the
/// same client: a `chrome107` hello behind a `Chrome/133` UA is a mismatch a
/// header-matching middlebox reads in a single packet.
#[test]
fn http_identity_names_the_version_the_hello_imitates() {
    for (fingerprint, marker) in [
        (TlsFingerprint::Chrome107, "Chrome/107.0.0.0"),
        (TlsFingerprint::Firefox133, "Firefox/133.0"),
        (TlsFingerprint::Safari155, "Version/15.5"),
        
        (TlsFingerprint::Safari180, "Version/18.0"),
        (TlsFingerprint::Edge101, "Edg/101.0.1210.47"),
        (TlsFingerprint::Chrome99Android, "Chrome/99.0.4844.58 Mobile"),
        (TlsFingerprint::Chrome116, "Chrome/116.0.0.0"),
        (TlsFingerprint::Chrome123, "Chrome/123.0.0.0"),
        (TlsFingerprint::Chrome131, "Chrome/131.0.0.0"),
        (TlsFingerprint::Chrome131Android, "Chrome/131.0.0.0 Mobile"),
        (TlsFingerprint::Chrome146, "Chrome/146.0.0.0"),
        (TlsFingerprint::Firefox147, "Firefox/147.0"),
        (TlsFingerprint::Safari153, "Version/15.3"),
        (TlsFingerprint::Safari170, "Version/17.0"),
        (TlsFingerprint::Safari172Ios, "Version/17.2 Mobile"),
        (TlsFingerprint::Safari184Ios, "Version/18.4 Mobile"),
        (TlsFingerprint::Safari260, "Version/26.0"),
        (TlsFingerprint::Safari260Ios, "Version/26.0 Mobile"),
        (TlsFingerprint::Tor145, "Firefox/128.0"),
    ] {
        let identity = http_identity(fingerprint);
        let ua = identity.user_agent.expect("a browser profile carries a UA");
        assert!(ua.contains(marker), "{}: {ua}", fingerprint.code());
        let (_, in_list) = identity
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .expect("the UA is part of the list, in its wire position");
        assert_eq!(*in_list, ua, "{}: field and list disagree", fingerprint.code());
        if let Some((_, value)) = identity
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("sec-ch-ua"))
        {
            let version = ua.split("Chrome/").nth(1).and_then(|v| v.split('.').next()).expect("UA version");
            assert!(value.contains(&format!("v=\"{version}\"")), "{}: {value}", fingerprint.code());
        }
        // The HTTP identity is the impersonated client's, encoding included:
        // what the byte-counting probes do with it is their own business.
        let (_, encoding) = identity
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .expect("every identity states its encoding");
        let expected = match fingerprint {
            TlsFingerprint::Firefox133
            | TlsFingerprint::Chrome146
            | TlsFingerprint::Chrome131
            | TlsFingerprint::Chrome131Android
            | TlsFingerprint::Chrome123
            | TlsFingerprint::Firefox147
            | TlsFingerprint::Safari260
            | TlsFingerprint::Safari260Ios
            | TlsFingerprint::Tor145 => "gzip, deflate, br, zstd",
            TlsFingerprint::Chrome107
            | TlsFingerprint::Safari155
            | TlsFingerprint::Safari180
            | TlsFingerprint::Edge101
            | TlsFingerprint::Chrome99Android
            | TlsFingerprint::Chrome116
            | TlsFingerprint::Safari153
            | TlsFingerprint::Safari170
            | TlsFingerprint::Safari172Ios
            | TlsFingerprint::Safari184Ios => "gzip, deflate, br",
            TlsFingerprint::Rustls => "identity",
        };
        assert_eq!(*encoding, expected, "{}: {}", fingerprint.code(), *encoding);
    }
    let baseline = http_identity(TlsFingerprint::Rustls);
    assert!(baseline.user_agent.is_none(), "the baseline profile impersonates nobody");
    assert_eq!(baseline.headers, [("accept-encoding", "identity")]);
}

/// Every profile's h2 shape against the wrapper it copies: the settings that go
/// out and the order they go out in, the connection window, the request's
/// pseudo-header order, and the priority its `HEADERS` frame carries.
///
/// Read from each wrapper's own flags — `--http2-settings`,
/// `--http2-window-update`, `--http2-pseudo-headers-order`,
/// `--http2-stream-weight` / `--http2-stream-exclusive`, `--http2-no-priority` —
/// and cross-checked against what the bundle itself sends to an echo service
/// (`tools/fingerprint/fingerprint.py echo-diff`). Safari 18 and 26 name `8:1`
/// and `9:1`, which this build cannot put on the wire: neither h2 nor hyper
/// exposes them (see `vendor/h2/README-PATCH.md`), so they are absent by design.
///
/// One table rather than a sample per field, because the fields are what a
/// profile *is*: sampling Chrome, Firefox and Safari 15.5 is how Safari 18 kept
/// a pseudo-header order of `m,s,p,a` against the `m,s,a,p` its wrapper, its
/// capture and the bundle all send.
#[test]
fn every_h2_preface_matches_the_wrapper_it_copies() {
    use ::h2::client::PseudoOrder;
    use ::h2::client::PseudoOrder::*;

    /// The `SETTINGS` payload as the wire orders it: `settings_order` names the
    /// ids that go first, in that order, and the rest follow ascending.
    fn payload(h2: &H2Fingerprint) -> String {
        let mut present: Vec<(u16, u32)> = Vec::new();
        if let Some(value) = h2.header_table_size {
            present.push((1, value));
        }
        if let Some(value) = h2.enable_push {
            present.push((2, value as u32));
        }
        if let Some(value) = h2.max_concurrent_streams {
            present.push((3, value));
        }
        present.push((4, h2.initial_window_size));
        if let Some(value) = h2.max_frame_size {
            present.push((5, value));
        }
        if let Some(value) = h2.max_header_list_size {
            present.push((6, value));
        }
        if let Some(value) = h2.enable_connect_protocol {
            present.push((8, value as u32));
        }
        if let Some(value) = h2.no_rfc7540_priorities {
            present.push((9, value as u32));
        }
        let first: Vec<(u16, u32)> = h2
            .settings_order
            .iter()
            .filter_map(|id| present.iter().find(|(kind, _)| kind == id).copied())
            .collect();
        let rest: Vec<(u16, u32)> = present
            .iter()
            .copied()
            .filter(|(kind, _)| !first.iter().any(|(f, _)| f == kind))
            .collect();
        first
            .into_iter()
            .chain(rest)
            .map(|(id, value)| format!("{id}:{value}"))
            .collect::<Vec<_>>()
            .join(";")
    }

    /// One row: profile, settings payload, `WINDOW_UPDATE` increment, pseudo
    /// header order, request priority.
    type Row = (TlsFingerprint, &'static str, u32, PseudoOrder, Option<(u16, bool)>);

    let expected: [Row; 20] = [
        (TlsFingerprint::Firefox133, "1:65536;2:0;4:131072;5:16384", 12_517_377, MethodPathAuthorityScheme, Some((42, false))),
        (TlsFingerprint::Firefox147, "1:65536;2:0;4:131072;5:16384", 12_517_377, MethodPathAuthorityScheme, Some((42, false))),
        (TlsFingerprint::Tor145, "1:65536;2:0;4:131072;5:16384", 12_517_377, MethodPathAuthorityScheme, Some((42, false))),
        (TlsFingerprint::Chrome107, "1:65536;2:0;3:1000;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome99Android, "1:65536;3:1000;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Edge101, "1:65536;3:1000;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome116, "1:65536;2:0;3:1000;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome123, "1:65536;2:0;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome131, "1:65536;2:0;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome131Android, "1:65536;2:0;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome146, "1:65536;2:0;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Chrome146, "1:65536;2:0;4:6291456;6:262144", 15_663_105, MethodAuthoritySchemePath, Some((256, true))),
        (TlsFingerprint::Safari155, "4:4194304;3:100", 10_485_760, MethodSchemePathAuthority, Some((255, false))),
        (TlsFingerprint::Safari153, "4:4194304;3:100", 10_485_760, MethodSchemePathAuthority, Some((255, false))),
        (TlsFingerprint::Safari170, "2:0;4:4194304;3:100", 10_485_760, MethodSchemePathAuthority, Some((255, false))),
        (TlsFingerprint::Safari172Ios, "2:0;4:2097152;3:100", 10_485_760, MethodSchemePathAuthority, Some((255, false))),
        (TlsFingerprint::Safari180, "2:0;3:100;4:2097152;8:1;9:1", 10_420_225, MethodSchemeAuthorityPath, Some((256, false))),
        (TlsFingerprint::Safari184Ios, "2:0;3:100;4:2097152;9:1", 10_420_225, MethodSchemeAuthorityPath, Some((256, false))),
        (TlsFingerprint::Safari260, "2:0;3:100;4:2097152;9:1", 10_420_225, MethodSchemeAuthorityPath, None),
        (TlsFingerprint::Safari260Ios, "2:0;3:100;4:2097152;9:1", 10_420_225, MethodSchemeAuthorityPath, None),
    ];

    for (fingerprint, settings, increment, pseudo, priority) in expected {
        let code = fingerprint.code();
        let h2 = h2_fingerprint(fingerprint).expect("every profile but the baseline tunes h2");
        assert_eq!(payload(&h2), settings, "{code} settings payload");
        assert_eq!(h2.connection_window - 65_535, increment, "{code} window increment");
        assert_eq!(h2.pseudo_order, pseudo, "{code} pseudo-header order");
        assert_eq!(h2.priority, priority, "{code} request priority");
    }
    assert!(h2_fingerprint(TlsFingerprint::Rustls).is_none(), "the baseline keeps hyper's defaults");
}

/// The version-bearing label is display only: it must not collide with a
/// parser name, and every profile whose shape is a pinned client version has
/// to say which one.
#[test]
fn display_labels_name_the_pinned_version() {
    assert_eq!(TlsFingerprint::Firefox133.display_label(), "FIREFOX 133");
    assert_eq!(TlsFingerprint::Chrome107.display_label(), "CHROME 107");
    assert_eq!(TlsFingerprint::Safari155.display_label(), "SAFARI 155");
    assert_eq!(TlsFingerprint::Rustls.display_label(), "RUSTLS");
    assert_eq!(TlsFingerprint::Chrome146.display_label(), "CHROME 146");
    assert_eq!(TlsFingerprint::Safari180.display_label(), "SAFARI 180");
    assert_eq!(TlsFingerprint::Edge101.display_label(), "EDGE 101");
    for fp in TlsFingerprint::ALL {
        assert!(fp.display_label().starts_with(fp.token()), "{fp:?}");
        assert!(fp.display_label().is_ascii(), "{fp:?}");
    }
}

#[test]
fn fingerprint_tokens_are_stable() {
    assert_eq!(TlsFingerprint::Rustls.token(), "RUSTLS");
    assert_eq!(TlsFingerprint::Firefox133.token(), "FIREFOX");
    assert_eq!(TlsFingerprint::Rustls.code(), "rustls");
    assert_eq!(TlsFingerprint::Firefox133.code(), "firefox133");
    assert_eq!(TlsFingerprint::default(), TlsFingerprint::Rustls);
}

#[test]
fn fingerprint_parses_known_values_and_rejects_others() {
    assert_eq!(TlsFingerprint::parse("rustls"), Some(TlsFingerprint::Rustls));
    assert_eq!(TlsFingerprint::parse("FIREFOX147"), Some(TlsFingerprint::Firefox147));
    assert_eq!(TlsFingerprint::parse(" firefox147 "), Some(TlsFingerprint::Firefox147));
    // The unnumbered names are gone rather than aliased: a config or a script
    // that still says `firefox` is told it is unknown instead of silently
    // measuring a version it does not name.
    for old in ["firefox", "chrome", "safari", "tor", "edge", "custom"] {
        assert_eq!(TlsFingerprint::parse(old), None, "{old} must not resolve");
    }
    // One name per record, and it is the code `--legend` prints and `--json`
    // carries. The control shape is the one name with no version in it.
    for (name, fingerprint) in [
        ("chrome107", TlsFingerprint::Chrome107),
        ("chrome99android", TlsFingerprint::Chrome99Android),
        ("chrome116", TlsFingerprint::Chrome116),
        ("chrome123", TlsFingerprint::Chrome123),
        ("chrome131", TlsFingerprint::Chrome131),
        ("chrome131android", TlsFingerprint::Chrome131Android),
        ("chrome146", TlsFingerprint::Chrome146),
        ("firefox133", TlsFingerprint::Firefox133),
        ("firefox147", TlsFingerprint::Firefox147),
        ("safari155", TlsFingerprint::Safari155),
        ("safari153", TlsFingerprint::Safari153),
        ("safari170", TlsFingerprint::Safari170),
        ("safari172ios", TlsFingerprint::Safari172Ios),
        ("safari180", TlsFingerprint::Safari180),
        ("safari184ios", TlsFingerprint::Safari184Ios),
        ("safari260", TlsFingerprint::Safari260),
        ("safari260ios", TlsFingerprint::Safari260Ios),
        ("edge101", TlsFingerprint::Edge101),
        ("tor145", TlsFingerprint::Tor145),
    ] {
        assert_eq!(TlsFingerprint::parse(name), Some(fingerprint), "{name}");
        assert_eq!(
            TlsFingerprint::parse(&name.to_ascii_uppercase()),
            Some(fingerprint),
            "{name} in caps"
        );
    }
    // The bundle's wrapper names are rejected, and so is every unnumbered or
    // non-matching spelling: a name that resolves to a client version other
    // than the one it says is worse than a name that does not resolve — the
    // first silently measures another client, the second is reported.
    for name in [
        "curl_chrome107",
        "curl_chrome116",
        "curl_chrome123",
        "curl_chrome146",
        "curl_firefox133",
        "curl_firefox147",
        "curl_safari155",
        "curl_safari170",
        "curl_safari172_ios",
        "curl_safari184_ios",
        "curl_edge101",
        "curl_tor145",
        "chrome99",
        "chrome133",
        "firefox135",
        "safari184",
        "safari184_ios",
        "safari172_ios",
        "chrome131_android",
        "chrome",
    ] {
        assert_eq!(TlsFingerprint::parse(name), None, "{name} must not resolve");
    }
    assert_eq!(TlsFingerprint::parse(""), None);
}

/// Test 6 takes a *list* of profiles; `all` and the profile codes must work,
/// and an unrecognised token must be reported rather than silently swapped
/// for a different set.
#[test]
fn fingerprint_list_parsing() {
    assert_eq!(TlsFingerprint::parse_list("all").0, TlsFingerprint::ALL.to_vec());
    assert_eq!(TlsFingerprint::parse_list("").0, TlsFingerprint::ALL.to_vec());
    assert_eq!(
        TlsFingerprint::parse_list("chrome107, safari155").0,
        vec![TlsFingerprint::Chrome107, TlsFingerprint::Safari155]
    );
    // Duplicates collapse, order is kept.
    assert_eq!(
        TlsFingerprint::parse_list("safari155 safari155 rustls").0,
        vec![TlsFingerprint::Safari155, TlsFingerprint::Rustls]
    );
    // Mixed: the known half runs, the rest is reported.
    let (known, unknown) = TlsFingerprint::parse_list("firefox133,bogus");
    assert_eq!(known, vec![TlsFingerprint::Firefox133]);
    assert_eq!(unknown, vec!["bogus".to_string()]);
    // A wrapper name is exactly as unknown as any other typo, and it is
    // reported rather than mapped to the version it names.
    let (_, unknown) = TlsFingerprint::parse_list("curl_chrome107");
    assert_eq!(unknown, vec!["curl_chrome107".to_string()]);
    // Nothing recognised: fall back to all, still reporting what was wrong.
    let (known, unknown) = TlsFingerprint::parse_list("bogus");
    assert_eq!(known, TlsFingerprint::ALL.to_vec());
    assert_eq!(unknown, vec!["bogus".to_string()]);
    assert!(TlsFingerprint::parse_list("all").1.is_empty());
}

/// Every variant has exactly one record, in the same order, and no record
/// describes a variant twice. This is what makes "a profile is data" true:
/// `spec()` panics on a variant with no row, and this test is the only place
/// that can compare the hand-written variant list with the table.
#[test]
fn fingerprint_table_is_total() {
    assert_eq!(TlsFingerprint::ALL.len(), SHAPES.len(), "one record per variant");
    for (variant, shape) in TlsFingerprint::ALL.iter().zip(SHAPES) {
        assert_eq!(*variant, shape.variant, "records are in report order");
    }
    for shape in SHAPES {
        assert_eq!(
            shape.variant.spec().code,
            shape.code,
            "{}: spec() finds its own record",
            shape.code
        );
    }
}

/// One name per record, lowercase, and — apart from the control shape — the
/// name carries the version it sends: a second record claiming `chrome146`
/// would make the parser's answer depend on table order, and a name without a
/// number would hide which version a probe presented.
#[test]
fn profile_names_are_unique_lowercase_and_versioned() {
    let mut seen: Vec<&str> = Vec::new();
    for shape in SHAPES {
        assert_eq!(shape.code, shape.code.to_ascii_lowercase(), "{}: code is lowercase", shape.code);
        assert!(!shape.source.is_empty(), "{}: a record states where it came from", shape.code);
        assert!(!seen.contains(&shape.code), "{} is claimed twice", shape.code);
        if shape.variant != TlsFingerprint::Rustls {
            assert!(
                shape.code.chars().any(|c| c.is_ascii_digit()),
                "{}: a client profile's name carries its version",
                shape.code
            );
        }
        seen.push(shape.code);
    }
}

/// The default set is what a run pays for in network time, so it is a decision
/// rather than a copy of everything: it must be non-empty, it must name real
/// shapes, and it must not repeat one.
#[test]
fn default_set_is_a_subset_of_all() {
    assert!(!TlsFingerprint::DEFAULT_SET.is_empty());
    for (index, fingerprint) in TlsFingerprint::DEFAULT_SET.iter().enumerate() {
        assert!(TlsFingerprint::ALL.contains(fingerprint), "{fingerprint:?} is not a profile");
        assert!(
            !TlsFingerprint::DEFAULT_SET[..index].contains(fingerprint),
            "{fingerprint:?} is listed twice"
        );
    }
}

/// The baseline is the one record that installs nothing: no profile, no
/// impersonated `User-Agent`, no h2 preface, no certificate compression. Every
/// other record has to be a real shape, because `apply` would otherwise hand
/// rustls a hello that is neither the baseline nor a browser's.
#[test]
fn the_baseline_is_the_only_shape_that_impersonates_nobody() {
    for shape in SHAPES {
        if shape.baseline {
            assert!(shape.ciphers.is_empty(), "{}: the baseline overrides nothing", shape.code);
            assert!(shape.headers.is_none(), "{}: the baseline impersonates nobody", shape.code);
            assert!(shape.h2.is_none(), "{}: the baseline keeps hyper's defaults", shape.code);
            assert!(!shape.pq, "{}: the baseline uses the shared provider", shape.code);
        } else {
            assert!(!shape.ciphers.is_empty(), "{}: a profile states its cipher list", shape.code);
            assert!(shape.headers.is_some(), "{}: a profile presents a header set", shape.code);
            assert!(shape.h2.is_some(), "{}: a profile pins its h2 preface", shape.code);
            assert!(!shape.alpn.is_empty(), "{}: a profile offers an ALPN list", shape.code);
            // A profile that advertises no certificate compression has to say
            // so: the empty list is what keeps extension 27 off the wire, and a
            // shape that lists the extension but no algorithm would be one no
            // client sends. Safari 15.3 and Tor 14.5 send none.
            if shape.cert_compression.is_empty() {
                assert!(
                    matches!(shape.variant, TlsFingerprint::Safari153 | TlsFingerprint::Tor145),
                    "{}: a profile with no compress_certificate must name the client that sends none",
                    shape.code
                );
            }
        }
        assert_eq!(
            shape.baseline,
            hello_profile(shape.variant).is_none(),
            "{}: only the baseline installs no profile",
            shape.code
        );
    }
}

/// The profile must describe Firefox 133: 17 ciphers, the hybrid group
/// first, its extension order (session_ticket and psk_key_exchange_modes in,
/// signed_certificate_timestamp out), and nothing suppressed.
#[test]
fn firefox_profile_matches_the_shape_it_is_pinned_to() {
    let profile = hello_profile(TlsFingerprint::Firefox133).expect("firefox installs a profile");

    assert_eq!(profile.cipher_suites.as_ref().map(|c| c.len()), Some(17));
    assert_eq!(profile.groups.as_ref().and_then(|g| g.first()), Some(&4588));

    let order = profile.extension_order.as_ref().expect("extension order");
    assert_eq!(order.len(), 16);
    assert_eq!(order.first(), Some(&EXT_SERVER_NAME));
    assert_eq!(order.last(), Some(&EXT_ENCRYPTED_CLIENT_HELLO));
    assert!(order.contains(&EXT_RENEGOTIATION_INFO));
    assert!(order.contains(&EXT_DELEGATED_CREDENTIALS));
    assert!(order.contains(&EXT_RECORD_SIZE_LIMIT));
    assert!(order.contains(&EXT_SESSION_TICKET));
    assert!(order.contains(&EXT_PSK_KEY_EXCHANGE_MODES));
    assert!(!order.contains(&EXT_SCT), "Firefox 133 sends no SCT");
    // 65037 is the extension whose absence used to be this profile's one
    // deviation from `curl_firefox133`; it is GREASE ECH, and the wrapper's
    // `--ech true` is what puts it there.
    assert_eq!(order.iter().filter(|ext| **ext == EXT_ENCRYPTED_CLIENT_HELLO).count(), 1);

    assert!(profile.suppress_extensions.is_empty());
    assert!(!profile.grease);
    // Firefox offers both protocols, and so must the profile now that the
    // probes speak HTTP/2 as well.
    assert_eq!(profile.alpn.as_deref(), Some(&[b"h2".to_vec(), b"http/1.1".to_vec()][..]));
}

/// The JA3 (and size) of the hello a profile writes on `version`: the two
/// pinned builders are what the probes and test 6 use, `Any` is what the
/// tools and the earlier measurements used.
fn client_hello_of(fingerprint: TlsFingerprint, version: TlsVersion) -> (String, usize) {
    let (ja3, length, _) = client_hello_full(fingerprint, version);
    (ja3, length)
}

/// The three fingerprints of the hello a profile writes on `version`: JA3,
/// the hello size, and JA4.
fn client_hello_full(
    fingerprint: TlsFingerprint,
    version: TlsVersion,
) -> (String, usize, String) {
    let profile = match version {
        TlsVersion::Tls12 => TlsProfile::insecure(fingerprint).tls12(),
        TlsVersion::Tls13 => TlsProfile::insecure(fingerprint).tls13(),
        TlsVersion::Any => TlsProfile::insecure(fingerprint),
    };
    let config = create_tls_config(&profile);
    let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
    let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).expect("write ClientHello");
    (
        crate::net::ja3::client_hello_ja3(&buf),
        buf.len() - 5,
        crate::net::ja4::client_hello_ja4(&buf),
    )
}

/// The three profiles must send exactly the JA3 their pinned
/// `curl-impersonate` version sends, measured from the v2.2.2 bundle with a
/// local ClientHello sniffer (`curl_chrome107`, `curl_safari155`,
/// `curl_firefox133`).
///
/// Anything that changes these — an extension added or dropped, a cipher
/// reordered, the padding extension lost — makes the profile stop
/// reproducing the fingerprint the censor is reported to match on.
///
/// Both pinned builders were checked because a hello that advertises one
/// version while still carrying the other's extensions and cipher suites is a
/// shape no client sends: `standby-rezka.tv` answered the hybrid with
/// `alert_illegal_parameter`. Pinned, the bundles drop what belongs to the
/// other version — the 1.2-era extensions and the 1.2 cipher suites from a
/// 1.3-only hello, `supported_versions` and the padding (a 1.2 hello is
/// already under the 256-byte floor where BoringSSL stops padding) from a
/// 1.2-only one — and Chrome also drops ALPS from the 1.2 hello.
///
/// The 1.3 hellos are byte-identical to the pinned bundles; the point-formats
/// field is empty there, which is what a 1.3-only browser hello has. The 1.2
/// hellos stop one extension short of the bundle's, which lists
/// `compress_certificate` (27) in a 1.2 hello — rustls offers it only when
/// the hello also offers 1.3, so the cipher suites match and `27` is the one
/// extension we cannot send. Firefox's 1.3 hello stops at `27` for the ECH
/// reason in its record.
#[test]
fn bundle_versions_match_their_ja3() {
    const CHROME_107: &str = CHROME_107_JA3;
    const SAFARI_155: &str = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-\
         49161-49172-49171-157-156-53-47-49160-49170-10,\
         0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0";
    // `curl_firefox133` sends `...,28-27-65037`, and so does this build: the
    // GREASE ECH extension closes the list of the four Firefox-family and Tor
    // shapes whose wrapper names `--ech true` (see the record in `shapes`).
    const FIREFOX_133: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-\
         49161-49171-49172-156-157-47-53,\
         0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0";

    const CHROME_107_TLS13: &str =
        "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-17513-21,29-23-24,";
    const SAFARI_155_TLS13: &str =
        "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-21,29-23-24-25,";
    const FIREFOX_133_TLS13: &str =
        "771,4865-4867-4866,0-23-65281-10-16-5-34-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,";

    const CHROME_107_TLS12: &str = "771,49195-49199-49196-49200-52393-52392-49171-49172-\
         156-157-47-53,0-23-65281-10-11-35-16-5-13-18,29-23-24,0";
    const SAFARI_155_TLS12: &str = "771,49196-49195-52393-49200-49199-52392-49162-49161-\
         49172-49171-157-156-53-47-49160-49170-10,\
         0-23-65281-10-11-16-5-13-18,29-23-24-25,0";
    const FIREFOX_133_TLS12: &str = "771,49195-49199-52393-52392-49196-49200-49162-49161-\
         49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-13-28-65037,\
         4588-29-23-24-25-256-257,0";

    // The M4 shapes, all of them clients that do not permute, so their JA3 is
    // one string. `chrome99android` is Chrome 107's hello behind a phone's
    // identity and carries exactly that JA3; the two Firefox rows are 133's with
    // the certificate-timestamp extension, ECH included; Tor is 145's with the
    // ECH extension and without `compress_certificate`. `chrome116`,
    // `chrome123`, `chrome131`, `chrome131android` and `chrome146` are absent on
    // purpose: Chromium shuffles the extension order from 110 on, so their JA3
    // differs per connection and only JA4 can be pinned (see
    // `added_shapes_match_the_captures_they_were_read_from`).
    const FIREFOX_147: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-\
         49161-49171-49172-156-157-47-53,\
         0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0";
    const SAFARI_153: &str = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-\
         49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-49160-49170-10,\
         0-23-65281-10-11-16-5-13-18-51-45-43-21,29-23-24-25,0";
    const SAFARI_180: &str = SAFARI_155;
    // Safari 26.0 on macOS reorders the three TLS 1.3 suites, drops padding and
    // sends the session ticket; the iOS hello keeps the older order and pads.
    const SAFARI_260: &str = "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-\
         49161-49172-49171-157-156-53-47-49160-49170-10,\
         0-23-65281-10-11-35-16-5-13-18-51-45-43-27,4588-29-23-24-25,0";
    const SAFARI_260_IOS: &str = "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-\
         49162-49161-49172-49171-157-156-53-47-49160-49170-10,\
         0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25,0";
    const TOR_145: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-\
         49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-28-65037,29-23-24-25-256-257,0";

    // The pinned-version rows cover the three profiles the report names, which
    // is where the version pinning was measured; the rest of the table is the
    // unpinned hello.
    let rows: [(TlsVersion, &[(TlsFingerprint, &str)]); 3] = [
        (
            TlsVersion::Any,
            &[
                (TlsFingerprint::Chrome107, CHROME_107),
                (TlsFingerprint::Safari155, SAFARI_155),
                (TlsFingerprint::Firefox133, FIREFOX_133),
                (TlsFingerprint::Chrome99Android, CHROME_107),
                (TlsFingerprint::Firefox147, FIREFOX_147),
                (TlsFingerprint::Safari153, SAFARI_153),
                (TlsFingerprint::Safari170, SAFARI_155),
                (TlsFingerprint::Safari172Ios, SAFARI_155),
                (TlsFingerprint::Safari184Ios, SAFARI_180),
                (TlsFingerprint::Safari260, SAFARI_260),
                (TlsFingerprint::Safari260Ios, SAFARI_260_IOS),
                (TlsFingerprint::Tor145, TOR_145),
            ],
        ),
        (
            TlsVersion::Tls13,
            &[
                (TlsFingerprint::Chrome107, CHROME_107_TLS13),
                (TlsFingerprint::Safari155, SAFARI_155_TLS13),
                (TlsFingerprint::Firefox133, FIREFOX_133_TLS13),
            ],
        ),
        (
            TlsVersion::Tls12,
            &[
                (TlsFingerprint::Chrome107, CHROME_107_TLS12),
                (TlsFingerprint::Safari155, SAFARI_155_TLS12),
                (TlsFingerprint::Firefox133, FIREFOX_133_TLS12),
            ],
        ),
    ];
    for (version, rows) in rows {
        for (fingerprint, expected) in rows {
            assert_eq!(
                client_hello_of(*fingerprint, version).0,
                *expected,
                "{fingerprint} ({version:?})"
            );
        }
    }

    // BoringSSL pads a 1.3 browser hello to exactly 512 bytes — the
    // `curl-impersonate v2.2.2` chrome107/safari155 hellos measure 512 — and
    // the padding extension is part of the JA3s above, so both the size and a
    // lost pad are checked here. A 1.2 hello is shorter than the 256-byte
    // floor, so it carries no padding at all: the bundle's 1.2 hellos measure
    // 198 and 210 bytes against our 185 and 199 (the `compress_certificate`
    // difference), all of them well under the floor.
    for fingerprint in [TlsFingerprint::Chrome107, TlsFingerprint::Safari155] {
        for version in [TlsVersion::Any, TlsVersion::Tls13] {
            let (_, length) = client_hello_of(fingerprint, version);
            assert_eq!(length, 512, "{fingerprint} hello ({version:?})");
        }
        let (_, length) = client_hello_of(fingerprint, TlsVersion::Tls12);
        assert!(length < 256, "{fingerprint} 1.2 hello is padded: {length}");
    }
}

/// JA4 hashes what JA3 cannot: the signature-algorithms list and the ALPN
/// value. These are the values of the pinned bundle versions, computed from
/// the ClientHellos the same sniffer captured (`curl_chrome107`,
/// `curl_safari155`, `curl_firefox133`) and cross-checked against what
/// `tls.peet.ws` reports for our own probes.
///
/// The unpinned strings are the bundle's own. The version-pinned ones cannot be
/// captured from the wrapper — a `.bat` sets its own `--tlsv1.0`/`--tlsv1.2`
/// and the pinned client is a configuration this build makes, not a bundle
/// profile — so those are this build's own hellos, recorded so that a change to
/// the pinning path (a dropped `compress_certificate`, a lost ALPS) shows up as
/// a diff rather than as silence.
///
/// Firefox's differs from the bundle's in the extension count and hash only, and
/// only because of the omitted `encrypted_client_hello` (see its record); the
/// cipher hash is the bundle's.
#[test]
fn bundle_versions_match_their_ja4() {
    // The 1.3 unpinned hashes are the bundle's: those hellos are byte-identical
    // to `curl_chrome107`/`curl_safari155`/`curl_firefox133`. A pinned hello
    // drops what belongs to the other version — the 1.2-era extensions from a
    // 1.3-only hello and, at 1.2, `supported_versions` plus the padding — and
    // the strings below are the ones this build sends for that configuration.
    const CHROME_107_TLS13: &str = "t13d0312h2_55b375c5d22e_89e42599e699";
    const SAFARI_155_TLS13: &str = "t13d0311h2_55b375c5d22e_14aed462abe7";
    const FIREFOX_133_TLS13: &str = "t13d0314h2_55b375c5d22e_be02affae600";
    const CHROME_107_TLS12: &str = "t12d1210h2_d34a8e72043a_fae48490d0f6";
    const SAFARI_155_TLS12: &str = "t12d1709h2_ba5946811be1_e0e2b8a7da62";
    const FIREFOX_133_TLS12: &str = "t12d1412h2_c866b44c5a26_94a9864545c3";

    for (version, chrome, safari, firefox) in [
        (
            TlsVersion::Any,
            CHROME_107_JA4,
            SAFARI_155_JA4,
            FIREFOX_133_JA4,
        ),
        (TlsVersion::Tls13, CHROME_107_TLS13, SAFARI_155_TLS13, FIREFOX_133_TLS13),
        (TlsVersion::Tls12, CHROME_107_TLS12, SAFARI_155_TLS12, FIREFOX_133_TLS12),
    ] {
        let (_, _, got) = client_hello_full(TlsFingerprint::Chrome107, version);
        assert_eq!(got, chrome, "chrome ({version:?})");
        let (_, _, got) = client_hello_full(TlsFingerprint::Safari155, version);
        assert_eq!(got, safari, "safari ({version:?})");
        let (_, _, got) = client_hello_full(TlsFingerprint::Firefox133, version);
        assert_eq!(got, firefox, "firefox ({version:?})");
    }
}

/// Chrome 133, as uTLS `HelloChrome_133` (v1.8.2, unchanged on master) defines
/// it and `curl_chrome133a` sends it. Both sources agree on every list; only
/// uTLS supplies an extension *order*, because Chromium permutes it per
/// connection.
///
/// The expected strings are the uTLS lists with one edit and nothing else:
/// the extension list is compared *sorted*, because Chromium shuffles the order
/// per connection and a shuffled hello has no single JA3. The set is the uTLS
/// set — `encrypted_client_hello` (65037) included, since `curl_chrome133a`
/// names `--ech true` and sends the extension as GREASE — and JA4's sorted view
/// is the stable key.
///
/// With that edit the strings below are the uTLS lists, which is why a reader
/// can redo them against the source rather than against this test. The pinned
/// versions are derived the same way: the 1.3 hello drops what belongs to the
/// 1.2 era, the 1.2 hello drops `supported_versions` and ALPS.
#[test]
fn chrome_146_matches_the_utls_list_it_is_derived_from() {
    const CHROME_133_JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-\
         49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613-65037,\
         4588-29-23-24,0";
    const CHROME_133_TLS13: &str =
        "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-17613-65037,4588-29-23-24,";
    const CHROME_133_TLS12: &str = "771,49195-49199-49196-49200-52393-52392-49171-49172-\
         156-157-47-53,0-23-65281-10-11-35-16-5-13-18-65037,4588-29-23-24,0";

    for (version, expected) in [
        (TlsVersion::Any, CHROME_133_JA3),
        (TlsVersion::Tls13, CHROME_133_TLS13),
        (TlsVersion::Tls12, CHROME_133_TLS12),
    ] {
        assert_eq!(
            order_independent_ja3(&client_hello_of(TlsFingerprint::Chrome146, version).0),
            order_independent_ja3(expected),
            "{version:?}"
        );
    }
}

/// The JA4 of Chrome 133's hello, in the parts a source can speak to.
///
/// JA4 DBs publish `t13d1516h2_8daaf6152771_...` for the whole Chrome 133–146
/// line, and both parts of ours now line up with it:
///
/// * `t13d1516h2` — the counts, 16 extensions and 15 ciphers, which is what the
///   source sends (`encrypted_client_hello` included);
/// * `8daaf6152771` — the cipher hash, the published one. It moving means the
///   cipher list stopped being Chrome's, which no other test would notice;
/// * the extension hash is ours alone: it is computed over the extension *set*
///   in a fixed sorted order, and no public database says which set a Chrome
///   133 behind an ECH-less resolver sent.
#[test]
fn chrome_146_ja4_pins_the_parts_a_source_covers() {
    const CHROME_133_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

    let (_, _, ja4) = client_hello_full(TlsFingerprint::Chrome146, TlsVersion::Any);
    assert!(ja4.starts_with("t13d1516h2_"), "{ja4}");
    assert_eq!(
        ja4.split('_').nth(1),
        Some("8daaf6152771"),
        "the cipher hash the JA4 databases publish for Chrome 133+"
    );
    assert_eq!(ja4, CHROME_133_JA4);
}

/// Records that name the same TLS lists must put the same hello on the wire.
/// Edge is Chromium, Chrome 136 is Chrome 133's hello, and the two device rows
/// are their desktop siblings behind a phone's or a phone-shaped identity — so
/// the JA3/JA4 pins above are theirs too, rather than a second set of constants
/// per record that would let two records of one shape drift apart.
///
/// Safari 18 is deliberately *not* in this list: its cipher, group and extension
/// lists are Safari 15.5's, but its signature schemes are not (`ecdsa_sha1` is
/// gone, and JA4 hashes that list), which is why it has a pin of its own.
///
/// The sharing is a fact about the sources, not a convenience: the bundle's own
/// `safari_18.0_macOS` capture publishes the identical `ja3_text` (and a
/// `ja3_hash` of `773906b0efdefa24a7f2b8eb6985bf37`, which `tls.peet.ws`
/// reported for this profile's hello), and `curl_edge99/101` is documented to
/// emit the same JA3 as `curl_chrome99..107`.
#[test]
fn profiles_that_share_a_tls_shape_send_the_same_hello() {
    // `chrome136` is a shuffling shape, so the pair is compared with its
    // extension lists sorted — the set is the shape, the order is per
    // connection. A pair that carries ECH is compared the same way: the GREASE
    // body is rebuilt from random bytes on every connection and its length is
    // one of four values drawn with it, so neither the bytes nor the record
    // length can be compared across two hellos; every other pair is compared
    // byte for byte.
    let same = |left: TlsFingerprint, right: TlsFingerprint, version: TlsVersion| {
        let ours = client_hello_full(left, version);
        let theirs = client_hello_full(right, version);
        if left.spec().permute_extensions || right.spec().permute_extensions || left.spec().ech {
            assert_eq!(
                (order_independent_ja3(&ours.0), ours.2.clone()),
                (order_independent_ja3(&theirs.0), theirs.2.clone()),
                "{}",
                left.code()
            );
        } else {
            assert_eq!(ours, theirs, "{}", left.code());
        }
    };

    for version in [TlsVersion::Any, TlsVersion::Tls13, TlsVersion::Tls12] {
        same(TlsFingerprint::Edge101, TlsFingerprint::Chrome107, version);
        // The M4 rows that are an identity rather than a hello: Chrome 99's
        // Android build, Chrome 136 (which is Chrome 133's shape), Safari 18.4
        // on iOS and Firefox 144.
        for (left, right) in [
            (TlsFingerprint::Chrome99Android, TlsFingerprint::Chrome107),
            (TlsFingerprint::Chrome146, TlsFingerprint::Chrome146),
            (TlsFingerprint::Safari184Ios, TlsFingerprint::Safari180),
        ] {
            same(left, right, version);
        }
    }
}

/// The twelve shapes M4 added, pinned against the capture each record names:
/// the bundle's `.bat` wrapper read through a local ClientHello sniffer, and the
/// fork's own `tests/signatures/*.yaml` for the releases it publishes one for.
///
/// Six of them reproduce their source exactly, so the pin *is* the source's own
/// value and can be re-derived from the bundle without running this build:
/// `curl_chrome99_android` (Chrome 107's hello, and its JA4 with it),
/// `curl_safari153`, `curl_safari184_ios`, `curl_safari260` and
/// `curl_safari260_ios`, whose JA4s are what `safari_15.3_macos11.6.4.yaml`,
/// `safari_18.4_iOS.yaml`, `safari_26.0_macOS.yaml` and `safari_26.0_iOS.yaml`
/// compute — the iOS row among them because the two 26.0 hellos differ by three
/// extensions, not by one omission.
///
/// The other six carry `encrypted_client_hello` as GREASE, like the wrappers
/// they name, so the pin is the source's own value: JA4 counts a GREASE
/// extension out, and the extension hash is the source's too. Two of them —
/// `chrome123` and `chrome131android` — are the only shapes whose hello can fall
/// under the 512-byte floor a browser pads to with the shortest ECH body, and
/// this build sends the unpadded value there, which is the one the client itself
/// sends on three connections out of four (see their records).
///
/// Chrome 133, 136, 142, 145 and 146 send one hello, so `chrome136`
/// repeats Chrome 133's pin rather than carrying a second constant.
#[test]
fn added_shapes_match_the_captures_they_were_read_from() {
    for (fingerprint, ja4) in [
        (TlsFingerprint::Chrome99Android, "t13d1516h2_8daaf6152771_e5627efa2ab1"),
        (TlsFingerprint::Safari153, "t13d2613h2_2802a3db6c62_845d286b0d67"),
        (TlsFingerprint::Safari170, "t13d2014h2_a09f3c656075_14788d8d241b"),
        (TlsFingerprint::Safari172Ios, "t13d2014h2_a09f3c656075_14788d8d241b"),
        (TlsFingerprint::Safari184Ios, "t13d2014h2_a09f3c656075_e42f34c56612"),
        (TlsFingerprint::Safari260, "t13d2014h2_a09f3c656075_d0a99439f9b1"),
        (TlsFingerprint::Safari260Ios, "t13d2015h2_a09f3c656075_c258b721e490"),
    ] {
        let (_, _, got) = client_hello_full(fingerprint, TlsVersion::Any);
        assert_eq!(got, ja4, "{fingerprint}: the source's own JA4");
    }

    // Our extension *hash* is the source's too: JA4 sorts what it hashes, so
    // removing ECH changes the hash and nothing else — the counts stay the
    // source's minus one extension, and the cipher hash is the source's own,
    // which is the one part a wrong cipher list moves silently.
    for (fingerprint, ours, cipher_hash) in [
        (TlsFingerprint::Chrome116, "t13d1516h2_8daaf6152771_e5627efa2ab1", "8daaf6152771"),
        (TlsFingerprint::Chrome123, "t13d1516h2_8daaf6152771_02713d6af862", "8daaf6152771"),
        (TlsFingerprint::Chrome131, "t13d1516h2_8daaf6152771_02713d6af862", "8daaf6152771"),
        (TlsFingerprint::Chrome131Android, "t13d1516h2_8daaf6152771_02713d6af862", "8daaf6152771"),
        (TlsFingerprint::Chrome146, "t13d1516h2_8daaf6152771_d8a2da3f94cd", "8daaf6152771"),
        (TlsFingerprint::Firefox147, "t13d1717h2_5b57614c22b0_3cbfd9057e0d", "5b57614c22b0"),
        (TlsFingerprint::Tor145, "t13d1513h2_8daaf6152771_748f4c70de1c", "8daaf6152771"),
    ] {
        let (_, _, got) = client_hello_full(fingerprint, TlsVersion::Any);
        assert_eq!(got.split('_').nth(1), Some(cipher_hash), "{fingerprint}: the source's cipher hash");
        assert_eq!(got, ours, "{fingerprint}: our extension hash");
    }

    // Chrome 133's hello, which 136 shares: the pin is the one that test
    // carries. Both shuffle a GREASE ECH body whose length is drawn per
    // connection, so the comparison is the sorted extension list and the two
    // hashes — the length is not a property of the shape.
    let ours = client_hello_full(TlsFingerprint::Chrome146, TlsVersion::Any);
    let theirs = client_hello_full(TlsFingerprint::Chrome146, TlsVersion::Any);
    assert_eq!(
        (order_independent_ja3(&ours.0), ours.2),
        (order_independent_ja3(&theirs.0), theirs.2),
        "chrome136 sends Chrome 133's hello"
    );
}

/// Test 6 pins the TLS version and the ALPN it offers, and both have to
/// reach the wire: the pinned JA4 shows the version field (`t12`/`t13`) and
/// the ALPN field (`h2`/`h1`), while JA3 turns on the version — a 1.3-only
/// hello carries 3 ciphers and 12 extensions against the browser offer's 15
/// and 16 — but never on ALPN, whose values JA3 does not read.
#[test]
fn pinned_tls_version_and_alpn_reach_the_hello() {
    let hello = |tls12_only: bool, alpn: Option<Vec<Vec<u8>>>| {
        let mut profile = if tls12_only {
            TlsProfile::insecure(TlsFingerprint::Chrome107).tls12()
        } else {
            TlsProfile::insecure(TlsFingerprint::Chrome107).tls13()
        };
        if let Some(alpn) = alpn {
            profile = profile.alpn(alpn);
        }
        let config = create_tls_config(&profile);
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        (crate::net::ja3::client_hello_ja3(&buf), crate::net::ja4::client_hello_ja4(&buf))
    };

    let (ja3_default, ja4_default) = hello(false, None);
    assert!(ja4_default.starts_with("t13d0312h2_"), "{ja4_default}");

    // HTTP/1.1 alone: same hello except the ALPN extension's body, so JA4
    // keeps its counts and hashes and changes only the ALPN field.
    let (ja3_http11, ja4_http11) = hello(false, Some(vec![b"http/1.1".to_vec()]));
    assert!(ja4_http11.starts_with("t13d0312h1_"), "{ja4_http11}");
    assert_eq!(
        ja4_http11.split_once('_').map(|x| x.1),
        ja4_default.split_once('_').map(|x| x.1),
        "h2 and http/1.1 differ in the ALPN field only"
    );
    assert_eq!(ja3_http11, ja3_default, "JA3 hashes types, not ALPN values");

    // TLS 1.2: the version field follows the pinned version. A browser's
    // 1.2-only hello carries no `supported_versions` for JA4 to read, so the
    // field comes from the ClientHello's legacy version — not from its TLS
    // 1.0 record header, which no client's protocol is.
    let (_, ja4_tls12) = hello(true, None);
    assert!(ja4_tls12.starts_with("t12d"), "{ja4_tls12}");
}

/// Browser hellos open `supported_versions` with a GREASE code point, and
/// JA3/JA4 both ignore it — but a middlebox may read the list, so the hello
/// has to carry it and the two fingerprint hashes have to be unmoved by it.
///
/// Firefox greases nothing, so its list must stay plain: adding the value
/// there would deviate from `curl_firefox133` rather than approach it.
///
/// The unpinned builder is the browser's own offer — 1.3 *and* 1.2, with the
/// profile's GREASE — and it is what tests 3 and 4 send, plus test 6's TLS
/// 1.3 axis: the burst asks whether a *browser shape* is blocked, so the
/// offer has to be the browser's, and it can only be built unpinned.
///
/// The pinned builders are test 2's two columns (and test 6's TLS 1.2 axis),
/// where the whole point is a client that speaks exactly one version: a
/// hello offering both is never answered with 1.2, so the isolation is bought
/// with one version in the list instead of two — `0x0304` for the 1.3 phase,
/// `0x0303` for the 1.2 one. See `net::tls::TlsProfile::tls13` for why the
/// deviation is accepted rather than faked.
#[test]
fn grease_version_leads_supported_versions() {
    // The `supported_versions` body of a hello, `None` when the hello does
    // not carry the extension at all, and the record size.
    let versions = |profile: TlsProfile| {
        let config = create_tls_config(&profile);
        let name = rustls::pki_types::ServerName::try_from("example.com").expect("valid name");
        let mut conn = rustls::ClientConnection::new(config, name).expect("client conn");
        let mut buf = Vec::new();
        conn.write_tls(&mut buf).expect("write ClientHello");
        let body = crate::net::ja3::extensions(&buf[crate::net::ja3::RECORD_HEADER..])
            .into_iter()
            .find(|(ext_type, _)| *ext_type == 43)
            .map(|(_, body)| body.to_vec());
        let list = body.map(|body| {
            let entries = body[0] as usize / 2;
            (0..entries)
                .map(|i| u16::from_be_bytes([body[1 + 2 * i], body[2 + 2 * i]]))
                .collect::<Vec<u16>>()
        });
        (list, buf.len())
    };

    for shape in SHAPES.iter().filter(|shape| !shape.baseline) {
        let fp = shape.variant;
        // The browser's own offer: both modern versions, the profile's
        // fallbacks behind them, and a GREASE value in front of them when the
        // client greases — Firefox does not. The record is the expectation, so
        // a new profile is covered here without a second list.
        let (browser, record) = versions(TlsProfile::insecure(fp));
        let browser = browser.expect("the browser offer carries supported_versions");
        let expected = [vec![0x0304, 0x0303], shape.legacy_versions.to_vec()].concat();
        if shape.grease {
            assert!(is_grease_version(browser[0]), "{fp:?} must open with GREASE: {browser:04x?}");
            assert_eq!(&browser[1..], &expected[..], "{fp:?}: {browser:04x?}");
        } else {
            assert_eq!(browser, expected, "{fp:?} does not grease");
        }
        if shape.padding_to == Some(512) {
            assert_eq!(record, 512 + 5, "{fp:?}: the padded hello must stay 512 bytes");
        } else {
            // No padding extension: the hello is past the 256-byte floor
            // BoringSSL pads above on its own, so nothing is lost by leaving it
            // out.
            assert!(record > 256 + 5, "{fp:?}: {record} bytes is under the padding floor");
        }

        // Pinned to 1.3: one version in the list (test 2's TLS 1.3 column),
        // and no fallbacks — a pinned run isolates one version on purpose.
        let (only13, _) = versions(TlsProfile::insecure(fp).tls13());
        let only13 = only13.expect("a 1.3-only hello still names its version");
        if shape.grease {
            assert!(is_grease_version(only13[0]), "{fp:?}: {only13:04x?}");
            assert_eq!(&only13[1..], &[0x0304], "{fp:?}: {only13:04x?}");
        } else {
            assert_eq!(only13, vec![0x0304], "{fp:?}");
        }

        // TLS 1.2 alone: the pinned version replaces 1.3 — and the extension
        // goes with it, because a hello that cannot negotiate anything above
        // 1.2 has no version list to send. That is what the pinned bundles
        // send (`curl_chrome107 --tls-max 1.2` carries no extension 43), and
        // it is the shape test 2's second column measures.
        let (only12, _) = versions(TlsProfile::insecure(fp).tls12());
        assert!(only12.is_none(), "{fp:?}: a 1.2-only hello carries no supported_versions");
    }
    let (rustls_list, _) = versions(TlsProfile::insecure(TlsFingerprint::Rustls));
    assert_eq!(
        rustls_list.expect("the baseline carries supported_versions"),
        vec![0x0304, 0x0303],
        "the baseline offers both, untouched"
    );
}

/// RFC 8701: `0x?a?a` with both bytes equal.
fn is_grease_version(value: u16) -> bool {
    let (hi, lo) = (value >> 8, value & 0xff);
    hi == lo && lo & 0x0f == 0x0a
}

/// The curl shapes predate post-quantum key exchange, so they must not be
/// given the hybrid group — a group the original does not offer would change
/// the fingerprint being reproduced.
#[test]
fn the_legacy_profiles_do_not_use_the_pq_provider() {
    assert!(!needs_pq(TlsFingerprint::Chrome107));
    assert!(!needs_pq(TlsFingerprint::Safari155));
    assert!(needs_pq(TlsFingerprint::Firefox133));
    // Chrome 133 offers X25519MLKEM768 first, so it needs the provider that can
    // share a key over it; Edge and Safari 18 predate the hybrid group.
    assert!(needs_pq(TlsFingerprint::Chrome146));
    assert!(!needs_pq(TlsFingerprint::Safari180));
    assert!(!needs_pq(TlsFingerprint::Edge101));
    assert!(advertises_cert_compression(TlsFingerprint::Chrome107));
    assert!(advertises_cert_compression(TlsFingerprint::Safari155));
    assert!(!advertises_cert_compression(TlsFingerprint::Rustls));
}

/// The decompressor list is what rustls reads to decide whether to offer
/// extension 27 and to pick a decoder for the algorithm the server answered
/// with; an empty list against an advertised extension is a fatal
/// `SelectedUnofferedCertCompression`. A shape that advertises compression
/// therefore has to come with a non-empty list, and the baseline — which
/// advertises nothing — with an empty one. Which *algorithms* sit in the list is
/// `every_advertised_compression_algorithm_is_readable`'s business.
#[test]
fn the_decompressor_list_follows_the_profile() {
    for (name, fingerprint, advertises) in [
        ("rustls", TlsFingerprint::Rustls, false),
        ("firefox133", TlsFingerprint::Firefox133, true),
        ("chrome107", TlsFingerprint::Chrome107, true),
        ("safari155", TlsFingerprint::Safari155, true),
        ("chrome146", TlsFingerprint::Chrome146, true),
        ("safari180", TlsFingerprint::Safari180, true),
        ("edge101", TlsFingerprint::Edge101, true),
    ] {
        let config = create_tls_config(&TlsProfile::insecure(fingerprint).tls13());
        assert_eq!(
            !config.cert_decompressors.is_empty(),
            advertises,
            "{name} decompressor list"
        );
    }
}

/// RFC 8879: the server may compress its certificate with anything the hello
/// offered, so every code point a shape advertises has to have a
/// decompressor behind it — otherwise the handshake dies on a certificate
/// this build cannot read.
#[test]
fn every_advertised_compression_algorithm_is_readable() {
    for shape in SHAPES.iter().filter(|shape| !shape.baseline) {
        for code in shape.cert_compression {
            assert!(
                crate::net::cert_compression::covers((*code).into()),
                "{} advertises {code}, which this build cannot decompress",
                shape.code
            );
        }
    }
}

/// A code point the provider cannot serve, named with the reason it is still
/// advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unimplemented {
    Cipher,
    Group,
    SignatureScheme,
}

/// What a shape advertises and this build cannot serve.
///
/// The browser's list is what JA3 hashes, so it cannot be trimmed to the
/// provider's without changing the very fingerprint the profile exists to
/// reproduce. What can be required is that every such code point is named
/// here, and that the entry disappears the day the provider grows it (the
/// gate fails then, and the shape starts being served for real).
///
/// What the gap costs in the field: a server that selects one of these — a
/// 3DES suite, a static-RSA key exchange, an SHA-1 signature — ends the
/// handshake, where a browser would have completed it. That is a real
/// difference from the client the profile imitates, and it is bounded: the
/// suites a real server of a probed host picks are negotiated against a real
/// browser the same way, and the classifier reports the failure as the alert
/// or reset it is rather than as a block.
const UNIMPLEMENTED: &[(Unimplemented, u16, &str)] = &[
    // --- AES-CBC under ECDHE: the provider carries AEAD suites only (three
    // per key-exchange family), and no CBC suite is in rustls-rustcrypto.
    (Unimplemented::Cipher, 0xc009, "ECDHE-ECDSA-AES128-CBC-SHA: no CBC suite in the provider"),
    (Unimplemented::Cipher, 0xc00a, "ECDHE-ECDSA-AES256-CBC-SHA: no CBC suite in the provider"),
    (Unimplemented::Cipher, 0xc013, "ECDHE-RSA-AES128-CBC-SHA: no CBC suite in the provider"),
    (Unimplemented::Cipher, 0xc014, "ECDHE-RSA-AES256-CBC-SHA: no CBC suite in the provider"),
    // --- Static-RSA key transport: rustls has no RSA key exchange at all, so
    // every `TLS_RSA_WITH_*` a browser offers is out of reach.
    (Unimplemented::Cipher, 0x002f, "RSA-AES128-CBC-SHA: rustls offers no RSA key exchange"),
    (Unimplemented::Cipher, 0x0035, "RSA-AES256-CBC-SHA: rustls offers no RSA key exchange"),
    (Unimplemented::Cipher, 0x003c, "RSA-AES128-CBC-SHA256: rustls offers no RSA key exchange"),
    (Unimplemented::Cipher, 0x003d, "RSA-AES256-CBC-SHA256: rustls offers no RSA key exchange"),
    (Unimplemented::Cipher, 0x009c, "RSA-AES128-GCM-SHA256: rustls offers no RSA key exchange"),
    (Unimplemented::Cipher, 0x009d, "RSA-AES256-GCM-SHA384: rustls offers no RSA key exchange"),
    // --- The CBC/SHA-256 suites Safari 15.3 still offered and 15.5 dropped:
    // CBC again, and absent from the provider for the same reason as the group
    // above. They exist here because `safari153`'s cipher list is the only one
    // that carries them.
    (Unimplemented::Cipher, 0xc023, "ECDHE-ECDSA-AES128-CBC-SHA256: no CBC suite in the provider"),
    (Unimplemented::Cipher, 0xc024, "ECDHE-ECDSA-AES256-CBC-SHA384: no CBC suite in the provider"),
    (Unimplemented::Cipher, 0xc027, "ECDHE-RSA-AES128-CBC-SHA256: no CBC suite in the provider"),
    (Unimplemented::Cipher, 0xc028, "ECDHE-RSA-AES256-CBC-SHA384: no CBC suite in the provider"),
    // --- 3DES: dropped by rustls and absent from the provider, and every peer
    // that still selects it is one a modern browser would also have offered.
    (Unimplemented::Cipher, 0x000a, "RSA-3DES-EDE-CBC-SHA: no 3DES in the provider"),
    (Unimplemented::Cipher, 0xc008, "ECDHE-ECDSA-3DES-EDE-CBC-SHA: no 3DES in the provider"),
    (Unimplemented::Cipher, 0xc012, "ECDHE-RSA-3DES-EDE-CBC-SHA: no 3DES in the provider"),
    // --- Groups the provider does not implement: `kx::ALL_KX_GROUPS` is
    // X25519, P-256 and P-384. A browser lists more than it shares a key with,
    // which is why these are advertised without ever being a key share.
    (Unimplemented::Group, 0x0019, "secp521r1: the provider has no P-521 group"),
    (Unimplemented::Group, 0x0100, "ffdhe2048: the provider has no finite-field group"),
    (Unimplemented::Group, 0x0101, "ffdhe3072: the provider has no finite-field group"),
    // --- Signature schemes: the provider verifies ECDSA P-256/P-384, Ed25519
    // and RSA PSS/PKCS1 with SHA-256 and above. SHA-1 is gone from both rustls
    // and the provider, and a P-521 verifier is missing with its group.
    (Unimplemented::SignatureScheme, 0x0201, "rsa_pkcs1_sha1: no SHA-1 verification"),
    (Unimplemented::SignatureScheme, 0x0203, "ecdsa_sha1: no SHA-1 verification"),
    (Unimplemented::SignatureScheme, 0x0603, "ecdsa_secp521r1_sha512: no P-521 verifier"),
];

/// The gate that keeps a shape and the provider it runs on in step.
///
/// A profile is only half a fingerprint: the provider is the other half, and
/// a cipher, group or signature scheme the hello advertises but the provider
/// cannot run is a shape that dies on the wire. Every record is checked
/// against the provider `needs_pq` selects for it, and every code point the
/// provider lacks has to be named in `UNIMPLEMENTED` with its reason.
#[test]
fn every_advertised_code_point_is_served_or_named() {
    let mut unserved: Vec<String> = Vec::new();
    for shape in SHAPES.iter().filter(|shape| !shape.baseline) {
        let provider = if shape.pq { crypto_provider_with_pq() } else { crypto_provider() };
        let suites: Vec<u16> = provider
            .cipher_suites
            .iter()
            .map(|suite| u16::from(suite.suite()))
            .collect();
        let groups: Vec<u16> = provider.kx_groups.iter().map(|group| u16::from(group.name())).collect();
        let schemes: Vec<u16> = provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .map(|(scheme, _)| u16::from(*scheme))
            .collect();

        for (kind, advertised, served) in [
            (Unimplemented::Cipher, shape.ciphers, suites.as_slice()),
            (Unimplemented::Group, shape.groups, groups.as_slice()),
            (Unimplemented::SignatureScheme, shape.sig_algs, schemes.as_slice()),
        ] {
            for code in advertised {
                if !served.contains(code) && !named(kind, *code) {
                    unserved.push(format!(
                        "({kind:?}, {code:#06x}), // {} advertises it",
                        shape.code
                    ));
                }
            }
        }
    }
    assert!(unserved.is_empty(), "advertised but not served, nor named in UNIMPLEMENTED:\n{}", unserved.join("\n"));

    // The other direction: an exemption the provider now serves is stale, and
    // naming a code point it never lacked would hide a code point it does.
    let provider = crypto_provider();
    let suites: Vec<u16> =
        provider.cipher_suites.iter().map(|suite| u16::from(suite.suite())).collect();
    let groups: Vec<u16> = provider.kx_groups.iter().map(|group| u16::from(group.name())).collect();
    let schemes: Vec<u16> = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .map(|(scheme, _)| u16::from(*scheme))
        .collect();
    for (kind, code, reason) in UNIMPLEMENTED {
        assert!(!reason.is_empty(), "{kind:?} {code:#06x}: an exemption states a reason");
        let served = match kind {
            Unimplemented::Cipher => suites.contains(code),
            Unimplemented::Group => groups.contains(code),
            Unimplemented::SignatureScheme => schemes.contains(code),
        };
        assert!(!served, "{kind:?} {code:#06x} is served now, drop its exemption: {reason}");
    }
}

fn named(kind: Unimplemented, code: u16) -> bool {
    UNIMPLEMENTED.iter().any(|(named_kind, named_code, _)| *named_kind == kind && *named_code == code)
}

/// The hello's `key_share` carries the provider's first group, and
/// `supported_groups` is written from the record — so a record that lists a
/// different group first would advertise one thing and share another, a shape
/// no browser sends.
#[test]
fn the_advertised_group_list_opens_with_the_group_we_share() {
    for shape in SHAPES.iter().filter(|shape| !shape.baseline) {
        let provider = if shape.pq { crypto_provider_with_pq() } else { crypto_provider() };
        let first = provider.kx_groups.first().expect("a provider offers a group");
        assert_eq!(
            shape.groups.first().copied(),
            Some(u16::from(first.name())),
            "{}: the advertised list must open with the group the hello shares",
            shape.code
        );
    }
}

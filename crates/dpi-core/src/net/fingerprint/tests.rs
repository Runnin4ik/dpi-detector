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
const SAFARI_155_JA4: &str = "t13d2014h2_a09f3c656075_2a6581477f52";
const FIREFOX_133_JA4_LESS_ECH: &str = "t13d1715h2_5b57614c22b0_8fb63dbc839a";

/// The HTTP identity and the ClientHello of a profile have to describe the
/// same client: a `chrome107` hello behind a `Chrome/133` UA is a mismatch a
/// header-matching middlebox reads in a single packet.
#[test]
fn http_identity_names_the_version_the_hello_imitates() {
    for (fingerprint, marker) in [
        (TlsFingerprint::Chrome, "Chrome/107.0.0.0"),
        (TlsFingerprint::Firefox, "Firefox/133.0"),
        (TlsFingerprint::Safari, "Version/15.5"),
        (TlsFingerprint::Chrome133, "Chrome/133.0.0.0"),
        (TlsFingerprint::Safari18, "Version/18.0"),
        (TlsFingerprint::Edge, "Edg/101.0.1210.47"),
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
        if let Some((_, value)) = identity.headers.iter().find(|(name, _)| *name == "sec-ch-ua") {
            let version = ua.split("Chrome/").nth(1).and_then(|v| v.split('.').next()).expect("UA version");
            assert!(value.contains(&format!("v=\"{version}\"")), "{}: {value}", fingerprint.code());
        }
        // The HTTP identity is the impersonated client's, encoding included:
        // what the byte-counting probes do with it is their own business.
        let (_, encoding) = identity
            .headers
            .iter()
            .find(|(name, _)| *name == "accept-encoding")
            .expect("every identity states its encoding");
        let expected = match fingerprint {
            TlsFingerprint::Firefox | TlsFingerprint::Chrome133 => "gzip, deflate, br, zstd",
            TlsFingerprint::Chrome
            | TlsFingerprint::Safari
            | TlsFingerprint::Safari18
            | TlsFingerprint::Edge => "gzip, deflate, br",
            TlsFingerprint::Rustls => "identity",
        };
        assert_eq!(*encoding, expected, "{}: {}", fingerprint.code(), *encoding);
    }
    let baseline = http_identity(TlsFingerprint::Rustls);
    assert!(baseline.user_agent.is_none(), "the baseline profile impersonates nobody");
    assert_eq!(baseline.headers, [("accept-encoding", "identity")]);
}

/// The h2 preface is what the pinned wrapper configures through
/// `--http2-settings` / `--http2-window-update`; the increment h2 puts on the
/// wire is the connection window minus the protocol's 65535 default.
#[test]
fn h2_preface_matches_the_wrapper_it_is_pinned_to() {
    let chrome = h2_fingerprint(TlsFingerprint::Chrome).expect("chrome tunes h2");
    assert_eq!(chrome.header_table_size, Some(65_536));
    assert_eq!(chrome.max_concurrent_streams, Some(1000));
    assert_eq!(chrome.initial_window_size, 6_291_456);
    assert_eq!(chrome.max_frame_size, None, "Chrome advertises no MAX_FRAME_SIZE");
    assert_eq!(chrome.connection_window - 65_535, 15_663_105);

    let firefox = h2_fingerprint(TlsFingerprint::Firefox).expect("firefox tunes h2");
    assert_eq!(firefox.header_table_size, Some(65_536));
    assert_eq!(firefox.initial_window_size, 131_072);
    assert_eq!(firefox.max_frame_size, Some(16_384));
    assert_eq!(firefox.connection_window - 65_535, 12_517_377);

    let safari = h2_fingerprint(TlsFingerprint::Safari).expect("safari tunes h2");
    assert_eq!(safari.header_table_size, None, "Safari sends no HEADER_TABLE_SIZE");
    assert_eq!(safari.max_concurrent_streams, Some(100));
    assert_eq!(safari.initial_window_size, 4_194_304);
    assert_eq!(safari.connection_window - 65_535, 10_485_760);

    assert!(h2_fingerprint(TlsFingerprint::Rustls).is_none(), "the baseline keeps hyper's defaults");
}

/// The request shape is measured, not guessed: each triple is what the
/// bundle named in its `.bat` and what it put on the wire (decrypted with the
/// bundle's `SSLKEYLOGFILE`). Chrome 107 sends no
/// `--http2-pseudo-headers-order`, Firefox 133 `"mpas"` and Safari 155
/// `"mspa"`; all three take the PRIORITY flag on the request's `HEADERS`.
#[test]
fn h2_request_shape_matches_the_wrapper_it_is_pinned_to() {
    use ::h2::client::PseudoOrder::*;

    let chrome = h2_fingerprint(TlsFingerprint::Chrome).expect("chrome tunes h2");
    assert_eq!(chrome.pseudo_order, MethodAuthoritySchemePath);
    assert_eq!(chrome.priority, Some((256, true)));

    let firefox = h2_fingerprint(TlsFingerprint::Firefox).expect("firefox tunes h2");
    assert_eq!(firefox.pseudo_order, MethodPathAuthorityScheme);
    assert_eq!(firefox.priority, Some((42, false)));

    let safari = h2_fingerprint(TlsFingerprint::Safari).expect("safari tunes h2");
    assert_eq!(safari.pseudo_order, MethodSchemePathAuthority);
    assert_eq!(safari.priority, Some((255, false)));
}

/// Which settings a preface carries is part of the shape: Chrome sends
/// `SETTINGS_MAX_HEADER_LIST_SIZE = 262144` and `SETTINGS_ENABLE_PUSH = 0`,
/// Firefox the push setting but no header-list size, Safari neither.
#[test]
fn h2_preface_settings_match_the_wrapper_they_are_pinned_to() {
    let chrome = h2_fingerprint(TlsFingerprint::Chrome).expect("chrome tunes h2");
    assert_eq!(chrome.max_header_list_size, Some(262_144));
    assert_eq!(chrome.enable_push, Some(false));

    let firefox = h2_fingerprint(TlsFingerprint::Firefox).expect("firefox tunes h2");
    assert_eq!(firefox.max_header_list_size, None, "Firefox sends no header-list size");
    assert_eq!(firefox.enable_push, Some(false));

    let safari = h2_fingerprint(TlsFingerprint::Safari).expect("safari tunes h2");
    assert_eq!(safari.max_header_list_size, None, "Safari sends no header-list size");
    assert_eq!(safari.enable_push, None, "Safari sends no push setting");
    assert_eq!(safari.settings_order, [4, 3], "Safari lists the window before the stream cap");

    // Chrome 133 dropped MAX_CONCURRENT_STREAMS; Edge leaves out ENABLE_PUSH;
    // Safari 18 sends neither a header-table size nor a header-list size, and
    // lists its settings in ascending order.
    let chrome133 = h2_fingerprint(TlsFingerprint::Chrome133).expect("chrome133 tunes h2");
    assert_eq!(chrome133.max_concurrent_streams, None, "Chrome 133 sends no stream cap");
    assert_eq!(chrome133.connection_window - 65_535, 15_663_105);

    let edge = h2_fingerprint(TlsFingerprint::Edge).expect("edge tunes h2");
    assert_eq!(edge.enable_push, None, "Edge sends no push setting");
    assert_eq!(edge.max_concurrent_streams, Some(1000));
    assert_eq!(edge.connection_window - 65_535, 15_663_105);

    let safari18 = h2_fingerprint(TlsFingerprint::Safari18).expect("safari18 tunes h2");
    assert_eq!(safari18.header_table_size, None);
    assert_eq!(safari18.max_concurrent_streams, Some(100));
    assert_eq!(safari18.initial_window_size, 2_097_152);
    assert_eq!(safari18.enable_push, Some(false));
    assert_eq!(safari18.settings_order, &[] as &[u16], "Safari 18 lists 2, 3 and 4 ascending");
    assert_eq!(safari18.connection_window - 65_535, 10_420_225);
}

/// h2 sorts the settings it sends by id; Safari's preface does not, so the
/// order is part of the shape. An empty order means the sorted default the
/// other profiles and the baseline keep.
#[test]
fn h2_settings_go_out_in_the_order_the_wrapper_sends_them() {
    for (fingerprint, expected) in [
        (TlsFingerprint::Chrome, &[][..]),
        (TlsFingerprint::Firefox, &[][..]),
        (TlsFingerprint::Safari, &[4, 3][..]),
    ] {
        let h2 = h2_fingerprint(fingerprint).expect("browser profiles tune h2");
        assert_eq!(h2.settings_order, expected, "{}", fingerprint.code());
    }
}

/// The version-bearing label is display only: it must not collide with a
/// parser name, and every profile whose shape is a pinned client version has
/// to say which one.
#[test]
fn display_labels_name_the_pinned_version() {
    assert_eq!(TlsFingerprint::Firefox.display_label(), "FIREFOX 133");
    assert_eq!(TlsFingerprint::Chrome.display_label(), "CHROME 107");
    assert_eq!(TlsFingerprint::Safari.display_label(), "SAFARI 155");
    assert_eq!(TlsFingerprint::Rustls.display_label(), "RUSTLS");
    assert_eq!(TlsFingerprint::Chrome133.display_label(), "CHROME 133");
    assert_eq!(TlsFingerprint::Safari18.display_label(), "SAFARI 18");
    assert_eq!(TlsFingerprint::Edge.display_label(), "EDGE 101");
    for fp in TlsFingerprint::ALL {
        assert!(fp.display_label().starts_with(fp.token()), "{fp:?}");
        assert!(fp.display_label().is_ascii(), "{fp:?}");
    }
}

#[test]
fn fingerprint_tokens_are_stable() {
    assert_eq!(TlsFingerprint::Rustls.token(), "RUSTLS");
    assert_eq!(TlsFingerprint::Firefox.token(), "FIREFOX");
    assert_eq!(TlsFingerprint::Rustls.code(), "rustls");
    assert_eq!(TlsFingerprint::Firefox.code(), "firefox");
    assert_eq!(TlsFingerprint::default(), TlsFingerprint::Rustls);
}

#[test]
fn fingerprint_parses_known_values_and_rejects_others() {
    assert_eq!(TlsFingerprint::parse("rustls"), Some(TlsFingerprint::Rustls));
    assert_eq!(TlsFingerprint::parse("FIREFOX"), Some(TlsFingerprint::Firefox));
    assert_eq!(TlsFingerprint::parse(" firefox "), Some(TlsFingerprint::Firefox));
    // The old name is gone rather than aliased: a config or a script that
    // still says `custom` is told it is unknown instead of silently measuring
    // the same profile under a name the tool no longer prints.
    assert_eq!(TlsFingerprint::parse("custom"), None);
    assert_eq!(TlsFingerprint::parse("chrome"), Some(TlsFingerprint::Chrome));
    assert_eq!(TlsFingerprint::parse("safari"), Some(TlsFingerprint::Safari));
    // The names the fingerprint-blocking report uses are accepted when the
    // shape is the one a profile here reproduces, and rejected otherwise.
    assert_eq!(
        TlsFingerprint::parse("curl_chrome107"),
        Some(TlsFingerprint::Chrome)
    );
    // Edge is Chromium but not Chrome: the bundle's own Edge names map to the
    // Edge record, whose header set is what tells the two clients apart.
    assert_eq!(
        TlsFingerprint::parse("curl_edge101"),
        Some(TlsFingerprint::Edge)
    );
    assert_eq!(TlsFingerprint::parse("edge"), Some(TlsFingerprint::Edge));
    assert_eq!(TlsFingerprint::parse("chrome133"), Some(TlsFingerprint::Chrome133));
    assert_eq!(TlsFingerprint::parse("curl_chrome133a"), Some(TlsFingerprint::Chrome133));
    assert_eq!(TlsFingerprint::parse("safari18"), Some(TlsFingerprint::Safari18));
    assert_eq!(TlsFingerprint::parse("curl_safari180"), Some(TlsFingerprint::Safari18));
    // Chrome 131 is the same hello with ALPS at the *old* code point, and
    // Safari 18.4 an extra h2 setting: neither is a shape these records send.
    assert_eq!(TlsFingerprint::parse("curl_chrome131"), None);
    assert_eq!(TlsFingerprint::parse("safari184"), Some(TlsFingerprint::Safari));
    assert_eq!(
        TlsFingerprint::parse("curl_safari155"),
        Some(TlsFingerprint::Safari)
    );
    assert_eq!(
        TlsFingerprint::parse("curl_safari184_ios"),
        Some(TlsFingerprint::Safari)
    );
    assert_eq!(
        TlsFingerprint::parse("curl_firefox133"),
        Some(TlsFingerprint::Firefox)
    );
    // Shapes no profile sends: shuffled extension order, post-quantum
    // group, signed certificate timestamps.
    assert_eq!(TlsFingerprint::parse("curl_chrome116"), None);
    assert_eq!(TlsFingerprint::parse("curl_safari260"), None);
    assert_eq!(TlsFingerprint::parse("curl_firefox147"), None);
    assert_eq!(TlsFingerprint::parse("curl_firefox144"), None);
    assert_eq!(TlsFingerprint::parse(""), None);
}

/// Test 6 takes a *list* of profiles; `all` and the curl aliases must work,
/// and an unrecognised token must be reported rather than silently swapped
/// for a different set.
#[test]
fn fingerprint_list_parsing() {
    assert_eq!(TlsFingerprint::parse_list("all").0, TlsFingerprint::ALL.to_vec());
    assert_eq!(TlsFingerprint::parse_list("").0, TlsFingerprint::ALL.to_vec());
    assert_eq!(
        TlsFingerprint::parse_list("chrome, safari").0,
        vec![TlsFingerprint::Chrome, TlsFingerprint::Safari]
    );
    assert_eq!(TlsFingerprint::parse_list("curl_chrome107").0, vec![TlsFingerprint::Chrome]);
    // Duplicates collapse, order is kept.
    assert_eq!(
        TlsFingerprint::parse_list("safari safari rustls").0,
        vec![TlsFingerprint::Safari, TlsFingerprint::Rustls]
    );
    // Mixed: the known half runs, the rest is reported.
    let (known, unknown) = TlsFingerprint::parse_list("firefox,bogus");
    assert_eq!(known, vec![TlsFingerprint::Firefox]);
    assert_eq!(unknown, vec!["bogus".to_string()]);
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

/// A name may belong to one shape only, and names are matched lowercase: a
/// second record claiming `chrome` would make the parser's answer depend on
/// table order.
#[test]
fn profile_names_are_unique_and_lowercase() {
    let mut seen: Vec<&str> = Vec::new();
    for shape in SHAPES {
        assert_eq!(shape.code, shape.code.to_ascii_lowercase(), "{}: code is lowercase", shape.code);
        assert!(!shape.source.is_empty(), "{}: a record states where it came from", shape.code);
        // The canonical name has to be one of the accepted ones: the parsers
        // and the config validator both go through this list.
        assert!(shape.aliases.contains(&shape.code), "{}: the code is not an alias", shape.code);
        for name in shape.aliases {
            assert_eq!(*name, name.to_ascii_lowercase(), "{}: alias {name} is lowercase", shape.code);
            assert!(!seen.contains(name), "{name} is claimed twice");
            seen.push(name);
        }
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
            assert_eq!(
                shape.baseline,
                shape.cert_compression.is_empty(),
                "{}: only the baseline sends no compress_certificate",
                shape.code
            );
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
    let profile = hello_profile(TlsFingerprint::Firefox).expect("firefox installs a profile");

    assert_eq!(profile.cipher_suites.as_ref().map(|c| c.len()), Some(17));
    assert_eq!(profile.groups.as_ref().and_then(|g| g.first()), Some(&4588));

    let order = profile.extension_order.as_ref().expect("extension order");
    assert_eq!(order.len(), 15);
    assert_eq!(order.first(), Some(&EXT_SERVER_NAME));
    assert_eq!(order.last(), Some(&EXT_COMPRESS_CERTIFICATE));
    assert!(order.contains(&EXT_RENEGOTIATION_INFO));
    assert!(order.contains(&EXT_DELEGATED_CREDENTIALS));
    assert!(order.contains(&EXT_RECORD_SIZE_LIMIT));
    assert!(order.contains(&EXT_SESSION_TICKET));
    assert!(order.contains(&EXT_PSK_KEY_EXCHANGE_MODES));
    assert!(!order.contains(&EXT_SCT), "Firefox 133 sends no SCT");
    // 65037 is the one extension curl_firefox133 has and this profile does
    // not: every hand-built GREASE ECH body was rejected by the ECH-aware
    // servers (see the record in `shapes`).
    assert_eq!(order.iter().filter(|ext| **ext == 65037).count(), 0);

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
    // `curl_firefox133` sends `...,28-27-65037` — the profile stops at 27,
    // because a GREASE ECH body this build writes is rejected by every
    // ECH-aware server (see the Firefox record in `shapes`).
    const FIREFOX_133: &str = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-\
         49161-49171-49172-156-157-47-53,\
         0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,4588-29-23-24-25-256-257,0";

    const CHROME_107_TLS13: &str =
        "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-17513-21,29-23-24,";
    const SAFARI_155_TLS13: &str =
        "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-21,29-23-24-25,";
    const FIREFOX_133_TLS13: &str =
        "771,4865-4867-4866,0-23-65281-10-16-5-34-51-43-13-45-28-27,4588-29-23-24-25-256-257,";

    const CHROME_107_TLS12: &str = "771,49195-49199-49196-49200-52393-52392-49171-49172-\
         156-157-47-53,0-23-65281-10-11-35-16-5-13-18,29-23-24,0";
    const SAFARI_155_TLS12: &str = "771,49196-49195-52393-49200-49199-52392-49162-49161-\
         49172-49171-157-156-53-47-49160-49170-10,\
         0-23-65281-10-11-16-5-13-18,29-23-24-25,0";
    const FIREFOX_133_TLS12: &str = "771,49195-49199-52393-52392-49196-49200-49162-49161-\
         49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-13-28,\
         4588-29-23-24-25-256-257,0";

    for (version, profiles) in [
        (
            TlsVersion::Any,
            [
                (TlsFingerprint::Chrome, CHROME_107),
                (TlsFingerprint::Safari, SAFARI_155),
                (TlsFingerprint::Firefox, FIREFOX_133),
            ],
        ),
        (
            TlsVersion::Tls13,
            [
                (TlsFingerprint::Chrome, CHROME_107_TLS13),
                (TlsFingerprint::Safari, SAFARI_155_TLS13),
                (TlsFingerprint::Firefox, FIREFOX_133_TLS13),
            ],
        ),
        (
            TlsVersion::Tls12,
            [
                (TlsFingerprint::Chrome, CHROME_107_TLS12),
                (TlsFingerprint::Safari, SAFARI_155_TLS12),
                (TlsFingerprint::Firefox, FIREFOX_133_TLS12),
            ],
        ),
    ] {
        for (fingerprint, expected) in profiles {
            assert_eq!(
                client_hello_of(fingerprint, version).0,
                expected,
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
    for fingerprint in [TlsFingerprint::Chrome, TlsFingerprint::Safari] {
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
/// Firefox's differs in the extension count and hash only, and only because
/// of the omitted `encrypted_client_hello` (see its record); the cipher hash
/// is the bundle's.
#[test]
fn bundle_versions_match_their_ja4() {
    // The pinned 1.3 hashes are the bundle's: those hellos are byte-identical
    // to `curl_chrome107`/`curl_safari155`/`curl_firefox133` pinned with
    // `--tlsv1.3 --tls-max 1.3`. The 1.2 hashes are ours alone — the pinned
    // configuration is the one where rustls cannot send the bundle's
    // `compress_certificate`, so the extension count and hash differ by that
    // one extension.
    const CHROME_107_TLS13: &str = "t13d0312h2_55b375c5d22e_89e42599e699";
    const SAFARI_155_TLS13: &str = "t13d0311h2_55b375c5d22e_3727ed65331a";
    const FIREFOX_133_TLS13: &str = "t13d0313h2_55b375c5d22e_1dac57d28bce";
    const CHROME_107_TLS12: &str = "t12d1210h2_d34a8e72043a_fae48490d0f6";
    const SAFARI_155_TLS12: &str = "t12d1709h2_ba5946811be1_8c31861e0dbb";
    const FIREFOX_133_TLS12: &str = "t12d1411h2_c866b44c5a26_242292a3764d";

    for (version, chrome, safari, firefox) in [
        (
            TlsVersion::Any,
            CHROME_107_JA4,
            SAFARI_155_JA4,
            FIREFOX_133_JA4_LESS_ECH,
        ),
        (TlsVersion::Tls13, CHROME_107_TLS13, SAFARI_155_TLS13, FIREFOX_133_TLS13),
        (TlsVersion::Tls12, CHROME_107_TLS12, SAFARI_155_TLS12, FIREFOX_133_TLS12),
    ] {
        let (_, _, got) = client_hello_full(TlsFingerprint::Chrome, version);
        assert_eq!(got, chrome, "chrome ({version:?})");
        let (_, _, got) = client_hello_full(TlsFingerprint::Safari, version);
        assert_eq!(got, safari, "safari ({version:?})");
        let (_, _, got) = client_hello_full(TlsFingerprint::Firefox, version);
        assert_eq!(got, firefox, "firefox ({version:?})");
    }
}

/// Chrome 133, as uTLS `HelloChrome_133` (v1.8.2, unchanged on master) defines
/// it and `curl_chrome133a` sends it. Both sources agree on every list; only
/// uTLS supplies an extension *order*, because Chromium permutes it per
/// connection.
///
/// The expected strings are the uTLS lists with two edits and nothing else:
///
/// * `encrypted_client_hello` (65037) is removed — this build cannot synthesize
///   a GREASE ECH body the ECH-aware servers accept (see the Firefox record);
/// * the order is the pre-shuffle list, because a permuted hello cannot be
///   pinned at all. JA3 is order-sensitive, so this pin holds for one shape out
///   of the distribution a real Chrome 133 sends; JA4's sorted view is the
///   stable key.
///
/// With those two edits the strings below are the uTLS lists in the uTLS order,
/// which is why a reader can redo them against the source rather than against
/// this test. The pinned versions are derived the same way: the 1.3 hello drops
/// what belongs to the 1.2 era, the 1.2 hello drops `supported_versions` and
/// ALPS.
#[test]
fn chrome_133_matches_the_utls_list_it_is_derived_from() {
    const CHROME_133_JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-\
         49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17613,4588-29-23-24,0";
    const CHROME_133_TLS13: &str =
        "771,4865-4866-4867,0-10-16-5-13-18-51-45-43-27-17613,4588-29-23-24,";
    const CHROME_133_TLS12: &str = "771,49195-49199-49196-49200-52393-52392-49171-49172-\
         156-157-47-53,0-23-65281-10-11-35-16-5-13-18,4588-29-23-24,0";

    for (version, expected) in [
        (TlsVersion::Any, CHROME_133_JA3),
        (TlsVersion::Tls13, CHROME_133_TLS13),
        (TlsVersion::Tls12, CHROME_133_TLS12),
    ] {
        assert_eq!(
            client_hello_of(TlsFingerprint::Chrome133, version).0,
            expected,
            "chrome133 ({version:?})"
        );
    }
}

/// The JA4 of Chrome 133's unpinned hello, in the three parts a source can
/// speak to, and one it cannot.
///
/// JA4 DBs publish `t13d1516h2_8daaf6152771_...` for the whole Chrome 133–146
/// line, so two parts of ours have to line up with it and one cannot:
///
/// * `t13d1515h2` — the counts, derived: 15 ciphers, 16 extensions less the
///   omitted ECH, h2 as the ALPN;
/// * `8daaf6152771` — the cipher hash, the published one. It moving means the
///   cipher list stopped being Chrome's, which no other test would notice;
/// * the extension hash is ours alone: nobody publishes a hash for an ECH-less
///   Chrome 133, so the full string carries the `_LESS_ECH` suffix the Firefox
///   pin uses — a regression guard, not evidence.
#[test]
fn chrome_133_ja4_pins_the_parts_a_source_covers() {
    const CHROME_133_JA4_LESS_ECH: &str = "t13d1515h2_8daaf6152771_22334254f9f7";

    let (_, _, ja4) = client_hello_full(TlsFingerprint::Chrome133, TlsVersion::Any);
    assert!(ja4.starts_with("t13d1515h2_"), "{ja4}");
    assert_eq!(
        ja4.split('_').nth(1),
        Some("8daaf6152771"),
        "the cipher hash the JA4 databases publish for Chrome 133+"
    );
    assert_eq!(ja4, CHROME_133_JA4_LESS_ECH);
}

/// Records that name the same TLS lists must put the same hello on the wire.
/// Edge is Chromium and Safari 18.0 is Safari 15.5's hello, so the JA3/JA4 pins
/// above are theirs too — the alternative, a second set of constants per
/// record, is how two records of one shape drift apart.
///
/// The sharing is a fact about the sources, not a convenience: the bundle's own
/// `safari_18.0_macOS` capture publishes the identical `ja3_text` (and a
/// `ja3_hash` of `773906b0efdefa24a7f2b8eb6985bf37`, which `tls.peet.ws`
/// reported for this profile's hello), and `curl_edge99/101` is documented to
/// emit the same JA3 as `curl_chrome99..107`.
#[test]
fn profiles_that_share_a_tls_shape_send_the_same_hello() {
    for version in [TlsVersion::Any, TlsVersion::Tls13, TlsVersion::Tls12] {
        assert_eq!(
            client_hello_full(TlsFingerprint::Edge, version),
            client_hello_full(TlsFingerprint::Chrome, version),
            "edge101 sends Chrome's hello ({version:?})"
        );
        assert_eq!(
            client_hello_full(TlsFingerprint::Safari18, version),
            client_hello_full(TlsFingerprint::Safari, version),
            "safari18 sends Safari 15.5's hello ({version:?})"
        );
    }
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
            TlsProfile::insecure(TlsFingerprint::Chrome).tls12()
        } else {
            TlsProfile::insecure(TlsFingerprint::Chrome).tls13()
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
fn curl_family_profiles_do_not_use_the_pq_provider() {
    assert!(!needs_pq(TlsFingerprint::Chrome));
    assert!(!needs_pq(TlsFingerprint::Safari));
    assert!(needs_pq(TlsFingerprint::Firefox));
    // Chrome 133 offers X25519MLKEM768 first, so it needs the provider that can
    // share a key over it; Edge and Safari 18 predate the hybrid group.
    assert!(needs_pq(TlsFingerprint::Chrome133));
    assert!(!needs_pq(TlsFingerprint::Safari18));
    assert!(!needs_pq(TlsFingerprint::Edge));
    assert!(advertises_cert_compression(TlsFingerprint::Chrome));
    assert!(advertises_cert_compression(TlsFingerprint::Safari));
    assert!(!advertises_cert_compression(TlsFingerprint::Rustls));
}

/// The decompressor list is what rustls reads to decide whether to offer
/// extension 27 and to pick a decoder for the algorithm the server answered
/// with; an empty list against an advertised extension is a fatal
/// `SelectedUnofferedCertCompression`. The default profile must keep the
/// empty list so its hello stays the baseline shape.
#[test]
fn the_decompressor_list_follows_the_profile() {
    for (name, fingerprint, decompressors) in [
        ("Rustls", TlsFingerprint::Rustls, 0),
        ("Firefox", TlsFingerprint::Firefox, 2),
        ("Chrome", TlsFingerprint::Chrome, 2),
        ("Safari", TlsFingerprint::Safari, 2),
        ("Chrome133", TlsFingerprint::Chrome133, 2),
        ("Safari18", TlsFingerprint::Safari18, 2),
        ("Edge", TlsFingerprint::Edge, 2),
    ] {
        let config = create_tls_config(&TlsProfile::insecure(fingerprint).tls13());
        assert_eq!(
            config.cert_decompressors.len(),
            decompressors,
            "{name} decompressor count"
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
    (Unimplemented::Cipher, 0x009c, "RSA-AES128-GCM-SHA256: rustls offers no RSA key exchange"),
    (Unimplemented::Cipher, 0x009d, "RSA-AES256-GCM-SHA384: rustls offers no RSA key exchange"),
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

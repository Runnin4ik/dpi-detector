//! What the legend's JA4 pass costs, priced in ClientHello builds.
//!
//! Run it deliberately: `cargo run --profile release-local -p dpi-core --example
//! ja4_cost`. The profile matters — the numbers are a ratio of two timings, and
//! a dev build (`opt-level = 0`) inverts what they say.
//!
//! Answers one question: how much of the legend's cost is the JA4 pass in
//! `hello_ja4_variants`, and how many ClientHello builds that pass performs.

use dpi_core::net::fingerprint::TlsFingerprint;
use dpi_core::net::tls::{hello_ja4_variants, hello_record, TlsProfile};
use std::time::Instant;

fn main() {
    let t = Instant::now();
    let mut variants = 0usize;
    for f in TlsFingerprint::ALL {
        variants += hello_ja4_variants(f).len();
    }
    let all = t.elapsed();
    println!(
        "hello_ja4_variants over {} shapes: {:?} ({} variants total)",
        TlsFingerprint::ALL.len(),
        all,
        variants
    );

    let p = TlsProfile::insecure(TlsFingerprint::Chrome133);
    let n = 300u32;
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(hello_record(&p));
    }
    let per = t.elapsed() / n;
    println!("one hello_record: {:?}", per);
    println!(
        "=> the legend pass performs about {} hello builds",
        all.as_nanos() / per.as_nanos().max(1)
    );
}

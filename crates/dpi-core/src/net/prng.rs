//! xorshift64* — the generator both fat-window probes draw their padding from.
//!
//! Test 3 pads its request with `fat_random_pool_size` bytes of ASCII and test
//! 5 uploads a 16 KB chunk per frame. Both want bytes no censor can match to the
//! tool, and both had their own copy of the four lines below — the same
//! constants, the same three shifts, kept in step by hand.
//!
//! `rand` is in the graph for the seed alone; an 8-byte state and a shift is
//! cheaper than a generator crate, and a constant seed makes the sequence
//! reproducible where a test needs that.

/// The xorshift64* state.
///
/// Not cryptographic: the padding exists so that two runs of the tool do not
/// look alike on the wire, not to resist an adversary who can read the state.
pub(crate) struct Xorshift64Star(u64);

impl Xorshift64Star {
    /// Seeds the generator. Zero is refused because xorshift never leaves it.
    pub(crate) fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }

    /// The next value: three shifts over the state, then the multiply that
    /// makes the top bits usable.
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A constant seed gives a constant sequence — what test 5's chunk relies
    /// on — and the values are spread, not stuck at one byte.
    #[test]
    fn a_seeded_sequence_is_reproducible_and_spread() {
        let draw = |seed| {
            let mut rng = Xorshift64Star::new(seed);
            (0..64).map(|_| rng.next_u64()).collect::<Vec<_>>()
        };
        let seed = 0x0123_4567_89AB_CDEF;
        assert_eq!(draw(seed), draw(seed));
        assert_ne!(draw(1), draw(2), "the seed reaches the sequence");

        let mut rng = Xorshift64Star::new(seed);
        let bytes: Vec<u8> = (0..4096).map(|_| (rng.next_u64() >> 33) as u8).collect();
        assert!(bytes.contains(&0), "a byte value repeats");
        let distinct: std::collections::HashSet<u8> = bytes.iter().copied().collect();
        assert!(distinct.len() > 200, "the high bits are spread: {} distinct", distinct.len());
    }

    /// Zero would pin the state at zero for ever; the seed is refused instead.
    #[test]
    fn a_zero_seed_still_moves() {
        let mut rng = Xorshift64Star::new(0);
        let first = rng.next_u64();
        assert_ne!(first, 0);
        assert_ne!(first, rng.next_u64());
    }
}

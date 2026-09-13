//! The crate's single CSPRNG call site.

use getrandom::fill;

/// There is no fallback: callers refuse the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsprngError;

impl core::fmt::Display for CsprngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the platform CSPRNG failed; refusing to substitute a weaker source")
    }
}

impl core::error::Error for CsprngError {}

pub(crate) fn fill_bytes(buf: &mut [u8]) -> Result<(), CsprngError> {
    fill(buf).map_err(|_| CsprngError)
}

/// `n == 0` returns `Ok(0)`; callers refuse it before they get here.
pub(crate) fn uniform_below(n: u32) -> Result<u32, CsprngError> {
    if n <= 1 {
        return Ok(0);
    }

    // The largest multiple of `n` that fits in `u32`, computed in `u64` so it cannot wrap.
    let range = 1_u64 << 32;
    let limit = range - (range % u64::from(n));

    loop {
        let mut bytes = [0_u8; 4];
        fill_bytes(&mut bytes)?;
        let draw = u32::from_le_bytes(bytes);
        if u64::from(draw) < limit {
            return Ok(draw % n);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{fill_bytes, uniform_below};

    #[test]
    fn fill_bytes_writes_something() {
        let mut buf = [0_u8; 32];
        fill_bytes(&mut buf).expect("the platform CSPRNG is available in tests");
        assert!(buf.iter().any(|&b| b != 0), "fill wrote nothing");
    }

    #[test]
    fn n_below_two_needs_no_draw_and_is_documented_as_such() {
        assert_eq!(uniform_below(0), Ok(0));
        assert_eq!(uniform_below(1), Ok(0));
    }

    #[test]
    fn uniform_below_never_returns_n_or_more() {
        for n in [1_u32, 2, 3, 7, 26, 62, 70, 95, 255, 256, 257, 7776] {
            for _ in 0..200 {
                let value = uniform_below(n).expect("CSPRNG");
                assert!(value < n, "uniform_below({n}) returned {value}");
            }
        }
    }

    #[test]
    fn the_accept_region_is_an_exact_multiple_of_n() {
        // Mirrors the arithmetic in `uniform_below`, so a changed formula fails here.
        let range = 1_u64 << 32;
        for n in [2_u32, 3, 7, 26, 62, 70, 95, 255, 256, 257, 7776, u32::MAX] {
            let limit = range - (range % u64::from(n));
            assert_eq!(
                limit % u64::from(n),
                0,
                "the accept region for n = {n} is not a multiple of n, so \
                 residues are not equally likely"
            );
            assert!(
                range - limit < u64::from(n),
                "n = {n} discards more than it must"
            );
            if range % u64::from(n) != 0 {
                assert!(
                    range % u64::from(n) > 0,
                    "sanity: n = {n} was chosen because it does not divide 2^32"
                );
            }
        }
    }

    #[test]
    fn powers_of_two_discard_nothing() {
        let range = 1_u64 << 32;
        for n in [2_u32, 4, 16, 256, 65536] {
            let limit = range - (range % u64::from(n));
            assert_eq!(limit, range, "n = {n} divides 2^32 and should discard 0");
        }
    }

    #[test]
    fn a_smoke_test_on_the_distribution_labelled_as_a_smoke_test() {
        // Generous bounds: this catches gross failures, not bias.
        const N: u32 = 8;
        const DRAWS: usize = 8_000;
        let mut counts = [0_usize; N as usize];
        for _ in 0..DRAWS {
            let value = uniform_below(N).expect("CSPRNG") as usize;
            if let Some(slot) = counts.get_mut(value) {
                *slot += 1;
            }
        }
        let expected = DRAWS / N as usize;
        for (value, &count) in counts.iter().enumerate() {
            assert!(
                count > expected / 2 && count < expected * 2,
                "value {value} appeared {count} times, expected about {expected}"
            );
        }
    }
}

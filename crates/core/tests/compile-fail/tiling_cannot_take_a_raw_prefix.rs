//! I6b: `tiles_exactly` takes only a `CanonicalPrefix`, so a raw prefix cannot
//! be tiled before it is checked for canonicality.
use chiavora_core::manifest::tiles_exactly;

fn main() {
    // Non-canonical: a bit is set below `prefixLen = 1`.
    let raw = [(1_u8, 0x8000_0000_0000_0001_u64)];
    let _ = tiles_exactly(&raw);
}

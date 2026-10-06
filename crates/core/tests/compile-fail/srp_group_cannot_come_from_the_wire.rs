//! A served `N` and `g` cannot become a `Group`: its fields are private (E0451).

fn main() {
    let hostile = chiavora_core::srp::Group {
        hex: "DEADBEEF",
        generator: 2,
        bits: 32,
    };
    let _ = hostile;
}

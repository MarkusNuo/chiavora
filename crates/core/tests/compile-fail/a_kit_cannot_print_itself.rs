//! A `Kit` has no `Display`, so `{}` cannot print it.

use chiavora_core::emergency_kit::Kit;

fn main() {
    let kit: Option<Kit> = None;
    if let Some(kit) = kit {
        println!("{kit}");
    }
}

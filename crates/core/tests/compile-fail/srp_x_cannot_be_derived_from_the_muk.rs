//! `srpX` cannot be derived from the MUK: both are siblings of `rootKey`, not parent and child.
use chiavora_core::derive::derive_srp_x;
use chiavora_core::secret::{kind::Muk, Secret};

fn main() {
    let muk = Secret::<Muk>::from_derived_bytes(vec![0; 32]);
    let _srp_x = derive_srp_x(&muk);
}

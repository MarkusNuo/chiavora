//! A `Secret<SrpX>` cannot be passed where a `Secret<Muk>` is expected.
use chiavora_core::secret::{
    kind::{Muk, SrpX},
    Secret,
};

fn takes_the_muk(_muk: &Secret<Muk>) {}

fn main() {
    let srp_x = Secret::<SrpX>::new(b"key material".to_vec());
    takes_the_muk(&srp_x);
}

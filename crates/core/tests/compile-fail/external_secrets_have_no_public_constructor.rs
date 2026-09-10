//! `Secret::from_external_bytes` cannot be called from outside `core`.

use chiavora_core::secret::{kind::AccountPassword, Secret};

fn main() {
    let password = Secret::<AccountPassword>::from_external_bytes(zeroize::Zeroizing::new(
        b"hunter2".to_vec(),
    ));
    let _ = password;
}

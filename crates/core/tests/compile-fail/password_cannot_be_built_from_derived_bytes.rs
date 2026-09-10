//! `from_derived_bytes` refuses the `AccountPassword` brand; only `entry::accept` makes one.

use chiavora_core::secret::{kind::AccountPassword, Secret};

fn main() {
    let password = Secret::<AccountPassword>::from_derived_bytes(b"hunter2".to_vec());
    let _ = password;
}

//! The password field yields `Secret<AccountPassword>`; a caller cannot ask it for a `Muk`.

use chiavora_core::entry::{accept, PasswordField};
use chiavora_core::secret::{kind::Muk, Secret};

fn main() {
    let muk: Result<Secret<Muk>, _> = accept::<PasswordField>(b"hunter2".to_vec());
    let _ = muk;
}

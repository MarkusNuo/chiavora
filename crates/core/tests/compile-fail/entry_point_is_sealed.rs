//! `EntryPoint` is sealed, so no crate outside `core` can declare a new entry point.

use chiavora_core::entry::{EntryError, EntryPoint};
use chiavora_core::secret::kind::AccountPassword;
use zeroize::Zeroizing;

struct BiometricPromptField;

impl EntryPoint for BiometricPromptField {
    type Yields = AccountPassword;

    const NAME: &'static str = "biometric prompt field";

    fn transform(raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, EntryError> {
        Ok(raw)
    }
}

fn main() {}

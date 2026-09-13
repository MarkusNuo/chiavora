//! On-device Argon2id measurement, not a product API; the derived key is thrown away.

use std::time::Instant;

use chiavora_core::derive::{derive_root_key, AccountIdentifiers, DeriveError, KdfParams};
use chiavora_core::entry::{accept, PasswordField, SecretKeyField};

#[derive(Debug, uniffi::Record)]
pub struct DerivationOutcome {
    pub completed: bool,
    pub millis: u64,
    pub refusal: Option<String>,
    pub oom_score_adj_before: Option<i32>,
    pub oom_score_adj_after: Option<i32>,
    pub mem_available_kib_before: Option<u64>,
    pub mem_available_kib_after: Option<u64>,
    pub memory_kib: u32,
    pub iterations: u32,
}

#[derive(Debug, uniffi::Error)]
pub enum HarnessError {
    BelowI4Floor,
    FixedVectorRefused,
}

impl core::fmt::Display for HarnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BelowI4Floor => f.write_str("parameters below the I4 floor"),
            Self::FixedVectorRefused => {
                f.write_str("the fixed vector was refused by an entry point")
            }
        }
    }
}

impl std::error::Error for HarnessError {}

#[uniffi::export]
pub fn harness_derive_once(
    memory_kib: u32,
    iterations: u32,
) -> Result<DerivationOutcome, HarnessError> {
    let params = KdfParams::new(memory_kib, iterations).map_err(|_| HarnessError::BelowI4Floor)?;

    // Through the entry points, so the password is normalized as a typed one would be.
    let password = accept::<PasswordField>(HARNESS_PASSWORD.to_vec())
        .map_err(|_| HarnessError::FixedVectorRefused)?;
    let secret_key = accept::<SecretKeyField>(HARNESS_SECRET_KEY.to_vec())
        .map_err(|_| HarnessError::FixedVectorRefused)?;

    let ids = AccountIdentifiers {
        account_id: &HARNESS_ACCOUNT_ID,
        account_salt: &HARNESS_ACCOUNT_SALT,
    };

    let oom_before = oom_score_adj();
    let mem_before = mem_available_kib();
    let started = Instant::now();
    let outcome = derive_root_key(&password, &secret_key, ids, params);
    let elapsed = started.elapsed();
    let oom_after = oom_score_adj();
    let mem_after = mem_available_kib();

    // The root key is dropped and zeroized here, never read, returned or logged.
    let refusal = match outcome {
        Ok(_) => None,
        Err(DeriveError::Argon2Allocation) => Some("Argon2Allocation".to_owned()),
        Err(DeriveError::BelowI4Floor) => Some("BelowI4Floor".to_owned()),
        Err(other) => Some(format!("{other:?}")),
    };

    Ok(DerivationOutcome {
        completed: refusal.is_none(),
        millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        refusal,
        oom_score_adj_before: oom_before,
        oom_score_adj_after: oom_after,
        mem_available_kib_before: mem_before,
        mem_available_kib_after: mem_after,
        memory_kib,
        iterations,
    })
}

const HARNESS_PASSWORD: &[u8] = b"correct horse battery staple";
const HARNESS_SECRET_KEY: &[u8] = b"CHV1-0000-0000-0000-0000-0000-0000-00XV";
/// A fixed 128-bit account identifier (`docs/adr/0005`).
const HARNESS_ACCOUNT_ID: [u8; 16] = [0x1D; 16];
const HARNESS_ACCOUNT_SALT: [u8; 32] = [0x5A; 32];

fn oom_score_adj() -> Option<i32> {
    std::fs::read_to_string("/proc/self/oom_score_adj")
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn mem_available_kib() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{harness_derive_once, HarnessError};
    use chiavora_core::derive::{I4_FLOOR_ITERATIONS, I4_FLOOR_MEMORY_KIB};

    #[test]
    fn the_fixed_vector_is_accepted_by_this_builds_entry_points() {
        let outcome = harness_derive_once(I4_FLOOR_MEMORY_KIB, I4_FLOOR_ITERATIONS)
            .expect("the fixed vector must be acceptable");
        assert!(outcome.completed, "refused: {:?}", outcome.refusal);
        assert_eq!(outcome.memory_kib, I4_FLOOR_MEMORY_KIB);
    }

    #[test]
    fn the_i4_floor_has_no_measurement_exemption() {
        let err = harness_derive_once(I4_FLOOR_MEMORY_KIB - 1, I4_FLOOR_ITERATIONS)
            .expect_err("below the floor must not be measurable");
        assert!(matches!(err, HarnessError::BelowI4Floor));
    }
}

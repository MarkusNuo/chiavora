//! An unknown identifier must look known (RFC 5054 §2.5.1.3); the transport is not covered yet.

use chiavora_core::srp::{
    fake_credentials, select_credentials, FakeCredentials, Group, SRP_SALT_LEN, SRP_SEED_KEY_LEN,
    SRP_VERIFIER_LEN,
};
use zeroize::Zeroizing;

use crate::auth::{AuthRecord, AuthRecordError};

/// Not a `Secret`: it is a deployment secret an operator supplies, not account key material.
pub struct SeedKey(Zeroizing<Vec<u8>>);

impl SeedKey {
    pub fn new(bytes: Vec<u8>) -> Result<Self, AuthRecordError> {
        if bytes.len() != SRP_SEED_KEY_LEN {
            return Err(AuthRecordError::SeedKeyLength);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SeedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SeedKey(<redacted>)")
    }
}

/// Equal traces for a known and an unknown identifier show that both paths did the same work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    LookedUp {
        identifier_len: usize,
    },
    #[allow(clippy::struct_field_names)]
    Fabricated {
        seed_len: usize,
        identifier_len: usize,
    },
    Selected {
        salt_len: usize,
        verifier_len: usize,
    },
    BuiltRecord {
        account_id_len: usize,
    },
}

pub type Stored<'a> = Option<(&'a [u8], &'a [u8], &'a [u8])>;

pub fn resolve_credentials(
    seed: &SeedKey,
    identifier: &[u8],
    stored: Stored<'_>,
) -> Result<(AuthRecord, Vec<Op>), AuthRecordError> {
    let mut trace = Vec::with_capacity(4);

    trace.push(Op::LookedUp {
        identifier_len: identifier.len(),
    });

    // Unconditionally, before anything looks at `stored`: the timing claim rests on this line.
    let fake: FakeCredentials = fake_credentials(Group::RFC5054_4096, seed.expose(), identifier)
        .map_err(AuthRecordError::Srp)?;
    trace.push(Op::Fabricated {
        seed_len: SRP_SEED_KEY_LEN,
        identifier_len: identifier.len(),
    });

    let pair = stored.map(|(_, salt, verifier)| (salt, verifier));
    let (srp_salt, verifier) = select_credentials(pair, &fake).map_err(AuthRecordError::Srp)?;
    trace.push(Op::Selected {
        salt_len: SRP_SALT_LEN,
        verifier_len: SRP_VERIFIER_LEN,
    });

    let account_id = select_account_id(stored.map(|(id, _, _)| id), &fake.account_id);
    trace.push(Op::BuiltRecord {
        account_id_len: account_id.len(),
    });

    Ok((AuthRecord::new(&account_id, &srp_salt, &verifier)?, trace))
}

/// Without branching; with nothing stored, both sides are the fabricated value.
fn select_account_id(stored: Option<&[u8]>, fake: &[u8]) -> Vec<u8> {
    let source = stored.filter(|id| id.len() == fake.len()).unwrap_or(fake);
    let exists = u8::from(stored.is_some_and(|id| id.len() == fake.len()));
    source
        .iter()
        .zip(fake.iter())
        .map(|(real, fabricated)| {
            let mask = 0_u8.wrapping_sub(exists);
            (real & mask) | (fabricated & !mask)
        })
        .collect()
}

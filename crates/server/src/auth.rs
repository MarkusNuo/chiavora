//! Stores `(srpSalt, v)` and nothing a password could be recovered from; it checks only widths.

use chiavora_core::emergency_kit::ACCOUNT_ID_LEN;
use chiavora_core::srp::{SRP_SALT_LEN, SRP_VERIFIER_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRecordError {
    AccountIdLength,
    SaltLength,
    VerifierLength,
}

impl core::fmt::Display for AuthRecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::AccountIdLength => f.write_str("accountId is not 16 bytes; refusing"),
            Self::SaltLength => f.write_str("srpSalt is not 32 bytes; refusing"),
            Self::VerifierLength => f.write_str("the verifier is not 512 bytes; refusing"),
        }
    }
}

impl core::error::Error for AuthRecordError {}

/// The fields are private so that the width checks in [`AuthRecord::new`] cannot be bypassed.
#[derive(Debug, Clone)]
pub struct AuthRecord {
    account_id: Vec<u8>,
    srp_salt: Vec<u8>,
    verifier: Vec<u8>,
}

impl AuthRecord {
    pub fn new(
        account_id: &[u8],
        srp_salt: &[u8],
        verifier: &[u8],
    ) -> Result<Self, AuthRecordError> {
        if account_id.len() != ACCOUNT_ID_LEN {
            return Err(AuthRecordError::AccountIdLength);
        }
        if srp_salt.len() != SRP_SALT_LEN {
            return Err(AuthRecordError::SaltLength);
        }
        if verifier.len() != SRP_VERIFIER_LEN {
            return Err(AuthRecordError::VerifierLength);
        }
        Ok(Self {
            account_id: account_id.to_vec(),
            srp_salt: srp_salt.to_vec(),
            verifier: verifier.to_vec(),
        })
    }

    #[must_use]
    pub fn account_id(&self) -> &[u8] {
        &self.account_id
    }

    /// Public by design; the pre-auth endpoint serves it.
    #[must_use]
    pub fn srp_salt(&self) -> &[u8] {
        &self.srp_salt
    }

    /// `v = g^x mod N`: the public half of the SRP pair, not key material.
    #[must_use]
    pub fn verifier(&self) -> &[u8] {
        &self.verifier
    }

    /// Hand-written rather than derived, so that a new field cannot slip in unnoticed.
    #[must_use]
    pub fn to_stored_bytes(&self) -> Vec<u8> {
        // R1: all three widths are constants that `new` has checked.
        let mut out = Vec::with_capacity(ACCOUNT_ID_LEN + SRP_SALT_LEN + SRP_VERIFIER_LEN);
        out.extend_from_slice(&self.account_id);
        out.extend_from_slice(&self.srp_salt);
        out.extend_from_slice(&self.verifier);
        out
    }
}

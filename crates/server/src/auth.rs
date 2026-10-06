//! Stores `(srpSalt, v)` and nothing a password could be recovered from; it checks only widths.

use chiavora_core::emergency_kit::ACCOUNT_ID_LEN;
use chiavora_core::secret::{kind::SrpEphemeralSecret, Secret};
use chiavora_core::srp::{
    check_public_value, generate_ephemeral, server_public_bytes, Group, ServerExchange, Sha256Hash,
    SrpError, SRP_SALT_LEN, SRP_VERIFIER_LEN,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRecordError {
    AccountIdLength,
    SaltLength,
    VerifierLength,
    ClientPublicLength,
    /// What the caller is told is the endpoint's decision.
    Srp(SrpError),
}

impl core::fmt::Display for AuthRecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::AccountIdLength => f.write_str("accountId is not 16 bytes; refusing"),
            Self::SaltLength => f.write_str("srpSalt is not 32 bytes; refusing"),
            Self::VerifierLength => f.write_str("the verifier is not 512 bytes; refusing"),
            Self::ClientPublicLength => f.write_str("A is not 512 bytes; refusing"),
            Self::Srp(inner) => write!(f, "the SRP exchange was refused: {inner}"),
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

/// Replay resistance rests on each `b` being used once, so [`PendingExchange::finish`] takes
/// `self` by value. The exchange is never stored or persisted.
#[derive(Debug)]
pub struct PendingExchange {
    account_id: Vec<u8>,
    srp_salt: Vec<u8>,
    verifier: Vec<u8>,
    client_public: Vec<u8>,
    ephemeral: Secret<SrpEphemeralSecret>,
    server_public: Vec<u8>,
}

impl PendingExchange {
    pub fn begin(record: &AuthRecord, client_public: &[u8]) -> Result<Self, AuthRecordError> {
        if client_public.len() != SRP_VERIFIER_LEN {
            return Err(AuthRecordError::ClientPublicLength);
        }
        // Refused before any exponentiation, so one packet cannot cost a modexp.
        check_public_value(Group::RFC5054_4096, client_public).map_err(AuthRecordError::Srp)?;
        let ephemeral = generate_ephemeral().map_err(AuthRecordError::Srp)?;
        let server_public =
            server_public_bytes::<Sha256Hash>(Group::RFC5054_4096, &ephemeral, record.verifier())
                .map_err(AuthRecordError::Srp)?;
        Ok(Self {
            account_id: record.account_id().to_vec(),
            srp_salt: record.srp_salt().to_vec(),
            verifier: record.verifier().to_vec(),
            client_public: client_public.to_vec(),
            ephemeral,
            server_public,
        })
    }

    #[must_use]
    pub fn server_public(&self) -> &[u8] {
        &self.server_public
    }

    pub fn finish(self, client_proof: &[u8]) -> Result<ServerExchange, AuthRecordError> {
        chiavora_core::srp::server_finish::<Sha256Hash>(
            Group::RFC5054_4096,
            &self.ephemeral,
            &self.verifier,
            &self.client_public,
            &self.account_id,
            &self.srp_salt,
            client_proof,
        )
        .map_err(AuthRecordError::Srp)
    }
}

//! The MAC covers the request as sent; any normalisation happens before it, on both sides.

use hmac::Mac as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::secret::{
    kind::{SrpMacKeyClientToServer, SrpMacKeyServerToClient},
    Secret,
};

pub const MAC_FORMAT_VERSION: u8 = 0x01;

const DOMAIN: &[u8] = b"chiavora-request-mac";

pub const NONCE_LEN: usize = 16;

pub const BODY_HASH_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacError {
    FieldLength,
    FieldTooLong,
    Version,
    Truncated,
}

impl core::fmt::Display for MacError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::FieldLength => f.write_str("a fixed-width MAC field is not its width"),
            Self::FieldTooLong => f.write_str("a MAC field is longer than u32::MAX"),
            Self::Version => f.write_str("the MAC encoding has an unknown format version"),
            Self::Truncated => f.write_str("the MAC encoding ends inside a field"),
        }
    }
}

impl core::error::Error for MacError {}

#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'a> {
    pub method: &'a [u8],
    /// The path, as the client sent it, not normalised.
    pub path: &'a [u8],
    pub body_hash: &'a [u8],
    /// Unix seconds. The accepted window is ±300 s.
    pub timestamp: i64,
    /// [`NONCE_LEN`] bytes from the single CSPRNG site.
    pub nonce: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedParts {
    pub method: Vec<u8>,
    pub path: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub timestamp: i64,
    pub nonce: Vec<u8>,
}

#[must_use]
pub fn body_hash(body: &[u8]) -> Vec<u8> {
    Sha256::digest(body).to_vec()
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), MacError> {
    // R1: propagated; a truncated prefix would let two requests encode alike.
    let len = u32::try_from(field.len()).map_err(|_| MacError::FieldTooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

pub fn encode(parts: &RequestParts<'_>) -> Result<Vec<u8>, MacError> {
    if parts.body_hash.len() != BODY_HASH_LEN || parts.nonce.len() != NONCE_LEN {
        return Err(MacError::FieldLength);
    }
    let mut out = Vec::with_capacity(
        1 + 4
            + DOMAIN.len()
            + 4 * 5
            + parts.method.len()
            + parts.path.len()
            + BODY_HASH_LEN
            + 8
            + NONCE_LEN,
    );
    out.push(MAC_FORMAT_VERSION);
    push_field(&mut out, DOMAIN)?;
    push_field(&mut out, parts.method)?;
    push_field(&mut out, parts.path)?;
    push_field(&mut out, parts.body_hash)?;
    push_field(&mut out, &parts.timestamp.to_be_bytes())?;
    push_field(&mut out, parts.nonce)?;
    Ok(out)
}

fn take_field(input: &[u8]) -> Result<(&[u8], &[u8]), MacError> {
    let (len_bytes, rest) = input.split_at_checked(4).ok_or(MacError::Truncated)?;
    let len_array: [u8; 4] = len_bytes.try_into().map_err(|_| MacError::Truncated)?;
    let len = usize::try_from(u32::from_be_bytes(len_array)).map_err(|_| MacError::Truncated)?;
    rest.split_at_checked(len).ok_or(MacError::Truncated)
}

/// Only the tag is sent, so this exists to prove `encode` injective by round trip.
pub fn decode(input: &[u8]) -> Result<DecodedParts, MacError> {
    let (version, rest) = input.split_first().ok_or(MacError::Truncated)?;
    if *version != MAC_FORMAT_VERSION {
        return Err(MacError::Version);
    }
    let (domain, rest) = take_field(rest)?;
    if domain != DOMAIN {
        return Err(MacError::FieldLength);
    }
    let (method, rest) = take_field(rest)?;
    let (path, rest) = take_field(rest)?;
    let (body, rest) = take_field(rest)?;
    let (stamp, rest) = take_field(rest)?;
    let (nonce, rest) = take_field(rest)?;

    if !rest.is_empty() {
        return Err(MacError::Truncated);
    }
    if body.len() != BODY_HASH_LEN || nonce.len() != NONCE_LEN {
        return Err(MacError::FieldLength);
    }
    let stamp_array: [u8; 8] = stamp.try_into().map_err(|_| MacError::FieldLength)?;

    Ok(DecodedParts {
        method: method.to_vec(),
        path: path.to_vec(),
        body_hash: body.to_vec(),
        timestamp: i64::from_be_bytes(stamp_array),
        nonce: nonce.to_vec(),
    })
}

fn tag_with(key: &[u8], parts: &RequestParts<'_>) -> Result<Vec<u8>, MacError> {
    let input = encode(parts)?;
    let mut mac = <hmac::Hmac<Sha256> as hmac::Mac>::new_from_slice(key)
        .map_err(|_| MacError::FieldLength)?;
    mac.update(&input);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn client_to_server_tag(
    key: &Secret<SrpMacKeyClientToServer>,
    parts: &RequestParts<'_>,
) -> Result<Vec<u8>, MacError> {
    tag_with(key.expose(), parts)
}

pub fn server_to_client_tag(
    key: &Secret<SrpMacKeyServerToClient>,
    parts: &RequestParts<'_>,
) -> Result<Vec<u8>, MacError> {
    tag_with(key.expose(), parts)
}

/// Compares two tags in constant time; a length mismatch returns `false` early, as lengths are
/// public.
#[must_use]
pub fn tags_match(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

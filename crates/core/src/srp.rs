//! SRP-6a (RFC 5054) over the 4096-bit group, given `x` (`docs/adr/0008`).

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, ConcatenatingMul as _, NonZero, Odd, Resize as _};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::secret::{
    kind::{
        SrpEphemeralSecret, SrpExponent, SrpMacKeyClientToServer, SrpMacKeyServerToClient,
        SrpPremasterSecret, SrpSessionKey, SrpX,
    },
    Secret,
};

/// RFC 5054 Appendix A's 4096-bit prime (`g = 5`), checked against `tests/vectors/srp_groups.json`.
const N_4096_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33",
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2",
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7",
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8",
    "DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

#[cfg(test)]
const N_1024_HEX: &str = concat!(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576",
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1",
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC",
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
);

/// The only group a release build can name is [`Group::RFC5054_4096`].
#[derive(Debug, Clone, Copy)]
pub struct Group {
    hex: &'static str,
    generator: u32,
    bits: u32,
}

impl Group {
    pub const RFC5054_4096: Self = Self {
        hex: N_4096_HEX,
        generator: 5,
        bits: 4096,
    };

    #[cfg(test)]
    pub(crate) const RFC5054_1024_TEST_ONLY: Self = Self {
        hex: N_1024_HEX,
        generator: 2,
        bits: 1024,
    };

    fn modulus(self) -> Result<BoxedUint, SrpError> {
        Option::from(BoxedUint::from_be_hex(self.hex, self.bits)).ok_or(SrpError::Group)
    }

    const fn padded_len(self) -> usize {
        self.bits as usize / 8
    }
}

/// A type parameter, never a wire value, so a server has nothing to negotiate.
pub trait SrpHash: sealed::Sealed {
    const LEN: usize;

    fn digest(parts: &[&[u8]]) -> Vec<u8>;
}

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, Copy)]
pub struct Sha256Hash;

impl sealed::Sealed for Sha256Hash {}
impl SrpHash for Sha256Hash {
    const LEN: usize = 32;

    fn digest(parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().to_vec()
    }
}

/// SHA-1, only for RFC 5054 Appendix B's vectors; `sha1` is a dev-dependency.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sha1Hash;

#[cfg(test)]
impl sealed::Sealed for Sha1Hash {}

#[cfg(test)]
impl SrpHash for Sha1Hash {
    const LEN: usize = 20;

    fn digest(parts: &[&[u8]]) -> Vec<u8> {
        use sha1::Digest as _;
        let mut hasher = sha1::Sha1::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrpError {
    Group,
    EvenModulus,
    PublicValueOutOfRange,
    Csprng,
    Precision,
    Hkdf,
    TranscriptFieldLength,
}

impl core::fmt::Display for SrpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Group => f.write_str("the SRP group constant is not valid hex of its width"),
            Self::EvenModulus => f.write_str("the SRP modulus is even"),
            Self::PublicValueOutOfRange => {
                f.write_str("an SRP public value is zero mod N or out of range; refusing")
            }
            Self::Csprng => {
                f.write_str("the platform CSPRNG failed while drawing srpSalt; refusing")
            }
            Self::Precision => f.write_str("an SRP value did not fit the requested precision"),
            Self::Hkdf => f.write_str("HKDF refused the SRP session key length"),
            Self::TranscriptFieldLength => {
                f.write_str("an SRP proof-transcript field is not its fixed width; refusing")
            }
        }
    }
}

impl core::error::Error for SrpError {}

/// `PAD(x)`: left-pad to the byte length of `N` (RFC 5054 §2.6).
fn pad(value: &BoxedUint, group: Group) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    // R1: `width` comes from one of this module's own groups, never from input.
    let width = group.padded_len();
    let mut out = vec![0_u8; width];
    let start = width.saturating_sub(bytes.len());
    for (slot, byte) in out.iter_mut().skip(start).zip(bytes.iter()) {
        *slot = *byte;
    }
    out
}

/// Exponents are bounded at this public precision rather than at `N`'s, which would cost about
/// fourteen times the squarings; their own bit length is secret and cannot be the bound.
fn natural_precision(bytes: usize) -> Result<u32, SrpError> {
    // R1: not absorbed; an overflow becomes `SrpError::Precision`.
    let bits = u32::try_from(bytes)
        .ok()
        .and_then(|len| len.checked_mul(8))
        .ok_or(SrpError::Precision)?;
    Ok(bits.next_multiple_of(crypto_bigint::Limb::BITS))
}

fn widen(value: BoxedUint, bits: u32) -> Result<BoxedUint, SrpError> {
    value.try_resize(bits).ok_or(SrpError::Precision)
}

fn params(group: Group) -> Result<BoxedMontyParams, SrpError> {
    let modulus = group.modulus()?;
    let odd = Option::from(Odd::new(modulus)).ok_or(SrpError::EvenModulus)?;
    Ok(BoxedMontyParams::new(odd))
}

fn secret_to_uint(secret: &[u8]) -> Result<BoxedUint, SrpError> {
    BoxedUint::from_be_slice(secret, natural_precision(secret.len())?)
        .map_err(|_| SrpError::Precision)
}

fn generator(group: Group) -> Result<BoxedUint, SrpError> {
    widen(BoxedUint::from(u64::from(group.generator)), group.bits)
}

pub const SRP_SALT_LEN: usize = 32;

pub fn generate_srp_salt() -> Result<Vec<u8>, SrpError> {
    let mut salt = vec![0_u8; SRP_SALT_LEN];
    crate::csprng::fill_bytes(&mut salt).map_err(|_| SrpError::Csprng)?;
    Ok(salt)
}

/// This replaces RFC 5054's `x = H(s, H(I:p))` (`docs/adr/0008`). `srpSalt` adds no entropy; it
/// only keeps the construction in SRP's shape.
pub fn private_exponent(
    srp_salt: &[u8],
    srp_x: &Secret<SrpX>,
) -> Result<Secret<SrpExponent>, SrpError> {
    let mut hasher = Sha256::new();
    hasher.update(srp_salt);
    hasher.update(srp_x.expose());
    let digest = Zeroizing::new(hasher.finalize().to_vec());
    Ok(Secret::from_derived_bytes(digest.to_vec()))
}

/// `v = g^x mod N`, the verifier the server stores (RFC 5054 §2.4); constant-time in `x`.
pub fn verifier(group: Group, exponent: &Secret<SrpExponent>) -> Result<BoxedUint, SrpError> {
    let monty = params(group)?;
    let x = secret_to_uint(exponent.expose())?;
    let bound = x.bits_precision();
    Ok(BoxedMontyForm::new(generator(group)?, &monty)
        .pow_bounded_exp(&x, bound)
        .retrieve())
}

/// `k = H(N ‖ PAD(g))`, SRP-6a's multiplier (RFC 5054 §2.5.3), at `N`'s precision.
pub fn multiplier<H: SrpHash>(group: Group) -> Result<BoxedUint, SrpError> {
    let modulus = group.modulus()?;
    let digest = H::digest(&[&pad(&modulus, group), &pad(&generator(group)?, group)]);
    widen(secret_to_uint(&digest)?, group.bits)
}

/// `u = H(PAD(A) ‖ PAD(B))` (RFC 5054 §2.6), at the digest's precision since it is an exponent.
pub fn scrambler<H: SrpHash>(
    group: Group,
    client_public: &BoxedUint,
    server_public: &BoxedUint,
) -> Result<BoxedUint, SrpError> {
    let digest = H::digest(&[&pad(client_public, group), &pad(server_public, group)]);
    secret_to_uint(&digest)
}

pub fn client_public(
    group: Group,
    ephemeral: &Secret<SrpEphemeralSecret>,
) -> Result<BoxedUint, SrpError> {
    let monty = params(group)?;
    let exponent = secret_to_uint(ephemeral.expose())?;
    let bound = exponent.bits_precision();
    Ok(BoxedMontyForm::new(generator(group)?, &monty)
        .pow_bounded_exp(&exponent, bound)
        .retrieve())
}

pub fn server_public<H: SrpHash>(
    group: Group,
    ephemeral: &Secret<SrpEphemeralSecret>,
    verifier: &BoxedUint,
) -> Result<BoxedUint, SrpError> {
    let monty = params(group)?;
    let nonzero = Option::from(NonZero::new(group.modulus()?)).ok_or(SrpError::EvenModulus)?;

    let k = multiplier::<H>(group)?;
    let exponent = secret_to_uint(ephemeral.expose())?;
    let bound = exponent.bits_precision();

    let g_to_b = BoxedMontyForm::new(generator(group)?, &monty)
        .pow_bounded_exp(&exponent, bound)
        .retrieve();
    let k_v = k.mul_mod(verifier, &nonzero);
    Ok(k_v.add_mod(&g_to_b, &nonzero))
}

/// The client's premaster secret, `S = (B − k·g^x)^(a + u·x) mod N`.
pub fn client_premaster<H: SrpHash>(
    group: Group,
    ephemeral: &Secret<SrpEphemeralSecret>,
    exponent: &Secret<SrpExponent>,
    server_public: &BoxedUint,
) -> Result<Secret<SrpPremasterSecret>, SrpError> {
    let monty = params(group)?;
    let nonzero = Option::from(NonZero::new(group.modulus()?)).ok_or(SrpError::EvenModulus)?;

    // RFC 5054 §2.6: the client aborts if `B % N == 0`.
    if bool::from(server_public.rem_vartime(&nonzero).is_zero()) {
        return Err(SrpError::PublicValueOutOfRange);
    }

    let a = secret_to_uint(ephemeral.expose())?;
    let x = secret_to_uint(exponent.expose())?;
    let k = multiplier::<H>(group)?;

    let client_pub = client_public(group, ephemeral)?;
    let u = scrambler::<H>(group, &client_pub, server_public)?;

    let x_at_n = widen(x.clone(), group.bits)?;
    let g_to_x = BoxedMontyForm::new(generator(group)?, &monty)
        .pow_bounded_exp(&x_at_n, x.bits_precision())
        .retrieve();
    let base = server_public.sub_mod(&k.mul_mod(&g_to_x, &nonzero), &nonzero);

    // a + u·x without modular reduction: `concatenating_mul` widens so nothing wraps, and the
    // resulting precision, hence the squaring count, depends only on public widths.
    let ux = u.concatenating_mul(&x);
    let room = ux.bits_precision() + crypto_bigint::Limb::BITS;
    let exp = widen(ux, room)?.wrapping_add(&widen(a, room)?);
    let bound = exp.bits_precision();

    let secret = BoxedMontyForm::new(base, &monty)
        .pow_bounded_exp(&exp, bound)
        .retrieve();
    Ok(Secret::from_derived_bytes(
        Zeroizing::new(pad(&secret, group)).to_vec(),
    ))
}

/// The server's premaster secret, `S = (A · v^u)^b mod N`.
pub fn server_premaster<H: SrpHash>(
    group: Group,
    ephemeral: &Secret<SrpEphemeralSecret>,
    verifier: &BoxedUint,
    client_public: &BoxedUint,
) -> Result<Secret<SrpPremasterSecret>, SrpError> {
    let monty = params(group)?;
    let nonzero = Option::from(NonZero::new(group.modulus()?)).ok_or(SrpError::EvenModulus)?;

    if bool::from(client_public.rem_vartime(&nonzero).is_zero()) {
        return Err(SrpError::PublicValueOutOfRange);
    }

    let b = secret_to_uint(ephemeral.expose())?;
    let server_pub = server_public::<H>(group, ephemeral, verifier)?;
    let u = scrambler::<H>(group, client_public, &server_pub)?;

    let u_at_n = widen(u.clone(), group.bits)?;
    let v_to_u = BoxedMontyForm::new(verifier.clone(), &monty)
        .pow_bounded_exp(&u_at_n, u.bits_precision())
        .retrieve();
    let base = client_public.mul_mod(&v_to_u, &nonzero);

    let secret = BoxedMontyForm::new(base, &monty)
        .pow_bounded_exp(&b, b.bits_precision())
        .retrieve();
    Ok(Secret::from_derived_bytes(
        Zeroizing::new(pad(&secret, group)).to_vec(),
    ))
}

pub const SRP_KEY_LEN: usize = 32;

const INFO_SESSION_KEY: &[u8] = b"chiavora-srp-k";
const INFO_MAC_C2S: &[u8] = b"chiavora-mac-c2s";
const INFO_MAC_S2C: &[u8] = b"chiavora-mac-s2c";

/// Siblings rather than a chain, because `K` is hashed into the transmitted `M1`.
#[derive(Debug)]
pub struct SessionKeys {
    /// `K`: hashed into `M1` and `M2`, and used for nothing else.
    pub session_key: Secret<SrpSessionKey>,
    pub mac_client_to_server: Secret<SrpMacKeyClientToServer>,
    pub mac_server_to_client: Secret<SrpMacKeyServerToClient>,
}

/// One HKDF expansion of `S` under one label, with no salt; `info` carries the separation.
fn expand(premaster: &Secret<SrpPremasterSecret>, info: &[u8]) -> Result<Vec<u8>, SrpError> {
    let mut out = Zeroizing::new(vec![0_u8; SRP_KEY_LEN]);
    Hkdf::<Sha256>::new(None, premaster.expose())
        .expand(info, out.as_mut_slice())
        .map_err(|_| SrpError::Hkdf)?;
    Ok(out.to_vec())
}

pub fn session_keys(premaster: &Secret<SrpPremasterSecret>) -> Result<SessionKeys, SrpError> {
    Ok(SessionKeys {
        session_key: Secret::from_derived_bytes(expand(premaster, INFO_SESSION_KEY)?),
        mac_client_to_server: Secret::from_derived_bytes(expand(premaster, INFO_MAC_C2S)?),
        mac_server_to_client: Secret::from_derived_bytes(expand(premaster, INFO_MAC_S2C)?),
    })
}

/// `H(N) XOR H(g)`, the group's contribution to `M1` (RFC 5054 §2.6), with `g` padded.
fn group_xor<H: SrpHash>(group: Group) -> Result<Vec<u8>, SrpError> {
    let modulus = group.modulus()?;
    let h_n = H::digest(&[&pad(&modulus, group)]);
    let h_g = H::digest(&[&pad(&generator(group)?, group)]);
    Ok(h_n
        .iter()
        .zip(h_g.iter())
        .map(|(left, right)| left ^ right)
        .collect())
}

/// `M1 = H(H(N) XOR H(g) ‖ H(I) ‖ s ‖ PAD(A) ‖ PAD(B) ‖ K)`, the client's proof (RFC 5054 §2.6).
/// Every field is fixed-width. `identity` is the `accountId`, never the email, which can change.
pub fn client_proof<H: SrpHash>(
    group: Group,
    identity: &[u8],
    srp_salt: &[u8],
    client_public: &BoxedUint,
    server_public: &BoxedUint,
    session_key: &Secret<SrpSessionKey>,
) -> Result<Vec<u8>, SrpError> {
    if srp_salt.len() != SRP_SALT_LEN {
        return Err(SrpError::TranscriptFieldLength);
    }
    Ok(H::digest(&[
        &group_xor::<H>(group)?,
        &H::digest(&[identity]),
        srp_salt,
        &pad(client_public, group),
        &pad(server_public, group),
        session_key.expose(),
    ]))
}

/// `M2 = H(PAD(A) ‖ M1 ‖ K)`, the server's proof (RFC 5054 §2.6), sent only after `M1` verifies.
pub fn server_proof<H: SrpHash>(
    group: Group,
    client_public: &BoxedUint,
    client_proof: &[u8],
    session_key: &Secret<SrpSessionKey>,
) -> Result<Vec<u8>, SrpError> {
    if client_proof.len() != H::LEN {
        return Err(SrpError::TranscriptFieldLength);
    }
    Ok(H::digest(&[
        &pad(client_public, group),
        client_proof,
        session_key.expose(),
    ]))
}

/// Compares two proofs in constant time; use it, never `==`, on `M1` and `M2`. A length mismatch
/// returns `false` early, as lengths are public.
#[must_use]
pub fn proofs_match(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.ct_eq(right).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        client_premaster, client_public, multiplier, pad, scrambler, server_premaster,
        server_public, Group, Sha1Hash, SrpError,
    };
    use crate::secret::{
        kind::{SrpEphemeralSecret, SrpExponent},
        Secret,
    };
    use crypto_bigint::{BoxedUint, Resize as _};

    /// The vectors as `tools/srp_reference.py` extracted them from the RFC.
    fn appendix_b() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/vectors/rfc5054_appendix_b.json")).unwrap()
    }

    fn groups_json() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/vectors/srp_groups.json")).unwrap()
    }

    /// A field by path, without `Index` (the workspace denies `indexing_slicing`).
    fn field<'a>(value: &'a serde_json::Value, path: &[&str]) -> &'a serde_json::Value {
        path.iter()
            .fold(value, |node, key| node.get(key).expect("field present"))
    }

    #[test]
    fn the_group_table_matches_the_rfc() {
        let json = groups_json();
        let shipping = field(&json, &["groups", "4096"]);
        assert_eq!(
            super::N_4096_HEX,
            field(shipping, &["N"]).as_str().unwrap(),
            "the 4096-bit modulus must be RFC 5054 Appendix A's, byte for byte"
        );
        assert_eq!(
            u64::from(Group::RFC5054_4096.generator),
            field(shipping, &["g"]).as_u64().unwrap()
        );
        assert_eq!(Group::RFC5054_4096.bits, 4096);

        let test_only = field(&json, &["groups", "1024"]);
        assert_eq!(
            super::N_1024_HEX,
            field(test_only, &["N"]).as_str().unwrap()
        );
        assert_eq!(Group::RFC5054_1024_TEST_ONLY.generator, 2);
    }

    #[test]
    fn pad_left_pads_short_values_to_the_modulus_width() {
        let group = Group::RFC5054_1024_TEST_ONLY;
        let small = BoxedUint::from(1_u64).resize(group.bits);
        let padded = pad(&small, group);
        assert_eq!(padded.len(), 128, "1024 bits is 128 bytes");
        assert_eq!(
            padded.last().copied(),
            Some(1),
            "the value lands at the end"
        );
        assert!(
            padded.iter().rev().skip(1).all(|b| *b == 0),
            "everything above it is zero padding"
        );
    }

    /// Compared as trimmed bytes, because each value is carried at its own precision.
    #[test]
    fn rfc5054_appendix_b_vectors_pass_for_the_exchange_algebra_at_1024_sha1() {
        let json = appendix_b();
        let v = field(&json, &["vectors"]);
        let group = Group::RFC5054_1024_TEST_ONLY;

        let published = |name: &str| hex::decode(field(v, &[name]).as_str().unwrap());
        let at_modulus = |name: &str| {
            BoxedUint::from_be_slice(&hex::pad_to(&published(name), 128), group.bits).unwrap()
        };

        let a = Secret::<SrpEphemeralSecret>::from_derived_bytes(published("a"));
        let b = Secret::<SrpEphemeralSecret>::from_derived_bytes(published("b"));
        let x = Secret::<SrpExponent>::from_derived_bytes(published("x"));
        let verifier = at_modulus("v");
        let want_a = at_modulus("A");
        let want_b = at_modulus("B");

        assert_eq!(
            hex::trim(&multiplier::<Sha1Hash>(group).unwrap()),
            published("k"),
            "k = H(N || PAD(g))"
        );
        assert_eq!(
            hex::trim(&client_public(group, &a).unwrap()),
            published("A"),
            "A = g^a mod N"
        );
        assert_eq!(
            hex::trim(&server_public::<Sha1Hash>(group, &b, &verifier).unwrap()),
            published("B"),
            "B = k*v + g^b mod N"
        );
        assert_eq!(
            hex::trim(&scrambler::<Sha1Hash>(group, &want_a, &want_b).unwrap()),
            published("u"),
            "u = H(PAD(A) || PAD(B))"
        );

        let client = client_premaster::<Sha1Hash>(group, &a, &x, &want_b).unwrap();
        let server = server_premaster::<Sha1Hash>(group, &b, &verifier, &want_a).unwrap();
        assert_eq!(
            client.expose(),
            server.expose(),
            "both sides must reach the same premaster secret"
        );
        assert_eq!(
            client.expose(),
            hex::pad_to(&published("S"), 128).as_slice(),
            "S must match RFC 5054 Appendix B"
        );
    }

    #[test]
    fn a_server_public_value_of_zero_is_refused() {
        let group = Group::RFC5054_1024_TEST_ONLY;
        let a = Secret::<SrpEphemeralSecret>::from_derived_bytes(vec![7_u8; 32]);
        let x = Secret::<SrpExponent>::from_derived_bytes(vec![9_u8; 20]);
        let zero = BoxedUint::zero_with_precision(group.bits);
        // `Secret` has no `Debug` or `PartialEq`, so the error is matched, not compared.
        let refused = client_premaster::<super::Sha256Hash>(group, &a, &x, &zero);
        assert!(
            matches!(refused, Err(SrpError::PublicValueOutOfRange)),
            "B == 0 mod N must be refused, not absorbed into a session"
        );
    }

    mod hex {
        use crypto_bigint::BoxedUint;

        /// Hex to bytes; `chunks_exact` because the workspace denies `indexing_slicing`.
        pub fn decode(hex: &str) -> Vec<u8> {
            hex.as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let text = core::str::from_utf8(pair).expect("hex is ASCII");
                    u8::from_str_radix(text, 16).expect("hex digit pair")
                })
                .collect()
        }

        pub fn pad_to(bytes: &[u8], width: usize) -> Vec<u8> {
            core::iter::repeat_n(0_u8, width.saturating_sub(bytes.len()))
                .chain(bytes.iter().copied())
                .collect()
        }

        /// A value's minimal big-endian bytes, as the RFC prints it.
        pub fn trim(value: &BoxedUint) -> Vec<u8> {
            value.to_be_bytes_trimmed_vartime().to_vec()
        }
    }
}

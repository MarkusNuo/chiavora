//! The checksum is a typo aid, not integrity: a wrong key is caught by the derivation failing.
//!
//! ```text
//! CHV1-000G-40R4-0M30-E209-185G-R38E-1WCH
//! ```

use zeroize::Zeroizing;

use crate::base32::{self, Base32Error};

use crate::csprng::{self, CsprngError};
use crate::secret::{kind::SecretKeyMaterial, Secret};

/// It versions the format, not the key.
pub const PREFIX: &str = "CHV1-";

pub const PREFIX_TAG: &str = "CHV1";

/// The Secret Key's length in bytes (§2.1: 128 bits).
pub const KEY_LEN: usize = 16;

/// Base32 characters carrying key material: `ceil(128 / 5)`.
pub const DATA_CHARS: usize = 26;

pub const CHECK_CHARS: usize = 2;

pub const GROUP_LEN: usize = 4;

/// The product tag every key-material rendering begins with: `CHV1` and the Kit's `CHVKT1`.
pub const RENDERED_PREFIX: &str = "CHV";

/// Symbols in a canonical Secret Key after normalisation; the shortest key-material
/// rendering, so the length threshold for recognising a paste.
pub const RENDERED_CHARS: usize = PREFIX_TAG.len() + DATA_CHARS + CHECK_CHARS;

/// The threshold must not exceed the Kit's length, or a pasted Kit would slip under it.
const _: () = assert!(crate::emergency_kit::COMPACT_CHARS_WITHOUT_CHECKPOINT >= RENDERED_CHARS);

/// No variant carries any of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKeyError {
    WrongPrefix,
    WrongLength {
        expected: usize,
    },
    InvalidCharacter {
        at: usize,
    },
    NonCanonicalTrailingBits,
    ChecksumMismatch,
    /// No weaker source, so no retry.
    Csprng,
}

impl core::fmt::Display for SecretKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::WrongPrefix => write!(f, "a Secret Key must start with {PREFIX}"),
            Self::WrongLength { expected } => {
                write!(f, "expected {expected} base32 characters after the prefix")
            }
            Self::InvalidCharacter { at } => {
                write!(f, "character {at} is not in the base32 alphabet")
            }
            Self::NonCanonicalTrailingBits => {
                f.write_str("the final character carries non-zero padding bits")
            }
            Self::ChecksumMismatch => {
                f.write_str("the checksum does not match; check for a mistyped character")
            }
            Self::Csprng => {
                f.write_str("the platform CSPRNG failed; refusing to generate a weaker key")
            }
        }
    }
}

impl core::error::Error for SecretKeyError {}

impl From<Base32Error> for SecretKeyError {
    fn from(error: Base32Error) -> Self {
        match error {
            Base32Error::WrongLength { expected } => Self::WrongLength { expected },
            Base32Error::InvalidCharacter { at } => Self::InvalidCharacter { at },
            Base32Error::NonCanonicalTrailingBits => Self::NonCanonicalTrailingBits,
            Base32Error::ChecksumMismatch => Self::ChecksumMismatch,
        }
    }
}

impl From<CsprngError> for SecretKeyError {
    fn from(_: CsprngError) -> Self {
        Self::Csprng
    }
}

/// The Secret Key in printed form, and I1(a)'s one intended egress. It has no `Display` and
/// no `Deref`, its `Debug` is redacted, and the FFI guard does not catch it, so its only exit
/// is [`EmergencyKitLine::expose_for_printing`]. Zeroized on drop.
pub struct EmergencyKitLine(Zeroizing<String>);

impl EmergencyKitLine {
    /// For a Kit view or a PDF and nothing else.
    #[must_use]
    pub fn expose_for_printing(&self) -> &str {
        &self.0
    }
}

/// Redacted: `Debug` is what a logger and a crash reporter consume.
impl core::fmt::Debug for EmergencyKitLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmergencyKitLine(redacted)")
    }
}

pub fn generate() -> Result<Secret<SecretKeyMaterial>, SecretKeyError> {
    let mut bytes = Zeroizing::new(vec![0_u8; KEY_LEN]);
    csprng::fill_bytes(&mut bytes)?;
    Ok(Secret::from_external_bytes(bytes))
}

pub fn render(key: &Secret<SecretKeyMaterial>) -> Result<EmergencyKitLine, SecretKeyError> {
    let bytes = key.expose();
    if bytes.len() != KEY_LEN {
        return Err(SecretKeyError::WrongLength {
            expected: DATA_CHARS + CHECK_CHARS,
        });
    }
    let chars = base32::encode_with_checksum(bytes);
    let mut out = Zeroizing::new(String::with_capacity(PREFIX.len() + chars.len() + 8));
    out.push_str(PREFIX);
    out.push_str(&base32::group(&chars));
    Ok(EmergencyKitLine(out))
}

/// The public path is [`crate::entry::accept`].
pub(crate) fn decode(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretKeyError> {
    // Normalised before the prefix is matched, so `CHVI` and spaces for hyphens still decode.
    let normalised = base32::normalise_input(input);
    let symbols = normalised
        .strip_prefix(PREFIX_TAG.as_bytes())
        .ok_or(SecretKeyError::WrongPrefix)?;
    base32::decode_with_checksum(symbols, KEY_LEN).map_err(SecretKeyError::from)
}

/// Checks the tag and the length, not a full decode, so a mistyped key is caught too.
/// No defence against A8: the key has already been on the clipboard.
pub(crate) fn looks_like_rendered_key_material(input: &[u8]) -> bool {
    let normalised = base32::normalise_input(input);
    normalised.len() >= RENDERED_CHARS && normalised.starts_with(RENDERED_PREFIX.as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{decode, generate, render, SecretKeyError, DATA_CHARS, GROUP_LEN, KEY_LEN, PREFIX};
    use crate::secret::{kind::SecretKeyMaterial, Secret};
    use zeroize::Zeroizing;

    fn key(bytes: Vec<u8>) -> Secret<SecretKeyMaterial> {
        Secret::from_external_bytes(Zeroizing::new(bytes))
    }

    #[test]
    fn a_generated_key_is_128_bits_and_round_trips_through_the_rendering() {
        let secret = generate().expect("CSPRNG");
        assert_eq!(secret.len(), KEY_LEN, "§2.1: 128 bits");
        let line = render(&secret).expect("rendered");
        let decoded = decode(line.expose_for_printing().as_bytes()).expect("decoded");
        assert_eq!(&*decoded, secret.expose());
    }

    #[test]
    fn a_csprng_failure_maps_to_the_intended_variant() {
        use crate::csprng::CsprngError;

        let mapped = SecretKeyError::from(CsprngError);
        assert_eq!(mapped, SecretKeyError::Csprng);
        let text = format!("{mapped}");
        assert!(text.contains("CSPRNG"), "it must say what failed: {text}");
        assert!(
            text.contains("refusing"),
            "R1: it must say it is refusing rather than substituting: {text}"
        );
    }

    #[test]
    fn rendering_a_mis_sized_key_is_refused_rather_than_rendered_short() {
        let short = key(vec![0xAA; KEY_LEN - 1]);
        assert!(matches!(
            render(&short),
            Err(SecretKeyError::WrongLength { .. })
        ));
    }

    #[test]
    fn the_renderings_share_the_product_tag() {
        use super::RENDERED_PREFIX;
        use crate::emergency_kit::HEADER;

        assert!(super::PREFIX_TAG.starts_with(RENDERED_PREFIX));
        assert!(HEADER.starts_with(RENDERED_PREFIX));
    }

    #[test]
    fn a_pasted_secret_key_or_kit_is_recognised_and_a_password_is_not() {
        use super::looks_like_rendered_key_material as looks_like;

        let secret = generate().expect("CSPRNG");
        let line = render(&secret).expect("rendered");
        assert!(looks_like(line.expose_for_printing().as_bytes()));

        let transcribed = line
            .expose_for_printing()
            .to_lowercase()
            .replace('-', " ")
            .replacen("chv1", "chvi", 1);
        assert!(looks_like(transcribed.as_bytes()));

        let kit = crate::emergency_kit::Kit::new(
            [0x11; crate::emergency_kit::ACCOUNT_ID_LEN],
            [0x22; crate::emergency_kit::ACCOUNT_SALT_LEN],
            secret,
            None,
        )
        .expect("kit");
        assert!(looks_like(kit.render_compact().as_bytes()));

        // The third normalises to `CHV10USH1PP0`, which starts with the tag.
        for password in [
            "a-real-password",
            "correct horse battery staple",
            "chvious-hippo",
        ] {
            assert!(
                !looks_like(password.as_bytes()),
                "{password} was mistaken for key material"
            );
        }
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = generate().expect("CSPRNG");
        let b = generate().expect("CSPRNG");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn the_rendering_has_the_shape_adr_0004_specifies() {
        let line = render(&key(vec![0_u8; KEY_LEN])).expect("rendered");
        let rendered = line.expose_for_printing();
        assert!(rendered.starts_with(PREFIX));
        let body = rendered.strip_prefix(PREFIX).unwrap();
        let groups: Vec<&str> = body.split('-').collect();
        assert_eq!(groups.len(), 7, "7 groups");
        for group in &groups {
            assert_eq!(group.len(), GROUP_LEN, "{group} is not {GROUP_LEN} chars");
        }
        assert_eq!(body.replace('-', "").len(), 28, "26 key + 2 checksum");
    }

    #[test]
    fn the_emergency_kit_line_does_not_leak_through_debug() {
        let line = render(&key(vec![0xAB; KEY_LEN])).expect("rendered");
        let rendered = format!("{line:?}");
        assert_eq!(rendered, "EmergencyKitLine(redacted)");
        assert!(!rendered.contains("CHV1"));
    }

    #[test]
    fn lowercase_hyphens_and_spaces_are_accepted_on_input() {
        let secret = key(vec![0x5A; KEY_LEN]);
        let canonical = render(&secret).unwrap();
        let canonical = canonical.expose_for_printing().to_owned();

        let lower = canonical.to_lowercase();
        let no_hyphens = canonical.replace('-', "").replacen("CHV1", "CHV1-", 1);
        let spaced = canonical.replace('-', " ");

        for variant in [lower, no_hyphens, spaced] {
            let decoded = decode(variant.as_bytes())
                .unwrap_or_else(|e| panic!("{variant} should decode: {e}"));
            assert_eq!(&*decoded, secret.expose());
        }
    }

    #[test]
    fn crockford_normalises_o_to_zero_and_i_and_l_to_one() {
        let secret = key(vec![0x00; KEY_LEN]);
        let canonical = render(&secret).unwrap();
        let canonical = canonical.expose_for_printing().to_owned();
        assert!(canonical.contains('0'), "the all-zero key renders as zeros");

        for (digit, letter) in [('0', 'O'), ('0', 'o')] {
            let typo = canonical.replace(digit, &letter.to_string());
            let decoded = decode(typo.as_bytes())
                .unwrap_or_else(|e| panic!("{letter} must normalise to {digit}: {e}"));
            assert_eq!(&*decoded, secret.expose());
        }

        // A key whose rendering contains a `1`, for the I/L direction.
        let ones = key(vec![
            0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84,
            0x21, 0x08,
        ]);
        let rendered = render(&ones).unwrap();
        let rendered = rendered.expose_for_printing().to_owned();
        if rendered.contains('1') {
            for letter in ['I', 'L', 'i', 'l'] {
                let typo = rendered.replace('1', &letter.to_string());
                let decoded = decode(typo.as_bytes())
                    .unwrap_or_else(|e| panic!("{letter} must normalise to 1: {e}"));
                assert_eq!(&*decoded, ones.expose());
            }
        }
    }

    #[test]
    fn u_is_not_in_the_alphabet_and_nothing_maps_to_it() {
        let secret = key(vec![0x5A; KEY_LEN]);
        let rendered = render(&secret).unwrap();
        let rendered = rendered.expose_for_printing().to_owned();
        assert!(!rendered.contains('U'), "U must never be emitted");

        let mut chars: Vec<char> = rendered.chars().collect();
        // Position 5 is the first character after `CHV1-`.
        if let Some(slot) = chars.get_mut(5) {
            *slot = 'U';
        }
        let typo: String = chars.into_iter().collect();
        let error = decode(typo.as_bytes()).expect_err("U must be refused");
        assert!(
            matches!(error, SecretKeyError::InvalidCharacter { .. }),
            "expected InvalidCharacter, got {error:?}"
        );
    }

    #[test]
    fn a_non_canonical_trailing_character_is_refused_not_masked() {
        let secret = key(vec![0x00; KEY_LEN]);
        let line = render(&secret).unwrap();
        let text = line.expose_for_printing().to_owned();
        let symbols: String = text
            .strip_prefix(PREFIX)
            .unwrap()
            .chars()
            .filter(|c| *c != '-')
            .collect();
        // For an all-zero key the 26th character is `0`; `1` adds a non-zero padding bit.
        let mut mutated: Vec<char> = symbols.chars().collect();
        assert_eq!(mutated.get(DATA_CHARS - 1), Some(&'0'));
        if let Some(slot) = mutated.get_mut(DATA_CHARS - 1) {
            *slot = '1';
        }
        let rebuilt: String = format!("{PREFIX}{}", mutated.into_iter().collect::<String>());
        let error = decode(rebuilt.as_bytes()).expect_err("non-canonical must be refused");
        assert_eq!(error, SecretKeyError::NonCanonicalTrailingBits);
    }

    #[test]
    fn a_single_character_typo_is_caught_by_the_checksum() {
        let secret = key(vec![0x3C; KEY_LEN]);
        let line = render(&secret).unwrap();
        let text = line.expose_for_printing().to_owned();
        let mut caught = 0;
        let mut attempted = 0;
        for (index, character) in text.char_indices() {
            if character == '-' || index < PREFIX.len() {
                continue;
            }
            let replacement = if character == 'C' { 'D' } else { 'C' };
            let mut mutated: Vec<char> = text.chars().collect();
            if let Some(slot) = mutated.get_mut(index) {
                *slot = replacement;
            }
            let candidate: String = mutated.into_iter().collect();
            attempted += 1;
            match decode(candidate.as_bytes()) {
                Ok(decoded) => assert_ne!(
                    &*decoded,
                    secret.expose(),
                    "a typo decoded to the original key"
                ),
                Err(_) => caught += 1,
            }
        }
        assert!(attempted > 20, "the loop must actually mutate characters");
        // A 10-bit checksum catches about 1023 typos in 1024, not all of them.
        assert!(
            caught * 10 >= attempted * 9,
            "the checksum caught only {caught} of {attempted} single-character typos"
        );
    }

    #[test]
    fn the_wrong_prefix_and_the_wrong_length_are_refused() {
        assert_eq!(
            decode(b"CHV2-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA53").err(),
            Some(SecretKeyError::WrongPrefix)
        );
        assert!(matches!(
            decode(b"CHV1-0000").err(),
            Some(SecretKeyError::WrongLength { .. })
        ));
    }

    #[test]
    fn no_error_names_a_character_of_the_input() {
        let secret = key(vec![0x77; KEY_LEN]);
        let line = render(&secret).unwrap();
        let text = line.expose_for_printing().to_owned();
        let truncated = text.get(..text.len() - 3).unwrap_or_default().to_owned();
        for input in [String::from("nope"), truncated, format!("{text}Z")] {
            if let Err(error) = decode(input.as_bytes()) {
                let shown = format!("{error} | {error:?}");
                let body: String = text
                    .strip_prefix(PREFIX)
                    .unwrap_or_default()
                    .chars()
                    .filter(|c| *c != '-')
                    .collect();
                assert!(
                    !shown.contains(&body),
                    "the error text leaked the Secret Key: {shown}"
                );
            }
        }
    }
}

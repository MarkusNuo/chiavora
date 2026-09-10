use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::csprng::{self, CsprngError};
use crate::secret::{kind::SecretKeyMaterial, Secret};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// It versions the format, not the key.
pub const PREFIX: &str = "CHV1-";

pub const PREFIX_TAG: &str = "CHV1";

/// The Secret Key's length in bytes (§2.1: 128 bits).
pub const KEY_LEN: usize = 16;

/// Base32 characters carrying key material: `ceil(128 / 5)`.
pub const DATA_CHARS: usize = 26;

pub const CHECK_CHARS: usize = 2;

pub const GROUP_LEN: usize = 4;

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
    AmbiguousDigitOne {
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
            Self::AmbiguousDigitOne { at } => write!(
                f,
                "character {at} is '1', which could be 'I' or 'L'; \
                 check the Emergency Kit rather than guessing"
            ),
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

    let mut chars = Zeroizing::new(String::with_capacity(DATA_CHARS + CHECK_CHARS));
    for index in 0..DATA_CHARS {
        chars.push(char::from(alphabet_at(five_bits_at(bytes, index))));
    }
    let check = checksum(bytes);
    #[allow(clippy::cast_possible_truncation)]
    let high = ((check >> 5) & 0x1F) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let low = (check & 0x1F) as u8;
    chars.push(char::from(alphabet_at(high)));
    chars.push(char::from(alphabet_at(low)));

    let mut out = Zeroizing::new(String::with_capacity(PREFIX.len() + 35));
    out.push_str(PREFIX);
    for (position, character) in chars.chars().enumerate() {
        if position > 0 && position % GROUP_LEN == 0 {
            out.push('-');
        }
        out.push(character);
    }
    Ok(EmergencyKitLine(out))
}

/// The public path is [`crate::entry::accept`].
pub(crate) fn decode(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretKeyError> {
    let mut normalised: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(input.len()));
    for byte in input {
        if *byte == b'-' || byte.is_ascii_whitespace() {
            continue;
        }
        normalised.push(byte.to_ascii_uppercase());
    }

    let symbols: Zeroizing<Vec<u8>> = Zeroizing::new(
        normalised
            .strip_prefix(PREFIX_TAG.as_bytes())
            .ok_or(SecretKeyError::WrongPrefix)?
            .to_vec(),
    );

    if symbols.len() != DATA_CHARS + CHECK_CHARS {
        return Err(SecretKeyError::WrongLength {
            expected: DATA_CHARS + CHECK_CHARS,
        });
    }

    let mut values = Zeroizing::new(Vec::with_capacity(symbols.len()));
    for (at, byte) in symbols.iter().enumerate() {
        values.push(symbol_value(*byte, at)?);
    }

    let last_data = values
        .get(DATA_CHARS - 1)
        .copied()
        .ok_or(SecretKeyError::WrongLength {
            expected: DATA_CHARS + CHECK_CHARS,
        })?;
    if last_data & 0x03 != 0 {
        return Err(SecretKeyError::NonCanonicalTrailingBits);
    }

    let mut key = Zeroizing::new(vec![0_u8; KEY_LEN]);
    for (index, value) in values.iter().take(DATA_CHARS).enumerate() {
        write_five_bits(&mut key, index, *value);
    }

    let expected = checksum(&key);
    let given = u16::from(values.get(DATA_CHARS).copied().unwrap_or(0)) << 5
        | u16::from(values.get(DATA_CHARS + 1).copied().unwrap_or(0));
    if given != expected {
        return Err(SecretKeyError::ChecksumMismatch);
    }

    Ok(key)
}

fn alphabet_at(value: u8) -> u8 {
    ALPHABET
        .get(usize::from(value & 0x1F))
        .copied()
        .unwrap_or(b'A')
}

fn symbol_value(byte: u8, at: usize) -> Result<u8, SecretKeyError> {
    let mapped = match byte {
        b'0' => b'O',
        b'8' => b'B',
        b'1' => return Err(SecretKeyError::AmbiguousDigitOne { at }),
        other => other,
    };
    ALPHABET
        .iter()
        .position(|c| *c == mapped)
        .and_then(|p| u8::try_from(p).ok())
        .ok_or(SecretKeyError::InvalidCharacter { at })
}

fn five_bits_at(bytes: &[u8], index: usize) -> u8 {
    let bit = index * 5;
    let mut value = 0_u8;
    for offset in 0..5 {
        let position = bit + offset;
        let byte_index = position / 8;
        let in_byte = position % 8;
        let bit_set = bytes
            .get(byte_index)
            .copied()
            .is_some_and(|b| (b >> (7 - in_byte)) & 1 == 1);
        value = (value << 1) | u8::from(bit_set);
    }
    value
}

fn write_five_bits(bytes: &mut [u8], index: usize, value: u8) {
    let bit = index * 5;
    for offset in 0..5 {
        let position = bit + offset;
        let byte_index = position / 8;
        let in_byte = position % 8;
        let bit_set = (value >> (4 - offset)) & 1 == 1;
        if !bit_set {
            continue;
        }
        if let Some(slot) = bytes.get_mut(byte_index) {
            *slot |= 1 << (7 - in_byte);
        }
    }
}

fn checksum(key: &[u8]) -> u16 {
    let digest = Sha256::digest(key);
    let high = u16::from(digest.get(30).copied().unwrap_or(0) & 0x03);
    let low = u16::from(digest.get(31).copied().unwrap_or(0));
    (high << 8) | low
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
    fn zero_maps_to_o_and_eight_maps_to_b() {
        let secret = key(vec![0x00; KEY_LEN]);
        let canonical = render(&secret).unwrap();
        let canonical = canonical.expose_for_printing().to_owned();
        assert!(canonical.contains('A'), "sanity: the all-zero key is all A");

        for (digit, letter) in [('0', 'O'), ('8', 'B')] {
            let secret = key(vec![0xFF; KEY_LEN]);
            let line = render(&secret).unwrap();
            let text = line.expose_for_printing().to_owned();
            if !text.contains(letter) {
                continue;
            }
            let typo = text.replace(letter, &digit.to_string());
            let decoded = decode(typo.as_bytes())
                .unwrap_or_else(|e| panic!("{digit} must map to {letter}: {e}"));
            assert_eq!(&*decoded, secret.expose());
        }
    }

    #[test]
    fn the_digit_one_is_refused_rather_than_guessed() {
        let secret = key(vec![0x21; KEY_LEN]);
        let line = render(&secret).unwrap();
        let text = line.expose_for_printing().to_owned();
        let candidate = if text.contains('I') { 'I' } else { 'L' };
        if !text.contains(candidate) {
            return;
        }
        let typo = text.replacen(candidate, "1", 1);
        let error = decode(typo.as_bytes()).expect_err("'1' must be refused");
        assert!(matches!(error, SecretKeyError::AmbiguousDigitOne { .. }));
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
        assert_eq!(mutated.get(DATA_CHARS - 1), Some(&'A'));
        if let Some(slot) = mutated.get_mut(DATA_CHARS - 1) {
            *slot = 'B';
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
            decode(b"CHV1-AAAA").err(),
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

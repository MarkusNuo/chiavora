//! `docs/adr/0004`. The checksum is a per-field transcription aid, not integrity.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) const CHECK_CHARS: usize = 2;

pub(crate) const GROUP_LEN: usize = 4;

/// No variant carries any of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base32Error {
    WrongLength {
        /// Checksum included.
        expected: usize,
    },
    InvalidCharacter {
        /// Zero-based, among the base32 characters.
        at: usize,
    },
    NonCanonicalTrailingBits,
    ChecksumMismatch,
}

impl core::fmt::Display for Base32Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::WrongLength { expected } => {
                write!(f, "expected {expected} base32 characters")
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
        }
    }
}

impl core::error::Error for Base32Error {}

pub(crate) const fn data_chars(len: usize) -> usize {
    (len * 8).div_ceil(5)
}

const fn padding_bits(len: usize) -> usize {
    data_chars(len) * 5 - len * 8
}

pub(crate) fn encode_with_checksum(bytes: &[u8]) -> Zeroizing<String> {
    let chars = data_chars(bytes.len());
    // R1: `chars` comes from `bytes.len()`, the input in hand, not a declared count.
    let mut out = Zeroizing::new(String::with_capacity(chars + CHECK_CHARS));
    for index in 0..chars {
        out.push(char::from(alphabet_at(five_bits_at(bytes, index))));
    }
    let check = checksum(bytes);
    #[allow(clippy::cast_possible_truncation)]
    let high = ((check >> 5) & 0x1F) as u8;
    #[allow(clippy::cast_possible_truncation)]
    let low = (check & 0x1F) as u8;
    out.push(char::from(alphabet_at(high)));
    out.push(char::from(alphabet_at(low)));
    out
}

pub(crate) fn group(chars: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(chars.len() + chars.len() / GROUP_LEN));
    for (position, character) in chars.chars().enumerate() {
        if position > 0 && position % GROUP_LEN == 0 {
            out.push('-');
        }
        out.push(character);
    }
    out
}

/// Run it before matching any prefix, because a header such as `CHV1` may be typed as `CHVI`.
pub(crate) fn normalise_input(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    for byte in input {
        if *byte == b'-' || byte.is_ascii_whitespace() {
            continue;
        }
        out.push(normalise(byte.to_ascii_uppercase()));
    }
    out
}

const fn normalise(byte: u8) -> u8 {
    match byte {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    }
}

/// The checksum is checked last, so a malformed field says why.
pub(crate) fn decode_with_checksum(
    symbols: &[u8],
    expected_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
    let chars = data_chars(expected_len);
    let expected = chars + CHECK_CHARS;
    if symbols.len() != expected {
        return Err(Base32Error::WrongLength { expected });
    }

    let mut values = Zeroizing::new(Vec::with_capacity(symbols.len()));
    for (at, byte) in symbols.iter().enumerate() {
        values.push(symbol_value(*byte, at)?);
    }

    // Non-zero padding bits would give one value several encodings.
    let pad = padding_bits(expected_len);
    if pad > 0 {
        let last = values
            .get(chars - 1)
            .copied()
            .ok_or(Base32Error::WrongLength { expected })?;
        // `pad` is 0..5, so the mask cannot overflow.
        let mask = (1_u8 << pad) - 1;
        if last & mask != 0 {
            return Err(Base32Error::NonCanonicalTrailingBits);
        }
    }

    // R1: `expected_len` matches the number of symbols present, checked above.
    let mut bytes = Zeroizing::new(vec![0_u8; expected_len]);
    for (index, value) in values.iter().take(chars).enumerate() {
        write_five_bits(&mut bytes, index, *value);
    }

    // R1: the length was checked above, so both indices exist; a wrong digit only fails closed.
    let given = u16::from(values.get(chars).copied().unwrap_or(0)) << 5
        | u16::from(values.get(chars + 1).copied().unwrap_or(0));
    // Not constant-time: the checksum is public.
    if given != checksum(&bytes) {
        return Err(Base32Error::ChecksumMismatch);
    }

    Ok(bytes)
}

fn alphabet_at(value: u8) -> u8 {
    // R1: `& 0x1F` keeps the index inside the 32-byte table.
    ALPHABET
        .get(usize::from(value & 0x1F))
        .copied()
        .unwrap_or(b'0')
}

fn symbol_value(byte: u8, at: usize) -> Result<u8, Base32Error> {
    ALPHABET
        .iter()
        .position(|c| *c == byte)
        // R1: `position` is below 32, and a failed conversion still ends in a refusal.
        .and_then(|p| u8::try_from(p).ok())
        .ok_or(Base32Error::InvalidCharacter { at })
}

fn five_bits_at(bytes: &[u8], index: usize) -> u8 {
    let bit = index * 5;
    let mut value = 0_u8;
    for offset in 0..5 {
        let position = bit + offset;
        let bit_set = bytes
            .get(position / 8)
            .copied()
            .is_some_and(|b| (b >> (7 - position % 8)) & 1 == 1);
        value = (value << 1) | u8::from(bit_set);
    }
    value
}

fn write_five_bits(bytes: &mut [u8], index: usize, value: u8) {
    let bit = index * 5;
    for offset in 0..5 {
        let position = bit + offset;
        if (value >> (4 - offset)) & 1 == 0 {
            continue;
        }
        if let Some(slot) = bytes.get_mut(position / 8) {
            *slot |= 1 << (7 - position % 8);
        }
    }
}

pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    // R1: SHA-256 is 32 bytes, so indices 30 and 31 always exist.
    let digest = Sha256::digest(bytes);
    let high = u16::from(digest.get(30).copied().unwrap_or(0) & 0x03);
    let low = u16::from(digest.get(31).copied().unwrap_or(0));
    (high << 8) | low
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        data_chars, decode_with_checksum, encode_with_checksum, group, normalise_input,
        padding_bits, Base32Error, CHECK_CHARS,
    };

    #[test]
    fn the_character_count_and_padding_are_the_arithmetic_adr_0004_states() {
        assert_eq!(data_chars(16), 26);
        assert_eq!(padding_bits(16), 2);
        assert_eq!(data_chars(32), 52);
        assert_eq!(padding_bits(32), 4);
        for len in 1..=64 {
            assert!(
                padding_bits(len) < 5,
                "len {len} pads {}",
                padding_bits(len)
            );
            assert_eq!(data_chars(len) * 5, len * 8 + padding_bits(len));
        }
    }

    #[test]
    fn every_length_the_kit_uses_round_trips() {
        for len in 1..=40_usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| {
                    u8::try_from(i % 251)
                        .unwrap_or(0)
                        .wrapping_mul(37)
                        .wrapping_add(11)
                })
                .collect();
            let encoded = encode_with_checksum(&bytes);
            assert_eq!(encoded.chars().count(), data_chars(len) + CHECK_CHARS);
            let decoded = decode_with_checksum(encoded.as_bytes(), len)
                .unwrap_or_else(|e| panic!("len {len} did not round-trip: {e:?}"));
            assert_eq!(&*decoded, &bytes, "len {len}");
        }
    }

    #[test]
    fn grouping_is_presentation_only() {
        let bytes = [0x5A_u8; 16];
        let encoded = encode_with_checksum(&bytes);
        let grouped = group(&encoded);
        assert!(grouped.contains('-'));
        let normalised = normalise_input(grouped.as_bytes());
        assert_eq!(&*normalised, encoded.as_bytes());
    }

    #[test]
    fn crockford_normalisation_is_applied_to_the_whole_input() {
        let normalised = normalise_input(b"chv1 o0-i1-l1  ");
        assert_eq!(&*normalised, b"CHV1001111");
    }

    #[test]
    fn a_non_canonical_trailing_character_is_refused() {
        // 16 bytes leave 2 padding bits, so `1`, `2` and `3` are non-canonical in the last place.
        let bytes = [0_u8; 16];
        let encoded = encode_with_checksum(&bytes);
        let mut symbols: Vec<u8> = encoded.as_bytes().to_vec();
        for replacement in *b"123" {
            let mut mutated = symbols.clone();
            if let Some(slot) = mutated.get_mut(data_chars(16) - 1) {
                *slot = replacement;
            }
            assert_eq!(
                decode_with_checksum(&mutated, 16).err(),
                Some(Base32Error::NonCanonicalTrailingBits),
                "{} must be refused as non-canonical",
                char::from(replacement)
            );
        }
        symbols.truncate(encoded.len());
        assert!(decode_with_checksum(&symbols, 16).is_ok());
    }

    #[test]
    fn a_length_error_is_reported_before_a_checksum_error() {
        let encoded = encode_with_checksum(&[1_u8; 16]);
        let short = encoded
            .as_bytes()
            .get(..10)
            .expect("at least 10 characters");
        assert!(matches!(
            decode_with_checksum(short, 16),
            Err(Base32Error::WrongLength { .. })
        ));
    }

    #[test]
    fn a_single_character_typo_is_usually_caught() {
        // A 10-bit checksum catches about 1023 typos in 1024, not all of them.
        let bytes = [0x3C_u8; 16];
        let encoded = encode_with_checksum(&bytes);
        let symbols = encoded.as_bytes().to_vec();
        let (mut caught, mut attempted) = (0_usize, 0_usize);
        for index in 0..symbols.len() {
            let mut mutated = symbols.clone();
            let original = mutated.get(index).copied().unwrap_or(b'0');
            if let Some(slot) = mutated.get_mut(index) {
                *slot = if original == b'C' { b'D' } else { b'C' };
            }
            attempted += 1;
            match decode_with_checksum(&mutated, 16) {
                Ok(decoded) => assert_ne!(&*decoded, &bytes, "a typo decoded to the original"),
                Err(_) => caught += 1,
            }
        }
        assert!(attempted >= 28);
        assert!(
            caught * 10 >= attempted * 9,
            "caught only {caught} of {attempted}"
        );
    }
}

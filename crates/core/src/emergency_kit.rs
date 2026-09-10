//! ```text
//! CHVKT1 ‖ accountId(28) ‖ accountSalt(54) ‖ CHV1 ‖ secretKey(28) ‖ flag(1) ‖ [checkpoint(28)]
//! ```

use zeroize::Zeroizing;

use crate::base32::{self, Base32Error};
use crate::entry::{accept, EntryError, SecretKeyField};
use crate::secret::{kind::SecretKeyMaterial, Secret};
use crate::secret_key::{KEY_LEN, PREFIX_TAG};

/// It has no `I`, `L` or `O`, which normalisation would rewrite.
pub const HEADER: &str = "CHVKT1";

/// `accountId` length in bytes (`docs/adr/0005`: 128 bits).
pub const ACCOUNT_ID_LEN: usize = 16;

/// `accountSalt` length in bytes (`docs/adr/0005`: 256 bits).
pub const ACCOUNT_SALT_LEN: usize = 32;

/// Reserved checkpoint length in bytes, for when sync fills it.
pub const CHECKPOINT_LEN: usize = 16;

pub const FLAG_ABSENT: char = '0';

pub const FLAG_PRESENT: char = '1';

/// It lives in `core` because it is a security claim about the document, not layout.
pub const ADVISORY: &str = "\
Store this where a photograph of it would not be.

This sheet carries everything needed to unlock your vault except your \
password. A photograph of it, plus a guessed password, is enough. That is \
different from \"keep it safe\": a photo in a cloud backup is safe from fire \
and is not safe from this.

Anyone who has both this sheet and your password has your vault. Nobody can \
recover it for you if you lose both.";

/// Only the Secret Key is a [`Secret`]; the other two are not secret under the threat model.
pub struct Kit {
    account_id: [u8; ACCOUNT_ID_LEN],
    account_salt: [u8; ACCOUNT_SALT_LEN],
    secret_key: Secret<SecretKeyMaterial>,
    checkpoint: Option<[u8; CHECKPOINT_LEN]>,
}

/// Redacted: together the fields are what makes a photograph a break, so none is printed.
impl core::fmt::Debug for Kit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Kit(redacted, checkpoint: {})",
            if self.checkpoint.is_some() {
                "present"
            } else {
                "absent"
            }
        )
    }
}

/// No variant carries any of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitError {
    WrongHeader,
    WrongLength {
        expected: usize,
    },
    /// Each field has its own checksum so the user knows which line to check.
    BadField {
        field: Field,
        cause: Base32Error,
    },
    BadPresenceFlag,
    Entry(EntryError),
    WrongFieldLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    AccountId,
    AccountSalt,
    SecretKey,
    Checkpoint,
}

impl core::fmt::Display for Field {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            Self::AccountId => "account",
            Self::AccountSalt => "salt",
            Self::SecretKey => "secret key",
            Self::Checkpoint => "checkpoint",
        })
    }
}

impl core::fmt::Display for KitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::WrongHeader => write!(f, "an Emergency Kit begins with {HEADER}"),
            Self::WrongLength { expected } => {
                write!(f, "expected {expected} base32 characters in the Kit")
            }
            Self::BadField { field, cause } => write!(f, "the {field} line: {cause}"),
            Self::BadPresenceFlag => f.write_str("the checkpoint presence flag is not 0 or 1"),
            Self::Entry(inner) => write!(f, "{inner}"),
            Self::WrongFieldLength => f.write_str("a Kit field is the wrong length"),
        }
    }
}

impl core::error::Error for KitError {}

const fn field_chars(len: usize) -> usize {
    base32::data_chars(len) + base32::CHECK_CHARS
}

pub const COMPACT_CHARS_WITHOUT_CHECKPOINT: usize = HEADER.len()
    + field_chars(ACCOUNT_ID_LEN)
    + field_chars(ACCOUNT_SALT_LEN)
    + 4 // the CHV1 tag on the Secret Key field
    + field_chars(KEY_LEN)
    + 1; // the presence flag

pub const COMPACT_CHARS_WITH_CHECKPOINT: usize =
    COMPACT_CHARS_WITHOUT_CHECKPOINT + field_chars(CHECKPOINT_LEN);

impl Kit {
    pub fn new(
        account_id: [u8; ACCOUNT_ID_LEN],
        account_salt: [u8; ACCOUNT_SALT_LEN],
        secret_key: Secret<SecretKeyMaterial>,
        checkpoint: Option<[u8; CHECKPOINT_LEN]>,
    ) -> Result<Self, KitError> {
        if secret_key.len() != KEY_LEN {
            return Err(KitError::WrongFieldLength);
        }
        Ok(Self {
            account_id,
            account_salt,
            secret_key,
            checkpoint,
        })
    }

    #[must_use]
    pub const fn account_id(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.account_id
    }

    #[must_use]
    pub const fn account_salt(&self) -> &[u8; ACCOUNT_SALT_LEN] {
        &self.account_salt
    }

    #[must_use]
    pub const fn secret_key(&self) -> &Secret<SecretKeyMaterial> {
        &self.secret_key
    }

    /// Absence is encoded by a presence flag, never by zero bytes.
    #[must_use]
    pub const fn checkpoint(&self) -> Option<&[u8; CHECKPOINT_LEN]> {
        self.checkpoint.as_ref()
    }

    #[must_use]
    pub fn render_compact(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(String::with_capacity(COMPACT_CHARS_WITH_CHECKPOINT));
        chars.push_str(HEADER);
        chars.push_str(&base32::encode_with_checksum(&self.account_id));
        chars.push_str(&base32::encode_with_checksum(&self.account_salt));
        chars.push_str(PREFIX_TAG);
        chars.push_str(&base32::encode_with_checksum(self.secret_key.expose()));
        match &self.checkpoint {
            Some(checkpoint) => {
                chars.push(FLAG_PRESENT);
                chars.push_str(&base32::encode_with_checksum(checkpoint));
            }
            None => chars.push(FLAG_ABSENT),
        }
        base32::group(&chars)
    }
}

/// The Secret Key goes through [`crate::entry::accept`] like any other input.
pub fn parse(input: &[u8]) -> Result<Kit, KitError> {
    // Normalise before matching the header: `CHVKT1` may have been typed as `CHVKTI`.
    let normalised = base32::normalise_input(input);
    let body = normalised
        .strip_prefix(HEADER.as_bytes())
        .ok_or(KitError::WrongHeader)?;

    let mut at = 0_usize;
    let account_id = take_field::<ACCOUNT_ID_LEN>(body, &mut at, Field::AccountId)?;
    let account_salt = take_field::<ACCOUNT_SALT_LEN>(body, &mut at, Field::AccountSalt)?;

    // The `CHV1` tag stays on, so the entry point sees what a person would type.
    let key_chars = PREFIX_TAG.len() + field_chars(KEY_LEN);
    let key_slice = body.get(at..at + key_chars).ok_or(KitError::WrongLength {
        expected: COMPACT_CHARS_WITHOUT_CHECKPOINT,
    })?;
    at += key_chars;
    let secret_key = accept::<SecretKeyField>(key_slice.to_vec()).map_err(KitError::Entry)?;

    let flag = body.get(at).copied().ok_or(KitError::WrongLength {
        expected: COMPACT_CHARS_WITHOUT_CHECKPOINT,
    })?;
    at += 1;

    let checkpoint = match flag {
        b'0' => None,
        b'1' => Some(take_field::<CHECKPOINT_LEN>(
            body,
            &mut at,
            Field::Checkpoint,
        )?),
        _ => return Err(KitError::BadPresenceFlag),
    };

    // Trailing characters are refused, so a Kit has exactly one rendering.
    if at != body.len() {
        return Err(KitError::WrongLength {
            expected: if checkpoint.is_some() {
                COMPACT_CHARS_WITH_CHECKPOINT
            } else {
                COMPACT_CHARS_WITHOUT_CHECKPOINT
            },
        });
    }

    Kit::new(account_id, account_salt, secret_key, checkpoint)
}

fn take_field<const N: usize>(
    body: &[u8],
    at: &mut usize,
    field: Field,
) -> Result<[u8; N], KitError> {
    let chars = field_chars(N);
    let slice = body.get(*at..*at + chars).ok_or(KitError::WrongLength {
        expected: COMPACT_CHARS_WITHOUT_CHECKPOINT,
    })?;
    *at += chars;
    let bytes = base32::decode_with_checksum(slice, N)
        .map_err(|cause| KitError::BadField { field, cause })?;
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        parse, Field, Kit, KitError, ACCOUNT_ID_LEN, ACCOUNT_SALT_LEN, ADVISORY, CHECKPOINT_LEN,
        COMPACT_CHARS_WITHOUT_CHECKPOINT, COMPACT_CHARS_WITH_CHECKPOINT, FLAG_ABSENT, HEADER,
    };
    use crate::secret_key::{generate, KEY_LEN};

    fn kit(checkpoint: Option<[u8; CHECKPOINT_LEN]>) -> Kit {
        Kit::new(
            [0x11; ACCOUNT_ID_LEN],
            [0x22; ACCOUNT_SALT_LEN],
            generate().expect("CSPRNG"),
            checkpoint,
        )
        .expect("a well-formed Kit")
    }

    #[test]
    fn the_header_survives_its_own_normalisation() {
        let normalised = crate::base32::normalise_input(HEADER.as_bytes());
        assert_eq!(
            &*normalised,
            HEADER.as_bytes(),
            "the header must be a fixed point of the input normalisation"
        );
        for source in ['I', 'L', 'O'] {
            assert!(
                !HEADER.contains(source),
                "{source} is a normalisation source and cannot appear in the header"
            );
        }
        let tag = crate::base32::normalise_input(super::PREFIX_TAG.as_bytes());
        assert_eq!(&*tag, super::PREFIX_TAG.as_bytes());
    }

    #[test]
    fn a_kit_round_trips_and_carries_all_four_derivation_inputs_minus_the_password() {
        let original = kit(None);
        let rendered = original.render_compact();
        let parsed = parse(rendered.as_bytes()).expect("round-trip");

        assert_eq!(parsed.account_id(), original.account_id());
        assert_eq!(parsed.account_salt(), original.account_salt());
        assert_eq!(parsed.secret_key().expose(), original.secret_key().expose());
        assert_eq!(parsed.checkpoint(), None);
        assert_eq!(parsed.secret_key().len(), KEY_LEN);
    }

    #[test]
    fn absent_is_not_zero() {
        let absent = kit(None);
        let zeros = kit(Some([0_u8; CHECKPOINT_LEN]));

        assert_eq!(absent.checkpoint(), None);
        assert_eq!(zeros.checkpoint(), Some(&[0_u8; CHECKPOINT_LEN]));

        let a = absent.render_compact();
        let z = zeros.render_compact();
        assert_ne!(*a, *z, "absent and zero must not render identically");

        assert_eq!(parse(a.as_bytes()).unwrap().checkpoint(), None);
        assert_eq!(
            parse(z.as_bytes()).unwrap().checkpoint(),
            Some(&[0_u8; CHECKPOINT_LEN])
        );
    }

    #[test]
    fn the_reserved_field_costs_one_character_when_absent() {
        let absent = kit(None).render_compact();
        let present = kit(Some([0x5A; CHECKPOINT_LEN])).render_compact();
        let flat = |s: &str| s.chars().filter(|c| *c != '-').collect::<String>();
        assert_eq!(flat(&absent).len(), COMPACT_CHARS_WITHOUT_CHECKPOINT);
        assert_eq!(flat(&present).len(), COMPACT_CHARS_WITH_CHECKPOINT);
        // The flat form, because grouping in fours puts a hyphen inside the header.
        assert!(flat(&absent).starts_with(HEADER));
        assert!(flat(&present).starts_with(HEADER));
    }

    #[test]
    fn r6_the_header_is_not_exempt_from_normalisation() {
        let original = kit(None);
        let rendered = original.render_compact().to_string();
        for variant in [
            rendered.to_lowercase(),
            rendered.replace('-', ""),
            rendered.replace('-', " "),
            rendered.to_uppercase(),
            rendered.replacen("CHVKT1", "chvkt1", 1),
            format!("  {rendered}\n"),
        ] {
            let parsed = parse(variant.as_bytes())
                .unwrap_or_else(|e| panic!("{variant:?} should parse: {e}"));
            assert_eq!(parsed.secret_key().expose(), original.secret_key().expose());
        }
    }

    #[test]
    fn a_typo_names_the_field_it_is_in() {
        let rendered = kit(None).render_compact().to_string();
        let flat: Vec<char> = rendered.chars().filter(|c| *c != '-').collect();

        // A character inside the accountId field, which starts after the header.
        let mut mutated = flat.clone();
        let index = HEADER.len() + 3;
        let original = mutated
            .get(index)
            .copied()
            .expect("inside the accountId field");
        if let Some(slot) = mutated.get_mut(index) {
            *slot = if original == 'C' { 'D' } else { 'C' };
        }
        let text: String = mutated.into_iter().collect();
        match parse(text.as_bytes()) {
            Err(KitError::BadField { field, .. }) => assert_eq!(field, Field::AccountId),
            other => panic!("expected a named field, got {other:?}"),
        }
    }

    #[test]
    fn trailing_characters_are_refused_not_ignored() {
        let rendered = kit(None).render_compact().to_string();
        assert!(matches!(
            parse(format!("{rendered}ZZZZ").as_bytes()),
            Err(KitError::WrongLength { .. })
        ));
    }

    #[test]
    fn a_bad_presence_flag_is_refused() {
        let rendered = kit(None).render_compact().to_string();
        let flat: String = rendered.chars().filter(|c| *c != '-').collect();
        let mut chars: Vec<char> = flat.chars().collect();
        let last = chars.len() - 1;
        assert_eq!(
            chars.get(last).copied(),
            Some(FLAG_ABSENT),
            "the flag is last when absent"
        );
        if let Some(slot) = chars.get_mut(last) {
            *slot = 'Z';
        }
        let text: String = chars.into_iter().collect();
        assert_eq!(
            parse(text.as_bytes()).err(),
            Some(KitError::BadPresenceFlag)
        );
    }

    #[test]
    fn the_wrong_header_is_refused() {
        // The flat form, because grouping puts a hyphen inside the header.
        let rendered = kit(None).render_compact().to_string();
        let flat: String = rendered.chars().filter(|c| *c != '-').collect();
        let text = flat.replacen("CHVKT1", "CHVKT2", 1);
        assert_ne!(text, flat, "the substitution must have applied");
        assert_eq!(parse(text.as_bytes()).err(), Some(KitError::WrongHeader));
    }

    #[test]
    fn the_advisory_says_what_a_photograph_costs() {
        assert!(ADVISORY.contains("photograph"));
        assert!(
            ADVISORY.contains("plus a guessed password"),
            "the advisory must say what a photograph is sufficient for"
        );
        assert!(
            ADVISORY.contains("different from \"keep it safe\""),
            "the advisory must contrast with \"keep it safe\", not merely avoid it"
        );
        assert!(
            ADVISORY.contains("Nobody can"),
            "N2/N3: the Kit must say the loss is unrecoverable"
        );
    }

    #[test]
    fn no_error_leaks_the_kit() {
        let rendered = kit(None).render_compact().to_string();
        let flat: String = rendered.chars().filter(|c| *c != '-').collect();
        for input in [
            String::from("nope"),
            flat.get(..40).unwrap_or_default().to_owned(),
            format!("{flat}ZZZZ"),
        ] {
            if let Err(error) = parse(input.as_bytes()) {
                let shown = format!("{error} | {error:?}");
                assert!(
                    !shown.contains(flat.get(7..40).unwrap_or("unreachable")),
                    "the error text leaked the Kit: {shown}"
                );
            }
        }
    }
}

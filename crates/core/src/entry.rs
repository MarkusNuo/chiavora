//! The one path by which raw input becomes key material (I1(a)).

use zeroize::Zeroizing;

use unicode_general_category::{get_general_category, GeneralCategory};
use unicode_normalization::UnicodeNormalization;

use crate::secret::{kind, ExternalKind, Secret, SecretKind};

/// Not a password policy: it stops a hostile host handing Argon2id a gigabyte.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// Far above the 39-character rendering, so a pasted Kit line with surrounding text still fits.
pub const MAX_SECRET_KEY_BYTES: usize = 256;

/// No variant carries any of the input, since an error here is likely to be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    Empty,
    TooLong {
        max: usize,
    },
    NotUtf8,
    ControlCharacter,
    /// A later Unicode version could give it a decomposition and change the password's bytes.
    UnassignedCodePoint,
    SecretKeyFormat(crate::secret_key::SecretKeyError),
    /// The key has already been on the clipboard by then; the refusal cannot undo that.
    PastedKeyMaterial,
}

impl core::fmt::Display for EntryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Empty => f.write_str("the field was empty"),
            Self::TooLong { max } => {
                write!(f, "input exceeds this entry point's bound of {max} bytes")
            }
            Self::NotUtf8 => f.write_str("the password field did not contain text"),
            Self::ControlCharacter => f.write_str("a password cannot contain a control character"),
            Self::UnassignedCodePoint => f.write_str(
                "a password cannot contain a character this build's Unicode version does not \
                 assign",
            ),
            Self::SecretKeyFormat(inner) => write!(f, "{inner}"),
            Self::PastedKeyMaterial => f.write_str(
                "this looks like a Secret Key or an Emergency Kit; type it or scan the QR code \
                 rather than pasting it",
            ),
        }
    }
}

impl core::error::Error for EntryError {}

mod sealed {
    pub trait Sealed {}
}

pub trait EntryPoint: sealed::Sealed {
    type Yields: SecretKind + ExternalKind;

    const NAME: &'static str;

    fn transform(raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, EntryError>;
}

pub fn accept<P: EntryPoint>(raw: Vec<u8>) -> Result<Secret<P::Yields>, EntryError> {
    // Wrapped before the first check runs: rejected input is wiped too.
    let raw = Zeroizing::new(raw);
    let material = P::transform(raw)?;
    Ok(Secret::from_external_bytes(material))
}

/// NFC and nothing else (no trimming, case change or width mapping), so one typed password
/// gives the same bytes on every device.
pub struct PasswordField;

impl sealed::Sealed for PasswordField {}

impl EntryPoint for PasswordField {
    type Yields = kind::AccountPassword;

    const NAME: &'static str = "password field";

    fn transform(raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, EntryError> {
        if raw.is_empty() {
            return Err(EntryError::Empty);
        }
        if raw.len() > MAX_PASSWORD_BYTES {
            return Err(EntryError::TooLong {
                max: MAX_PASSWORD_BYTES,
            });
        }
        let text = core::str::from_utf8(&raw).map_err(|_| EntryError::NotUtf8)?;
        // Checked before normalizing, so the error is about what was typed.
        for ch in text.chars() {
            if ch.is_control() {
                return Err(EntryError::ControlCharacter);
            }
            if get_general_category(ch) == GeneralCategory::Unassigned {
                return Err(EntryError::UnassignedCodePoint);
            }
        }
        let composed: Zeroizing<String> = Zeroizing::new(text.nfc().collect());
        // NFC can lengthen the input, so the bound is checked again.
        if composed.len() > MAX_PASSWORD_BYTES {
            return Err(EntryError::TooLong {
                max: MAX_PASSWORD_BYTES,
            });
        }
        Ok(Zeroizing::new(composed.as_bytes().to_vec()))
    }
}

pub struct SecretKeyField;

impl sealed::Sealed for SecretKeyField {}

impl EntryPoint for SecretKeyField {
    type Yields = kind::SecretKeyMaterial;

    const NAME: &'static str = "Secret Key field";

    fn transform(raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, EntryError> {
        if raw.is_empty() {
            return Err(EntryError::Empty);
        }
        if raw.len() > MAX_SECRET_KEY_BYTES {
            return Err(EntryError::TooLong {
                max: MAX_SECRET_KEY_BYTES,
            });
        }
        crate::secret_key::decode(&raw).map_err(EntryError::SecretKeyFormat)
    }
}

/// A pasted Secret Key or Kit line is refused (A8); otherwise exactly [`PasswordField`].
pub struct ClipboardPaste;

impl sealed::Sealed for ClipboardPaste {}

impl EntryPoint for ClipboardPaste {
    type Yields = kind::AccountPassword;

    const NAME: &'static str = "clipboard paste";

    fn transform(raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, EntryError> {
        // The bound comes first: the key-material check normalises a copy.
        if raw.is_empty() {
            return Err(EntryError::Empty);
        }
        if raw.len() > MAX_PASSWORD_BYTES {
            return Err(EntryError::TooLong {
                max: MAX_PASSWORD_BYTES,
            });
        }
        // Before the password checks, so a pasted Kit line gets the right error.
        if crate::secret_key::looks_like_rendered_key_material(&raw) {
            return Err(EntryError::PastedKeyMaterial);
        }
        PasswordField::transform(raw)
    }
}

/// Exactly one trailing `\n` or `\r\n` is removed as transport framing; spaces are kept.
pub struct CliStdin;

impl sealed::Sealed for CliStdin {}

impl EntryPoint for CliStdin {
    type Yields = kind::AccountPassword;

    const NAME: &'static str = "CLI stdin";

    fn transform(mut raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, EntryError> {
        // `\r\n` is checked first, or a CRLF line would keep its `\r`.
        let terminator = if raw.ends_with(b"\r\n") {
            2
        } else {
            usize::from(raw.ends_with(b"\n"))
        };
        let keep = raw.len().saturating_sub(terminator);
        raw.truncate(keep);
        PasswordField::transform(raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStatus {
    CoveredInCore,
    CarriesNoSecret,
    Owed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRecord {
    pub surface: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct EntryPointRecord {
    pub name: &'static str,
    pub status: EntryStatus,
    pub host: Option<HostRecord>,
    pub yields: Option<&'static str>,
    pub blocked_on: Option<&'static str>,
    pub resolved_by: Option<&'static str>,
}

pub const REGISTRY: [EntryPointRecord; 6] = [
    EntryPointRecord {
        name: "password field",
        status: EntryStatus::CoveredInCore,
        yields: Some("AccountPassword"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("nothing about the bytes it accepts is undecided"),
    },
    EntryPointRecord {
        name: "Secret Key field",
        // The formatted string is the key, so decoding it above `core` would
        // break N1.
        status: EntryStatus::CoveredInCore,
        yields: Some("SecretKey"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("the CHV1- format (docs/adr/0004)"),
    },
    EntryPointRecord {
        name: "Emergency Kit QR decode path",
        // The QR payload is the Kit's compact rendering, so this goes through
        // `emergency_kit::parse` and from there through `SecretKeyField`.
        status: EntryStatus::CoveredInCore,
        yields: Some("SecretKey"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("the Kit format (docs/adr/0004)"),
    },
    EntryPointRecord {
        name: "clipboard paste",
        status: EntryStatus::CoveredInCore,
        yields: Some("AccountPassword"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("the password only; a pasted Kit line is refused"),
    },
    EntryPointRecord {
        name: "CLI stdin",
        status: EntryStatus::CoveredInCore,
        yields: Some("AccountPassword"),
        host: Some(HostRecord { surface: "cli" }),
        blocked_on: None,
        resolved_by: Some("the password only; the CLI unlocks, it does not enroll"),
    },
    EntryPointRecord {
        name: "inbound native messaging",
        // The extension holds no keys (§3.3), so nothing may brand bytes here.
        status: EntryStatus::CarriesNoSecret,
        yields: None,
        host: None,
        blocked_on: None,
        resolved_by: Some("neither secret crosses here"),
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{accept, EntryError, EntryPoint, PasswordField, MAX_PASSWORD_BYTES};

    #[test]
    fn i1a_the_password_field_brands_its_input() {
        let secret = accept::<PasswordField>(b"correct-horse-battery-staple".to_vec())
            .expect("a plain ASCII password is accepted");
        assert_eq!(secret.expose(), b"correct-horse-battery-staple");
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("AccountPassword"), "{rendered}");
        assert!(!rendered.contains("horse"), "{rendered}");
    }

    #[test]
    fn an_empty_password_field_is_refused() {
        assert_eq!(
            accept::<PasswordField>(Vec::new()).err(),
            Some(EntryError::Empty)
        );
    }

    #[test]
    fn the_resource_bound_is_enforced_and_is_not_a_policy() {
        let ok = vec![b'a'; MAX_PASSWORD_BYTES];
        assert!(
            accept::<PasswordField>(ok).is_ok(),
            "the bound is inclusive"
        );
        let too_long = vec![b'a'; MAX_PASSWORD_BYTES + 1];
        assert_eq!(
            accept::<PasswordField>(too_long).err(),
            Some(EntryError::TooLong {
                max: MAX_PASSWORD_BYTES
            })
        );
        assert!(accept::<PasswordField>(b"a".to_vec()).is_ok());
    }

    #[test]
    fn the_two_forms_of_one_typed_password_derive_one_byte_sequence() {
        // U+00F6 composed against o + U+0308 decomposed.
        let composed = "passw\u{f6}rd".as_bytes().to_vec();
        let decomposed = "passwo\u{308}rd".as_bytes().to_vec();
        assert_ne!(composed, decomposed, "the two forms really do differ");

        let a = accept::<PasswordField>(composed.clone()).expect("composed is accepted");
        let b = accept::<PasswordField>(decomposed).expect("decomposed is accepted");
        assert_eq!(
            a.expose(),
            b.expose(),
            "two spellings of one password still derive two keys"
        );
        assert_eq!(
            a.expose(),
            composed.as_slice(),
            "NFC is the composed form, so that is what should be hashed"
        );
    }

    #[test]
    fn nfc_and_nothing_else() {
        for input in [
            &b" leading space is part of the password"[..],
            &b"trailing space is part of the password "[..],
            &b"  both  "[..],
            "CaseIsPreserved".as_bytes(),
            // Fullwidth A (U+FF21): NFKC would map it, NFC does not.
            "\u{ff21}bc".as_bytes(),
            "a\u{3000}b".as_bytes(),
        ] {
            let secret = accept::<PasswordField>(input.to_vec()).expect("accepted");
            assert_eq!(
                secret.expose(),
                input,
                "input {input:?} was altered by something other than NFC"
            );
        }
    }

    #[test]
    fn control_characters_and_unassigned_code_points_are_refused_by_name() {
        for input in [&b"\ttab"[..], &b"newline\n"[..], &b"nul\0"[..]] {
            assert_eq!(
                accept::<PasswordField>(input.to_vec()).err(),
                Some(EntryError::ControlCharacter),
                "input {input:?} must be refused as a control character"
            );
        }
        // U+0378 is unassigned in every Unicode version to date.
        assert_eq!(
            accept::<PasswordField>("bad\u{378}".as_bytes().to_vec()).err(),
            Some(EntryError::UnassignedCodePoint)
        );
        assert_eq!(
            accept::<PasswordField>(vec![0xFF, 0xFE]).err(),
            Some(EntryError::NotUtf8)
        );
    }

    #[test]
    fn normalization_is_idempotent_so_a_stored_password_re_derives() {
        let once = accept::<PasswordField>("passwo\u{308}rd".as_bytes().to_vec())
            .expect("accepted")
            .expose()
            .to_vec();
        let twice = accept::<PasswordField>(once.clone())
            .expect("accepted")
            .expose()
            .to_vec();
        assert_eq!(
            once, twice,
            "NFC applied twice differs from NFC applied once"
        );
    }

    #[test]
    fn no_error_variant_can_carry_the_input() {
        let secret_ish = "s3cr3t-p4ssw0rd";
        let errors = [
            accept::<PasswordField>(Vec::new()).err(),
            accept::<PasswordField>(vec![b'x'; MAX_PASSWORD_BYTES + 1]).err(),
            accept::<PasswordField>(format!("{secret_ish}\u{f6}").into_bytes()).err(),
            accept::<PasswordField>(format!(" {secret_ish}").into_bytes()).err(),
        ];
        for error in errors.into_iter().flatten() {
            let shown = format!("{error} | {error:?}");
            assert!(
                !shown.contains("s3cr3t"),
                "error text leaked input: {shown}"
            );
        }
    }

    #[test]
    fn the_secret_key_field_refuses_empty_and_over_long_input() {
        use super::{SecretKeyField, MAX_SECRET_KEY_BYTES};

        assert_eq!(
            accept::<SecretKeyField>(Vec::new()).err(),
            Some(EntryError::Empty)
        );
        assert_eq!(
            accept::<SecretKeyField>(vec![b'0'; MAX_SECRET_KEY_BYTES + 1]).err(),
            Some(EntryError::TooLong {
                max: MAX_SECRET_KEY_BYTES
            })
        );
        let padded = format!(
            "{}{}",
            " ".repeat(MAX_SECRET_KEY_BYTES - 40),
            "CHV1-0000-0000-0000-0000-0000-0000-00XV"
        );
        assert!(padded.len() < MAX_SECRET_KEY_BYTES);
        assert!(accept::<SecretKeyField>(padded.into_bytes()).is_ok());
    }

    #[test]
    fn the_clipboard_carries_the_password_and_refuses_a_pasted_kit_line() {
        use super::ClipboardPaste;
        use crate::emergency_kit::{Kit, ACCOUNT_ID_LEN, ACCOUNT_SALT_LEN};

        let secret = accept::<ClipboardPaste>(b"correct-horse-battery-staple".to_vec())
            .expect("a plain ASCII password pastes");
        assert!(format!("{secret:?}").contains("AccountPassword"));

        let key = crate::secret_key::generate().expect("CSPRNG");
        let line = crate::secret_key::render(&key).expect("rendered");
        assert_eq!(
            accept::<ClipboardPaste>(line.expose_for_printing().as_bytes().to_vec()).err(),
            Some(EntryError::PastedKeyMaterial)
        );

        let kit =
            Kit::new([0x11; ACCOUNT_ID_LEN], [0x22; ACCOUNT_SALT_LEN], key, None).expect("kit");
        assert_eq!(
            accept::<ClipboardPaste>(kit.render_compact().as_bytes().to_vec()).err(),
            Some(EntryError::PastedKeyMaterial)
        );
    }

    #[test]
    fn the_clipboard_checks_its_resource_bound_before_it_normalises() {
        // Over-long and key-like, so the error shows which check ran first.
        use super::ClipboardPaste;

        let mut huge = b"CHV1".to_vec();
        huge.extend(std::iter::repeat_n(b'0', MAX_PASSWORD_BYTES));
        assert_eq!(
            accept::<ClipboardPaste>(huge).err(),
            Some(EntryError::TooLong {
                max: MAX_PASSWORD_BYTES
            }),
            "the bound must refuse before the normalisation pass runs"
        );
    }

    #[test]
    fn stdin_strips_one_line_terminator_as_transport_framing() {
        use super::CliStdin;

        for raw in [
            &b"correct-horse-battery-staple"[..],
            &b"correct-horse-battery-staple\n"[..],
            &b"correct-horse-battery-staple\r\n"[..],
        ] {
            let accepted = accept::<CliStdin>(raw.to_vec());
            assert!(accepted.is_ok(), "{raw:?} was refused: {accepted:?}");
            let secret = accepted.expect("just asserted");
            assert_eq!(
                secret.expose(),
                b"correct-horse-battery-staple",
                "the terminator reached the secret"
            );
        }
    }

    #[test]
    fn the_framing_rule_is_not_a_trim() {
        use super::CliStdin;

        for (raw, expected) in [
            (&b"a-real-password \n"[..], &b"a-real-password "[..]),
            (&b" a-real-password\n"[..], &b" a-real-password"[..]),
            (&b"a-real-password\r\n"[..], &b"a-real-password"[..]),
            (&b"a-real-password"[..], &b"a-real-password"[..]),
        ] {
            let result = accept::<CliStdin>(raw.to_vec());
            assert!(result.is_ok(), "{raw:?} was refused: {:?}", result.err());
            let secret = result.expect("checked on the line above");
            assert_eq!(
                secret.expose(),
                expected,
                "{raw:?} did not strip exactly one terminator and leave the rest alone"
            );
        }

        for raw in [&b"a-real-password\n\n"[..], &b"a-real-password\t"[..]] {
            assert_eq!(
                accept::<CliStdin>(raw.to_vec()).err(),
                Some(EntryError::ControlCharacter),
                "{raw:?} should have been refused as a control character"
            );
        }
    }

    #[test]
    fn every_entry_point_names_itself_the_way_the_registry_does() {
        use super::{CliStdin, ClipboardPaste, EntryStatus, SecretKeyField, REGISTRY};

        let covered: Vec<&str> = REGISTRY
            .iter()
            .filter(|r| r.status == EntryStatus::CoveredInCore)
            .map(|r| r.name)
            .collect();
        for name in [
            PasswordField::NAME,
            SecretKeyField::NAME,
            ClipboardPaste::NAME,
            CliStdin::NAME,
        ] {
            assert!(covered.contains(&name), "{name} is not a covered row");
        }
    }
}

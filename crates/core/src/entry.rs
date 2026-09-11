//! The one path by which raw input becomes key material (I1(a)).

use zeroize::Zeroizing;

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
    NormalizationUndecided,
    SurroundingWhitespace,
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
            Self::NormalizationUndecided => f.write_str(
                "non-ASCII input is refused until password normalization is decided",
            ),
            Self::SurroundingWhitespace => f.write_str(
                "leading or trailing whitespace is refused until trimming is decided",
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
        if !raw.is_ascii() {
            return Err(EntryError::NormalizationUndecided);
        }
        let surrounded = raw.first().is_some_and(u8::is_ascii_whitespace)
            || raw.last().is_some_and(u8::is_ascii_whitespace);
        if surrounded {
            return Err(EntryError::SurroundingWhitespace);
        }
        Ok(raw)
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
    pub gate_phrase: &'static str,
    pub statement: &'static str,
    pub status: EntryStatus,
    pub host: Option<HostRecord>,
    pub yields: Option<&'static str>,
    pub blocked_on: Option<&'static str>,
    pub resolved_by: Option<&'static str>,
}

pub const REGISTRY: [EntryPointRecord; 6] = [
    EntryPointRecord {
        name: "password field",
        gate_phrase: "the password field",
        statement: "",
        status: EntryStatus::CoveredInCore,
        yields: Some("AccountPassword"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("built; nothing about the bytes it accepts is undecided"),
    },
    EntryPointRecord {
        name: "Secret Key field",
        gate_phrase: "the Secret Key field",
        statement: "",
        status: EntryStatus::CoveredInCore,
        yields: Some("SecretKey"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("docs/adr/0004 decided the CHV1- format"),
    },
    EntryPointRecord {
        name: "Emergency Kit QR decode path",
        gate_phrase: "the Emergency Kit QR decode path",
        statement: "",
        status: EntryStatus::CoveredInCore,
        yields: Some("SecretKey"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some("docs/adr/0004 closed the format half; built the Kit"),
    },
    EntryPointRecord {
        name: "clipboard paste",
        gate_phrase: "clipboard paste",
        statement: "",
        status: EntryStatus::CoveredInCore,
        yields: Some("AccountPassword"),
        host: Some(HostRecord {
            surface: "mobile/app",
        }),
        blocked_on: None,
        resolved_by: Some(" - the password only, and a pasted Kit line is refused"),
    },
    EntryPointRecord {
        name: "CLI stdin",
        gate_phrase: "CLI stdin",
        statement: "",
        status: EntryStatus::CoveredInCore,
        yields: Some("AccountPassword"),
        host: Some(HostRecord {
            surface: "cli",
        }),
        blocked_on: None,
        resolved_by: Some(
            " - the password only; the CLI unlocks an enrolled vault and does not enroll",
        ),
    },
    EntryPointRecord {
        name: "inbound native messaging",
        gate_phrase: "inbound native messaging",
        statement: "",
        // The extension holds no keys (§3.3), so nothing may brand bytes here.
        status: EntryStatus::CarriesNoSecret,
        yields: None,
        host: None,
        blocked_on: None,
        resolved_by: Some(" - neither secret crosses here, and no EntryPoint may exist"),
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
    fn non_ascii_input_is_refused_rather_than_normalized_by_guesswork() {
        // U+00F6 composed against o + U+0308 decomposed.
        let composed = "passw\u{f6}rd".as_bytes().to_vec();
        let decomposed = "passwo\u{308}rd".as_bytes().to_vec();
        assert_ne!(composed, decomposed, "the two forms really do differ");
        for form in [composed, decomposed] {
            assert_eq!(
                accept::<PasswordField>(form).err(),
                Some(EntryError::NormalizationUndecided)
            );
        }
    }

    #[test]
    fn everything_accepted_today_is_normalization_invariant() {
        let accepted = [
            &b"plain"[..],
            &b"with-symbols!@#$%^&*()"[..],
            &b"digits1234567890"[..],
            &b"inner space is fine"[..],
        ];
        for input in accepted {
            let secret = accept::<PasswordField>(input.to_vec()).expect("accepted");
            assert!(secret.expose().is_ascii(), "accepted a non-ASCII input");
        }
    }

    #[test]
    fn surrounding_whitespace_is_refused_because_trimming_is_undecided() {
        for input in [
            &b" leading"[..],
            &b"trailing "[..],
            &b"\ttab"[..],
            &b"newline\n"[..],
        ] {
            assert_eq!(
                accept::<PasswordField>(input.to_vec()).err(),
                Some(EntryError::SurroundingWhitespace),
                "input {input:?} must be refused"
            );
        }
        assert!(accept::<PasswordField>(b"two words".to_vec()).is_ok());
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

        for raw in [
            &b"a-real-password \n"[..],
            &b" a-real-password\n"[..],
            &b"a-real-password\n\n"[..],
            &b"a-real-password\t"[..],
        ] {
            assert_eq!(
                accept::<CliStdin>(raw.to_vec()).err(),
                Some(EntryError::SurroundingWhitespace),
                "{raw:?} was accepted, so the framing rule has become a trim"
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

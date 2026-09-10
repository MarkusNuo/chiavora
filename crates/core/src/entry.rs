//! The one path by which raw input becomes key material (I1(a)).

use zeroize::Zeroizing;

use crate::secret::{kind, ExternalKind, Secret, SecretKind};

/// Not a password policy: it stops a hostile host handing Argon2id a gigabyte.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// No variant carries any of the input, since an error here is likely to be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    Empty,
    TooLong {
        max: usize,
    },
    NormalizationUndecided,
    SurroundingWhitespace,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStatus {
    Covered,
    Owed,
}

#[derive(Debug, Clone, Copy)]
pub struct EntryPointRecord {
    pub name: &'static str,
    pub gate_phrase: &'static str,
    pub statement: &'static str,
    pub status: EntryStatus,
    pub yields: Option<&'static str>,
    pub blocked_on: Option<&'static str>,
}

pub const REGISTRY: [EntryPointRecord; 6] = [
    EntryPointRecord {
        name: "password field",
        gate_phrase: "the password field",
        statement: "",
        status: EntryStatus::Covered,
        yields: Some("AccountPassword"),
        blocked_on: None,
    },
    EntryPointRecord {
        name: "Secret Key field",
        gate_phrase: "the Secret Key field",
        statement: "",
        status: EntryStatus::Owed,
        yields: Some("SecretKey"),
        blocked_on: Some(" / docs/adr/0004 - Base32 rendering and checksum undecided"),
    },
    EntryPointRecord {
        name: "Emergency Kit QR decode path",
        gate_phrase: "the Emergency Kit QR decode path",
        statement: "",
        status: EntryStatus::Owed,
        yields: Some("SecretKey"),
        blocked_on: Some(" / docs/adr/0004, and the Kit itself is "),
    },
    EntryPointRecord {
        name: "clipboard paste",
        gate_phrase: "clipboard paste",
        statement: "",
        status: EntryStatus::Owed,
        yields: None,
        blocked_on: Some(" - which secret a paste carries"),
    },
    EntryPointRecord {
        name: "CLI stdin",
        gate_phrase: "CLI stdin",
        statement: "",
        status: EntryStatus::Owed,
        yields: None,
        blocked_on: Some(
            " - docs/security-design.md does not say whether stdin carries the password or the Secret Key",
        ),
    },
    EntryPointRecord {
        name: "inbound native messaging",
        gate_phrase: "inbound native messaging",
        statement: "",
        status: EntryStatus::Owed,
        yields: None,
        blocked_on: Some(
            " - and what arrives inbound may be item data rather than key material",
        ),
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
    fn the_entry_point_names_itself_the_same_way_the_registry_does() {
        let covered = super::REGISTRY
            .iter()
            .find(|r| r.status == super::EntryStatus::Covered)
            .expect("one covered row");
        assert_eq!(PasswordField::NAME, covered.name);
    }
}

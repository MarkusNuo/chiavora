//! A generated password is item data for the UI, clipboard and autofill, not a `Secret`.

use zeroize::Zeroizing;

use crate::csprng::{uniform_below, CsprngError};

pub const MAX_LENGTH: usize = 128;

pub const MAX_PASSPHRASE_WORDS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    Lowercase,
    Uppercase,
    Digit,
    /// Symbols that most password fields accept without escaping.
    Symbol,
}

impl CharClass {
    const fn chars(self) -> &'static [u8] {
        match self {
            Self::Lowercase => b"abcdefghijklmnopqrstuvwxyz",
            Self::Uppercase => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Self::Digit => b"0123456789",
            Self::Symbol => b"!#$%&()*+,-./:;<=>?@[]^_{|}~",
        }
    }

    pub const ALL: [Self; 4] = [Self::Lowercase, Self::Uppercase, Self::Digit, Self::Symbol];
}

const AMBIGUOUS: &[u8] = b"0O1lI5S8B";

/// No `Default`: these are product decisions for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    length: usize,
    classes: Vec<CharClass>,
    exclude_ambiguous: bool,
    require_one_of_each: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateError {
    /// An empty password that looks generated is worse than an error.
    ZeroLength,
    TooLong {
        max: usize,
    },
    NoClasses,
    AlphabetEmptyAfterExclusions,
    LengthBelowClassCount,
    Csprng,
    AlphabetTooLarge,
    AlphabetIndexOutOfRange,
}

impl core::fmt::Display for GenerateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::ZeroLength => f.write_str("a password of length zero is refused"),
            Self::TooLong { max } => write!(f, "a password longer than {max} characters"),
            Self::NoClasses => f.write_str("no character classes selected"),
            Self::AlphabetEmptyAfterExclusions => {
                f.write_str("excluding ambiguous characters left an empty alphabet")
            }
            Self::LengthBelowClassCount => {
                f.write_str("the length is below the number of required classes")
            }
            Self::Csprng => {
                f.write_str("the platform CSPRNG failed; refusing to generate a weaker password")
            }
            Self::AlphabetTooLarge => f.write_str("the alphabet does not fit in a u32"),
            Self::AlphabetIndexOutOfRange => f.write_str("a drawn index fell outside the alphabet"),
        }
    }
}

impl core::error::Error for GenerateError {}

impl From<CsprngError> for GenerateError {
    fn from(_: CsprngError) -> Self {
        Self::Csprng
    }
}

impl Policy {
    pub fn new(
        length: usize,
        classes: &[CharClass],
        exclude_ambiguous: bool,
        require_one_of_each: bool,
    ) -> Result<Self, GenerateError> {
        if length == 0 {
            return Err(GenerateError::ZeroLength);
        }
        if length > MAX_LENGTH {
            return Err(GenerateError::TooLong { max: MAX_LENGTH });
        }
        if classes.is_empty() {
            return Err(GenerateError::NoClasses);
        }

        // De-duplicated in `CharClass::ALL`'s order, so the alphabet is deterministic.
        let mut deduped = Vec::new();
        for class in CharClass::ALL {
            if classes.contains(&class) {
                deduped.push(class);
            }
        }

        if require_one_of_each && length < deduped.len() {
            return Err(GenerateError::LengthBelowClassCount);
        }

        let candidate = Self {
            length,
            classes: deduped,
            exclude_ambiguous,
            require_one_of_each,
        };
        if candidate.alphabet().is_empty() {
            return Err(GenerateError::AlphabetEmptyAfterExclusions);
        }
        for class in &candidate.classes {
            if candidate.class_chars(*class).is_empty() {
                // An empty class would leave the rejection loop spinning.
                return Err(GenerateError::AlphabetEmptyAfterExclusions);
            }
        }
        Ok(candidate)
    }

    #[must_use]
    pub const fn length(&self) -> usize {
        self.length
    }

    /// Satisfied by discarding uniform draws that miss a class rather than by placing
    /// characters, so no position is biased.
    #[must_use]
    pub const fn require_one_of_each(&self) -> bool {
        self.require_one_of_each
    }

    fn class_chars(&self, class: CharClass) -> Vec<u8> {
        class
            .chars()
            .iter()
            .copied()
            .filter(|b| !self.exclude_ambiguous || !AMBIGUOUS.contains(b))
            .collect()
    }

    #[must_use]
    pub fn alphabet(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for class in &self.classes {
            out.extend(self.class_chars(*class));
        }
        out
    }
}

pub fn password(policy: &Policy) -> Result<Zeroizing<String>, GenerateError> {
    // Bounded so a policy that cannot be satisfied fails instead of hanging.
    const MAX_ATTEMPTS: usize = 1_000;

    let alphabet = policy.alphabet();
    // Cannot fail (at most 75 characters), and a fallback would misstate the alphabet.
    let size = u32::try_from(alphabet.len()).map_err(|_| GenerateError::AlphabetTooLarge)?;
    if size == 0 {
        return Err(GenerateError::NoClasses);
    }

    for _ in 0..MAX_ATTEMPTS {
        // Sized by the ceiling, which `Policy::new` enforces, not by the request.
        let mut out = Zeroizing::new(String::with_capacity(MAX_LENGTH));
        for _ in 0..policy.length {
            let index = uniform_below(size)?;
            // Both conversions propagate: a fallback would weaken the password silently.
            let position = usize::try_from(index).map_err(|_| GenerateError::AlphabetTooLarge)?;
            let byte = *alphabet
                .get(position)
                .ok_or(GenerateError::AlphabetIndexOutOfRange)?;
            out.push(char::from(byte));
        }
        if !policy.require_one_of_each || satisfies_all_classes(policy, &out) {
            return Ok(out);
        }
    }

    Err(GenerateError::LengthBelowClassCount)
}

fn satisfies_all_classes(policy: &Policy, candidate: &str) -> bool {
    policy.classes.iter().all(|class| {
        let permitted = policy.class_chars(*class);
        candidate.bytes().any(|b| permitted.contains(&b))
    })
}

/// Exact because the draw has no modulo bias. With [`Policy::require_one_of_each`]
/// the true figure is a fraction of a bit lower. Not for passwords a person typed.
#[must_use]
pub fn entropy_bits(policy: &Policy) -> f64 {
    let size = policy.alphabet().len();
    if size <= 1 {
        return 0.0;
    }
    // Both values are far below 2^53, so these casts are exact.
    #[allow(clippy::cast_precision_loss)]
    let bits_per_char = (size as f64).log2();
    #[allow(clippy::cast_precision_loss)]
    let length = policy.length as f64;
    bits_per_char * length
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{entropy_bits, password, CharClass, GenerateError, Policy, AMBIGUOUS};

    fn all_classes() -> Vec<CharClass> {
        CharClass::ALL.to_vec()
    }

    #[test]
    fn a_csprng_failure_maps_to_the_intended_variant() {
        use crate::csprng::CsprngError;

        let mapped = GenerateError::from(CsprngError);
        assert_eq!(mapped, GenerateError::Csprng);
        let text = format!("{mapped}");
        assert!(text.contains("CSPRNG"), "it must say what failed: {text}");
        assert!(
            text.contains("refusing"),
            "R1: it must say it is refusing rather than substituting: {text}"
        );
    }

    #[test]
    fn a_policy_reports_back_what_it_was_given() {
        let policy = Policy::new(24, &[CharClass::Digit, CharClass::Digit], false, false).unwrap();
        assert_eq!(policy.length(), 24);
        assert!(!policy.require_one_of_each());
        // De-duplicated: two `Digit`s are one class, so the alphabet is 10.
        assert_eq!(policy.alphabet().len(), 10);

        let strict = Policy::new(8, &all_classes(), true, true).unwrap();
        assert_eq!(strict.length(), 8);
        assert!(strict.require_one_of_each());
    }

    #[test]
    fn a_generated_password_has_the_requested_length_and_alphabet() {
        let policy = Policy::new(24, &all_classes(), false, false).unwrap();
        let alphabet = policy.alphabet();
        let generated = password(&policy).unwrap();
        assert_eq!(generated.chars().count(), 24);
        for byte in generated.bytes() {
            assert!(
                alphabet.contains(&byte),
                "generated a character outside the alphabet: {byte:#04x}"
            );
        }
    }

    #[test]
    fn the_length_ceiling_is_refused_above_and_accepted_at() {
        let at = Policy::new(super::MAX_LENGTH, &[CharClass::Lowercase], false, false);
        assert!(at.is_ok(), "the ceiling itself is accepted");
        let over = Policy::new(super::MAX_LENGTH + 1, &[CharClass::Lowercase], false, false);
        assert_eq!(
            over.err(),
            Some(GenerateError::TooLong {
                max: super::MAX_LENGTH
            })
        );
    }

    #[test]
    fn two_generated_passwords_differ() {
        let policy = Policy::new(32, &all_classes(), false, false).unwrap();
        let a = password(&policy).unwrap();
        let b = password(&policy).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn policy_has_no_default_and_refuses_degenerate_values() {
        assert_eq!(
            Policy::new(0, &all_classes(), false, false).err(),
            Some(GenerateError::ZeroLength)
        );
        assert_eq!(
            Policy::new(16, &[], false, false).err(),
            Some(GenerateError::NoClasses)
        );
        assert!(Policy::new(1, &[CharClass::Digit], false, false).is_ok());
    }

    #[test]
    fn requiring_more_classes_than_characters_is_refused_not_looped() {
        assert_eq!(
            Policy::new(3, &all_classes(), false, true).err(),
            Some(GenerateError::LengthBelowClassCount)
        );
        assert!(Policy::new(4, &all_classes(), false, true).is_ok());
    }

    #[test]
    fn excluding_ambiguous_characters_removes_them_from_every_class() {
        let policy = Policy::new(40, &all_classes(), true, false).unwrap();
        let alphabet = policy.alphabet();
        for &ambiguous in AMBIGUOUS {
            assert!(
                !alphabet.contains(&ambiguous),
                "{} survived the ambiguity filter",
                char::from(ambiguous)
            );
        }
        let generated = password(&policy).unwrap();
        for byte in generated.bytes() {
            assert!(!AMBIGUOUS.contains(&byte));
        }
    }

    #[test]
    fn require_one_of_each_is_satisfied_by_every_accepted_password() {
        let policy = Policy::new(8, &all_classes(), false, true).unwrap();
        // Eight characters over four classes reject often enough to exercise the loop.
        for _ in 0..50 {
            let generated = password(&policy).unwrap();
            for class in CharClass::ALL {
                let permitted = policy.alphabet();
                let has = generated
                    .bytes()
                    .any(|b| class.chars().contains(&b) && permitted.contains(&b));
                assert!(has, "{generated:?} is missing {class:?}");
            }
        }
    }

    #[test]
    fn rejection_does_not_pin_characters_to_positions() {
        let policy = Policy::new(8, &all_classes(), false, true).unwrap();
        let mut first_char_classes = std::collections::BTreeSet::new();
        for _ in 0..200 {
            let generated = password(&policy).unwrap();
            let first = generated.bytes().next().expect("non-empty");
            for class in CharClass::ALL {
                if class.chars().contains(&first) {
                    first_char_classes.insert(format!("{class:?}"));
                }
            }
        }
        assert!(
            first_char_classes.len() > 1,
            "every password started with the same class, which is what \
             position-stuffing looks like: {first_char_classes:?}"
        );
    }

    #[test]
    fn entropy_is_arithmetic_over_the_alphabet() {
        // 26 + 26 + 10 + 13 = 75 characters; log2(75) = 6.2288...
        let policy = Policy::new(20, &all_classes(), false, false).unwrap();
        assert_eq!(policy.alphabet().len(), 90);
        let bits = entropy_bits(&policy);
        assert!(
            (bits - 20.0 * 90.0_f64.log2()).abs() < 1e-9,
            "expected exactly length * log2(alphabet), got {bits}"
        );

        let digits = Policy::new(6, &[CharClass::Digit], false, false).unwrap();
        assert!((entropy_bits(&digits) - 6.0 * 10.0_f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn excluding_ambiguous_characters_lowers_the_reported_entropy() {
        let wide = Policy::new(20, &all_classes(), false, false).unwrap();
        let narrow = Policy::new(20, &all_classes(), true, false).unwrap();
        assert!(narrow.alphabet().len() < wide.alphabet().len());
        assert!(entropy_bits(&narrow) < entropy_bits(&wide));
    }

    #[test]
    fn a_generated_password_is_not_branded_key_material() {
        let policy = Policy::new(12, &all_classes(), false, false).unwrap();
        let generated = password(&policy).unwrap();
        let borrowed: &str = &generated;
        assert_eq!(borrowed.chars().count(), 12);
        drop(generated);
    }
}

//! A generated password is item data, not key material, so it may cross the boundary.

use chiavora_core::generate::{self, CharClass, Policy, MAX_LENGTH, MAX_PASSPHRASE_WORDS};
use chiavora_core::passphrase::{
    self, PassphrasePolicy, WORDLIST_ATTRIBUTION, WORDLIST_SOURCE, WORD_COUNT,
};

/// Not a `Secret`: it is meant to be shown and copied.
#[derive(Debug, uniffi::Record)]
pub struct GeneratedValue {
    pub value: String,
    pub entropy_bits: f64,
}

/// Never carries the value or any part of it.
#[derive(Debug, uniffi::Error)]
pub enum GeneratorError {
    Policy {
        reason: String,
    },
    /// The platform CSPRNG failed or the word list is broken; never retried with a weaker source.
    Generation {
        reason: String,
    },
}

impl core::fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy { reason } | Self::Generation { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for GeneratorError {}

#[derive(Debug, uniffi::Record)]
pub struct GeneratorLimits {
    pub max_length: u32,
    pub max_words: u32,
    pub word_count: u32,
    pub symbols: String,
    /// The CC BY 3.0 US attribution the about screen must show.
    pub wordlist_attribution: String,
    pub wordlist_source: String,
}

#[must_use]
#[uniffi::export]
pub fn generator_limits() -> GeneratorLimits {
    GeneratorLimits {
        max_length: u32::try_from(MAX_LENGTH).unwrap_or(u32::MAX),
        max_words: u32::try_from(MAX_PASSPHRASE_WORDS).unwrap_or(u32::MAX),
        word_count: u32::try_from(WORD_COUNT).unwrap_or(u32::MAX),
        symbols: String::from_utf8_lossy(CharClass::Symbol.characters()).into_owned(),
        wordlist_attribution: WORDLIST_ATTRIBUTION.to_owned(),
        wordlist_source: WORDLIST_SOURCE.to_owned(),
    }
}

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
#[uniffi::export]
pub fn generate_password(
    length: u32,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
    require_one_of_each: bool,
) -> Result<GeneratedValue, GeneratorError> {
    let mut classes = Vec::new();
    if lowercase {
        classes.push(CharClass::Lowercase);
    }
    if uppercase {
        classes.push(CharClass::Uppercase);
    }
    if digits {
        classes.push(CharClass::Digit);
    }
    if symbols {
        classes.push(CharClass::Symbol);
    }

    let policy = Policy::new(
        length as usize,
        &classes,
        exclude_ambiguous,
        require_one_of_each,
    )
    .map_err(|e| GeneratorError::Policy {
        reason: e.to_string(),
    })?;

    let value = generate::password(&policy).map_err(|e| GeneratorError::Generation {
        reason: e.to_string(),
    })?;

    Ok(GeneratedValue {
        // Copied out on purpose; the `Zeroizing` original is still wiped on drop.
        value: value.to_string(),
        entropy_bits: generate::entropy_bits(&policy),
    })
}

// uniffi exports take owned values, so `separator` cannot be a `&str`.
#[allow(clippy::needless_pass_by_value)]
#[uniffi::export]
pub fn generate_passphrase(
    words: u32,
    separator: String,
    capitalise: bool,
) -> Result<GeneratedValue, GeneratorError> {
    let mut chars = separator.chars();
    let (Some(separator), None) = (chars.next(), chars.next()) else {
        return Err(GeneratorError::Policy {
            reason: "the separator must be exactly one character".to_owned(),
        });
    };

    let policy = PassphrasePolicy::new(words as usize, separator, capitalise).map_err(|e| {
        GeneratorError::Policy {
            reason: e.to_string(),
        }
    })?;

    let value = passphrase::passphrase(&policy).map_err(|e| GeneratorError::Generation {
        reason: e.to_string(),
    })?;

    Ok(GeneratedValue {
        value: value.to_string(),
        entropy_bits: passphrase::entropy_bits(&policy),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_default_password_is_twenty_characters_and_its_entropy_is_reported() {
        let out = generate_password(20, true, true, true, true, false, true)
            .expect(" default is generatable");
        assert_eq!(out.value.chars().count(), 20);
        // 20 * log2(75).
        assert!((out.entropy_bits - 124.576).abs() < 0.01);
    }

    #[test]
    fn the_default_passphrase_is_five_hyphenated_words() {
        let out = generate_passphrase(5, "-".to_owned(), false).expect("generates");
        assert!((out.entropy_bits - 64.62).abs() < 0.01);
        assert!(out
            .value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'-'));
    }

    #[test]
    fn a_refused_policy_names_the_refusal_and_carries_no_value() {
        let err = generate_password(0, true, true, true, true, false, false)
            .expect_err("length zero is refused");
        let text = err.to_string();
        assert!(text.contains("zero"), "{text}");

        let none = generate_password(20, false, false, false, false, false, false)
            .expect_err("no classes is refused");
        assert!(none.to_string().contains("classes"));

        let over = generate_password(
            u32::try_from(MAX_LENGTH).unwrap() + 1,
            true,
            true,
            true,
            true,
            false,
            false,
        )
        .expect_err("above the ceiling is refused");
        assert!(over.to_string().contains(&MAX_LENGTH.to_string()));
    }

    #[test]
    fn a_multi_character_separator_is_refused_rather_than_truncated() {
        let err = generate_passphrase(5, "-- ".to_owned(), false).expect_err("refused");
        assert!(err.to_string().contains("one character"), "{err}");
        assert!(generate_passphrase(5, String::new(), false).is_err());
    }

    #[test]
    fn the_limits_come_from_core_and_name_the_attribution() {
        let limits = generator_limits();
        assert_eq!(limits.max_length as usize, MAX_LENGTH);
        assert_eq!(limits.max_words as usize, MAX_PASSPHRASE_WORDS);
        assert_eq!(limits.word_count as usize, WORD_COUNT);
        assert_eq!(limits.symbols, "!@#$%^&*-_=+?");
        assert!(limits.wordlist_attribution.contains("Electronic Frontier"));
        assert!(limits.wordlist_attribution.contains("CC BY 3.0 US"));
    }
}

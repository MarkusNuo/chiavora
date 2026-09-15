//! Passphrases from the EFF large wordlist (CC BY 3.0 US, attributed in `NOTICE`).

use zeroize::Zeroizing;

use crate::csprng::{uniform_below, CsprngError};
use crate::generate::MAX_PASSPHRASE_WORDS;

const RAW: &str = include_str!("eff_large_wordlist.txt");

pub const WORD_COUNT: usize = 7776;

pub const WORDLIST_SHA256: &str =
    "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

pub const WORDLIST_SOURCE: &str = "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt";

/// One constant so the app, the CLI and `NOTICE` agree.
pub const WORDLIST_ATTRIBUTION: &str =
    "Passphrases use the EFF Long Wordlist by the Electronic Frontier Foundation, \
     licensed CC BY 3.0 US.";

/// Always a bug in this repository, never hostile input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordlistError {
    WrongLength {
        found: usize,
    },
    /// A line was not `<5 dice digits>\t<word>`.
    MalformedLine {
        at: usize,
    },
}

impl core::fmt::Display for WordlistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { found } => write!(
                f,
                "the word list holds {found} entries, not {WORD_COUNT}; every entropy figure \
                 derived from it would be wrong"
            ),
            Self::MalformedLine { at } => {
                write!(f, "word list line {at} is not a dice roll and a word")
            }
        }
    }
}

impl core::error::Error for WordlistError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseError {
    /// An empty value that looks generated is worse than an error.
    ZeroWords,
    TooManyWords {
        max: usize,
    },
    SeparatorNotAscii,
    Csprng,
    Wordlist(WordlistError),
}

impl core::fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroWords => f.write_str("a passphrase of zero words is refused"),
            Self::TooManyWords { max } => write!(f, "a passphrase longer than {max} words"),
            Self::SeparatorNotAscii => {
                f.write_str("the separator must be a printable ASCII character")
            }
            Self::Csprng => {
                f.write_str("the platform CSPRNG failed; refusing to generate a weaker passphrase")
            }
            Self::Wordlist(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for PassphraseError {}

impl From<CsprngError> for PassphraseError {
    fn from(_: CsprngError) -> Self {
        Self::Csprng
    }
}

impl From<WordlistError> for PassphraseError {
    fn from(e: WordlistError) -> Self {
        Self::Wordlist(e)
    }
}

fn is_wellformed(roll: &str, word: &str) -> bool {
    roll.len() == 5
        && roll.bytes().all(|b| (b'1'..=b'6').contains(&b))
        && !word.is_empty()
        && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        && word.starts_with(|c: char| c.is_ascii_lowercase())
        && word.ends_with(|c: char| c.is_ascii_lowercase())
}

/// With the default separator, these words cannot be recovered by splitting on it.
pub const HYPHENATED: [&str; 4] = ["drop-down", "felt-tip", "t-shirt", "yo-yo"];

pub fn words() -> Result<Vec<&'static str>, WordlistError> {
    // A CRLF checkout must still parse: a passphrase holding a `\r` is a lockout.
    let mut out = Vec::with_capacity(WORD_COUNT);
    for (at, line) in RAW.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (roll, word) = line
            .split_once('\t')
            .ok_or(WordlistError::MalformedLine { at })?;
        if !is_wellformed(roll, word) {
            return Err(WordlistError::MalformedLine { at });
        }
        out.push(word);
    }
    if out.len() != WORD_COUNT {
        return Err(WordlistError::WrongLength { found: out.len() });
    }
    Ok(out)
}

/// No `Default`: the values are product decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphrasePolicy {
    words: usize,
    separator: char,
    capitalise: bool,
}

impl PassphrasePolicy {
    pub fn recommended() -> Result<Self, PassphraseError> {
        Self::new(5, '-', false)
    }

    pub fn new(words: usize, separator: char, capitalise: bool) -> Result<Self, PassphraseError> {
        if words == 0 {
            return Err(PassphraseError::ZeroWords);
        }
        if words > MAX_PASSPHRASE_WORDS {
            return Err(PassphraseError::TooManyWords {
                max: MAX_PASSPHRASE_WORDS,
            });
        }
        // A separator that cannot be retyped would lock the user out.
        if !separator.is_ascii_graphic() {
            return Err(PassphraseError::SeparatorNotAscii);
        }
        Ok(Self {
            words,
            separator,
            capitalise,
        })
    }

    #[must_use]
    pub const fn words(&self) -> usize {
        self.words
    }

    #[must_use]
    pub const fn separator(&self) -> char {
        self.separator
    }

    #[must_use]
    pub const fn capitalise(&self) -> bool {
        self.capitalise
    }
}

/// Each word is an independent uniform draw, with replacement, so a word may repeat.
pub fn passphrase(policy: &PassphrasePolicy) -> Result<Zeroizing<String>, PassphraseError> {
    let words = words()?;
    let mut out = Zeroizing::new(String::new());
    for index in 0..policy.words {
        if index > 0 {
            out.push(policy.separator);
        }
        let pick = *words
            // R1: `WORD_COUNT` is 7776, so this cannot fail; if it did, `u32::MAX`
            // would draw past the list and the `ok_or` below would refuse it.
            .get(uniform_below(u32::try_from(WORD_COUNT).unwrap_or(u32::MAX))? as usize)
            .ok_or(WordlistError::WrongLength { found: words.len() })?;
        if policy.capitalise {
            let mut chars = pick.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(pick);
        }
    }
    Ok(out)
}

/// Capitalisation and the separator add nothing, as the policy is assumed known.
#[must_use]
pub fn entropy_bits(policy: &PassphrasePolicy) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let list = WORD_COUNT as f64;
    #[allow(clippy::cast_precision_loss)]
    let count = policy.words as f64;
    count * list.log2()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_list_is_effs_file_byte_for_byte() {
        let digest = Sha256::digest(RAW.as_bytes());
        assert_eq!(
            format!("{digest:x}"),
            WORDLIST_SHA256,
            "the word list is not the file this module documents. If it was \
             deliberately changed, the entropy claim and the attribution both \
             need re-checking; if it was a line-ending conversion, see \
             .gitattributes"
        );
    }

    #[test]
    fn the_list_holds_exactly_7776_distinct_words() {
        let words = words().expect("the shipped list parses");
        assert_eq!(words.len(), WORD_COUNT);

        let mut sorted = words.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), WORD_COUNT, "the word list repeats a word");
    }

    #[test]
    fn a_short_or_truncated_list_is_refused_rather_than_measured() {
        // `RAW` is a `const`, so the parse loop is repeated over synthetic input.
        fn parse(raw: &str) -> Result<usize, WordlistError> {
            let mut n = 0;
            for (at, line) in raw.lines().enumerate() {
                let line = line.trim_end_matches('\r');
                if line.is_empty() {
                    continue;
                }
                let (roll, word) = line
                    .split_once('\t')
                    .ok_or(WordlistError::MalformedLine { at })?;
                if !is_wellformed(roll, word) {
                    return Err(WordlistError::MalformedLine { at });
                }
                n += 1;
            }
            Ok(n)
        }

        assert_eq!(parse("11111\tabacus\n11112\tabdomen\n"), Ok(2));
        assert_eq!(
            parse("11111\tabacus\nabdomen\n"),
            Err(WordlistError::MalformedLine { at: 1 })
        );
        assert_eq!(
            parse("1111\tabacus\n"),
            Err(WordlistError::MalformedLine { at: 0 })
        );
        assert_eq!(
            parse("11711\tabacus\n"),
            Err(WordlistError::MalformedLine { at: 0 }),
            "a 7 is not a die face"
        );
        assert_eq!(
            parse("11111\tAbacus\n"),
            Err(WordlistError::MalformedLine { at: 0 }),
            "the list is lowercase; capitalisation is this module's to apply"
        );
        assert_eq!(
            parse("11111\tt-shirt\n"),
            Ok(1),
            "EFF's list really does contain hyphenated words"
        );
        assert_eq!(
            parse("11111\t-shirt\n"),
            Err(WordlistError::MalformedLine { at: 0 }),
            "a leading hyphen is not a word"
        );
        assert_eq!(
            parse("11111\tshirt-\n"),
            Err(WordlistError::MalformedLine { at: 0 }),
            "a trailing hyphen is not a word"
        );
    }

    #[test]
    fn the_recommended_policy_is_five_hyphenated_lowercase_words() {
        let policy = PassphrasePolicy::recommended().expect(" defaults are valid");
        assert_eq!(policy.words(), 5);
        assert_eq!(policy.separator(), '-');
        assert!(!policy.capitalise());

        // Not `split('-')`: four of EFF's words contain a hyphen.
        let phrase = passphrase(&policy).expect("generates");
        assert!(
            phrase.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            "unexpected character in {}",
            phrase.as_str()
        );
        assert!(!phrase.starts_with('-') && !phrase.ends_with('-'));
    }

    #[test]
    fn capitalising_changes_the_output_and_not_the_entropy() {
        let plain = PassphrasePolicy::new(5, '-', false).unwrap();
        let capped = PassphrasePolicy::new(5, '-', true).unwrap();

        assert!(
            (entropy_bits(&plain) - entropy_bits(&capped)).abs() < f64::EPSILON,
            "capitalisation moved the reported entropy; it adds nothing an \
             attacker who knows the policy does not already know"
        );

        // A separator no word contains, so the split is exact (`T-shirt` is one word).
        let capped_dot = PassphrasePolicy::new(5, '.', true).unwrap();
        let out = passphrase(&capped_dot).expect("generates");
        assert!(
            out.split('.')
                .all(|w| w.starts_with(|c: char| c.is_ascii_uppercase())),
            "capitalise was reported as on and did not happen: {}",
            out.as_str()
        );
    }

    #[test]
    fn the_separator_changes_the_output_and_not_the_entropy() {
        let hyphen = PassphrasePolicy::new(4, '-', false).unwrap();
        let dot = PassphrasePolicy::new(4, '.', false).unwrap();
        assert!((entropy_bits(&hyphen) - entropy_bits(&dot)).abs() < f64::EPSILON);

        let out = passphrase(&dot).expect("generates");
        assert_eq!(out.matches('.').count(), 3);
    }

    #[test]
    fn entropy_is_words_times_log2_of_the_list() {
        let policy = PassphrasePolicy::recommended().expect(" defaults are valid");
        let bits = entropy_bits(&policy);
        assert!((bits - 5.0 * 7776.0_f64.log2()).abs() < 1e-9);
        assert!(
            (bits - 64.62).abs() < 0.01,
            " default is {bits} bits"
        );

        let twelve = PassphrasePolicy::new(12, '-', false).unwrap();
        assert!((entropy_bits(&twelve) - 12.0 * 7776.0_f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn the_ceiling_is_refused_above_and_accepted_at() {
        assert!(PassphrasePolicy::new(MAX_PASSPHRASE_WORDS, '-', false).is_ok());
        assert_eq!(
            PassphrasePolicy::new(MAX_PASSPHRASE_WORDS + 1, '-', false),
            Err(PassphraseError::TooManyWords {
                max: MAX_PASSPHRASE_WORDS
            })
        );
        assert_eq!(
            PassphrasePolicy::new(0, '-', false),
            Err(PassphraseError::ZeroWords)
        );
    }

    #[test]
    fn a_separator_that_cannot_be_retyped_is_refused() {
        for bad in ['\n', '\t', ' ', '\u{200b}'] {
            assert_eq!(
                PassphrasePolicy::new(3, bad, false),
                Err(PassphraseError::SeparatorNotAscii),
                "{bad:?} was accepted as a separator"
            );
        }
    }

    #[test]
    fn the_four_hyphenated_words_are_still_the_only_four() {
        let found: Vec<&str> = words()
            .expect("parses")
            .into_iter()
            .filter(|w| w.contains('-'))
            .collect();
        assert_eq!(found, HYPHENATED.to_vec());
    }

    #[test]
    fn two_generated_passphrases_differ() {
        let policy = PassphrasePolicy::recommended().expect(" defaults are valid");
        let a = passphrase(&policy).expect("generates");
        let b = passphrase(&policy).expect("generates");
        assert_ne!(*a, *b, "two draws of 64.6 bits collided");
    }
}

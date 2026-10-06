//! The screens read these values from here instead of keeping their own copy.

use core::time::Duration;

pub const PROVISIONAL: bool = true;

pub const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest idle timeout a user may choose, so that "never" is not reachable.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Not user-configurable: below API 33 this TTL is the clipboard's only protection.
pub const CLIPBOARD_TTL: Duration = Duration::from_secs(30);

/// Consecutive failed biometric unlocks before the wrapped MUK is wiped.
/// Account-password entries are not counted.
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Carries the bounds so a caller can tell the user what is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfBounds {
    pub requested: Duration,
    pub min: Duration,
    pub max: Duration,
}

impl core::fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "an idle timeout of {}s is outside the permitted {}s..={}s",
            self.requested.as_secs(),
            self.min.as_secs(),
            self.max.as_secs()
        )
    }
}

impl core::error::Error for OutOfBounds {}

/// Only [`LockPolicy::new`] and [`LockPolicy::default`] build one, so every timeout has been
/// checked against the bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicy {
    idle_timeout: Duration,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl LockPolicy {
    /// Out of range is refused, never clamped.
    pub const fn new(idle_timeout: Duration) -> Result<Self, OutOfBounds> {
        // `Duration` comparison is not `const`; both bounds are whole seconds.
        if idle_timeout.as_secs() < MIN_IDLE_TIMEOUT.as_secs()
            || idle_timeout.as_secs() > MAX_IDLE_TIMEOUT.as_secs()
        {
            return Err(OutOfBounds {
                requested: idle_timeout,
                min: MIN_IDLE_TIMEOUT,
                max: MAX_IDLE_TIMEOUT,
            });
        }
        Ok(Self { idle_timeout })
    }

    /// How long the app may sit idle before the session is dropped. The
    /// enrolment stays, so the next unlock is a biometric touch.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    #[must_use]
    pub const fn clipboard_ttl(&self) -> Duration {
        CLIPBOARD_TTL
    }

    #[must_use]
    pub const fn max_failed_attempts(&self) -> u32 {
        MAX_FAILED_ATTEMPTS
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_inside_its_own_bounds() {
        assert!(LockPolicy::new(DEFAULT_IDLE_TIMEOUT).is_ok());
        assert_eq!(LockPolicy::default().idle_timeout(), DEFAULT_IDLE_TIMEOUT);
    }

    #[test]
    fn a_timeout_outside_the_bounds_is_refused_rather_than_clamped() {
        let too_long = MAX_IDLE_TIMEOUT + Duration::from_secs(1);
        let err = LockPolicy::new(too_long).unwrap_err();
        assert_eq!(err.requested, too_long);
        assert_eq!((err.min, err.max), (MIN_IDLE_TIMEOUT, MAX_IDLE_TIMEOUT));

        let too_short = MIN_IDLE_TIMEOUT
            .checked_sub(Duration::from_secs(1))
            .expect("the floor is above zero, so a second below it exists");
        assert!(LockPolicy::new(too_short).is_err());
    }

    #[test]
    fn the_bounds_themselves_are_accepted() {
        assert!(LockPolicy::new(MIN_IDLE_TIMEOUT).is_ok());
        assert!(LockPolicy::new(MAX_IDLE_TIMEOUT).is_ok());
    }

    #[test]
    fn the_provisional_marker_is_still_set() {
        let still_the_recommended_values = DEFAULT_IDLE_TIMEOUT == Duration::from_secs(120)
            && MIN_IDLE_TIMEOUT == Duration::from_secs(30)
            && MAX_IDLE_TIMEOUT == Duration::from_secs(900)
            && CLIPBOARD_TTL == Duration::from_secs(30)
            && MAX_FAILED_ATTEMPTS == 5;
        assert!(
            !still_the_recommended_values || PROVISIONAL,
            "the values are the ones - proposed and PROVISIONAL is \
             clear, so a build now reports that somebody decided these numbers \
             when nobody has"
        );
    }

    #[test]
    fn the_error_text_names_the_range_rather_than_only_refusing() {
        let err = LockPolicy::new(Duration::from_secs(1)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("30"), "the floor is not in {text:?}");
        assert!(text.contains("900"), "the ceiling is not in {text:?}");
    }
}

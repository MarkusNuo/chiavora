//! Durations cross as whole seconds, because `uniffi` has no duration type.

use chiavora_core::lock_policy::{self, LockPolicy};

#[derive(Debug, uniffi::Record)]
pub struct LockPolicyReport {
    pub idle_timeout_seconds: u32,
    pub min_idle_timeout_seconds: u32,
    pub max_idle_timeout_seconds: u32,
    pub clipboard_ttl_seconds: u32,
    pub max_failed_attempts: u32,
    pub provisional: bool,
}

fn seconds(d: core::time::Duration) -> u32 {
    // R1: every policy timeout is under a quarter of an hour, so this cannot saturate.
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

#[must_use]
#[uniffi::export]
pub fn lock_policy() -> LockPolicyReport {
    let policy = LockPolicy::default();
    LockPolicyReport {
        idle_timeout_seconds: seconds(policy.idle_timeout()),
        min_idle_timeout_seconds: seconds(lock_policy::MIN_IDLE_TIMEOUT),
        max_idle_timeout_seconds: seconds(lock_policy::MAX_IDLE_TIMEOUT),
        clipboard_ttl_seconds: seconds(policy.clipboard_ttl()),
        max_failed_attempts: policy.max_failed_attempts(),
        provisional: lock_policy::PROVISIONAL,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_report_carries_the_bounds_the_screen_needs() {
        let r = lock_policy();
        assert!(
            r.min_idle_timeout_seconds <= r.idle_timeout_seconds
                && r.idle_timeout_seconds <= r.max_idle_timeout_seconds,
            "the default sits outside the bounds the same call reports, so a \
             slider drawn from this would open with its handle off the track"
        );
    }

    #[test]
    fn the_provisional_flag_is_reported_rather_than_dropped() {
        assert_eq!(lock_policy().provisional, lock_policy::PROVISIONAL);
    }
}

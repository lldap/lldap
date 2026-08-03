use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::types::{TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_STEP_SECS};

#[derive(Default)]
pub struct FailedAttempts(Mutex<HashMap<(String, u64), u8>>);

impl FailedAttempts {
    pub fn new() -> Self {
        Self::default()
    }

    // The allowance is spent per step and refills with the next code, so a mistyped
    // digit costs a wait rather than a lockout.
    pub fn allowed(&self, user_uuid: &str, now_unix: u64) -> bool {
        let step = now_unix / TOTP_STEP_SECS;
        let mut failed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        failed.retain(|(_, entry_step), _| *entry_step >= step);
        failed
            .get(&(user_uuid.to_owned(), step))
            .is_none_or(|count| *count < TOTP_MAX_ATTEMPTS_PER_STEP)
    }

    pub fn record_failure(&self, user_uuid: &str, now_unix: u64) {
        let step = now_unix / TOTP_STEP_SECS;
        let mut failed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = failed.entry((user_uuid.to_owned(), step)).or_insert(0);
        *count = count.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_are_capped_per_step_and_per_user() {
        let failed = FailedAttempts::new();
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            assert!(failed.allowed("uuid-a", 1000));
            failed.record_failure("uuid-a", 1000);
        }
        assert!(!failed.allowed("uuid-a", 1000));
        assert!(failed.allowed("uuid-b", 1000));
    }

    #[test]
    fn the_next_step_refills_the_allowance() {
        let failed = FailedAttempts::new();
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            failed.record_failure("uuid-a", 1000);
        }
        assert!(!failed.allowed("uuid-a", 1000));
        assert!(failed.allowed("uuid-a", 1000 + TOTP_STEP_SECS));
    }
}

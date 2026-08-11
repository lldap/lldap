use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::types::{TOTP_MAX_ATTEMPTS_PER_STEP, TOTP_STEP_SECS};

#[derive(Default)]
pub struct FailedAttempts(Mutex<HashMap<(String, u64), u8>>);

impl FailedAttempts {
    pub fn new() -> Self {
        Self::default()
    }

    // Spent per step and refilled by the next code, so a mistyped digit costs a wait.
    // One lock: checking and counting apart lets concurrent requests all pass the gate.
    pub fn reserve(&self, user_uuid: &str, now_unix: u64) -> bool {
        let step = now_unix / TOTP_STEP_SECS;
        let mut failed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        failed.retain(|(_, entry_step), _| *entry_step >= step);
        let count = failed.entry((user_uuid.to_owned(), step)).or_insert(0);
        if *count >= TOTP_MAX_ATTEMPTS_PER_STEP {
            return false;
        }
        *count += 1;
        true
    }

    // A correct code costs nothing.
    pub fn refund(&self, user_uuid: &str, now_unix: u64) {
        let step = now_unix / TOTP_STEP_SECS;
        let mut failed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = failed.get_mut(&(user_uuid.to_owned(), step)) {
            *count = count.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_are_capped_per_step_and_per_user() {
        let failed = FailedAttempts::new();
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            assert!(failed.reserve("uuid-a", 1000));
        }
        assert!(!failed.reserve("uuid-a", 1000));
        assert!(failed.reserve("uuid-b", 1000));
        failed.refund("uuid-a", 1000);
        assert!(failed.reserve("uuid-a", 1000));
    }

    #[test]
    fn allowance_refills_on_the_next_step() {
        let failed = FailedAttempts::new();
        for _ in 0..TOTP_MAX_ATTEMPTS_PER_STEP {
            assert!(failed.reserve("uuid-a", 1000));
        }
        assert!(!failed.reserve("uuid-a", 1000));
        assert!(failed.reserve("uuid-a", 1000 + TOTP_STEP_SECS));
    }
}

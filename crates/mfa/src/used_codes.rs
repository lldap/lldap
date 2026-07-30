use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Mutex, PoisonError};

use crate::types::TOTP_ACCEPTANCE_WINDOW_SECS;

/// Codes that were accepted, until they fall out of their acceptance window.
/// A code is only ever valid once (RFC 6238), per user.
#[derive(Default)]
pub struct UsedCodes(Mutex<HashMap<(String, String), i64>>);

impl UsedCodes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the code can be used now; marks it used if so. A refused code
    /// keeps its original expiry, so replays cannot extend it.
    pub fn mark_used(&self, user_uuid: &str, code: &str, now_unix: i64) -> bool {
        let mut used = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        used.retain(|_, expiry| *expiry > now_unix);
        match used.entry((user_uuid.to_owned(), code.to_owned())) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(now_unix + TOTP_ACCEPTANCE_WINDOW_SECS);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_single_use_per_user() {
        let used = UsedCodes::new();
        assert!(used.mark_used("uuid-a", "123456", 1000));
        assert!(!used.mark_used("uuid-a", "123456", 1000));
        assert!(used.mark_used("uuid-b", "123456", 1000));
        assert!(used.mark_used("uuid-a", "654321", 1000));
    }

    #[test]
    fn code_is_refused_for_its_whole_window() {
        let used = UsedCodes::new();
        assert!(used.mark_used("uuid-a", "123456", 1000));
        assert!(!used.mark_used("uuid-a", "123456", 999 + TOTP_ACCEPTANCE_WINDOW_SECS));
        assert!(used.mark_used("uuid-a", "123456", 1000 + TOTP_ACCEPTANCE_WINDOW_SECS));
    }
}

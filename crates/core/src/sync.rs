//! The workspace's lock-poisoning policy, in one place.
//!
//! A poisoned `Mutex`/`RwLock` means *another* thread or task panicked while
//! holding the guard. Rust's default answer — propagate the poison, which
//! `unwrap`/`expect` turns into a second panic — assumes the guarded value may
//! have been left half-updated. Nothing in this workspace is in that shape:
//! every critical section is a single map insert, slot swap, queue push or
//! counter bump on `Zeroizing` key material, `Arc`s and `Instant`s, so the
//! value behind a poisoned lock is structurally intact either way.
//!
//! The asymmetry that matters is what a second panic *costs*. A session-local
//! lock — the proxy's `SessionPortals` and `RowContext` — costs the one
//! session that is already being torn down. A process-wide key cache
//! ([`crate::envelope::Ciphers`], the proxy's Vault key source) costs every
//! session from then on: each new one panics in its own task, is caught and
//! logged as an abnormal termination, and the proxy stays up accepting
//! connections while failing 100% of them until it is restarted.
//!
//! So the policy is uniform: recover the value, never panic on poison. A call
//! site that genuinely cannot tolerate a half-updated value must not use this
//! and needs its own justification — there is none today.

use std::sync::PoisonError;

/// Recovers the guarded value from a poisoned lock instead of panicking.
///
/// Implemented for exactly the `Result` that `Mutex::lock`, `RwLock::read` and
/// `RwLock::write` return, so it reads as a suffix on the acquisition:
///
/// ```
/// use std::sync::RwLock;
///
/// use dbsec_core::sync::Unpoisoned as _;
///
/// let cache = RwLock::new(vec![1, 2, 3]);
/// assert_eq!(cache.read().unpoisoned().len(), 3);
/// ```
pub trait Unpoisoned {
    /// The lock guard the acquisition would have produced.
    type Guard;

    /// The guard, whether or not the lock is poisoned.
    fn unpoisoned(self) -> Self::Guard;
}

impl<G> Unpoisoned for Result<G, PoisonError<G>> {
    type Guard = G;

    fn unpoisoned(self) -> G {
        self.unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, RwLock};

    use super::*;

    /// The whole point: a lock poisoned by another thread's panic still hands
    /// back the value it was guarding, and that value is the one the panicking
    /// thread left — not a default and not a second panic.
    #[test]
    fn a_poisoned_lock_still_hands_back_its_value() {
        let mutex = Arc::new(Mutex::new(vec![1, 2, 3]));
        let poisoner = Arc::clone(&mutex);
        let panicked = std::thread::spawn(move || {
            let mut guard = poisoner.lock().unpoisoned();
            guard.push(4);
            panic!("the guarded value is intact at this point");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread has to have panicked");
        assert!(mutex.is_poisoned());

        assert_eq!(*mutex.lock().unpoisoned(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn both_rwlock_halves_are_covered() {
        let lock = RwLock::new(0u32);
        *lock.write().unpoisoned() += 1;
        assert_eq!(*lock.read().unpoisoned(), 1);
    }
}

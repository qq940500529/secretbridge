// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{error::Error, fmt, sync::Arc, time::Duration};

use keyring::{Entry, Error as KeyringError};
use tokio::{sync::Semaphore, task, time::timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "com.shulianchuangyuan.secretbridge";
pub(crate) const SECRET_READ_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStoreError {
    NotFound,
    LockedOrDenied,
    Unavailable,
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "the credential entry does not exist",
            Self::LockedOrDenied => {
                "the operating-system credential store is locked or denied access"
            }
            Self::Unavailable => "the operating-system credential store is unavailable",
        })
    }
}

impl Error for SecretStoreError {}

pub trait SecretStore: Send + Sync {
    fn set(&self, credential_id: Uuid, secret: &str) -> Result<(), SecretStoreError>;
    fn get(&self, credential_id: Uuid) -> Result<Zeroizing<String>, SecretStoreError>;
    fn delete(&self, credential_id: Uuid) -> Result<(), SecretStoreError>;
}

/// Bounds request waiting and the number of native reads that can remain
/// blocked in an operating-system prompt. A timed-out blocking call may still
/// finish later; its result is dropped without reaching the caller.
#[derive(Clone)]
pub(crate) struct SecretReadGate {
    capacity: Arc<Semaphore>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretReadError {
    Store(SecretStoreError),
    TimedOut,
    Cancelled,
    Worker,
}

impl SecretReadGate {
    pub(crate) fn new() -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(4)),
        }
    }

    pub(crate) async fn get(
        &self,
        store: Arc<dyn SecretStore>,
        credential_id: Uuid,
        limit: Duration,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Zeroizing<String>, SecretReadError> {
        let capacity = self.capacity.clone();
        let read = async move {
            let permit = capacity
                .acquire_owned()
                .await
                .map_err(|_| SecretReadError::Worker)?;
            task::spawn_blocking(move || {
                let _permit = permit;
                store.get(credential_id)
            })
            .await
            .map_err(|_| SecretReadError::Worker)?
            .map_err(SecretReadError::Store)
        };
        if let Some(cancellation) = cancellation {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => Err(SecretReadError::Cancelled),
                result = timeout(limit, read) => result.map_err(|_| SecretReadError::TimedOut)?,
            }
        } else {
            timeout(limit, read)
                .await
                .map_err(|_| SecretReadError::TimedOut)?
        }
    }
}

#[derive(Default)]
pub struct NativeSecretStore;

impl NativeSecretStore {
    fn map_error(error: &KeyringError) -> SecretStoreError {
        match error {
            KeyringError::NoEntry => SecretStoreError::NotFound,
            KeyringError::NoStorageAccess(_) => SecretStoreError::LockedOrDenied,
            _ => SecretStoreError::Unavailable,
        }
    }

    fn entry(credential_id: Uuid) -> Result<Entry, SecretStoreError> {
        Entry::new(KEYRING_SERVICE, &credential_id.to_string())
            .map_err(|error| Self::map_error(&error))
    }
}

impl SecretStore for NativeSecretStore {
    fn set(&self, credential_id: Uuid, secret: &str) -> Result<(), SecretStoreError> {
        Self::entry(credential_id)?
            .set_password(secret)
            .map_err(|error| Self::map_error(&error))
    }

    fn get(&self, credential_id: Uuid) -> Result<Zeroizing<String>, SecretStoreError> {
        Self::entry(credential_id)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(|error| Self::map_error(&error))
    }

    fn delete(&self, credential_id: Uuid) -> Result<(), SecretStoreError> {
        Self::entry(credential_id)?
            .delete_credential()
            .map_err(|error| Self::map_error(&error))
    }
}

pub struct MemorySecretStore {
    values: std::sync::Mutex<std::collections::HashMap<Uuid, Zeroizing<String>>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self {
            values: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl SecretStore for MemorySecretStore {
    fn set(&self, credential_id: Uuid, secret: &str) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(credential_id, Zeroizing::new(secret.to_owned()));
        Ok(())
    }

    fn get(&self, credential_id: Uuid) -> Result<Zeroizing<String>, SecretStoreError> {
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&credential_id)
            .cloned()
            .ok_or(SecretStoreError::NotFound)
    }

    fn delete(&self, credential_id: Uuid) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&credential_id)
            .map(|_| ())
            .ok_or(SecretStoreError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::{
        NativeSecretStore, SecretReadError, SecretReadGate, SecretStore, SecretStoreError,
    };

    struct BlockingStore {
        released: Arc<(Mutex<bool>, Condvar)>,
        reads: AtomicUsize,
    }

    impl SecretStore for BlockingStore {
        fn set(&self, _: Uuid, _: &str) -> Result<(), SecretStoreError> {
            unreachable!("read test never writes a secret")
        }

        fn get(&self, _: Uuid) -> Result<Zeroizing<String>, SecretStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let (lock, ready) = &*self.released;
            let mut released = lock.lock().unwrap();
            while !*released {
                let (guard, wait) = ready
                    .wait_timeout(released, Duration::from_secs(5))
                    .unwrap();
                released = guard;
                if wait.timed_out() {
                    return Err(SecretStoreError::Unavailable);
                }
            }
            Ok(Zeroizing::new("synthetic-only".to_owned()))
        }

        fn delete(&self, _: Uuid) -> Result<(), SecretStoreError> {
            unreachable!("read test never deletes a secret")
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocked_native_reads_have_a_bounded_wait_and_worker_count() {
        let store = Arc::new(BlockingStore {
            released: Arc::new((Mutex::new(false), Condvar::new())),
            reads: AtomicUsize::new(0),
        });
        let gate = SecretReadGate::new();
        let mut calls = Vec::new();
        for _ in 0..4 {
            let gate = gate.clone();
            let store = store.clone();
            calls.push(tokio::spawn(async move {
                gate.get(store, Uuid::new_v4(), Duration::from_secs(10), None)
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.reads.load(Ordering::SeqCst) != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("four native reads start");
        assert_eq!(gate.capacity.available_permits(), 0);
        let fifth = gate
            .get(
                store.clone(),
                Uuid::new_v4(),
                Duration::from_millis(20),
                None,
            )
            .await;
        assert!(matches!(fifth, Err(SecretReadError::TimedOut)));
        assert_eq!(store.reads.load(Ordering::SeqCst), 4);
        let (lock, ready) = &*store.released;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        for call in calls {
            assert!(call.await.unwrap().is_ok());
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while gate.capacity.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late results release all native read slots");
    }

    #[tokio::test]
    async fn a_timed_out_native_read_releases_its_slot_when_it_finishes() {
        let store = Arc::new(BlockingStore {
            released: Arc::new((Mutex::new(false), Condvar::new())),
            reads: AtomicUsize::new(0),
        });
        let gate = SecretReadGate::new();
        let pending = {
            let gate = gate.clone();
            let store = store.clone();
            tokio::spawn(async move {
                gate.get(store, Uuid::new_v4(), Duration::from_secs(2), None)
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.reads.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("native read started before timeout");
        let result = pending.await.unwrap();
        assert!(matches!(result, Err(SecretReadError::TimedOut)));
        let (lock, ready) = &*store.released;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        tokio::time::timeout(Duration::from_secs(2), async {
            while gate.capacity.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late read releases its slot");
    }

    #[tokio::test]
    async fn cancelled_read_does_not_start_a_native_call() {
        let store = Arc::new(BlockingStore {
            released: Arc::new((Mutex::new(false), Condvar::new())),
            reads: AtomicUsize::new(0),
        });
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = SecretReadGate::new()
            .get(
                store.clone(),
                Uuid::new_v4(),
                Duration::from_secs(1),
                Some(&cancellation),
            )
            .await;
        assert!(matches!(result, Err(SecretReadError::Cancelled)));
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    }

    struct DisposableNativeEntry {
        id: Uuid,
    }

    impl DisposableNativeEntry {
        fn new() -> Self {
            Self { id: Uuid::new_v4() }
        }
    }

    impl Drop for DisposableNativeEntry {
        fn drop(&mut self) {
            let _ = NativeSecretStore.delete(self.id);
        }
    }

    fn write_then_fail(
        store: &NativeSecretStore,
        entry: DisposableNativeEntry,
        secret: &str,
    ) -> Result<(), &'static str> {
        store
            .set(entry.id, secret)
            .expect("write failure-path disposable secret");
        drop(entry);
        Err("synthetic failure after native credential write")
    }

    #[test]
    #[ignore = "explicitly mutates the operating-system credential store"]
    fn native_store_round_trip_uses_a_disposable_entry() {
        let store = NativeSecretStore;
        let entry = DisposableNativeEntry::new();
        let initial = "secretbridge-native-store-synthetic-initial";
        let replacement = "secretbridge-native-store-synthetic-replacement";

        store
            .set(entry.id, initial)
            .expect("write disposable secret");
        assert_eq!(
            store
                .get(entry.id)
                .expect("read disposable secret")
                .as_str(),
            initial
        );
        store
            .set(entry.id, replacement)
            .expect("overwrite disposable secret");
        assert_eq!(
            store
                .get(entry.id)
                .expect("read overwritten disposable secret")
                .as_str(),
            replacement
        );
        store.delete(entry.id).expect("delete disposable secret");
        assert!(
            store.get(entry.id).is_err(),
            "deleted secret must be absent"
        );

        let failed_entry = DisposableNativeEntry::new();
        let failed_id = failed_entry.id;
        assert!(write_then_fail(&store, failed_entry, initial).is_err());
        assert!(
            store.get(failed_id).is_err(),
            "failure-path disposable secret must be cleaned"
        );
    }
}

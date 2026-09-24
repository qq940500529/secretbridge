// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coordinates catalog state with the operating-system credential store.
//!
//! External secret-store operations cannot share a transaction with SQLite. Each mutation first
//! claims the catalog version and disables execution, then changes the native entry, and finally
//! records the resulting public state. A failure after the claim therefore remains fail-closed.

use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

use tokio::{
    sync::{Mutex, OwnedMutexGuard, oneshot},
    task,
    time::timeout,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    catalog::{Catalog, CatalogError, CredentialReference, SecretState},
    secret_store::{SecretStore, SecretStoreError},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialServiceError {
    Catalog(CatalogError),
    NotConfigured,
    Store(SecretStoreError),
    TimedOut,
    Worker,
}

const NATIVE_MUTATION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct CredentialService {
    catalog: Catalog,
    store: Arc<dyn SecretStore>,
    native_mutations: Arc<Mutex<()>>,
    native_timeout: Duration,
}

impl CredentialService {
    pub(crate) fn new(
        catalog: Catalog,
        store: Arc<dyn SecretStore>,
        native_mutations: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            catalog,
            store,
            native_mutations,
            native_timeout: NATIVE_MUTATION_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(mut self, native_timeout: Duration) -> Self {
        self.native_timeout = native_timeout;
        self
    }

    async fn lock_native(&self) -> Result<OwnedMutexGuard<()>, CredentialServiceError> {
        timeout(
            self.native_timeout,
            self.native_mutations.clone().lock_owned(),
        )
        .await
        .map_err(|_| CredentialServiceError::TimedOut)
    }

    pub(crate) async fn delete(&self, id: Uuid) -> Result<(), CredentialServiceError> {
        let catalog = self.catalog.clone();
        let current = task::spawn_blocking(move || catalog.get_credential_reference(id))
            .await
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Catalog)?;

        let catalog = self.catalog.clone();
        task::spawn_blocking(move || catalog.ensure_credential_reference_deletable(id))
            .await
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Catalog)?;

        if current.secret_state == SecretState::Available {
            let catalog = self.catalog.clone();
            task::spawn_blocking(move || {
                catalog.begin_credential_secret_mutation(id, current.version)
            })
            .await
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Catalog)?;
        }
        // Also clear a previously timed-out native write before removing an
        // unconfigured reference. The native gate keeps late writes ordered.
        self.delete_native_entry(id).await?;

        let catalog = self.catalog.clone();
        task::spawn_blocking(move || catalog.delete_credential_reference(id))
            .await
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Catalog)
    }

    pub(crate) async fn set(
        &self,
        id: Uuid,
        expected_version: u64,
        secret: Zeroizing<String>,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let catalog = self.catalog.clone();
        let pending = task::spawn_blocking(move || {
            catalog.begin_credential_secret_mutation(id, expected_version)
        })
        .await
        .map_err(|_| CredentialServiceError::Worker)?
        .map_err(CredentialServiceError::Catalog)?;

        let native_guard = self.lock_native().await?;
        let store = self.store.clone();
        let catalog = self.catalog.clone();
        let (ready_sender, ready_receiver) = oneshot::channel();
        let (commit_sender, commit_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = oneshot::channel();
        task::spawn_blocking(move || {
            let _native_guard = native_guard;
            match store.set(id, secret.as_str()) {
                Ok(()) => {
                    // If the request timed out or was cancelled, never publish
                    // the entry as configured. Clear its late native write
                    // before another mutation can take the gate.
                    if ready_sender.send(Ok(())).is_err() || commit_receiver.recv().is_err() {
                        if store.delete(id).is_err() {
                            tracing::warn!(code = "native_secret_cleanup_failed");
                        }
                        return;
                    }
                    let result = catalog
                        .finish_credential_secret_mutation(id, pending.version, true)
                        .map_err(CredentialServiceError::Catalog);
                    if result.is_err() && store.delete(id).is_err() {
                        tracing::warn!(code = "native_secret_cleanup_failed");
                    }
                    let _ = finished_sender.send(result);
                }
                Err(error) => {
                    // Some native providers may report an error after changing
                    // their entry. Keep the catalog disabled and remove any
                    // partial write before releasing the mutation gate.
                    if store.delete(id).is_err() {
                        tracing::warn!(code = "native_secret_cleanup_failed");
                    }
                    let _ = ready_sender.send(Err(error));
                }
            }
        });
        timeout(self.native_timeout, ready_receiver)
            .await
            .map_err(|_| CredentialServiceError::TimedOut)?
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Store)?;
        commit_sender
            .send(())
            .map_err(|_| CredentialServiceError::Worker)?;
        finished_receiver
            .await
            .map_err(|_| CredentialServiceError::Worker)?
    }

    pub(crate) async fn clear(
        &self,
        id: Uuid,
        expected_version: u64,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let catalog = self.catalog.clone();
        let current = task::spawn_blocking(move || catalog.get_credential_reference(id))
            .await
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Catalog)?;
        if current.version != expected_version {
            return Err(CredentialServiceError::Catalog(
                CatalogError::VersionConflict,
            ));
        }
        if current.secret_state == SecretState::NotConfigured {
            return Err(CredentialServiceError::NotConfigured);
        }

        let catalog = self.catalog.clone();
        let pending = task::spawn_blocking(move || {
            catalog.begin_credential_secret_mutation(id, expected_version)
        })
        .await
        .map_err(|_| CredentialServiceError::Worker)?
        .map_err(CredentialServiceError::Catalog)?;
        self.delete_native_entry(id).await?;

        let catalog = self.catalog.clone();
        task::spawn_blocking(move || {
            catalog.finish_credential_secret_mutation(id, pending.version, false)
        })
        .await
        .map_err(|_| CredentialServiceError::Worker)?
        .map_err(CredentialServiceError::Catalog)
    }

    async fn delete_native_entry(&self, id: Uuid) -> Result<(), CredentialServiceError> {
        let native_guard = self.lock_native().await?;
        let store = self.store.clone();
        match timeout(
            self.native_timeout,
            task::spawn_blocking(move || {
                let _native_guard = native_guard;
                store.delete(id)
            }),
        )
        .await
        .map_err(|_| CredentialServiceError::TimedOut)?
        .map_err(|_| CredentialServiceError::Worker)?
        {
            Ok(()) | Err(SecretStoreError::NotFound) => Ok(()),
            Err(error) => Err(CredentialServiceError::Store(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Condvar, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Notify;

    use super::*;

    struct PausedWriteStore {
        released: (StdMutex<bool>, Condvar),
        started: Notify,
        delete_released: (StdMutex<bool>, Condvar),
        delete_started: Notify,
        value: StdMutex<Option<Zeroizing<String>>>,
        deletions: AtomicUsize,
    }

    impl PausedWriteStore {
        fn new(write_released: bool, delete_released: bool) -> Self {
            Self {
                released: (StdMutex::new(write_released), Condvar::new()),
                started: Notify::new(),
                delete_released: (StdMutex::new(delete_released), Condvar::new()),
                delete_started: Notify::new(),
                value: StdMutex::new(None),
                deletions: AtomicUsize::new(0),
            }
        }

        fn release_write(&self) {
            let (lock, ready) = &self.released;
            *lock.lock().unwrap() = true;
            ready.notify_all();
        }

        fn release_delete(&self) {
            let (lock, ready) = &self.delete_released;
            *lock.lock().unwrap() = true;
            ready.notify_all();
        }
    }

    impl SecretStore for PausedWriteStore {
        fn set(&self, _: Uuid, secret: &str) -> Result<(), SecretStoreError> {
            self.started.notify_one();
            let (lock, ready) = &self.released;
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
            *self.value.lock().unwrap() = Some(Zeroizing::new(secret.to_owned()));
            Ok(())
        }

        fn get(&self, _: Uuid) -> Result<Zeroizing<String>, SecretStoreError> {
            self.value
                .lock()
                .unwrap()
                .clone()
                .ok_or(SecretStoreError::NotFound)
        }

        fn delete(&self, _: Uuid) -> Result<(), SecretStoreError> {
            self.delete_started.notify_one();
            let (lock, ready) = &self.delete_released;
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
            self.deletions.fetch_add(1, Ordering::SeqCst);
            self.value
                .lock()
                .unwrap()
                .take()
                .map(|_| ())
                .ok_or(SecretStoreError::NotFound)
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn late_native_write_is_removed_before_a_retry_can_publish_it() {
        let catalog = Catalog::in_memory().unwrap();
        let credential = catalog
            .create_credential_reference(
                &serde_json::from_value(serde_json::json!({
                    "name": "Synthetic write recovery",
                    "kind": "password"
                }))
                .unwrap(),
            )
            .unwrap();
        let store = Arc::new(PausedWriteStore::new(false, true));
        let service =
            CredentialService::new(catalog.clone(), store.clone(), Arc::new(Mutex::new(())))
                .with_timeout(Duration::from_millis(100));
        let credential_id = credential.id;
        let credential_version = credential.version;
        let pending = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .set(
                        credential_id,
                        credential_version,
                        Zeroizing::new("synthetic-first".to_owned()),
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), store.started.notified())
            .await
            .expect("native write started");
        assert!(matches!(
            pending.await.unwrap(),
            Err(CredentialServiceError::TimedOut)
        ));
        assert_eq!(
            catalog
                .get_credential_reference(credential_id)
                .unwrap()
                .secret_state,
            SecretState::NotConfigured
        );

        store.release_write();
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.deletions.load(Ordering::SeqCst) != 1 || store.get(credential_id).is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late write cleanup completed");
        assert!(matches!(
            store.get(credential_id),
            Err(SecretStoreError::NotFound)
        ));

        let current = catalog.get_credential_reference(credential_id).unwrap();
        let configured = service
            .set(
                credential_id,
                current.version,
                Zeroizing::new("synthetic-retry".to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(configured.secret_state, SecretState::Available);
        assert_eq!(
            store.get(credential_id).unwrap().as_str(),
            "synthetic-retry"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_native_write_is_removed_before_a_retry() {
        let catalog = Catalog::in_memory().unwrap();
        let credential = catalog
            .create_credential_reference(
                &serde_json::from_value(serde_json::json!({
                    "name": "Synthetic cancelled write",
                    "kind": "password"
                }))
                .unwrap(),
            )
            .unwrap();
        let store = Arc::new(PausedWriteStore::new(false, true));
        let service =
            CredentialService::new(catalog.clone(), store.clone(), Arc::new(Mutex::new(())));
        let credential_id = credential.id;
        let pending = {
            let service = service.clone();
            tokio::spawn(async move {
                service
                    .set(
                        credential_id,
                        credential.version,
                        Zeroizing::new("synthetic-cancelled".to_owned()),
                    )
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), store.started.notified())
            .await
            .expect("native write started");
        pending.abort();
        let _ = pending.await;
        store.release_write();
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.deletions.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled write cleanup completed");
        assert_eq!(
            catalog
                .get_credential_reference(credential_id)
                .unwrap()
                .secret_state,
            SecretState::NotConfigured
        );
        assert!(matches!(
            store.get(credential_id),
            Err(SecretStoreError::NotFound)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn late_native_delete_cannot_remove_a_retry() {
        let catalog = Catalog::in_memory().unwrap();
        let credential = catalog
            .create_credential_reference(
                &serde_json::from_value(serde_json::json!({
                    "name": "Synthetic late delete",
                    "kind": "password"
                }))
                .unwrap(),
            )
            .unwrap();
        let store = Arc::new(PausedWriteStore::new(true, true));
        let service =
            CredentialService::new(catalog.clone(), store.clone(), Arc::new(Mutex::new(())))
                .with_timeout(Duration::from_millis(100));
        let credential_id = credential.id;
        let configured = service
            .set(
                credential_id,
                credential.version,
                Zeroizing::new("synthetic-old".to_owned()),
            )
            .await
            .unwrap();
        *store.delete_released.0.lock().unwrap() = false;
        let pending = {
            let service = service.clone();
            tokio::spawn(async move { service.clear(credential_id, configured.version).await })
        };
        tokio::time::timeout(Duration::from_secs(2), store.delete_started.notified())
            .await
            .expect("native deletion started");
        assert!(matches!(
            pending.await.unwrap(),
            Err(CredentialServiceError::TimedOut)
        ));
        assert_eq!(
            catalog
                .get_credential_reference(credential_id)
                .unwrap()
                .secret_state,
            SecretState::NotConfigured
        );
        store.release_delete();
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.deletions.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late deletion completed");
        let current = catalog.get_credential_reference(credential_id).unwrap();
        let retried = service
            .set(
                credential_id,
                current.version,
                Zeroizing::new("synthetic-new".to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(retried.secret_state, SecretState::Available);
        assert_eq!(store.get(credential_id).unwrap().as_str(), "synthetic-new");
    }
}

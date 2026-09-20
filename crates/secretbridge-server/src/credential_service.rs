// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coordinates catalog state with the operating-system credential store.
//!
//! External secret-store operations cannot share a transaction with SQLite. Each mutation first
//! claims the catalog version and disables execution, then changes the native entry, and finally
//! records the resulting public state. A failure after the claim therefore remains fail-closed.

use std::sync::Arc;

use tokio::task;
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
    Worker,
}

#[derive(Clone)]
pub(crate) struct CredentialService {
    catalog: Catalog,
    store: Arc<dyn SecretStore>,
}

impl CredentialService {
    pub(crate) fn new(catalog: Catalog, store: Arc<dyn SecretStore>) -> Self {
        Self { catalog, store }
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
            self.delete_native_entry(id).await?;
        }

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

        let store = self.store.clone();
        task::spawn_blocking(move || store.set(id, &secret))
            .await
            .map_err(|_| CredentialServiceError::Worker)?
            .map_err(CredentialServiceError::Store)?;

        let catalog = self.catalog.clone();
        task::spawn_blocking(move || {
            catalog.finish_credential_secret_mutation(id, pending.version, true)
        })
        .await
        .map_err(|_| CredentialServiceError::Worker)?
        .map_err(CredentialServiceError::Catalog)
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
        let store = self.store.clone();
        match task::spawn_blocking(move || store.delete(id))
            .await
            .map_err(|_| CredentialServiceError::Worker)?
        {
            Ok(()) | Err(SecretStoreError::NotFound) => Ok(()),
            Err(error) => Err(CredentialServiceError::Store(error)),
        }
    }
}

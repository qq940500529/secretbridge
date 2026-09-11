// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_CREDENTIAL_REFERENCES: usize = 128;
const MAX_TARGETS: usize = 128;
const MAX_NAME_CHARS: usize = 80;
const MAX_DESCRIPTION_CHARS: usize = 240;

#[derive(Clone, Default)]
pub struct Catalog {
    data: Arc<RwLock<CatalogData>>,
}

#[derive(Default)]
struct CatalogData {
    credential_references: HashMap<Uuid, CredentialReference>,
    targets: HashMap<Uuid, Target>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    Password,
    ApiToken,
    SshKey,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    NotConfigured,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialReference {
    pub id: Uuid,
    pub name: String,
    pub kind: CredentialKind,
    pub purpose: Option<String>,
    pub secret_state: SecretState,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCredentialReference {
    name: String,
    kind: CredentialKind,
    purpose: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Database,
    HttpService,
    SshHost,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetEnvironment {
    Development,
    Test,
    Production,
}

#[derive(Clone, Debug, Serialize)]
pub struct Target {
    pub id: Uuid,
    pub name: String,
    pub kind: TargetKind,
    pub environment: TargetEnvironment,
    pub description: Option<String>,
    pub credential_reference_id: Option<Uuid>,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTarget {
    name: String,
    kind: TargetKind,
    environment: TargetEnvironment,
    description: Option<String>,
    credential_reference_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    Capacity,
    CredentialReferenceNotFound,
    Invalid,
    NotFound,
    ResourceInUse,
}

impl Catalog {
    #[must_use]
    pub fn list_credential_references(&self) -> Vec<CredentialReference> {
        let mut items = self
            .read_data()
            .credential_references
            .values()
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by_key(|item| (item.created_at_unix_ms, item.id));
        items
    }

    pub fn create_credential_reference(
        &self,
        request: &CreateCredentialReference,
    ) -> Result<CredentialReference, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let purpose = normalize_optional(request.purpose.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let mut data = self.write_data();
        if data.credential_references.len() >= MAX_CREDENTIAL_REFERENCES {
            return Err(CatalogError::Capacity);
        }
        let item = CredentialReference {
            id: Uuid::new_v4(),
            name,
            kind: request.kind,
            purpose,
            secret_state: SecretState::NotConfigured,
            created_at_unix_ms: now_unix_ms(),
        };
        data.credential_references.insert(item.id, item.clone());
        Ok(item)
    }

    pub fn delete_credential_reference(&self, id: Uuid) -> Result<(), CatalogError> {
        let mut data = self.write_data();
        if data
            .targets
            .values()
            .any(|target| target.credential_reference_id == Some(id))
        {
            return Err(CatalogError::ResourceInUse);
        }
        data.credential_references
            .remove(&id)
            .map(|_| ())
            .ok_or(CatalogError::NotFound)
    }

    #[must_use]
    pub fn list_targets(&self) -> Vec<Target> {
        let mut items = self
            .read_data()
            .targets
            .values()
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by_key(|item| (item.created_at_unix_ms, item.id));
        items
    }

    pub fn create_target(&self, request: &CreateTarget) -> Result<Target, CatalogError> {
        let name = normalize_required(&request.name, MAX_NAME_CHARS)?;
        let description =
            normalize_optional(request.description.as_deref(), MAX_DESCRIPTION_CHARS)?;
        let mut data = self.write_data();
        if data.targets.len() >= MAX_TARGETS {
            return Err(CatalogError::Capacity);
        }
        if request
            .credential_reference_id
            .is_some_and(|id| !data.credential_references.contains_key(&id))
        {
            return Err(CatalogError::CredentialReferenceNotFound);
        }
        let target = Target {
            id: Uuid::new_v4(),
            name,
            kind: request.kind,
            environment: request.environment,
            description,
            credential_reference_id: request.credential_reference_id,
            created_at_unix_ms: now_unix_ms(),
        };
        data.targets.insert(target.id, target.clone());
        Ok(target)
    }

    pub fn delete_target(&self, id: Uuid) -> Result<(), CatalogError> {
        self.write_data()
            .targets
            .remove(&id)
            .map(|_| ())
            .ok_or(CatalogError::NotFound)
    }

    fn read_data(&self) -> std::sync::RwLockReadGuard<'_, CatalogData> {
        self.data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_data(&self) -> std::sync::RwLockWriteGuard<'_, CatalogData> {
        self.data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn normalize_required(value: &str, maximum: usize) -> Result<String, CatalogError> {
    let value = value.trim();
    let count = value.chars().count();
    if count == 0 || count > maximum || value.chars().any(char::is_control) {
        return Err(CatalogError::Invalid);
    }
    Ok(value.to_owned())
}

fn normalize_optional(value: Option<&str>, maximum: usize) -> Result<Option<String>, CatalogError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    normalize_required(value, maximum).map(Some)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        Catalog, CatalogError, CreateCredentialReference, CreateTarget, CredentialKind,
        TargetEnvironment, TargetKind,
    };
    use uuid::Uuid;

    #[test]
    fn linked_reference_cannot_be_deleted_before_its_target() {
        let catalog = Catalog::default();
        let credential = catalog
            .create_credential_reference(&CreateCredentialReference {
                name: "Synthetic database operator".to_owned(),
                kind: CredentialKind::Password,
                purpose: None,
            })
            .expect("synthetic reference");
        let target = catalog
            .create_target(&CreateTarget {
                name: "Synthetic reporting database".to_owned(),
                kind: TargetKind::Database,
                environment: TargetEnvironment::Test,
                description: None,
                credential_reference_id: Some(credential.id),
            })
            .expect("synthetic target");

        assert_eq!(
            catalog.delete_credential_reference(credential.id),
            Err(CatalogError::ResourceInUse)
        );
        catalog.delete_target(target.id).expect("delete target");
        catalog
            .delete_credential_reference(credential.id)
            .expect("delete unlinked reference");
    }

    #[test]
    fn control_characters_and_unknown_links_are_rejected() {
        let catalog = Catalog::default();
        let invalid = catalog.create_credential_reference(&CreateCredentialReference {
            name: "unsafe\nname".to_owned(),
            kind: CredentialKind::ApiToken,
            purpose: None,
        });
        assert!(matches!(invalid, Err(CatalogError::Invalid)));

        let target = catalog.create_target(&CreateTarget {
            name: "Synthetic target".to_owned(),
            kind: TargetKind::HttpService,
            environment: TargetEnvironment::Development,
            description: None,
            credential_reference_id: Some(Uuid::new_v4()),
        });
        assert!(matches!(
            target,
            Err(CatalogError::CredentialReferenceNotFound)
        ));
    }
}

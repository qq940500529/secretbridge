// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{error::Error, fmt};

use keyring::Entry;
use uuid::Uuid;
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "com.shulianchuangyuan.secretbridge";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretStoreError {
    Unavailable,
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the operating-system credential store is unavailable")
    }
}

impl Error for SecretStoreError {}

pub trait SecretStore: Send + Sync {
    fn set(&self, credential_id: Uuid, secret: &str) -> Result<(), SecretStoreError>;
    fn get(&self, credential_id: Uuid) -> Result<Zeroizing<String>, SecretStoreError>;
    fn delete(&self, credential_id: Uuid) -> Result<(), SecretStoreError>;
}

#[derive(Default)]
pub struct NativeSecretStore;

impl NativeSecretStore {
    fn entry(credential_id: Uuid) -> Result<Entry, SecretStoreError> {
        Entry::new(KEYRING_SERVICE, &credential_id.to_string())
            .map_err(|_| SecretStoreError::Unavailable)
    }
}

impl SecretStore for NativeSecretStore {
    fn set(&self, credential_id: Uuid, secret: &str) -> Result<(), SecretStoreError> {
        Self::entry(credential_id)?
            .set_password(secret)
            .map_err(|_| SecretStoreError::Unavailable)
    }

    fn get(&self, credential_id: Uuid) -> Result<Zeroizing<String>, SecretStoreError> {
        Self::entry(credential_id)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(|_| SecretStoreError::Unavailable)
    }

    fn delete(&self, credential_id: Uuid) -> Result<(), SecretStoreError> {
        Self::entry(credential_id)?
            .delete_credential()
            .map_err(|_| SecretStoreError::Unavailable)
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
            .ok_or(SecretStoreError::Unavailable)
    }

    fn delete(&self, credential_id: Uuid) -> Result<(), SecretStoreError> {
        self.values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&credential_id)
            .map(|_| ())
            .ok_or(SecretStoreError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{NativeSecretStore, SecretStore};

    #[test]
    #[ignore = "explicitly mutates the operating-system credential store"]
    fn native_store_round_trip_uses_a_disposable_entry() {
        let store = NativeSecretStore;
        let id = Uuid::new_v4();
        let secret = "secretbridge-native-store-synthetic-check";
        store.set(id, secret).expect("write disposable secret");
        let loaded = store.get(id);
        let _ = store.delete(id);
        assert_eq!(loaded.expect("read disposable secret").as_str(), secret);
    }
}

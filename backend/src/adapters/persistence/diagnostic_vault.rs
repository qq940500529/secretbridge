// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Append-only encrypted diagnostic records. The broker holds only the public key between exports.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::Argon2;
use hkdf::Hkdf;
use p256::{PublicKey, Sec1Point, SecretKey, ecdh::EphemeralSecret, elliptic_curve::Generate};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Catalog, CatalogError, now_unix_ms_i64};

const WRAP_AAD: &[u8] = b"secretbridge/diagnostic-vault/private/v1";
const RECOVERY_WRAP_AAD: &[u8] = b"secretbridge/diagnostic-vault/recovery/v1";
const RECORD_AAD: &[u8] = b"secretbridge/diagnostic-vault/record/v1";
const MAX_RECORD_BYTES: usize = 32 * 1024;
const MAX_RECORDS: i64 = 2_000;

#[derive(Debug, Deserialize, Serialize)]
pub struct UnlockedDiagnosticRecord {
    pub category: String,
    pub created_at_unix_ms: u64,
    pub data: serde_json::Value,
}

struct VaultHeader {
    public_key: Vec<u8>,
    salt: Vec<u8>,
    wrap_nonce: Vec<u8>,
    wrapped_private_key: Vec<u8>,
    recovery_salt: Option<Vec<u8>>,
    recovery_nonce: Option<Vec<u8>>,
    recovery_wrapped_private_key: Option<Vec<u8>>,
}

struct WrappedPrivateKey {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

fn new_recovery_key() -> Zeroizing<String> {
    let random: [u8; 32] = rand::random();
    Zeroizing::new(hex::encode(random))
}

fn wrap_private(
    private: &SecretKey,
    passphrase: &str,
    aad: &[u8],
) -> Result<WrappedPrivateKey, CatalogError> {
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 12] = rand::random();
    let key = derive_wrap_key(passphrase, &salt)?;
    let private_bytes = Zeroizing::new(private.to_bytes());
    let wrapped = seal(&key, &nonce, &private_bytes, aad)?;
    Ok(WrappedPrivateKey {
        salt,
        nonce,
        ciphertext: wrapped,
    })
}

fn derive_wrap_key(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CatalogError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::default()
        .hash_password_into(pin.as_bytes(), salt, &mut *key)
        .map_err(|_| CatalogError::Storage)?;
    Ok(key)
}

fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CatalogError> {
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| CatalogError::Storage)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| CatalogError::Storage)?
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CatalogError::Storage)
}

fn open(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CatalogError> {
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| CatalogError::Storage)?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| CatalogError::Storage)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| CatalogError::Storage)?
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CatalogError::Invalid)
}

fn header(connection: &rusqlite::Connection) -> Result<Option<VaultHeader>, CatalogError> {
    connection
        .query_row(
            "SELECT public_key, salt, wrap_nonce, wrapped_private_key,
                recovery_salt, recovery_nonce, recovery_wrapped_private_key
           FROM diagnostic_vault WHERE singleton = 1",
            [],
            |row| {
                Ok(VaultHeader {
                    public_key: row.get(0)?,
                    salt: row.get(1)?,
                    wrap_nonce: row.get(2)?,
                    wrapped_private_key: row.get(3)?,
                    recovery_salt: row.get(4)?,
                    recovery_nonce: row.get(5)?,
                    recovery_wrapped_private_key: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|_| CatalogError::Storage)
}

fn unwrap_private(header: &VaultHeader, pin: &str) -> Result<SecretKey, CatalogError> {
    let key = derive_wrap_key(pin, &header.salt)?;
    let plaintext = open(
        &key,
        &header.wrap_nonce,
        &header.wrapped_private_key,
        WRAP_AAD,
    )?;
    let private = SecretKey::from_slice(&plaintext).map_err(|_| CatalogError::Storage)?;
    let expected =
        PublicKey::from_sec1_bytes(&header.public_key).map_err(|_| CatalogError::Storage)?;
    if private.public_key() != expected {
        return Err(CatalogError::Storage);
    }
    Ok(private)
}

fn unwrap_recovery_private(
    header: &VaultHeader,
    recovery_key: &str,
) -> Result<SecretKey, CatalogError> {
    if recovery_key.len() != 64 || !recovery_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CatalogError::Invalid);
    }
    let salt = header
        .recovery_salt
        .as_deref()
        .ok_or(CatalogError::Invalid)?;
    let nonce = header
        .recovery_nonce
        .as_deref()
        .ok_or(CatalogError::Invalid)?;
    let wrapped = header
        .recovery_wrapped_private_key
        .as_deref()
        .ok_or(CatalogError::Invalid)?;
    let key = derive_wrap_key(recovery_key, salt)?;
    let plaintext = open(&key, nonce, wrapped, RECOVERY_WRAP_AAD)?;
    let private = SecretKey::from_slice(&plaintext).map_err(|_| CatalogError::Storage)?;
    let expected =
        PublicKey::from_sec1_bytes(&header.public_key).map_err(|_| CatalogError::Storage)?;
    if private.public_key() != expected {
        return Err(CatalogError::Storage);
    }
    Ok(private)
}

impl Catalog {
    pub fn verify_diagnostic_pin(&self, pin: &str) -> Result<bool, CatalogError> {
        let connection = self.lock();
        let header = header(&connection)?.ok_or(CatalogError::Invalid)?;
        Ok(unwrap_private(&header, pin).is_ok())
    }
    pub fn diagnostic_vault_ready(&self) -> Result<bool, CatalogError> {
        Ok(header(&self.lock())?.is_some())
    }

    pub fn initialize_diagnostic_vault(&self, pin: &str) -> Result<String, CatalogError> {
        let connection = self.lock();
        if header(&connection)?.is_some() {
            return Err(CatalogError::Invalid);
        }
        let private = SecretKey::generate();
        let public = Sec1Point::from(private.public_key());
        let pin_wrap = wrap_private(&private, pin, WRAP_AAD)?;
        let recovery_key = new_recovery_key();
        let recovery_wrap = wrap_private(&private, &recovery_key, RECOVERY_WRAP_AAD)?;
        connection.execute(
            "INSERT INTO diagnostic_vault(singleton, public_key, salt, wrap_nonce, wrapped_private_key,
                recovery_salt, recovery_nonce, recovery_wrapped_private_key)
             VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![public.as_ref(), pin_wrap.salt.as_slice(), pin_wrap.nonce.as_slice(), pin_wrap.ciphertext,
                recovery_wrap.salt.as_slice(), recovery_wrap.nonce.as_slice(), recovery_wrap.ciphertext],
        ).map_err(|_| CatalogError::Storage)?;
        Ok(recovery_key.to_string())
    }

    pub fn rotate_diagnostic_vault_pin(
        &self,
        old_pin: &str,
        new_pin: &str,
    ) -> Result<(), CatalogError> {
        let connection = self.lock();
        let header = header(&connection)?.ok_or(CatalogError::Invalid)?;
        let private = unwrap_private(&header, old_pin)?;
        let wrapped = wrap_private(&private, new_pin, WRAP_AAD)?;
        connection.execute(
            "UPDATE diagnostic_vault SET salt = ?1, wrap_nonce = ?2, wrapped_private_key = ?3 WHERE singleton = 1",
            params![wrapped.salt.as_slice(), wrapped.nonce.as_slice(), wrapped.ciphertext],
        ).map_err(|_| CatalogError::Storage)?;
        Ok(())
    }

    pub fn regenerate_diagnostic_recovery_key(&self, pin: &str) -> Result<String, CatalogError> {
        let connection = self.lock();
        let header = header(&connection)?.ok_or(CatalogError::Invalid)?;
        let private = unwrap_private(&header, pin)?;
        let recovery_key = new_recovery_key();
        let wrapped = wrap_private(&private, &recovery_key, RECOVERY_WRAP_AAD)?;
        connection
            .execute(
                "UPDATE diagnostic_vault SET recovery_salt = ?1, recovery_nonce = ?2,
                recovery_wrapped_private_key = ?3 WHERE singleton = 1",
                params![
                    wrapped.salt.as_slice(),
                    wrapped.nonce.as_slice(),
                    wrapped.ciphertext
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        Ok(recovery_key.to_string())
    }

    pub fn recover_diagnostic_vault_pin(
        &self,
        recovery_key: &str,
        new_pin: &str,
    ) -> Result<String, CatalogError> {
        let connection = self.lock();
        let header = header(&connection)?.ok_or(CatalogError::Invalid)?;
        let private = unwrap_recovery_private(&header, recovery_key)?;
        let pin_wrap = wrap_private(&private, new_pin, WRAP_AAD)?;
        let next_key = new_recovery_key();
        let recovery_wrap = wrap_private(&private, &next_key, RECOVERY_WRAP_AAD)?;
        connection
            .execute(
                "UPDATE diagnostic_vault SET salt = ?1, wrap_nonce = ?2, wrapped_private_key = ?3,
                recovery_salt = ?4, recovery_nonce = ?5, recovery_wrapped_private_key = ?6
             WHERE singleton = 1",
                params![
                    pin_wrap.salt.as_slice(),
                    pin_wrap.nonce.as_slice(),
                    pin_wrap.ciphertext,
                    recovery_wrap.salt.as_slice(),
                    recovery_wrap.nonce.as_slice(),
                    recovery_wrap.ciphertext
                ],
            )
            .map_err(|_| CatalogError::Storage)?;
        Ok(next_key.to_string())
    }

    pub fn record_encrypted_diagnostic(
        &self,
        category: &str,
        data: serde_json::Value,
    ) -> Result<(), CatalogError> {
        let connection = self.lock();
        let header = header(&connection)?.ok_or(CatalogError::Invalid)?;
        let public =
            PublicKey::from_sec1_bytes(&header.public_key).map_err(|_| CatalogError::Storage)?;
        let record = UnlockedDiagnosticRecord {
            category: category.to_owned(),
            created_at_unix_ms: u64::try_from(now_unix_ms_i64()?)
                .map_err(|_| CatalogError::Storage)?,
            data,
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&record).map_err(|_| CatalogError::Storage)?);
        if plaintext.len() > MAX_RECORD_BYTES {
            return Err(CatalogError::Invalid);
        }
        let ephemeral = EphemeralSecret::generate();
        let ephemeral_public = Sec1Point::from(ephemeral.public_key());
        let shared = ephemeral.diffie_hellman(&public);
        let mut key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(Some(RECORD_AAD), shared.raw_secret_bytes().as_slice())
            .expand(&header.public_key, &mut *key)
            .map_err(|_| CatalogError::Storage)?;
        let nonce: [u8; 12] = rand::random();
        let ciphertext = seal(&key, &nonce, &plaintext, RECORD_AAD)?;
        connection.execute(
            "INSERT INTO diagnostic_records(ephemeral_public_key, nonce, ciphertext) VALUES(?1, ?2, ?3)",
            params![ephemeral_public.as_ref(), nonce.as_slice(), ciphertext],
        ).map_err(|_| CatalogError::Storage)?;
        connection.execute(
            "DELETE FROM diagnostic_records WHERE id NOT IN (SELECT id FROM diagnostic_records ORDER BY id DESC LIMIT ?1)",
            [MAX_RECORDS],
        ).map_err(|_| CatalogError::Storage)?;
        Ok(())
    }

    pub fn unlock_diagnostic_records(
        &self,
        pin: &str,
        include_commands: bool,
        include_events: bool,
    ) -> Result<Vec<UnlockedDiagnosticRecord>, CatalogError> {
        let connection = self.lock();
        let header = header(&connection)?.ok_or(CatalogError::Invalid)?;
        let private = unwrap_private(&header, pin)?;
        let mut statement = connection.prepare(
            "SELECT ephemeral_public_key, nonce, ciphertext FROM diagnostic_records ORDER BY id DESC LIMIT ?1",
        ).map_err(|_| CatalogError::Storage)?;
        let rows = statement
            .query_map([MAX_RECORDS], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| CatalogError::Storage)?;
        let mut output = Vec::new();
        for row in rows {
            let (ephemeral_public, nonce, ciphertext) = row.map_err(|_| CatalogError::Storage)?;
            let public =
                PublicKey::from_sec1_bytes(&ephemeral_public).map_err(|_| CatalogError::Storage)?;
            let shared = private.diffie_hellman(&public);
            let mut key = Zeroizing::new([0_u8; 32]);
            Hkdf::<Sha256>::new(Some(RECORD_AAD), shared.raw_secret_bytes().as_slice())
                .expand(&header.public_key, &mut *key)
                .map_err(|_| CatalogError::Storage)?;
            let plaintext = open(&key, &nonce, &ciphertext, RECORD_AAD)?;
            let record: UnlockedDiagnosticRecord =
                serde_json::from_slice(&plaintext).map_err(|_| CatalogError::Storage)?;
            if (record.category == "command" && include_commands)
                || (record.category != "command" && include_events)
            {
                output.push(record);
            }
        }
        output.reverse();
        Ok(output)
    }
}

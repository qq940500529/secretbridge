// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    Catalog, CatalogError, CredentialKind, SecretState, TargetKind, credential_by_id,
    ensure_capacity, normalize_optional, normalize_required, now_unix_ms_i64, params, target_by_id,
};
use crate::database_task::{DatabaseConfig, DatabaseOperation};
use crate::domain::resources::{
    ConnectionOptions, HttpAuthentication, Resource, ResourceAuthentication, ResourceRequest,
};
use uuid::Uuid;

fn resource(connection: &rusqlite::Connection, id: Uuid) -> Result<Resource, CatalogError> {
    let target = target_by_id(connection, id)?.ok_or(CatalogError::NotFound)?;
    let credential = credential_by_id(connection, id)?.ok_or(CatalogError::Storage)?;
    let (labels, options): (String, String) = connection
        .query_row(
            "SELECT labels_json, options_json FROM resource_configuration WHERE resource_id = ?1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| CatalogError::Storage)?;
    Ok(Resource {
        target,
        authentication: ResourceAuthentication {
            kind: credential.kind,
            secret_state: credential.secret_state,
            secret_version: credential.version,
        },
        labels: serde_json::from_str(&labels).map_err(|_| CatalogError::Storage)?,
        connection: serde_json::from_str(&options).map_err(|_| CatalogError::Storage)?,
    })
}

impl ResourceRequest {
    fn validate(&self) -> Result<(), CatalogError> {
        normalize_required(&self.name, 80)?;
        normalize_optional(self.description.as_deref(), 240)?;
        normalize_optional(self.address.as_deref(), 2048)?;
        normalize_optional(self.username.as_deref(), 256)?;
        if self.labels.len() > 16
            || self
                .labels
                .iter()
                .any(|label| normalize_required(label, 40).is_err())
        {
            return Err(CatalogError::Invalid);
        }
        let host = self.address.as_deref().unwrap_or("");
        let username = self.username.as_deref().unwrap_or("");
        match &self.connection {
            ConnectionOptions::None => (),
            ConnectionOptions::Database {
                engine,
                port,
                database,
                tls_mode,
                ca_certificate,
            } => {
                if self.kind != TargetKind::Database
                    || self.authentication_kind != CredentialKind::Password
                {
                    return Err(CatalogError::Invalid);
                }
                let db = DatabaseConfig {
                    engine: *engine,
                    operation: DatabaseOperation::Check,
                    host: placeholder(host, "resource.example.invalid").into(),
                    port: *port,
                    database: placeholder(database, "resource_database").into(),
                    username: placeholder(username, "resource_user").into(),
                    password_slot: "authentication".into(),
                    tls_mode: *tls_mode,
                    ca_certificate: ca_certificate.clone(),
                    query: String::new(),
                    columns: vec![],
                    max_rows: 1,
                    expected_min_rows: None,
                };
                let command = crate::domain::resources::database_command(db, Uuid::nil());
                command.validate()?;
            }
            ConnectionOptions::Ssh {
                port,
                host_key_sha256,
            } => {
                if self.kind != TargetKind::SshHost
                    || self.authentication_kind == CredentialKind::ApiToken
                {
                    return Err(CatalogError::Invalid);
                }
                let command = crate::domain::resources::ssh_command(
                    placeholder(host, "resource.example.invalid"),
                    placeholder(username, "resource_user"),
                    *port,
                    placeholder(
                        host_key_sha256,
                        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    ),
                    self.authentication_kind,
                    Uuid::nil(),
                );
                command.validate()?;
            }
            ConnectionOptions::Telnet { .. } => {
                if self.kind != TargetKind::TelnetHost {
                    return Err(CatalogError::Invalid);
                }
            }
            ConnectionOptions::Http {
                authentication,
                header_name,
            } => self.validate_http(host, username, *authentication, header_name.as_deref())?,
        }
        Ok(())
    }
    fn validate_http(
        &self,
        host: &str,
        username: &str,
        authentication: HttpAuthentication,
        header_name: Option<&str>,
    ) -> Result<(), CatalogError> {
        let url = reqwest::Url::parse(placeholder(host, "https://resource.example.invalid"))
            .map_err(|_| CatalogError::Invalid)?;
        if self.kind != TargetKind::HttpService
            || !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || (matches!(&authentication, HttpAuthentication::Basic)
                && username.contains([':', '\r', '\n', '\0']))
        {
            return Err(CatalogError::Invalid);
        }
        if matches!(authentication, HttpAuthentication::ApiKey) {
            let header = placeholder(header_name.unwrap_or(""), "X-API-Key");
            reqwest::header::HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| CatalogError::Invalid)?;
            if header.len() > 128
                || matches!(
                    header.to_ascii_lowercase().as_str(),
                    "host"
                        | "content-length"
                        | "transfer-encoding"
                        | "connection"
                        | "accept-encoding"
                        | "content-type"
                        | "authorization"
                )
            {
                return Err(CatalogError::Invalid);
            }
        } else if header_name.is_some() {
            return Err(CatalogError::Invalid);
        }
        if !matches!(authentication, HttpAuthentication::None) && url.scheme() != "https" {
            return Err(CatalogError::Invalid);
        }
        Ok(())
    }
}

fn placeholder<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

impl Catalog {
    pub fn get_resource(&self, id: Uuid) -> Result<Resource, CatalogError> {
        resource(&self.lock(), id)
    }
    pub fn list_resources(&self) -> Result<Vec<Resource>, CatalogError> {
        let connection = self.lock();
        let mut statement = connection
            .prepare("SELECT resource_id FROM resource_configuration ORDER BY resource_id")
            .map_err(|_| CatalogError::Storage)?;
        let ids = statement
            .query_map([], |row| super::uuid_from_row(row, 0))
            .map_err(|_| CatalogError::Storage)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CatalogError::Storage)?;
        ids.into_iter()
            .map(|id| resource(&connection, id))
            .collect()
    }
    pub fn save_resource(
        &self,
        id: Option<Uuid>,
        request: &ResourceRequest,
    ) -> Result<Resource, CatalogError> {
        request.validate()?;
        let name = normalize_required(&request.name, 80)?;
        let description = normalize_optional(request.description.as_deref(), 240)?;
        let address = normalize_optional(request.address.as_deref(), 2048)?;
        let username = normalize_optional(request.username.as_deref(), 256)?;
        let now = now_unix_ms_i64()?;
        let connection = self.lock();
        let tx = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        let resource_id = id.unwrap_or_else(Uuid::new_v4);
        if id.is_some() {
            let current = resource(&tx, resource_id)?;
            if Some(current.target.version) != request.expected_version {
                return Err(CatalogError::VersionConflict);
            }
            if current.authentication.secret_state == SecretState::Available
                && current.authentication.kind != request.authentication_kind
            {
                return Err(CatalogError::Invalid);
            }
            tx.execute("UPDATE targets SET name=?1, kind=?2, environment=?3, description=?4, address=?5, username=?6, updated_at_unix_ms=?7, credential_reference_id=?8, version=version+1 WHERE id=?8", params![name, request.kind.as_storage(), request.environment.as_storage(), description, address, username, now, resource_id.to_string()]).map_err(|_| CatalogError::Storage)?;
            tx.execute("UPDATE credential_references SET name=?1, kind=?2, updated_at_unix_ms=?3, version=version+1 WHERE id=?4", params![name, request.authentication_kind.as_storage(), now, resource_id.to_string()]).map_err(|_| CatalogError::Storage)?;
        } else {
            if request.expected_version.is_some() {
                return Err(CatalogError::Invalid);
            }
            ensure_capacity(&tx, "targets", super::MAX_TARGETS)?;
            ensure_capacity(
                &tx,
                "credential_references",
                super::MAX_CREDENTIAL_REFERENCES,
            )?;
            tx.execute("INSERT INTO credential_references(id,name,kind,secret_state,created_at_unix_ms,updated_at_unix_ms,version) VALUES(?1,?2,?3,'not_configured',?4,?4,1)", params![resource_id.to_string(), name, request.authentication_kind.as_storage(), now]).map_err(|_| CatalogError::Storage)?;
            tx.execute("INSERT INTO targets(id,name,kind,environment,description,address,username,credential_reference_id,created_at_unix_ms,updated_at_unix_ms,version) VALUES(?1,?2,?3,?4,?5,?6,?7,?1,?8,?8,1)", params![resource_id.to_string(), name, request.kind.as_storage(), request.environment.as_storage(), description, address, username, now]).map_err(|_| CatalogError::Storage)?;
        }
        tx.execute(
            "UPDATE targets SET allow_insecure_protocol=?1 WHERE id=?2",
            params![
                matches!(
                    request.connection,
                    ConnectionOptions::Telnet {
                        allow_plaintext: true
                    }
                ),
                resource_id.to_string()
            ],
        )
        .map_err(|_| CatalogError::Storage)?;
        let postgres = match &request.connection {
            ConnectionOptions::Database {
                engine: crate::database_task::DatabaseEngine::Postgres,
                port,
                database,
                tls_mode,
                ..
            } => Some(super::PostgresTargetConfig {
                host: address.clone().unwrap_or_default(),
                username: username.clone().unwrap_or_default(),
                port: *port,
                database: database.clone(),
                tls_mode: match tls_mode {
                    crate::database_task::DatabaseTls::VerifyFull => {
                        super::PostgresTlsMode::VerifyFull
                    }
                    crate::database_task::DatabaseTls::Disabled => super::PostgresTlsMode::Disabled,
                },
            }),
            _ => None,
        };
        tx.execute("UPDATE targets SET postgres_host=?1, postgres_port=?2, postgres_database=?3, postgres_username=?4, postgres_tls_mode=?5 WHERE id=?6",
            params![postgres.as_ref().map(|p|p.host.as_str()),postgres.as_ref().map(|p|p.port),postgres.as_ref().map(|p|p.database.as_str()),postgres.as_ref().map(|p|p.username.as_str()),postgres.as_ref().map(|p|p.tls_mode.as_storage()),resource_id.to_string()])
            .map_err(|_|CatalogError::Storage)?;
        let labels: std::collections::BTreeSet<_> =
            request.labels.iter().map(|label| label.trim()).collect();
        tx.execute("INSERT INTO resource_configuration(resource_id,labels_json,options_json) VALUES(?1,?2,?3) ON CONFLICT(resource_id) DO UPDATE SET labels_json=excluded.labels_json,options_json=excluded.options_json", params![resource_id.to_string(), serde_json::to_string(&labels).map_err(|_| CatalogError::Invalid)?, serde_json::to_string(&request.connection).map_err(|_| CatalogError::Invalid)?]).map_err(|_| CatalogError::Storage)?;
        tx.commit().map_err(|_| CatalogError::Storage)?;
        resource(&connection, resource_id)
    }
    /// Check references without changing the aggregate before native deletion.
    pub(crate) fn prepare_resource_deletion(&self, id: Uuid) -> Result<(), CatalogError> {
        let connection = self.lock();
        resource(&connection, id)?;
        let referenced: i64 = connection.query_row("SELECT (SELECT COUNT(*) FROM action_templates WHERE target_id=?1) + (SELECT COUNT(*) FROM approvals WHERE target_id=?1) + (SELECT COUNT(*) FROM command_slots WHERE credential_id=?1)", [id.to_string()], |row| row.get(0)).map_err(|_| CatalogError::Storage)?;
        if referenced > 0 {
            return Err(CatalogError::ResourceInUse);
        }
        Ok(())
    }
    pub(crate) fn delete_resource(&self, id: Uuid) -> Result<(), CatalogError> {
        self.prepare_resource_deletion(id)?;
        let connection = self.lock();
        let tx = connection
            .unchecked_transaction()
            .map_err(|_| CatalogError::Storage)?;
        tx.execute("DELETE FROM targets WHERE id=?1", [id.to_string()])
            .map_err(|_| CatalogError::Storage)?;
        tx.execute(
            "DELETE FROM credential_references WHERE id=?1",
            [id.to_string()],
        )
        .map_err(|_| CatalogError::Storage)?;
        tx.commit().map_err(|_| CatalogError::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ResourceRequest {
        serde_json::from_value(serde_json::json!({"name":"Synthetic database","kind":"database","environment":"test","address":"db.example.invalid","username":"reader","authentication_kind":"password","labels":["reporting","reporting"],"connection":{"protocol":"database","engine":"postgres","database":"synthetic","port":5432,"tls_mode":"disabled","ca_certificate":null}})).unwrap()
    }
    #[test]
    fn incomplete_optional_settings_can_be_saved_without_fabricated_defaults() {
        let catalog = Catalog::in_memory().unwrap();
        let mut value = request();
        value.username = None;
        if let ConnectionOptions::Database { database, .. } = &mut value.connection {
            database.clear();
        }
        let saved = catalog.save_resource(None, &value).unwrap();
        assert_eq!(saved.target.username, None);
        assert_eq!(
            saved.missing_connection_fields(),
            vec!["database", "username"]
        );
        value.kind = TargetKind::HttpService;
        value.address = Some("https://api.example.invalid".into());
        value.connection = ConnectionOptions::Http {
            authentication: HttpAuthentication::ApiKey,
            header_name: Some("X-API-Key".into()),
        };
        assert!(
            catalog
                .save_resource(None, &value)
                .unwrap()
                .missing_connection_fields()
                .is_empty()
        );
        value.connection = ConnectionOptions::Http {
            authentication: HttpAuthentication::Basic,
            header_name: None,
        };
        assert_eq!(
            catalog
                .save_resource(None, &value)
                .unwrap()
                .missing_connection_fields(),
            vec!["username"]
        );
        value.connection = ConnectionOptions::Http {
            authentication: HttpAuthentication::ApiKey,
            header_name: Some("Host".into()),
        };
        assert!(matches!(
            catalog.save_resource(None, &value),
            Err(CatalogError::Invalid)
        ));
    }
    #[test]
    fn resource_is_one_identity_and_rotation_invalidates_aggregate_revision() {
        let catalog = Catalog::in_memory().unwrap();
        let mut request = request();
        let saved = catalog.save_resource(None, &request).unwrap();
        assert_eq!(saved.labels, vec!["reporting"]);
        let value = serde_json::to_value(&saved).unwrap();
        for key in [
            "postgres",
            "credential_reference_id",
            "allow_insecure_protocol",
            "secret",
        ] {
            assert!(value.get(key).is_none());
        }
        assert_eq!(catalog.list_resources().unwrap().len(), 1);
        assert_eq!(
            catalog
                .get_credential_reference(saved.target.id)
                .unwrap()
                .id,
            saved.target.id
        );
        catalog
            .set_credential_secret_state(saved.target.id, saved.authentication.secret_version, true)
            .unwrap();
        let updated = catalog.get_resource(saved.target.id).unwrap();
        assert_eq!(updated.target.version, saved.target.version + 1);
        assert!(updated.authentication.secret_version > saved.authentication.secret_version);
        request.expected_version = Some(updated.target.version);
        request.name = "Renamed synthetic".into();
        let changed = catalog
            .save_resource(Some(saved.target.id), &request)
            .unwrap();
        assert_eq!(changed.target.version, updated.target.version + 1);
        assert!(matches!(
            catalog.save_resource(Some(saved.target.id), &request),
            Err(CatalogError::VersionConflict)
        ));
    }
    #[test]
    fn invalid_protocol_metadata_and_secret_payloads_are_rejected() {
        let catalog = Catalog::in_memory().unwrap();
        let mut request = request();
        if let ConnectionOptions::Database { ca_certificate, .. } = &mut request.connection {
            *ca_certificate = Some("/tmp/synthetic.pem".into());
        }
        assert!(catalog.save_resource(None, &request).is_err());
        request.connection = ConnectionOptions::Http {
            authentication: HttpAuthentication::Bearer,
            header_name: None,
        };
        request.kind = TargetKind::HttpService;
        request.address = Some("http://example.invalid".into());
        assert!(catalog.save_resource(None, &request).is_err());
        let value = serde_json::json!({"name":"fixture","kind":"database","environment":"test","authentication_kind":"password","secret":"synthetic"});
        assert!(serde_json::from_value::<ResourceRequest>(value).is_err());
        assert!(catalog.list_resources().unwrap().is_empty());
    }
}

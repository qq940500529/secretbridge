// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::catalog::{BrowserAuthMode, SecretState};

fn source() -> Catalog {
    let catalog = Catalog::in_memory().unwrap();
    let credential = catalog
        .create_credential_reference(
            &serde_json::from_value(serde_json::json!({"name":"reference","kind":"password"}))
                .unwrap(),
        )
        .unwrap();
    catalog.create_target(&serde_json::from_value(serde_json::json!({"name":"local","kind":"http_service","environment":"development","credential_reference_id":credential.id})).unwrap()).unwrap();
    catalog
}
#[test]
fn configuration_preview_is_read_only_and_import_replay_is_idempotent() {
    let bundle = source().export_configuration().unwrap();
    let catalog = Catalog::in_memory().unwrap();
    let preview = catalog.import_configuration(&bundle, false, None).unwrap();
    assert!(catalog.list_targets().unwrap().is_empty());
    assert!(
        catalog
            .import_configuration(&bundle, true, Some("wrong"))
            .is_err()
    );
    let imported = catalog
        .import_configuration(&bundle, true, Some(&preview.digest))
        .unwrap();
    assert!(!imported.replayed);
    assert!(
        catalog
            .import_configuration(&bundle, true, Some(&preview.digest))
            .unwrap()
            .replayed
    );
    let credentials = catalog.list_credential_references().unwrap();
    let targets = catalog.list_targets().unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(targets.len(), 1);
    assert_ne!(credentials[0].id, bundle.credentials[0].id);
    assert_eq!(targets[0].credential_reference_id, Some(credentials[0].id));
    assert_eq!(credentials[0].secret_state, SecretState::NotConfigured);
}
#[test]
fn invalid_bundle_never_partially_writes_and_rejects_unknown_secret_fields() {
    let mut bundle = source().export_configuration().unwrap();
    bundle.connections[0].credential_reference_id = Some(Uuid::new_v4());
    let catalog = Catalog::in_memory().unwrap();
    assert!(catalog.import_configuration(&bundle, true, None).is_err());
    assert!(catalog.list_credential_references().unwrap().is_empty());
    let mut json = serde_json::to_value(&bundle).unwrap();
    json["credentials"][0]["secret"] = "never accepted".into();
    assert!(serde_json::from_value::<ConfigurationBundle>(json).is_err());
}

#[test]
fn sqlite_backup_round_trips_and_rejects_foreign_schema() {
    let catalog = source();
    let session_digest = [7_u8; 32];
    catalog
        .store_browser_session(&session_digest, u64::MAX / 2)
        .unwrap();
    catalog.set_browser_auth_mode(BrowserAuthMode::Pin).unwrap();
    let bytes = catalog.backup_bytes().unwrap();
    let (report, restored) = inspect_backup(&bytes).unwrap();
    assert_eq!(report.credentials, 1);
    assert_eq!(restored.list_targets().unwrap().len(), 1);
    assert_eq!(
        restored.browser_auth_mode().unwrap(),
        BrowserAuthMode::PairingLink
    );
    assert_eq!(
        restored.active_browser_session_count(u64::MAX / 4).unwrap(),
        0
    );
    assert!(inspect_backup(b"not sqlite").is_err());
    catalog
        .lock()
        .execute_batch("CREATE TABLE foreign_table(id TEXT)")
        .unwrap();
    assert!(inspect_backup(&catalog.backup_bytes().unwrap()).is_err());
}

#[test]
fn import_remaps_command_slots_and_preserves_disabled_templates() {
    let (state, _) = crate::AppState::new([]);
    crate::command::tests::configure(&state, "environment", 10);
    let mut bundle = state.catalog.export_configuration().unwrap();
    bundle.templates[0].enabled = false;
    let catalog = Catalog::in_memory().unwrap();
    let preview = catalog.import_configuration(&bundle, false, None).unwrap();
    catalog
        .import_configuration(&bundle, true, Some(&preview.digest))
        .unwrap();
    let credential = catalog.list_credential_references().unwrap().remove(0);
    let target = catalog.list_targets().unwrap().remove(0);
    let template = catalog.list_action_templates().unwrap().remove(0);
    assert!(!template.enabled);
    assert_eq!(template.target_id, target.id);
    assert_eq!(
        template.command.unwrap().slots[0].credential_id,
        credential.id
    );
    assert!(catalog.list_approvals().unwrap().is_empty());
}
#[test]
fn persistent_import_receipt_survives_catalog_reopen() {
    let path = std::env::temp_dir().join(format!(
        "secretbridge-import-replay-{}.sqlite3",
        Uuid::new_v4()
    ));
    let bundle = source().export_configuration().unwrap();
    let catalog = Catalog::open(&path).unwrap();
    let preview = catalog.import_configuration(&bundle, false, None).unwrap();
    catalog
        .import_configuration(&bundle, true, Some(&preview.digest))
        .unwrap();
    drop(catalog);
    let reopened = Catalog::open(&path).unwrap();
    assert!(
        reopened
            .import_configuration(&bundle, true, Some(&preview.digest))
            .unwrap()
            .replayed
    );
    assert_eq!(reopened.list_targets().unwrap().len(), 1);
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn backup_rejects_triggers_and_newer_schema_versions() {
    let catalog = source();
    catalog
        .lock()
        .execute_batch("PRAGMA user_version=99")
        .unwrap();
    assert!(inspect_backup(&catalog.backup_bytes().unwrap()).is_err());
    catalog.lock().execute_batch("PRAGMA user_version=15; CREATE TRIGGER foreign_trigger AFTER INSERT ON configuration_imports BEGIN SELECT 1; END;").unwrap();
    assert!(inspect_backup(&catalog.backup_bytes().unwrap()).is_err());
}

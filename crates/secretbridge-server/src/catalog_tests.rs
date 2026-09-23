// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{fs, path::PathBuf};

use uuid::Uuid;

use super::ai_conversations::{ALL_OPERATIONS_ACKNOWLEDGEMENT, ConversationApprovalPolicy};
use super::{ApprovalNotificationChannel, SetAiConversationPolicy};
use super::{
    ApprovalOperation, ApprovalResultScope, ApprovalState, BrowserAuthChannel,
    BrowserAuthEventKind, BrowserAuthMode, CancelSyntheticRun, Catalog, CatalogError,
    CatalogOpenError, CreateActionTemplate, CreateApproval, CreateCredentialReference,
    CreateSyntheticRun, CreateTarget, CredentialKind, DecideApproval, MAX_ACTIVE_APPROVALS,
    MAX_ACTIVE_RUNS, POSTGRES_POLICY_VERSION, PolicyDecision, PolicyReasonCode, PolicyRequirement,
    PostgresRunResult, PostgresTargetConfig, PostgresTlsMode, RunState, SYNTHETIC_POLICY_VERSION,
    SafeEventKind, SecretState, TargetEnvironment, TargetKind, UpdateActionTemplate,
    UpdateCredentialReference, UpdateTarget,
};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "conversation policy transitions and revocation form one security regression"
)]
fn conversation_policies_preserve_human_control_and_task_scope() {
    let catalog = Catalog::in_memory().expect("catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let conversation = catalog.create_ai_conversation("Synthetic session").unwrap();
    let request = |template_id| CreateApproval {
        authorization_mode: crate::parameters::AuthorizationMode::default(),
        parameters: crate::parameters::ParameterValues::default(),
        action_template_id: template_id,
        conversation_id: Some(conversation.id),
        reason: None,
        expires_in_seconds: 300,
    };

    let first = catalog.create_approval(&request(template.id)).unwrap();
    assert_eq!(first.state, ApprovalState::Pending);
    assert_eq!(first.conversation_id, Some(conversation.id));
    let approved = catalog
        .approve_approval(
            first.id,
            &DecideApproval {
                expected_version: first.version,
                note: None,
            },
        )
        .unwrap();
    assert!(!approved.preauthorized);

    let same_task = catalog
        .set_ai_conversation_policy(
            conversation.id,
            &SetAiConversationPolicy {
                expected_version: conversation.version,
                approval_policy: ConversationApprovalPolicy::SameTaskOnce,
                risk_acknowledgement: None,
            },
        )
        .unwrap();
    let reused = catalog.create_approval(&request(template.id)).unwrap();
    assert_eq!(reused.state, ApprovalState::Approved);
    assert!(reused.preauthorized);

    let second_template = create_action_template(&catalog, target.id);
    let changed = catalog
        .create_approval(&request(second_template.id))
        .unwrap();
    assert_eq!(changed.state, ApprovalState::Pending);
    assert!(matches!(
        catalog.set_ai_conversation_policy(
            conversation.id,
            &SetAiConversationPolicy {
                expected_version: same_task.version,
                approval_policy: ConversationApprovalPolicy::ConversationOnce,
                risk_acknowledgement: None,
            }
        ),
        Err(CatalogError::Invalid)
    ));
    let all_operations = catalog
        .set_ai_conversation_policy(
            conversation.id,
            &SetAiConversationPolicy {
                expected_version: same_task.version,
                approval_policy: ConversationApprovalPolicy::ConversationOnce,
                risk_acknowledgement: Some(ALL_OPERATIONS_ACKNOWLEDGEMENT.to_owned()),
            },
        )
        .unwrap();
    assert_eq!(
        catalog.get_approval(changed.id).unwrap().state,
        ApprovalState::Approved
    );
    let broad = catalog
        .create_approval(&request(second_template.id))
        .unwrap();
    assert!(broad.preauthorized);
    assert!(broad.expires_at_unix_ms <= all_operations.grant_expires_at_unix_ms.unwrap());

    catalog
        .set_ai_conversation_policy(
            conversation.id,
            &SetAiConversationPolicy {
                expected_version: all_operations.version,
                approval_policy: ConversationApprovalPolicy::EveryTask,
                risk_acknowledgement: None,
            },
        )
        .unwrap();
    assert_eq!(
        catalog.get_approval(broad.id).unwrap().state,
        ApprovalState::Revoked
    );
    assert_eq!(
        catalog.get_approval(changed.id).unwrap().state,
        ApprovalState::Revoked
    );
    assert_eq!(
        catalog.get_approval(approved.id).unwrap().state,
        ApprovalState::Approved
    );
    assert_eq!(
        catalog
            .create_approval(&request(second_template.id))
            .unwrap()
            .state,
        ApprovalState::Pending
    );
}

#[test]
fn notification_channel_is_persisted_in_catalog() {
    let database = TemporaryDatabase::new();
    let catalog = Catalog::open(&database.path).unwrap();
    assert_eq!(
        catalog.approval_notification_channel().unwrap(),
        ApprovalNotificationChannel::Browser
    );
    catalog
        .set_approval_notification_channel(ApprovalNotificationChannel::System)
        .unwrap();
    assert_eq!(
        catalog.approval_notification_channel().unwrap(),
        ApprovalNotificationChannel::System
    );
    drop(catalog);
    assert_eq!(
        Catalog::open(&database.path)
            .unwrap()
            .approval_notification_channel()
            .unwrap(),
        ApprovalNotificationChannel::System
    );
}

#[test]
fn totp_replay_guard_is_monotonic_and_resettable() {
    let catalog = Catalog::in_memory().expect("catalog");
    catalog.activate_totp(100).expect("activate TOTP");
    assert_eq!(catalog.browser_auth_mode().unwrap(), BrowserAuthMode::Totp);
    assert_eq!(
        catalog.consume_totp_step(100),
        Err(CatalogError::InvalidApprovalTransition)
    );
    assert_eq!(
        catalog.consume_totp_step(99),
        Err(CatalogError::InvalidApprovalTransition)
    );
    catalog.consume_totp_step(101).expect("new time step");
    catalog.reset_totp_replay_guard().expect("reset guard");
    catalog.consume_totp_step(1).expect("step after reset");
}

#[test]
fn browser_auth_events_are_fixed_and_bounded() {
    let catalog = Catalog::in_memory().expect("catalog");
    let approval_id = Uuid::new_v4();
    catalog
        .record_browser_auth_event(
            BrowserAuthEventKind::VerificationFailed,
            BrowserAuthChannel::Mcp,
            Some(approval_id),
        )
        .expect("record event");
    let events = catalog.list_browser_auth_events().expect("list events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, BrowserAuthEventKind::VerificationFailed);
    assert_eq!(events[0].channel, BrowserAuthChannel::Mcp);
    assert_eq!(events[0].approval_id, Some(approval_id));
    for _ in 0..2_049 {
        catalog
            .record_browser_auth_event(
                BrowserAuthEventKind::VerificationSucceeded,
                BrowserAuthChannel::Browser,
                None,
            )
            .expect("record bounded event");
    }
    let stored = catalog
        .lock()
        .query_row("SELECT COUNT(*) FROM browser_auth_events", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("count bounded events");
    assert_eq!(stored, 2_048);
}

#[test]
fn linked_reference_cannot_be_deleted_before_its_target() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);

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
fn updates_increment_versions_and_preserve_relationships() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let updated_credential = catalog
        .update_credential_reference(
            credential.id,
            &UpdateCredentialReference {
                name: "Updated synthetic operator".to_owned(),
                kind: CredentialKind::ApiToken,
                purpose: Some("Updated metadata only".to_owned()),
                address: Some("https://api.example.test".to_owned()),
                username: Some("automation".to_owned()),
                expected_version: 1,
            },
        )
        .expect("update credential");
    let updated_target = catalog
        .update_target(
            target.id,
            &UpdateTarget {
                name: "Updated synthetic target".to_owned(),
                kind: TargetKind::HttpService,
                environment: TargetEnvironment::Development,
                description: None,
                address: Some("server.example.test".to_owned()),
                username: Some("operator".to_owned()),
                allow_insecure_protocol: false,
                credential_reference_id: None,
                postgres: None,
                expected_version: 1,
            },
        )
        .expect("update target");

    assert_eq!(updated_credential.version, 2);
    assert_eq!(updated_credential.name, "Updated synthetic operator");
    assert_eq!(updated_target.version, 2);
    assert!(updated_target.credential_reference_id.is_none());

    let stale = catalog.update_credential_reference(
        credential.id,
        &UpdateCredentialReference {
            name: "Stale edit".to_owned(),
            kind: CredentialKind::Password,
            purpose: None,
            address: None,
            username: None,
            expected_version: 1,
        },
    );
    assert!(matches!(stale, Err(CatalogError::VersionConflict)));
}

#[test]
fn records_survive_database_reopen() {
    let database = TemporaryDatabase::new();
    let credential_id = {
        let catalog = Catalog::open(&database.path).expect("open catalog");
        create_credential(&catalog).id
    };
    let reopened = Catalog::open(&database.path).expect("reopen catalog");
    let items = reopened
        .list_credential_references()
        .expect("list credentials");

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, credential_id);
    assert_eq!(items[0].version, 1);
}

#[test]
fn control_characters_and_unknown_links_are_rejected() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let invalid = catalog.create_credential_reference(&CreateCredentialReference {
        name: "unsafe\nname".to_owned(),
        kind: CredentialKind::ApiToken,
        purpose: None,
        address: None,
        username: None,
    });
    assert!(matches!(invalid, Err(CatalogError::Invalid)));

    let target = catalog.create_target(&CreateTarget {
        name: "Synthetic target".to_owned(),
        kind: TargetKind::HttpService,
        environment: TargetEnvironment::Development,
        description: None,
        address: None,
        username: None,
        allow_insecure_protocol: false,
        credential_reference_id: Some(Uuid::new_v4()),
        postgres: None,
    });
    assert!(matches!(
        target,
        Err(CatalogError::CredentialReferenceNotFound)
    ));
}

#[test]
fn telnet_connections_require_an_explicit_plaintext_opt_in() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let disabled = catalog
        .create_target(&CreateTarget {
            name: "Legacy switch".to_owned(),
            kind: TargetKind::TelnetHost,
            environment: TargetEnvironment::Test,
            description: Some("Synthetic isolated device".to_owned()),
            address: Some("192.0.2.10:23".to_owned()),
            username: Some("synthetic-operator".to_owned()),
            allow_insecure_protocol: false,
            credential_reference_id: None,
            postgres: None,
        })
        .expect("disabled Telnet metadata");
    assert!(!disabled.allow_insecure_protocol);

    let enabled = catalog
        .update_target(
            disabled.id,
            &UpdateTarget {
                name: disabled.name,
                kind: disabled.kind,
                environment: disabled.environment,
                description: disabled.description,
                address: disabled.address,
                username: disabled.username,
                allow_insecure_protocol: true,
                credential_reference_id: None,
                postgres: None,
                expected_version: disabled.version,
            },
        )
        .expect("explicit Telnet opt-in");
    assert!(enabled.allow_insecure_protocol);

    assert!(matches!(
        catalog.create_target(&CreateTarget {
            name: "Invalid plaintext flag".to_owned(),
            kind: TargetKind::SshHost,
            environment: TargetEnvironment::Test,
            description: None,
            address: Some("ssh.example.test".to_owned()),
            username: Some("operator".to_owned()),
            allow_insecure_protocol: true,
            credential_reference_id: None,
            postgres: None,
        }),
        Err(CatalogError::Invalid)
    ));
}

#[test]
fn credential_secret_metadata_is_versioned_without_storing_a_secret() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let configured = catalog
        .set_credential_secret_state(credential.id, 1, true)
        .expect("mark configured");
    assert_eq!(configured.secret_state, SecretState::Available);
    assert!(configured.secret_updated_at_unix_ms.is_some());
    assert_eq!(configured.version, 2);

    assert!(matches!(
        catalog.set_credential_secret_state(credential.id, 1, false),
        Err(CatalogError::VersionConflict)
    ));
}

#[test]
fn credential_mutation_fails_closed_before_external_storage_changes() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let configured = catalog
        .set_credential_secret_state(credential.id, 1, true)
        .expect("mark configured");
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let approval = create_approval(&catalog, template.id);
    let approval = catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .expect("approve before mutation");

    let pending = catalog
        .begin_credential_secret_mutation(credential.id, configured.version)
        .expect("begin mutation");
    assert_eq!(pending.secret_state, SecretState::NotConfigured);
    assert_eq!(pending.version, configured.version + 1);
    assert!(matches!(
        catalog.begin_credential_secret_mutation(credential.id, configured.version),
        Err(CatalogError::VersionConflict)
    ));
    assert!(matches!(
        catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "mutation-invalidates-approval".to_owned(),
        }),
        Err(CatalogError::PolicyDenied)
    ));

    let repaired = catalog
        .finish_credential_secret_mutation(credential.id, pending.version, true)
        .expect("finish mutation");
    assert_eq!(repaired.secret_state, SecretState::Available);
    assert_eq!(repaired.version, configured.version + 1);
}

#[test]
fn terminal_history_does_not_consume_active_capacity() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    catalog
        .set_credential_secret_state(credential.id, 1, true)
        .expect("configure credential");
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);

    for index in 0..MAX_ACTIVE_APPROVALS {
        let approval = create_approval(&catalog, template.id);
        catalog
            .deny_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: Some(format!("terminal history {index}")),
                },
            )
            .expect("deny approval");
    }
    let approval = create_approval(&catalog, template.id);
    catalog
        .deny_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .expect("deny post-boundary approval");

    let catalog = Catalog::in_memory().expect("second in-memory catalog");
    let credential = create_credential(&catalog);
    catalog
        .set_credential_secret_state(credential.id, 1, true)
        .expect("configure second credential");
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);

    for index in 0..MAX_ACTIVE_RUNS {
        let approval = create_approval(&catalog, template.id);
        let approval = catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: None,
                },
            )
            .expect("approve history run");
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: format!("history-{index}"),
            })
            .expect("create history run")
            .run;
        catalog.start_run(run.id).expect("start history run");
        catalog
            .complete_synthetic_run(run.id)
            .expect("complete history run");
    }
    let approval = create_approval(&catalog, template.id);
    let approval = catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .expect("approve post-boundary run");
    assert!(
        catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "post-boundary".to_owned(),
            })
            .is_ok()
    );
}

#[test]
fn interrupted_run_recovery_propagates_storage_failure() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let approval = create_approved_workflow(&catalog);
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "recovery-write-failure".to_owned(),
        })
        .expect("create run")
        .run;
    catalog
        .lock()
        .execute_batch(&format!(
            "CREATE TRIGGER reject_recovery BEFORE UPDATE OF state ON synthetic_runs
                 WHEN OLD.id = '{}' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;",
            run.id
        ))
        .expect("install failure trigger");

    assert_eq!(
        catalog.recover_interrupted_runs(),
        Err(CatalogError::Storage)
    );
}

#[test]
fn postgres_target_configuration_is_bounded_and_database_only() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = catalog
        .create_target(&CreateTarget {
            name: "Reporting replica".to_owned(),
            kind: TargetKind::Database,
            environment: TargetEnvironment::Test,
            description: None,
            address: Some("db.test.example".to_owned()),
            username: Some("secretbridge_reader".to_owned()),
            allow_insecure_protocol: false,
            credential_reference_id: Some(credential.id),
            postgres: Some(PostgresTargetConfig {
                host: "DB.TEST.EXAMPLE".to_owned(),
                port: 5432,
                database: "reporting".to_owned(),
                username: "secretbridge_reader".to_owned(),
                tls_mode: PostgresTlsMode::VerifyFull,
            }),
        })
        .expect("PostgreSQL target");
    let postgres = target.postgres.expect("PostgreSQL configuration");
    assert_eq!(postgres.host, "db.test.example");
    assert_eq!(postgres.tls_mode, PostgresTlsMode::VerifyFull);

    assert!(matches!(
        catalog.create_target(&CreateTarget {
            name: "Invalid HTTP target".to_owned(),
            kind: TargetKind::HttpService,
            environment: TargetEnvironment::Test,
            description: None,
            address: None,
            username: None,
            allow_insecure_protocol: false,
            credential_reference_id: None,
            postgres: Some(PostgresTargetConfig {
                host: "example.test".to_owned(),
                port: 5432,
                database: "reporting".to_owned(),
                username: "reader".to_owned(),
                tls_mode: PostgresTlsMode::VerifyFull,
            }),
        }),
        Err(CatalogError::Invalid)
    ));
}

#[test]
fn postgres_connection_check_requires_configured_password_and_has_safe_results() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    catalog
        .set_credential_secret_state(credential.id, credential.version, true)
        .expect("configured secret metadata");
    let target = catalog
        .create_target(&CreateTarget {
            name: "Read-only reporting database".to_owned(),
            kind: TargetKind::Database,
            environment: TargetEnvironment::Test,
            description: None,
            address: Some("db.test.example".to_owned()),
            username: Some("secretbridge_reader".to_owned()),
            allow_insecure_protocol: false,
            credential_reference_id: Some(credential.id),
            postgres: Some(PostgresTargetConfig {
                host: "db.test.example".to_owned(),
                port: 5432,
                database: "reporting".to_owned(),
                username: "secretbridge_reader".to_owned(),
                tls_mode: PostgresTlsMode::VerifyFull,
            }),
        })
        .expect("PostgreSQL target");
    let template = catalog
        .create_action_template(&CreateActionTemplate {
            command: None,
            target_id: target.id,
            name: "PostgreSQL connection check".to_owned(),
            operation: ApprovalOperation::PostgresConnectionCheck,
            result_scope: ApprovalResultScope::StatusOnly,
            description: None,
            timeout_seconds: 10,
        })
        .expect("PostgreSQL template");
    let evaluation = catalog
        .evaluate_action_template(template.id)
        .expect("policy evaluation");
    assert_eq!(evaluation.policy_version, POSTGRES_POLICY_VERSION);
    assert_eq!(evaluation.decision, PolicyDecision::EligibleForApproval);
    assert_eq!(evaluation.execution_mode, "controlled_postgres");
    assert!(
        evaluation
            .requirements
            .contains(&PolicyRequirement::TlsVerifyFull)
    );
    assert!(
        evaluation
            .requirements
            .contains(&PolicyRequirement::ReadOnlyTransaction)
    );

    let approval = create_approval(&catalog, template.id);
    let approved = catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .expect("approve PostgreSQL check");
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approved.id,
            idempotency_key: "postgres-check-001".to_owned(),
        })
        .expect("create PostgreSQL run")
        .run;
    catalog.start_run(run.id).expect("start PostgreSQL run");
    let completed = catalog
        .complete_postgres_run(run.id, PostgresRunResult::ConnectionFailed)
        .expect("finish PostgreSQL run");
    assert_eq!(completed.state, RunState::Failed);
    assert_eq!(
        completed.result_status.as_deref(),
        Some("postgres_connection_failed")
    );
    let events = catalog.list_safe_events(Some(run.id)).expect("safe events");
    assert_eq!(events[1].message, "postgres connection check started");
    assert_eq!(events[2].kind, SafeEventKind::Failed);
    assert_eq!(events[2].message, "postgres connection check failed");
}

#[test]
fn approvals_are_versioned_and_follow_the_fixed_state_machine() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let approval = create_approval(&catalog, template.id);
    assert_eq!(approval.state, ApprovalState::Pending);
    assert_eq!(approval.action_template_id, Some(template.id));
    assert_eq!(approval.action_template_version, Some(1));

    let approved = catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: 1,
                note: Some("Synthetic scope reviewed".to_owned()),
            },
        )
        .expect("approve request");
    assert_eq!(approved.state, ApprovalState::Approved);
    assert_eq!(approved.version, 2);

    let stale = catalog.revoke_approval(
        approval.id,
        &DecideApproval {
            expected_version: 1,
            note: None,
        },
    );
    assert!(matches!(stale, Err(CatalogError::VersionConflict)));

    let revoked = catalog
        .revoke_approval(
            approval.id,
            &DecideApproval {
                expected_version: 2,
                note: Some("No longer needed".to_owned()),
            },
        )
        .expect("revoke approval");
    assert_eq!(revoked.state, ApprovalState::Revoked);
    assert_eq!(revoked.version, 3);

    let invalid = catalog.approve_approval(
        approval.id,
        &DecideApproval {
            expected_version: 3,
            note: None,
        },
    );
    assert!(matches!(
        invalid,
        Err(CatalogError::InvalidApprovalTransition)
    ));
    assert_eq!(
        catalog.delete_target(target.id),
        Err(CatalogError::ResourceInUse)
    );
}

#[test]
fn listing_expires_active_approvals() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let approval = create_approval(&catalog, template.id);
    catalog
        .lock()
        .execute(
            "UPDATE approvals SET expires_at_unix_ms = 0 WHERE id = ?1",
            [approval.id.to_string()],
        )
        .expect("force expiry");

    let items = catalog.list_approvals().expect("list approvals");
    assert_eq!(items[0].state, ApprovalState::Expired);
    assert_eq!(items[0].version, 2);
}

#[test]
fn version_one_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    {
        let connection = rusqlite::Connection::open(&database.path).expect("open v1 database");
        connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     CREATE TABLE credential_references (
                        id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
                        kind TEXT NOT NULL, purpose TEXT, secret_state TEXT NOT NULL,
                        created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     CREATE TABLE targets (
                        id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL,
                        kind TEXT NOT NULL, environment TEXT NOT NULL, description TEXT,
                        credential_reference_id TEXT REFERENCES credential_references(id) ON DELETE RESTRICT,
                        created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     CREATE INDEX targets_credential_reference_idx ON targets(credential_reference_id);
                     PRAGMA user_version = 1;",
                )
                .expect("create v1 schema");
    }

    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 1);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 1);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let approval = create_approval(&catalog, template.id);
    assert_eq!(approval.state, ApprovalState::Pending);
    let version = catalog
        .lock()
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .expect("schema version");
    assert_eq!(version, super::SCHEMA_VERSION);
}

#[test]
fn version_twelve_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    let run_id = {
        let catalog = Catalog::open(&database.path).unwrap();
        let approval = create_approved_workflow(&catalog);
        catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "v12-command-upgrade".into(),
            })
            .unwrap()
            .run
            .id
    };
    let connection = rusqlite::Connection::open(&database.path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE configuration_imports; DROP TABLE command_slots; DROP TABLE run_output;
            ALTER TABLE action_templates DROP COLUMN command_json;
            ALTER TABLE synthetic_runs DROP COLUMN exit_code;
            PRAGMA user_version=12;",
        )
        .unwrap();
    drop(connection);
    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 12);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 12);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    assert_eq!(
        catalog.get_synthetic_run(run_id).unwrap().state,
        RunState::Queued
    );
    assert!(
        catalog.list_action_templates().unwrap()[0]
            .command
            .is_none()
    );
    assert!(catalog.output(run_id, 0).unwrap().items.is_empty());
    assert_eq!(
        catalog
            .lock()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        super::SCHEMA_VERSION
    );
}

#[test]
fn version_thirteen_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    let (run_id, approval_id) = {
        let catalog = Catalog::open(&database.path).unwrap();
        let approval = create_approved_workflow(&catalog);
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "v13-preserved".into(),
            })
            .unwrap()
            .run;
        catalog
            .append_output(run.id, "stdout", "already-sanitized")
            .unwrap();
        catalog
            .lock()
            .execute(
                "UPDATE synthetic_runs SET exit_code=7 WHERE id=?1",
                [run.id.to_string()],
            )
            .unwrap();
        (run.id, approval.id)
    };
    let connection = rusqlite::Connection::open(&database.path).unwrap();
    let sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='synthetic_runs'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let sql = sql
        .replacen("synthetic_runs", "runs_old_schema", 1)
        .replace(
            "approval_id TEXT NOT NULL REFERENCES",
            "approval_id TEXT NOT NULL UNIQUE REFERENCES",
        );
    connection
        .execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")
        .unwrap();
    connection.execute_batch(&sql).unwrap();
    connection
        .execute_batch(
            "INSERT INTO runs_old_schema SELECT * FROM synthetic_runs;
            DROP TABLE synthetic_runs; ALTER TABLE runs_old_schema RENAME TO synthetic_runs;
            CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
            ALTER TABLE approvals DROP COLUMN authorization_mode;
            ALTER TABLE approvals DROP COLUMN parameters_json;
            DROP TABLE configuration_imports;
            PRAGMA user_version=13; COMMIT;",
        )
        .unwrap();
    drop(connection);
    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 13);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 13);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    let page = catalog.output(run_id, 0).unwrap();
    assert_eq!(page.items[0].text, "already-sanitized");
    assert_eq!(page.exit_code, Some(7));
    assert_eq!(catalog.list_safe_events(Some(run_id)).unwrap().len(), 1);
    assert!(
        catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id,
                idempotency_key: "v13-preserved".into()
            })
            .unwrap()
            .replayed
    );
    assert_eq!(
        catalog
            .get_approval(approval_id)
            .unwrap()
            .authorization_mode,
        crate::parameters::AuthorizationMode::EveryRun
    );
    assert_eq!(
        catalog
            .lock()
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn authorization_modes_control_consumption_and_revalidate_every_run() {
    use crate::parameters::{AuthorizationMode, ParameterValues};
    for mode in [
        AuthorizationMode::EveryRun,
        AuthorizationMode::Once,
        AuthorizationMode::TimeWindow,
    ] {
        let catalog = Catalog::in_memory().unwrap();
        let initial = create_approved_workflow(&catalog);
        let approval = catalog
            .create_approval(&CreateApproval {
                action_template_id: initial.action_template_id.unwrap(),
                conversation_id: None,
                reason: None,
                expires_in_seconds: 60,
                authorization_mode: mode,
                parameters: ParameterValues::new(),
            })
            .unwrap();
        let approval = catalog
            .approve_approval(
                approval.id,
                &DecideApproval {
                    expected_version: approval.version,
                    note: None,
                },
            )
            .unwrap();
        let request = CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "mode-first".into(),
        };
        let first = catalog.create_synthetic_run(&request).unwrap();
        assert_eq!(
            catalog.create_synthetic_run(&request).unwrap().run.id,
            first.run.id
        );
        let second = catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "mode-second".into(),
        });
        assert_eq!(second.is_ok(), mode == AuthorizationMode::TimeWindow);
        catalog
            .lock()
            .execute(
                "UPDATE targets SET version=version+1 WHERE id=?1",
                [approval.target_id.to_string()],
            )
            .unwrap();
        assert!(
            catalog
                .create_synthetic_run(&CreateSyntheticRun {
                    approval_id: approval.id,
                    idempotency_key: "mode-changed".into()
                })
                .is_err()
        );
    }
}

#[test]
fn version_two_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    let target_id = Uuid::new_v4();
    let approval_id = Uuid::new_v4();
    {
        let connection = rusqlite::Connection::open(&database.path).expect("open v2 database");
        connection
                .execute_batch(
                    "PRAGMA foreign_keys = ON;
                     CREATE TABLE credential_references (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                        purpose TEXT, secret_state TEXT NOT NULL, created_at_unix_ms INTEGER NOT NULL,
                        updated_at_unix_ms INTEGER NOT NULL, version INTEGER NOT NULL
                     );
                     CREATE TABLE targets (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                        environment TEXT NOT NULL, description TEXT, credential_reference_id TEXT,
                        created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     CREATE TABLE approvals (
                        id TEXT PRIMARY KEY, target_id TEXT NOT NULL REFERENCES targets(id),
                        operation TEXT NOT NULL, result_scope TEXT NOT NULL, reason TEXT,
                        state TEXT NOT NULL, decision_note TEXT, created_at_unix_ms INTEGER NOT NULL,
                        updated_at_unix_ms INTEGER NOT NULL, expires_at_unix_ms INTEGER NOT NULL,
                        version INTEGER NOT NULL
                     );
                     PRAGMA user_version = 2;",
                )
                .expect("create v2 schema");
        connection
                .execute(
                    "INSERT INTO targets VALUES (?1, 'Migrated target', 'database', 'test', NULL, NULL, 1, 1, 1)",
                    [target_id.to_string()],
                )
                .expect("insert v2 target");
        connection
                .execute(
                    "INSERT INTO approvals VALUES (?1, ?2, 'inspect_metadata', 'metadata_summary', NULL, 'pending', NULL, 1, 1, 9999999999999, 1)",
                    [approval_id.to_string(), target_id.to_string()],
                )
                .expect("insert v2 approval");
    }

    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 2);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 2);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    let records = catalog.list_approvals().expect("list migrated approvals");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, approval_id);
    assert_eq!(records[0].action_template_id, None);
    assert_eq!(records[0].action_template_version, None);
    assert_eq!(records[0].target_version, 1);
    assert_eq!(
        catalog
            .lock()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("schema version"),
        super::SCHEMA_VERSION
    );
}

#[test]
fn version_three_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    drop(Catalog::open(&database.path).expect("create current catalog"));
    {
        let connection = rusqlite::Connection::open(&database.path).expect("open database");
        connection
            .execute_batch(
                "DROP TABLE configuration_imports; DROP TABLE command_slots; DROP TABLE run_output;
                     DROP TABLE safe_events;
                     DROP TABLE synthetic_runs;
                     PRAGMA user_version = 3;",
            )
            .expect("restore version three layout");
    }

    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 3);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 3);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    let approval = create_approved_workflow(&catalog);
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "v3-migration-check".to_owned(),
        })
        .expect("create run after migration")
        .run;
    assert_eq!(run.state, RunState::Queued);
    assert_eq!(
        catalog
            .lock()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("schema version"),
        super::SCHEMA_VERSION
    );
}

#[test]
fn version_four_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    let (run_id, target_version) = {
        let catalog = Catalog::open(&database.path).expect("create current catalog");
        let approval = create_approved_workflow(&catalog);
        let run = catalog
            .create_synthetic_run(&CreateSyntheticRun {
                approval_id: approval.id,
                idempotency_key: "v4-policy-snapshot".to_owned(),
            })
            .expect("create run")
            .run;
        (run.id, approval.target_version)
    };
    {
        let connection = rusqlite::Connection::open(&database.path).expect("open database");
        connection
            .execute_batch(
                "DROP TABLE configuration_imports; DROP TABLE command_slots; DROP TABLE run_output;
                     ALTER TABLE synthetic_runs DROP COLUMN target_version;
                     ALTER TABLE approvals DROP COLUMN target_version;
                     PRAGMA user_version = 4;",
            )
            .expect("restore version four layout");
    }

    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 4);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 4);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    let run = catalog.get_synthetic_run(run_id).expect("migrated run");
    assert_eq!(run.target_version, target_version);
    assert_eq!(
        catalog
            .lock()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("schema version"),
        super::SCHEMA_VERSION
    );
}

#[test]
fn version_eleven_database_is_rejected_without_mutation() {
    let database = TemporaryDatabase::new();
    drop(Catalog::open(&database.path).expect("create current catalog"));
    {
        let connection = rusqlite::Connection::open(&database.path).expect("open database");
        connection
            .execute_batch(
                "DROP TABLE configuration_imports; DROP TABLE command_slots; DROP TABLE run_output;
                     CREATE TABLE security_validation_runs (id TEXT PRIMARY KEY);
                     CREATE TABLE security_validation_checks (id TEXT PRIMARY KEY);
                     CREATE TABLE pilot_readiness_snapshots (id TEXT PRIMARY KEY);
                     CREATE TABLE pilot_readiness_checks (id TEXT PRIMARY KEY);
                     CREATE TABLE platform_boundary_snapshots (id TEXT PRIMARY KEY);
                     CREATE TABLE platform_boundary_checks (id TEXT PRIMARY KEY);
                     CREATE TABLE pilot_campaigns (id TEXT PRIMARY KEY);
                     CREATE TABLE pilot_scenario_evidence (id TEXT PRIMARY KEY);
                     PRAGMA user_version = 11;",
            )
            .expect("restore obsolete governance layout");
    }

    let catalog = match Catalog::open(&database.path) {
        Ok(catalog) => catalog,
        Err(CatalogOpenError::UnsupportedSchema(version)) => {
            assert_eq!(version, 11);
            let connection = rusqlite::Connection::open(&database.path).unwrap();
            let stored: i64 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(stored, 11);
            return;
        }
        Err(error) => panic!("unexpected catalog error: {error}"),
    };
    for table in [
        "security_validation_runs",
        "security_validation_checks",
        "pilot_readiness_snapshots",
        "pilot_readiness_checks",
        "platform_boundary_snapshots",
        "platform_boundary_checks",
        "pilot_campaigns",
        "pilot_scenario_evidence",
    ] {
        let present = catalog
            .lock()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get::<_, bool>(0),
            )
            .expect("inspect migrated schema");
        assert!(!present, "obsolete table {table} must be removed");
    }
    let credential = create_credential(&catalog);
    assert_eq!(
        catalog
            .get_credential_reference(credential.id)
            .expect("core catalog remains usable")
            .id,
        credential.id
    );
    assert_eq!(
        catalog
            .lock()
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .expect("schema version"),
        super::SCHEMA_VERSION
    );
}

#[test]
fn synthetic_runs_are_idempotent_single_use_and_cancellable() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let approval = create_approved_workflow(&catalog);
    let request = CreateSyntheticRun {
        approval_id: approval.id,
        idempotency_key: "request-001".to_owned(),
    };
    let created = catalog
        .create_synthetic_run(&request)
        .expect("create synthetic run");
    assert!(!created.replayed);
    assert_eq!(created.run.state, RunState::Queued);

    let replayed = catalog
        .create_synthetic_run(&request)
        .expect("replay idempotent request");
    assert!(replayed.replayed);
    assert_eq!(replayed.run.id, created.run.id);
    let other_approval = create_approved_workflow(&catalog);
    assert!(matches!(
        catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: other_approval.id,
            idempotency_key: "request-001".to_owned(),
        }),
        Err(CatalogError::IdempotencyConflict)
    ));
    assert!(matches!(
        catalog.create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "request-002".to_owned(),
        }),
        Err(CatalogError::ApprovalConsumed)
    ));

    let running = catalog
        .start_synthetic_run(created.run.id)
        .expect("start synthetic run");
    assert_eq!(running.state, RunState::Running);
    assert_eq!(running.version, 2);
    assert!(matches!(
        catalog.cancel_synthetic_run(
            running.id,
            &CancelSyntheticRun {
                expected_version: 1,
            },
        ),
        Err(CatalogError::VersionConflict)
    ));
    let cancelled = catalog
        .cancel_synthetic_run(
            running.id,
            &CancelSyntheticRun {
                expected_version: 2,
            },
        )
        .expect("cancel synthetic run");
    assert_eq!(cancelled.state, RunState::Cancelled);
    assert_eq!(cancelled.result_status.as_deref(), Some("cancelled"));
    assert!(matches!(
        catalog.complete_synthetic_run(cancelled.id),
        Err(CatalogError::InvalidRunTransition)
    ));
    let events = catalog
        .list_safe_events(Some(cancelled.id))
        .expect("list safe events");
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, SafeEventKind::Requested);
    assert_eq!(events[2].kind, SafeEventKind::Cancelled);
}

#[test]
fn synthetic_runs_stop_when_authorization_is_no_longer_active() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");

    let queued_approval = create_approved_workflow(&catalog);
    let queued = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: queued_approval.id,
            idempotency_key: "revoked-before-start".to_owned(),
        })
        .expect("create queued run")
        .run;
    catalog
        .revoke_approval(
            queued_approval.id,
            &DecideApproval {
                expected_version: queued_approval.version,
                note: Some("Authorization withdrawn".to_owned()),
            },
        )
        .expect("revoke queued authorization");
    assert!(matches!(
        catalog.start_synthetic_run(queued.id),
        Err(CatalogError::ApprovalNotUsable)
    ));
    let stopped = catalog
        .invalidate_synthetic_run(queued.id)
        .expect("stop queued run");
    assert_eq!(stopped.state, RunState::Cancelled);
    assert_eq!(
        stopped.result_status.as_deref(),
        Some("authorization_revoked")
    );

    let running_approval = create_approved_workflow(&catalog);
    let running = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: running_approval.id,
            idempotency_key: "revoked-while-running".to_owned(),
        })
        .expect("create running run")
        .run;
    catalog
        .start_synthetic_run(running.id)
        .expect("start synthetic run");
    catalog
        .revoke_approval(
            running_approval.id,
            &DecideApproval {
                expected_version: running_approval.version,
                note: Some("Authorization withdrawn during run".to_owned()),
            },
        )
        .expect("revoke running authorization");
    assert!(matches!(
        catalog.complete_synthetic_run(running.id),
        Err(CatalogError::ApprovalNotUsable)
    ));
    let stopped = catalog
        .invalidate_synthetic_run(running.id)
        .expect("stop running run");
    assert_eq!(stopped.state, RunState::Cancelled);
    let events = catalog
        .list_safe_events(Some(stopped.id))
        .expect("list authorization events");
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].kind, SafeEventKind::AuthorizationRevoked);
    assert_eq!(events[2].message, "authorization no longer active");
}

#[test]
fn active_runs_recover_as_failed_after_restart() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let approval = create_approved_workflow(&catalog);
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "restart-check".to_owned(),
        })
        .expect("create run")
        .run;
    catalog.start_synthetic_run(run.id).expect("start run");

    assert_eq!(catalog.recover_interrupted_runs().expect("recover runs"), 1);
    let recovered = catalog.get_synthetic_run(run.id).expect("recovered run");
    assert_eq!(recovered.state, RunState::Failed);
    assert_eq!(
        recovered.result_status.as_deref(),
        Some("service_restarted")
    );
    assert_eq!(
        catalog.recover_interrupted_runs().expect("repeat recovery"),
        0
    );
}

#[test]
fn disabled_templates_reject_new_approvals_and_preserve_existing_snapshots() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let approval = create_approval(&catalog, template.id);
    let disabled = catalog
        .update_action_template(
            template.id,
            &UpdateActionTemplate {
                command: None,
                target_id: target.id,
                name: template.name.clone(),
                operation: ApprovalOperation::SyntheticHealthCheck,
                result_scope: ApprovalResultScope::StatusOnly,
                description: Some("Disabled after review".to_owned()),
                timeout_seconds: 20,
                enabled: false,
                expected_version: 1,
            },
        )
        .expect("disable template");
    assert_eq!(disabled.version, 2);
    assert!(!disabled.enabled);
    assert!(matches!(
        catalog.create_approval(&CreateApproval {
            authorization_mode: crate::parameters::AuthorizationMode::default(),
            parameters: crate::parameters::ParameterValues::default(),
            action_template_id: template.id,
            conversation_id: None,
            reason: None,
            expires_in_seconds: 300,
        }),
        Err(CatalogError::NotFound)
    ));
    let stored = catalog.list_approvals().expect("list approvals");
    assert_eq!(stored[0].id, approval.id);
    assert_eq!(stored[0].operation, ApprovalOperation::InspectMetadata);
    assert_eq!(stored[0].action_template_version, Some(1));
    assert_eq!(
        catalog.delete_action_template(template.id),
        Err(CatalogError::ResourceInUse)
    );
}

#[test]
fn policy_evaluation_is_explainable_and_fails_closed_on_version_drift() {
    let catalog = Catalog::in_memory().expect("in-memory catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let template = create_action_template(&catalog, target.id);
    let evaluation = catalog
        .evaluate_action_template(template.id)
        .expect("evaluate template");
    assert_eq!(evaluation.policy_version, SYNTHETIC_POLICY_VERSION);
    assert_eq!(evaluation.decision, PolicyDecision::EligibleForApproval);
    assert_eq!(
        evaluation.reason_codes,
        vec![PolicyReasonCode::FixedSyntheticScope]
    );
    assert_eq!(evaluation.target_version, target.version);
    assert!(
        evaluation
            .requirements
            .contains(&PolicyRequirement::TransitionRevalidation)
    );

    let pending = create_approval(&catalog, template.id);
    catalog
        .update_target(
            target.id,
            &UpdateTarget {
                name: target.name.clone(),
                kind: target.kind,
                environment: target.environment,
                description: Some("Changed after approval request".to_owned()),
                address: target.address.clone(),
                username: target.username.clone(),
                allow_insecure_protocol: target.allow_insecure_protocol,
                credential_reference_id: target.credential_reference_id,
                postgres: target.postgres.clone(),
                expected_version: target.version,
            },
        )
        .expect("update target");
    assert!(matches!(
        catalog.approve_approval(
            pending.id,
            &DecideApproval {
                expected_version: pending.version,
                note: None,
            },
        ),
        Err(CatalogError::PolicyDenied)
    ));

    let second_target = create_target(&catalog, credential.id);
    let second_template = create_action_template(&catalog, second_target.id);
    let approval = create_approval(&catalog, second_template.id);
    let approved = catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: Some("Policy reviewed".to_owned()),
            },
        )
        .expect("approve request");
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approved.id,
            idempotency_key: "policy-drift-run".to_owned(),
        })
        .expect("create run")
        .run;
    catalog
        .update_action_template(
            second_template.id,
            &UpdateActionTemplate {
                command: None,
                target_id: second_target.id,
                name: second_template.name.clone(),
                operation: second_template.operation,
                result_scope: second_template.result_scope,
                description: second_template.description.clone(),
                timeout_seconds: second_template.timeout_seconds,
                enabled: false,
                expected_version: second_template.version,
            },
        )
        .expect("disable template");
    let denied = catalog
        .evaluate_action_template(second_template.id)
        .expect("evaluate disabled template");
    assert_eq!(denied.decision, PolicyDecision::Denied);
    assert_eq!(
        denied.reason_codes,
        vec![PolicyReasonCode::TemplateDisabled]
    );
    assert!(matches!(
        catalog.start_synthetic_run(run.id),
        Err(CatalogError::PolicyDenied)
    ));
}

fn create_credential(catalog: &Catalog) -> super::CredentialReference {
    catalog
        .create_credential_reference(&CreateCredentialReference {
            name: "Synthetic database operator".to_owned(),
            kind: CredentialKind::Password,
            purpose: None,
            address: Some("db.test.example".to_owned()),
            username: Some("synthetic_reader".to_owned()),
        })
        .expect("synthetic reference")
}

fn create_target(catalog: &Catalog, credential_id: Uuid) -> super::Target {
    catalog
        .create_target(&CreateTarget {
            name: "Synthetic reporting database".to_owned(),
            kind: TargetKind::Database,
            environment: TargetEnvironment::Test,
            description: None,
            address: Some("db.test.example".to_owned()),
            username: Some("synthetic_reader".to_owned()),
            allow_insecure_protocol: false,
            credential_reference_id: Some(credential_id),
            postgres: None,
        })
        .expect("synthetic target")
}

fn create_action_template(catalog: &Catalog, target_id: Uuid) -> super::ActionTemplate {
    catalog
        .create_action_template(&CreateActionTemplate {
            command: None,
            target_id,
            name: "Inspect synthetic target metadata".to_owned(),
            operation: ApprovalOperation::InspectMetadata,
            result_scope: ApprovalResultScope::MetadataSummary,
            description: Some("No command or network operation".to_owned()),
            timeout_seconds: 15,
        })
        .expect("synthetic action template")
}

#[test]
fn one_time_drafts_remain_reviewable_without_becoming_saved_templates() {
    let catalog = Catalog::in_memory().expect("catalog");
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let request = CreateActionTemplate {
        command: None,
        target_id: target.id,
        name: "One-time metadata review".to_owned(),
        operation: ApprovalOperation::InspectMetadata,
        result_scope: ApprovalResultScope::MetadataSummary,
        description: None,
        timeout_seconds: 15,
    };
    let draft = catalog.create_one_time_draft(&request).expect("draft");
    assert!(draft.one_time);
    assert!(catalog.list_action_templates().unwrap().is_empty());
    assert!(catalog.get_action_template(draft.id).unwrap().one_time);
    let approval = create_approval(&catalog, draft.id);
    let saved = catalog
        .create_action_template(&request)
        .expect("explicit save");
    assert!(!saved.one_time);
    assert_eq!(catalog.list_action_templates().unwrap().len(), 1);
    assert_eq!(approval.action_template_id, Some(draft.id));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "creation, startup repair, export and explicit re-save share one legacy terminal fixture"
)]
fn temporary_terminal_binding_cannot_be_saved_or_exported_as_reusable() {
    let database = TemporaryDatabase::new();
    let catalog = Catalog::open(&database.path).unwrap();
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let executable = std::env::current_exe().unwrap();
    let mut command = crate::command::CommandConfig {
        terminal_id: Some(Uuid::new_v4()),
        database: None,
        http: None,
        ssh: None,
        telnet: None,
        git: None,
        parameters: Vec::new(),
        program: executable.to_string_lossy().into_owned(),
        working_directory: executable.parent().unwrap().to_string_lossy().into_owned(),
        arguments: Vec::new(),
        stdin_content: None,
        slots: Vec::new(),
    };
    let request = CreateActionTemplate {
        command: Some(command.clone()),
        target_id: target.id,
        name: "Synthetic terminal-bound command".to_owned(),
        operation: ApprovalOperation::CommandExecution,
        result_scope: ApprovalResultScope::SanitizedOutput,
        description: None,
        timeout_seconds: 15,
    };
    assert!(matches!(
        catalog.create_action_template(&request),
        Err(CatalogError::Invalid)
    ));
    assert!(catalog.create_one_time_draft(&request).unwrap().one_time);
    command.terminal_id = None;
    let saved = catalog
        .create_action_template(&CreateActionTemplate {
            command: Some(command.clone()),
            ..request
        })
        .unwrap();
    let mut old_command = command.clone();
    old_command.terminal_id = Some(Uuid::new_v4());
    catalog
        .lock()
        .execute(
            "UPDATE action_templates SET command_json = ?1 WHERE id = ?2",
            rusqlite::params![
                serde_json::to_string(&old_command).unwrap(),
                saved.id.to_string()
            ],
        )
        .unwrap();
    drop(catalog);

    let reopened = Catalog::open(&database.path).unwrap();
    let legacy = reopened.get_action_template(saved.id).unwrap();
    assert!(!legacy.enabled);
    assert!(legacy.command.as_ref().unwrap().terminal_id.is_some());
    let exported = reopened.export_configuration().unwrap();
    assert_eq!(exported.templates.len(), 1);
    assert!(!exported.templates[0].enabled);
    assert!(
        exported.templates[0]
            .command
            .as_ref()
            .unwrap()
            .terminal_id
            .is_none()
    );
    assert!(matches!(
        reopened.update_action_template(
            legacy.id,
            &UpdateActionTemplate {
                command: legacy.command.clone(),
                target_id: legacy.target_id,
                name: legacy.name.clone(),
                operation: legacy.operation,
                result_scope: legacy.result_scope,
                description: legacy.description.clone(),
                timeout_seconds: legacy.timeout_seconds,
                enabled: true,
                expected_version: legacy.version,
            }
        ),
        Err(CatalogError::Invalid)
    ));
    let repaired = reopened
        .update_action_template(
            legacy.id,
            &UpdateActionTemplate {
                command: Some(command),
                target_id: legacy.target_id,
                name: legacy.name,
                operation: legacy.operation,
                result_scope: legacy.result_scope,
                description: legacy.description,
                timeout_seconds: legacy.timeout_seconds,
                enabled: true,
                expected_version: legacy.version,
            },
        )
        .unwrap();
    assert!(repaired.enabled);
    assert!(repaired.command.unwrap().terminal_id.is_none());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "denial, expiry, success and cancellation share one one-time lifecycle fixture"
)]
fn one_time_drafts_retire_after_denial_expiry_and_completed_run() {
    let catalog = Catalog::in_memory().unwrap();
    let credential = create_credential(&catalog);
    let target = create_target(&catalog, credential.id);
    let request = CreateActionTemplate {
        command: None,
        target_id: target.id,
        name: "One-time synthetic review".to_owned(),
        operation: ApprovalOperation::InspectMetadata,
        result_scope: ApprovalResultScope::MetadataSummary,
        description: None,
        timeout_seconds: 15,
    };
    let denied = catalog.create_one_time_draft(&request).unwrap();
    let approval = create_approval(&catalog, denied.id);
    assert!(matches!(
        catalog.create_approval(&CreateApproval {
            authorization_mode: crate::parameters::AuthorizationMode::default(),
            parameters: crate::parameters::ParameterValues::default(),
            action_template_id: denied.id,
            conversation_id: None,
            reason: None,
            expires_in_seconds: 300,
        }),
        Err(CatalogError::ApprovalConsumed)
    ));
    catalog
        .deny_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    assert!(!catalog.get_action_template(denied.id).unwrap().enabled);

    let expired = catalog.create_one_time_draft(&request).unwrap();
    let approval = create_approval(&catalog, expired.id);
    catalog
        .lock()
        .execute(
            "UPDATE approvals SET expires_at_unix_ms = 0 WHERE id = ?1",
            [approval.id.to_string()],
        )
        .unwrap();
    catalog.list_approvals().unwrap();
    assert!(!catalog.get_action_template(expired.id).unwrap().enabled);

    let completed = catalog.create_one_time_draft(&request).unwrap();
    let approval = create_approval(&catalog, completed.id);
    catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "one-time-completed-run".to_owned(),
        })
        .unwrap()
        .run;
    catalog.start_run(run.id).unwrap();
    catalog.complete_synthetic_run(run.id).unwrap();
    assert!(!catalog.get_action_template(completed.id).unwrap().enabled);
    assert!(catalog.list_action_templates().unwrap().is_empty());
    assert_eq!(
        catalog
            .get_approval(approval.id)
            .unwrap()
            .action_template_id,
        Some(completed.id)
    );

    let cancelled = catalog.create_one_time_draft(&request).unwrap();
    let approval = create_approval(&catalog, cancelled.id);
    catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "one-time-cancelled-run".to_owned(),
        })
        .unwrap()
        .run;
    catalog
        .cancel_synthetic_run(
            run.id,
            &CancelSyntheticRun {
                expected_version: run.version,
            },
        )
        .unwrap();
    assert!(!catalog.get_action_template(cancelled.id).unwrap().enabled);

    let failed = catalog.create_one_time_draft(&request).unwrap();
    let approval = create_approval(&catalog, failed.id);
    catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    let run = catalog
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "one-time-timed-out-run".to_owned(),
        })
        .unwrap()
        .run;
    catalog.start_run(run.id).unwrap();
    catalog
        .transition_run(
            run.id,
            None,
            &[RunState::Running],
            RunState::Failed,
            Some("timed_out"),
            SafeEventKind::Failed,
            "command run failed",
            false,
        )
        .unwrap();
    assert!(!catalog.get_action_template(failed.id).unwrap().enabled);
}

#[test]
fn orphan_one_time_draft_is_removed_on_reopen() {
    let database = TemporaryDatabase::new();
    let draft_id = {
        let catalog = Catalog::open(&database.path).unwrap();
        let credential = create_credential(&catalog);
        let target = create_target(&catalog, credential.id);
        catalog
            .create_one_time_draft(&CreateActionTemplate {
                command: None,
                target_id: target.id,
                name: "Interrupted one-time request".to_owned(),
                operation: ApprovalOperation::InspectMetadata,
                result_scope: ApprovalResultScope::MetadataSummary,
                description: None,
                timeout_seconds: 15,
            })
            .unwrap()
            .id
    };
    let reopened = Catalog::open(&database.path).unwrap();
    assert!(matches!(
        reopened.get_action_template(draft_id),
        Err(CatalogError::NotFound)
    ));
    let target_id = reopened.list_targets().unwrap()[0].id;
    let interrupted = reopened
        .create_one_time_draft(&CreateActionTemplate {
            command: None,
            target_id,
            name: "Interrupted one-time run".to_owned(),
            operation: ApprovalOperation::InspectMetadata,
            result_scope: ApprovalResultScope::MetadataSummary,
            description: None,
            timeout_seconds: 15,
        })
        .unwrap();
    let approval = create_approval(&reopened, interrupted.id);
    reopened
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: None,
            },
        )
        .unwrap();
    let run = reopened
        .create_synthetic_run(&CreateSyntheticRun {
            approval_id: approval.id,
            idempotency_key: "one-time-interrupted-run".to_owned(),
        })
        .unwrap()
        .run;
    reopened.start_run(run.id).unwrap();
    drop(reopened);
    let recovered = Catalog::open(&database.path).unwrap();
    assert_eq!(recovered.recover_interrupted_runs().unwrap(), 1);
    assert!(
        !recovered
            .get_action_template(interrupted.id)
            .unwrap()
            .enabled
    );
}

#[test]
fn diagnostic_failures_only_keep_fixed_codes_and_time_bounds() {
    let database = TemporaryDatabase::new();
    let catalog = Catalog::open(&database.path).expect("catalog");
    catalog
        .record_diagnostic_failure("terminal_busy")
        .expect("first failure");
    catalog
        .record_diagnostic_failure("terminal_busy")
        .expect("second failure");
    catalog
        .record_diagnostic_failure("synthetic-password-never-store")
        .expect("unknown code ignored");
    let failures = catalog.list_diagnostic_failures().expect("summary");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].code, "terminal_busy");
    assert_eq!(failures[0].stage, "terminal_lease");
    assert_eq!(failures[0].recovery_actions[0], "wait_for_active_run");
    assert_eq!(failures[0].occurrences, 2);
    assert!(failures[0].first_at_unix_ms <= failures[0].last_at_unix_ms);
    drop(catalog);
    let reopened = Catalog::open(&database.path).expect("reopen catalog");
    assert_eq!(
        reopened.list_diagnostic_failures().unwrap()[0].occurrences,
        2
    );
}

#[test]
fn diagnostic_vault_encrypts_selective_records_and_rewraps_on_pin_change() {
    let database = TemporaryDatabase::new();
    let catalog = Catalog::open(&database.path).unwrap();
    let first_pin = "synthetic-first-passphrase";
    let second_pin = "synthetic-second-passphrase";
    catalog.initialize_diagnostic_vault(first_pin).unwrap();
    let marker = "synthetic-command-marker";
    catalog
        .record_encrypted_diagnostic("command", serde_json::json!({ "program": marker }))
        .unwrap();
    catalog
        .record_encrypted_diagnostic("event", serde_json::json!({ "code": "test_event" }))
        .unwrap();
    let ciphertext: Vec<u8> = catalog
        .lock()
        .query_row(
            "SELECT ciphertext FROM diagnostic_records ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !ciphertext
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    );
    assert_eq!(
        catalog
            .unlock_diagnostic_records(first_pin, false, true)
            .unwrap()
            .len(),
        1
    );
    let command = catalog
        .unlock_diagnostic_records(first_pin, true, false)
        .unwrap();
    assert_eq!(command.len(), 1);
    assert_eq!(command[0].data["program"], marker);
    let backup = catalog.backup_bytes().unwrap();
    assert!(
        !backup
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    );
    assert!(
        !backup
            .windows(first_pin.len())
            .any(|window| window == first_pin.as_bytes())
    );
    assert!(
        !catalog
            .verify_diagnostic_pin("wrong-synthetic-passphrase")
            .unwrap()
    );
    catalog
        .rotate_diagnostic_vault_pin(first_pin, second_pin)
        .unwrap();
    assert!(!catalog.verify_diagnostic_pin(first_pin).unwrap());
    assert_eq!(
        catalog
            .unlock_diagnostic_records(second_pin, true, true)
            .unwrap()
            .len(),
        2
    );
    drop(catalog);
    let reopened = Catalog::open(&database.path).unwrap();
    assert_eq!(
        reopened
            .unlock_diagnostic_records(second_pin, true, true)
            .unwrap()
            .len(),
        2
    );
    reopened
        .lock()
        .execute(
            "UPDATE diagnostic_records SET ciphertext = X'00' WHERE id = 1",
            [],
        )
        .unwrap();
    assert!(
        reopened
            .unlock_diagnostic_records(second_pin, true, true)
            .is_err()
    );
}

fn create_approval(catalog: &Catalog, action_template_id: Uuid) -> super::Approval {
    catalog
        .create_approval(&CreateApproval {
            authorization_mode: crate::parameters::AuthorizationMode::default(),
            parameters: crate::parameters::ParameterValues::default(),
            action_template_id,
            conversation_id: None,
            reason: Some("Synthetic workflow validation".to_owned()),
            expires_in_seconds: 300,
        })
        .expect("synthetic approval")
}

fn create_approved_workflow(catalog: &Catalog) -> super::Approval {
    let credential = create_credential(catalog);
    let target = create_target(catalog, credential.id);
    let template = create_action_template(catalog, target.id);
    let approval = create_approval(catalog, template.id);
    catalog
        .approve_approval(
            approval.id,
            &DecideApproval {
                expected_version: approval.version,
                note: Some("Approved for synthetic run test".to_owned()),
            },
        )
        .expect("approve synthetic workflow")
}

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "secretbridge-catalog-test-{}.sqlite3",
                Uuid::new_v4()
            )),
        }
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

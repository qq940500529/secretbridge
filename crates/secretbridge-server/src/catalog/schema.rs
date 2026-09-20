// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Creation of the current catalog schema.
//!
//! Unpublished legacy schemas are rejected before this module is called. The staged builders
//! below assemble the current schema in reviewable groups; they are not a compatibility chain.

use std::fmt::Write as _;

use rusqlite::{Connection, OptionalExtension};

use super::{CatalogOpenError, SCHEMA_VERSION};

pub(super) fn prepare(connection: &Connection) -> Result<(), CatalogOpenError> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
    if version > SCHEMA_VERSION {
        return Err(CatalogOpenError::UnsupportedSchema(version));
    }
    initialize_schema(connection, version)
}

#[allow(
    clippy::too_many_lines,
    reason = "the declarative SQLite schema and staged pre-release bootstrap remain auditable together"
)]
fn initialize_schema(connection: &Connection, version: i64) -> Result<(), CatalogOpenError> {
    if version == 0 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE credential_references (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                kind TEXT NOT NULL CHECK (kind IN ('password', 'api_token', 'ssh_key')),
                purpose TEXT CHECK (purpose IS NULL OR length(purpose) <= 240),
                address TEXT CHECK (address IS NULL OR length(address) <= 2048),
                username TEXT CHECK (username IS NULL OR length(username) <= 256),
                secret_state TEXT NOT NULL CHECK (secret_state = 'not_configured'),
                secret_configured INTEGER NOT NULL DEFAULT 0 CHECK (secret_configured IN (0, 1)),
                secret_updated_at_unix_ms INTEGER,
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE TABLE targets (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                kind TEXT NOT NULL CHECK (kind IN ('database', 'http_service', 'ssh_host', 'telnet_host')),
                environment TEXT NOT NULL CHECK (environment IN ('development', 'test', 'production')),
                description TEXT CHECK (description IS NULL OR length(description) <= 240),
                address TEXT CHECK (address IS NULL OR length(address) <= 2048),
                username TEXT CHECK (username IS NULL OR length(username) <= 256),
                allow_insecure_protocol INTEGER NOT NULL DEFAULT 0 CHECK (allow_insecure_protocol IN (0, 1)),
                credential_reference_id TEXT REFERENCES credential_references(id) ON DELETE RESTRICT,
                postgres_host TEXT,
                postgres_port INTEGER CHECK (postgres_port IS NULL OR postgres_port BETWEEN 1 AND 65535),
                postgres_database TEXT,
                postgres_username TEXT,
                postgres_tls_mode TEXT CHECK (postgres_tls_mode IS NULL OR postgres_tls_mode = 'verify_full'),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX targets_credential_reference_idx
                ON targets(credential_reference_id);
             CREATE TABLE browser_auth_settings (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                mode TEXT NOT NULL CHECK (mode IN ('pairing_link', 'pin')),
                updated_at_unix_ms INTEGER NOT NULL
             );
             INSERT INTO browser_auth_settings(singleton, mode, updated_at_unix_ms)
                VALUES(1, 'pairing_link', 0);
             CREATE TABLE action_templates (
                id TEXT PRIMARY KEY NOT NULL,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check', 'command_execution')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                description TEXT CHECK (description IS NULL OR length(description) <= 240),
                timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX action_templates_target_idx ON action_templates(target_id);
             CREATE TABLE approvals (
                id TEXT PRIMARY KEY NOT NULL,
                action_template_id TEXT REFERENCES action_templates(id) ON DELETE RESTRICT,
                action_template_version INTEGER,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                target_version INTEGER NOT NULL CHECK (target_version >= 1),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check', 'command_execution')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                reason TEXT CHECK (reason IS NULL OR length(reason) <= 240),
                state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
                decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= 240),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX approvals_target_idx ON approvals(target_id);
             CREATE INDEX approvals_state_idx ON approvals(state);
             CREATE TABLE synthetic_runs (
                id TEXT PRIMARY KEY NOT NULL,
                approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
                idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
                action_template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE RESTRICT,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                target_version INTEGER NOT NULL CHECK (target_version >= 1),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check', 'command_execution')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                result_status TEXT CHECK (result_status IS NULL OR result_status IN ('command_ok', 'command_failed', 'command_cleanup_failed', 'synthetic_ok', 'postgres_connection_ok', 'postgres_connection_failed', 'postgres_configuration_invalid', 'credential_unavailable', 'timed_out', 'cancelled', 'service_restarted', 'authorization_revoked')),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                started_at_unix_ms INTEGER,
                finished_at_unix_ms INTEGER,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
             CREATE TABLE safe_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
                sequence INTEGER NOT NULL CHECK (sequence >= 1),
                kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'failed', 'cancelled', 'interrupted', 'authorization_revoked')),
                state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                message TEXT NOT NULL CHECK (message IN ('command run started', 'command run succeeded', 'command run failed', 'request accepted', 'synthetic run started', 'synthetic run completed', 'postgres connection check started', 'postgres connection check succeeded', 'postgres connection check failed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
                created_at_unix_ms INTEGER NOT NULL,
                UNIQUE(run_id, sequence)
             );
             CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
             CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
             PRAGMA user_version = 12;
             COMMIT;",
        )?;
    }
    if version == 1 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE action_templates (
                id TEXT PRIMARY KEY NOT NULL,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                description TEXT CHECK (description IS NULL OR length(description) <= 240),
                timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX action_templates_target_idx ON action_templates(target_id);
             CREATE TABLE approvals (
                id TEXT PRIMARY KEY NOT NULL,
                action_template_id TEXT REFERENCES action_templates(id) ON DELETE RESTRICT,
                action_template_version INTEGER,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                target_version INTEGER NOT NULL CHECK (target_version >= 1),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                reason TEXT CHECK (reason IS NULL OR length(reason) <= 240),
                state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
                decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= 240),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX approvals_target_idx ON approvals(target_id);
             CREATE INDEX approvals_state_idx ON approvals(state);
             CREATE TABLE synthetic_runs (
                id TEXT PRIMARY KEY NOT NULL,
                approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
                idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
                action_template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE RESTRICT,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                target_version INTEGER NOT NULL CHECK (target_version >= 1),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                result_status TEXT CHECK (result_status IS NULL OR result_status IN ('synthetic_ok', 'cancelled', 'service_restarted', 'authorization_revoked')),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                started_at_unix_ms INTEGER,
                finished_at_unix_ms INTEGER,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
             CREATE TABLE safe_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
                sequence INTEGER NOT NULL CHECK (sequence >= 1),
                kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'cancelled', 'interrupted', 'authorization_revoked')),
                state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
                message TEXT NOT NULL CHECK (message IN ('command run started', 'command run succeeded', 'command run failed', 'request accepted', 'synthetic run started', 'synthetic run completed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
                created_at_unix_ms INTEGER NOT NULL,
                UNIQUE(run_id, sequence)
             );
             CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
             CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
             PRAGMA user_version = 5;
             COMMIT;",
        )?;
    }
    if version == 2 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE action_templates (
                id TEXT PRIMARY KEY NOT NULL,
                target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
                name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
                result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
                description TEXT CHECK (description IS NULL OR length(description) <= 240),
                timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             CREATE INDEX action_templates_target_idx ON action_templates(target_id);
             ALTER TABLE approvals ADD COLUMN action_template_id TEXT REFERENCES action_templates(id) ON DELETE RESTRICT;
             ALTER TABLE approvals ADD COLUMN action_template_version INTEGER;
             PRAGMA user_version = 3;
             COMMIT;",
        )?;
    }
    if version == 2 || version == 3 {
        create_run_schema(connection)?;
    }
    if (2..=4).contains(&version) {
        migrate_policy_snapshot_schema(connection)?;
    }
    if (1..=5).contains(&version) {
        migrate_native_secret_and_postgres_schema(connection)?;
    }
    if (1..=6).contains(&version) {
        migrate_controlled_postgres_schema(connection)?;
    }
    if (1..=11).contains(&version) {
        migrate_remove_obsolete_governance(connection)?;
    }
    if version < 13 {
        // Rebuild constrained tables with the expanded operation/result enums.
        migrate_controlled_postgres_schema(connection)?;
        connection.execute_batch(
            "BEGIN IMMEDIATE;
            ALTER TABLE action_templates ADD COLUMN command_json TEXT;
            ALTER TABLE synthetic_runs ADD COLUMN exit_code INTEGER;
            CREATE TABLE command_slots (
                template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE CASCADE,
                credential_id TEXT NOT NULL REFERENCES credential_references(id) ON DELETE RESTRICT,
                PRIMARY KEY(template_id, credential_id));
            CREATE TABLE run_output (
                run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
                sequence INTEGER NOT NULL, stream TEXT NOT NULL, text TEXT NOT NULL,
                PRIMARY KEY(run_id, sequence));
            PRAGMA user_version = 13; COMMIT;",
        )?;
    }
    if version < 14 {
        migrate_parameterized_tasks(connection)?;
    }
    if version < 15 {
        connection.execute_batch(
            "BEGIN IMMEDIATE;
            CREATE TABLE configuration_imports (
                digest TEXT PRIMARY KEY NOT NULL,
                report_json TEXT NOT NULL
            ); PRAGMA user_version = 15; COMMIT;",
        )?;
    }
    if version < 16 {
        connection.pragma_update(None, "user_version", 16_i64)?;
    }
    if version < 17 {
        let mut migration = String::from("BEGIN IMMEDIATE;");
        for (table, column, definition) in [
            (
                "credential_references",
                "address",
                "TEXT CHECK (address IS NULL OR length(address) <= 2048)",
            ),
            (
                "credential_references",
                "username",
                "TEXT CHECK (username IS NULL OR length(username) <= 256)",
            ),
        ] {
            if !column_exists(connection, table, column)? {
                write!(
                    &mut migration,
                    "ALTER TABLE {table} ADD COLUMN {column} {definition};"
                )
                .expect("writing a schema migration to String cannot fail");
            }
        }
        for (column, definition) in [
            (
                "address",
                "TEXT CHECK (address IS NULL OR length(address) <= 2048)",
            ),
            (
                "username",
                "TEXT CHECK (username IS NULL OR length(username) <= 256)",
            ),
            (
                "allow_insecure_protocol",
                "INTEGER NOT NULL DEFAULT 0 CHECK (allow_insecure_protocol IN (0, 1))",
            ),
        ] {
            if !column_exists(connection, "targets", column)? {
                write!(
                    &mut migration,
                    "ALTER TABLE targets ADD COLUMN {column} {definition};"
                )
                .expect("writing a schema migration to String cannot fail");
            }
        }
        migration.push_str(
            "CREATE TABLE IF NOT EXISTS browser_auth_settings (
                singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
                mode TEXT NOT NULL CHECK (mode IN ('pairing_link', 'pin')),
                updated_at_unix_ms INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO browser_auth_settings(singleton, mode, updated_at_unix_ms)
                VALUES(1, 'pairing_link', 0);",
        );
        migration.push_str(
            "CREATE TABLE targets_v17 (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
                kind TEXT NOT NULL CHECK (kind IN ('database', 'http_service', 'ssh_host', 'telnet_host')),
                environment TEXT NOT NULL CHECK (environment IN ('development', 'test', 'production')),
                description TEXT CHECK (description IS NULL OR length(description) <= 240),
                address TEXT CHECK (address IS NULL OR length(address) <= 2048),
                username TEXT CHECK (username IS NULL OR length(username) <= 256),
                allow_insecure_protocol INTEGER NOT NULL DEFAULT 0 CHECK (allow_insecure_protocol IN (0, 1)),
                credential_reference_id TEXT REFERENCES credential_references(id) ON DELETE RESTRICT,
                postgres_host TEXT,
                postgres_port INTEGER CHECK (postgres_port IS NULL OR postgres_port BETWEEN 1 AND 65535),
                postgres_database TEXT,
                postgres_username TEXT,
                postgres_tls_mode TEXT CHECK (postgres_tls_mode IS NULL OR postgres_tls_mode = 'verify_full'),
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                version INTEGER NOT NULL CHECK (version >= 1)
             );
             INSERT INTO targets_v17
                (id, name, kind, environment, description, address, username,
                 allow_insecure_protocol, credential_reference_id, postgres_host,
                 postgres_port, postgres_database, postgres_username, postgres_tls_mode,
                 created_at_unix_ms, updated_at_unix_ms, version)
             SELECT id, name, kind, environment, description, address, username,
                    allow_insecure_protocol, credential_reference_id, postgres_host,
                    postgres_port, postgres_database, postgres_username, postgres_tls_mode,
                    created_at_unix_ms, updated_at_unix_ms, version
               FROM targets;
             DROP TABLE targets;
             ALTER TABLE targets_v17 RENAME TO targets;
             CREATE INDEX targets_credential_reference_idx ON targets(credential_reference_id);
             PRAGMA user_version = 17; COMMIT;",
        );
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute_batch(&migration)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        if connection
            .query_row("PRAGMA foreign_key_check", [], |row| row.get::<_, String>(0))
            .optional()?
            .is_some()
        {
            return Err(CatalogOpenError::Database(rusqlite::Error::InvalidQuery));
        }
    }
    Ok(())
}

fn create_run_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE synthetic_runs (
            id TEXT PRIMARY KEY NOT NULL,
            approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
            idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
            action_template_id TEXT NOT NULL REFERENCES action_templates(id) ON DELETE RESTRICT,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            result_status TEXT CHECK (result_status IS NULL OR result_status IN ('synthetic_ok', 'cancelled', 'service_restarted', 'authorization_revoked')),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            started_at_unix_ms INTEGER,
            finished_at_unix_ms INTEGER,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
         CREATE TABLE safe_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES synthetic_runs(id) ON DELETE RESTRICT,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'cancelled', 'interrupted', 'authorization_revoked')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            message TEXT NOT NULL CHECK (message IN ('command run started', 'command run succeeded', 'command run failed', 'request accepted', 'synthetic run started', 'synthetic run completed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
            created_at_unix_ms INTEGER NOT NULL,
            UNIQUE(run_id, sequence)
         );
         CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
         CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
         PRAGMA user_version = 4;
         COMMIT;",
    )
}

fn migrate_policy_snapshot_schema(connection: &Connection) -> rusqlite::Result<()> {
    let mut migration = String::from("BEGIN IMMEDIATE;");
    if !column_exists(connection, "approvals", "target_version")? {
        migration.push_str("ALTER TABLE approvals ADD COLUMN target_version INTEGER;");
    }
    if !column_exists(connection, "synthetic_runs", "target_version")? {
        migration.push_str("ALTER TABLE synthetic_runs ADD COLUMN target_version INTEGER;");
    }
    migration.push_str(
        "UPDATE approvals
            SET target_version = (SELECT version FROM targets WHERE targets.id = approvals.target_id)
          WHERE target_version IS NULL;
         UPDATE synthetic_runs
            SET target_version = (SELECT target_version FROM approvals WHERE approvals.id = synthetic_runs.approval_id)
          WHERE target_version IS NULL;
         PRAGMA user_version = 5;
         COMMIT;",
    );
    connection.execute_batch(&migration)
}

fn migrate_native_secret_and_postgres_schema(connection: &Connection) -> rusqlite::Result<()> {
    let mut migration = String::from("BEGIN IMMEDIATE;");
    for (table, column, definition) in [
        (
            "credential_references",
            "secret_configured",
            "INTEGER NOT NULL DEFAULT 0 CHECK (secret_configured IN (0, 1))",
        ),
        (
            "credential_references",
            "secret_updated_at_unix_ms",
            "INTEGER",
        ),
        ("targets", "postgres_host", "TEXT"),
        (
            "targets",
            "postgres_port",
            "INTEGER CHECK (postgres_port IS NULL OR postgres_port BETWEEN 1 AND 65535)",
        ),
        ("targets", "postgres_database", "TEXT"),
        ("targets", "postgres_username", "TEXT"),
        (
            "targets",
            "postgres_tls_mode",
            "TEXT CHECK (postgres_tls_mode IS NULL OR postgres_tls_mode = 'verify_full')",
        ),
    ] {
        if !column_exists(connection, table, column)? {
            write!(
                &mut migration,
                "ALTER TABLE {table} ADD COLUMN {column} {definition};"
            )
            .expect("writing a schema migration to String cannot fail");
        }
    }
    migration.push_str("PRAGMA user_version = 6; COMMIT;");
    connection.execute_batch(&migration)
}

#[allow(
    clippy::too_many_lines,
    reason = "the v7 table rebuild is kept in one auditable transaction"
)]
fn migrate_controlled_postgres_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "PRAGMA foreign_keys = OFF;
         BEGIN IMMEDIATE;
         CREATE TABLE action_templates_v7 (
            id TEXT PRIMARY KEY NOT NULL,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            name TEXT NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 80),
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check', 'command_execution')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
            description TEXT CHECK (description IS NULL OR length(description) <= 240),
            timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 300),
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         INSERT INTO action_templates_v7
            (id, target_id, name, operation, result_scope, description,
             timeout_seconds, enabled, created_at_unix_ms, updated_at_unix_ms, version)
         SELECT id, target_id, name, operation, result_scope, description,
                timeout_seconds, enabled, created_at_unix_ms, updated_at_unix_ms, version
           FROM action_templates;
         CREATE TABLE approvals_v7 (
            id TEXT PRIMARY KEY NOT NULL,
            action_template_id TEXT REFERENCES action_templates_v7(id) ON DELETE RESTRICT,
            action_template_version INTEGER,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            target_version INTEGER NOT NULL CHECK (target_version >= 1),
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check', 'command_execution')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
            reason TEXT CHECK (reason IS NULL OR length(reason) <= 240),
            state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'revoked', 'expired')),
            decision_note TEXT CHECK (decision_note IS NULL OR length(decision_note) <= 240),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            expires_at_unix_ms INTEGER NOT NULL,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         INSERT INTO approvals_v7
            (id, action_template_id, action_template_version, target_id, target_version,
             operation, result_scope, reason, state, decision_note,
             created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version)
         SELECT id, action_template_id, action_template_version, target_id, target_version,
                operation, result_scope, reason, state, decision_note,
                created_at_unix_ms, updated_at_unix_ms, expires_at_unix_ms, version
           FROM approvals;
         CREATE TABLE synthetic_runs_v7 (
            id TEXT PRIMARY KEY NOT NULL,
            approval_id TEXT NOT NULL UNIQUE REFERENCES approvals_v7(id) ON DELETE RESTRICT,
            idempotency_key_hash TEXT NOT NULL UNIQUE CHECK (length(idempotency_key_hash) = 64),
            action_template_id TEXT NOT NULL REFERENCES action_templates_v7(id) ON DELETE RESTRICT,
            target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
            target_version INTEGER NOT NULL CHECK (target_version >= 1),
            operation TEXT NOT NULL CHECK (operation IN ('inspect_metadata', 'synthetic_health_check', 'postgres_connection_check', 'command_execution')),
            result_scope TEXT NOT NULL CHECK (result_scope IN ('status_only', 'metadata_summary', 'sanitized_output')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            result_status TEXT CHECK (result_status IS NULL OR result_status IN ('command_ok', 'command_failed', 'command_cleanup_failed', 'synthetic_ok', 'postgres_connection_ok', 'postgres_connection_failed', 'postgres_configuration_invalid', 'credential_unavailable', 'timed_out', 'cancelled', 'service_restarted', 'authorization_revoked')),
            created_at_unix_ms INTEGER NOT NULL,
            updated_at_unix_ms INTEGER NOT NULL,
            started_at_unix_ms INTEGER,
            finished_at_unix_ms INTEGER,
            version INTEGER NOT NULL CHECK (version >= 1)
         );
         INSERT INTO synthetic_runs_v7
            (id, approval_id, idempotency_key_hash, action_template_id, target_id,
             target_version, operation, result_scope, state, result_status,
             created_at_unix_ms, updated_at_unix_ms, started_at_unix_ms,
             finished_at_unix_ms, version)
         SELECT id, approval_id, idempotency_key_hash, action_template_id, target_id,
                target_version, operation, result_scope, state, result_status,
                created_at_unix_ms, updated_at_unix_ms, started_at_unix_ms,
                finished_at_unix_ms, version
           FROM synthetic_runs;
         CREATE TABLE safe_events_v7 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES synthetic_runs_v7(id) ON DELETE RESTRICT,
            sequence INTEGER NOT NULL CHECK (sequence >= 1),
            kind TEXT NOT NULL CHECK (kind IN ('requested', 'started', 'succeeded', 'failed', 'cancelled', 'interrupted', 'authorization_revoked')),
            state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'cancelled', 'failed')),
            message TEXT NOT NULL CHECK (message IN ('command run started', 'command run succeeded', 'command run failed', 'request accepted', 'synthetic run started', 'synthetic run completed', 'postgres connection check started', 'postgres connection check succeeded', 'postgres connection check failed', 'run cancelled', 'service restarted before completion', 'authorization no longer active')),
            created_at_unix_ms INTEGER NOT NULL,
            UNIQUE(run_id, sequence)
         );
         INSERT INTO safe_events_v7
            (id, run_id, sequence, kind, state, message, created_at_unix_ms)
         SELECT id, run_id, sequence, kind, state, message, created_at_unix_ms
           FROM safe_events;
         DROP TABLE safe_events;
         DROP TABLE synthetic_runs;
         DROP TABLE approvals;
         DROP TABLE action_templates;
         ALTER TABLE action_templates_v7 RENAME TO action_templates;
         ALTER TABLE approvals_v7 RENAME TO approvals;
         ALTER TABLE synthetic_runs_v7 RENAME TO synthetic_runs;
         ALTER TABLE safe_events_v7 RENAME TO safe_events;
         CREATE INDEX action_templates_target_idx ON action_templates(target_id);
         CREATE INDEX approvals_target_idx ON approvals(target_id);
         CREATE INDEX approvals_state_idx ON approvals(state);
         CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
         CREATE INDEX safe_events_run_idx ON safe_events(run_id, sequence);
         CREATE INDEX safe_events_created_idx ON safe_events(created_at_unix_ms, id);
         PRAGMA user_version = 7;
         COMMIT;
         PRAGMA foreign_keys = ON;",
    )?;
    if connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()?
        .is_some()
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn migrate_remove_obsolete_governance(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         DROP TABLE IF EXISTS pilot_scenario_evidence;
         DROP TABLE IF EXISTS pilot_campaigns;
         DROP TABLE IF EXISTS pilot_readiness_checks;
         DROP TABLE IF EXISTS pilot_readiness_snapshots;
         DROP TABLE IF EXISTS platform_boundary_checks;
         DROP TABLE IF EXISTS platform_boundary_snapshots;
         DROP TABLE IF EXISTS security_validation_checks;
         DROP TABLE IF EXISTS security_validation_runs;
         PRAGMA user_version = 12;
         COMMIT;",
    )
}

fn column_exists(
    connection: &Connection,
    table: &'static str,
    column: &str,
) -> rusqlite::Result<bool> {
    let query =
        format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)");
    connection.query_row(&query, [column], |row| row.get(0))
}

fn migrate_parameterized_tasks(connection: &Connection) -> rusqlite::Result<()> {
    // Keep the original name in all foreign-key declarations. Rebuild only the
    // run table, preserving output, events, exit codes and idempotency keys.
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='synthetic_runs'",
        [],
        |row| row.get(0),
    )?;
    let sql = sql
        .replacen("synthetic_runs", "synthetic_runs_next", 1)
        .replace(
            "approval_id TEXT NOT NULL UNIQUE",
            "approval_id TEXT NOT NULL",
        );
    connection.pragma_update(None, "foreign_keys", false)?;
    let result = (|| {
        connection.execute_batch("BEGIN IMMEDIATE;")?;
        connection.execute_batch(&sql)?;
        connection.execute_batch("INSERT INTO synthetic_runs_next SELECT * FROM synthetic_runs;
            DROP TABLE synthetic_runs;
            ALTER TABLE synthetic_runs_next RENAME TO synthetic_runs;
            CREATE INDEX synthetic_runs_state_idx ON synthetic_runs(state);
            CREATE INDEX synthetic_runs_approval_idx ON synthetic_runs(approval_id);
            ALTER TABLE approvals ADD COLUMN authorization_mode TEXT NOT NULL DEFAULT '\"every_run\"';
            ALTER TABLE approvals ADD COLUMN parameters_json TEXT NOT NULL DEFAULT '{}';
            PRAGMA user_version=14; COMMIT;")
    })();
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK;");
    }
    connection.pragma_update(None, "foreign_keys", true)?;
    result
}

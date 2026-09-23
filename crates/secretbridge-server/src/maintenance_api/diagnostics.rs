// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;

use crate::{
    catalog::{ActionTemplate, RunState, SyntheticRun},
    terminal::TerminalSummary,
};

pub(super) fn run_recovery_actions(code: &str) -> &'static [&'static str] {
    match code {
        "credential_unavailable" => &[
            "check_os_credential_store",
            "ask_human_to_reenter_credential",
        ],
        "authorization_revoked" => &[
            "review_current_approval_state",
            "request_new_approval_if_needed",
        ],
        "timed_out" => &[
            "inspect_sanitized_output",
            "review_timeout_and_target",
            "request_new_approval_if_needed",
        ],
        "service_restarted" => &["inspect_run_state", "request_new_approval_if_needed"],
        "command_cleanup_failed" => &[
            "check_private_temporary_directory",
            "do_not_retry_until_clean",
        ],
        "postgres_configuration_invalid" => &["ask_human_to_correct_connection_metadata"],
        "postgres_connection_failed" | "database_connection_failed" | "ssh_connection_failed" => {
            &["check_target_network_and_trust", "inspect_sanitized_output"]
        }
        "database_query_failed"
        | "http_request_failed"
        | "sftp_transfer_failed"
        | "git_failed"
        | "command_failed" => &["inspect_sanitized_output", "verify_operation_parameters"],
        _ => &[
            "inspect_sanitized_output",
            "contact_maintainer_with_safe_diagnostics",
        ],
    }
}

#[derive(Serialize)]
pub(super) struct StateConsistency {
    pub active_runs_missing_start: usize,
    pub finished_runs_missing_finish: usize,
    pub active_runs_missing_template: usize,
    pub active_terminal_runs_missing_terminal: usize,
}

impl StateConsistency {
    pub fn total_issues(&self) -> usize {
        self.active_runs_missing_start
            + self.finished_runs_missing_finish
            + self.active_runs_missing_template
            + self.active_terminal_runs_missing_terminal
    }
}

pub(super) fn check_state_consistency(
    runs: &[SyntheticRun],
    templates: &[ActionTemplate],
    terminals: &[TerminalSummary],
) -> StateConsistency {
    let mut result = StateConsistency {
        active_runs_missing_start: 0,
        finished_runs_missing_finish: 0,
        active_runs_missing_template: 0,
        active_terminal_runs_missing_terminal: 0,
    };
    for run in runs {
        let active = matches!(run.state, RunState::Queued | RunState::Running);
        if run.state == RunState::Running && run.started_at_unix_ms.is_none() {
            result.active_runs_missing_start += 1;
        }
        if !active && run.finished_at_unix_ms.is_none() {
            result.finished_runs_missing_finish += 1;
        }
        if !active {
            continue;
        }
        let Some(template) = templates
            .iter()
            .find(|item| item.id == run.action_template_id)
        else {
            result.active_runs_missing_template += 1;
            continue;
        };
        if template
            .command
            .as_ref()
            .and_then(|command| command.terminal_id)
            .is_some_and(|id| !terminals.iter().any(|terminal| terminal.id == id))
        {
            result.active_terminal_runs_missing_terminal += 1;
        }
    }
    result
}

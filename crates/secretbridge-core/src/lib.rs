// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]

use serde::Serialize;

pub const API_VERSION: &str = "v1";
pub const PRODUCT_NAME: &str = "SecretBridge";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    SyntheticOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBoundary {
    UnverifiedSameUser,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StatusResponse {
    pub product: &'static str,
    pub api_version: &'static str,
    pub release_stage: &'static str,
    pub mode: RuntimeMode,
    pub identity_boundary: IdentityBoundary,
    pub paired: bool,
    pub real_credentials_enabled: bool,
}

impl StatusResponse {
    #[must_use]
    pub const fn synthetic_only(paired: bool) -> Self {
        Self {
            product: PRODUCT_NAME,
            api_version: API_VERSION,
            release_stage: "m0",
            mode: RuntimeMode::SyntheticOnly,
            identity_boundary: IdentityBoundary::UnverifiedSameUser,
            paired,
            real_credentials_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityBoundary, RuntimeMode, StatusResponse};

    #[test]
    fn m0_status_never_claims_real_credentials() {
        let status = StatusResponse::synthetic_only(true);
        assert_eq!(status.mode, RuntimeMode::SyntheticOnly);
        assert_eq!(
            status.identity_boundary,
            IdentityBoundary::UnverifiedSameUser
        );
        assert!(!status.real_credentials_enabled);
    }
}

// SPDX-FileCopyrightText: 2026 数链创元（天津）信息技术有限责任公司
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::catalog::CatalogError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

pub type ParameterValues = BTreeMap<String, Value>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationMode {
    #[default]
    EveryRun,
    Once,
    TimeWindow,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Integer,
    Boolean,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParameterDefinition {
    pub name: String,
    pub label: String,
    pub kind: ParameterType,
    #[serde(default)]
    pub required: bool,
    pub default: Option<Value>,
    #[serde(default)]
    pub choices: Vec<Value>,
    pub max_length: Option<usize>,
}

impl ParameterDefinition {
    fn accepts(&self, value: &Value) -> bool {
        let typed = match self.kind {
            ParameterType::String => value.as_str().is_some_and(|s| {
                !s.contains('\0')
                    && s.chars().count() <= self.max_length.unwrap_or(2048)
                    && s.len() <= 8192
                    && (!self.required || !s.is_empty())
            }),
            ParameterType::Integer => value
                .as_i64()
                .is_some_and(|n| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&n)),
            ParameterType::Boolean => value.is_boolean(),
        };
        typed && (self.choices.is_empty() || self.choices.contains(value))
    }
}

pub fn validate(definitions: &[ParameterDefinition]) -> Result<(), CatalogError> {
    if definitions.len() > 16
        || serde_json::to_vec(definitions)
            .map_err(|_| CatalogError::Invalid)?
            .len()
            > 8192
    {
        return Err(CatalogError::Invalid);
    }
    let mut names = HashSet::new();
    for definition in definitions {
        if !crate::command::identifier(&definition.name)
            || !names.insert(&definition.name)
            || definition.label.trim().is_empty()
            || definition.label.chars().count() > 80
            || definition.choices.len() > 32
            || definition.max_length.is_some_and(|n| n == 0 || n > 2048)
            || (definition.kind != ParameterType::String && definition.max_length.is_some())
            || definition.choices.iter().any(|v| !definition.accepts(v))
            || definition
                .default
                .as_ref()
                .is_some_and(|v| !definition.accepts(v))
        {
            return Err(CatalogError::Invalid);
        }
    }
    Ok(())
}

pub fn resolve(
    definitions: &[ParameterDefinition],
    supplied: &ParameterValues,
) -> Result<ParameterValues, CatalogError> {
    validate(definitions)?;
    if supplied
        .keys()
        .any(|name| !definitions.iter().any(|d| d.name == *name))
    {
        return Err(CatalogError::Invalid);
    }
    let mut resolved = ParameterValues::new();
    for definition in definitions {
        let value = supplied
            .get(&definition.name)
            .or(definition.default.as_ref());
        if let Some(value) = value {
            if !definition.accepts(value) {
                return Err(CatalogError::Invalid);
            }
            resolved.insert(definition.name.clone(), value.clone());
        } else if definition.required {
            return Err(CatalogError::Invalid);
        } else {
            // A missing optional argument remains one argument, never changes argv structure.
            let empty = match definition.kind {
                ParameterType::String => Value::String(String::new()),
                ParameterType::Integer => Value::from(0),
                ParameterType::Boolean => Value::from(false),
            };
            if !definition.accepts(&empty) {
                return Err(CatalogError::Invalid);
            }
            resolved.insert(definition.name.clone(), empty);
        }
    }
    if serde_json::to_vec(&resolved)
        .map_err(|_| CatalogError::Invalid)?
        .len()
        > 8192
    {
        return Err(CatalogError::Invalid);
    }
    Ok(resolved)
}

pub fn argument(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn definition() -> ParameterDefinition {
        ParameterDefinition {
            name: "company".into(),
            label: "公司".into(),
            kind: ParameterType::String,
            required: true,
            default: Some(json!("100")),
            choices: vec![json!("100"), json!("101")],
            max_length: Some(3),
        }
    }

    #[test]
    fn defaults_types_choices_and_unknown_fields() {
        let d = definition();
        assert_eq!(
            resolve(std::slice::from_ref(&d), &ParameterValues::new()).unwrap()["company"],
            json!("100")
        );
        for value in [json!(100), json!("102"), json!(""), json!(null)] {
            assert!(
                resolve(
                    std::slice::from_ref(&d),
                    &BTreeMap::from([("company".into(), value)])
                )
                .is_err()
            );
        }
        assert!(resolve(&[d], &BTreeMap::from([("unknown".into(), json!(1))])).is_err());
    }

    #[test]
    fn required_and_unicode_limits() {
        let mut d = definition();
        d.choices.clear();
        d.default = None;
        d.max_length = Some(2);
        assert!(resolve(&[d.clone()], &ParameterValues::new()).is_err());
        assert!(
            resolve(
                &[d.clone()],
                &BTreeMap::from([("company".into(), json!("天津"))])
            )
            .is_ok()
        );
        assert!(resolve(&[d], &BTreeMap::from([("company".into(), json!("天津市"))])).is_err());
    }

    #[test]
    fn booleans_integers_and_optional_fallbacks_are_strict() {
        let definitions:Vec<ParameterDefinition>=serde_json::from_value(json!([
            {"name":"count","label":"数量","kind":"integer","default":null,"choices":[],"max_length":null},
            {"name":"verbose","label":"详细输出","kind":"boolean","default":null,"choices":[],"max_length":null}
        ])).unwrap();
        assert_eq!(
            resolve(&definitions, &ParameterValues::new()).unwrap(),
            BTreeMap::from([("count".into(), json!(0)), ("verbose".into(), json!(false))])
        );
        for value in [json!(1.2), json!("1"), json!(9_007_199_254_740_992_i64)] {
            assert!(resolve(&definitions, &BTreeMap::from([("count".into(), value)])).is_err());
        }
        assert!(
            resolve(
                &definitions,
                &BTreeMap::from([("verbose".into(), json!("false"))])
            )
            .is_err()
        );
        let duplicate = vec![definition(), definition()];
        assert!(validate(&duplicate).is_err());
    }
}

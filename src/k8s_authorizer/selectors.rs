use super::err::ParseError;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{
    FieldSelectorRequirement, LabelSelectorRequirement,
};
use std::collections::HashSet;

#[derive(Debug)]
pub struct Selector {
    pub key: String,
    // Does the key point to a required value, or optional/nullable one?
    // For a required field, Exists is always true, and NotExists is always false.
    pub nullable: bool,

    pub op: SelectorPredicate,
}

impl Selector {
    pub fn exact_match(&self) -> Option<String> {
        match &self.op {
            SelectorPredicate::In(values) => {
                if values.len() == 1 {
                    Some(values.iter().next().unwrap().clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn in_values(key: &str, nullable: bool, values: impl IntoIterator<Item = String>) -> Self {
        Self {
            key: key.to_string(),
            nullable,
            op: SelectorPredicate::In(values.into_iter().collect()),
        }
    }
}

#[derive(Debug)]
pub enum SelectorPredicate {
    Exists,
    NotExists,
    In(HashSet<String>),
    NotIn(HashSet<String>),
}

impl TryFrom<FieldSelectorRequirement> for Selector {
    type Error = ParseError;
    fn try_from(value: FieldSelectorRequirement) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            key: value.key,
            // All fields pointed to today are required, or casted to concrete values
            nullable: false,
            op: match value.operator.as_str() {
                "In" => SelectorPredicate::In(
                    value
                        .values
                        .ok_or_else(|| {
                            ParseError::InvalidFieldSelectorRequirement(
                                "In operator requires a non-empty values list".to_string(),
                            )
                        })?
                        .into_iter()
                        .collect(),
                ),
                "NotIn" => SelectorPredicate::NotIn(
                    value
                        .values
                        .ok_or_else(|| {
                            ParseError::InvalidFieldSelectorRequirement(
                                "NotIn operator requires a non-empty values list".to_string(),
                            )
                        })?
                        .into_iter()
                        .collect(),
                ),
                "Exists" => SelectorPredicate::Exists,
                "NotExists" => SelectorPredicate::NotExists,
                _ => {
                    return Err(ParseError::InvalidFieldSelectorRequirement(format!(
                        "unsupported selector operator: {}",
                        value.operator
                    )))
                }
            },
        })
    }
}

impl TryFrom<LabelSelectorRequirement> for Selector {
    type Error = ParseError;
    fn try_from(value: LabelSelectorRequirement) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            key: value.key,
            // All labels are nullable, they might not be defined for a given object
            nullable: true,
            op: match value.operator.as_str() {
                "In" => SelectorPredicate::In(
                    value
                        .values
                        .ok_or_else(|| {
                            ParseError::InvalidLabelSelectorRequirement(
                                "In operator requires a non-empty values list".to_string(),
                            )
                        })?
                        .into_iter()
                        .collect(),
                ),
                "NotIn" => SelectorPredicate::NotIn(
                    value
                        .values
                        .ok_or_else(|| {
                            ParseError::InvalidLabelSelectorRequirement(
                                "NotIn operator requires a non-empty values list".to_string(),
                            )
                        })?
                        .into_iter()
                        .collect(),
                ),
                "Exists" => SelectorPredicate::Exists,
                "NotExists" => SelectorPredicate::NotExists,
                _ => {
                    return Err(ParseError::InvalidLabelSelectorRequirement(format!(
                        "unsupported selector operator: {}",
                        value.operator
                    )))
                }
            },
        })
    }
}

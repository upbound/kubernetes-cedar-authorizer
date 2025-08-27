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
    // TODO: This should probably be populated at another layer, when a schema is available.
    // pub nullable: bool,
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

    #[cfg(test)]
    pub fn exists(key: &str) -> Self {
        Self {
            key: key.to_string(),
            op: SelectorPredicate::Exists,
        }
    }

    #[cfg(test)]
    pub fn in_values(key: &str, values: impl IntoIterator<Item = String>) -> Self {
        Self {
            key: key.to_string(),
            op: SelectorPredicate::In(values.into_iter().collect()),
        }
    }

    #[cfg(test)]
    pub fn not_in_values(key: &str, values: impl IntoIterator<Item = String>) -> Self {
        Self {
            key: key.to_string(),
            op: SelectorPredicate::NotIn(values.into_iter().collect()),
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
            // TODO: How to handle discrepancies between field selectors and the schema?
            // Not all field selectors are required in the schema, and some casts are non-trivial.
            // See: https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/4358-custom-resource-field-selectors/README.md
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

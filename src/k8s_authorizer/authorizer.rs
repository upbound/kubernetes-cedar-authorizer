use std::fmt::Display;

use super::err::{ParseError};
use cedar_policy::PolicySet;
use k8s_openapi::api::authorization::v1::{SubjectAccessReview};

use super::attributes::{Attributes, UserInfo, Verb, ResourceAttributes};
use super::err::AuthorizerError;
use super::selectors::Selector;
use cedar_policy_core::ast;

pub trait KubernetesAuthorizer {
    /// Determines whether the request is authorized.
    /// Returns a Response object with the decision, reason, and errors, or an unexpected error.
    fn is_authorized(&self, attrs: &Attributes) -> Result<Response, AuthorizerError>;

    /// Convenience method that converts the Result<Response, AuthorizerError> into a Response.
    /// If the Result is an unexpected error, NoOpinion is returned, and the errors are added to the Response.
    /// If the Result is ok, the Response is returned as is.
    fn is_authorized_response(&self, attrs: &Attributes) -> Response {
        self.is_authorized(attrs).into()
    }
}

#[derive(Debug)]
pub struct Response {
    pub decision: Decision,
    pub reason: Reason,
    pub errors: Vec<AuthorizerError>,
}

#[derive(Debug, PartialEq)]
pub struct Reason(Option<String>);

impl Reason {
    pub fn unexpected_error() -> Self {
        "Got unexpected error".to_string().into()
    }
    pub fn allowed_by_policies(action: &str, policy_ids: &Vec<ast::PolicyID>) -> Self {
        format!("action {action} allowed by policies {policy_ids:?}").into()
    }
    pub fn denied_by_policies(action: &str, policy_ids: &Vec<ast::PolicyID>) -> Self {
        format!("action {action} denied by policies {policy_ids:?}").into()
    }
    pub fn no_allow_policy_match(action: &str) -> Self {
        format!("no allow policy matched action {action}").into()
    }
    pub fn not_unconditionally_allowed(action: &str, conditions: Vec<ast::Policy>) -> Self {
        format!("action {action} is not unconditionally allowed. conditions: {conditions:?}").into()
    }
    pub fn with_cause(self, cause: Reason) -> Self {
        match (&self.0, &cause.0) {
            (Some(reason), Some(cause)) => format!("{reason}: {cause}").into(),
            (None, _) => cause,
            (_, None) => self,
        }
    }
}

impl From<String> for Reason {
    fn from(value: String) -> Self {
        Self(Some(value))
    }
}

impl Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_ref().unwrap_or(&"".to_string()))
    }
}

impl Default for Reason {
    fn default() -> Self {
        Self(None)
    }
}

impl From<Result<Response, AuthorizerError>> for Response {
    fn from(value: Result<Response, AuthorizerError>) -> Self {
        match value {
            Ok(r) => r,
            Err(e) => Response {
                decision: Decision::NoOpinion,
                reason: Reason::unexpected_error(),
                errors: vec![e],
            }
        }
    }
}

impl Response {
    pub fn no_opinion() -> Self {
        Response{
            decision: Decision::NoOpinion,
            reason: Default::default(),
            errors: Default::default(),
        }
    }
    pub fn allow() -> Self {
        Response{
            decision: Decision::Allow,
            reason: Default::default(),
            errors: Default::default(),
        }
    }
    pub fn with_reason(self, reason: Reason) -> Self {
        Self {
            decision: self.decision,
            reason,
            errors: self.errors,
        }
    }
    pub fn with_errors(self, errors: impl IntoIterator<Item = AuthorizerError>) -> Self {
        Self {
            decision: self.decision,
            reason: self.reason,
            errors: errors.into_iter().collect(),
        }
    }
    pub fn conditional(policies: PolicySet) -> Self {
        Self {
            decision: Decision::Conditional(policies),
            reason: Default::default(),
            errors: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Conditional(PolicySet),
    Deny,
    NoOpinion,
}

impl TryFrom<SubjectAccessReview> for Attributes {
    type Error = ParseError;
    fn try_from(value: SubjectAccessReview) -> Result<Self, Self::Error> {
        let spec = value.spec;
        let user = UserInfo {
            name: spec.user.ok_or_else(|| ParseError::InvalidUsername("".to_string(), "cannot be empty".to_string()))?, 
            uid: spec.uid,
            groups: spec.groups.unwrap_or_default().into_iter().collect(),
            extra: spec.extra.unwrap_or_default().into_iter().collect(),
        };
        match (spec.resource_attributes, spec.non_resource_attributes) {
            (Some(resource_attrs), None) => {
                let verb: Verb = resource_attrs.verb.unwrap_or_default().parse()?;

                Ok(Attributes{
                    user,
                    verb: verb.clone(),
                    path: None,

                    resource_attrs: Some(ResourceAttributes { 
                        namespace: resource_attrs.namespace.unwrap_or_default().parse()?, 
                        resource: resource_attrs.resource.unwrap_or_default().parse()?, 
                        name: resource_attrs.name.unwrap_or_default().parse()?, 
                        api_group: resource_attrs.group.unwrap_or_default().parse()?, 
                        // api_version: resource_attrs.version.unwrap_or_default().parse()?,
                        field_selector: match (verb.supports_selectors(), resource_attrs.field_selector) {
                            (false, _) => None, // Don't parse if the verb does not support it. TODO: error or warning?
                            (true, None) => None,
                            (true, Some(selector_params)) => match (selector_params.raw_selector, selector_params.requirements) {
                                (Some(_), _) => return Err(ParseError::InvalidFieldSelectorRequirement("raw_selector is not supported".to_string())),
                                (None, Some(reqs)) => Some(reqs.into_iter().map(|req| req.try_into()).collect::<Result<Vec<Selector>, ParseError>>()?),
                                (None, None) => None,
                            },
                        },
                        label_selector: match (verb.supports_selectors(), resource_attrs.label_selector) {
                            (false, _) => None, // Don't parse if the verb does not support it. TODO: error or warning?
                            (true, None) => None,
                            (true, Some(selector_params)) => match (selector_params.raw_selector, selector_params.requirements) {
                                (Some(_), _) => return Err(ParseError::InvalidLabelSelectorRequirement("raw_selector is not supported".to_string())),
                                (None, Some(reqs)) => Some(reqs.into_iter().map(|req| req.try_into()).collect::<Result<Vec<Selector>, ParseError>>()?),
                                (None, None) => None,
                            },
                        }
                    })
                })
            },
            (None, Some(nonresource_attrs)) => Ok(Attributes{
                user,
                verb: nonresource_attrs.verb.unwrap_or_default().parse()?,
                path: nonresource_attrs.path,
                resource_attrs: None,
            }),
            (Some(_), Some(_)) => Err(ParseError::InvalidSubjectAccessReview("resource and non-resource attributes are mutually exclusive".to_string())),   
            (None, None) => Err(ParseError::InvalidSubjectAccessReview("no resource or non-resource attributes".to_string())),
        }
    }
}
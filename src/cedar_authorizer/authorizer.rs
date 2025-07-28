use cedar_policy::{PolicySet};

use cedar_policy_core::tpe::entities::PartialEntity;
use cedar_policy_core::tpe::request::PartialEntityUID;

use cedar_policy_core::validator::json_schema::{Fragment, NamespaceDefinition};
use cedar_policy_core::validator::RawName;

use crate::k8s_authorizer::{Attributes, KubernetesAuthorizer, Response, Decision, Verb, AuthorizerError, Reason};
use crate::schema::core::K8S_NS;

use super::err::SchemaError;

struct CedarKubeAuthorizer<'a> {
    policies: PolicySet,
    schema: Fragment<RawName>,
    k8s_ns: &'a NamespaceDefinition<RawName>,
}

impl<'a> CedarKubeAuthorizer<'a> {
    fn register_schema(&'a mut self, schema: Fragment<RawName>) -> Result<(), SchemaError> {
        self.schema = schema;
        self.k8s_ns = self.schema.0.get(&K8S_NS).ok_or(SchemaError::NoKubernetesNamespace)?;
        Ok(())
    }

    fn construct_principal(&self, attrs: &Attributes) -> Result<(PartialEntityUID, PartialEntity), AuthorizerError> {
        if attrs.user.is_any_principal() {
            return Ok((PartialEntityUID, PartialEntity::new()));
        }

        Entity::new()
    }

    fn is_authorized_for_action(&self, attrs: &Attributes, action: &str) -> Result<Response, AuthorizerError> {
        // Check both typed and untyped actions, if applicable.
        // There is a typed action only if
        // a) the action is get, list, watch, create, update, patch, delete, deletecollection, and
        // b) the resource refers to a resource type in the schema.

        let req = PartialRequest::new(PartialEntityUid::new())


        if !attrs.is_resource_request() {
            self.policies.tpe()
        }



    }

}

impl KubernetesAuthorizer for CedarKubeAuthorizer<'_> {
    fn is_authorized(&self, attrs: &Attributes) -> Result<Response, AuthorizerError> {
        // Check that verb is supported in schema
        // If * => check with every action in schema in subroutine
        
        let verb_str = attrs.verb.to_string();
        if self.k8s_ns.actions.contains_key(verb_str.as_str()) {
            return Err(AuthorizerError::UnsupportedVerb(verb_str))
        }

        match attrs.verb {
            Verb::Any => {
                let mut errors = Vec::new();
                // TODO: Check the * action first, then others.
                for (action, _) in self.k8s_ns.actions.iter() {
                    // If an unexpected error occurs (i.e. error in the Result), just bubble it up.
                    // Non-critical errors are added to the Response.errors field, and it is possible to return
                    // Allow even if there are such errors.
                    let resp: Response = self.is_authorized_for_action(attrs, action.as_str())?;
                    errors.extend(resp.errors);
                    match resp.decision {
                        Decision::Allow => continue,
                        // Note: It is intentional here to fold a Cedar Deny policy into a Kubernetes NoOpinion response.
                        Decision::Deny => return Ok(Response::no_opinion().with_errors(errors).with_reason(Reason::denied_by_policy(action).with_cause(resp.reason))),
                        Decision::NoOpinion => return Ok(Response::no_opinion().with_errors(errors).with_reason(Reason::not_allowed_by_policy(action).with_cause(resp.reason))),
                        // Conditional policies are only supported for Create, Update, and Delete (and related verbs), not any, whose condition is arbitrary.
                        Decision::Conditional(_) => return Ok(Response::no_opinion().with_errors(errors).with_reason(Reason::not_unconditionally_allowed_by_policy(action).with_cause(resp.reason))),
                    }
                }

                Ok(Response::allow().with_errors(errors))
            },
            _ => self.is_authorized_for_action(attrs, &attrs.verb.to_string()),
        }
    }
}

// TODO: Translate to connect verbs
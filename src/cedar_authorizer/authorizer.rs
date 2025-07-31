use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use smol_str::ToSmolStr;
use uuid::Uuid;

use cedar_policy::{Authorizer, PolicySet};

use cedar_policy_core::tpe::entities::{PartialEntities, PartialEntity};
use cedar_policy_core::tpe::request::{PartialEntityUID, PartialRequest};

use cedar_policy_core::validator::json_schema::{Fragment, NamespaceDefinition};
use cedar_policy_core::validator::{RawName, ValidatorSchema};
use cedar_policy_core::ast::{Eid, EntityType, EntityUID, Name, UnreservedId};

use crate::cedar_authorizer::residuals::{DetailedDecision, PartialResponseNew};
use crate::k8s_authorizer::{Attributes, AuthorizerError, Decision, EmptyWildcardStringSelector, KubernetesAuthorizer, Reason, Response, Verb};
use crate::schema::core::{ENTITY_NAMESPACE, K8S_NS, MAP_STRINGSTRINGSET, PRINCIPAL_NODE, PRINCIPAL_SERVICEACCOUNT, PRINCIPAL_USER, RESOURCE_NONRESOURCEURL, RESOURCE_RESOURCE};

use cedar_policy_core::ast::Value as CedarValue;
use cedar_policy_core::ast;

use super::residuals::BoolResidualValue;
use super::err::SchemaError;

use kube::api::DynamicObject;


struct CedarKubeAuthorizer {
    policies: PolicySet,
    schema: Fragment<RawName>,
    schema_validator: ValidatorSchema,
    // k8s_ns: &'a NamespaceDefinition<RawName>,
}

impl CedarKubeAuthorizer {

    pub fn new(ps: PolicySet, schema: Fragment<RawName>) -> Result<Self, SchemaError> {
        Ok(Self {
            policies: ps,
            schema: schema.clone(),
            // k8s_ns: schema.0.get(&K8S_NS).ok_or(SchemaError::NoKubernetesNamespace)?,
            schema_validator: schema.try_into()?,
        })
    }
    fn register_schema(&mut self, schema: Fragment<RawName>) -> Result<(), SchemaError> {
        self.schema = schema.clone();
        // self.k8s_ns = self.schema.0.get(&K8S_NS).ok_or(SchemaError::NoKubernetesNamespace)?;
        self.schema_validator = schema.try_into()?;
        Ok(())
    }

    fn register_policies(&mut self, policies: PolicySet) -> Result<(), SchemaError> {
        // TODO: Add mutex
        // TODO: What all fields can be wildcards, i.e. partially unknown, and require schema rewrite?
        // At least:
        // - k8s::Resource: apiGroup, resourceCombined, name. (namespace is already an entity reference.)
        self.policies = policies;
        Ok(())
    }

    fn construct_principal(&self, attrs: &Attributes) -> Result<(PartialEntityUID, Vec<PartialEntity>), AuthorizerError> {
        // If the principal is any, it must match any user and use partial evaluation.
        if attrs.user.is_any_principal() {
            return Ok((PartialEntityUID{
                ty: EntityType::EntityType(PRINCIPAL_USER.name.name()),
                eid: None,
            }, Vec::new()));
        }

        let mut entities = Vec::new();

        let extra_entity_uid = EntityUID::from_components(EntityType::EntityType(MAP_STRINGSTRINGSET.0.name()), Eid::new(Uuid::new_v4().to_smolstr()), None);
        
        entities.push(PartialEntity{
            uid: extra_entity_uid.clone(),
            attrs: Some(BTreeMap::from([
                ("keys".to_smolstr(), ast::Value::set_of_lits(attrs.user.extra.keys().map(|k| k.as_str().into()), None)),
            ])),
            ancestors: None,
            tags: Some(attrs.user.extra.iter().map(|(k, v)| (k.into(), ast::Value::set_of_lits(v.iter().map(|v| v.as_str().into()), None))).collect()),
        });

        let mut principal_attrs = BTreeMap::from([
            ("username".to_smolstr(), attrs.user.name.as_str().into()),
            ("groups".to_smolstr(), ast::Value::set_of_lits(attrs.user.groups.iter().map(|g| g.as_str().into()), None)),
            ("extra".to_smolstr(), extra_entity_uid.into())
        ]);

        if let Some(uid) = &attrs.user.uid {
            principal_attrs.insert("uid".to_smolstr(), uid.as_str().into());
        }

        let mut principal_type = PRINCIPAL_USER.name.name();

        if let Some(sa_nsname_str) = attrs.user.name.strip_prefix("system:serviceaccount:") {

            let parts: Vec<&str> = sa_nsname_str.split(':').collect();
            if parts.len() != 2 {
                return Err(AuthorizerError::InvalidServiceAccount(attrs.user.name.clone(), "expected format: 'system:serviceaccount:<namespace>:<name>'".to_string()));
            }

            principal_attrs.insert("namespace".to_smolstr(), parts[0].into());
            principal_attrs.insert("name".to_smolstr(), parts[1].into());

            // TODO: Add the namespace anchestor.

            principal_type = PRINCIPAL_SERVICEACCOUNT.name.name();
        } else if let Some(nodename) = attrs.user.name.strip_prefix("system:node:") {
            principal_type = PRINCIPAL_NODE.name.name();
            // TODO: Add some validation here
            principal_attrs.insert("name".to_smolstr(), nodename.into());
        }

        let principal_uid = EntityUID::from_components(EntityType::EntityType(principal_type), Eid::new(Uuid::new_v4().to_smolstr()), None);
        entities.push(PartialEntity{
            uid: principal_uid.clone(),
            attrs: Some(principal_attrs),
            ancestors: None,
            tags: None,
        });

        return Ok((principal_uid.into(), entities));
    }

    fn construct_resource(&self, attrs: &Attributes) -> Result<(PartialEntityUID, Vec<PartialEntity>), AuthorizerError> {

        match &attrs.resource_attrs {
            None => {
                let resource_uid = EntityUID::from_components(EntityType::EntityType(RESOURCE_NONRESOURCEURL.name.name()), Eid::new(Uuid::new_v4().to_smolstr()), None);
                let resource_entities = Vec::from([PartialEntity{
                    uid: resource_uid.clone(),
                    attrs: Some(BTreeMap::from([
                        ("path".to_smolstr(), attrs.path.clone().unwrap_or_default().into()),
                    ])),
                    ancestors: None,
                    tags: None,
                }]);
                return Ok((resource_uid.into(), resource_entities));
            },
            Some(resource_attrs) => {
                let resource_uid = EntityUID::from_components(EntityType::EntityType(RESOURCE_RESOURCE.name.name()), Eid::new(Uuid::new_v4().to_smolstr()), None);

                let mut resource_entities = Vec::new();
                let namespace_entity_uid = EntityUID::from_components(EntityType::EntityType(ENTITY_NAMESPACE.name.name()), Eid::new(Uuid::new_v4().to_smolstr()), None);

                let resource_entity_attrs = BTreeMap::from([
                    ("apiGroup".to_smolstr(), resource_attrs.api_group.to_string().into()), // TODO: This is wrong; should use match and rewrite the schema
                    ("name".to_smolstr(), resource_attrs.name.to_string().into()),  // TODO: This is wrong; should use match and rewrite the schema
                    ("namespace".to_smolstr(), namespace_entity_uid.clone().into()),
                    ("resourceCombined".to_smolstr(), resource_attrs.resource.to_string().into()), // TODO: This is wrong; should use match and rewrite the schema
                ]);

                match &resource_attrs.namespace {
                    EmptyWildcardStringSelector::Any => (), // Leave the namespace unknown
                    EmptyWildcardStringSelector::Exact(ns_name) => {
                        resource_entities.push(PartialEntity{
                            uid: namespace_entity_uid,
                            attrs: Some(BTreeMap::from([
                                ("name".to_smolstr(), ns_name.as_str().into()),
                            ])),
                            ancestors: None,
                            tags: None,
                        });
                    },
                }

                resource_entities.push(PartialEntity{
                    uid: resource_uid.clone(),
                    attrs: Some(resource_entity_attrs),
                    ancestors: None,
                    tags: None,
                });

                return Ok((resource_uid.into(), resource_entities));
            },
        }
    }

    // INVARIANT: verb is validated to exist in the schema already.
    fn is_authorized_for_action(&self, attrs: &Attributes, action: &str) -> Result<PartialResponseNew, AuthorizerError> {
        // Check both typed and untyped actions, if applicable.
        // There is a typed action only if
        // a) the action is get, list, watch, create, update, patch, delete, deletecollection, and
        // b) the resource refers to a resource type in the schema.

        // TODO: If we have a 

        let action_entity = format!(r#"k8s::Action::"{action}""#).parse()?;

        let (principal_uid, principal_entities) = self.construct_principal(attrs)?;

        let (resource_uid, resource_entities) = self.construct_resource(attrs)?;
        
        let req = PartialRequest::new(principal_uid, action_entity, resource_uid, None, &self.schema_validator)?;

        let entities = PartialEntities::from_entities(
            principal_entities.iter()
                .map(|e| (e.uid.clone(), e.clone()))
                .chain(resource_entities.iter()
                    .map(|e| (e.uid.clone(), e.clone()))),
            &self.schema_validator
        )?;

        let resp = super::residuals::tpe(&self.policies, &req, &entities, &self.schema_validator)?;
        
        Ok(resp.is_authorized_new()?)
    }

}

impl KubernetesAuthorizer for CedarKubeAuthorizer {
    fn is_authorized(&self, attrs: &Attributes) -> Result<Response, AuthorizerError> {
        // Check that verb is supported in schema
        // If * => check with every action in schema in subroutine

        let k8s_ns = self.schema.0.get(&K8S_NS).ok_or(AuthorizerError::NoKubernetesNamespace)?;
        
        let verb_str = attrs.verb.to_string();
        if !k8s_ns.actions.contains_key(verb_str.as_str()) {
            return Err(AuthorizerError::UnsupportedVerb(verb_str))
        }

        match attrs.verb {
            Verb::Any => {
                let mut errors = Vec::new();
                let mut allowed_ids = HashSet::new();
                // TODO: Check the * action first, then others.
                for (action, _) in k8s_ns.actions.iter() {
                    println!("action: {}", action);
                    
                    let resp = self.is_authorized_for_action(attrs, action.as_str())?;
                    // TODO: Propagate errors?

                    match resp.decision() {
                        DetailedDecision::Allow(permitted_policy_ids) => allowed_ids.extend(permitted_policy_ids.into_iter()),
                        DetailedDecision::Conditional(conditions) =>
                            return Ok(Response::no_opinion().with_errors(errors).with_reason(Reason::not_unconditionally_allowed(action, conditions))),
                        DetailedDecision::Deny(forbidden_policy_ids) =>
                            return Ok(Response::no_opinion().with_errors(errors).with_reason(Reason::denied_by_policies(action,&forbidden_policy_ids))),
                        DetailedDecision::NoOpinion => return Ok(Response::no_opinion().with_errors(errors))
                    }
                }

                Ok(Response::allow().with_errors(errors))
            },
            // Semantics:
            // - If there are any true denies, deny.
            // (- If there are any folded true denies, deny.)
            // We can add this optimization later.
            // - If there are any residual denies (that do not fold to false), conditional
            // TODO: Should we give full context here; i.e. including foldable residual forbid policies?
            // In the beginning, we do not do this, but keep things simple.
            // The permit policies could potentially just be folded into "true", if there is at least one true.
            // - If there are any true allows, allow.
            // - NOTE: Do not fold allows to true, only to false.
            // - If there are any residual allows (that do not fold to false), conditional
            //   At this point, it is known that there are no residual denies.
            // - Otherwise (only false denies and allows, or none), no opinion.
            // TODO: Maybe we want still to fold here too?
            _ => {
                let action_str = attrs.verb.to_string();
                match self.is_authorized_for_action(attrs, &action_str)?.decision() {
                    // TODO: Propagate errors
                    DetailedDecision::Allow(permitted_policy_ids) => Ok(Response::allow().with_reason(Reason::allowed_by_policies(&action_str, &permitted_policy_ids))),
                    DetailedDecision::Deny(forbidden_policy_ids) => Ok(Response::no_opinion().with_reason(Reason::denied_by_policies(&action_str,&forbidden_policy_ids))),
                    DetailedDecision::Conditional(conditional_policies) => Ok(Response::conditional(PolicySet::from_policies(conditional_policies.into_iter().map(|p| p.into()))?)),
                    DetailedDecision::NoOpinion => Ok(Response::no_opinion().with_reason(Reason::no_allow_policy_match(&action_str)))
                }
            },
        }
    }
}

// TODO: Translate to connect verbs

mod test {
    
    #[test]
    fn test_is_authorized() {
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy::PolicySet;
        use cedar_policy_core::validator::json_schema::Fragment;
        use std::str::FromStr;
        use crate::k8s_authorizer::{ StarWildcardStringSelector, EmptyWildcardStringSelector, KubernetesAuthorizer, CombinedResource, Response, Verb};
        use crate::k8s_authorizer::test_utils::AttributesBuilder;

        let policies = PolicySet::from_str(include_str!("testfiles/simple.cedar")).unwrap();
        let (schema, _) = Fragment::from_cedarschema_str(include_str!("testfiles/simple.cedarschema"), &Extensions::all_available()).unwrap();

        let authorizer = super::CedarKubeAuthorizer::new(policies, schema).unwrap();

        // TODO: Fix validation problem with nonresourceurl and any verb.
        let test_cases = vec![
            ("superadmin can do anything", 
            AttributesBuilder::new("superadmin", Verb::Any)
                .with_resource(
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("admin can't do anything, as they are forbidden to get in the supersecret namespace",
            AttributesBuilder::new("admin", Verb::Any)
                .with_resource(
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount can do X",
            AttributesBuilder::new("system:serviceaccount:foo:bar", Verb::Get)
                .with_resource(
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
        ];

        for (description, attrs, expected_resp) in test_cases {
            println!("{}", description);
            let resp = authorizer.is_authorized_response(&attrs);
            assert_eq!(expected_resp.decision, resp.decision, "got {:?} with reason: {}, errors: {:?}", resp.decision, resp.reason, resp.errors);
        }
    }
}
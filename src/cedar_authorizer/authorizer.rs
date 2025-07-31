use k8s_openapi::api::core::v1 as corev1;
use kube;
use kube::runtime::reflector;
use kube::runtime::watcher;
use smol_str::ToSmolStr;
use std::collections::HashMap;
use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;
use uuid::Uuid;

use cedar_policy::PolicySet;

use cedar_policy_core::tpe::entities::{PartialEntities, PartialEntity};
use cedar_policy_core::tpe::request::{PartialEntityUID, PartialRequest};

use cedar_policy_core::ast::{Eid, EntityType, EntityUID};
use cedar_policy_core::validator::json_schema::Fragment;
use cedar_policy_core::validator::{RawName, ValidatorSchema};

use crate::cedar_authorizer::residuals::{DetailedDecision, PartialResponseNew};
use crate::k8s_authorizer::CombinedResource;
use crate::k8s_authorizer::StarWildcardStringSelector;
use crate::k8s_authorizer::{
    Attributes, AuthorizerError, EmptyWildcardStringSelector, KubernetesAuthorizer, Reason,
    Response, Verb,
};
use crate::schema::core::{
    ENTITY_NAMESPACE, K8S_NS, MAP_STRINGSTRINGSET, PRINCIPAL_NODE, PRINCIPAL_SERVICEACCOUNT,
    PRINCIPAL_UNAUTHENTICATEDUSER, PRINCIPAL_USER, RESOURCE_NONRESOURCEURL, RESOURCE_RESOURCE,
};
use kube::discovery::Scope;

use cedar_policy_core::ast;

use super::entitybuilder::{string_slice, BuiltEntity, EntityBuilder};
use super::err::SchemaError;
use super::kubestore::{KubeApiGroup, KubeDiscovery, KubeStore};

struct CedarKubeAuthorizer<S: KubeStore<corev1::Namespace>, G: KubeApiGroup, D: KubeDiscovery<G>> {
    policies: PolicySet,
    schema: Fragment<RawName>,
    schema_validator: ValidatorSchema,
    namespaces: S,
    discovery: D,

    _phantom: PhantomData<G>,
    // k8s_ns: &'a NamespaceDefinition<RawName>,
}

impl<S: KubeStore<corev1::Namespace>, G: KubeApiGroup, D: KubeDiscovery<G>>
    CedarKubeAuthorizer<S, G, D>
{
    pub fn new(
        ps: PolicySet,
        schema: Fragment<RawName>,
        namespaces: S,
        discovery: D,
    ) -> Result<Self, SchemaError> {
        Ok(Self {
            policies: ps,
            schema: schema.clone(),
            // k8s_ns: schema.0.get(&K8S_NS).ok_or(SchemaError::NoKubernetesNamespace)?,
            schema_validator: schema.try_into()?,
            namespaces,
            discovery,
            _phantom: PhantomData,
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

    fn construct_principal(&self, attrs: &Attributes) -> Result<BuiltEntity, AuthorizerError> {
        // If the principal is any, it must match any user and use partial evaluation.
        if attrs.user.is_any_principal() {
            return Ok(EntityBuilder::new().build(EntityType::EntityType(
                PRINCIPAL_UNAUTHENTICATEDUSER.name.name(),
            )));
        }

        let mut entity_builder: EntityBuilder = EntityBuilder::new()
            .with_attr("username", Some(attrs.user.name.as_str()))
            .with_attr("groups", Some(string_slice(attrs.user.groups.iter())))
            .with_attr(
                "uid",
                attrs
                    .user
                    .uid
                    .as_ref()
                    .map(|uid| Into::<ast::Value>::into(uid.as_str())),
            )
            .with_entity_attr(
                "extra",
                Some(
                    EntityBuilder::new()
                        .with_attr("keys", Some(string_slice(attrs.user.extra.keys())))
                        .with_tags(
                            attrs
                                .user
                                .extra
                                .iter()
                                .map(|(k, v)| (k.into(), string_slice(v.iter())))
                                .collect(),
                        )
                        .build(EntityType::EntityType(MAP_STRINGSTRINGSET.0.name())),
                ),
            );

        let mut principal_type = PRINCIPAL_USER.name.name();

        if let Some(sa_nsname_str) = attrs.user.name.strip_prefix("system:serviceaccount:") {
            let parts: Vec<&str> = sa_nsname_str.split(':').collect();
            if parts.len() != 2 {
                return Err(AuthorizerError::InvalidServiceAccount(
                    attrs.user.name.clone(),
                    "expected format: 'system:serviceaccount:<namespace>:<name>'".to_string(),
                ));
            }

            entity_builder.add_entity_attr("namespace", Some(self.namespace_entity(parts[0])?));
            entity_builder.add_attr("name", Some(parts[1]));

            // TODO: Add the namespace anchestor.

            principal_type = PRINCIPAL_SERVICEACCOUNT.name.name();
        } else if let Some(nodename) = attrs.user.name.strip_prefix("system:node:") {
            principal_type = PRINCIPAL_NODE.name.name();
            // TODO: Add some validation here
            entity_builder.add_attr("name", Some(nodename));
        }

        Ok(entity_builder.build(EntityType::EntityType(principal_type)))
    }

    fn namespace_entity(&self, ns_name: &str) -> Result<BuiltEntity, AuthorizerError> {
        let ns_ref = reflector::ObjectRef::new(ns_name);
        let ns = self
            .namespaces
            .get(&ns_ref)
            .ok_or(AuthorizerError::NoKubernetesNamespace)?;

        let ns_uid = ns
            .metadata
            .uid
            .as_ref()
            .ok_or(AuthorizerError::NoKubernetesNamespace)?;
        // TODO: Add the namespace objectmeta too
        Ok(EntityBuilder::new()
            .with_eid(ns_uid)
            .with_attr("name", Some(ns_name))
            .build(EntityType::EntityType(ENTITY_NAMESPACE.name.name())))
    }

    fn construct_resource(&self, attrs: &Attributes) -> Result<BuiltEntity, AuthorizerError> {
        match &attrs.resource_attrs {
            None => Ok(EntityBuilder::new()
                .with_attr("path", Some(attrs.path.clone().unwrap_or_default()))
                .build(EntityType::EntityType(RESOURCE_NONRESOURCEURL.name.name()))),
            Some(resource_attrs) => {
                let mut resource_builder = EntityBuilder::new()
                    // TODO: This is wrong; should use match and rewrite the schema
                    .with_attr("apiGroup", Some(resource_attrs.api_group.to_string()))
                    .with_attr("name", Some(resource_attrs.name.to_string()))
                    .with_attr(
                        "resourceCombined",
                        Some(resource_attrs.resource.to_string()),
                    );

                resource_builder.add_entity_attr(
                    "namespace",
                    match &resource_attrs.namespace {
                        // Ugh, how do we know whether the namespace is "any" or "none" (for a cluster-wide resource)?
                        // If apiGroup & resource are known, we know whether the resource is cluster-scoped or namespace-scoped.
                        // If both or either are unknown, we must (for safety) assume that cluster-wide, i.e. "any".
                        EmptyWildcardStringSelector::Any => {
                            let any_namespace_fallback = Some(
                                EntityBuilder::new()
                                    .build(EntityType::EntityType(ENTITY_NAMESPACE.name.name())),
                            );

                            match (&resource_attrs.api_group, &resource_attrs.resource) {
                                (
                                    StarWildcardStringSelector::Exact(api_group),
                                    CombinedResource::ResourceOnly { resource },
                                )
                                | (
                                    StarWildcardStringSelector::Exact(api_group),
                                    CombinedResource::ResourceSubresource { resource, .. },
                                ) => {
                                    match self.discovery.get_api_group(api_group.as_str()) {
                                        Some(api_group) => {
                                            let resources = api_group.recommended_resources();
                                            let resource =
                                                resources.iter().find(|r| &r.0.plural == resource);
                                            match resource {
                                                Some(resource) => match resource.1.scope {
                                                    Scope::Cluster => None,
                                                    Scope::Namespaced => any_namespace_fallback,
                                                },
                                                None => any_namespace_fallback, // TODO: log unexpected?
                                            }
                                        }
                                        None => any_namespace_fallback, // TODO: log unexpected?
                                    }
                                }
                                _ => any_namespace_fallback,
                            }
                        } // Leave the namespace attributes unknown
                        EmptyWildcardStringSelector::Exact(ns_name) => {
                            Some(self.namespace_entity(ns_name.as_str())?)
                        }
                    },
                );

                Ok(resource_builder.build(EntityType::EntityType(RESOURCE_RESOURCE.name.name())))
            }
        }
    }

    // INVARIANT: verb is validated to exist in the schema already.
    fn is_authorized_for_action(
        &self,
        attrs: &Attributes,
        action: &str,
    ) -> Result<PartialResponseNew, AuthorizerError> {
        // Check both typed and untyped actions, if applicable.
        // There is a typed action only if
        // a) the action is get, list, watch, create, update, patch, delete, deletecollection, and
        // b) the resource refers to a resource type in the schema.

        // TODO: If we have a

        let action_entity = format!(r#"k8s::Action::"{action}""#).parse()?;

        let principal_entity = self.construct_principal(attrs)?;
        let resource_entity = self.construct_resource(attrs)?;

        let req = PartialRequest::new(
            principal_entity.uid().clone().into(),
            action_entity,
            resource_entity.uid().clone().into(),
            None,
            &self.schema_validator,
        )?;

        // Collect all entities into a single map; a chained iterator does not work, as
        // that could yield duplicate entities (e.g. for namespace across ServiceAccount and k8s::Resource).
        let mut deduplicated_entities = principal_entity.consume_entities();
        deduplicated_entities.extend(resource_entity.consume_entities());
        let entities = PartialEntities::from_entities(
            deduplicated_entities.into_iter(),
            &self.schema_validator,
        )?;

        let resp = super::residuals::tpe(&self.policies, &req, &entities, &self.schema_validator)?;

        Ok(resp.is_authorized_new()?)
    }
}

impl<S: KubeStore<corev1::Namespace>, G: KubeApiGroup, D: KubeDiscovery<G>> KubernetesAuthorizer
    for CedarKubeAuthorizer<S, G, D>
{
    fn is_authorized(&self, attrs: &Attributes) -> Result<Response, AuthorizerError> {
        // Check that verb is supported in schema
        // If * => check with every action in schema in subroutine

        let k8s_ns = self
            .schema
            .0
            .get(&K8S_NS)
            .ok_or(AuthorizerError::NoKubernetesNamespace)?;

        let verb_str = attrs.verb.to_string();
        if !k8s_ns.actions.contains_key(verb_str.as_str()) {
            return Err(AuthorizerError::UnsupportedVerb(verb_str));
        }

        match attrs.verb {
            Verb::Any => {
                let errors = Vec::new();
                let mut allowed_ids = HashSet::new();
                // TODO: Check the * action first, then others.
                for (action, _) in k8s_ns.actions.iter() {
                    println!("action: {action}");

                    let resp = self.is_authorized_for_action(attrs, action.as_str())?;
                    // TODO: Propagate errors?

                    match resp.decision() {
                        DetailedDecision::Allow(permitted_policy_ids) => {
                            allowed_ids.extend(permitted_policy_ids.into_iter())
                        }
                        DetailedDecision::Conditional(conditions) => {
                            return Ok(Response::no_opinion().with_errors(errors).with_reason(
                                Reason::not_unconditionally_allowed(action, conditions),
                            ))
                        }
                        DetailedDecision::Deny(forbidden_policy_ids) => {
                            return Ok(Response::no_opinion().with_errors(errors).with_reason(
                                Reason::denied_by_policies(action, &forbidden_policy_ids),
                            ))
                        }
                        DetailedDecision::NoOpinion => {
                            return Ok(Response::no_opinion().with_errors(errors))
                        }
                    }
                }

                Ok(Response::allow().with_errors(errors))
            }
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
                match self
                    .is_authorized_for_action(attrs, &action_str)?
                    .decision()
                {
                    // TODO: Propagate errors
                    DetailedDecision::Allow(permitted_policy_ids) => Ok(Response::allow()
                        .with_reason(Reason::allowed_by_policies(
                            &action_str,
                            &permitted_policy_ids,
                        ))),
                    DetailedDecision::Deny(forbidden_policy_ids) => Ok(Response::no_opinion()
                        .with_reason(Reason::denied_by_policies(
                            &action_str,
                            &forbidden_policy_ids,
                        ))),
                    DetailedDecision::Conditional(conditional_policies) => {
                        Ok(Response::conditional(PolicySet::from_policies(
                            conditional_policies.into_iter().map(|p| p.into()),
                        )?))
                    }
                    DetailedDecision::NoOpinion => Ok(Response::no_opinion()
                        .with_reason(Reason::no_allow_policy_match(&action_str))),
                }
            }
        }
    }
}

// TODO: Translate to connect verbs

mod test {

    /*
    let nodes: kube::Api<corev1::Namespace> = kube::Api::all(client);
        let lp = kube::Config::infer();
        let (reader, writer) = reflector::store();
        let rf = reflector(writer, watcher(nodes, lp));
     */

    #[test]
    fn test_is_authorized() {
        use super::super::kubestore::{TestKubeApiGroup, TestKubeDiscovery, TestKubeStore};
        use crate::k8s_authorizer::test_utils::AttributesBuilder;
        use crate::k8s_authorizer::{
            CombinedResource, EmptyWildcardStringSelector, KubernetesAuthorizer, Response,
            StarWildcardStringSelector, Verb,
        };
        use cedar_policy::PolicySet;
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy_core::validator::json_schema::Fragment;
        use k8s_openapi::api::core::v1 as corev1;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
        use kube::discovery::{ApiCapabilities, ApiResource, Scope};
        use std::str::FromStr;

        let policies = PolicySet::from_str(include_str!("testfiles/simple.cedar")).unwrap();
        let (schema, _) = Fragment::from_cedarschema_str(
            include_str!("testfiles/simple.cedarschema"),
            Extensions::all_available(),
        )
        .unwrap();

        let namespace_store = TestKubeStore::new(vec![corev1::Namespace {
            metadata: metav1::ObjectMeta {
                name: Some("foo".to_string()),
                uid: Some("1e00c0eb-ec4c-41a2-bb59-e7dea5b21b50".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }]);

        let discovery = TestKubeDiscovery::new(vec![TestKubeApiGroup {
            name: "".to_string(),
            recommended_groups_resources: vec![(
                ApiResource {
                    group: "".to_string(),
                    version: "v1".to_string(),
                    kind: "Node".to_string(),
                    plural: "nodes".to_string(),
                    api_version: "v1".to_string(),
                },
                ApiCapabilities {
                    scope: Scope::Cluster,
                    subresources: vec![],
                    operations: vec![],
                },
            )],
        }]);

        let authorizer =
            super::CedarKubeAuthorizer::new(policies, schema, namespace_store, discovery).unwrap();

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
            ("serviceaccount can get serviceaccounts in its own namespace",
            AttributesBuilder::new("system:serviceaccount:foo:bar", Verb::Get)
                .with_resource(
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("serviceaccount can get serviceaccounts in its own namespace, but not in the supersecret namespace",
            AttributesBuilder::new("system:serviceaccount:supersecret:bar", Verb::Get)
                .with_resource(
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Exact("supersecret".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("anonymous user can only get the version",
            AttributesBuilder::new("system:anonymous", Verb::Get)
                .with_path("/version")
                .build(), Response::allow()),
            ("anonymous user cannot get other paths",
            AttributesBuilder::new("system:anonymous", Verb::Get)
                .with_path("/metrics")
                .build(), Response::no_opinion()),
            ("a node can only its own node object",
            AttributesBuilder::new("system:node:node-1", Verb::Get)
                .with_resource(
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "nodes".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Exact("node-1".to_string()))
                .build(), Response::allow()),
            ("a node cannot get other nodes",
            AttributesBuilder::new("system:node:node-1", Verb::Get)
                .with_resource(
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "nodes".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Exact("node-2".to_string()))
                .build(), Response::no_opinion()),
        ];

        for (description, attrs, expected_resp) in test_cases {
            println!("{description}");
            let resp = authorizer.is_authorized_response(&attrs);
            assert_eq!(
                expected_resp.decision, resp.decision,
                "got {} with reason: {}, errors: {:?}",
                resp.decision, resp.reason, resp.errors
            );
        }
    }
}

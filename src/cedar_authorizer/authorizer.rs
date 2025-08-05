use k8s_openapi::api::core::v1 as corev1;
use kube;
use kube::runtime::reflector;
use std::collections::HashSet;
use std::marker::PhantomData;

use cedar_policy_core::tpe::entities::PartialEntities;
use cedar_policy_core::tpe::request::PartialRequest;

use cedar_policy_core::ast::EntityType;

use crate::cedar_authorizer::kube_invariants::DetailedDecision;
use crate::cedar_authorizer::kube_invariants::{self};
use crate::k8s_authorizer::StarWildcardStringSelector;
use crate::k8s_authorizer::{
    Attributes, AuthorizerError, EmptyWildcardStringSelector, KubernetesAuthorizer, ParseError,
    Reason, ResourceAttributes, Response, Verb,
};
use crate::k8s_authorizer::{CombinedResource, RequestType};
use crate::schema::core::{
    ENTITY_NAMESPACE, K8S_NS, PRINCIPAL_NODE, PRINCIPAL_SERVICEACCOUNT,
    PRINCIPAL_UNAUTHENTICATEDUSER, PRINCIPAL_USER, RESOURCE_NONRESOURCEURL, RESOURCE_RESOURCE,
};
use kube::discovery::Scope;

use cedar_policy_core::ast;

use super::entitybuilder::{BuiltEntity, EntityBuilder, RecordBuilder};
use super::kube_invariants::SchemaError;
use super::kubestore::{KubeApiGroup, KubeDiscovery, KubeStore};

// TODO: Disallow usage of "is k8s::Resource", such that we do not need to do authorization requests separately for "untyped" and "typed" variants?
//   If we make it such that (given you restrict the verb to some resource verb) you MUST keep the policy open to all typed variants, then
//   we probably have an easier time analyzing as well who has access to some given resource, and we don't need rewrites from untyped -> typed worlds.
struct CedarKubeAuthorizer<
    'a,
    S: KubeStore<corev1::Namespace>,
    G: KubeApiGroup,
    D: KubeDiscovery<G>,
> {
    policies: kube_invariants::PolicySet<'a>,
    namespaces: S,
    discovery: D,

    _phantom: PhantomData<G>,
    // k8s_ns: &'a NamespaceDefinition<RawName>,
}

impl<'a, S: KubeStore<corev1::Namespace>, G: KubeApiGroup, D: KubeDiscovery<G>>
    CedarKubeAuthorizer<'a, S, G, D>
{
    // TODO: Add possibility to dynamically update the schema and policies later as well.
    pub fn new(
        policies: kube_invariants::PolicySet<'a>,
        namespaces: S,
        discovery: D,
    ) -> Result<Self, SchemaError> {
        Ok(Self {
            policies,
            namespaces,
            discovery,
            _phantom: PhantomData,
        })
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
            .with_string_set("groups", Some(attrs.user.groups.clone()))
            .with_attr(
                "uid",
                attrs
                    .user
                    .uid
                    .as_ref()
                    .map(|uid| Into::<ast::Value>::into(uid.as_str())),
            )
            .with_string_to_stringset_map("extra", Some(&attrs.user.extra));

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

        Ok(EntityBuilder::new()
            .with_eid(ns_uid)
            .with_attr("name", Some(ns_name))
            .with_record_attr(
                "metadata",
                Some(
                    RecordBuilder::new()
                        .with_string_to_string_map("labels", ns.metadata.labels.as_ref())
                        .with_string_to_string_map("annotations", ns.metadata.annotations.as_ref())
                        .with_string_set("finalizers", ns.metadata.finalizers.clone())
                        .with_attr("uid", Some(ns_uid.as_str()))
                        .with_attr("deleted", Some(ns.metadata.deletion_timestamp.is_some())),
                ),
            )
            .build(EntityType::EntityType(ENTITY_NAMESPACE.name.name())))
    }

    fn construct_untyped_resource(
        &self,
        attrs: &Attributes,
    ) -> Result<BuiltEntity, AuthorizerError> {
        match &attrs.request_type {
            RequestType::NonResource(nonresource_attrs) => Ok(EntityBuilder::new()
                // TODO: If it is "*", actually keep unknown
                .with_entity_attr(
                    "path",
                    Some(EntityBuilder::unknown_string(
                        match nonresource_attrs.path {
                            StarWildcardStringSelector::Any => None,
                            _ => Some(nonresource_attrs.path.to_string()),
                        },
                    )),
                )
                .build(EntityType::EntityType(RESOURCE_NONRESOURCEURL.name.name()))),
            RequestType::Resource(resource_attrs) => {
                let mut resource_builder = EntityBuilder::new()
                    .with_entity_attr(
                        "apiGroup",
                        Some(EntityBuilder::unknown_string(
                            match resource_attrs.api_group {
                                StarWildcardStringSelector::Any => None,
                                _ => Some(resource_attrs.api_group.to_string()),
                            },
                        )),
                    )
                    .with_entity_attr(
                        "name",
                        Some(EntityBuilder::unknown_string(match resource_attrs.name {
                            EmptyWildcardStringSelector::Any => None,
                            _ => Some(resource_attrs.name.to_string()),
                        })),
                    )
                    .with_entity_attr(
                        "resourceCombined",
                        Some(EntityBuilder::unknown_string(
                            match resource_attrs.resource {
                                CombinedResource::Any => None,
                                _ => Some(resource_attrs.resource.to_string()),
                            },
                        )),
                    );

                resource_builder.add_entity_attr(
                    "namespace",
                    match &resource_attrs.namespace {
                        // Ugh, how do we know whether the namespace is "any" or "none" (for a cluster-wide resource)?
                        // If apiGroup & resource are known, we know whether the resource is cluster-scoped or namespace-scoped.
                        // If both or either are unknown, we must (for safety) assume that cluster-wide, i.e. "any".
                        EmptyWildcardStringSelector::Any => {
                            let any_namespace_fallback = Some(EntityBuilder::build_unknown(
                                EntityType::EntityType(ENTITY_NAMESPACE.name.name()),
                            ));

                            match (&resource_attrs.api_group, &resource_attrs.resource) {
                                (
                                    StarWildcardStringSelector::Exact(api_group),
                                    CombinedResource::ResourceOnly { resource },
                                )
                                | (
                                    StarWildcardStringSelector::Exact(api_group),
                                    CombinedResource::ResourceSubresource { resource, .. },
                                ) => {
                                    // TODO: What if we are backed by multiple clusters that can have varying discovery info?
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
    ) -> Result<DetailedDecision, AuthorizerError> {
        // Check both typed and untyped actions, if applicable.
        // There is a typed action only if
        // a) the action is get, list, watch, create, update, patch, delete, deletecollection, and
        // b) the resource refers to a resource type in the schema.

        let principal_entity = self.construct_principal(attrs)?;
        let resource_entity = self.construct_untyped_resource(attrs)?;

        let action_entity = if resource_entity
            .uid()
            .to_string()
            .starts_with("k8s::nonresource::")
        {
            format!(r#"k8s::nonresource::Action::"{action}""#).parse()?
        } else {
            format!(r#"k8s::Action::"{action}""#).parse()?
        };

        let untyped_req = PartialRequest::new(
            principal_entity.uid().clone().into(),
            action_entity,
            resource_entity.uid().clone().into(),
            None,
            self.policies.schema().as_ref(),
        )?;

        // Collect all entities into a single map; a chained iterator does not work, as
        // that could yield duplicate entities (e.g. for namespace across ServiceAccount and k8s::Resource).
        let mut deduplicated_entities = principal_entity.consume_entities();
        deduplicated_entities.extend(resource_entity.consume_entities());
        let entities = PartialEntities::from_entities(
            deduplicated_entities.into_iter(),
            self.policies.schema().as_ref(),
        )?;

        let untyped_resp = self.policies.tpe(&untyped_req, &entities)?;

        Ok(match untyped_resp.decision()? {
            DetailedDecision::Allow(permitted_policy_ids) => {
                DetailedDecision::Allow(permitted_policy_ids)
            }
            // For the untyped case, the parts that may be conditional, are actually known, but just kept unknown, as they can have any value.
            // Thus, if we get a conditional decision for an untyped request, there is some condition on "any value", which thus must evaluate to false.
            // TODO: Rejecting allow rules is easy, but rejecting deny rules for this reason seems dangerous?
            DetailedDecision::Conditional(_) => DetailedDecision::NoOpinion,
            DetailedDecision::Deny(forbidden_policy_ids) => {
                DetailedDecision::Deny(forbidden_policy_ids)
            }
            DetailedDecision::NoOpinion => DetailedDecision::NoOpinion,
        })
    }
}

impl<'a, S: KubeStore<corev1::Namespace>, G: KubeApiGroup, D: KubeDiscovery<G>> KubernetesAuthorizer
    for CedarKubeAuthorizer<'a, S, G, D>
{
    fn is_authorized(&self, mut attrs: Attributes) -> Result<Response, AuthorizerError> {
        // Check that verb is supported in schema
        // If * => check with every action in schema in subroutine

        let k8s_ns = self
            .policies
            .schema()
            .get_namespace(&K8S_NS)
            .ok_or(AuthorizerError::NoKubernetesNamespace)?;

        let verb_str = attrs.verb.to_string();
        if !k8s_ns.actions.contains_key(verb_str.as_str()) {
            return Err(AuthorizerError::UnsupportedVerb(verb_str));
        }

        // Populate the resource attributes from the field selectors, if present.
        match &mut attrs.request_type {
            RequestType::Resource(resource_attrs) => {
                default_from_selectors(resource_attrs)?;
            }
            RequestType::NonResource(_) => (),
        }

        match attrs.verb {
            Verb::Any => {
                let errors = Vec::new();
                let mut allowed_ids = HashSet::new();
                // TODO: Check the * action first, then others.
                for (action, _) in k8s_ns.actions.iter() {
                    println!("action: {action}");

                    let resp = self.is_authorized_for_action(&attrs, action.as_str())?;
                    // TODO: Propagate errors?

                    match resp {
                        DetailedDecision::Allow(permitted_policy_ids) => {
                            allowed_ids.extend(permitted_policy_ids.into_iter())
                        }
                        DetailedDecision::Conditional(conditions) => {
                            return Ok(Response::no_opinion().with_errors(errors).with_reason(
                                Reason::not_unconditionally_allowed(action, &conditions),
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
                match self.is_authorized_for_action(&attrs, &action_str)? {
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
                        Ok(Response::conditional(conditional_policies))
                    }
                    DetailedDecision::NoOpinion => Ok(Response::no_opinion()
                        .with_reason(Reason::no_allow_policy_match(&action_str))),
                }
            }
        }
    }
}

// TODO: Should we validate to only allow only field selectors for specific verbs?
// TODO: The more generic solution here is to allow multiple values for a field selector,
// get a residual, and use the SAT/SMT/symbolic compiler method to make sure that all possible values
// are authorized.
fn default_from_selectors(built_resource_attrs: &mut ResourceAttributes) -> Result<(), ParseError> {
    if let Some(field_selectors) = &built_resource_attrs.field_selector {
        for field_selector in field_selectors {
            match field_selector.key.as_str() {
                // Populate the name field from the field selector, if present, like Kubernetes does.
                "metadata.name" => {
                    match (&built_resource_attrs.name, field_selector.exact_match()) {
                        // Fold the field selector value into the spec requirement, just like Kubernetes RequestInfo code does.
                        (EmptyWildcardStringSelector::Any, Some(fieldselector_name)) => {
                            built_resource_attrs.name =
                                EmptyWildcardStringSelector::Exact(fieldselector_name);
                        }
                        // No requirements, nothing to do.
                        (EmptyWildcardStringSelector::Any, None) => (),
                        // If name is specified both in the SAR spec and in the field selector, they must match.
                        (
                            EmptyWildcardStringSelector::Exact(spec_name),
                            Some(fieldselector_name),
                        ) => {
                            if spec_name.as_str() != fieldselector_name {
                                return Err(ParseError::InvalidFieldSelectorRequirement(format!("if metadata.name is specified both on the SubjectAccessReview spec ({spec_name}) and in the field selector ({fieldselector_name}), they must match")));
                            }
                        }
                        // This is the usual case, name is specified in the SAR spec, but no field selector is present.
                        (EmptyWildcardStringSelector::Exact(_), None) => (),
                    }
                }
                // Populate the namespace field from the field selector in the similar manner, however, UNLIKE Kubernetes.
                // We here choose to be consistent with the way we populate the name field, and not Kubernetes.
                "metadata.namespace" => {
                    match (
                        &built_resource_attrs.namespace,
                        field_selector.exact_match(),
                    ) {
                        // Fold the field selector value into the spec requirement.
                        (EmptyWildcardStringSelector::Any, Some(fieldselector_namespace)) => {
                            built_resource_attrs.namespace =
                                EmptyWildcardStringSelector::Exact(fieldselector_namespace);
                        }
                        // No requirements, nothing to do.
                        (EmptyWildcardStringSelector::Any, None) => (),
                        // If namespace is specified both in the SAR spec and in the field selector, they must match.
                        (
                            EmptyWildcardStringSelector::Exact(spec_namespace),
                            Some(fieldselector_namespace),
                        ) => {
                            if spec_namespace.as_str() != fieldselector_namespace {
                                return Err(ParseError::InvalidFieldSelectorRequirement(format!("if metadata.namespace is specified both on the SubjectAccessReview spec ({spec_namespace}) and in the field selector ({fieldselector_namespace}), they must match")));
                            }
                        }
                        // This is the usual case, namespace is specified in the SAR spec, but no field selector is present.
                        (EmptyWildcardStringSelector::Exact(_), None) => (),
                    }
                }
                _ => (),
            }
        }
    }
    Ok(())
}

// TODO: Translate to connect verbs

mod test {
    #[test]
    fn test_is_authorized() {
        use super::super::kubestore::{TestKubeApiGroup, TestKubeDiscovery, TestKubeStore};
        use crate::k8s_authorizer::test_utils::AttributesBuilder;
        use crate::k8s_authorizer::Selector;
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
        use std::collections::BTreeMap;
        use std::str::FromStr;

        let policies = PolicySet::from_str(include_str!("testfiles/simple.cedar")).unwrap();
        let (schema, _) = Fragment::from_cedarschema_str(
            include_str!("testfiles/simple.cedarschema"),
            Extensions::all_available(),
        )
        .unwrap();

        let namespace_store = TestKubeStore::new(vec![
            corev1::Namespace {
                metadata: metav1::ObjectMeta {
                    name: Some("foo".to_string()),
                    uid: Some("1e00c0eb-ec4c-41a2-bb59-e7dea5b21b50".to_string()),
                    labels: Some(BTreeMap::from([(
                        "serviceaccounts-allowed".to_string(),
                        "true".to_string(),
                    )])),
                    ..Default::default()
                },
                ..Default::default()
            },
            corev1::Namespace {
                metadata: metav1::ObjectMeta {
                    name: Some("bar".to_string()),
                    uid: Some("5a16a27e-f43b-4a07-a0d2-bf111f3d39ef".to_string()),
                    labels: Some(BTreeMap::from([(
                        "serviceaccounts-allowed".to_string(),
                        "false".to_string(),
                    )])),
                    ..Default::default()
                },
                ..Default::default()
            },
        ]);

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

        let schema = super::kube_invariants::Schema::new(schema).unwrap();
        let policies = super::kube_invariants::PolicySet::new(policies.as_ref(), &schema).unwrap();

        let authorizer =
            super::CedarKubeAuthorizer::new(policies, namespace_store, discovery).unwrap();

        // TODO: Fix validation problem with nonresourceurl and any verb.
        let test_cases = vec![
            ("superadmin can do anything on any verb", 
            AttributesBuilder::resource("superadmin", Verb::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("admin can't do anything on any verb, as they are forbidden to get in the supersecret namespace",
            AttributesBuilder::resource("admin", Verb::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("admin can't do anything on the get verb, as they are forbidden to get in the supersecret namespace",
            AttributesBuilder::resource("admin", Verb::Get,
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount can get serviceaccounts in its own namespace",
            AttributesBuilder::resource("system:serviceaccount:foo:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("serviceaccount can get serviceaccounts in its own namespace, but through a field selector",
            AttributesBuilder::resource_and_selectors("system:serviceaccount:foo:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    None,
                    Some(vec![Selector::in_values("metadata.namespace", false, vec!["foo".to_string()])])
                )
                .build(), Response::allow()),
            ("serviceaccount can get serviceaccounts in its own namespace, but not in the supersecret namespace",
            AttributesBuilder::resource("system:serviceaccount:supersecret:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Exact("supersecret".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount can get serviceaccounts in a namespace which does not have the label",
            AttributesBuilder::resource("system:serviceaccount:bar:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "serviceaccounts".to_string() },
                    EmptyWildcardStringSelector::Exact("bar".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("anonymous user can get openapi v2",
            AttributesBuilder::nonresource("system:anonymous", Verb::Get,
                StarWildcardStringSelector::Exact("/openapi/v2".to_string()))
                .build(), Response::allow()),
            ("anonymous user can get openapi v3",
            AttributesBuilder::nonresource("system:anonymous", Verb::Get,
                StarWildcardStringSelector::Exact("/openapi/v3/apps.json".to_string()))
                .build(), Response::allow()),
            ("anonymous user cannot get other paths",
            AttributesBuilder::nonresource("system:anonymous", Verb::Get,
                StarWildcardStringSelector::Exact("/metrics".to_string()))
                .build(), Response::no_opinion()),
            ("anonymous user cannot get any path",
            AttributesBuilder::nonresource("system:anonymous", Verb::Get,
                StarWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("a node can only its own node object",
            AttributesBuilder::resource("system:node:node-1", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "nodes".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Exact("node-1".to_string()))
                .build(), Response::allow()),
            ("a node cannot get other nodes",
            AttributesBuilder::resource("system:node:node-1", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "nodes".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Exact("node-2".to_string()))
                .build(), Response::no_opinion()),
            ("lucas can get pods in the foo namespace",
            AttributesBuilder::resource("lucas", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                    .with_group("lucas")
                .build(), Response::allow()),
            ("lucas should not be able to get pods in all namespaces (no opinion expected, NOT conditional)",
            AttributesBuilder::resource("lucas", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                    .with_group("lucas")
                .build(), Response::no_opinion()),
            ("user should not be able to get resource foo across all API groups when resource.apiGroup='*'",
            AttributesBuilder::resource("explicitwildcardshouldfail", Verb::Get,
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "foo".to_string() },
                    // Note: There is one forbid policy which disallows access to the supersecret namespace, so hence this operates on a dedicated namespace, and not any.
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("user should be able to get resource foo across all API groups when resource.apiGroup is omitted",
            AttributesBuilder::resource("omittedconditionok", Verb::Get,
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "foo".to_string() },
                    // Note: There is one forbid policy which disallows access to the supersecret namespace, so hence this operates on a dedicated namespace, and not any.
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("singleitemwatch can watch pod bar in the foo namespace",
            AttributesBuilder::resource_and_selectors("singleitemwatch", Verb::Watch,
                    StarWildcardStringSelector::Exact("".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    None,
                    Some(vec![
                        Selector::in_values("metadata.namespace", false, vec!["foo".to_string()]),
                        Selector::in_values("metadata.name", false, vec!["bar".to_string()]),
                    ])
                )
                .build(), Response::allow()),
                ("singleitemwatch cannot get pod bar in the foo namespace, as the authorization was only for the watch verb",
                AttributesBuilder::resource_and_selectors("singleitemwatch", Verb::Get,
                        StarWildcardStringSelector::Exact("".to_string()),
                        CombinedResource::ResourceOnly { resource: "pods".to_string() },
                        EmptyWildcardStringSelector::Any,
                        EmptyWildcardStringSelector::Any,
                        None,
                        Some(vec![
                            Selector::in_values("metadata.namespace", false, vec!["foo".to_string()]),
                            Selector::in_values("metadata.name", false, vec!["bar".to_string()]),
                        ])
                    )
                    .build(), Response::no_opinion()),
        ];

        for (description, attrs, expected_resp) in test_cases {
            println!("{description}");
            let resp = authorizer.is_authorized_response(attrs);
            assert_eq!(
                expected_resp.decision, resp.decision,
                "got {} with reason: {}, errors: {:?}",
                resp.decision, resp.reason, resp.errors
            );
        }
    }
}

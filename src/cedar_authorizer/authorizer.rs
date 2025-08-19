use cedar_policy_core::validator::json_schema::{CommonTypeId, NamespaceDefinition};
use cedar_policy_core::validator::{json_schema, RawName};
use k8s_openapi::api::core::v1 as corev1;
use kube::core::GroupVersion;
use kube::{self, Resource};
use kube::runtime::reflector;
use smol_str::SmolStr;
use std::collections::HashSet;
use std::sync::LazyLock;

use cedar_policy_core::tpe::entities::PartialEntities;
use cedar_policy_core::tpe::request::PartialRequest;

use cedar_policy_core::ast::{Annotation, AnyId, EntityType, Id, InternalName, Name, UnreservedId};

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
    PRINCIPAL_UNAUTHENTICATEDUSER, PRINCIPAL_USER, RESOURCE_NONRESOURCEURL, RESOURCE_RESOURCE, ENTITY_OBJECTMETA,
};
use kube::discovery::Scope;

use cedar_policy_core::ast;

use super::entitybuilder::{BuiltEntity, EntityBuilder, RecordBuilderImpl, RecordBuilder};
use super::kube_invariants::SchemaError;
use super::kubestore::{KubeApiGroup, KubeDiscovery, KubeStore};

const API_GROUP_ANNOTATION: LazyLock<AnyId> = LazyLock::new(|| "apiGroup".parse().unwrap());

// TODO: When the k8s API server turns an update or patch into a create; it uses the authorizer to check whether the
// create is allowed (unconditionally). It means that for a patch that is turned into a create:
// 1. There is a SAR "can principal P patch resource R?"
// 2. There is another SAR "can principal P create resource R?"
// 3. There is an admission request of "can principal P create this specific resource R?"
// If the step 1 is conditional, then step 3 will enforce the condition. But in order for step 2 to succeed as well
// (for a Cedar policy "principal can create or patch resource R when spec.foo=bar"), we need to carry the context from the
// authorizer to the admission controller from step 2 to 3 as well.
// Apparently, e.g. RBAC objects, RuntimeClasses, and some similar, set Strategy.AllowCreateOnUpdate==true. Test this out in practice.

// TODO: The webhook authorizer change for k8s upstream must use some context value to know whether the caller is capable of
// enforcing the condition being returned. In other words, as the authorizer is used in multiple places, make sure that we don't
// fold a "conditional" into an "allow", if the authorization caller cannot handle the special "conditional" responses.

// TODO: It is possible to change metadata using a status subresource for some core APIs like Services, see
// https://github.com/kubernetes/kubernetes/issues/45539. In this project, we could potentially (and optionally) tighten this
// through a forbid rule that only allows some specific actors (like well-known core controllers) to change metadata.

// TODO: Disallow usage of "is k8s::Resource", such that we do not need to do authorization requests separately for "untyped" and "typed" variants?
//   If we make it such that (given you restrict the verb to some resource verb) you MUST keep the policy open to all typed variants, then
//   we probably have an easier time analyzing as well who has access to some given resource, and we don't need rewrites from untyped -> typed worlds.
pub struct CedarKubeAuthorizer<S: KubeStore<corev1::Namespace>> {
    policies: kube_invariants::PolicySet,
    namespaces: S,
    // k8s_ns: &'a NamespaceDefinition<RawName>,
}

impl<S: KubeStore<corev1::Namespace>>
    CedarKubeAuthorizer<S>
{
    // TODO: Add possibility to dynamically update the schema and policies later as well.
    pub fn new(
        policies: kube_invariants::PolicySet,
        namespaces: S,
    ) -> Result<Self, SchemaError> {
        Ok(Self {
            policies,
            namespaces,
        })
    }

    fn construct_principal(&self, attrs: &Attributes) -> Result<BuiltEntity, AuthorizerError> {
        // If the principal is any, it must match any user and use partial evaluation.
        if attrs.user.is_any_principal() {
            return Ok(EntityBuilder::new().build(PRINCIPAL_UNAUTHENTICATEDUSER.name.name()));
        }

        let mut entity_builder: EntityBuilder = EntityBuilder::new()
            .with_attr("username", Some(attrs.user.name.as_str()))
            .with_string_set("groups", Some(attrs.user.groups.iter().map(|s| s.as_str())))
            .with_attr(
                "uid",
                attrs
                    .user
                    .uid
                    .as_ref()
                    .map(|uid| uid.as_str()),
            )
            .with_string_to_stringset_map("extra", Some(&attrs.user.extra));

        let mut principal_type = PRINCIPAL_USER.name.name();

        if let Some(sa_nsname_str) = attrs.user.name.strip_prefix("system:serviceaccount:") {
            let parts: Vec<&str> = sa_nsname_str.split(':').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Err(AuthorizerError::InvalidPrincipal(
                    attrs.user.name.clone(),
                    "expected format: 'system:serviceaccount:<namespace>:<name>'".to_string(),
                ));
            }

            entity_builder.add_attr("serviceAccountNamespace", Some(parts[0]));
            entity_builder.add_attr("serviceAccountName", Some(parts[1]));

            principal_type = PRINCIPAL_SERVICEACCOUNT.name.name();
        } else if let Some(nodename) = attrs.user.name.strip_prefix("system:node:") {
            if nodename.is_empty() {
                return Err(AuthorizerError::InvalidPrincipal(
                    attrs.user.name.clone(),
                    "expected format: 'system:node:<name>'".to_string(),
                ));
            }
            principal_type = PRINCIPAL_NODE.name.name();
            // TODO: Add some validation here
            entity_builder.add_attr("nodeName", Some(nodename));
        }

        Ok(entity_builder.build(principal_type))
    }

    fn namespace_entity(&self, ns_name: &str) -> Result<BuiltEntity, AuthorizerError> {
        let stored_ns = self
            .namespaces
            .get(&reflector::ObjectRef::new(ns_name));
        let stored_ns_metadata = stored_ns.as_ref().map(|ns| &ns.metadata);
        
        Ok(EntityBuilder::new()
            // Note: resource.namespace.name is populated (if non-wildcard), although the namespace
            // does not exist in Kubernetes, and thus no metadata is available (left unknown).
            .with_attr("name", Some(ns_name))
            // TODO: Should this entity also have a deterministic UID; as 
            .with_metadata(match stored_ns_metadata {
                Some(ns_metadata) => Some(ns_metadata),
                None => None,
                })
            .build(ENTITY_NAMESPACE.name.name()))
    }

    fn construct_resource(
        &self,
        attrs: &Attributes,
    ) -> Result<(BuiltEntity, bool), AuthorizerError> {
        match &attrs.request_type {
            RequestType::NonResource(nonresource_attrs) => Ok((
                EntityBuilder::new()
                    .with_attr(
                        "path",
                        Some(EntityBuilder::unknown_string(
                            match nonresource_attrs.path {
                                StarWildcardStringSelector::Any => None,
                                _ => Some(nonresource_attrs.path.to_string()),
                            },
                        )),
                    )
                    .build(RESOURCE_NONRESOURCEURL.name.name()),
                false,
            )),
            RequestType::Resource(resource_attrs) => {
                let mut resource_builder = EntityBuilder::new()
                    .with_attr(
                        "apiGroup",
                        Some(EntityBuilder::unknown_string(
                            match resource_attrs.api_group {
                                StarWildcardStringSelector::Any => None,
                                _ => Some(resource_attrs.api_group.to_string()),
                            },
                        )),
                    )
                    .with_attr(
                        "name",
                        Some(EntityBuilder::unknown_string(match resource_attrs.name {
                            EmptyWildcardStringSelector::Any => None,
                            _ => Some(resource_attrs.name.to_string()),
                        })),
                    )
                    .with_attr(
                        "resourceCombined",
                        Some(EntityBuilder::unknown_string(
                            match resource_attrs.resource {
                                CombinedResource::Any => None,
                                _ => Some(resource_attrs.resource.to_string()),
                            },
                        )),
                    );

                match (&resource_attrs.api_group, &resource_attrs.resource) {
                    (
                        StarWildcardStringSelector::Exact(api_group),
                        CombinedResource::ResourceOnly { resource },
                    )
                    | (
                        StarWildcardStringSelector::Exact(api_group),
                        CombinedResource::ResourceSubresource { resource, .. },
                    ) => match self
                        .find_schema_entity_for_api_group_and_resource(api_group, resource)
                    {
                        Some(( resource_type_namespace_name, resource_type_namespace, typed_resource_entity_id, resource_type)) => {
                            let record = entity_to_record(&resource_type)?;
                            resource_builder.add_attr(
                                "namespace",
                                match &resource_attrs.namespace {
                                    EmptyWildcardStringSelector::Any => {
                                        match record.attributes.contains_key("namespace") {
                                            // An unset namespace for a namespaced resource means "any".
                                            true => Some(EntityBuilder::build_unknown(
                                                ENTITY_NAMESPACE.name.name(),
                                            )),
                                            // An unset namespace for a cluster-scoped resource means "none".
                                            false => None,
                                        }
                                    }
                                    EmptyWildcardStringSelector::Exact(ns_name) => {
                                        Some(self.namespace_entity(ns_name.as_str())?)
                                    }
                                },
                            );

                            // TODO: Enforce all these invariants early on, instead of here (late).
                            // In that case, we can guard against ever starting to consider a faulty schema and 
                            // thus failing all authz requests.
                            let kind = resource_type.annotations.0.get(&"kind".parse().unwrap()).into_iter().flatten().map(|a| a.val.clone()).next().ok_or_else(||AuthorizerError::UnexpectedSchemaShape("schema should have kind annotation registered at GVR resource entity".to_string()))?;
                            
                            match &resource_attrs.api_version {
                                StarWildcardStringSelector::Exact(api_version) => {
                                    let api_group_version: SmolStr = GroupVersion::gv(&api_group, api_version).api_version().into();
                                    resource_builder.add_attr(
                                        "request",
                                        match record.attributes.get("request") {
                                            Some(_) => match attrs.verb {
                                                // In authorization, keep resource.request unknown for the verbs which
                                                // carry request data.
                                                Verb::Create
                                                | Verb::Update
                                                | Verb::Patch
                                                | Verb::Connect => {
                                                    let versioned_record = resource_type_namespace.common_types.get(&CommonTypeId::new(format!("Versioned{kind}").parse::<UnreservedId>().unwrap()).unwrap())
                                                    .ok_or_else(|| AuthorizerError::UnexpectedSchemaShape("schema should have common type registered at GVR resource entity".to_string()))?;
                                                    let versioned_record = type_to_record(&versioned_record.ty)?;
                                                    let specific_version_attr = versioned_record.attributes.get(api_version.as_str());

                                                    Some(RecordBuilderImpl::new()
                                                    .with_attr("apiVersion", Some(api_group_version.clone()))
                                                    .with_attr("kind", Some(kind.clone()))
                                                    // Only expose the metadata field if there a) the apiVersion is an exact match, and b) the given apiVersion exists in the schema.
                                                    .with_attr("metadata", match specific_version_attr {
                                                        Some(_) => Some(EntityBuilder::build_unknown(ENTITY_OBJECTMETA.name.name())),
                                                        None => None,
                                                    })
                                                    .with_attr(api_version.as_str(), match specific_version_attr {
                                                        Some(_) => Some(EntityBuilder::build_unknown(format!("{}{}", &crate::util::title_case(&api_version), &kind).parse::<Name>().unwrap().qualify_with_name(resource_type_namespace_name.as_ref()))),
                                                        None => None
                                                    }))
                                                }
                                                // For verbs that do not carry request data, make "resource has request" return false.
                                                _ => None,
                                            },
                                            // If the type does not have a request, ok, don't add anything.
                                            None => None,
                                        },
                                    );
        
                                    resource_builder.add_attr(
                                        "stored",
                                        match record.attributes.get("stored") {
                                            Some(_) => match attrs.verb {
                                                // In authorization, keep resource.request unknown for the verbs which
                                                // carry request data.
                                                // TODO: Do we get any stored data for connect verbs?
                                                // TODO: Should we allow arbitrary verbs to operate conditionally?
                                                // TODO: Actually make this known, and populate the apiVersion & kind fields
                                                // Keep metadata unknown, but also only populate one of the versioned fields.
                                                Verb::Get
                                                | Verb::List
                                                | Verb::Watch
                                                | Verb::Update
                                                | Verb::Patch
                                                | Verb::Delete
                                                | Verb::DeleteCollection => {
                                                    let versioned_record = resource_type_namespace.common_types.get(&CommonTypeId::new(format!("Versioned{kind}").parse::<UnreservedId>().unwrap()).unwrap())
                                                    .ok_or_else(|| AuthorizerError::UnexpectedSchemaShape("schema should have common type registered at GVR resource entity".to_string()))?;
                                                    let versioned_record = type_to_record(&versioned_record.ty)?;
                                                    let specific_version_attr = versioned_record.attributes.get(api_version.as_str());

                                                    Some(RecordBuilderImpl::new()
                                                    .with_attr("apiVersion", Some(api_group_version.clone()))
                                                    .with_attr("kind", Some(kind.clone()))
                                                    // Only expose the metadata field if there a) the apiVersion is an exact match, and b) the given apiVersion exists in the schema.
                                                    .with_attr("metadata", match specific_version_attr {
                                                        Some(_) => Some(EntityBuilder::build_unknown(ENTITY_OBJECTMETA.name.name())),
                                                        None => None,
                                                    })
                                                    .with_attr(api_version.as_str(), match specific_version_attr {
                                                        Some(_) => Some(EntityBuilder::build_unknown(format!("{}{}", &crate::util::title_case(&api_version), &kind).parse::<Name>().unwrap().qualify_with_name(resource_type_namespace_name.as_ref()))),
                                                        None => None
                                                    }))
                                                }
                                                // For verbs that do not carry request data, make "resource has request" return false.
                                                _ => None,
                                            },
                                            // If the type does not have a stored value, ok, don't add anything.
                                            None => None,
                                        },
                                    );
                                }
                                // If the apiVersion is an any match, resource.stored and resource.request are nil, but unlike
                                // the untyped case (k8s::Resource), the specific resource entity type is used (e.g. core::pods)
                                StarWildcardStringSelector::Any => (),
                            }

                            Ok((resource_builder.build(Name::unqualified_name(typed_resource_entity_id).qualify_with_name(resource_type_namespace_name.as_ref())), true))
                        }
                        // Untyped k8s::Resource case, due to to the resource requested not being in the schema,
                        // e.g. due to discovery not being up to date, or the requested resource begin "virtual".
                        None => {
                            self.finish_building_untyped_resource(resource_builder, resource_attrs)
                        }
                    },
                    // Untyped k8s::Resource case, due to multiple possible resource type matches.
                    _ => self.finish_building_untyped_resource(resource_builder, resource_attrs),
                }
            }
        }
    }

    fn finish_building_untyped_resource(
        &self,
        resource_builder: EntityBuilder,
        resource_attrs: &ResourceAttributes,
    ) -> Result<(BuiltEntity, bool), AuthorizerError> {
        Ok((
            resource_builder
                .with_attr(
                    "namespace",
                    match &resource_attrs.namespace {
                        // Here we must assume that the namespace is "any",
                        // as we're arbitrarily selecting across a (possibly infinite) set of k8s resource types.
                        // However, in theory all matched resources could be cluster-scoped (imagine apiGroup="foo" and resource="*"),
                        // where all resources in apiGroup="foo" are cluster-scoped. If so, it would be better to make "resource has namespace"
                        // queries return "false", but this we cannot know, we lose a little bit of precision here.
                        // TODO: Create a Cedar issue to discuss whether "foo has bar" should be able to be unknown, which is what we want here.
                        EmptyWildcardStringSelector::Any => {
                            Some(EntityBuilder::build_unknown(ENTITY_NAMESPACE.name.name()))
                        }
                        EmptyWildcardStringSelector::Exact(ns_name) => {
                            Some(self.namespace_entity(ns_name.as_str())?)
                        }
                    },
                )
                .build(RESOURCE_RESOURCE.name.name()),
            false,
        ))
    }

    fn find_schema_entity_for_api_group_and_resource<'a>(
        &'a self,
        api_group: &str,
        resource: &str,
    ) -> Option<(&'a Option<Name>, &'a NamespaceDefinition<RawName>, UnreservedId, &'a json_schema::EntityType<RawName>)> {

        let (ns_name, ns) = self.policies.schema_ref().get_fragment().0.iter().find(|(_, entity)| {
            match entity.annotations.0.get(&API_GROUP_ANNOTATION) {
                Some(api_group_annotation) => match api_group_annotation {
                    Some(Annotation { val, .. }) => val.as_str() == api_group,
                    None => false,
                },
                None => false,
            }
        })?;

        // TODO: If unwrap is used, at least replace them all with an expect.
        let resource_cedar_compatible_name = resource.replace("/", "_").parse::<UnreservedId>().unwrap();
        ns.entity_types
            .get(&resource_cedar_compatible_name)
            .map(| entity_type| {
                (
                    ns_name,
                    ns,
                    resource_cedar_compatible_name,
                    entity_type,
                )
            })
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

        // TODO: Unit-test the construct_principal/resource functions.
        let principal_entity = self.construct_principal(attrs)?;
        // TODO: Derive typed_resource from the uid of the built entity.
        let (resource_entity, typed_resource) = self.construct_resource(attrs)?;

        let action_entity = if resource_entity
            .uid()
            .to_string()
            .starts_with("k8s::nonresource::")
        {
            format!(r#"k8s::nonresource::Action::"{action}""#).parse()?
        } else {
            format!(r#"k8s::Action::"{action}""#).parse()?
        };

        let req = PartialRequest::new(
            principal_entity.uid().clone().into(),
            action_entity,
            resource_entity.uid().clone().into(),
            None,
            self.policies.schema().as_ref().as_ref(),
        )?;

        
        let (principal_entities, principal_jsonpaths) = principal_entity.into_parts("principal");
        let (resource_entities, resource_jsonpaths) = resource_entity.into_parts("resource");

        // Note: There must be no duplicate UIDs in the entities, as we do not deduplicate them.
        // As of writing, no such duplicate entities between principal and resource is known.
        let entities = PartialEntities::from_entities(
            principal_entities.into_iter().chain(resource_entities.into_iter()),
            self.policies.schema().as_ref().as_ref(),
        )?;

        let untyped_resp = self.policies.tpe(&req, &entities)?;

        Ok(match untyped_resp.decision()? {
            DetailedDecision::Allow(permitted_policy_ids) => {
                DetailedDecision::Allow(permitted_policy_ids)
            }
            // For the untyped case, the parts that may be conditional, are actually known, but just kept unknown, as they can have any value.
            // Thus, if we get a conditional decision for an untyped request, there is some condition on "any value", which thus must evaluate to false.
            // TODO: Rejecting allow rules is easy, but rejecting deny rules for this reason seems dangerous?
            DetailedDecision::Conditional(condition, unknown_jsonpaths_to_uid) => {
                if typed_resource {
                    DetailedDecision::Conditional(condition, unknown_jsonpaths_to_uid.into_iter()
                        .chain(principal_jsonpaths.into_iter())
                        .chain(resource_jsonpaths.into_iter())
                        .collect())
                } else {
                    DetailedDecision::NoOpinion
                }
            }
            DetailedDecision::Deny(forbidden_policy_ids) => {
                DetailedDecision::Deny(forbidden_policy_ids)
            }
            DetailedDecision::NoOpinion => DetailedDecision::NoOpinion,
        })
    }
}

impl<S: KubeStore<corev1::Namespace>> KubernetesAuthorizer
    for CedarKubeAuthorizer<S>
{
    fn is_authorized(&self, mut attrs: Attributes) -> Result<Response, AuthorizerError> {
        // Check that verb is supported in schema
        // If * => check with every action in schema in subroutine

        let schema = self.policies.schema();
        let k8s_ns = schema
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

                    let resp = self.is_authorized_for_action(&attrs, action.as_str())?;
                    // TODO: Propagate errors?

                    match resp {
                        DetailedDecision::Allow(permitted_policy_ids) => {
                            allowed_ids.extend(permitted_policy_ids.into_iter())
                        }
                        DetailedDecision::Conditional(conditions, _) => {
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
                    DetailedDecision::Conditional(conditional_policies, unknown_jsonpaths_to_uid) => {
                        Ok(Response::conditional(conditional_policies, unknown_jsonpaths_to_uid))
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

// TODO: This should be upstreamed to cedar-policy-core.
/*fn namespace_of_name(name: &Name) -> Option<Name> {
    let internal_name = name.as_ref();
    match internal_name.namespace().as_str() {
        "" => None,
        namespace => Some(namespace.parse().unwrap()),
    }
}*/

// TODO: Translate to connect verbs

fn entity_to_record(
    entity: &json_schema::EntityType<RawName>,
) -> Result<&json_schema::RecordType<RawName>, AuthorizerError> {
    match &entity.kind {
        json_schema::EntityTypeKind::Standard(standard_type) => type_to_record(&standard_type.shape.0),
        _ => Err(AuthorizerError::UnexpectedSchemaShape(format!(
            "Expected record type, got {entity:?}"
        ))),
    }
}

fn type_to_record(ty: &json_schema::Type<RawName>) -> Result<&json_schema::RecordType<RawName>, AuthorizerError> {
    match ty {
        json_schema::Type::Type { ty, .. } => match ty {
            json_schema::TypeVariant::Record(record) => Ok(record),
            _ => Err(AuthorizerError::UnexpectedSchemaShape(format!(
                "Expected record type, got {ty:?}"
            ))),
        },
        _ => Err(AuthorizerError::UnexpectedSchemaShape(format!(
            "Expected record type, got {ty:?}"
        ))),
    }
}

/*fn entity_ref_of_type(
    main_ty: &json_schema::Type<RawName>,
    relevant_namespace: Option<&Name>,
) -> Result<InternalName, AuthorizerError> {
    let raw_name = match main_ty {
        json_schema::Type::Type { ty, .. } => match ty {
            json_schema::TypeVariant::Entity { name } => name.clone(),
            json_schema::TypeVariant::EntityOrCommon { type_name } => type_name.clone(),
            _ => {
                return Err(AuthorizerError::UnexpectedSchemaShape(format!(
                    "Expected entity reference, got {main_ty}"
                )))
            }
        },
        _ => {
            return Err(AuthorizerError::UnexpectedSchemaShape(format!(
                "Expected entity reference, got {main_ty}"
            )))
        }
    };
    Ok(raw_name.qualify_with_name(relevant_namespace))
}*/

mod test {
    use std::sync::Arc;

    use crate::cedar_authorizer::kube_invariants;

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
        use std::collections::{BTreeMap, HashMap};
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

        let schema = super::kube_invariants::Schema::new(schema).unwrap();
        let policies =
            super::kube_invariants::PolicySet::new(policies.as_ref(), Arc::new(schema.clone()))
                .unwrap();

        let authorizer =
            super::CedarKubeAuthorizer::new(policies, namespace_store).unwrap();

        // TODO: Fix validation problem with nonresourceurl and any verb.
        let test_cases = vec![
            ("superadmin can do anything on any verb", 
            AttributesBuilder::resource("superadmin", Verb::Any,
                    StarWildcardStringSelector::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("admin can't do anything on any verb, as they are forbidden to get in the supersecret namespace",
            AttributesBuilder::resource("admin", Verb::Any,
                    StarWildcardStringSelector::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("admin can't do anything on the get verb, as they are forbidden to get in the supersecret namespace",
            AttributesBuilder::resource("admin", Verb::Get,
                    StarWildcardStringSelector::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount can get pods in its own namespace",
            AttributesBuilder::resource("system:serviceaccount:foo:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("serviceaccount can get pods in its own namespace, but through a field selector",
            AttributesBuilder::resource_and_selectors("system:serviceaccount:foo:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    None,
                    Some(vec![Selector::in_values("metadata.namespace", false, vec!["foo".to_string()])])
                )
                .build(), Response::allow()),
            ("serviceaccount can get pods in its own namespace, but not in the supersecret namespace",
            AttributesBuilder::resource("system:serviceaccount:supersecret:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("supersecret".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount can get pods in a namespace which does not have the label",
            AttributesBuilder::resource("system:serviceaccount:bar:bar", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("bar".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount can conditionally get pods in a namespace which is not in the storage",
            AttributesBuilder::resource("system:serviceaccount:baz:baz", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("baz".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::conditional(kube_invariants::PolicySet::from_str(r#"permit(
    principal,
    action,
    resource
) when {
(((meta::V1ObjectMeta::"0610f71c-7aab-4153-a235-afe4280a59f5"["labels"]).hasTag("serviceaccounts-allowed")) && (((meta::V1ObjectMeta::"0610f71c-7aab-4153-a235-afe4280a59f5"["labels"]).getTag("serviceaccounts-allowed")) == "true"))
};"#, Arc::new(schema.clone())).unwrap(), HashMap::from([
    ("resource.name".to_string(), r#"meta::UnknownString::"222fa568-eb07-411c-a6ff-b6eab75392dc""#.parse().unwrap()),
    ("resource.namespace.metadata".to_string(), r#"meta::V1ObjectMeta::"0610f71c-7aab-4153-a235-afe4280a59f5""#.parse().unwrap()),
    ("resource.stored.v1".to_string(), r#"core::V1Pod::"03600274-f607-4061-8080-fb1f7adc63a4""#.parse().unwrap()),
    ("resource.stored.metadata".to_string(), r#"meta::V1ObjectMeta::"9c869675-8159-4f4d-b8c0-2173efe8142b""#.parse().unwrap()),
]))),
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
            ("a node can only get its own node object",
            AttributesBuilder::resource("system:node:node-1", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "nodes".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Exact("node-1".to_string()))
                .build(), Response::allow()),
            ("a node cannot get other nodes",
            AttributesBuilder::resource("system:node:node-1", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "nodes".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Exact("node-2".to_string()))
                .build(), Response::no_opinion()),
            ("a node can get pods in the foo namespace",
            AttributesBuilder::resource("system:node:node-1", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Exact("pod-abc".to_string()))
                .build(), Response::conditional(kube_invariants::PolicySet::from_str(r#"permit(
  principal,
  action,
  resource
) when {
  ((core::V1Pod::"80f44bb4-96d6-46bb-8c3e-ca5c797a04e8" has "spec") && ((((core::V1Pod::"80f44bb4-96d6-46bb-8c3e-ca5c797a04e8")["spec"])["nodeName"]) == "node-1"))
};"#, Arc::new(schema.clone())).unwrap(), HashMap::from([
    ("resource.stored.v1".to_string(), r#"core::V1Pod::"80f44bb4-96d6-46bb-8c3e-ca5c797a04e8""#.parse().unwrap()),
    ("resource.stored.metadata".to_string(), r#"meta::V1ObjectMeta::"b7b65842-3d3a-48a8-8239-0f48010c1867""#.parse().unwrap()),
]))),
            ("lucas can get pods in the notinstorage namespace",
            AttributesBuilder::resource("lucas", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("notinstorage".to_string()),
                    EmptyWildcardStringSelector::Any)
                    .with_group("lucas")
                .build(), Response::allow()),
            ("lucas should not be able to get pods in all namespaces (no opinion expected, NOT conditional)",
            AttributesBuilder::resource("lucas", Verb::Get,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
                    CombinedResource::Any,
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any)
                    .with_group("lucas")
                .build(), Response::no_opinion()),
            ("user should not be able to get resource foo across all API groups when resource.apiGroup='*'",
            AttributesBuilder::resource("explicitwildcardshouldfail", Verb::Get,
                    StarWildcardStringSelector::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "foo".to_string() },
                    // Note: There is one forbid policy which disallows access to the supersecret namespace, so hence this operates on a dedicated namespace, and not any.
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("user should be able to get resource foo across all API groups when resource.apiGroup is omitted",
            AttributesBuilder::resource("omittedconditionok", Verb::Get,
                    StarWildcardStringSelector::Any,
                    StarWildcardStringSelector::Any,
                    CombinedResource::ResourceOnly { resource: "foo".to_string() },
                    // Note: There is one forbid policy which disallows access to the supersecret namespace, so hence this operates on a dedicated namespace, and not any.
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::allow()),
            ("singleitemwatch can watch pod bar in the foo namespace",
            AttributesBuilder::resource_and_selectors("singleitemwatch", Verb::Watch,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Any,
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
                        StarWildcardStringSelector::Any,
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

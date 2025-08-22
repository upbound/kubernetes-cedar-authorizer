use cedar_policy_core::entities::Schema;
use cedar_policy_core::extensions::Extensions;
use cedar_policy_core::validator::json_schema::{
    ActionEntityUID, CommonTypeId, NamespaceDefinition,
};
use cedar_policy_core::validator::{json_schema, RawName, ValidatorSchema};
use cedar_policy_symcc::solver::Solver;
use k8s_openapi::api::core::v1 as corev1;
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::core::GroupVersion;
use kube::runtime::reflector;
use kube::{self};
use smol_str::{SmolStr, ToSmolStr};
use std::collections::HashSet;
use std::sync::LazyLock;

use cedar_policy_core::tpe::entities::{PartialEntities, PartialEntity};
use cedar_policy_core::tpe::request::PartialRequest;

use cedar_policy_core::ast::{self, Annotation, AnyId, Name, UnreservedId};

use crate::cedar_authorizer::entitybuilder::PartialValue;
use crate::cedar_authorizer::kube_invariants::{self};
use crate::cedar_authorizer::kube_invariants::{ActionCapability, DetailedDecision};
use crate::cedar_authorizer::symcc;
use crate::k8s_authorizer::StarWildcardStringSelector;
use crate::k8s_authorizer::{
    Attributes, AuthorizerError, EmptyWildcardStringSelector, KubernetesAuthorizer, ParseError,
    Reason, ResourceAttributes, Response, Verb,
};
use crate::k8s_authorizer::{CombinedResource, RequestType};
use crate::schema::core::{
    ENTITY_NAMESPACE, ENTITY_OBJECTMETA, K8S_NONRESOURCE_NS, K8S_NS, PRINCIPAL_NODE,
    PRINCIPAL_SERVICEACCOUNT, PRINCIPAL_UNAUTHENTICATEDUSER, PRINCIPAL_USER,
    RESOURCE_NONRESOURCEURL, RESOURCE_RESOURCE,
};

use super::entitybuilder::{BuiltEntity, EntityBuilder, RecordBuilder, RecordBuilderImpl};
use super::kube_invariants::SchemaError;
use super::kubestore::KubeStore;

static API_GROUP_ANNOTATION: LazyLock<AnyId> = LazyLock::new(|| "apiGroup".parse().unwrap());

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
pub struct CedarKubeAuthorizer<
    S: KubeStore<corev1::Namespace>,
    F: symcc::SolverFactory<C>,
    C: Solver,
> {
    policies: kube_invariants::PolicySet,
    namespaces: S,
    symcc_evaluator: symcc::SymbolicEvaluator<F, C>,
    // k8s_ns: &'a NamespaceDefinition<RawName>,
}

impl<S: KubeStore<corev1::Namespace>, F: symcc::SolverFactory<C>, C: Solver>
    CedarKubeAuthorizer<S, F, C>
{
    // TODO: Add possibility to dynamically update the schema and policies later as well.
    pub fn new(
        policies: kube_invariants::PolicySet,
        namespaces: S,
        symcc_factory: F,
    ) -> Result<Self, SchemaError> {
        Ok(Self {
            symcc_evaluator: symcc::SymbolicEvaluator::new(policies.schema(), symcc_factory)?,
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
            .with_attr("username", attrs.user.name.to_smolstr())
            .with_attr(
                "groups",
                attrs
                    .user
                    .groups
                    .iter()
                    .map(|s| s.to_smolstr())
                    .collect::<HashSet<_>>(),
            )
            .with_attr("uid", attrs.user.uid.as_ref())
            .with_attr("extra", attrs.user.extra.clone());

        let mut principal_type = PRINCIPAL_USER.name.name();

        if let Some(sa_nsname_str) = attrs.user.name.strip_prefix("system:serviceaccount:") {
            let parts: Vec<&str> = sa_nsname_str.split(':').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Err(AuthorizerError::InvalidPrincipal(
                    attrs.user.name.clone(),
                    "expected format: 'system:serviceaccount:<namespace>:<name>'".to_string(),
                ));
            }

            entity_builder.add_attr("serviceAccountNamespace", parts[0]);
            entity_builder.add_attr("serviceAccountName", parts[1]);

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
            entity_builder.add_attr("nodeName", nodename);
        }

        Ok(entity_builder.build(principal_type))
    }

    /*fn namespace_entity(&self, ns_name: &str) -> Result<BuiltEntity, AuthorizerError> {
        let stored_ns = self.namespaces.get(&reflector::ObjectRef::new(ns_name));
        let stored_ns_metadata = stored_ns.as_ref().map(|ns| &ns.metadata);

        Ok(EntityBuilder::new()
            // Note: resource.namespace.name is populated (if non-wildcard), although the namespace
            // does not exist in Kubernetes, and thus no metadata is available (left unknown).
            .with_attr("name", ns_name)
            .with_attr(
                "metadata",
                match stored_ns_metadata {
                    Some(ns_metadata) => PartialValue::Known(ns_metadata),
                    None => PartialValue::Unknown,
                },
            )
            .build(ENTITY_NAMESPACE.name.name()))
    }*/

    fn construct_resource(
        &self,
        attrs: &Attributes,
        action_capability: &ActionCapability,
    ) -> Result<(BuiltEntity, Option<bool>), AuthorizerError> {
        match &attrs.request_type {
            RequestType::NonResource(nonresource_attrs) => Ok((
                EntityBuilder::new()
                    .with_attr(
                        "path",
                        match nonresource_attrs.path {
                            StarWildcardStringSelector::Any => PartialValue::Unknown,
                            _ => {
                                PartialValue::Known(nonresource_attrs.path.to_string().to_smolstr())
                            }
                        },
                    )
                    .build(RESOURCE_NONRESOURCEURL.name.name()),
                None,
            )),
            RequestType::Resource(resource_attrs) => {
                let mut resource_builder = EntityBuilder::new()
                    .with_attr(
                        "apiGroup",
                        match resource_attrs.api_group {
                            StarWildcardStringSelector::Any => PartialValue::Unknown,
                            _ => PartialValue::Known(
                                resource_attrs.api_group.to_string().to_smolstr(),
                            ),
                        },
                    )
                    .with_attr(
                        "resourceCombined",
                        match resource_attrs.resource {
                            CombinedResource::Any => PartialValue::Unknown,
                            _ => PartialValue::Known(
                                resource_attrs.resource.to_string().to_smolstr(),
                            ),
                        },
                    )
                    .with_attr(
                        "name",
                        match resource_attrs.name {
                            EmptyWildcardStringSelector::Any => PartialValue::Unknown,
                            _ => PartialValue::Known(resource_attrs.name.to_string().to_smolstr()),
                        },
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
                        Some((
                            resource_type_namespace_name,
                            resource_type_namespace,
                            typed_resource_entity_id,
                            resource_type,
                        )) => {
                            let record = entity_to_record(resource_type)?;

                            // Only populate the namespace field if there is such an attribute in the schema.
                            // The namespace is never set for a cluster-scoped resource
                            // If the SAR specifies some exact namespace for a cluster-scoped resource,
                            // the SAR value is ignored. TODO: Check if this is the case also for k8s RBAC.
                            if record.attributes.contains_key("namespace") {
                                resource_builder.add_attr(
                                    "namespace",
                                    match &resource_attrs.namespace {
                                        EmptyWildcardStringSelector::Any => PartialValue::Unknown,
                                        EmptyWildcardStringSelector::Exact(ns_name) => {
                                            PartialValue::Known(ns_name.to_smolstr())
                                        }
                                    },
                                );
                            }

                            // TODO: Enforce all these invariants early on, instead of here (late).
                            // In that case, we can guard against ever starting to consider a faulty schema and
                            // thus failing all authz requests.
                            let kind = resource_type.annotations.0.get(&"kind".parse().unwrap()).into_iter().flatten().map(|a| a.val.clone()).next().ok_or_else(||AuthorizerError::UnexpectedSchemaShape("schema should have kind annotation registered at GVR resource entity".to_string()))?;

                            match &resource_attrs.api_version {
                                StarWildcardStringSelector::Exact(api_version) => {
                                    let api_group_version: SmolStr =
                                        GroupVersion::gv(api_group, api_version)
                                            .api_version()
                                            .into();

                                    // TODO: For now, we only populate the namespace metadata if conditional authorization is supported, in other words,
                                    // only when VAP is enabled. If decisions were computed directly based on namespace metadata (e.g. unconditional allow or deny),
                                    // then authorization would become state-dependent, and return varying results for the same SAR, depending on mutable etcd state.
                                    // In practice, the Node authorizer is state-dependent, but that is a specialized use-case, and we need to be careful to expose such things
                                    // to the policy author in a way that could be confusing. The general idea would be that authorization is stateless, and must return cacheable
                                    // responses, but then the enforcement point (e.g. the API server) is able to allow/deny individual requests based on data in etcd.
                                    // In the future, one could consider adding the ability to operate on namespace metadata for list, watch, deletecollection verbs as well,
                                    // those cannot be supported before the API server is able to enforce conditions for such requests.
                                    // It might also be unintuitive that the precondition on namespace metadata existing, is that the API version is an exact match.
                                    // Given these specific circumstances when this field is available, it is hard to say whether it is more confusing than helpful.
                                    match (
                                        record.attributes.contains_key("namespaceMetadata"),
                                        action_capability.supports_conditional_decision(),
                                    ) {
                                        (true, true) => {
                                            resource_builder.add_attr::<&str, PartialValue<&metav1::ObjectMeta>>("namespaceMetadata", PartialValue::Unknown);
                                        }
                                        (_, _) => (),
                                    }

                                    match (
                                        record.attributes.contains_key("request"),
                                        action_capability.has_request_object(),
                                    ) {
                                        (true, true) => {
                                            let versioned_record = resource_type_namespace.common_types.get(&CommonTypeId::new(format!("Versioned{kind}").parse::<UnreservedId>().unwrap()).unwrap())
                                            .ok_or_else(|| AuthorizerError::UnexpectedSchemaShape("schema should have common type registered at GVR resource entity".to_string()))?;
                                            let versioned_record =
                                                type_to_record(&versioned_record.ty)?;
                                            let specific_version_attr = versioned_record
                                                .attributes
                                                .get(api_version.as_str());
                                            resource_builder.add_attr(
                                                "request",
                                                    RecordBuilderImpl::new()
                                                    .with_attr("apiVersion", Some(api_group_version.clone()))
                                                    .with_attr("kind", Some(kind.clone()))
                                                    // Only expose the metadata field if there a) the apiVersion is an exact match, and b) the given apiVersion exists in the schema.
                                                    .with_attr::<&str, PartialValue<&metav1::ObjectMeta>>("metadata", match specific_version_attr {
                                                        Some(_) => PartialValue::Unknown,
                                                        None => PartialValue::Unset,
                                                    })
                                                    // TODO: Use partialvalue here and unknown/unset instead of this Option<Unknown> style
                                                    .with_attr(api_version.as_str(), specific_version_attr.map(|_| EntityBuilder::build_unknown(format!("{}{}", &crate::util::title_case(api_version), &kind).parse::<Name>().unwrap().qualify_with_name(resource_type_namespace_name.as_ref()))))
                                                );
                                        }
                                        // For verbs that do not carry request data, make "resource has request" return false.
                                        (true, false) => (),
                                        // If the type does not have a request, ok, don't add anything.
                                        (false, _) => (),
                                    };

                                    match (
                                        record.attributes.contains_key("stored"),
                                        action_capability.has_stored_object(),
                                    ) {
                                        (true, true) => {
                                            let versioned_record = resource_type_namespace.common_types.get(&CommonTypeId::new(format!("Versioned{kind}").parse::<UnreservedId>().unwrap()).unwrap())
                                                    .ok_or_else(|| AuthorizerError::UnexpectedSchemaShape("schema should have common type registered at GVR resource entity".to_string()))?;
                                            let versioned_record =
                                                type_to_record(&versioned_record.ty)?;
                                            let specific_version_attr = versioned_record
                                                .attributes
                                                .get(api_version.as_str());

                                            resource_builder.add_attr(
                                                "stored",
                                                RecordBuilderImpl::new()
                                                    .with_attr("apiVersion", Some(api_group_version.clone()))
                                                    .with_attr("kind", Some(kind.clone()))
                                                    // Only expose the metadata field if there a) the apiVersion is an exact match, and b) the given apiVersion exists in the schema.
                                                    .with_attr::<&str, PartialValue<&metav1::ObjectMeta>>("metadata", match specific_version_attr {
                                                        Some(_) => PartialValue::Unknown,
                                                        None => PartialValue::Unset,
                                                    })
                                                    .with_attr(api_version.as_str(), specific_version_attr.map(|_| EntityBuilder::build_unknown(format!("{}{}", &crate::util::title_case(api_version), &kind).parse::<Name>().unwrap().qualify_with_name(resource_type_namespace_name.as_ref()))))
                                                );
                                        }
                                        // For verbs that do not have stored data, make "resource has stored" return false.
                                        (true, false) => (),
                                        // If the type does not have a stored object, ok, don't add anything.
                                        (false, _) => (),
                                    }
                                }
                                // If the apiVersion is an any match, resource.stored, resource.request, and resource.namespaceMetadata are nil, but unlike
                                // the untyped case (k8s::Resource), the specific resource entity type is used (e.g. core::pods).
                                StarWildcardStringSelector::Any => (),
                            }

                            Ok((
                                resource_builder.build(
                                    Name::unqualified_name(typed_resource_entity_id)
                                        .qualify_with_name(resource_type_namespace_name.as_ref()),
                                ),
                                Some(record.attributes.contains_key("namespace")),
                            ))
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
    ) -> Result<(BuiltEntity, Option<bool>), AuthorizerError> {
        Ok((
            resource_builder
                .with_attr(
                    "namespace",
                    match &resource_attrs.namespace {
                        // Here we cannot distinguish between namespace being "any" or "unset". We assume that the namespace is "any",
                        // as we're arbitrarily selecting across a (possibly infinite) set of k8s resource types.
                        // However, in theory all matched resources could be cluster-scoped (imagine apiGroup="foo" and resource="*"),
                        // where all resources in apiGroup="foo" are cluster-scoped. If so, it would be better to make "resource has namespace"
                        // queries return "false", but this we cannot know, we lose a little bit of precision here.
                        // TODO: Create a Cedar issue to discuss whether "foo has bar" should be able to be unknown, which is what we want here.
                        EmptyWildcardStringSelector::Any => PartialValue::Unknown,
                        EmptyWildcardStringSelector::Exact(ns_name) => {
                            PartialValue::Known(ns_name.to_smolstr())
                        }
                    },
                )
                // None here means that we don't know whether the resource is namespace-scoped or cluster-scoped.
                .build(RESOURCE_RESOURCE.name.name()),
            None,
        ))
    }

    fn find_schema_entity_for_api_group_and_resource<'a>(
        &'a self,
        api_group: &str,
        resource: &str,
    ) -> Option<(
        &'a Option<Name>,
        &'a NamespaceDefinition<RawName>,
        UnreservedId,
        &'a json_schema::EntityType<RawName>,
    )> {
        let (ns_name, ns) =
            self.policies
                .schema_ref()
                .get_fragment()
                .0
                .iter()
                .find(
                    |(_, entity)| match entity.annotations.0.get(&API_GROUP_ANNOTATION) {
                        Some(Some(Annotation { val, .. })) => val.as_str() == api_group,
                        _ => false,
                    },
                )?;

        // TODO: If unwrap is used, at least replace them all with an expect.
        let resource_cedar_compatible_name =
            resource.replace("/", "_").parse::<UnreservedId>().unwrap();
        ns.entity_types
            .get(&resource_cedar_compatible_name)
            .map(|entity_type| (ns_name, ns, resource_cedar_compatible_name, entity_type))
    }

    // INVARIANT: verb is validated to exist in the schema already.
    async fn is_authorized_for_action(
        &self,
        attrs: &Attributes,
        action: &str,
        action_schemadef: &json_schema::ActionType<RawName>,
        cedar_ns_name: &Option<Name>,
    ) -> Result<DetailedDecision, AuthorizerError> {
        let action_capability = self
            .policies
            .schema_ref()
            .get_action_capabilities(cedar_ns_name, action);
        // TODO: Unit-test the construct_principal/resource functions.
        let principal_entity = self.construct_principal(attrs)?;
        let (resource_entity, namespace_scoped) =
            self.construct_resource(attrs, &action_capability)?;

        let principal_entity_uid = principal_entity.uid().clone();
        let resource_entity_uid = resource_entity.uid().clone();
        //let cedar_ns_internalname = cedar_ns_name.as_ref().map(|n| n.as_ref());
        let action_entity_uid: ast::EntityUID = match &attrs.request_type {
            RequestType::Resource(_) => format!(r#"k8s::Action::"{action}""#).parse()?,
            RequestType::NonResource(_) => {
                format!(r#"k8s::nonresource::Action::"{action}""#).parse()?
            }
        };
        let code_schema =
            cedar_policy_core::validator::CoreSchema::new(self.policies.schema_ref().as_ref());
        let action_entity = PartialEntity {
            uid: action_entity_uid.clone(),
            attrs: None,
            ancestors: Some(
                code_schema
                    .action(&action_entity_uid)
                    .expect("INVARIANT: action existence in the schema is checked in is_authorized")
                    .ancestors()
                    .cloned()
                    .collect(),
            ),
            tags: None,
        };

        let req = PartialRequest::new(
            principal_entity_uid.clone().into(),
            action_entity_uid.clone(),
            resource_entity_uid.clone().into(),
            None,
            self.policies.schema().as_ref().as_ref(),
        )?;

        let (principal_entities, principal_jsonpaths) = principal_entity.into_parts("principal");
        let (resource_entities, resource_jsonpaths) = resource_entity.into_parts("resource");

        // Note: There must be no duplicate UIDs in the entities, as we do not deduplicate them.
        // As of writing, no such duplicate entities between principal and resource is known.
        let entities = PartialEntities::from_entities(
            principal_entities
                .into_iter()
                .chain(resource_entities.into_iter())
                .chain(std::iter::once((
                    action_entity_uid.clone().into(),
                    action_entity,
                ))),
            self.policies.schema().as_ref().as_ref(),
        )?;

        let untyped_resp = self.policies.tpe(&req, &entities)?;

        Ok(match untyped_resp.decision()? {
            DetailedDecision::Allow(permitted_policy_ids) => {
                DetailedDecision::Allow(permitted_policy_ids)
            }
            DetailedDecision::Conditional(condition, unknown_jsonpaths_to_uid) => {
                //println!("conditional decision: {condition}");

                // Union all the unknown jsonpaths.
                let unknown_jsonpaths_to_uid = unknown_jsonpaths_to_uid
                    .into_iter()
                    .chain(principal_jsonpaths)
                    .chain(resource_jsonpaths)
                    .collect();

                // For conditional authorization to be supported, apiGroup, apiVersion, and resource must be exact matches.
                // TODO: Should label selector authorization be allowed, even though we don't know the resource type?
                if let Some((_, api_version, _)) = attrs.supports_conditional_authorization() {
                    if action_capability.supports_conditional_decision() {
                        DetailedDecision::Conditional(condition, unknown_jsonpaths_to_uid)
                    } else if action_capability.supports_selectors() {
                        let reqenv = cedar_policy::RequestEnv::new(
                            principal_entity_uid.entity_type().clone().into(),
                            action_entity_uid.into(),
                            resource_entity_uid.entity_type().clone().into(),
                        );

                        match self
                            .symcc_evaluator
                            .selector_conditions_are_authorized(
                                &attrs,
                                &reqenv,
                                condition,
                                unknown_jsonpaths_to_uid,
                                &api_version,
                                namespace_scoped.unwrap_or(true),
                            )
                            .await?
                        {
                            // TODO: Fill in these, although we don't know exactly which allow policy fired.
                            true => {
                                DetailedDecision::Allow(Vec::from([ast::PolicyID::from_string(
                                    "conditional_authorization",
                                )]))
                            }
                            // TODO: Fill in these, although we don't know exactly which deny policy fired; or if it was due to no matching allow rules.
                            false => {
                                DetailedDecision::Deny(Vec::from([ast::PolicyID::from_string(
                                    "conditional_authorization",
                                )]))
                            }
                        }
                    } else {
                        // For the untyped case, the parts that may be conditional, are actually known, but just kept unknown, as they can have any value.
                        // Thus, if we get a conditional decision for an untyped request, there is some condition on "any value", which thus must evaluate to false.
                        // TODO: Rejecting allow rules is easy, but rejecting deny rules for this reason seems dangerous?
                        // TODO: If the resource is an untyped resource request, it might still need symcc,
                        // because of the 'resource.resourceCombined like "*/scale"' expressions.
                        // However, that could also be solved without symcc, by manual traversal for the specific use-case.
                        DetailedDecision::NoOpinion
                    }
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

impl<
        S: KubeStore<corev1::Namespace> + Send + Sync,
        F: symcc::SolverFactory<C> + Send + Sync,
        C: Solver + Send + Sync,
    > KubernetesAuthorizer for CedarKubeAuthorizer<S, F, C>
{
    fn is_authorized(
        &self,
        mut attrs: Attributes,
    ) -> impl std::future::Future<Output = Result<Response, AuthorizerError>> + Send {
        async move {
            let action_str = attrs.verb.to_string();
            let cedar_ns_name = match &mut attrs.request_type {
                RequestType::Resource(resource_attrs) => {
                    // Lookup the action capabilities for the resource request. An error is returned if the action is not supported.
                    let action_capability = self
                        .policies
                        .schema_ref()
                        .get_action_capabilities(&K8S_NS, &action_str);
                    if action_capability.supports_selectors() {
                        // Populate the resource attributes from the field selectors, if present.
                        resource_attrs.default_from_selectors()?;
                    } else {
                        resource_attrs.field_selector = None;
                        resource_attrs.label_selector = None;
                    }
                    &K8S_NS
                }
                RequestType::NonResource(_) => {
                    // Lookup the action capabilities for the non-resource request. An error is returned if the action is not supported.
                    &K8S_NONRESOURCE_NS
                }
            };

            let cedar_ns = self
                .policies
                .schema_ref()
                .get_namespace(cedar_ns_name)
                .ok_or_else(|| {
                    AuthorizerError::UnexpectedSchemaShape(format!(
                        "schema should have {cedar_ns_name:?} namespace registered"
                    ))
                })?;

            let action_schemadef = match cedar_ns.actions.get(action_str.as_str()) {
                Some(action_schemadef) => action_schemadef,
                None => return Err(AuthorizerError::UnsupportedVerb(action_str)),
            };

            match attrs.verb {
                // If the action is Any, verify that all actions are unconditionally allowed.
                Verb::Any => {
                    let errors = Vec::new();
                    let mut allowed_ids = HashSet::new();
                    // TODO: Check the * action first, then others.
                    // Deliberately shadow the action_str and action_schemadef variables so they aren't accidentally used.
                    for (action_str, action_schemadef) in cedar_ns.actions.iter() {
                        let resp = self
                            .is_authorized_for_action(
                                &attrs,
                                action_str.as_str(),
                                action_schemadef,
                                &cedar_ns_name,
                            )
                            .await?;
                        // TODO: Propagate errors?

                        match resp {
                            DetailedDecision::Allow(permitted_policy_ids) => {
                                allowed_ids.extend(permitted_policy_ids.into_iter())
                            }
                            DetailedDecision::Conditional(conditions, _) => {
                                return Ok(Response::no_opinion().with_errors(errors).with_reason(
                                    Reason::not_unconditionally_allowed(action_str, &conditions),
                                ))
                            }
                            DetailedDecision::Deny(forbidden_policy_ids) => {
                                return Ok(Response::no_opinion().with_errors(errors).with_reason(
                                    Reason::denied_by_policies(action_str, &forbidden_policy_ids),
                                ))
                            }
                            // TODO: Add as reason that a specific action is not unconditionally allowed.
                            DetailedDecision::NoOpinion => {
                                return Ok(Response::no_opinion()
                                    .with_errors(errors)
                                    .with_reason(Reason::no_allow_policy_match(action_str)))
                            }
                        }
                    }
                    // TODO: Add all policies that allowed the action as reason?
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
                    match self
                        .is_authorized_for_action(
                            &attrs,
                            &action_str,
                            action_schemadef,
                            &cedar_ns_name,
                        )
                        .await?
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
                        DetailedDecision::Conditional(
                            conditional_policies,
                            unknown_jsonpaths_to_uid,
                        ) => Ok(Response::conditional(
                            conditional_policies,
                            unknown_jsonpaths_to_uid,
                        )),
                        DetailedDecision::NoOpinion => Ok(Response::no_opinion()
                            .with_reason(Reason::no_allow_policy_match(&action_str))),
                    }
                }
            }
        }
    }
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
        json_schema::EntityTypeKind::Standard(standard_type) => {
            type_to_record(&standard_type.shape.0)
        }
        _ => Err(AuthorizerError::UnexpectedSchemaShape(format!(
            "Expected record type, got {entity:?}"
        ))),
    }
}

fn type_to_record(
    ty: &json_schema::Type<RawName>,
) -> Result<&json_schema::RecordType<RawName>, AuthorizerError> {
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

    #[tokio::test]
    async fn test_is_authorized() {
        use super::super::kubestore::TestKubeStore;
        use crate::cedar_authorizer::kube_invariants;
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

        use crate::cedar_authorizer::symcc::LocalSolverFactory;
        use std::collections::{BTreeMap, HashMap};
        use std::str::FromStr;
        use std::sync::Arc;

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
            /*corev1::Namespace {
                metadata: metav1::ObjectMeta {
                    name: Some("supersecret".to_string()),
                    uid: Some("1e00c0eb-ec4c-41a2-bb59-e7dea5b21b50".to_string()),
                    labels: Some(BTreeMap::from([(
                        "serviceaccounts-allowed".to_string(),
                        "true".to_string(),
                    )])),
                    ..Default::default()
                },
                ..Default::default()
            },*/
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
            super::CedarKubeAuthorizer::new(policies, namespace_store, LocalSolverFactory).unwrap();

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
            ("serviceaccount can create pods in its own namespace, if the namespace has the label",
            AttributesBuilder::resource("system:serviceaccount:foo:bar", Verb::Create,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("foo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::conditional(kube_invariants::PolicySet::from_str(r#"permit(
    principal,
    action,
    resource
) when {
(meta::V1ObjectMeta::"85388367-1edd-4bc3-8627-4cb36fa65130" has "labels") &&
(meta::V1ObjectMeta::"85388367-1edd-4bc3-8627-4cb36fa65130"["labels"]).hasTag("serviceaccounts-allowed") &&
(meta::V1ObjectMeta::"85388367-1edd-4bc3-8627-4cb36fa65130"["labels"]).getTag("serviceaccounts-allowed") == "true"
};"#, Arc::new(schema.clone())).unwrap(), HashMap::from([
    ("resource.name".to_string(), r#"meta::UnknownString::"899b04c3-0d65-4375-95d9-b643da26c747""#.parse().unwrap()),
    ("resource.namespaceMetadata".to_string(), r#"meta::V1ObjectMeta::"85388367-1edd-4bc3-8627-4cb36fa65130""#.parse().unwrap()),
    ("resource.request.v1".to_string(), r#"core::V1Pod::"20fa9537-3d09-4628-9841-cdc26099bf64""#.parse().unwrap()),
    ("resource.request.metadata".to_string(), r#"meta::V1ObjectMeta::"f9144f25-4359-4efe-80a2-3b74ed5bc57c""#.parse().unwrap()),
]))),
            ("serviceaccount cannot create pods in another namespace",
            AttributesBuilder::resource("system:serviceaccount:foo:bar", Verb::Create,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("notmatchingfoo".to_string()),
                    EmptyWildcardStringSelector::Any)
                .build(), Response::no_opinion()),
            ("serviceaccount cannot create pods in the supersecret namespace",
            AttributesBuilder::resource("system:serviceaccount:supersecret:bar", Verb::Create,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Exact("supersecret".to_string()),
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
            ("node-1 can watch its own pods cluster-wide, except in the supersecret namespace",
            AttributesBuilder::resource_and_selectors("system:node:node-1", Verb::Watch,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    None,
                    Some(vec![
                        Selector::in_values("spec.nodeName", vec!["node-1".to_string()]),
                        Selector::not_in_values("metadata.namespace", vec!["supersecret".to_string()]),
                    ]))
                .build(), Response::allow()),
            ("node-1 cannot watch all pods cluster-wide",
            AttributesBuilder::resource_and_selectors("system:node:node-1", Verb::Watch,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    None,
                    None)
                    .build(), Response::no_opinion()),
            ("node-1 cannot watch pods cluster-wide when spec.nodeName is either node-1 or node-2",
            AttributesBuilder::resource_and_selectors("system:node:node-1", Verb::Watch,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "pods".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    None,
                    Some(vec![
                        Selector::in_values("spec.nodeName", vec!["node-1".to_string(), "node-2".to_string()]),
                        Selector::not_in_values("metadata.namespace", vec!["supersecret".to_string()]),
                    ]))
                .build(), Response::no_opinion()),
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
                        Selector::in_values("metadata.namespace", vec!["foo".to_string()]),
                        Selector::in_values("metadata.name", vec!["bar".to_string()]),
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
                            Selector::in_values("metadata.namespace", vec!["foo".to_string()]),
                            Selector::in_values("metadata.name", vec!["bar".to_string()]),
                        ])
                    )
                    .build(), Response::no_opinion()),
            ("contour can list secrets cluster-wide (except the supersecret namespace), if the secret has the correct labels",
            AttributesBuilder::resource_and_selectors("system:serviceaccount:foo:contour", Verb::List,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "secrets".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    Some(vec![
                        Selector::in_values("allowed-ingress", vec!["contour".to_string(), "*".to_string()]),
                        Selector::not_in_values("clearancelevel", vec!["supersecret".to_string(), "confidential".to_string()]),
                    ]),
                    Some(vec![
                        Selector::not_in_values("metadata.namespace", vec!["supersecret".to_string()]),
                    ]))
                    .build(), Response::allow()),
            ("contour cannot list istio's secrets cluster-wide, if the secret has the correct labels",
            AttributesBuilder::resource_and_selectors("system:serviceaccount:foo:contour", Verb::List,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "secrets".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    Some(vec![
                        Selector::in_values("allowed-ingress", vec!["contour".to_string(), "*".to_string(), "istio".to_string()]),
                        Selector::not_in_values("clearancelevel", vec!["supersecret".to_string(), "confidential".to_string()]),
                    ]),
                    Some(vec![
                        Selector::not_in_values("metadata.namespace", vec!["supersecret".to_string()]),
                    ]))
                    .build(), Response::no_opinion()),
            ("contour cannot list secrets cluster-wide, if confidential secrets could match the label selector",
            AttributesBuilder::resource_and_selectors("system:serviceaccount:foo:contour", Verb::List,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "secrets".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    Some(vec![
                        Selector::in_values("allowed-ingress", vec!["contour".to_string(), "*".to_string()]),
                        Selector::not_in_values("clearancelevel", vec!["supersecret".to_string()]),
                    ]),
                    Some(vec![
                        Selector::not_in_values("metadata.namespace", vec!["supersecret".to_string()]),
                    ]))
                    .build(), Response::no_opinion()),
            ("contour cannot list secrets cluster-wide, if confidential or supersecret secrets could match the label selector (whole clearancelevel label selector omitted)",
            AttributesBuilder::resource_and_selectors("system:serviceaccount:foo:contour", Verb::List,
                    StarWildcardStringSelector::Exact("".to_string()),
                    StarWildcardStringSelector::Exact("v1".to_string()),
                    CombinedResource::ResourceOnly { resource: "secrets".to_string() },
                    EmptyWildcardStringSelector::Any,
                    EmptyWildcardStringSelector::Any,
                    Some(vec![
                        Selector::in_values("allowed-ingress", vec!["contour".to_string(), "*".to_string()]),
                    ]),
                    Some(vec![
                        Selector::not_in_values("metadata.namespace", vec!["supersecret".to_string()]),
                    ]))
                    .build(), Response::no_opinion()),
        ];

        for (description, attrs, expected_resp) in test_cases {
            println!("{description}");
            let resp = authorizer.is_authorized_response(attrs).await;
            assert_eq!(
                expected_resp.decision, resp.decision,
                "got {} with reason: {}, errors: {:?}",
                resp.decision, resp.reason, resp.errors
            );
        }
    }
}

/*
    Rewrites of the AST to support partially-unknown attributes of simple values, when Cedar TPE only supports that through entity references.

    The attributes that can be partially unknown of resources are:
    Of k8s::Resource:
    - (simple) resource.apiGroup                (during SubjectAccessReviews for *)
    - (simple) resource.resourceCombined        (during SubjectAccessReviews for *)
    - (simple) resource.name                    (during SubjectAccessReviews for *, or list/watch/deletecollection without fieldSelector .metadata.name)
    - (entityref) resource.namespace            (during SubjectAccessReviews for *, or cluster-wide list/watch/deletecollection for a namespaced resource)

    Of typed resources, e.g. core::secrets:
    - (simple) resource.name                    (during list/watch/deletecollection (without fieldSelector .metadata.name), and creates)
    - (entityref) resource.namespace            (during cluster-wide list/watch/deletecollection (without fieldSelector .metadata.namespace) for a namespaced resource)
      Note: Kubernetes disallows POST /api/v1/pods, i.e. a cluster-wide create request for a namespaced resource, so we always have the
      namespace available for creates if applicable.
    - (entityref) resource.request              (during create/update/patch requests)
    - (entityref) resource.stored               (during update/patch/delete/deletecollection requests)

    We will thus:
    - For each entity that is a resource accessible from some action in the Cedar k8s namespace, which also has the
      attribute resource.apiGroup, resource.resourceCombined, and resource.name, we will create a new entityref




    For the general case, if we have a policy which:
    - is relevant both in a request environment which this code cares about (i.e. has a resource type which is rewritten)
        and in a request environment which is not rewritten, and
    - actually references the rewritten value, e.g. resource.apiGroup
    - then we need to guard the change with an "if" statement as follows:
        resource.apiGroup => if (resource is k8s::Resource || resource is core::secrets) { resource.apiGroup.value } else { resource.apiGroup }
        (or the other way, depending on which set of resource types is bigger)
    - This means that the policy will typecheck afterwards in our rewritten policies, as well as all other ones.

    If a policy does not match any request environments that are NOT rewritten, then we can remove the if statement and just substitute
      resource.apiGroup => resource.apiGroup.value

    In our case, we will rewrite the same fields for all resource types, and we can enforce the invariant that policies cannot apply to
      any non-rewritten resource types for now.
*/

mod err;
mod policyset;
mod residual;
mod schema;

pub use err::*;
pub use policyset::PolicySet;
pub use residual::{DetailedDecision, PartialResponseNew};
pub use schema::Schema;

use cedar_policy_core::ast;
use serde::{Deserialize, Serialize};
use k8s_openapi::api::authorization::v1::SubjectAccessReview;

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorizationConditions(pub Vec<AuthorizationCELCondition>);

pub const CONDITIONAL_AUTHORIZATION_CONDITIONS_ANNOTATION: &str = "kubernetes.io/SubjectAccessReviewConditions";

impl AuthorizationConditions {
  pub fn from_policy_set<M: super::cel::EntityToCelVariableMapper>(policy_set: &super::kube_invariants::PolicySet, entity_uid_mapper: &mut M) -> Result<Self, super::cel::CedarToCelError> {
    let cel_conditions = policy_set.as_ref().policies().map(|p| AuthorizationCELCondition::new_from_policy(p, entity_uid_mapper)).collect::<Result<Vec<_>, _>>()?;
    Ok(Self(cel_conditions))
  }
  pub fn apply_to_subject_access_review(&self, sar: &mut SubjectAccessReview) -> Result<(), serde_json::Error> {
    sar.metadata.annotations.get_or_insert_default().insert(CONDITIONAL_AUTHORIZATION_CONDITIONS_ANNOTATION.to_string(), serde_json::to_string(self)?);
    Ok(())
  }
  pub fn map_cel_exprs<F: Fn(&super::cel::CELExpression) -> super::cel::CELExpression>(&self, f: F) -> Self {
    Self(self.0.iter().map(|c| c.map_cel_expr(&f)).collect())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCELCondition {
    pub id: ast::PolicyID,
    pub condition: super::cel::CELExpression,
    pub effect: AuthorizationCELConditionEffect,
}

impl AuthorizationCELCondition {
  pub fn new(id: ast::PolicyID, condition: super::cel::CELExpression, effect: ast::Effect) -> Self {
    Self {
      id,
      condition,
      effect: match effect {
        ast::Effect::Permit => AuthorizationCELConditionEffect::Allow,
        ast::Effect::Forbid => AuthorizationCELConditionEffect::Deny,
      },
    }
  }
  pub fn new_from_policy<M: super::cel::EntityToCelVariableMapper>(policy: &ast::Policy, entity_uid_mapper: &mut M) -> Result<Self, super::cel::CedarToCelError> {
    Ok(Self::new(policy.id().clone(), super::cel::cedar_to_cel(&policy.condition(), entity_uid_mapper)?, policy.effect()))
  }
  pub fn map_cel_expr<F: Fn(&super::cel::CELExpression) -> super::cel::CELExpression>(&self, f: F) -> Self {
    Self {
      id: self.id.clone(),
      condition: f(&self.condition),
      effect: self.effect.clone(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorizationCELConditionEffect {
    Allow,
    Deny,
}
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

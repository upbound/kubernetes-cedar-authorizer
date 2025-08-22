permit(
    principal is k8s::ServiceAccount,
    action == k8s::Action::"create",
    resource is core::secrets
) when {
    principal.serviceAccountName == "default" && // SA name
    principal.serviceAccountNamespace == resource.namespace.name &&
    resource has request.v1.type &&
    resource.request.v1.type == "crossplane.io/connection-secret"
};

// CEL rule v1: has(object.type) && object.type == "crossplane.io/connection-secret"
// CEL rule v2: has(object.type2) && object.type2 == "crossplane.io/connection-secret"

permit(
    principal,
    action == k8s::Action::"create",
    resource
) when {
    resource.apiGroup == "authorization.k8s.io" &&
    resource.resourceCombined == "selfsubjectaccessreviews"
};
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

permit(
    principal,
    action == k8s::Action::"create",
    resource
) when {
    resource.apiGroup == "authorization.k8s.io" &&
    resource.resourceCombined == "selfsubjectaccessreviews"
};
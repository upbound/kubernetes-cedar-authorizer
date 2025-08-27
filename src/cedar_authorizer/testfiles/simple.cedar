permit (
    principal is k8s::User,
    action,
    resource
)
// Even though the have this weird residual in the beginning (whenever namespace=*), the principals should be allowed to perform */*
when { ["admin", "superadmin"].contains(principal.username) };

// (resource has namespace && resource.namespace.name == "supersecret") ||
forbid (
    principal,
    action in [k8s::Action::"*"], // Testing that the entity hierarchy is correctly propagated to TPE
    resource
)
when
{
    resource has namespace &&
    resource.namespace == "supersecret"
} unless {
    principal has username && principal.username == "superadmin"
};

permit (
    principal,
    action == k8s::nonresource::Action::"get",
    resource
)
when { resource.path like "/openapi/*" };

// This is expected to not have any effect, as it wrongly puts a condition for the path being "*", which even though it's
// string representation is that in the SAR, requires an absence of condition to be allowed here.
permit (
    principal is k8s::UnauthenticatedUser,
    action == k8s::nonresource::Action::"get",
    resource
)
when { resource.path == "*" };

@allow("unconstrained-apigroup")
permit (
    principal is k8s::ServiceAccount,
    action in [k8s::Action::"create", k8s::Action::"list"], // <- list is a static false, remove it
    resource
)
when
{
    resource.apiGroup == "" &&
    resource.resourceCombined == "pods" &&
    resource has namespace &&
    resource.namespace == principal.serviceAccountNamespace &&
    resource has namespaceMetadata.labels &&
    resource.namespaceMetadata.labels.hasTag("serviceaccounts-allowed") &&
    resource.namespaceMetadata.labels.getTag("serviceaccounts-allowed") == "true"
};

// CEL condition:
// has(namespaceObject.labels) &&
// has(namespaceObject.labels["serviceaccounts-allowed"]) &&
// namespaceObject.labels["serviceaccounts-allowed"] == "true"

permit (
    principal is k8s::Node,
    action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
    resource
)
when { resource.apiGroup == "" && resource.resourceCombined == "nodes" && resource.name == principal.nodeName };

permit (
    principal is k8s::User,
    action,
    resource
)
when { principal.groups.contains("lucas") && resource has namespace && resource.namespace == "notinstorage" };

permit (
    principal is k8s::User,
    action == k8s::Action::"get",
    resource
)
when { principal.username == "explicitwildcardshouldfail" && resource.apiGroup == "*" && resource.resourceCombined == "foo" };

permit (
    principal is k8s::User,
    action == k8s::Action::"get",
    resource
)
when { principal.username == "omittedconditionok" && resource.resourceCombined == "foo" };

permit (
    principal is k8s::User,
    action == k8s::Action::"watch",
    resource
)
when { principal.username == "singleitemwatch" && resource has namespace && resource.namespace == "foo" && resource.name == "bar" };


permit (
    principal is k8s::Node,
    action == k8s::Action::"watch",
    resource is core::pods
)
when { resource has stored.v1.spec && resource.stored.v1.spec.nodeName == principal.nodeName };

// Allow contour and istio ingress controllers to list and watch secrets, but only if:
// - The secret allows either all ingresses (through the "*" label value) or the specific ingress controller (through the ingress controller's service account name)
// - The secret's clearance level is not supersecret or confidential
permit (
    principal is k8s::ServiceAccount,
    action in [k8s::Action::"list", k8s::Action::"watch"],
    resource is core::secrets // TODO: Should label selector authorization be allowed, even though we don't know the resource type?
)
when {
    ["contour", "istio"].contains(principal.serviceAccountName) &&
    resource has stored.metadata.labels &&
    resource.stored.metadata.labels.hasTag("allowed-ingress") &&
    (resource.stored.metadata.labels.getTag("allowed-ingress") == "*" || resource.stored.metadata.labels.getTag("allowed-ingress") == principal.serviceAccountName) &&
    // Clearance labelselector must be present
    // TODO: This is most likely wrong, as this does not authorize label NotExists, which should be authorized.
    resource.stored.metadata.labels.hasTag("clearancelevel")
} unless {
    // Clearance level must not be supersecret or confidential
    resource.stored.metadata.labels.getTag("clearancelevel") == "supersecret" ||
    resource.stored.metadata.labels.getTag("clearancelevel") == "confidential"
};

permit (
    principal is k8s::User,
    action == k8s::Action::"watch",
    resource is core::secrets
)
when { principal.username like "oidc:*" && resource has stored.metadata.labels && resource.stored.metadata.labels.hasTag("public-access") };


// oidc-front-proxy group members can impersonate users with the oidc: prefix
permit (
    principal is k8s::User,
    action in [k8s::Action::"constrainedimpersonate", k8s::Action::"impersonate"],
    resource is io::k8s::authentication::users
) when {
    principal.groups.contains("oidc-front-proxy") &&
    resource.name like "oidc:*"
};

// Unconditional Allow.

// oidc-front-proxy group members can impersonate groups with the oidc: prefix, but only if the impersonated user also has the oidc: prefix
permit (
    principal is k8s::User,
    action == k8s::Action::"constrainedimpersonate",
    resource is io::k8s::authentication::groups
) when {
    principal.groups.contains("oidc-front-proxy") &&
    resource.name like "oidc:*" &&
    context.impersonatedPrincipal.username like "oidc:*"
};

// CEL Condition: request.user.username.startsWith("oidc:")

// node-agent foo ServiceAccount can impersonate the node it is scheduled on, but only to get pods (e.g. not Secrets)
permit (
    principal is k8s::ServiceAccount,
    action == k8s::Action::"constrainedimpersonate",
    resource is io::k8s::authentication::nodes
) when {
    principal.serviceAccountName == "node-agent-foo" &&
    principal.serviceAccountNamespace == "node-agent-foo-ns" &&
    principal.extra.hasTag("authentication.kubernetes.io/node-name") &&
    principal.extra.getTag("authentication.kubernetes.io/node-name") == [resource.name] &&
    context.impersonatedAction == "get" &&
    context.impersonatedResource.apiGroup == "" &&
    context.impersonatedResource.resourceCombined == "pods"
};

// CEL Condition: request.verb == "get" && request.resource.apiGroup == "" && request.resource.resource == "pods"

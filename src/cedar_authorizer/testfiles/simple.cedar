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
    action == k8s::Action::"get",
    resource
)
when
{
    resource has namespace &&
    resource.namespace.name == "supersecret" &&
    (principal is k8s::UnauthenticatedUser ||
     principal.username != "superadmin")
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

permit (
    principal is k8s::ServiceAccount,
    action in [k8s::Action::"get", k8s::Action::"list"],
    resource
)
when
{
    resource.apiGroup == "" &&
    resource.resourceCombined == "serviceaccounts" &&
    resource has namespace &&
    resource.namespace == principal.namespace &&
    resource.namespace.metadata.labels.hasTag("serviceaccounts-allowed") &&
    resource.namespace.metadata.labels.getTag("serviceaccounts-allowed") == "true"
};

permit (
    principal is k8s::Node,
    action in [k8s::Action::"get", k8s::Action::"list", k8s::Action::"watch"],
    resource
)
when { resource.apiGroup == "" && resource.resourceCombined == "nodes" && resource.name == principal.name };

permit (
    principal is k8s::User,
    action,
    resource
)
when { principal.groups.contains("lucas") && resource has namespace && resource.namespace.name == "foo" };

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
when { principal.username == "singleitemwatch" && resource has namespace &&resource.namespace.name == "foo" && resource.name == "bar" };


permit (
    principal is k8s::Node,
    action == k8s::Action::"get",
    resource is core::pods
)
when { resource has stored && resource.stored has v1.spec && resource.stored.v1.spec.nodeName == principal.name };
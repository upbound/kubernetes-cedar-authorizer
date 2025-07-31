
permit (
    principal is k8s::User,
    action,
    resource is k8s::Resource
)
// Even though the have this weird residual in the beginning (whenever namespace=*), the principals should be allowed to perform */*
when { ["admin", "superadmin"].contains(principal.username) };
// (resource has namespace && resource.namespace.name == "supersecret") || 

forbid (
    principal,
    action == k8s::Action::"get",
    resource
)
when { resource has namespace && resource.namespace.name == "supersecret" && principal.username != "superadmin" };

permit (
    principal,
    action == k8s::Action::"get",
    resource is k8s::NonResourceURL
)
when { resource.path == "/version" };

permit (
    principal is k8s::ServiceAccount,
    action in [k8s::Action::"get", k8s::Action::"list"],
    resource is k8s::Resource
)
when
{
    resource.apiGroup == "" &&
    resource.resourceCombined == "serviceaccounts" &&
    resource has namespace &&
    resource.namespace.name == principal.namespace.name
};

permit (
    principal is k8s::Node,
    action in [k8s::Action::"get", k8s::Action::"list"],
    resource is k8s::Resource
)
when { resource.apiGroup == "core" && resource.resourceCombined == "nodes" };
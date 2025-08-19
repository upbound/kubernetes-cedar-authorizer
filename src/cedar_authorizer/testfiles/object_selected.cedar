permit(
    principal,
    action == k8s::Action::"get",
    resource is core::pods
) when {
    // Preamble
    resource.apiGroup == "" &&
    resource.resourceCombined == "pods" &&
    !(resource has request) &&
    // Actual policy
    resource has stored &&
    resource.stored.metadata.labels.hasTag("env") && 
    ["test", "dev"].contains(resource.stored.metadata.labels.getTag("env")) &&
    resource.stored.metadata.labels.hasTag("owner") && 
    ["team-2", "team-3"].contains(resource.stored.metadata.labels.getTag("owner"))
};
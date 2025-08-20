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
    (if resource.stored.metadata.labels.hasTag("env") then
        resource.stored.metadata.labels.getTag("env") != "prod"
     else true) &&
    resource.stored.metadata.labels.hasTag("owner") && 
    ["team-1", "team-2"].contains(resource.stored.metadata.labels.getTag("owner"))
};

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
    resource.stored.metadata.labels.getTag("env") == "test"
};
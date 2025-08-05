use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy_core::ast::UnreservedId;
use cedar_policy_core::validator::json_schema::{
    CommonTypeId, Fragment, Type, TypeOfAttribute, TypeVariant,
};
use cedar_policy_core::validator::RawName;
use kube::api::{GroupVersionKind, GroupVersionResource};
use serde_json::Value;

use super::core::K8S_NS;
use super::discovery::CedarGroupVersion;
use super::err::{Result, SchemaProcessingError};
use super::openapi::GroupVersionedOpenAPIType;
use super::types::{EntityWrapper, TypeKind};
use super::util::namespace_of_fragment;

pub(super) fn with_connect_rewrites(
    fragment: &mut Fragment<RawName>,
    gv: &CedarGroupVersion,
    openapi_spec: &Value,
) -> Result<HashMap<GroupVersionResource, HashSet<String>>> {
    let openapi_paths = openapi_spec
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            SchemaProcessingError::OpenAPI(
                "OpenAPI schema does not have a '.paths' object".to_string(),
            )
        })?;

    let special_connect_verb_path_mappings = HashMap::from([(
        ("get", "/api/v1/namespaces/{namespace}/pods/{name}/log"),
        GroupVersionKind {
            group: "".to_string(),
            version: "v1".to_string(),
            kind: "PodLogOptions".to_string(),
        },
    )]);

    let mut connect_mappings = HashMap::new();

    for (path, verbs_object) in openapi_paths {
        let verbs_object = verbs_object.as_object().ok_or_else(|| {
            SchemaProcessingError::OpenAPI(
                "OpenAPI schema does not have a '.paths[path]' object".to_string(),
            )
        })?;

        let mut k8s_actions = Vec::new();
        let mut gvks = Vec::new();

        for (verb, verb_object) in verbs_object {
            if verb == "parameters" {
                continue;
            }
            // println!("{}{}", path, verb);
            let verb_object = verb_object.as_object().ok_or_else(|| {
                SchemaProcessingError::OpenAPI(
                    "OpenAPI schema does not have a '.paths[path][verb]' object".to_string(),
                )
            })?;

            let mut k8s_action = verb_object
                .get("x-kubernetes-action")
                .and_then(|v| v.as_str())
                .unwrap_or_default();

            let mut gvk = verb_object
                .get("x-kubernetes-group-version-kind")
                .map(|o| GroupVersionKind {
                    group: o
                        .get("group")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    version: o
                        .get("version")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    kind: o
                        .get("kind")
                        .and_then(|s| s.as_str())
                        .unwrap_or_default()
                        .to_string(),
                })
                .unwrap_or_else(|| GroupVersionKind {
                    group: String::new(),
                    version: String::new(),
                    kind: String::new(),
                });

            // Fixup pods/log
            if let Some(mapped_gvk) =
                special_connect_verb_path_mappings.get(&(verb.as_str(), path.as_str()))
            {
                k8s_action = "connect";
                gvk = mapped_gvk.clone();
            }

            k8s_actions.push(k8s_action);

            if k8s_action == "connect" {
                // Sanity check
                if gvk.version.is_empty() || gvk.kind.is_empty() {
                    return Err(SchemaProcessingError::Unknown(format!(
                        "did not expect empty gvk in connect: {gvk:?} for {path}"
                    )));
                }
                gvks.push(gvk);

                if let Some(gvr) = parse_url_into_gvr(path.as_str()) {
                    // handle connect case
                    connect_mappings
                        .entry(gvr.clone())
                        .or_insert_with(HashSet::new)
                        .insert(verb.to_string());

                    let actions_ns = namespace_of_fragment(fragment, K8S_NS.clone());

                    // Remove this GVR from this {verb} action (if it exists); and make sure it exists in the connect action instead
                    let cedar_gvr_type_name = gv.resource_type_name(&gvr.resource)?.full_name();
                    if let Some(verb_action) = actions_ns
                        .actions
                        .get_mut(verb.as_str())
                        .and_then(|a| a.applies_to.as_mut())
                    {
                        verb_action
                            .resource_types
                            .retain(|type_name| type_name != &cedar_gvr_type_name);
                        eprintln!("Removed from {}: {}", verb, &cedar_gvr_type_name);
                    }

                    let connect_action = actions_ns.actions.get_mut("connect").and_then(|a| a.applies_to.as_mut()).ok_or_else(|| SchemaProcessingError::OpenAPI(
                        "Expected the connect actions to be populated already, it did not exist".to_string()
                    ))?;
                    if !connect_action
                        .resource_types
                        .iter()
                        .any(|type_name| type_name == &cedar_gvr_type_name)
                    {
                        eprintln!("Added to connect: {}", &cedar_gvr_type_name);
                        connect_action.resource_types.push(cedar_gvr_type_name);
                    }
                }
            }
        }

        // Note that there is a pretty query parameter that doesn't show up in Go structs, only API server
        // Only consider in=query. Turn into Sets in Cedar for the given type.
        // Maybe map the query parameters somewhere else than "request/payload" for connect?
        // TODO: Remove the "stored" object as it doesn't exist for connect.
        // TODO: Are Get/CreateOptions applicable on subresources, in general?
        // TODO: Probably these could be hard-coded for Kubernetes core, by them just magically "existing" prior to this
        // invocation. That way, custom integrators could also have their own "base", with typed params.
        // TODO: Connect resources never have an oldobject

        if k8s_actions.contains(&"connect") {
            // sanity check the OpenAPI invariants
            if !(!k8s_actions.is_empty()
                && !gvks.is_empty()
                && k8s_actions.iter().all(|v| *v == "connect")
                && gvks.iter().all(|gvk| *gvk == gvks[0]))
            {
                return Err(SchemaProcessingError::Unknown(format!(
                    "expected all k8s actions to be connect, and gvks to equal for {path}"
                )));
            }

            let openapi_type = GroupVersionedOpenAPIType::new(
                CedarGroupVersion::new(gvks[0].group.clone(), gvks[0].version.clone())?,
                gvks[0].kind.clone(),
            )?;

            let mut attrs = BTreeMap::new();

            let params = verbs_object
                .get("parameters")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            for param in params {
                // only consider query parameters
                if param.get("in").and_then(|s| s.as_str()) != Some("query") {
                    continue;
                }

                let name_opt = param.get("name").and_then(|s| s.as_str());
                let type_opt = param
                    .get("schema")
                    .and_then(|o| o.get("type"))
                    .and_then(|s| s.as_str());

                match (name_opt, type_opt) {
                    (Some(param_name), Some(param_type)) => {
                        let elem_type = match param_type {
                            "string" => TypeVariant::String,
                            "integer" => TypeVariant::Long,
                            "boolean" => TypeVariant::Boolean,
                            _ => {
                                return Err(SchemaProcessingError::Unknown(format!(
                                    "unknown param type {param_type} in {path} {param_name}"
                                )))
                            }
                        };
                        attrs.insert(
                            param_name.into(),
                            TypeOfAttribute {
                                ty: Type::Type {
                                    // To check one value, one can probably do opts.attr_name == ["foo"] or similar
                                    ty: TypeVariant::Set {
                                        element: Box::new(Type::Type {
                                            ty: elem_type,
                                            loc: None,
                                        }),
                                    },
                                    loc: None,
                                },
                                required: true,
                                annotations: Default::default(),
                            },
                        );
                    }
                    (_, _) => {
                        return Err(SchemaProcessingError::Unknown(format!(
                            "both param_type and param_name required in {path}"
                        )))
                    }
                }
            }

            // Remove metadata from versionlist for query kind
            let gv_cedar_ns = namespace_of_fragment(
                fragment,
                openapi_type.cedar_type_name.cedar_namespace.clone(),
            );
            let versionlist_type_name = CommonTypeId::new(UnreservedId::from_str(&format!(
                "Versioned{}",
                &gvks[0].kind
            ))?)?;
            let versionlist_type = gv_cedar_ns
                .common_types
                .get_mut(&versionlist_type_name)
                .ok_or_else(|| {
                    SchemaProcessingError::Unknown(
                        "expected versionlist to be available".to_string(),
                    )
                })?;
            match &mut versionlist_type.ty {
                Type::Type { ty, .. } => match ty {
                    TypeVariant::Record(rt) => {
                        rt.attributes.remove("metadata");
                    }
                    _ => {
                        return Err(SchemaProcessingError::Unknown(
                            "expected versionlist to be a record".to_string(),
                        ))
                    }
                },
                _ => {
                    return Err(SchemaProcessingError::Unknown(
                        "expected versionlist to be a record".to_string(),
                    ))
                }
            }

            EntityWrapper {
                name: openapi_type.cedar_type_name,
                attrs,
                kind: TypeKind::CommonType,
            }
            .apply(fragment)?;
        }
    }

    Ok(connect_mappings)
}

fn parse_url_into_gvr(url: &str) -> Option<GroupVersionResource> {
    let mut segments = url.trim_start_matches("/").split("/");
    let [group, version] = match segments.next()? {
        "api" => ["", segments.next()?],
        "apis" => [segments.next()?, segments.next()?],
        _ => return None,
    };
    // TODO: Make this nicer using a vector, not an interator
    let resource = match [segments.next(), segments.next()] {
        [Some("namespaces"), Some("{namespace}")] => {
            let resource = segments.next()?;
            segments.next(); // discard name after resource
            resource
        }
        [Some(resource), _] => resource,
        [None, _] => return None,
    };
    if let Some(subresource) = segments.next() {
        Some(GroupVersionResource::gvr(
            group,
            version,
            &format!("{resource}/{subresource}"),
        ))
    } else {
        Some(GroupVersionResource::gvr(group, version, resource))
    }
}

mod test {

    #[test]
    fn test_parse_url_into_gvr() {
        use kube::api::GroupVersionResource;
        let tests = [
            // core group
            (
                "/api/v1/namespaces/{namespace}/pods/{name}/binding",
                Some(GroupVersionResource::gvr("", "v1", "pods/binding")),
            ),
            (
                "/api/v1/namespaces/{namespace}/pods/{name}",
                Some(GroupVersionResource::gvr("", "v1", "pods")),
            ),
            (
                "/api/v1/namespaces/{namespace}/pods",
                Some(GroupVersionResource::gvr("", "v1", "pods")),
            ),
            (
                "/api/v1/nodes/{name}/proxy",
                Some(GroupVersionResource::gvr("", "v1", "nodes/proxy")),
            ),
            (
                "/api/v1/nodes/{name}",
                Some(GroupVersionResource::gvr("", "v1", "nodes")),
            ),
            (
                "/api/v1/nodes",
                Some(GroupVersionResource::gvr("", "v1", "nodes")),
            ),
            // Other API group
            (
                "/apis/foo.com/v2/namespaces/{namespace}/pods/{name}/binding",
                Some(GroupVersionResource::gvr("foo.com", "v2", "pods/binding")),
            ),
            (
                "/apis/foo.com/v2/namespaces/{namespace}/pods/{name}",
                Some(GroupVersionResource::gvr("foo.com", "v2", "pods")),
            ),
            (
                "/apis/foo.com/v2/namespaces/{namespace}/pods",
                Some(GroupVersionResource::gvr("foo.com", "v2", "pods")),
            ),
            (
                "/apis/foo.com/v2/nodes/{name}/proxy",
                Some(GroupVersionResource::gvr("foo.com", "v2", "nodes/proxy")),
            ),
            (
                "/apis/foo.com/v2/nodes/{name}",
                Some(GroupVersionResource::gvr("foo.com", "v2", "nodes")),
            ),
            (
                "/apis/foo.com/v2/nodes",
                Some(GroupVersionResource::gvr("foo.com", "v2", "nodes")),
            ),
        ];
        for (url, expected) in tests {
            assert_eq!(super::parse_url_into_gvr(url), expected)
        }
    }

    #[test]
    fn test_core_schema() {
        use crate::schema;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;
        use serde_json::Value;
        use std::io::Write;

        let test_schema_str =
            std::fs::read_to_string("src/schema/testfiles/withconnect.cedarschema")
                .unwrap_or_default();

        let apiresourcelist_core_v1_str =
            std::fs::read_to_string("src/schema/testfiles/apiresourcelist-core-v1.json")
                .expect("missing API resource list file");

        let openapi_core_v1_str =
            std::fs::read_to_string("src/schema/testfiles/openapi-core-v1.json")
                .expect("missing test schema");

        let apiresourcelist_core_v1: APIResourceList =
            serde_json::from_str(&apiresourcelist_core_v1_str)
                .expect("failed to deserialize APIResourceList");

        let openapi_core_v1: Value =
            serde_json::from_str(&openapi_core_v1_str).expect("failed to deserialize OpenAPI");

        let mut core_fragment = schema::core::build_base().expect("to succeed");
        schema::impersonate::with_impersonation(&mut core_fragment).expect("should work");
        schema::customverbs::with_custom_verbs(&mut core_fragment, Vec::new())
            .expect("should work");
        let gv = schema::CedarGroupVersion::new("".to_string(), "v1".to_string()).unwrap();
        schema::discovery::with_kubernetes_groupversion(
            &mut core_fragment,
            &gv,
            &apiresourcelist_core_v1,
        )
        .expect("openapi schema generation to work");
        let connect_mappings =
            schema::connect::with_connect_rewrites(&mut core_fragment, &gv, &openapi_core_v1)
                .expect("connect rewrite to work");
        eprintln!("Connect mappings: {connect_mappings:?}");

        let core_fragment_str = core_fragment
            .to_cedarschema()
            .expect("test schema can be displayed");
        eprintln!("{core_fragment}");
        // assert test schema file is already formatted
        if core_fragment_str != test_schema_str {
            let mut f = std::fs::File::create("src/schema/testfiles/withconnect.cedarschema")
                .expect("open file works");
            f.write_all(core_fragment_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}

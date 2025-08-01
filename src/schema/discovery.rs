use cedar_policy_core::ast::Name;
use cedar_policy_core::validator::json_schema::{
    CommonType, Fragment, RecordType, Type, TypeVariant,
};
use cedar_policy_core::validator::RawName;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;

use super::core::{ENTITY_NAMESPACE, K8S_NS, TYPE_OBJECTMETA};

use super::err::Result;
use super::openapi::GroupVersionedOpenAPIType;
use super::types::{ActionUID, CedarTypeName, EntityWrapper, TypeKind, TypeWrapper};
use super::util::namespace_of_fragment;
use std::collections::BTreeMap;
use std::str::FromStr;

pub(crate) fn group_to_cedar_ns(group: &str) -> Result<Option<Name>> {
    let parts: Vec<String> = match group.len() {
        0 => vec!["core".into()],
        _ => group
            .replace("-", "_")
            .split('.')
            .rev()
            .map(|s| s.to_string())
            .collect(),
    };

    // TODO: Here it would be nicer to have something like InternalName::new, with iterators etc. instead of parse from string.
    Ok(Some(Name::from_str(&parts.join("::"))?))
}

pub fn with_kubernetes_groupversion(
    fragment: &mut Fragment<RawName>,
    gv: &CedarGroupVersion,
    api_resource_list: &APIResourceList,
) -> Result<()> {
    // TODO: Add annotation to the cedar_ns with the API group

    //let cedar_ns = namespace_of_fragment(&mut fragment, gv.cedar_name.clone());

    // let k8s_cedar_ns = namespace_of_fragment(&mut fragment, K8S_NS.clone());
    /*let all_resource_actions: Vec<ActionUID> = k8s_cedar_ns.actions.keys().filter_map(|a| {
        if a == "impersonate" { // TODO: More predicates here in the future; use some Cedar annotation
            None
        } else {
            Some(ActionUID(Some(group_cedar_ns_name), a.to_string()))
        }
    }).collect();*/

    for resource in &api_resource_list.resources {
        // Only consider such GVRs which have a GVK.
        if resource.kind.is_empty() {
            continue;
        }

        // resource.group and/or resource.version might be empty; fallback to gv for both or either one if they are.
        let payload_gv = if resource.group.as_ref() == Some(&gv.group)
            && resource.version.as_ref() == Some(&gv.version)
        {
            gv.clone()
        } else {
            CedarGroupVersion::new(
                resource.group.clone().unwrap_or_else(|| gv.group.clone()),
                resource
                    .version
                    .clone()
                    .unwrap_or_else(|| gv.version.clone()),
            )?
        };

        let status_suffix = if resource.name.ends_with("/status") {
            "Status"
        } else {
            ""
        };
        // Special-case this one
        let kind = if gv.group.is_empty() && gv.version == "v1" && resource.name == "pods/log" {
            "PodLogOptions"
        } else {
            &resource.kind
        };

        let payload_versionlist_type_name = CedarTypeName::new(
            payload_gv.cedar_name.clone(),
            &format!("Versioned{kind}{status_suffix}"),
        )?;

        // Phase 1: Initialize top-level GVR type, if not exist
        let mut et = EntityWrapper {
            // resource.name is either something like "pods" or "pods/exec" => "pods" or "pods_exec"
            name: gv.resource_type_name(&resource.name)?,
            attrs: BTreeMap::from([
                ("apiGroup".into(), TypeWrapper::String.required()),
                //("apiVersion".into(), TypeWrapper::String.required()), TODO: Add later if needed
                ("resourceCombined".into(), TypeWrapper::String.required()),
                // TODO: required for subresources, not for top-level ones.
                ("name".into(), TypeWrapper::String.required()),
                (
                    "stored".into(),
                    TypeWrapper::CommonRef(payload_versionlist_type_name.full_name()).optional(),
                ),
                (
                    "request".into(),
                    TypeWrapper::CommonRef(payload_versionlist_type_name.full_name()).optional(),
                ),
            ]),
            kind: TypeKind::EntityType {
                members_of_types: if resource.namespaced {
                    Vec::from([&ENTITY_NAMESPACE.name])
                } else {
                    Vec::new()
                },
                apply_to_actions_as_principal: Vec::new(),
                apply_to_actions_as_resource: resource
                    .verbs
                    .iter()
                    .map(|v| ActionUID(K8S_NS.clone(), v.to_owned()))
                    .collect(),
                tags: None,
            },
        };

        if resource.namespaced {
            et.attrs.insert(
                "namespace".into(),
                TypeWrapper::CommonRef(ENTITY_NAMESPACE.name.full_name()).required(),
            );
        }
        // TODO: Update-only if not exists
        et.apply(fragment)?;

        // The GVR (e.g. core, v1, serviceaccounts/token) might be "backed by" a different payload GVK,
        // e.g. (authentication.k8s.io, v1, TokenRequest).
        // Fully-qualify the Cedar entity reference with a group if it is different (that is, non-empty in the APIResource)

        // not sure if this can happen, but just in case

        // Fully-qualify the Cedar entity reference with a group if it is different (that is, non-empty in the APIResource)

        // Insert an attribute with the versioned payload schema, both for the "new" and "old" objects

        let versioned_payload_openapi_type = GroupVersionedOpenAPIType::new(
            payload_gv.clone(), // TODO: avoid these better
            format!("{kind}{status_suffix}"),
        )?;

        // Apply an empty common type for the payload, to be filled in from OpenAPI later
        /*EntityWrapper {
            name: versioned_payload_openapi_type.cedar_type_name.clone(),
            attrs: BTreeMap::new(),
            kind: TypeKind::CommonType,
        }
        .apply(&mut fragment)?;*/

        let payload_versionlist_ns = namespace_of_fragment(
            fragment,
            payload_versionlist_type_name.cedar_namespace.clone(),
        );
        let payload_versionlist_type = payload_versionlist_ns
            .common_types // TODO: Make this an entity type instead
            .entry(payload_versionlist_type_name.clone().try_into()?)
            .or_insert_with(|| CommonType {
                ty: Type::Type {
                    ty: TypeVariant::Record(RecordType {
                        attributes: BTreeMap::from([
                            ("apiVersion".into(), TypeWrapper::String.required()),
                            ("kind".into(), TypeWrapper::String.required()),
                            (
                                // TODO: Metadata should probably not be set using status subresource. Check what is given in admission in the stored object; the full object or not?
                                // Only add metadata if it really exists on the top-level object, although it exists for pretty much all objects.
                                // TODO: How much information is available in admission for status subresource requests?
                                "metadata".into(),
                                TypeWrapper::CommonRef(TYPE_OBJECTMETA.name.full_name()).required(),
                            ),
                        ]),
                        additional_attributes: false,
                    }),
                    loc: None,
                },
                annotations: Default::default(),
                loc: None,
            });

        // The same resource, e.g. horizontalpodautoscalers, might exist in multiple versions (v1 and v2).
        // Add both versions to the schema
        if let Type::Type { ty, .. } = &mut payload_versionlist_type.ty {
            if let TypeVariant::Record(record) = ty {
                record.attributes.insert(
                    payload_gv.version.as_str().into(),
                    TypeWrapper::CommonRef(
                        versioned_payload_openapi_type.cedar_type_name.full_name(),
                    )
                    .optional(),
                );
            }
        }

        // TODO: Create payload_cedar_entity and dependents here from OpenAPI schema
    }

    Ok(())
}

#[derive(Clone)]
pub struct CedarGroupVersion {
    pub(super) group: String,
    pub(super) version: String,
    pub(super) cedar_name: Option<Name>,
}

impl CedarGroupVersion {
    pub fn new(group: String, version: String) -> Result<Self> {
        Ok(CedarGroupVersion {
            cedar_name: group_to_cedar_ns(&group)?,
            group,
            version,
        })
    }

    pub(crate) fn resource_type_name(&self, resource: &str) -> Result<CedarTypeName> {
        CedarTypeName::new(self.cedar_name.clone(), &resource.replace("/", "_"))
    }
}

mod test {

    #[test]
    fn test_core_schema() {
        use crate::schema;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;
        use std::io::Write;

        let test_schema_str =
            std::fs::read_to_string("src/schema/testfiles/withdiscovery.cedarschema")
                .unwrap_or_default();

        let apiresourcelist_core_v1_str =
            std::fs::read_to_string("src/schema/testfiles/apiresourcelist-core-v1.json")
                .expect("missing API resource list file");

        let apiresourcelist_core_v1: APIResourceList =
            serde_json::from_str(&apiresourcelist_core_v1_str)
                .expect("failed to deserialize APIResourceList");

        let mut core_fragment = schema::core::build_base().expect("to succeed");
        schema::impersonate::with_impersonation(&mut core_fragment).expect("should work");
        schema::customverbs::with_custom_verbs(&mut core_fragment, Vec::new())
            .expect("should work");
        schema::discovery::with_kubernetes_groupversion(
            &mut core_fragment,
            &schema::CedarGroupVersion::new("".to_string(), "v1".to_string()).unwrap(),
            &apiresourcelist_core_v1,
        )
        .expect("openapi schema generation to work");

        let core_fragment_str = core_fragment
            .to_cedarschema()
            .expect("test schema can be displayed");
        println!("{core_fragment}");
        // assert test schema file is already formatted
        if core_fragment_str != test_schema_str {
            let mut f = std::fs::File::create("src/schema/testfiles/withdiscovery.cedarschema")
                .expect("open file works");
            f.write_all(core_fragment_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}

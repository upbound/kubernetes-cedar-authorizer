use cedar_policy_core::validator::json_schema::*;
use cedar_policy_core::validator::RawName;

use super::core::TYPE_OBJECTMETA;
use super::discovery::CedarGroupVersion;
use super::types::{CedarTypeName, TypeWrapper};

use serde_json::Value;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Deref;
use std::sync::LazyLock;

use super::err::{Result, SchemaProcessingError};
use super::util::{make_stringmap_type, namespace_of_fragment};

pub(crate) struct GroupVersionedOpenAPIType {
    pub(crate) gv: CedarGroupVersion,
    // something like "PodStatus", scoped within gv
    pub(crate) openapi_type_name: String,
    pub(crate) cedar_type_name: CedarTypeName,
    //pub(crate) is_gvk: bool,
}

static META_COMPONENT_PREFIXES: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    HashSet::from([
        "io.k8s.apimachinery.pkg.apis.meta.v1.",
        "io.k8s.apimachinery.pkg.api.resource.",
        "io.k8s.apimachinery.pkg.util.intstr.",
        "io.k8s.apimachinery.pkg.runtime.",
    ])
});

// NOTE: Keep this in sync with the directories in https://github.com/kubernetes/api, and similar core type packages
static CORE_API_DIRECTORIES: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        // From https://github.com/kubernetes/api
        ("io.k8s.api.admission.", "admission.k8s.io"),
        (
            "io.k8s.api.admissionregistration.",
            "admissionregistration.k8s.io",
        ),
        ("io.k8s.api.apidiscovery.", "apidiscovery.k8s.io"),
        ("io.k8s.api.apiserverinternal.", "internal.apiserver.k8s.io"),
        ("io.k8s.api.apps.", "apps"),
        ("io.k8s.api.authentication.", "authentication.k8s.io"),
        ("io.k8s.api.authorization.", "authorization.k8s.io"),
        ("io.k8s.api.autoscaling.", "autoscaling"),
        ("io.k8s.api.batch.", "batch"),
        ("io.k8s.api.certificates.", "certificates.k8s.io"),
        ("io.k8s.api.coordination.", "coordination.k8s.io"),
        ("io.k8s.api.core.", ""),
        ("io.k8s.api.discovery.", "discovery.k8s.io"),
        ("io.k8s.api.events.", "events.k8s.io"),
        ("io.k8s.api.extensions.", "extensions"),
        ("io.k8s.api.flowcontrol.", "flowcontrol.apiserver.k8s.io"),
        ("io.k8s.api.imagepolicy.", "imagepolicy.k8s.io"),
        ("io.k8s.api.networking.", "networking.k8s.io"),
        ("io.k8s.api.node.", "node.k8s.io"),
        ("io.k8s.api.policy.", "policy"),
        ("io.k8s.api.rbac.", "rbac.authorization.k8s.io"),
        ("io.k8s.api.resource.", "resource.k8s.io"),
        ("io.k8s.api.scheduling.", "scheduling.k8s.io"),
        ("io.k8s.api.storage.", "storage.k8s.io"),
        ("io.k8s.api.storagemigration.", "storagemigration.k8s.io"),
        // From https://github.com/kubernetes/kube-aggregator
        (
            "io.k8s.kube-aggregator.pkg.apis.apiregistration.",
            "apiregistration.k8s.io",
        ),
        // From https://github.com/kubernetes/apiextensions-apiserver
        (
            "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.",
            "apiextensions.k8s.io",
        ),
    ])
});

// TODO: Implement handling for the status subresource; now no entity type is created for it.

impl GroupVersionedOpenAPIType {
    pub(crate) fn new(
        gv: CedarGroupVersion,
        openapi_type_name: String,
    ) -> Result<GroupVersionedOpenAPIType> {
        Ok(GroupVersionedOpenAPIType {
            cedar_type_name: CedarTypeName::new(
                gv.cedar_name.clone(),
                &format!("{}{}", &title_case(&gv.version), &openapi_type_name),
            )?,
            gv,
            openapi_type_name,
        })
    }

    // General pattern:
    // {group}.{version}.{kind}.
    // However, there are three archetypes of defining {group}:
    // io.k8s.apimachinery.pkg.apis.meta => k8s meta group
    // io.k8s.api.{group's first path} => k8s builtin API group. "" apiGroup called "core"
    //  => Note: "apps" group is "io.k8s.api.apps" in OpenAPI, but
    //           "authentication.k8s.io" group is "io.k8s.api.authentication".
    //     That is, only the first part of the API group is considered.
    // io.k8s.networking.gateway => Reversed API group for CRDs, for gateway.networking.k8s.io
    // TODO: Handle io.k8s.kube-aggregator.pkg.apis
    // TODO special case for API extensions?
    pub(crate) fn from_component_name<'a>(
        component_name: &str,
    ) -> Result<GroupVersionedOpenAPIType> {
        let parts: Vec<&str> = component_name.split('.').rev().collect();
        if parts.len() < 4 {
            return Err(SchemaProcessingError::OpenAPI(
                "there must be at least four parts of an OpenAPI schema.".to_string(),
            ));
        }

        let openapi_type_name = parts[0];
        let mut type_version = parts[1];
        let mut type_api_group = String::new();

        let has_meta_prefix = META_COMPONENT_PREFIXES
            .iter()
            .find(|prefix| component_name.starts_with(*prefix));
        let has_core_prefix = CORE_API_DIRECTORIES
            .keys()
            .find(|prefix| component_name.starts_with(*prefix));

        if let Some(meta_prefix) = has_meta_prefix {
            // Sanity check; we expect e.g.
            // component_name = io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta
            // meta_prefix    = io.k8s.apimachinery.pkg.apis.meta.v1.
            // If this is not the case, error
            if component_name.split(".").count() != meta_prefix.split(".").count() {
                return Err(SchemaProcessingError::Unknown(
                    "meta prefix is not as expected".to_string(),
                ));
            }
            type_api_group.push_str("meta"); // TODO: Is the official API group actually meta.k8s.io?
            type_version = "v1";
        } else if let Some(core_prefix) = has_core_prefix {
            // Sanity check; we expect e.g.
            // component_name = io.k8s.api.rbac.v1.ClusterRole
            // meta_prefix    = io.k8s.api.rbac.
            // If this is not the case, error
            if component_name.split(".").count() != core_prefix.split(".").count() + 1 {
                return Err(SchemaProcessingError::Unknown(format!(
                    "core prefix {core_prefix} is not as expected for component {component_name}"
                )));
            }
            // api group is the hashmap value for the prefix
            type_api_group.push_str(CORE_API_DIRECTORIES.deref().get(core_prefix).unwrap());
        } else {
            type_api_group.push_str(&parts[2..].join("."));
        }

        let type_gv = CedarGroupVersion::new(type_api_group, type_version.to_string())?;

        GroupVersionedOpenAPIType::new(type_gv, openapi_type_name.to_string())
    }

    // TODO: Make trait for this?
    /*fn full_name(&self) -> RawName {

    }*/
}

fn title_case(name: &str) -> String {
    name.chars()
        .enumerate()
        .map(|(i, c)| match i {
            0 => c.to_ascii_uppercase(),
            _ => c,
        })
        .collect()
}

pub(super) fn with_openapi_schemas(
    fragment: &mut Fragment<RawName>,
    openapi_spec: &Value,
) -> Result<()> {
    // TODO: Move this top-level into the binary?
    let schemas = openapi_spec
        .get("components")
        .and_then(|v| v.get("schemas"))
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            SchemaProcessingError::OpenAPI(
                "OpenAPI schema does not contain a .components.schemas object".to_string(),
            )
        })?;

    for (component_name, schema_definition) in schemas {
        if let Err(e) = process(fragment, component_name, schema_definition) {
            eprintln!("error: {e}")
        }
    }

    Ok(())
}

fn process(
    fragment: &mut Fragment<RawName>,
    component_name: &str,
    component_schema_val: &Value,
) -> Result<()> {
    // Parse the schema name into its components
    let openapi_type = GroupVersionedOpenAPIType::from_component_name(component_name)?;

    eprintln!("Processing: {component_name}");
    // This will create the namespace if not already exists
    let namespace = namespace_of_fragment(
        fragment,
        openapi_type.cedar_type_name.cedar_namespace.clone(),
    );

    // Don't re-create. TODO: might need to do some checksum calculations instead to detect drift between e.g. two clusters' API types.
    if namespace
        .common_types
        .contains_key(&openapi_type.cedar_type_name.common_type_id()?)
    {
        eprintln!("Type already exists: {component_name}");
        return Ok(());
    }

    let common_type_id = CommonTypeId::new(openapi_type.cedar_type_name.type_name.clone())?;

    let mut extra_types = Vec::new();

    match process_openapi_value(component_name, &[], component_schema_val, &mut extra_types) {
        Some(ty) => {
            eprintln!(
                "Adding common type: {}",
                openapi_type.cedar_type_name.full_name()
            );
            namespace.common_types.insert(
                common_type_id,
                CommonType {
                    ty,
                    annotations: Default::default(),
                    loc: None,
                },
            );

            for (extra_type_name, extra_type_def) in extra_types {
                let extra_ns =
                    namespace_of_fragment(fragment, extra_type_name.cedar_namespace.clone());
                extra_ns
                    .entity_types
                    .insert(extra_type_name.type_name, extra_type_def);
            }

            Ok(())
        }
        None => {
            // TODO: Distinguish between ok to not generate anything vs error
            eprintln!(
                "ERROR: couldn't generate common type: {}",
                openapi_type.cedar_type_name.full_name()
            );
            Ok(()) // TODO: return error?
        }
    }
}

fn process_openapi_value(
    component_name: &str,
    segments: &[&str],
    val: &Value,
    types_to_create: &mut Vec<(CedarTypeName, EntityType<RawName>)>,
) -> Option<Type<RawName>> {
    let segments_str = segments.join(".");
    let attr_name = format!("{component_name}(.{segments_str})");

    // Don't recurse indefinitely
    if segments.len() > 15 {
        eprintln!("Reached max depth: {attr_name}");
        return None;
    }

    let is_toplevel_kind = val
        .get("x-kubernetes-group-version-kind")
        .and_then(|f| f.as_array())
        .and_then(|a| a.first())
        .and_then(|o| o.as_object())
        .is_some();

    if is_toplevel_kind {
        let metadata_type_ref = val
            .get("properties")
            .and_then(|v| v.get("metadata"))
            .and_then(|v| v.get("allOf"))
            .and_then(|a| a.get(0))
            .and_then(|a| a.get("$ref"))
            .and_then(|s| s.as_str());
        eprintln!("Top-level: true, meta-typeref: {metadata_type_ref:?}");
        if let Some(type_ref) = metadata_type_ref {
            // skip lists with ListMeta, but generate v1.Status in the schema
            if type_ref == "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta"
                && component_name != "io.k8s.apimachinery.pkg.apis.meta.v1.Status"
            {
                eprintln!("Skipping list {component_name}");
                return None;
            }
        }
    }

    if component_name == "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps"
    {
        return empty_object();
    }

    if component_name == "io.k8s.apimachinery.pkg.util.intstr.IntOrString"
        || component_name == "io.k8s.apimachinery.pkg.api.resource.Quantity"
    {
        return Some(Type::Type {
            ty: TypeVariant::String,
            loc: None,
        });
    }

    // TODO: Check for mutual exclusitivity?
    let val_field_ref = val.get("$ref").and_then(|t| t.as_str());
    if let Some(type_ref) = val_field_ref {
        return match type_ref.strip_prefix("#/components/schemas/") {
            Some(ref_component_name) => {
                match GroupVersionedOpenAPIType::from_component_name(ref_component_name) {
                    Ok(t) => Some(Type::CommonTypeRef {
                        type_name: t.cedar_type_name.full_name(),
                        loc: None,
                    }),
                    Err(e) => {
                        eprintln!("Error: couldn't qualify ref {type_ref}: {e:?}");
                        return None;
                    }
                }
            }
            None => {
                eprintln!("Error: Supporting only in-schema fully-qualified references: {attr_name} refers to {type_ref}");
                None
            }
        };
    }

    let val_field_type = val.get("type").and_then(|t| t.as_str());
    let val_field_all_of = val.get("allOf").and_then(|a| a.as_array());

    match (val_field_type, val_field_all_of) {
        (Some(attr_type), None) => match attr_type {
            "string" => Some(Type::Type {
                ty: TypeVariant::String,
                loc: None,
            }),
            "integer" => Some(Type::Type {
                ty: TypeVariant::Long,
                loc: None,
            }),
            "boolean" => Some(Type::Type {
                ty: TypeVariant::Boolean,
                loc: None,
            }),
            "array" => match val.get("items") {
                Some(items) => match process_openapi_value(
                    component_name,
                    &Vec::from([segments, &["items"]]).concat(),
                    items,
                    types_to_create,
                ) {
                    // TODO: Figure out if this array is actually a k8s-style map, and
                    // use the tags approach.
                    Some(elem_type) => {
                        if is_simple_type(&elem_type) {
                            Some(Type::Type {
                                ty: TypeVariant::Set {
                                    element: Box::new(elem_type),
                                },
                                loc: None,
                            })
                        } else {
                            // TODO: We probably want to generate sub-types unnamed records (for CRDs) too here
                            eprintln!("Found non-simple set type {attr_name}, skipping");
                            None
                        }
                    }
                    None => {
                        eprintln!("{attr_name} didn't yield an element type, skipping");
                        None
                    }
                },
                None => {
                    eprintln!("{attr_name} didn't yield an element type, skipping");
                    None
                }
            },
            "object" => {
                // TODO: process enums
                let val_field_properties = val.get("properties").and_then(|p| p.as_object());
                let val_field_additional_properties = val.get("additionalProperties");

                match (val_field_properties, val_field_additional_properties) {
                    (Some(properties), None) => {
                        let mut record_type = RecordType {
                            attributes: BTreeMap::new(),
                            additional_attributes: false,
                        };
                        // Get required fields if they exist
                        let required_properties: HashSet<&str> = val
                            .get("required")
                            .and_then(|r| r.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                            .unwrap_or_default();

                        for (attr_name2, attr_value) in properties {
                            // These fields already exist on the version-aggregator object
                            if is_toplevel_kind
                                && (attr_name2 == "apiVersion"
                                    || attr_name2 == "kind"
                                    || attr_name2 == "metadata")
                            {
                                continue;
                            }

                            record_type.attributes.insert(
                                attr_name2.into(),
                                TypeOfAttribute {
                                    ty: match process_openapi_value(
                                        component_name,
                                        // TODO: Make small helper type for this purpose
                                        &Vec::from([segments, &[attr_name2]]).concat(),
                                        attr_value,
                                        types_to_create,
                                    ) {
                                        Some(ty) => ty,
                                        None => {
                                            eprintln!("Got none for {segments_str}.{attr_name2}");
                                            continue;
                                        }
                                    },
                                    annotations: Default::default(),
                                    required: required_properties.contains(attr_name2.as_str()),
                                },
                            );
                        }

                        Some(Type::Type {
                            ty: TypeVariant::Record(record_type),
                            loc: None,
                        })
                    }
                    (None, Some(elem_val)) => match process_openapi_value(
                        component_name,
                        &Vec::from([segments, &["additionalProperties"]]).concat(),
                        elem_val,
                        types_to_create,
                    ) {
                        Some(elem_value_type) => match make_stringmap_type(elem_value_type.clone())
                        {
                            Some(map_entity) => {
                                let map_entity_name = map_entity.0.full_name();
                                types_to_create.push(map_entity);
                                Some(Type::Type {
                                    ty: TypeVariant::Entity {
                                        name: map_entity_name,
                                    },
                                    loc: None,
                                })
                            }
                            None => None,
                        },
                        None => {
                            eprintln!("Error: didn't resolve element type of {segments_str}.additionalProperties");
                            None
                        }
                    },
                    (Some(_), Some(_)) => {
                        // TODO: error
                        eprintln!("Error {attr_name}: both properties and additionalProperties!");
                        None
                    }
                    (None, None) => {
                        // no properties, just empty object
                        empty_object()
                    }
                }
            }
            "number" => {
                eprintln!("Skipping number: {attr_name}, {val:?}");
                None
            }
            _ => {
                eprintln!("Skipping unknown type: {attr_type} for {attr_name}");
                None
            }
        },
        (None, Some(all_of)) => {
            if all_of.len() == 1 {
                process_openapi_value(
                    component_name,
                    &Vec::from([segments, &["allOf"]]).concat(),
                    &all_of[0],
                    types_to_create,
                )
            } else {
                eprintln!(
                    "Found allOf with other than one item: {} in {}",
                    all_of.len(),
                    attr_name
                );
                None // TODO: error
            }
        }
        (Some(_), Some(_)) => {
            eprintln!("{attr_name} saw both exclusive allOf and type, skipping");
            None
        }
        (None, None) => {
            eprintln!("{attr_name} didn't yield an element type, skipping");
            empty_object()
        }
    }
}

fn empty_object() -> Option<Type<RawName>> {
    Some(Type::Type {
        ty: TypeVariant::Record(RecordType {
            attributes: BTreeMap::new(),
            additional_attributes: false,
        }),
        loc: None,
    })
}

fn is_simple_type(t: &Type<RawName>) -> bool {
    match t {
        Type::CommonTypeRef { .. } => true,
        Type::Type { ty, .. } => match ty {
            TypeVariant::Boolean => true,
            TypeVariant::String => true,
            TypeVariant::Long => true,
            TypeVariant::Extension { .. } => true, // TODO: This might be useful in the future
            TypeVariant::EntityOrCommon { .. } => true,
            TypeVariant::Entity { .. } => true,
            TypeVariant::Record(_) => false,
            TypeVariant::Set { .. } => false,
        },
    }
}

mod test {
    #[test]
    fn test_type_from_componentname() {
        /*let core_v1 =
            CedarGroupVersion::new("".to_string(), "v1".to_string()).expect("parse works");
        let apps_v1 =
            CedarGroupVersion::new("apps".to_string(), "v1".to_string()).expect("parse works");
        let rbac_v1 =
            CedarGroupVersion::new("rbac.authorization.k8s.io".to_string(), "v1".to_string())
                .expect("parse works");
        let gateway_v1 =
            CedarGroupVersion::new("gateway.networking.k8s.io".to_string(), "v1".to_string())
                .expect("parse works");*/
        let tests = Vec::from([
            (
                "io.k8s.api.core.v1.Volume",
                "core::V1Volume",
                "",
                "v1",
                "Volume",
            ),
            (
                "io.k8s.apimachinery.pkg.apis.meta.v1.LabelSelector",
                "meta::V1LabelSelector",
                "meta",
                "v1",
                "LabelSelector",
            ),
            (
                "io.k8s.api.apps.v1.DeploymentStatus",
                "apps::V1DeploymentStatus",
                "apps",
                "v1",
                "DeploymentStatus",
            ),
            (
                "io.k8s.api.core.v1.PodSpec",
                "core::V1PodSpec",
                "",
                "v1",
                "PodSpec",
            ),
            (
                "io.k8s.apimachinery.pkg.api.resource.Quantity",
                "meta::V1Quantity",
                "meta",
                "v1",
                "Quantity",
            ),
            (
                "io.k8s.api.rbac.v1.Subject",
                "io::k8s::authorization::rbac::V1Subject",
                "rbac.authorization.k8s.io",
                "v1",
                "Subject",
            ),
            (
                "io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta",
                "meta::V1ListMeta",
                "meta",
                "v1",
                "ListMeta",
            ),
            (
                "io.k8s.networking.gateway.v1.GRPCRoute",
                "io::k8s::networking::gateway::V1GRPCRoute",
                "gateway.networking.k8s.io",
                "v1",
                "GRPCRoute",
            ),
            (
                "io.k8s.apimachinery.pkg.apis.meta.v1.Status",
                "meta::V1Status",
                "meta",
                "v1",
                "Status",
            ),
        ]);
        for test in tests {
            let t = super::GroupVersionedOpenAPIType::from_component_name(test.0)
                .expect("test to not error");
            assert_eq!(t.cedar_type_name.full_name().to_string(), test.1);
            assert_eq!(t.gv.group, test.2);
            assert_eq!(t.gv.version, test.3);
            assert_eq!(t.openapi_type_name, test.4);
        }
    }

    #[test]
    fn test_core_schema() {
        use crate::schema;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::APIResourceList;
        use serde_json::Value;
        use std::io::Write;

        let test_schema_str =
            std::fs::read_to_string("src/schema/testfiles/withopenapi.cedarschema")
                .unwrap_or_default();

        let apiresourcelist_core_v1_str =
            std::fs::read_to_string("src/schema/testfiles/apiresourcelist-core-v1.json")
                .expect("missing API resource list file");

        let openapi_core_v1_str =
            std::fs::read_to_string("src/schema/testfiles/openapi-core-v1.json")
                .expect("missing core openapi file");

        let apiresourcelist_core_v1: APIResourceList =
            serde_json::from_str(&apiresourcelist_core_v1_str)
                .expect("failed to deserialize APIResourceList");

        let openapi_core_v1: Value =
            serde_json::from_str(&openapi_core_v1_str).expect("failed to deserialize OpenAPI");

        let gv_core_v1 = schema::CedarGroupVersion::new("".to_string(), "v1".to_string()).unwrap();
        let mut core_fragment = schema::core::build_base().expect("to succeed");
        schema::impersonate::with_impersonation(&mut core_fragment).expect("should work");
        schema::customverbs::with_custom_verbs(&mut core_fragment, Vec::new())
            .expect("should work");
        schema::discovery::with_kubernetes_groupversion(
            &mut core_fragment,
            &gv_core_v1,
            &apiresourcelist_core_v1,
        )
        .expect("openapi schema generation to work");
        super::with_openapi_schemas(&mut core_fragment, &openapi_core_v1)
            .expect("openapi generation to work");

        let core_fragment_str = core_fragment
            .to_cedarschema()
            .expect("test schema can be displayed");

        // assert test schema file is already formatted
        if core_fragment_str != test_schema_str {
            let mut f = std::fs::File::create("src/schema/testfiles/withopenapi.cedarschema")
                .expect("open file works");
            f.write_all(core_fragment_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}

use std::{
    collections::{HashMap, HashSet},
    fmt::format,
    sync::LazyLock,
};

use cedar_policy_core::{
    ast,
    validator::{RawName, ValidatorSchema},
};

use cedar_policy_core::ast::{InternalName, Name, UnreservedId};
use cedar_policy_core::validator::json_schema::{self, EntityTypeKind, Fragment};
use smol_str::SmolStr;

use crate::{
    k8s_authorizer::AuthorizerError,
    schema::core::{K8S_NONRESOURCE_NS, K8S_NS},
};

use super::err::SchemaError;

// What resource attributes should be rewritten from a simple Cedar type (e.g. "string") to
// an entity type (e.g. "meta::UnknownString"), that can be left unknown during typed partial evaluation.
static STATIC_RESOURCE_ATTRIBUTE_REWRITES: LazyLock<HashMap<String, RawName>> =
    LazyLock::new(|| {
        HashMap::from([
            (
                "apiGroup".to_string(),
                "meta::UnknownString".parse().unwrap(),
            ),
            (
                "resourceCombined".to_string(),
                "meta::UnknownString".parse().unwrap(),
            ),
            ("name".to_string(), "meta::UnknownString".parse().unwrap()),
            (
                "namespace".to_string(),
                "meta::UnknownString".parse().unwrap(),
            ),
            ("path".to_string(), "meta::UnknownString".parse().unwrap()),
        ])
    });

#[derive(Clone)]
pub struct Schema {
    schema: Fragment<RawName>,
    public_api_schema: cedar_policy::Schema,
    action_capabilities: HashMap<(Option<ast::Name>, &'static str), ActionCapability>,
}

impl Schema {
    pub fn new(mut schema: Fragment<RawName>) -> Result<Self, SchemaError> {
        Self::rewrite_schema(
            &mut schema,
            K8S_NS.clone(),
            &STATIC_RESOURCE_ATTRIBUTE_REWRITES,
        )?;
        Self::rewrite_schema(
            &mut schema,
            K8S_NONRESOURCE_NS.clone(),
            &STATIC_RESOURCE_ATTRIBUTE_REWRITES,
        )?;

        let validator_schema: cedar_policy_core::validator::ValidatorSchema =
            schema.clone().try_into()?;

        Ok(Self {
            schema,
            public_api_schema: validator_schema.into(),
            // TODO: Compute this from the schema, so that extension verbs can utilize the capabilities.
            action_capabilities: HashMap::from([
                // Get doesn't support any of these fancy features. Selectors could maybe be added in the future to be consistent with list, watch.
                ((K8S_NS.clone(), "get"), Default::default()),
                // List, watch, deletecollection support selectors.
                ((K8S_NS.clone(), "list"), ActionCapability::with_selectors()),
                (
                    (K8S_NS.clone(), "watch"),
                    ActionCapability::with_selectors(),
                ),
                (
                    (K8S_NS.clone(), "deletecollection"),
                    ActionCapability::with_selectors(),
                ),
                (
                    (K8S_NS.clone(), "impersonate"),
                    ActionCapability::with_selectors(),
                ),
                // Create and connect only have a request object.
                (
                    (K8S_NS.clone(), "create"),
                    ActionCapability::with_objects(true, false),
                ),
                (
                    (K8S_NS.clone(), "connect"),
                    ActionCapability::with_objects(true, false),
                ),
                // Update and patch have both a request object and a stored object.
                (
                    (K8S_NS.clone(), "update"),
                    ActionCapability::with_objects(true, true),
                ),
                (
                    (K8S_NS.clone(), "patch"),
                    ActionCapability::with_objects(true, true),
                ),
                // Delete only has a stored object.
                (
                    (K8S_NS.clone(), "delete"),
                    ActionCapability::with_objects(false, true),
                ),
                // Anything not in this list supports none of these capabilities.
                // For example, none of the non-resource actions supports any of these capabilities.
            ]),
        })
    }

    pub fn get_namespace(
        &self,
        namespace: &Option<ast::Name>,
    ) -> Option<&json_schema::NamespaceDefinition<RawName>> {
        self.schema.0.get(namespace)
    }

    pub fn get_action_capabilities<'a>(
        &'a self,
        namespace: &Option<ast::Name>,
        action: &str,
    ) -> ActionCapability {
        self.action_capabilities
            .get(&(namespace.clone(), action))
            .cloned()
            .unwrap_or_default()
    }

    pub fn rewritten_resource_attributes(&self) -> &HashMap<String, RawName> {
        &STATIC_RESOURCE_ATTRIBUTE_REWRITES
    }

    pub fn get_fragment(&self) -> &Fragment<RawName> {
        &self.schema
    }

    fn rewrite_schema(
        schema: &mut Fragment<RawName>,
        actions_ns_name: Option<Name>,
        rewrite_resource_attr_to_entity: &HashMap<String, RawName>,
    ) -> Result<(), SchemaError> {
        let actions_ns = schema
            .0
            .get(&actions_ns_name)
            .ok_or(SchemaError::SchemaRewriteError(format!(
                "Namespace {} not found in schema",
                actions_ns_name
                    .as_ref()
                    .map(|n| n.to_string())
                    .unwrap_or_default()
            )))?;

        let resource_types: HashSet<InternalName> = actions_ns
            .actions
            .values()
            .flat_map(|action| action.applies_to.iter())
            .flat_map(|applies_to| applies_to.resource_types.iter())
            .map(|resource_type| {
                resource_type
                    .clone()
                    .qualify_with_name(actions_ns_name.as_ref())
            })
            .collect();

        for resource_type in resource_types {
            let resource_type_ns = match schema.0.get_mut(&ns_of_internal_name(&resource_type)) {
                Some(ns) => ns,
                None => {
                    return Err(SchemaError::SchemaRewriteError(format!(
                        "Namespace {} not found in schema",
                        resource_type.namespace()
                    )))
                }
            };
            let id = UnreservedId::try_from(resource_type.basename().clone()).unwrap();
            let resource_type_name = match resource_type_ns.entity_types.get_mut(&id) {
                Some(resource_type) => resource_type,
                None => return Err(SchemaError::MissingResourceType(resource_type.to_string())),
            };
            match &mut resource_type_name.kind {
                EntityTypeKind::Standard(json_schema::StandardEntityType {
                    shape:
                        json_schema::AttributesOrContext(json_schema::Type::Type {
                            ty:
                                json_schema::TypeVariant::Record(json_schema::RecordType {
                                    attributes, ..
                                }),
                            ..
                        }),
                    ..
                }) => {
                    for (resource_attr_name, new_entity_type_name) in rewrite_resource_attr_to_entity {
                        if let Some(attr) = attributes.get_mut(resource_attr_name.as_str()) {
                            *attr = json_schema::TypeOfAttribute {
                                ty: json_schema::Type::Type {
                                    ty: json_schema::TypeVariant::Entity {
                                        name: new_entity_type_name.clone(),
                                    },
                                    loc: None,
                                },
                                annotations: attr.annotations.clone(),
                                required: attr.required,
                            }
                        }
                    }
                }
                _ => {
                    return Err(SchemaError::SchemaRewriteError(format!(
                        "Resource type {resource_type} is not a standard entity record type as expected"
                    )))
                }
            }
        }
        Ok(())
    }
}

fn ns_of_internal_name(internal_name: &InternalName) -> Option<Name> {
    match internal_name.namespace().as_str() {
        "" => None,
        ns => Some(ns.parse().unwrap()),
    }
}

impl AsRef<Fragment<RawName>> for Schema {
    fn as_ref(&self) -> &Fragment<RawName> {
        &self.schema
    }
}

impl AsRef<ValidatorSchema> for Schema {
    fn as_ref(&self) -> &ValidatorSchema {
        self.public_api_schema.as_ref()
    }
}

impl AsRef<cedar_policy::Schema> for Schema {
    fn as_ref(&self) -> &cedar_policy::Schema {
        &self.public_api_schema
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Capabilities of an action.
/// The selectors capability specifies whether the action supports label and field selectors.
/// The request_object capability specifies whether the action contains a request object.
/// The stored_object capability specifies whether the action contains a stored object.
/// The selectors and request/stored_object capabilities are mutually exclusive.
pub struct ActionCapability {
    selectors: bool,
    request_object: bool,
    stored_object: bool,
}

impl ActionCapability {
    pub fn supports_conditional_decision(&self) -> bool {
        self.request_object || self.stored_object
    }

    pub fn supports_selectors(&self) -> bool {
        self.selectors
    }

    pub fn has_request_object(&self) -> bool {
        self.request_object
    }

    pub fn has_stored_object(&self) -> bool {
        self.stored_object || self.selectors
    }

    pub fn with_selectors() -> Self {
        Self {
            selectors: true,
            request_object: false,
            stored_object: false,
        }
    }

    pub fn with_objects(request_object: bool, stored_object: bool) -> Self {
        Self {
            selectors: false,
            request_object,
            stored_object,
        }
    }
}

impl Default for ActionCapability {
    fn default() -> Self {
        Self {
            selectors: false,
            request_object: false,
            stored_object: false,
        }
    }
}

mod test {
    #[test]
    fn test_rewrite_schema() {
        use super::Schema;
        use crate::schema::core::K8S_NS;
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy_core::validator::json_schema::Fragment;
        use std::collections::HashMap;
        use std::io::Write;
        let (mut schema, _) = Fragment::from_cedarschema_str(
            include_str!("testfiles/rewrite-schema/before.cedarschema"),
            Extensions::all_available(),
        )
        .unwrap();
        let rewrite_resource_attr_to_entity = HashMap::from([
            ("foo".to_string(), "meta::UnknownString".parse().unwrap()),
            ("bar".to_string(), "meta::UnknownString".parse().unwrap()),
        ]);
        Schema::rewrite_schema(
            &mut schema,
            K8S_NS.clone(),
            &rewrite_resource_attr_to_entity,
        )
        .unwrap();
        let got_schema_str = schema.to_cedarschema().unwrap();
        println!("{got_schema_str}");
        // assert test schema file is already formatted
        if got_schema_str != include_str!("testfiles/rewrite-schema/after.cedarschema") {
            let mut f = std::fs::File::create(
                "src/cedar_authorizer/kube_invariants/testfiles/rewrite-schema/after.cedarschema",
            )
            .expect("open file works");
            f.write_all(got_schema_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}
